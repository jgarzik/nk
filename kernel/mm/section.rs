//! Data sections: a file's control area, its subsections and their
//! prototype PTEs, and the section objects that reference them.
//!
//! One control area per file, found through
//! `FileObject->SectionObjectPointer->DataSectionObject`, which is
//! non-null exactly while the control area lives, as on Windows. Its
//! counts and flags are Windows' (`_CONTROL_AREA`); its layout is NK's,
//! since no driver reads it.
//!
//! A subsection here covers 256 KiB of the file, one system-cache view,
//! and holds that range's 64 prototype PTEs. It is made when a view or
//! a read-ahead first needs it and freed when nothing maps it and none
//! of its pages is in memory, as Windows makes and frees the prototype
//! PTEs of a mapped file per subsection range (`MiManageSubsectionView`).
//! A prototype PTE of a page that is only in the file is in subsection
//! format, so a fault finds the file and the offset from it.
//!
//! The PFN lock (`pfn::PFN`, rank 60) guards every count, flag and
//! prototype PTE here, and `SectionObjectPointer->DataSectionObject`.
//! Memory is allocated before the lock is taken and freed after it is
//! dropped; what becomes unused under the lock is put on a list and
//! freed by [`reap`].

use super::pfn::{self, Guard};
use super::{PAGE_SIZE, pool};
use crate::ob::object::{self, ObRef, SECTION_TYPE};
use core::cell::Cell;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use nk_mm::pte::Proto;
use nk_mm::section::{self as rule, SUBSECTION_PAGES, flag};
use nk_ntabi::io::{FILE_OBJECT, SECTION_OBJECT_POINTERS};
use nk_ntabi::status::*;

/// Windows' pool tags: control area, segment (NK's subsection
/// directory), subsection.
const TAG_CONTROL_AREA: u32 = u32::from_le_bytes(*b"MmCa");
const TAG_DIRECTORY: u32 = u32::from_le_bytes(*b"MmSm");
const TAG_SUBSECTION: u32 = u32::from_le_bytes(*b"MmSc");

/// A run of 256 KiB of a file and its prototype PTEs.
#[repr(C)]
pub struct Subsection {
    pub ca: *mut ControlArea,
    /// The file page its first prototype PTE describes.
    pub first_page: u64,
    /// Views mapping it, and read-aheads using it.
    pub views: Cell<u32>,
    /// Its pages that are in memory.
    pub resident: Cell<u32>,
    /// The system-cache view that maps it, or 0.
    pub view_va: Cell<u64>,
    next: AtomicPtr<Subsection>,
    pub protos: [AtomicU64; SUBSECTION_PAGES],
}

/// A file's data control area.
#[repr(C)]
pub struct ControlArea {
    pub sop: *mut SECTION_OBJECT_POINTERS,
    /// Referenced while the control area lives.
    pub file: *mut FILE_OBJECT,
    /// Bytes the section covers.
    pub size: Cell<u64>,
    /// One subsection pointer per 256 KiB, null where none is made.
    dir: Cell<*mut *mut Subsection>,
    dir_len: Cell<usize>,
    pub section_refs: Cell<u64>,
    /// Frames holding the file's pages.
    pub pfn_refs: Cell<u64>,
    pub mapped_views: Cell<u64>,
    pub user_refs: Cell<u64>,
    pub cache_views: Cell<u64>,
    pub writable_user_refs: Cell<u64>,
    /// Starts at 1, as Windows' does; one more per locked page.
    pub locked_pages: Cell<u64>,
    pub flushes: Cell<u64>,
    pub flags: Cell<u32>,
    next: AtomicPtr<ControlArea>,
}

/// The body of a section object (`_SECTION`'s place).
#[repr(C)]
pub struct Section {
    ca: *mut ControlArea,
    size: AtomicU64,
}

/// A counted reference to a section object.
pub struct SectionRef(ObRef);

impl SectionRef {
    /// The section's size in bytes.
    pub fn size(&self) -> u64 {
        // SAFETY: the reference keeps the body alive.
        unsafe { (*self.0.cast::<Section>()).size.load(Ordering::Relaxed) }
    }

    pub(super) fn ca(&self) -> *mut ControlArea {
        // SAFETY: as in `size`; `ca` is written once, before the
        // reference is handed out.
        unsafe { (*self.0.cast::<Section>()).ca }
    }
}

impl ControlArea {
    /// The subsection for 256 KiB index `index`, if made.
    pub fn subsection(&self, _: &Guard, index: usize) -> *mut Subsection {
        if index >= self.dir_len.get() {
            return core::ptr::null_mut();
        }
        // SAFETY: the directory holds `dir_len` entries; the lock guards
        // them.
        unsafe { self.dir.get().add(index).read() }
    }

    fn set_subsection(&self, _: &Guard, index: usize, ss: *mut Subsection) {
        // SAFETY: as in `subsection`; callers pass an index below the length.
        unsafe { self.dir.get().add(index).write(ss) };
    }

    /// Whether the cache manager alone writes its pages.
    pub fn no_write(&self) -> bool {
        self.flags.get() & flag::NO_MODIFIED_WRITING != 0
    }

    /// The counts the truncate and purge rules read.
    pub fn counts(&self) -> rule::Counts {
        rule::Counts {
            flags: self.flags.get(),
            locked_pages: self.locked_pages.get(),
            user_references: self.user_refs.get(),
            mapped_views: self.mapped_views.get(),
            size: self.size.get(),
        }
    }
}

/// A subsection directory for a section of `size` bytes, or null if
/// the pool has none.
fn new_directory(size: u64) -> (*mut *mut Subsection, usize) {
    let len = rule::subsections(size).max(1);
    let dir = pool::alloc_zeroed(len * size_of::<usize>(), TAG_DIRECTORY);
    (dir.cast(), if dir.is_null() { 0 } else { len })
}

/// Free memory the pool gave, as this module's own.
fn free(block: *mut u8) {
    if let Err(e) = pool::free(block) {
        crate::kd::bugcheck(format_args!("mm: freeing a section block {block:p}: {e:?}"));
    }
}

/// Grow `ca` to `size` bytes with the directory `dir` (of `len`
/// entries) made beforehand. Returns the directory now unused, to free.
fn grow(g: &Guard, ca: &ControlArea, size: u64, dir: *mut *mut Subsection, len: usize) -> *mut u8 {
    if size <= ca.size.get() {
        return dir.cast();
    }
    let old = ca.dir.get();
    if len > ca.dir_len.get() {
        for i in 0..ca.dir_len.get() {
            // SAFETY: both directories hold the entries indexed; the new
            // one is the caller's, not yet shared.
            unsafe { dir.add(i).write(ca.subsection(g, i)) };
        }
        ca.dir.set(dir);
        ca.dir_len.set(len);
        ca.size.set(size);
        return old.cast();
    }
    ca.size.set(size);
    dir.cast()
}

/// `MmCreateCacheManagerSection`: the data section of `file`, sized
/// `max_size` bytes (the cache manager passes the allocation size
/// rounded up to 1 MiB, unchecked against the file's size). The file's
/// control area is made, or referenced if it exists, and
/// `SectionObjectPointer->DataSectionObject` names it.
///
/// Called at `PASSIVE_LEVEL` with no spin lock held; the file system
/// holds the file's resource.
pub fn create_cache_manager_section(
    file: *mut FILE_OBJECT,
    max_size: u64,
) -> Result<SectionRef, NTSTATUS> {
    // SAFETY: the caller's file object is live.
    let sop = unsafe { (*file).SectionObjectPointer }.cast::<SECTION_OBJECT_POINTERS>();
    if sop.is_null() || max_size == 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let size = max_size.next_multiple_of(PAGE_SIZE as u64);
    let body =
        object::create(&SECTION_TYPE, size_of::<Section>()).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    // SAFETY: a fresh object body of that size; the reference is ours.
    let section = unsafe { ObRef::adopt(body) };
    let fresh =
        pool::alloc_zeroed(size_of::<ControlArea>(), TAG_CONTROL_AREA).cast::<ControlArea>();
    let (dir, len) = new_directory(size);
    if fresh.is_null() || dir.is_null() {
        for block in [fresh.cast::<u8>(), dir.cast::<u8>()] {
            if !block.is_null() {
                free(block);
            }
        }
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let (ca, unused) = {
        let g = pfn::lock();
        // SAFETY: the lock guards the pointer; the file system's block
        // lives as long as the file object.
        let existing = unsafe { (*sop).DataSectionObject }.cast::<ControlArea>();
        if existing.is_null() {
            // SAFETY: the fresh block is ours, zeroed, of the right size;
            // every field is valid zeroed.
            unsafe {
                (&raw mut (*fresh).sop).write(sop);
                (&raw mut (*fresh).file).write(file);
                object::reference(file.cast());
                let ca = &*fresh;
                ca.size.set(size);
                ca.dir.set(dir);
                ca.dir_len.set(len);
                ca.section_refs.set(1);
                ca.locked_pages.set(1);
                ca.flags.set(flag::FILE);
                (*sop).DataSectionObject = fresh.cast();
            }
            (fresh, [core::ptr::null_mut(), core::ptr::null_mut()])
        } else {
            // SAFETY: a live control area: the pointer is cleared under
            // this lock before one is freed.
            let ca = unsafe { &*existing };
            ca.section_refs.set(ca.section_refs.get() + 1);
            let dir = grow(&g, ca, size, dir, len);
            (existing, [fresh.cast(), dir])
        }
    };
    for block in unused.into_iter().filter(|b| !b.is_null()) {
        free(block);
    }
    // SAFETY: the body is ours alone until the reference is handed out.
    unsafe {
        let s = section.cast::<Section>();
        (&raw mut (*s).ca).write(ca);
        (*s).size.store(size, Ordering::Relaxed);
    }
    trace(format_args!(
        "create section {file:p} size {size:#x} control area {ca:p}"
    ));
    Ok(SectionRef(section))
}

/// `MmExtendSection` as the cache manager calls it
/// (`IgnoreFileSizeChecking`): grow the section to `new_size` bytes if
/// it is smaller. Returns the section's size.
pub fn extend_section(s: &SectionRef, new_size: u64) -> Result<u64, NTSTATUS> {
    let size = new_size.next_multiple_of(PAGE_SIZE as u64);
    if size <= s.size() {
        return Ok(s.size());
    }
    let (dir, len) = new_directory(size);
    if dir.is_null() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let unused = {
        let g = pfn::lock();
        // SAFETY: the section's reference keeps its control area.
        grow(&g, unsafe { &*s.ca() }, size, dir, len)
    };
    free(unused);
    // SAFETY: the reference keeps the body; the size only grows.
    unsafe {
        (*s.0.cast::<Section>())
            .size
            .fetch_max(size, Ordering::Relaxed)
    };
    trace(format_args!("extend section {:p} to {size:#x}", s.ca()));
    Ok(s.size())
}

/// `MmDisableModifiedWriteOfSection`: the page writers never write the
/// data section's pages; only the cache manager's flushes do. False if
/// the file has no data section.
pub fn disable_modified_write(sop: *mut SECTION_OBJECT_POINTERS) -> bool {
    let _g = pfn::lock();
    // SAFETY: the file system's block; the lock guards the pointer.
    let ca = unsafe { (*sop).DataSectionObject }.cast::<ControlArea>();
    if ca.is_null() {
        return false;
    }
    // SAFETY: live while the pointer names it, under the lock.
    let ca = unsafe { &*ca };
    ca.flags.set(ca.flags.get() | flag::NO_MODIFIED_WRITING);
    true
}

/// The control area `sop` names, under the lock.
pub fn control_area(_: &Guard, sop: *mut SECTION_OBJECT_POINTERS) -> Option<&'static ControlArea> {
    // SAFETY: the file system's block; the lock guards the pointer and
    // keeps what it names alive while it is held. The 'static lifetime
    // is the caller's to keep within the lock.
    unsafe { (*sop).DataSectionObject.cast::<ControlArea>().as_ref() }
}

/// The section object's delete procedure.
///
/// # Safety
/// `body` is a section object nothing refers to any more.
pub unsafe extern "C" fn deleted(body: *mut c_void) {
    // SAFETY: per the contract.
    let ca = unsafe { (*body.cast::<Section>()).ca };
    if ca.is_null() {
        return; // creation failed before a control area was named
    }
    {
        let g = pfn::lock();
        // SAFETY: the section's count kept the control area alive.
        let ca = unsafe { &*ca };
        ca.section_refs.set(ca.section_refs.get() - 1);
        check(&g, ca);
    }
    reap();
}

/// The subsection for 256 KiB index `index` of `ca`, made from `spare`
/// if there is none (the caller allocated `spare` before taking the
/// lock, and frees it if it is still there afterwards).
pub fn subsection_or(
    g: &Guard,
    ca: &ControlArea,
    index: usize,
    spare: &mut *mut Subsection,
) -> Option<*mut Subsection> {
    let ss = ca.subsection(g, index);
    if !ss.is_null() {
        return Some(ss);
    }
    if spare.is_null() || index >= ca.dir_len.get() {
        return None;
    }
    let ss = core::mem::replace(spare, core::ptr::null_mut());
    let first_page = (index * SUBSECTION_PAGES) as u64;
    // SAFETY: the spare is a zeroed block of the right size, ours until
    // it is entered in the directory.
    unsafe {
        (&raw mut (*ss).ca).write(core::ptr::from_ref(ca).cast_mut());
        (&raw mut (*ss).first_page).write(first_page);
        for proto in &(*ss).protos {
            proto.store(
                Proto::Subsection(ss.addr() as u64).encode(),
                Ordering::Relaxed,
            );
        }
    }
    ca.set_subsection(g, index, ss);
    Some(ss)
}

/// A zeroed block for a subsection, or null.
pub fn spare_subsection() -> *mut Subsection {
    pool::alloc_zeroed(size_of::<Subsection>(), TAG_SUBSECTION).cast()
}

/// Free a spare subsection [`subsection_or`] did not use.
pub fn drop_spare(spare: *mut Subsection) {
    if !spare.is_null() {
        free(spare.cast());
    }
}

/// The subsection whose prototype PTE array holds `proto`, and the
/// index in it, given the subsection `original` (the value the PTE
/// holds when its page is in the file only) names.
pub fn locate_proto(original: u64, proto: u64) -> (*mut Subsection, usize) {
    let Proto::Subsection(ss) = Proto::decode(original) else {
        crate::kd::bugcheck(format_args!(
            "mm: a page's original PTE {original:#x} is not in subsection format"
        ));
    };
    let base = core::mem::offset_of!(Subsection, protos) as u64 + ss;
    (ss as *mut Subsection, ((proto - base) / 8) as usize)
}

/// Note that a page of `ss` left memory, and free what that leaves
/// unused.
pub fn page_left(g: &Guard, ss: &Subsection) {
    ss.resident.set(ss.resident.get() - 1);
    // SAFETY: a subsection's control area outlives it.
    let ca = unsafe { &*ss.ca };
    ca.pfn_refs.set(ca.pfn_refs.get() - 1);
    unused_subsection(g, ss);
    check(g, ca);
}

/// Put `ss` on the list to free if nothing maps it and none of its
/// pages is in memory.
pub fn unused_subsection(g: &Guard, ss: &Subsection) {
    if ss.views.get() != 0 || ss.resident.get() != 0 {
        return;
    }
    // SAFETY: a subsection's control area outlives it.
    let ca = unsafe { &*ss.ca };
    let index = (ss.first_page / SUBSECTION_PAGES as u64) as usize;
    let me = core::ptr::from_ref(ss).cast_mut();
    if ca.subsection(g, index) == me {
        ca.set_subsection(g, index, core::ptr::null_mut());
        push(&REAP_SUBSECTIONS, me, |s| &s.next);
    }
}

/// `MiCheckControlArea`: once no section, view, page or flush holds
/// `ca`, the file's `DataSectionObject` is cleared and the control
/// area goes on the list to free, which drops its reference to the
/// file (and may so send the file system its close request).
pub fn check(_: &Guard, ca: &ControlArea) {
    let idle = ca.section_refs.get() == 0
        && ca.mapped_views.get() == 0
        && ca.pfn_refs.get() == 0
        && ca.flushes.get() == 0;
    if !idle || ca.flags.get() & flag::BEING_DELETED != 0 {
        return;
    }
    ca.flags.set(ca.flags.get() | flag::BEING_DELETED);
    let me = core::ptr::from_ref(ca).cast_mut();
    // SAFETY: the file system's block lives as long as the file object
    // the control area references.
    unsafe {
        if (*ca.sop).DataSectionObject == me.cast() {
            (*ca.sop).DataSectionObject = core::ptr::null_mut();
        }
    }
    push(&REAP_CONTROL_AREAS, me, |c| &c.next);
}

static REAP_SUBSECTIONS: AtomicPtr<Subsection> = AtomicPtr::new(core::ptr::null_mut());
static REAP_CONTROL_AREAS: AtomicPtr<ControlArea> = AtomicPtr::new(core::ptr::null_mut());

fn push<T>(list: &AtomicPtr<T>, item: *mut T, link: impl Fn(&T) -> &AtomicPtr<T>) {
    // SAFETY: the item is unreachable from anything else now; its link
    // is its own.
    let next = unsafe { link(&*item) };
    let mut head = list.load(Ordering::Acquire);
    loop {
        next.store(head, Ordering::Relaxed);
        match list.compare_exchange_weak(head, item, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(now) => head = now,
        }
    }
}

/// Free the subsections and control areas that became unused under the
/// PFN lock. Called with no Mm lock held, at or below `DISPATCH_LEVEL`.
pub fn reap() {
    let mut ss = REAP_SUBSECTIONS.swap(core::ptr::null_mut(), Ordering::AcqRel);
    while !ss.is_null() {
        // SAFETY: an unused subsection off every list but this one.
        let next = unsafe { (*ss).next.load(Ordering::Relaxed) };
        free(ss.cast());
        ss = next;
    }
    let mut ca = REAP_CONTROL_AREAS.swap(core::ptr::null_mut(), Ordering::AcqRel);
    while !ca.is_null() {
        // SAFETY: a control area nothing names any more: every page and
        // view is gone, so every subsection was reaped above or earlier.
        unsafe {
            let next = (*ca).next.load(Ordering::Relaxed);
            trace(format_args!(
                "delete control area {ca:p} of {:p}",
                (*ca).file
            ));
            free((*ca).dir.get().cast());
            object::dereference((*ca).file.cast());
            free(ca.cast());
            ca = next;
        }
    }
}

/// Take a standby page from its file for the allocator: the oldest.
/// False if standby is empty.
pub fn reclaim(g: &mut Guard) -> bool {
    let f = pfn::frames(g);
    let Some((frame, pte, original)) = f.db.reclaim() else {
        return false;
    };
    pfn::give_back_released(g, frame);
    let (ss, index) = locate_proto(original, pte);
    // SAFETY: a page in memory keeps its subsection alive.
    let ss = unsafe { &*ss };
    ss.protos[index].store(original, Ordering::Relaxed);
    page_left(g, ss);
    true
}

/// A line of `trace=mm`.
pub fn trace(what: core::fmt::Arguments<'_>) {
    if crate::kd::trace_mm() {
        kprintln!("NK-MM {what}");
    }
}

/// Whether the current thread's paging I/O is the cache manager's own
/// flush, or clustering is off for it (`MmIsRecursiveIoFault`).
pub fn is_recursive_io_fault() -> bool {
    use nk_ntabi::thread::{CACHE_MANAGER_ACTIVE, DISABLE_PAGE_FAULT_CLUSTERING};
    let thread = crate::ke::pcr::current_thread();
    // SAFETY: the current thread's ETHREAD; the fields are its own bytes.
    unsafe {
        thread.add(DISABLE_PAGE_FAULT_CLUSTERING).read() != 0
            || thread.add(CACHE_MANAGER_ACTIVE).read() == 1
    }
}
