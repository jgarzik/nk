//! Writing, purging and truncating a file's data section: what the
//! cache manager and file systems ask of it beyond mapping it.
//!
//! A flush writes the range's modified pages with synchronous paging
//! writes (`io::paging`), runs of at most 16 contiguous pages each,
//! with `ETHREAD.CacheManagerActive` set as `MmFlushSection` sets it,
//! so the file system knows the write for the cache manager's own
//! (`MmIsRecursiveIoFault`). A page is clean from the moment its write
//! starts (its view entry's dirty bit cleared, its translation dropped);
//! one written again meanwhile is dirty again. A failed write leaves its
//! pages modified, and a write that failed for want of memory or over a
//! bad sector is tried again page by page (`MiIsRetryIoStatus`).

use super::pfn::{self, Guard};
use super::section::{self, ControlArea, Subsection};
use super::{PAGE_SIZE, pool};
use crate::arch;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use nk_mm::pfn::{Location, flag};
use nk_mm::pt::Arch;
use nk_mm::pte::{self, Proto};
use nk_mm::section::{self as rule, SUBSECTION_PAGES};
use nk_ntabi::io::{FILE_OBJECT, IO_STATUS_BLOCK, MDL, MDL_PAGES_LOCKED, SECTION_OBJECT_POINTERS};
use nk_ntabi::ke::KEVENT;
use nk_ntabi::status::*;
use nk_ntabi::thread::CACHE_MANAGER_ACTIVE;

/// The pages `range` (offset and length; `None`: all) covers of a
/// section of `size` bytes, as `(subsection, first page, end page)`
/// runs.
fn runs(range: Option<(u64, u32)>, size: u64) -> impl Iterator<Item = (usize, usize, usize)> {
    let (start, end) = match range {
        Some((offset, 0)) => (offset, size),
        Some((offset, len)) => (offset, (offset + u64::from(len)).min(size)),
        None => (0, size),
    };
    let first = start / PAGE_SIZE as u64;
    let last = end.div_ceil(PAGE_SIZE as u64);
    let per = SUBSECTION_PAGES as u64;
    (first / per..last.div_ceil(per)).map(move |i| {
        let lo = first.max(i * per) - i * per;
        let hi = last.min((i + 1) * per) - i * per;
        (i as usize, lo as usize, hi as usize)
    })
}

/// `MmPurgeSection`: discard the pages `range` covers of the file's data
/// section, modified ones too, so that the next access reads the file.
/// False, changing nothing, when Windows' rule refuses
/// (`MiCanFileBeTruncatedInternal` with the purge's checks: being made
/// or deleted, pages locked, and with `require_no_views` any view
/// mapped), or when a page in the range is under I/O. A page a
/// system-cache view maps is taken out of the view first. True if the
/// file has no data section.
pub fn purge_section(
    sop: *mut SECTION_OBJECT_POINTERS,
    range: Option<(u64, u32)>,
    require_no_views: bool,
) -> bool {
    let purged = {
        let mut g = pfn::lock();
        match section::control_area(&g, sop) {
            None => true,
            Some(ca) => {
                let offset = range.map_or(0, |(offset, _)| offset);
                rule::can_truncate(&ca.counts(), Some(offset), true, !require_no_views)
                    && purge(&mut g, ca, range)
            }
        }
    };
    section::reap();
    section::trace(format_args!("purge {sop:p} {range:x?}: {purged}"));
    purged
}

/// Discard the pages of `ca` in `range`, once none is busy.
fn purge(g: &mut Guard, ca: &ControlArea, range: Option<(u64, u32)>) -> bool {
    let size = ca.size.get();
    // Refuse before anything changes: a page under I/O or locked.
    for (i, lo, hi) in runs(range, size) {
        let ss = ca.subsection(g, i);
        // SAFETY: a subsection in the directory is live under the lock.
        let Some(ss) = (unsafe { ss.as_ref() }) else {
            continue;
        };
        for proto in &ss.protos[lo..hi] {
            let (Proto::Valid(frame) | Proto::Transition(frame)) =
                Proto::decode(proto.load(Ordering::Relaxed))
            else {
                continue;
            };
            let e = pfn::frames(g).db.get(frame);
            if e.has(flag::READ_IN_PROGRESS | flag::WRITE_IN_PROGRESS)
                || e.ref_count > u16::from(e.share_count != 0)
            {
                return false;
            }
        }
    }
    let a = arch::pt_arch();
    let no_write = ca.no_write();
    for (i, lo, hi) in runs(range, size) {
        let ss = ca.subsection(g, i);
        // SAFETY: as above.
        let Some(ss) = (unsafe { ss.as_ref() }) else {
            continue;
        };
        let view = ss.view_va.get();
        for (j, proto) in ss.protos.iter().enumerate().take(hi).skip(lo) {
            let frame = match Proto::decode(proto.load(Ordering::Relaxed)) {
                Proto::Valid(frame) => {
                    // Mapped by its view only: out of the view first.
                    let va = view + (j * PAGE_SIZE) as u64;
                    let entry = super::cache::entry_of(va);
                    let old = entry.swap(
                        pte::prototype_pointer(core::ptr::from_ref(proto).addr() as u64),
                        Ordering::AcqRel,
                    );
                    arch::flush_tlb_page(va);
                    let db = &mut pfn::frames(g).db;
                    if a.present(old) && a.dirty(old) {
                        db.get_mut(frame).flags |= flag::MODIFIED;
                    }
                    if let Err(e) = db.unshare(frame, no_write, false) {
                        crate::kd::bugcheck(format_args!("mm: purging a mapped page: {}", e.0));
                    }
                    frame
                }
                Proto::Transition(frame) => frame,
                _ => continue,
            };
            debug_assert!(matches!(
                pfn::frames(g).db.get(frame).location(),
                Location::Standby | Location::Modified | Location::ModifiedNoWrite
            ));
            match pfn::frames(g).db.release(frame) {
                Ok((_, original)) => proto.store(original, Ordering::Relaxed),
                Err(e) => crate::kd::bugcheck(format_args!("mm: purging a page: {}", e.0)),
            }
            pfn::give_back_released(g, frame);
            section::page_left(g, ss);
        }
    }
    ca.flags.set(ca.flags.get() | rule::flag::WAS_PURGED);
    true
}

/// The most pages one flush write carries.
const WRITE_CLUSTER: usize = 16;
const TAG_FLUSH: u32 = u32::from_le_bytes(*b"MmFl");

/// How a flush acquires the file for the cache manager's flush, and
/// releases it (`FsRtlAcquireFileForCcFlushEx`, `FsRtlReleaseFileForCcFlush`):
/// the cache manager passes FsRtl's routines when `MmFlushSection` is
/// asked to acquire the file.
#[derive(Clone, Copy)]
pub struct FlushAcquire {
    pub acquire: fn(*mut FILE_OBJECT) -> NTSTATUS,
    pub release: fn(*mut FILE_OBJECT),
}

/// `MmFlushSection`: write the modified pages `range` covers (`None`:
/// the whole section) to the file, and wait for the writes. With
/// `acquire`, the file is acquired around them. `Information` is the
/// bytes written; `Status` the first failure, or success. A file with no
/// data section has nothing to write.
pub fn flush_section(
    sop: *mut SECTION_OBJECT_POINTERS,
    range: Option<(u64, u32)>,
    acquire: Option<FlushAcquire>,
) -> IO_STATUS_BLOCK {
    let mut result = IO_STATUS_BLOCK {
        Status: STATUS_SUCCESS,
        Information: 0,
    };
    let ca = {
        let g = pfn::lock();
        let Some(ca) = section::control_area(&g, sop) else {
            return result;
        };
        // The flush holds the control area, and with it the file.
        ca.flushes.set(ca.flushes.get() + 1);
        ca
    };
    let thread = crate::ke::pcr::current_thread();
    // SAFETY: the current thread's own ETHREAD byte.
    let was = unsafe { thread.add(CACHE_MANAGER_ACTIVE).replace(1) };
    let file = ca.file;
    let status = acquire.map_or(STATUS_SUCCESS, |a| (a.acquire)(file));
    if nt_error(status) {
        result.Status = status;
    } else {
        let block =
            pool::alloc_zeroed(size_of::<MDL>() + WRITE_CLUSTER * 8, TAG_FLUSH).cast::<MDL>();
        if block.is_null() {
            result.Status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            for (i, lo, hi) in runs(range, ca.size.get()) {
                flush_subsection(ca, i, lo, hi, block, &mut result);
            }
            let _ = pool::free(block.cast());
        }
        if let Some(a) = acquire {
            (a.release)(file);
        }
    }
    // SAFETY: as above.
    unsafe { thread.add(CACHE_MANAGER_ACTIVE).write(was) };
    {
        let g = pfn::lock();
        ca.flushes.set(ca.flushes.get() - 1);
        section::check(&g, ca);
    }
    section::reap();
    section::trace(format_args!(
        "flush {sop:p} {range:x?}: {:#x}, {:#x} bytes",
        result.Status, result.Information
    ));
    result
}

/// Write the modified pages `lo..hi` of subsection `i` of `ca`.
fn flush_subsection(
    ca: &ControlArea,
    i: usize,
    lo: usize,
    hi: usize,
    mdl: *mut MDL,
    result: &mut IO_STATUS_BLOCK,
) {
    let ss = {
        let g = pfn::lock();
        let ss = ca.subsection(&g, i);
        // SAFETY: live in the directory, under the lock.
        let Some(ss) = (unsafe { ss.as_ref() }) else {
            return;
        };
        // Held like a view while the lock is dropped.
        ss.views.set(ss.views.get() + 1);
        ss
    };
    let (mut j, mut alone_until) = (lo, lo);
    while j < hi {
        let most = if j < alone_until { 1 } else { WRITE_CLUSTER };
        let (start, frames) = match gather(ss, j, hi, most) {
            Gathered::Run(start, frames) => (start, frames),
            Gathered::Busy(at) => {
                // Another write of the page is in flight: wait it out.
                crate::ke::thread::sleep();
                j = at;
                continue;
            }
            Gathered::Clean => break,
        };
        let status = write(ca, ss, start, &frames, mdl);
        let bytes = (frames.len() * PAGE_SIZE) as u64;
        if !nt_error(status) {
            result.Information += bytes as usize;
        } else if frames.len() > 1 && rule::is_retry_status(status, bytes) {
            alone_until = start + frames.len();
            j = start;
            continue;
        } else if !nt_error(result.Status) {
            result.Status = status;
        }
        j = start + frames.len();
    }
    let g = pfn::lock();
    ss.views.set(ss.views.get() - 1);
    section::unused_subsection(&g, ss);
}

enum Gathered {
    /// A run of modified pages, each held and marked as being written:
    /// its first page and frames.
    Run(usize, Vec<u64>),
    /// The page at this index is being written by another flush.
    Busy(usize),
    /// No modified page from where the search began.
    Clean,
}

/// From page `j` on (before `hi`), the first run of at most `most`
/// modified pages, taken for writing.
fn gather(ss: &Subsection, mut j: usize, hi: usize, most: usize) -> Gathered {
    let mut frames = Vec::with_capacity(WRITE_CLUSTER);
    let a = arch::pt_arch();
    let mut g = pfn::lock();
    let view = ss.view_va.get();
    let mut start = j;
    while j < hi && frames.len() < most {
        let frame = match Proto::decode(ss.protos[j].load(Ordering::Relaxed)) {
            Proto::Valid(frame) => {
                if view != 0 {
                    // The view's record of writes goes to the PFN entry.
                    let va = view + (j * PAGE_SIZE) as u64;
                    let entry = super::cache::entry_of(va);
                    let e = entry.load(Ordering::Acquire);
                    if a.present(e) && a.dirty(e) {
                        entry.store(a.clean(e), Ordering::Release);
                        arch::flush_tlb_page(va);
                        pfn::frames(&mut g).db.get_mut(frame).flags |= flag::MODIFIED;
                    }
                }
                Some(frame)
            }
            Proto::Transition(frame) => Some(frame),
            _ => None,
        };
        let e = frame.map(|f| *pfn::frames(&mut g).db.get(f));
        match (frame, e) {
            (Some(frame), Some(e)) if e.has(flag::MODIFIED) && !e.has(flag::READ_IN_PROGRESS) => {
                if e.has(flag::WRITE_IN_PROGRESS) {
                    if frames.is_empty() {
                        return Gathered::Busy(j);
                    }
                    break;
                }
                let db = &mut pfn::frames(&mut g).db;
                if let Err(e) = db.reference(frame) {
                    crate::kd::bugcheck(format_args!("mm: flushing a page: {}", e.0));
                }
                let entry = db.get_mut(frame);
                entry.flags = entry.flags & !flag::MODIFIED | flag::WRITE_IN_PROGRESS;
                if frames.is_empty() {
                    start = j;
                }
                frames.push(frame);
            }
            _ if frames.is_empty() => {}
            _ => break,
        }
        j += 1;
    }
    if frames.is_empty() {
        Gathered::Clean
    } else {
        Gathered::Run(start, frames)
    }
}

/// Write `frames`, pages `start..` of `ss`, and settle them by the
/// result. Returns the write's status.
fn write(
    ca: &ControlArea,
    ss: &Subsection,
    start: usize,
    frames: &[u64],
    mdl: *mut MDL,
) -> NTSTATUS {
    let offset = (ss.first_page + start as u64) * PAGE_SIZE as u64;
    let mut event = core::mem::MaybeUninit::<KEVENT>::zeroed();
    let mut iosb = IO_STATUS_BLOCK {
        Status: STATUS_PENDING,
        Information: 0,
    };
    section::trace(format_args!(
        "write {:p} at {offset:#x}, {} pages",
        ca.file,
        frames.len()
    ));
    // SAFETY: the flush's own MDL block, with room for a cluster; the
    // frames are held by the write's references; the event and status
    // block live on this stack until the event is signalled.
    let status = unsafe {
        core::ptr::write_bytes(mdl.cast::<u8>(), 0, size_of::<MDL>() + WRITE_CLUSTER * 8);
        (*mdl).Size = (size_of::<MDL>() + frames.len() * 8) as i16;
        (*mdl).MdlFlags = MDL_PAGES_LOCKED;
        (*mdl).StartVa = (ss.view_va.get() + (start * PAGE_SIZE) as u64) as *mut _;
        (*mdl).ByteCount = (frames.len() * PAGE_SIZE) as u32;
        let pages = mdl.add(1).cast::<u64>();
        for (k, &frame) in frames.iter().enumerate() {
            pages.add(k).write(frame);
        }
        crate::ke::wait::KeInitializeEvent(event.as_mut_ptr(), 0, 0);
        let sent = crate::io::paging::synchronous_page_write(
            ca.file,
            mdl,
            offset as i64,
            event.as_mut_ptr(),
            &raw mut iosb,
            0,
        );
        if sent == STATUS_PENDING {
            crate::ke::wait::KeWaitForSingleObject(
                event.as_mut_ptr().cast(),
                0,
                0,
                0,
                core::ptr::null(),
            );
        }
        super::fault::unmap_system(mdl);
        iosb.Status
    };
    let mut g = pfn::lock();
    let no_write = ca.no_write();
    for &frame in frames {
        let db = &mut pfn::frames(&mut g).db;
        let e = db.get_mut(frame);
        e.flags &= !flag::WRITE_IN_PROGRESS;
        if nt_error(status) {
            e.flags |= flag::MODIFIED;
        }
        if let Err(e) = db.dereference(frame, no_write, false) {
            crate::kd::bugcheck(format_args!("mm: a flush write finished: {}", e.0));
        }
    }
    status
}

/// `MmCanFileBeTruncated`: whether the file may be cut to `new_size`
/// (`None`: to no size the caller names), by Windows' rule: true with no
/// data section; false while it is being made or deleted, while a page is
/// locked (unless only the cache manager writes it); true with no user
/// reference; else only for a size at or beyond the section's end. NK
/// makes no image sections, so none is there to flush first.
pub fn can_file_be_truncated(sop: *mut SECTION_OBJECT_POINTERS, new_size: Option<u64>) -> bool {
    let g = pfn::lock();
    section::control_area(&g, sop)
        .is_none_or(|ca| rule::can_truncate(&ca.counts(), new_size, false, false))
}

/// [`MmCanFileBeTruncated`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-mmcanfilebetruncated).
///
/// # Safety
/// `sop` is a file's section object pointers; `new_size` null or
/// readable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn MmCanFileBeTruncated(
    sop: *mut SECTION_OBJECT_POINTERS,
    new_size: *const i64,
) -> u8 {
    // SAFETY: per the contract.
    let size = unsafe { new_size.as_ref() }.map(|&s| s as u64);
    u8::from(can_file_be_truncated(sop, size))
}

/// [`MmFlushImageSection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-mmflushimagesection):
/// for `MmFlushForDelete` (0), false while the data section has user
/// references, is being made, or has pages locked; then the image
/// section would be deleted, but NK makes none. True otherwise.
///
/// # Safety
/// `sop` is a file's section object pointers.
#[allow(non_snake_case)]
pub unsafe extern "C" fn MmFlushImageSection(
    sop: *mut SECTION_OBJECT_POINTERS,
    flush_type: u32,
) -> u8 {
    const MM_FLUSH_FOR_DELETE: u32 = 0;
    let g = pfn::lock();
    if flush_type == MM_FLUSH_FOR_DELETE
        && let Some(ca) = section::control_area(&g, sop)
        && (ca.user_refs.get() != 0
            || ca.flags.get() & rule::flag::BEING_CREATED != 0
            || ca.locked_pages.get() > 1)
    {
        return 0;
    }
    1
}

/// [`MmDoesFileHaveUserWritableReferences`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-mmdoesfilehaveuserwritablereferences):
/// whether the data section has writable user views, as 1 or 0.
///
/// # Safety
/// `sop` is a file's section object pointers.
#[allow(non_snake_case)]
pub unsafe extern "C" fn MmDoesFileHaveUserWritableReferences(
    sop: *mut SECTION_OBJECT_POINTERS,
) -> u32 {
    let g = pfn::lock();
    u32::from(section::control_area(&g, sop).is_some_and(|ca| ca.writable_user_refs.get() != 0))
}

/// `MmOnlySystemCacheViewsPresent`: whether every view of the data
/// section is the system cache's.
pub fn only_system_cache_views(sop: *mut SECTION_OBJECT_POINTERS) -> bool {
    let g = pfn::lock();
    section::control_area(&g, sop).is_none_or(|ca| ca.mapped_views.get() == ca.cache_views.get())
}

/// Frames the allocator can hand out now: free, or on standby.
pub fn available_pages() -> usize {
    let [free, standby, _, _] = pfn::counts();
    (free + standby) as usize
}

/// Where the page at an offset of a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilePage {
    /// In the file only.
    Absent,
    /// In memory: its frame, where it is, whether it is modified, and
    /// its references.
    Resident {
        frame: u64,
        location: Location,
        modified: bool,
        references: u16,
    },
}

/// The page at `offset` of the file's data section, for tests and
/// traces.
pub fn page_of_file(sop: *mut SECTION_OBJECT_POINTERS, offset: u64) -> FilePage {
    let mut g = pfn::lock();
    let Some(ca) = section::control_area(&g, sop) else {
        return FilePage::Absent;
    };
    let (index, page) = rule::locate(offset);
    // SAFETY: live in the directory, under the lock.
    let Some(ss) = (unsafe { ca.subsection(&g, index).as_ref() }) else {
        return FilePage::Absent;
    };
    match Proto::decode(ss.protos[page].load(Ordering::Relaxed)) {
        Proto::Valid(frame) | Proto::Transition(frame) => {
            let e = *pfn::frames(&mut g).db.get(frame);
            FilePage::Resident {
                frame,
                location: e.location(),
                modified: e.has(flag::MODIFIED),
                references: e.ref_count,
            }
        }
        _ => FilePage::Absent,
    }
}

/// [`MmQuerySystemSize`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmquerysystemsize):
/// `MmLargeSystem`, as the pinned kernel answers whatever the memory.
#[allow(non_snake_case)]
pub extern "C" fn MmQuerySystemSize() -> u32 {
    2
}

/// `MmMdlPageContentsState`: with `MdlPageContentsQuery` (2), whether
/// the MDL says its pages' contents are known (flag 0x4000); else set
/// (`MdlPageContentsValid`, 1) or clear (any other) that flag and return
/// the state given, as the pinned kernel does.
///
/// # Safety
/// `mdl` is a live MDL.
#[allow(non_snake_case)]
pub unsafe extern "C" fn MmMdlPageContentsState(mdl: *mut MDL, state: u32) -> u32 {
    const CONTENTS: i16 = 0x4000;
    // SAFETY: per the contract.
    unsafe {
        if state == 2 {
            return u32::from((*mdl).MdlFlags & CONTENTS != 0);
        }
        if state == 1 {
            (*mdl).MdlFlags |= CONTENTS;
        } else {
            (*mdl).MdlFlags &= !CONTENTS;
        }
    }
    state
}
