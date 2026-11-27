//! Resolving a page of a section: the one path by which a page becomes
//! valid, for a touch of a view (the trap handler), for the cache
//! manager's own calls and for read-ahead.
//!
//! The prototype PTE decides:
//! - valid: the frame gains a mapping;
//! - transition: the frame is on a list (a soft fault: it comes off) or
//!   under I/O; a read in flight is waited for (a collided fault) and
//!   the resolution starts again;
//! - subsection: the page is in the file only (a hard fault). Frames are
//!   taken for it and for up to 15 more pages after it that are in the
//!   file only too, within its subsection and the section, unless the
//!   thread's paging I/O is the cache manager's own flush
//!   (`MmIsRecursiveIoFault`); each prototype PTE becomes a transition
//!   PTE whose frame is being read, and one synchronous paging read
//!   (`io::paging`) fills them all. On success the faulting page is
//!   mapped and the others go to standby. On failure the frames are
//!   freed, the prototype PTEs are as they were, and every thread that
//!   waited gets the read's status.
//!
//! Nothing waits or allocates under the PFN lock: the in-page block is
//! allocated before it is taken, and the lock is dropped across the
//! read and every wait.

use super::cache::valid_entry;
use super::pfn::{self, Guard};
use super::section::{self, Subsection};
use super::{PAGE_SIZE, phys_to_virt, pool};
use crate::io::paging;
use crate::ke::wait;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, Ordering};
use nk_mm::pfn::flag;
use nk_mm::pte::Proto;
use nk_mm::section::SUBSECTION_PAGES;
use nk_ntabi::io::{
    IO_STATUS_BLOCK, MDL, MDL_IO_PAGE_READ, MDL_MAPPED_TO_SYSTEM_VA, MDL_PAGES_LOCKED,
};
use nk_ntabi::ke::KEVENT;
use nk_ntabi::status::*;

const TAG_IN_PAGE: u32 = u32::from_le_bytes(*b"MmIn");
/// The largest read: the faulting page and fifteen after it, as many as
/// Windows' in-page block (`_MMINPAGE_SUPPORT`) has room for.
pub const CLUSTER: usize = 16;

/// How a page is wanted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// In memory, reading it if need be.
    FaultIn,
    /// In memory, with no read: a page in the file only gets a zeroed
    /// frame (its caller overwrites it).
    NoRead,
    /// Only if it is in memory.
    NoIo,
}

/// What became of the page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Got {
    Resident,
    /// [`Mode::NoIo`], and the page is in the file only.
    NeedsIo,
}

/// One read in flight: what its waiters wait on, and the MDL it reads
/// into, with room for a cluster.
#[repr(C)]
struct InPage {
    /// Signalled once the pages are settled, for the waiters.
    event: KEVENT,
    /// The paging request's own event.
    io_event: KEVENT,
    iosb: IO_STATUS_BLOCK,
    /// The reader's reference and each waiter's.
    refs: AtomicU32,
    status: AtomicI32,
    mdl: MDL,
    pages: [u64; CLUSTER],
}

impl InPage {
    fn new() -> *mut InPage {
        let block = pool::alloc_zeroed(size_of::<InPage>(), TAG_IN_PAGE).cast::<InPage>();
        if !block.is_null() {
            // SAFETY: a fresh block of the right size.
            unsafe {
                wait::KeInitializeEvent(&raw mut (*block).event, 0, 0);
                wait::KeInitializeEvent(&raw mut (*block).io_event, 0, 0);
            }
        }
        block
    }

    /// Drop a reference; the last frees the block.
    ///
    /// # Safety
    /// The caller holds a reference to the live block.
    unsafe fn release(block: *mut InPage) {
        // SAFETY: per the contract.
        if unsafe { (*block).refs.fetch_sub(1, Ordering::AcqRel) } == 1
            && let Err(e) = pool::free(block.cast())
        {
            crate::kd::bugcheck(format_args!("mm: freeing an in-page block: {e:?}"));
        }
    }
}

/// Make page `index` of subsection `ss` resident as `mode` asks and, with
/// `view` (the page-table entry of a mapped view of it), valid there.
/// `Err` is the status of a read that failed.
///
/// The caller keeps `ss` alive: a view of it, or a hold like one.
pub fn resolve(
    ss: *mut Subsection,
    index: usize,
    view: Option<&AtomicU64>,
    mode: Mode,
) -> Result<Got, NTSTATUS> {
    let mut block: *mut InPage = core::ptr::null_mut();
    let result = loop {
        let mut g = pfn::lock();
        let a = crate::arch::pt_arch();
        if view.is_some_and(|v| nk_mm::pt::Arch::present(&a, v.load(Ordering::Acquire))) {
            break Ok(Got::Resident);
        }
        // SAFETY: kept alive by the caller; the lock guards the PTEs.
        let ss_ref = unsafe { &*ss };
        let proto = &ss_ref.protos[index];
        match Proto::decode(proto.load(Ordering::Relaxed)) {
            Proto::Valid(frame) => {
                if let Some(v) = view {
                    map(&mut g, frame, proto, v);
                }
                break Ok(Got::Resident);
            }
            Proto::Transition(frame) => {
                let e = *pfn::frames(&mut g).db.get(frame);
                if e.has(flag::READ_IN_PROGRESS) {
                    let reading = e.io as *mut InPage;
                    // SAFETY: the reader's reference keeps the block
                    // while the frame says it is being read.
                    unsafe { (*reading).refs.fetch_add(1, Ordering::AcqRel) };
                    drop(g);
                    // SAFETY: the reference just taken.
                    let status = unsafe { collided(reading) };
                    if nt_error(status) {
                        break Err(status);
                    }
                    continue;
                }
                if let Some(v) = view {
                    map(&mut g, frame, proto, v);
                }
                break Ok(Got::Resident);
            }
            Proto::Subsection(_) => match mode {
                Mode::NoIo => break Ok(Got::NeedsIo),
                Mode::NoRead => break zero_fill(&mut g, ss_ref, index, view),
                Mode::FaultIn if block.is_null() => {
                    drop(g);
                    block = InPage::new();
                    if block.is_null() {
                        break Err(STATUS_INSUFFICIENT_RESOURCES);
                    }
                }
                Mode::FaultIn => {
                    let taken = core::mem::replace(&mut block, core::ptr::null_mut());
                    break hard_fault(g, ss_ref, index, view, taken);
                }
            },
            Proto::Zero => crate::kd::bugcheck(format_args!(
                "mm: a prototype PTE of subsection {ss:p} is empty"
            )),
        }
    };
    if !block.is_null() {
        // SAFETY: allocated here and never shared: the only reference.
        unsafe {
            (*block).refs.store(1, Ordering::Relaxed);
            InPage::release(block);
        }
    }
    section::reap();
    result
}

/// Map `frame`, which `proto` owns, at the view entry `v`: one more
/// valid mapping, a soft fault if it was on a list.
fn map(g: &mut Guard, frame: u64, proto: &AtomicU64, v: &AtomicU64) {
    match pfn::frames(g).db.share(frame) {
        Ok(soft) => {
            if soft {
                section::trace(format_args!("soft fault frame {frame:#x}"));
            }
        }
        Err(e) => crate::kd::bugcheck(format_args!("mm: mapping a section's page: {}", e.0)),
    }
    proto.store(Proto::Valid(frame).encode(), Ordering::Relaxed);
    v.store(valid_entry(frame), Ordering::Release);
}

/// Wait for a read in flight; returns its status.
///
/// # Safety
/// The caller holds a reference to the live block, which this gives up.
unsafe fn collided(block: *mut InPage) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        wait_for(&raw mut (*block).event);
        let status = (*block).status.load(Ordering::Acquire);
        InPage::release(block);
        status
    }
}

fn wait_for(event: *mut KEVENT) {
    // SAFETY: a live event; an Executive, kernel-mode, non-alertable
    // wait with no time-out.
    unsafe { wait::KeWaitForSingleObject(event.cast(), 0, 0, 0, core::ptr::null()) };
}

/// Undo the system mapping a driver made of a paging request's MDL
/// (`MmGetSystemAddressForMdlSafe`), as the memory manager does when the
/// request is over: the MDL is the memory manager's.
///
/// # Safety
/// `mdl` is a live MDL no driver holds any more.
pub unsafe fn unmap_system(mdl: *mut MDL) {
    // SAFETY: per the contract.
    unsafe {
        if (*mdl).MdlFlags & MDL_MAPPED_TO_SYSTEM_VA != 0 {
            crate::io::mdl::MmUnmapLockedPages((*mdl).MappedSystemVa, mdl);
        }
    }
}

/// A frame for a page, from the allocator or standby; the lock stays
/// held throughout.
fn take_frame(g: &mut Guard) -> Option<u64> {
    pfn::take(g, 1, None)
}

/// A page in the file only becomes a zeroed frame, mapped at `view`.
fn zero_fill(
    g: &mut Guard,
    ss: &Subsection,
    index: usize,
    view: Option<&AtomicU64>,
) -> Result<Got, NTSTATUS> {
    let Some(view) = view else {
        crate::kd::bugcheck(format_args!("mm: a page is zero-filled with no view"));
    };
    let frame = take_frame(g).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    // SAFETY: the frame is ours; the direct map covers it.
    unsafe { core::ptr::write_bytes(phys_to_virt(frame * PAGE_SIZE as u64), 0, PAGE_SIZE) };
    let proto = &ss.protos[index];
    let original = proto.load(Ordering::Relaxed);
    pfn::frames(g).db.allocate(
        frame,
        core::ptr::from_ref(proto).addr() as u64,
        original,
        false,
    );
    proto.store(Proto::Valid(frame).encode(), Ordering::Relaxed);
    view.store(valid_entry(frame), Ordering::Release);
    page_entered(ss, 1);
    Ok(Got::Resident)
}

/// `pages` frames now hold pages of `ss`.
fn page_entered(ss: &Subsection, pages: u32) {
    ss.resident.set(ss.resident.get() + pages);
    // SAFETY: a subsection's control area outlives it.
    let ca = unsafe { &*ss.ca };
    ca.pfn_refs.set(ca.pfn_refs.get() + u64::from(pages));
}

/// Read page `index` of `ss`, and a cluster after it, with `block`;
/// map it at `view` if there is one.
fn hard_fault(
    mut g: Guard,
    ss: &Subsection,
    index: usize,
    view: Option<&AtomicU64>,
    block: *mut InPage,
) -> Result<Got, NTSTATUS> {
    // SAFETY: a subsection's control area outlives it.
    let ca = unsafe { &*ss.ca };
    let in_section = ((ca.size.get() / PAGE_SIZE as u64).saturating_sub(ss.first_page) as usize)
        .min(SUBSECTION_PAGES);
    let most = if section::is_recursive_io_fault() {
        1
    } else {
        CLUSTER
    };
    let mut count = 0;
    while count < most && index + count < in_section {
        let proto = &ss.protos[index + count];
        let original = proto.load(Ordering::Relaxed);
        if !matches!(Proto::decode(original), Proto::Subsection(_)) {
            break;
        }
        let Some(frame) = take_frame(&mut g) else {
            break;
        };
        let db = &mut pfn::frames(&mut g).db;
        db.allocate(
            frame,
            core::ptr::from_ref(proto).addr() as u64,
            original,
            true,
        );
        db.get_mut(frame).io = block.addr() as u64;
        proto.store(Proto::Transition(frame).encode(), Ordering::Relaxed);
        // SAFETY: the block is this read's alone until the lock drops.
        unsafe { (*block).pages[count] = frame };
        count += 1;
    }
    if count == 0 {
        drop(g);
        // SAFETY: allocated by the caller, shared with no one.
        unsafe {
            (*block).refs.store(1, Ordering::Relaxed);
            InPage::release(block);
        }
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    page_entered(ss, count as u32);
    let file = ca.file;
    let offset = (ss.first_page + index as u64) * PAGE_SIZE as u64;
    let bytes = count * PAGE_SIZE;
    // SAFETY: the block is ours; its MDL describes the frames just
    // taken, which the read's reference keeps.
    unsafe {
        (*block).refs.store(1, Ordering::Relaxed);
        let mdl = &raw mut (*block).mdl;
        (*mdl).Size = (size_of::<MDL>() + count * 8) as i16;
        (*mdl).MdlFlags = MDL_PAGES_LOCKED | MDL_IO_PAGE_READ;
        (*mdl).StartVa = (ss.view_va.get() + (index * PAGE_SIZE) as u64) as *mut _;
        (*mdl).ByteCount = bytes as u32;
    }
    drop(g);
    section::trace(format_args!("read {file:p} at {offset:#x}, {count} pages"));
    // SAFETY: the file is referenced by the control area; the MDL,
    // event and status block are the block's, which lives until the
    // event is signalled and seen.
    let status = unsafe {
        let sent = paging::page_read(
            file,
            &raw mut (*block).mdl,
            offset as i64,
            &raw mut (*block).io_event,
            &raw mut (*block).iosb,
        );
        if sent == STATUS_PENDING {
            wait_for(&raw mut (*block).io_event);
        }
        unmap_system(&raw mut (*block).mdl);
        let iosb = (*block).iosb;
        if !nt_error(iosb.Status) && iosb.Information < bytes {
            // What the file did not give is zero.
            for (k, &frame) in (&(*block).pages)[..count].iter().enumerate() {
                let start = (k * PAGE_SIZE).max(iosb.Information) - k * PAGE_SIZE;
                if start < PAGE_SIZE {
                    core::ptr::write_bytes(
                        phys_to_virt(frame * PAGE_SIZE as u64).add(start),
                        0,
                        PAGE_SIZE - start,
                    );
                }
            }
        }
        iosb.Status
    };
    let mut g = pfn::lock();
    let no_write = ca.no_write();
    for k in 0..count {
        // SAFETY: the block is ours again: no read is in flight.
        let frame = unsafe { (*block).pages[k] };
        let proto = &ss.protos[index + k];
        let db = &mut pfn::frames(&mut g).db;
        if nt_error(status) {
            db.get_mut(frame).flags |= flag::IN_PAGE_ERROR;
            match db.release(frame) {
                Ok((_, original)) => proto.store(original, Ordering::Relaxed),
                Err(e) => crate::kd::bugcheck(format_args!("mm: a failed read: {}", e.0)),
            }
            pfn::give_back_released(&mut g, frame);
            section::page_left(&g, ss);
            continue;
        }
        db.read_done(frame);
        if k == 0
            && let Some(v) = view
        {
            map(&mut g, frame, proto, v);
        }
        if let Err(e) = pfn::frames(&mut g).db.dereference(frame, no_write, false) {
            crate::kd::bugcheck(format_args!("mm: a read finished: {}", e.0));
        }
    }
    // SAFETY: the block lives while this holds its reference.
    unsafe {
        (*block).status.store(status, Ordering::Release);
        wait::KeSetEvent(&raw mut (*block).event, 0, 0);
    }
    drop(g);
    // SAFETY: this read's reference.
    unsafe { InPage::release(block) };
    if nt_error(status) {
        section::trace(format_args!(
            "read {file:p} at {offset:#x} failed: {status:#x}"
        ));
        return Err(status);
    }
    Ok(Got::Resident)
}
