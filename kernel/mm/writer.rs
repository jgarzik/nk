//! Mapped-page writer (`MiMappedPageWriter`): background kernel thread that
//! flushes dirty unmapped data-file frames from `Location::Modified` to their
//! backing files in contiguous 16-page paging-write clusters, moving each
//! cleaned frame onto `Location::Standby` for immediate reclaim.

use super::PAGE_SIZE;
use super::pfn;
use super::section::{self, ControlArea, Subsection};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nk_mm::pfn::flag;
use nk_mm::pte::Proto;
use nk_mm::section::SUBSECTION_PAGES;
use nk_ntabi::io::{IO_STATUS_BLOCK, MDL, MDL_PAGES_LOCKED};
use nk_ntabi::ke::KEVENT;
use nk_ntabi::status::*;

const WRITE_CLUSTER: usize = 16;
/// Priority 17 (`LOW_REALTIME_PRIORITY + 1`), matching Windows `MiMappedPageWriter`.
const WRITER_PRIORITY: u8 = 17;

/// Stack-backed MDL with trailing PFN slots for one write cluster (zero pool traffic).
#[repr(C)]
struct WriterMdl {
    mdl: MDL,
    pages: [u64; WRITE_CLUSTER],
}

struct Events {
    wake: UnsafeCell<MaybeUninit<KEVENT>>,
    progress: UnsafeCell<MaybeUninit<KEVENT>>,
}

// SAFETY: initialized once in `init()` before starting the writer thread and
// accessed only via NT event primitives.
unsafe impl Sync for Events {}

static EVENTS: Events = Events {
    wake: UnsafeCell::new(MaybeUninit::uninit()),
    progress: UnsafeCell::new(MaybeUninit::uninit()),
};
static STARTED: AtomicBool = AtomicBool::new(false);
static CLUSTERS_WRITTEN: AtomicU64 = AtomicU64::new(0);
static PAGES_WRITTEN: AtomicU64 = AtomicU64::new(0);

/// Start the mapped-page writer system thread. Called once during boot after `cc::init`.
pub fn init() -> Result<(), &'static str> {
    if STARTED.swap(true, Ordering::AcqRel) {
        return Ok(());
    }
    // SAFETY: static events initialized once before the thread runs.
    unsafe {
        crate::ke::wait::KeInitializeEvent(EVENTS.wake.get().cast(), 1, 0); // SynchronizationEvent
        crate::ke::wait::KeInitializeEvent(EVENTS.progress.get().cast(), 1, 0);
    }
    crate::ke::thread::create(
        writer_thread,
        0,
        WRITER_PRIORITY,
        crate::ke::thread::ANYWHERE,
    )
    .map(|_| ())
}

/// Wake the mapped-page writer to flush pending `Location::Modified` pages.
pub fn kick() {
    if STARTED.load(Ordering::Acquire) {
        // SAFETY: initialized in `init()`.
        unsafe { crate::ke::wait::KeSetEvent(EVENTS.wake.get().cast(), 0, 0) };
    }
}

/// Wait up to `timeout_100ns` (negative relative 100ns units) for the writer to
/// complete at least one cluster writeback.
pub fn wait_progress(timeout_100ns: i64) {
    if !STARTED.load(Ordering::Acquire) {
        return;
    }
    // SAFETY: initialized in `init()`.
    unsafe {
        crate::ke::wait::wait(Some(EVENTS.progress.get().cast()), Some(timeout_100ns));
    }
}

/// Statistics for tests/diagnostics: `(clusters_written, pages_written)`.
#[allow(dead_code)]
pub fn stats() -> (u64, u64) {
    (
        CLUSTERS_WRITTEN.load(Ordering::Acquire),
        PAGES_WRITTEN.load(Ordering::Acquire),
    )
}

/// Flush every currently `Location::Modified` frame synchronously (called at shutdown).
pub fn flush_all() {
    if !STARTED.load(Ordering::Acquire) {
        return;
    }
    for _ in 0..256 {
        if pfn::modified_count() == 0 {
            break;
        }
        kick();
        wait_progress(-500_000); // 50 ms
    }
}

/// Attempt to gather and write one contiguous cluster of up to `WRITE_CLUSTER`
/// modified pages starting from the oldest frame on `Location::Modified`.
/// Returns `true` if a cluster was processed (even if write failed), `false` if
/// `Location::Modified` is empty or skipped.
fn write_one_cluster(mdl: *mut MDL) -> bool {
    let gathered: Option<(
        *mut ControlArea,
        *mut Subsection,
        usize,
        [u64; WRITE_CLUSTER],
        usize,
    )> = {
        let mut g = pfn::lock();
        let Some((_, pte, original)) = pfn::frames(&mut g).db.first_modified() else {
            return false;
        };
        let (ss_ptr, first_idx) = section::locate_proto(original, pte);
        // SAFETY: `first_modified` returned a resident prototype frame belonging to `ss_ptr`.
        let ss = unsafe { &*ss_ptr };
        let ca_ptr = ss.ca;
        // SAFETY: `ss` belongs to live `ca_ptr`.
        let ca = unsafe { &*ca_ptr };
        if ca.file.is_null() || ca.no_write() {
            return false;
        }
        // Hold both `ControlArea` and `Subsection` alive across the I/O.
        ca.flushes.set(ca.flushes.get() + 1);
        ss.views.set(ss.views.get() + 1);

        let hi = (first_idx + WRITE_CLUSTER).min(SUBSECTION_PAGES);
        let mut frames = [0u64; WRITE_CLUSTER];
        let mut nframes = 0usize;
        for proto in ss.protos.iter().take(hi).skip(first_idx) {
            let decoded = Proto::decode(proto.load(Ordering::Relaxed));
            let (Proto::Transition(frame) | Proto::Valid(frame)) = decoded else {
                break;
            };
            let db = &mut pfn::frames(&mut g).db;
            let e = *db.get(frame);
            if !e.has(flag::MODIFIED)
                || e.has(flag::WRITE_IN_PROGRESS)
                || e.has(flag::READ_IN_PROGRESS)
            {
                break;
            }
            if db.reference(frame).is_err() {
                break;
            }
            let entry = db.get_mut(frame);
            entry.flags = (entry.flags & !flag::MODIFIED) | flag::WRITE_IN_PROGRESS;
            frames[nframes] = frame;
            nframes += 1;
        }

        if nframes == 0 {
            ss.views.set(ss.views.get() - 1);
            ca.flushes.set(ca.flushes.get() - 1);
            section::unused_subsection(&g, ss);
            section::check(&g, ca);
            None
        } else {
            Some((ca_ptr, ss_ptr, first_idx, frames, nframes))
        }
    };

    let Some((ca_ptr, ss_ptr, start, frames_buf, nframes)) = gathered else {
        section::reap();
        return false;
    };
    let frames = &frames_buf[..nframes];

    // SAFETY: `ca_ptr` and `ss_ptr` are pinned by `flushes` and `views`.
    let (file, offset, no_write) = unsafe {
        let ca = &*ca_ptr;
        let ss = &*ss_ptr;
        (
            ca.file,
            (ss.first_page + start as u64) * PAGE_SIZE as u64,
            ca.no_write(),
        )
    };

    let acq_status = crate::fsrtl::acquire::acquire_for_cc_flush(file);
    let write_status = if nt_error(acq_status) {
        acq_status
    } else {
        let mut event = MaybeUninit::<KEVENT>::zeroed();
        let mut iosb = IO_STATUS_BLOCK {
            Status: STATUS_PENDING,
            Information: 0,
        };
        // SAFETY: `mdl` belongs exclusively to this writer thread and holds up to
        // `WRITE_CLUSTER` PFNs; each frame in `frames` is pinned by `db.reference`.
        let st = unsafe {
            core::ptr::write_bytes(mdl.cast::<u8>(), 0, size_of::<MDL>() + WRITE_CLUSTER * 8);
            (*mdl).Size = (size_of::<MDL>() + frames.len() * 8) as i16;
            (*mdl).MdlFlags = MDL_PAGES_LOCKED;
            (*mdl).StartVa = core::ptr::null_mut();
            (*mdl).ByteCount = (frames.len() * PAGE_SIZE) as u32;
            let pages = mdl.add(1).cast::<u64>();
            for (k, &frame) in frames.iter().enumerate() {
                pages.add(k).write(frame);
            }
            crate::ke::wait::KeInitializeEvent(event.as_mut_ptr(), 0, 0);
            let sent = crate::io::paging::synchronous_page_write(
                file,
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
        crate::fsrtl::acquire::release_for_cc_flush(file);
        st
    };

    if !nt_error(write_status) {
        CLUSTERS_WRITTEN.fetch_add(1, Ordering::Relaxed);
        PAGES_WRITTEN.fetch_add(frames.len() as u64, Ordering::Relaxed);
    }

    {
        let mut g = pfn::lock();
        for &frame in frames {
            let db = &mut pfn::frames(&mut g).db;
            let e = db.get_mut(frame);
            e.flags &= !flag::WRITE_IN_PROGRESS;
            if nt_error(write_status) {
                e.flags |= flag::MODIFIED;
            }
            if let Err(err) = db.dereference(frame, no_write, false) {
                crate::kd::bugcheck(format_args!("mm: mapped-page writer finished: {}", err.0));
            }
        }
        // SAFETY: `ss_ptr` and `ca_ptr` remain pinned until we decrement below.
        unsafe {
            let ss = &*ss_ptr;
            let ca = &*ca_ptr;
            ss.views.set(ss.views.get() - 1);
            ca.flushes.set(ca.flushes.get() - 1);
            section::unused_subsection(&g, ss);
            section::check(&g, ca);
        }
    }
    section::reap();
    // SAFETY: initialized in `init()`.
    unsafe { crate::ke::wait::KeSetEvent(EVENTS.progress.get().cast(), 0, 0) };
    true
}

fn writer_thread(_arg: usize) {
    let mut storage = MaybeUninit::<WriterMdl>::zeroed();
    let mdl = storage.as_mut_ptr().cast::<MDL>();
    loop {
        let mut wrote_any = false;
        // Drain up to 16 clusters per wakeup so modified pages rapidly become Standby.
        for _ in 0..16 {
            if !write_one_cluster(mdl) {
                break;
            }
            wrote_any = true;
        }
        if wrote_any && pfn::modified_count() > 0 {
            continue;
        }
        // Sleep until kicked or periodic 250 ms sweep.
        // SAFETY: initialized in `init()`.
        unsafe {
            crate::ke::wait::wait(Some(EVENTS.wake.get().cast()), Some(-2_500_000));
        }
    }
}
