//! Dirty data and its writing: the dirty-page bitmap copy and MDL
//! writes mark (`CcSetDirtyInMask`), the flush that writes a file's
//! dirty runs through the memory manager (`CcFlushCachePriv`), and
//! `CcIsThereDirtyData`.
//!
//! A flush takes the dirty runs in offset order, pinned ones (dirty
//! BCBs) first, then those of the bitmap, and has each written by
//! `MmFlushSection`, the file taken for it through FsRtl. A write that
//! fails leaves its run dirty again unless the memory manager calls the
//! error fatal (a lost delayed write, logged). Write errors are returned
//! in the status block, never raised.

use super::{DIRTY, MASTER, Scm, dereference, reference, trace};
use crate::fsrtl::acquire::CC_FLUSH;
use crate::mm::{PAGE_SIZE, flush};
use core::cell::Cell;
use core::mem::MaybeUninit;
use nk_cc::mbcb::Run;
use nk_ntabi::io::{IO_STATUS_BLOCK, SECTION_OBJECT_POINTERS};
use nk_ntabi::ke::KEVENT;
use nk_ntabi::status::*;

/// A dirty run taken out of `scm`'s BCBs or bitmap and currently being
/// written by `MmFlushSection`, linked on `scm.inflight` under [`MASTER`]
/// so synchronous flushes wait for it instead of returning early.
pub struct InFlight {
    next: *mut InFlight,
    start: u64,
    end: u64,
}

/// A synchronous flush waiting for an overlapping [`InFlight`] write to
/// finish, linked on `scm.flush_waiters` under [`MASTER`].
pub struct FlushWaiter {
    next: *mut FlushWaiter,
    start: u64,
    end: u64,
    /// Set if an overlapping in-flight write failed with a fatal error
    /// that was not redirtied, so the waiter does not report false success.
    fatal: Cell<NTSTATUS>,
    event: *mut KEVENT,
}

fn overlaps(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

/// Publish an in-flight write range on `scm.inflight` under [`MASTER`].
///
/// # Safety
/// `node` lives on the caller's stack until [`finish_inflight`] unlinks it.
unsafe fn register_inflight(scm: &Scm, node: *mut InFlight, start: u64, end: u64) {
    let _m = MASTER.lock();
    // SAFETY: per the contract; guarded by `MASTER`.
    unsafe {
        (*node).start = start;
        (*node).end = end;
        (*node).next = scm.inflight.get();
    }
    scm.inflight.set(node);
}

/// Remove `node` from `scm.inflight` and wake any synchronous flushes
/// waiting on an overlapping range, propagating `fatal` if the write
/// failed fatally without redirtying.
fn finish_inflight(scm: &Scm, node: *mut InFlight, fatal: Option<NTSTATUS>) {
    let woken = {
        let _m = MASTER.lock();
        // SAFETY: `node` is on `scm.inflight`, guarded by `MASTER`.
        let (start, end) = unsafe { ((*node).start, (*node).end) };
        let mut cursor = scm.inflight.get();
        let mut prev: *mut InFlight = core::ptr::null_mut();
        while !cursor.is_null() {
            // SAFETY: nodes live on their writers' stacks until unlinked here.
            let next = unsafe { (*cursor).next };
            if cursor == node {
                if prev.is_null() {
                    scm.inflight.set(next);
                } else {
                    // SAFETY: as above.
                    unsafe { (*prev).next = next };
                }
                break;
            }
            prev = cursor;
            cursor = next;
        }
        let mut woken: *mut FlushWaiter = core::ptr::null_mut();
        let mut w = scm.flush_waiters.get();
        let mut w_prev: *mut FlushWaiter = core::ptr::null_mut();
        while !w.is_null() {
            // SAFETY: waiters live on their sleepers' stacks until detached
            // here and signalled.
            unsafe {
                let next = (*w).next;
                if overlaps((*w).start, (*w).end, start, end) {
                    if let Some(status) = fatal
                        && !nt_error((*w).fatal.get())
                    {
                        (*w).fatal.set(status);
                    }
                    if w_prev.is_null() {
                        scm.flush_waiters.set(next);
                    } else {
                        (*w_prev).next = next;
                    }
                    (*w).next = woken;
                    woken = w;
                } else {
                    w_prev = w;
                }
                w = next;
            }
        }
        woken
    };
    let mut w = woken;
    while !w.is_null() {
        // SAFETY: detached waiters live on their sleepers' stacks until
        // signalled; read `next` before waking.
        unsafe {
            let next = (*w).next;
            crate::ke::wait::KeSetEvent((*w).event, 0, 0);
            w = next;
        }
    }
}

/// Whether any [`InFlight`] write on `scm` overlaps `[start, end)`.
/// If so, link a stack waiter and wait for it to finish, returning any
/// fatal error status propagated from it; else return `None`.
fn wait_overlapping_inflight(scm: &Scm, start: u64, end: u64) -> Option<NTSTATUS> {
    let mut event = MaybeUninit::<KEVENT>::uninit();
    let mut waiter = FlushWaiter {
        next: core::ptr::null_mut(),
        start,
        end,
        fatal: Cell::new(STATUS_SUCCESS),
        event: event.as_mut_ptr(),
    };
    let must_wait = {
        let _m = MASTER.lock();
        let mut at = scm.inflight.get();
        let mut hit = false;
        while !at.is_null() {
            // SAFETY: nodes on `scm.inflight` live on their writers' stacks
            // under `MASTER`.
            unsafe {
                if overlaps((*at).start, (*at).end, start, end) {
                    hit = true;
                    break;
                }
                at = (*at).next;
            }
        }
        if hit {
            // SAFETY: stack event and waiter, signalled before we return.
            unsafe {
                crate::ke::wait::KeInitializeEvent(event.as_mut_ptr(), 0, 0);
                waiter.next = scm.flush_waiters.get();
            }
            scm.flush_waiters.set(&raw mut waiter);
        }
        hit
    };
    if !must_wait {
        return None;
    }
    // SAFETY: stack event initialised and linked above.
    unsafe { crate::ke::wait::wait(Some(event.as_mut_ptr().cast()), None) };
    Some(waiter.fatal.get())
}

/// The most one write of a flush carries: what the memory manager writes
/// in one request.
const RUN_PAGES: u64 = 16;

/// `CcSetDirtyInMask`: bytes `[offset, offset + length)` of `scm` are
/// dirty; their pages are charged to the map and the cache.
pub fn set_dirty_in_mask(scm: &Scm, offset: u64, length: u64) -> Result<(), NTSTATUS> {
    let newly = scm
        .with_bcbs(|_, mbcb| mbcb.set_dirty(offset, length))
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    if newly != 0 {
        charge(scm, newly as i64);
    }
    Ok(())
}

/// Add `pages` (negative: take them off) to the dirty counts of `scm`
/// and the cache.
pub fn charge(scm: &Scm, pages: i64) {
    let _m = MASTER.lock();
    let mut d = DIRTY.lock();
    scm.dirty_pages
        .set(scm.dirty_pages.get().wrapping_add_signed(pages));
    d.pages = d.pages.wrapping_add_signed(pages);
    drop(d);
    if pages > 0 {
        super::lazy::schedule_scan();
    }
}

/// Note a write's result in `result`: the first failure is kept, the
/// bytes written added up.
fn note(result: &mut IO_STATUS_BLOCK, written: &IO_STATUS_BLOCK) {
    result.Information += written.Information;
    if nt_error(written.Status) && !nt_error(result.Status) {
        result.Status = written.Status;
    }
}

/// Whether a failed write's run stays dirty: unless the error is fatal.
fn keep_dirty(status: NTSTATUS) -> bool {
    nt_error(status) && !nk_mm::section::is_write_error_fatal(true, false, status)
}

/// `CcFlushCachePriv`: write the dirty runs of `scm` in `range` (`None`:
/// the whole file), at most `budget` pages of them when one is given (the
/// lazy writer's). A range flush ends with a flush of the whole range, for
/// pages dirtied through other mappings.
pub fn flush_scm(scm: &Scm, range: Option<(u64, u32)>, budget: Option<u64>) -> IO_STATUS_BLOCK {
    reference(scm);
    let mut result = IO_STATUS_BLOCK {
        Status: STATUS_SUCCESS,
        Information: 0,
    };
    let (start, end) = match range {
        None => (0, u64::MAX),
        Some((offset, 0)) => (offset, u64::MAX),
        Some((offset, length)) => (offset, offset + u64::from(length)),
    };
    let page = PAGE_SIZE as u64;
    let mut left = budget.unwrap_or(u64::MAX);
    loop {
        // Pinned runs.
        let mut from = start;
        while left != 0 {
            let mut inflight = InFlight {
                next: core::ptr::null_mut(),
                start: 0,
                end: 0,
            };
            let Some(run) = super::pin::take_dirty_run(scm, from, end, RUN_PAGES * page, |s, e| {
                // SAFETY: `inflight` stays on this stack until `finish_inflight`.
                unsafe { register_inflight(scm, &raw mut inflight, s, e) };
            }) else {
                break;
            };
            from = run.offset + u64::from(run.length);
            let written =
                flush::flush_section(scm.sop, Some((run.offset, run.length)), Some(CC_FLUSH));
            trace(format_args!(
                "write pinned {:p} {:#x}+{:#x}: {:#x}",
                core::ptr::from_ref(scm),
                run.offset,
                run.length,
                written.Status
            ));
            let pages = u64::from(run.length).div_ceil(page);
            left = left.saturating_sub(pages);
            note(&mut result, &written);
            let redirty_run = keep_dirty(written.Status);
            super::pin::finish_run(run, redirty_run);
            let fatal = (nt_error(written.Status) && !redirty_run).then_some(written.Status);
            finish_inflight(scm, &raw mut inflight, fatal);
        }
        // Runs of the bitmap.
        let (first, stop) = (start / page, end.div_ceil(page));
        let mut from = first;
        while left != 0 {
            let most = RUN_PAGES.min(left);
            let mut inflight = InFlight {
                next: core::ptr::null_mut(),
                start: 0,
                end: 0,
            };
            let Some(run) = scm.with_bcbs(|_, mbcb| {
                let run = if budget.is_some() {
                    mbcb.take_lazy_run(most)
                } else {
                    mbcb.take_run(from, stop, most)
                }?;
                // Publish in-flight before releasing `bcb_lock` so a concurrent
                // synchronous flush never observes the bitmap clean while this
                // run has yet to reach disk.
                // SAFETY: `inflight` stays on this stack until `finish_inflight`.
                unsafe {
                    register_inflight(
                        scm,
                        &raw mut inflight,
                        run.page * page,
                        (run.page + run.pages) * page,
                    );
                }
                Some(run)
            }) else {
                break;
            };
            charge(scm, -(run.pages as i64));
            from = run.page + run.pages;
            left = left.saturating_sub(run.pages);
            let written = flush::flush_section(
                scm.sop,
                Some((run.page * page, (run.pages * page) as u32)),
                Some(CC_FLUSH),
            );
            trace(format_args!(
                "write {:p} {:#x}+{:#x}: {:#x}",
                core::ptr::from_ref(scm),
                run.page * page,
                run.pages * page,
                written.Status
            ));
            note(&mut result, &written);
            let redirty_run = keep_dirty(written.Status);
            if redirty_run {
                redirty(scm, run);
            }
            let fatal = (nt_error(written.Status) && !redirty_run).then_some(written.Status);
            finish_inflight(scm, &raw mut inflight, fatal);
        }
        // For synchronous flushes (`budget.is_none()`), wait out any
        // overlapping write-behind or concurrent flush already in flight,
        // then re-check the BCBs/bitmap in case that write failed and
        // redirtied its range.
        if budget.is_none()
            && let Some(fatal) = wait_overlapping_inflight(scm, start, end)
        {
            if nt_error(fatal) && !nt_error(result.Status) {
                result.Status = fatal;
            }
            continue;
        }
        break;
    }
    if range.is_some() || budget.is_none() {
        let rest = flush::flush_section(scm.sop, range, Some(CC_FLUSH));
        note(&mut result, &rest);
    }
    dereference(scm);
    result
}

/// Put a run that failed back in the bitmap.
fn redirty(scm: &Scm, run: Run) {
    // A run's bitmap range was there a moment ago; if its memory cannot
    // be had again the dirt is lost, as a fatal error loses it.
    if let Ok(newly) = scm.with_bcbs(|_, mbcb| mbcb.redirty(run)) {
        charge(scm, newly as i64);
    }
}

/// [`CcFlushCache`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccflushcache):
/// write the file's dirty data in the range (`offset` null: all of it),
/// and wait for it. With no cache map, the file's section is flushed.
///
/// # Safety
/// `sop` is a file's section object pointers; `offset` null or
/// readable; `iosb` null or writable. At `PASSIVE_LEVEL`.
pub unsafe extern "C" fn CcFlushCache(
    sop: *mut SECTION_OBJECT_POINTERS,
    offset: *const i64,
    length: u32,
    iosb: *mut IO_STATUS_BLOCK,
) {
    // SAFETY: per the contract.
    let range = unsafe { offset.as_ref() }.map(|&o| (o as u64, length));
    let result = flush_sop(sop, range);
    // SAFETY: per the contract.
    if let Some(iosb) = unsafe { iosb.as_mut() } {
        *iosb = result;
    }
}

/// Flush a file by its section object pointers: through its cache map
/// if it has one, else its section.
pub fn flush_sop(sop: *mut SECTION_OBJECT_POINTERS, range: Option<(u64, u32)>) -> IO_STATUS_BLOCK {
    // SAFETY: `sop` is a live `SECTION_OBJECT_POINTERS` at `PASSIVE_LEVEL`.
    match unsafe { super::acquire_map(sop) } {
        Some(scm) => {
            let result = flush_scm(scm, range, None);
            dereference(scm);
            result
        }
        None => flush::flush_section(sop, range, Some(CC_FLUSH)),
    }
}

/// [`CcIsThereDirtyData`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccistheredirtydata):
/// whether any file cached on the volume `vpb` has dirty data.
///
/// # Safety
/// `vpb` is a volume parameter block.
pub unsafe extern "C" fn CcIsThereDirtyData(vpb: *mut core::ffi::c_void) -> u8 {
    let m = MASTER.lock();
    let mut dirty = false;
    super::map::each(&m, |scm| {
        let file = scm.file_object.get();
        // SAFETY: a map's file object lives as long as the map.
        let on_volume = !file.is_null() && unsafe { (*file).Vpb } == vpb;
        let _d = DIRTY.lock();
        dirty |= on_volume && scm.dirty_pages.get() != 0;
    });
    u8::from(dirty)
}
