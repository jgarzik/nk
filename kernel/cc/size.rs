//! A cached file's sizes and contents as a whole: `CcSetFileSizes`,
//! `CcPurgeCacheSection`, `CcCoherencyFlushAndPurgeCache`, `CcZeroData`,
//! and the per-file knobs (`CcSetReadAheadGranularity`,
//! `CcSetAdditionalCacheAttributes`).

use super::flush::{charge, flush_sop, set_dirty_in_mask};
use super::vacb::{self, Busy};
use super::{
    MASTER, Scm, cache_manager_bugcheck, cached, dereference, flag, io_status, or_raise, pcm_of,
    scm_of, trace,
};
use crate::arch::seh::{Context, fourth_argument};
use crate::mm::cache::{self, Resident};
use crate::mm::{PAGE_SIZE, flush};
use nk_cc::VIEW_BYTES;
use nk_ntabi::cc::CC_FILE_SIZES;
use nk_ntabi::io::{FILE_OBJECT, IO_STATUS_BLOCK, SECTION_OBJECT_POINTERS};
use nk_ntabi::status::*;

/// `STATUS_CACHE_PAGE_LOCKED`: a success code.
const STATUS_CACHE_PAGE_LOCKED: NTSTATUS = 0x115;

/// The first page boundary at or after `offset`.
fn page_up(offset: u64) -> u64 {
    offset.next_multiple_of(PAGE_SIZE as u64)
}

/// `CcSetFileSizesEx`: the file's new sizes. A larger allocation extends
/// the section (an unexpected failure is `STATUS_UNEXPECTED_MM_EXTEND_ERR`);
/// a smaller file size takes back the views beyond it, forgets the dirt
/// there and purges its pages; the valid data length only goes down.
/// With no cache map, the file's section is purged beyond the new size.
///
/// # Safety
/// `file` is a live file object whose file system set its pointers.
pub unsafe fn set_file_sizes(file: *mut FILE_OBJECT, sizes: &CC_FILE_SIZES) -> NTSTATUS {
    // SAFETY: per the contract.
    let (scm, sop) = unsafe {
        (
            scm_of(file).as_ref(),
            (*file)
                .SectionObjectPointer
                .cast::<SECTION_OBJECT_POINTERS>(),
        )
    };
    let new_size = sizes.FileSize as u64;
    let Some(scm) = scm else {
        if !sop.is_null() {
            flush::purge_section(sop, Some((page_up(new_size), 0)), false);
        }
        return STATUS_SUCCESS;
    };
    {
        let _m = MASTER.lock();
        scm.open_count.set(scm.open_count.get() + 1);
    }
    let result = resize(scm, sizes);
    {
        let _m = MASTER.lock();
        scm.open_count.set(scm.open_count.get() - 1);
    }
    trace(format_args!(
        "sizes {file:p}: allocation {:#x} file {:#x} valid {:#x}: {result:#x}",
        sizes.AllocationSize, sizes.FileSize, sizes.ValidDataLength
    ));
    result
}

fn resize(scm: &Scm, sizes: &CC_FILE_SIZES) -> NTSTATUS {
    if let Err(status) = super::map::extend_for(scm, sizes.AllocationSize as u64) {
        return status;
    }
    let new_size = sizes.FileSize as u64;
    let old_size = scm.file_size.get() as u64;
    if new_size < old_size && scm.flags() & flag::PIN_ACCESS == 0 {
        let first = page_up(new_size).div_ceil(VIEW_BYTES) as usize;
        vacb::unmap_views(scm, first, Busy::Wait);
        let page = PAGE_SIZE as u64;
        let gone = scm.with_bcbs(|_, mbcb| mbcb.truncate(new_size.div_ceil(page)));
        charge(scm, -(gone as i64));
        super::pin::discard_from(scm, page_up(new_size));
        flush::purge_section(scm.sop, Some((page_up(new_size), 0)), false);
    }
    let _m = MASTER.lock();
    scm.file_size.set(sizes.FileSize);
    let valid = sizes.ValidDataLength;
    if valid < scm.valid_data_length.get() {
        scm.valid_data_length.set(valid);
    }
    if valid < scm.valid_data_goal.get() {
        scm.valid_data_goal.set(valid);
    }
    STATUS_SUCCESS
}

/// [`CcSetFileSizesEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccsetfilesizesex):
/// [`set_file_sizes`], returning its status.
///
/// # Safety
/// As [`set_file_sizes`]; `sizes` readable. At `PASSIVE_LEVEL`.
pub unsafe extern "C" fn CcSetFileSizesEx(
    file: *mut FILE_OBJECT,
    sizes: *const CC_FILE_SIZES,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { set_file_sizes(file, &sizes.read_unaligned()) }
}

/// What `CcSetFileSizes` is entered as: [`set_file_sizes`], raising its
/// failure.
///
/// # Safety
/// As [`CcSetFileSizesEx`], with `context` from `nk_with_caller_context`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_cc_set_file_sizes(
    file: *mut FILE_OBJECT,
    sizes: *const CC_FILE_SIZES,
    _: usize,
    context: *mut Context,
) {
    // SAFETY: per the contract.
    unsafe {
        let status = set_file_sizes(file, &sizes.read_unaligned());
        or_raise(
            context,
            if nt_error(status) {
                Err(status)
            } else {
                Ok(())
            },
        );
    }
}

/// `CcPurgeCacheSection`'s work: `range` as the memory manager takes it.
pub fn purge(
    sop: *mut SECTION_OBJECT_POINTERS,
    range: Option<(u64, u32)>,
    uninitialize: bool,
) -> bool {
    // SAFETY: `sop` is a live `SECTION_OBJECT_POINTERS` at `PASSIVE_LEVEL`.
    let Some(scm) = (unsafe { super::acquire_map(sop) }) else {
        return flush::purge_section(sop, range, false);
    };
    if uninitialize {
        // Every file object caching the file stops caching it.
        loop {
            let file = {
                let _m = MASTER.lock();
                // SAFETY: private maps on the list are live under the lock.
                unsafe { scm.first_private().as_ref() }.map(|p| p.file_object.get())
            };
            let Some(file) = file else { break };
            // SAFETY: a file object caching the file is live.
            unsafe {
                super::map::CcUninitializeCacheMap(file, core::ptr::null(), core::ptr::null_mut())
            };
        }
    }
    let offset = range.map_or(0, |(o, _)| o);
    let purged = (|| {
        if range.is_none_or(|(_, len)| len == 0)
            && !flush::can_file_be_truncated(sop, range.map(|(o, _)| o))
        {
            return false;
        }
        if !vacb::unmap_views(scm, (offset / VIEW_BYTES) as usize, Busy::Fail) {
            return false;
        }
        if !flush::purge_section(sop, range, false) {
            return false;
        }
        // The dirty data in the range is gone.
        let page = PAGE_SIZE as u64;
        let first = offset / page;
        let gone = match range {
            Some((o, len)) if len != 0 => scm.with_bcbs(|_, mbcb| {
                let mut gone = 0;
                while let Some(run) =
                    mbcb.take_run(first, (o + u64::from(len)).div_ceil(page), u64::MAX)
                {
                    gone += run.pages;
                }
                gone
            }),
            _ => scm.with_bcbs(|_, mbcb| mbcb.truncate(first)),
        };
        charge(scm, -(gone as i64));
        if range.is_none_or(|(_, len)| len == 0) {
            super::pin::discard_from(scm, offset);
        }
        true
    })();
    dereference(scm);
    purged
}

/// [`CcPurgeCacheSection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccpurgecachesection):
/// discard the file's cached pages in the range (`offset` null: all;
/// length 0: to the end), dirty ones too. FALSE when a view in the range
/// is in use or the memory manager refuses; never raises. With bit 0 of
/// `flags`, every file object caching the file stops caching it first.
///
/// Partial: a purge that collides with I/O in progress fails rather than
/// waiting and trying again.
///
/// # Safety
/// `sop` is a file's section object pointers; `offset` null or readable.
/// At `PASSIVE_LEVEL`.
pub unsafe extern "C" fn CcPurgeCacheSection(
    sop: *mut SECTION_OBJECT_POINTERS,
    offset: *const i64,
    length: u32,
    flags: u32,
) -> u8 {
    // SAFETY: per the contract.
    let range = unsafe { offset.as_ref() }.map(|&o| (o as u64, length));
    let purged = purge(sop, range, flags & 1 != 0);
    trace(format_args!("purge {sop:p} {range:x?}: {purged}"));
    u8::from(purged)
}

/// [`CcCoherencyFlushAndPurgeCache`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-cccoherencyflushandpurgecache):
/// flush the range, then (unless bit 0 of `flags`, no purge) purge it;
/// a purge that fails makes the status `STATUS_CACHE_PAGE_LOCKED`, a
/// success code. NK maps files in no user view, so there is no user
/// view's dirt to gather first.
///
/// # Safety
/// As [`CcPurgeCacheSection`]; `iosb` writable.
pub unsafe extern "C" fn CcCoherencyFlushAndPurgeCache(
    sop: *mut SECTION_OBJECT_POINTERS,
    offset: *const i64,
    length: u32,
    iosb: *mut IO_STATUS_BLOCK,
    flags: u32,
) {
    // SAFETY: per the contract.
    let range = unsafe { offset.as_ref() }.map(|&o| (o as u64, length));
    let mut result = flush_sop(sop, range);
    if !nt_error(result.Status) && flags & 1 == 0 && !purge(sop, range, false) {
        result.Status = STATUS_CACHE_PAGE_LOCKED;
    }
    // SAFETY: per the contract.
    unsafe { iosb.write(result) };
}

/// What `CcZeroData` is entered as: the fourth argument is `Wait`.
///
/// # Safety
/// Called by a file system as `CcZeroData`, with `context` from
/// `nk_with_caller_context`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_cc_zero_data(
    file: *mut FILE_OBJECT,
    start: *const i64,
    end: *const i64,
    context: *mut Context,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let wait = fourth_argument(&*context) as u8 != 0;
        let r = zero_data(
            file,
            start.read_unaligned() as u64,
            end.read_unaligned() as u64,
            wait,
        );
        u8::from(or_raise(context, r))
    }
}

/// `CcZeroData`'s work: zero `[start, end)` through the cache, marking it
/// dirty. Pages zeroed whole are not read.
///
/// # Safety
/// `file` is a live file object of a file system.
pub unsafe fn zero_data(
    file: *mut FILE_OBJECT,
    start: u64,
    end: u64,
    wait: bool,
) -> Result<bool, NTSTATUS> {
    // SAFETY: per the contract.
    if unsafe { pcm_of(file) }.is_none() {
        cache_manager_bugcheck(format_args!(
            "CcZeroData on {file:p}, which is not cached: zeroing on disk is not implemented"
        ));
    }
    // SAFETY: per the contract.
    let scm = unsafe { cached(file, "CcZeroData") };
    let mut at = start;
    while at < end {
        let Some(v) = vacb::get_va_wait(scm, at, wait)? else {
            return Ok(false);
        };
        let part = u64::from(v.left).min(end - at);
        let mode = if !wait {
            Resident::NoIo
        } else {
            Resident::WillOverwrite
        };
        // Pages zeroed whole need no read; without waiting nothing is read.
        let resident = cache::make_resident(v.va, part as usize, mode).map_err(io_status);
        let r = match resident {
            Ok(true) => {
                // SAFETY: the view's resident bytes.
                unsafe { core::ptr::write_bytes(v.va as *mut u8, 0, part as usize) };
                set_dirty_in_mask(scm, at, part).map(|()| true)
            }
            other => other,
        };
        vacb::free_va(v.vacb);
        if !r? {
            return Ok(false);
        }
        at += part;
    }
    Ok(true)
}

/// [`CcSetReadAheadGranularity`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccsetreadaheadgranularity):
/// the file object's read-ahead granularity, unchecked, as Windows takes
/// it.
///
/// # Safety
/// `file` is a cached file object.
pub unsafe extern "C" fn CcSetReadAheadGranularity(file: *mut FILE_OBJECT, granularity: u32) {
    // SAFETY: per the contract.
    if let Some(pcm) = unsafe { pcm_of(file) } {
        pcm.read_ahead_mask.set(granularity.wrapping_sub(1));
    }
}

/// The map of a file object an attribute is set on: one with a file
/// object caching it.
///
/// # Safety
/// `file` is a cached file object.
unsafe fn open_map(file: *mut FILE_OBJECT, routine: &str) -> &'static Scm {
    // SAFETY: per the contract.
    let scm = unsafe { cached(file, routine) };
    if scm.open_count.get() == 0 {
        cache_manager_bugcheck(format_args!("{routine} on a map no file object has open"));
    }
    scm
}

/// [`CcSetAdditionalCacheAttributes`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccsetadditionalcacheattributes):
/// turn read-ahead and write-behind off or on for the file. Turning
/// write-behind off also leaves the file's pages to the cache manager's
/// flushes alone; turning it on again does not undo that, as on Windows.
///
/// # Safety
/// As [`CcSetReadAheadGranularity`].
pub unsafe extern "C" fn CcSetAdditionalCacheAttributes(
    file: *mut FILE_OBJECT,
    disable_read_ahead: u8,
    disable_write_behind: u8,
) {
    // SAFETY: per the contract.
    let scm = unsafe { open_map(file, "CcSetAdditionalCacheAttributes") };
    let _m = MASTER.lock();
    let mut f = scm.flags();
    f = if disable_read_ahead != 0 {
        f | flag::DISABLE_READ_AHEAD
    } else {
        f & !flag::DISABLE_READ_AHEAD
    };
    f = if disable_write_behind != 0 {
        f | flag::DISABLE_WRITE_BEHIND | flag::MODIFIED_WRITE_DISABLED
    } else {
        f & !flag::DISABLE_WRITE_BEHIND
    };
    scm.set_flags(f);
}

/// [`CcSetAdditionalCacheAttributesEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccsetadditionalcacheattributesex):
/// read-ahead and write-behind from bits 1 and 2 of `flags`, as
/// [`CcSetAdditionalCacheAttributes`], then the map's other attributes
/// recorded as the pinned kernel records them (bits 0, 3, 4 and 5 of
/// `flags`). NK acts on none of those.
///
/// # Safety
/// As [`CcSetReadAheadGranularity`].
pub unsafe extern "C" fn CcSetAdditionalCacheAttributesEx(file: *mut FILE_OBJECT, flags: u32) {
    // SAFETY: per the contract.
    let scm = unsafe { open_map(file, "CcSetAdditionalCacheAttributesEx") };
    // SAFETY: as above.
    unsafe {
        CcSetAdditionalCacheAttributes(file, u8::from(flags & 2 != 0), u8::from(flags & 4 != 0))
    };
    let _m = MASTER.lock();
    let mut f = scm.flags();
    let set = |f: u32, bit: u32, on: bool| if on { f | 1 << bit } else { f & !(1 << bit) };
    f = set(f, 23, flags & 0x1 != 0);
    if flags & 0x8 == 0 && f & 1 << 26 != 0 {
        f |= 1 << 17;
    }
    f = set(f, 26, flags & 0x8 != 0);
    f = set(f, 28, flags & 0x10 != 0);
    f = set(f, 27, flags & 0x20 != 0);
    f = set(f, 12, flags & 0x1000_0000 != 0);
    scm.set_flags(f);
}
