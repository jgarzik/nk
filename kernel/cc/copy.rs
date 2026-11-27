//! Copying between a caller's buffer and the cache: `CcCopyReadEx`,
//! `CcCopyWrite` and `CcCopyWriteEx`, view by view.
//!
//! A read makes the view's pages resident (without waiting, it gives up
//! with FALSE if one would need a read), copies, and rotates the file
//! object's read history. A write makes no read of a page it overwrites
//! whole or of one wholly at or beyond the valid data length in the FCB
//! header (its other bytes become zero: `MmCopyToCachedPage`), reads the
//! rest, copies, and marks the range dirty in the map's bitmap; a write
//! through a file object opened for write-through is flushed at once.
//! A fault on the caller's buffer is raised as
//! `STATUS_INVALID_USER_BUFFER`; a failed read as its status, or
//! `STATUS_UNEXPECTED_IO_ERROR` if a file system would not expect it.

use super::flush::{flush_scm, set_dirty_in_mask};
use super::vacb::{self, View};
use super::{MASTER, STATUS_INVALID_USER_BUFFER, Scm, cache_manager_bugcheck, cached, io_status};
use super::{or_raise, pcm_of};
use crate::arch::seh::{Context, fourth_argument, stack_argument};
use crate::mm::cache::{self, Resident};
use crate::mm::{PAGE_SIZE, user};
use nk_ntabi::cc::FO_WRITE_THROUGH;
use nk_ntabi::fsrtl::FSRTL_COMMON_FCB_HEADER;
use nk_ntabi::io::{FILE_OBJECT, IO_STATUS_BLOCK};
use nk_ntabi::status::*;

/// Each view `[offset, offset + length)` touches, in order: `f` gets the
/// view (one more user, given back after) and the part of the range in
/// it. Stops at the first `Ok(false)` or error.
fn each_view(
    scm: &Scm,
    offset: u64,
    length: u64,
    mut f: impl FnMut(&View, u64, u64) -> Result<bool, NTSTATUS>,
) -> Result<bool, NTSTATUS> {
    let (mut at, end) = (offset, offset + length);
    while at < end {
        let v = vacb::get_va(scm, at)?;
        let part = u64::from(v.left).min(end - at);
        let r = f(&v, at, part);
        vacb::free_va(v.vacb);
        if !r? {
            return Ok(false);
        }
        at += part;
    }
    Ok(true)
}

/// What `CcCopyReadEx` is entered as: the fourth argument is `Wait`,
/// then the buffer, the status block and the issuing thread.
///
/// # Safety
/// Called by a file system as `CcCopyReadEx` on a cached file, with
/// `context` from `nk_with_caller_context`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_cc_copy_read_ex(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    length: u32,
    context: *mut Context,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let wait = fourth_argument(&*context) as u8 != 0;
        let buffer = stack_argument(&*context, 4) as *mut u8;
        let iosb = stack_argument(&*context, 5) as *mut IO_STATUS_BLOCK;
        let r = copy_read(file, offset.read_unaligned() as u64, length, wait, buffer);
        let done = or_raise(context, r);
        if done {
            iosb.write(IO_STATUS_BLOCK {
                Status: STATUS_SUCCESS,
                Information: length as usize,
            });
        }
        u8::from(done)
    }
}

/// `CcCopyReadEx`'s work.
///
/// # Safety
/// `file` is a cached file object; `buffer` the caller's, `length`
/// bytes.
pub unsafe fn copy_read(
    file: *mut FILE_OBJECT,
    offset: u64,
    length: u32,
    wait: bool,
    buffer: *mut u8,
) -> Result<bool, NTSTATUS> {
    // SAFETY: per the contract.
    let scm = unsafe { cached(file, "CcCopyReadEx") };
    let end = offset + u64::from(length);
    if end > scm.file_size.get() as u64 {
        cache_manager_bugcheck(format_args!(
            "CcCopyReadEx of {length:#x} bytes at {offset:#x} passes the end of the file \
             ({:#x}) (0x273)",
            scm.file_size.get()
        ));
    }
    if buffer.is_null() {
        return Err(STATUS_INVALID_USER_BUFFER);
    }
    let done = each_view(scm, offset, u64::from(length), |v, at, part| {
        let mode = if wait {
            Resident::FaultIn
        } else {
            Resident::NoIo
        };
        if !cache::make_resident(v.va, part as usize, mode).map_err(io_status)? {
            return Ok(false);
        }
        // SAFETY: the view's bytes are resident; the caller's buffer is
        // checked by the copy, whose faults are an error.
        unsafe {
            user::copy(
                buffer.add((at - offset) as usize),
                v.va as *const u8,
                part as usize,
            )
        }
        .map_err(|_| STATUS_INVALID_USER_BUFFER)?;
        Ok(true)
    })?;
    if done {
        // SAFETY: per the contract.
        if let Some(pcm) = unsafe { pcm_of(file) } {
            let (before, mask) = {
                let _m = MASTER.lock();
                let before = pcm.history.get();
                pcm.history.set(before.after(offset, u64::from(length)));
                (before, pcm.read_ahead_mask.get())
            };
            super::lazy::schedule_read_ahead(file, scm, before, offset, length, mask);
        }
    }
    Ok(done)
}

/// The valid data length in the file's FCB header.
///
/// # Safety
/// `file` is a live file object of a file system.
unsafe fn valid_data_length(file: *mut FILE_OBJECT) -> u64 {
    // SAFETY: per the contract.
    unsafe {
        let header = (*file).FsContext.cast::<FSRTL_COMMON_FCB_HEADER>();
        if header.is_null() {
            0
        } else {
            (&raw const (*header).ValidDataLength).read() as u64
        }
    }
}

/// `CcCopyWriteEx`'s work.
///
/// # Safety
/// As [`copy_read`], the buffer readable.
pub unsafe fn copy_write(
    file: *mut FILE_OBJECT,
    offset: u64,
    length: u32,
    wait: bool,
    buffer: *const u8,
) -> Result<bool, NTSTATUS> {
    // SAFETY: per the contract.
    let (scm, flags, vdl) = unsafe {
        (
            cached(file, "CcCopyWriteEx"),
            (*file).Flags,
            valid_data_length(file),
        )
    };
    if !wait && flags & FO_WRITE_THROUGH != 0 {
        return Ok(false);
    }
    let page = PAGE_SIZE as u64;
    let done = each_view(scm, offset, u64::from(length), |v, at, part| {
        let mut p = at;
        while p < at + part {
            let page_start = p & !(page - 1);
            let stop = (page_start + page).min(at + part);
            let va = v.va + (p - at) as usize;
            let src = buffer.wrapping_add((p - offset) as usize);
            let whole = p == page_start && stop == page_start + page;
            if whole || page_start >= vdl {
                // SAFETY: the view's page; the caller's bytes, whose
                // faults are an error.
                unsafe {
                    cache::copy_to_cached_page(va, src, (p - page_start) as u32, (stop - p) as u32)
                }
                .map_err(|status| {
                    if status == STATUS_ACCESS_VIOLATION {
                        STATUS_INVALID_USER_BUFFER
                    } else {
                        io_status(status)
                    }
                })?;
            } else {
                let mode = if wait {
                    Resident::FaultIn
                } else {
                    Resident::NoIo
                };
                if !cache::make_resident(va, (stop - p) as usize, mode).map_err(io_status)? {
                    return Ok(false);
                }
                // SAFETY: as above.
                unsafe { user::copy(va as *mut u8, src, (stop - p) as usize) }
                    .map_err(|_| STATUS_INVALID_USER_BUFFER)?;
            }
            p = stop;
        }
        set_dirty_in_mask(scm, at, part)?;
        Ok(true)
    })?;
    if done && flags & FO_WRITE_THROUGH != 0 {
        let written = flush_scm(scm, Some((offset, length)), None);
        if nt_error(written.Status) {
            return Err(io_status(written.Status));
        }
    }
    Ok(done)
}

/// What `CcCopyWriteEx` is entered as: the fourth argument is `Wait`,
/// then the buffer and the issuing thread.
///
/// # Safety
/// As [`nk_cc_copy_read_ex`], for `CcCopyWriteEx`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_cc_copy_write_ex(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    length: u32,
    context: *mut Context,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let wait = fourth_argument(&*context) as u8 != 0;
        let buffer = stack_argument(&*context, 4) as *const u8;
        let r = copy_write(file, offset.read_unaligned() as u64, length, wait, buffer);
        u8::from(or_raise(context, r))
    }
}
