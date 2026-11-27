//! The MDL interface: a file system hands its caller the cache's own
//! pages, locked, rather than copying (`CcMdlRead`, `CcPrepareMdlWrite`),
//! and is told when the caller is done with them.
//!
//! One MDL per view the range touches, chained in order. A read's pages
//! are read in first; a write's are read only where the range covers a
//! page in part. A write holds the map open (its open count) until it is
//! completed or aborted; completing it marks the range dirty, or with a
//! write-through file object writes it at once, raising a failure.

use super::flush::{flush_scm, set_dirty_in_mask};
use super::vacb;
use super::{MASTER, Scm, cached, io_status, or_raise, pcm_of};
use crate::arch::seh::{Context, fourth_argument, stack_argument};
use crate::io::mdl::{IoAllocateMdl, IoFreeMdl, MmUnlockPages, probe_and_lock};
use crate::ke::seh::{self, Guard};
use crate::mm::cache::{self, Resident};
use nk_ntabi::cc::FO_WRITE_THROUGH;
use nk_ntabi::io::{
    FAST_IO_DISPATCH, FILE_OBJECT, IO_READ_ACCESS, IO_STATUS_BLOCK, IO_WRITE_ACCESS, KERNEL_MODE,
    MDL,
};
use nk_ntabi::status::*;

/// Offsets in `FAST_IO_DISPATCH`.
const FAST_IO_MDL_READ_COMPLETE: usize = 0x88;
const FAST_IO_MDL_WRITE_COMPLETE: usize = 0x98;

/// Lock the pages of `[offset, offset + length)` of `scm`, view by view,
/// into a chain of MDLs, after `prepare` made each view's part resident.
/// On failure every MDL made is let go.
fn lock_range(
    scm: &Scm,
    offset: u64,
    length: u64,
    operation: u32,
    prepare: impl Fn(usize, usize) -> Result<bool, NTSTATUS>,
) -> Result<*mut MDL, NTSTATUS> {
    let mut chain: *mut MDL = core::ptr::null_mut();
    let mut tail: *mut *mut MDL = &raw mut chain;
    let (mut at, end) = (offset, offset + length);
    let mut failed = None;
    while at < end {
        let v = match vacb::get_va(scm, at) {
            Ok(v) => v,
            Err(status) => {
                failed = Some(status);
                break;
            }
        };
        let part = u64::from(v.left).min(end - at);
        let r = prepare(v.va, part as usize).and_then(|_| {
            // SAFETY: the view's pages, mapped while it is held.
            let mdl =
                unsafe { IoAllocateMdl(v.va as *mut _, part as u32, 0, 0, core::ptr::null_mut()) };
            if mdl.is_null() {
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            // SAFETY: a fresh MDL of the view's pages.
            match unsafe { probe_and_lock(mdl, KERNEL_MODE, operation) } {
                Ok(()) => Ok(mdl),
                Err(status) => {
                    // SAFETY: ours, not locked.
                    unsafe { IoFreeMdl(mdl) };
                    Err(io_status(status))
                }
            }
        });
        vacb::free_va(v.vacb);
        match r {
            Ok(mdl) => {
                // SAFETY: the chain's last link, ours.
                unsafe {
                    *tail = mdl;
                    tail = &raw mut (*mdl).Next;
                }
            }
            Err(status) => {
                failed = Some(status);
                break;
            }
        }
        at += part;
    }
    match failed {
        None => Ok(chain),
        Some(status) => {
            // SAFETY: the chain made here.
            unsafe { release_chain(chain) };
            Err(status)
        }
    }
}

/// Unlock and free every MDL of `chain`.
///
/// # Safety
/// `chain` is a chain of locked MDLs this module made.
unsafe fn release_chain(mut chain: *mut MDL) {
    while !chain.is_null() {
        // SAFETY: per the contract; the link is read before the MDL goes.
        unsafe {
            let next = (*chain).Next;
            MmUnlockPages(chain);
            IoFreeMdl(chain);
            chain = next;
        }
    }
}

/// Append `chain` to the caller's chain at `out`.
///
/// # Safety
/// `out` is writable and holds null or a chain.
unsafe fn append(out: *mut *mut MDL, chain: *mut MDL) {
    // SAFETY: per the contract.
    unsafe {
        let mut at = out;
        while !(*at).is_null() {
            at = &raw mut (**at).Next;
        }
        *at = chain;
    }
}

/// What `CcMdlRead` is entered as: the fourth argument is where the
/// chain goes, the fifth the status block.
///
/// # Safety
/// Called by a file system as `CcMdlRead` on a cached file, with
/// `context` from `nk_with_caller_context`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_cc_mdl_read(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    length: u32,
    context: *mut Context,
) {
    // SAFETY: per the contract.
    unsafe {
        let out = fourth_argument(&*context) as *mut *mut MDL;
        let iosb = stack_argument(&*context, 4) as *mut IO_STATUS_BLOCK;
        let r = mdl_read(file, offset.read_unaligned() as u64, length, out);
        or_raise(context, r);
        iosb.write(IO_STATUS_BLOCK {
            Status: STATUS_SUCCESS,
            Information: length as usize,
        });
    }
}

/// `CcMdlRead`'s work.
///
/// # Safety
/// `file` is a cached file object; `out` writable.
pub unsafe fn mdl_read(
    file: *mut FILE_OBJECT,
    offset: u64,
    length: u32,
    out: *mut *mut MDL,
) -> Result<(), NTSTATUS> {
    // SAFETY: per the contract.
    let scm = unsafe { cached(file, "CcMdlRead") };
    let chain = lock_range(scm, offset, u64::from(length), IO_READ_ACCESS, |va, len| {
        cache::make_resident(va, len, Resident::FaultIn).map_err(io_status)
    })?;
    // SAFETY: per the contract.
    unsafe { append(out, chain) };
    // SAFETY: as above.
    if let Some(pcm) = unsafe { pcm_of(file) } {
        let (before, mask) = {
            let _m = MASTER.lock();
            let before = pcm.history.get();
            pcm.history.set(before.after(offset, u64::from(length)));
            (before, pcm.read_ahead_mask.get())
        };
        super::lazy::schedule_read_ahead(file, scm, before, offset, length, mask);
    }
    Ok(())
}

/// The file system's fast-I/O routine at `offset` for `file`'s device,
/// if it has one.
///
/// # Safety
/// `file` is an open file object.
unsafe fn fast_io(file: *mut FILE_OBJECT, offset: usize) -> Option<(usize, usize)> {
    // SAFETY: per the contract; the driver's table, read by its size.
    unsafe {
        let device = crate::io::file::related_device(file);
        let table = (*(*device).DriverObject)
            .FastIoDispatch
            .cast::<FAST_IO_DISPATCH>();
        if table.is_null() || ((*table).SizeOfFastIoDispatch as usize) < offset + 8 {
            return None;
        }
        let r = table.cast::<u8>().add(offset).cast::<usize>().read();
        (r != 0).then_some((r, device.addr()))
    }
}

/// `CcMdlReadComplete2`: let go of a read's MDLs.
///
/// # Safety
/// `chain` came from `CcMdlRead`.
pub unsafe fn mdl_read_complete2(chain: *mut MDL) {
    // SAFETY: per the contract.
    unsafe { release_chain(chain) };
}

/// [`CcMdlReadComplete`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccmdlreadcomplete):
/// the caller is done with a read's pages: through the file system's
/// `MdlReadComplete` if it has one, else directly.
///
/// # Safety
/// `file` is the file object `chain` was read through.
pub unsafe extern "C" fn CcMdlReadComplete(file: *mut FILE_OBJECT, chain: *mut MDL) {
    // SAFETY: per the contract.
    unsafe {
        if let Some((routine, device)) = fast_io(file, FAST_IO_MDL_READ_COMPLETE)
            && seh::call(
                routine,
                [file.addr(), chain.addr(), device, 0],
                &Guard::Nothing,
            ) as u8
                != 0
        {
            return;
        }
        mdl_read_complete2(chain);
    }
}

/// What `CcPrepareMdlWrite` is entered as: as `CcMdlRead`.
///
/// # Safety
/// As [`nk_cc_mdl_read`], for `CcPrepareMdlWrite`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_cc_prepare_mdl_write(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    length: u32,
    context: *mut Context,
) {
    // SAFETY: per the contract.
    unsafe {
        let out = fourth_argument(&*context) as *mut *mut MDL;
        let iosb = stack_argument(&*context, 4) as *mut IO_STATUS_BLOCK;
        let r = prepare_mdl_write(file, offset.read_unaligned() as u64, length, out);
        or_raise(context, r);
        iosb.write(IO_STATUS_BLOCK {
            Status: STATUS_SUCCESS,
            Information: length as usize,
        });
    }
}

/// `CcPrepareMdlWrite`'s work. The map stays open until the write is
/// completed or aborted.
///
/// # Safety
/// As [`mdl_read`].
pub unsafe fn prepare_mdl_write(
    file: *mut FILE_OBJECT,
    offset: u64,
    length: u32,
    out: *mut *mut MDL,
) -> Result<(), NTSTATUS> {
    // SAFETY: per the contract.
    let scm = unsafe { cached(file, "CcPrepareMdlWrite") };
    let chain = lock_range(
        scm,
        offset,
        u64::from(length),
        IO_WRITE_ACCESS,
        |va, len| cache::make_resident(va, len, Resident::WillOverwrite).map_err(io_status),
    )?;
    {
        let _m = MASTER.lock();
        scm.open_count.set(scm.open_count.get() + 1);
    }
    // SAFETY: per the contract.
    unsafe { append(out, chain) };
    Ok(())
}

/// Mark `[offset, offset + length)` of `scm` modified in the memory
/// manager, through its views; the pages are locked, so resident.
fn mark_modified(scm: &Scm, offset: u64, length: u32) {
    let (mut at, end) = (offset, offset + u64::from(length));
    while at < end {
        let Ok(v) = vacb::get_va(scm, at) else { return };
        let part = u64::from(v.left).min(end - at);
        if cache::make_resident(v.va, part as usize, Resident::NoIo) == Ok(true) {
            cache::set_range_modified(v.va, part as usize);
        }
        vacb::free_va(v.vacb);
        at += part;
    }
}

/// One open count fewer, for a write completed or aborted.
fn close_write(scm: &Scm) {
    let _m = MASTER.lock();
    scm.open_count.set(scm.open_count.get() - 1);
}

/// `CcMdlWriteComplete2`: the caller wrote into the pages of `chain`,
/// which starts at `offset`: each MDL's range is dirty, or with a
/// write-through file object written at once.
///
/// # Safety
/// `chain` came from `CcPrepareMdlWrite` on `file`.
pub unsafe fn mdl_write_complete2(
    file: *mut FILE_OBJECT,
    mut offset: u64,
    mut chain: *mut MDL,
) -> Result<(), NTSTATUS> {
    // SAFETY: per the contract.
    let (scm, write_through) = unsafe {
        (
            cached(file, "CcMdlWriteComplete"),
            (*file).Flags & FO_WRITE_THROUGH != 0,
        )
    };
    let mut failed = None;
    while !chain.is_null() {
        // SAFETY: a locked MDL of the chain.
        let count = unsafe { (*chain).ByteCount };
        // Its pages were written through another mapping: the memory
        // manager hears they are modified, as locking them for writing
        // tells Windows'.
        mark_modified(scm, offset, count);
        // SAFETY: a locked MDL of the chain; its link read before it goes.
        let next = unsafe {
            let next = (*chain).Next;
            MmUnlockPages(chain);
            IoFreeMdl(chain);
            next
        };
        if failed.is_none() {
            let r = if write_through {
                let written = flush_scm(scm, Some((offset, count)), None);
                if nt_error(written.Status) {
                    Err(io_status(written.Status))
                } else {
                    Ok(())
                }
            } else {
                set_dirty_in_mask(scm, offset, u64::from(count))
            };
            failed = r.err();
        }
        offset += u64::from(count);
        chain = next;
    }
    close_write(scm);
    failed.map_or(Ok(()), Err)
}

/// What `CcMdlWriteComplete` is entered as: through the file system's
/// `MdlWriteComplete` if it has one, else [`mdl_write_complete2`],
/// raising its failure.
///
/// # Safety
/// As [`mdl_write_complete2`], with `context` from
/// `nk_with_caller_context`; `offset` readable.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_cc_mdl_write_complete(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    chain: *mut MDL,
    context: *mut Context,
) {
    // SAFETY: per the contract.
    unsafe {
        if let Some((routine, device)) = fast_io(file, FAST_IO_MDL_WRITE_COMPLETE)
            && seh::call(
                routine,
                [file.addr(), offset.addr(), chain.addr(), device],
                &Guard::Nothing,
            ) as u8
                != 0
        {
            return;
        }
        let r = mdl_write_complete2(file, offset.read_unaligned() as u64, chain);
        or_raise(context, r);
    }
}

/// [`CcMdlWriteAbort`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ccmdlwriteabort):
/// the caller gives a prepared write up: its pages are let go and
/// nothing is marked dirty.
///
/// # Safety
/// `chain` came from `CcPrepareMdlWrite` on `file`.
pub unsafe extern "C" fn CcMdlWriteAbort(file: *mut FILE_OBJECT, chain: *mut MDL) {
    // SAFETY: per the contract.
    unsafe {
        let scm = cached(file, "CcMdlWriteAbort");
        release_chain(chain);
        close_write(scm);
    }
}
