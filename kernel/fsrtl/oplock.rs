//! Opportunistic locks, as far as a file system meets them when none is
//! ever granted.
//!
//! An `OPLOCK` is a pointer in the file system's control block, null
//! until `FsRtlOplockFsctrl` grants the first oplock on the stream. NK
//! grants none: that routine is a trap, so no binary NK runs can create
//! one. Every other routine is what the pinned kernel does with a null
//! oplock: initialising writes nothing (Windows' routine is a bare
//! return; the file system zeroed the field), a check or a break lets
//! the operation go on at once, fast I/O is possible and no batch or
//! handle oplock is held. NK records no oplock keys, which only an
//! oplock's owner would ask for. Meeting an oplock that is not null
//! stops the system by name, since NK cannot have made it.

#![allow(non_snake_case)]

use crate::kd;
use core::ffi::c_void;
use nk_ntabi::io::{IO_STACK_LOCATION, IRP};
use nk_ntabi::status::{NTSTATUS, STATUS_SUCCESS};

/// `FSCTL_REQUEST_OPLOCK`.
const REQUEST_OPLOCK: u32 = 0x0009_0240;
/// `FSCTL_REQUEST_OPLOCK_LEVEL_2`.
const REQUEST_OPLOCK_LEVEL_2: u32 = 0x0009_0004;

/// Whether the file system's oplock field is null; stop the system if
/// it is not.
///
/// # Safety
/// `oplock` points to the field.
unsafe fn none(oplock: *const *mut c_void, routine: &str) -> bool {
    // SAFETY: per the contract.
    let held = unsafe { oplock.read_unaligned() };
    if !held.is_null() {
        kd::bugcheck(format_args!(
            "{routine}: an oplock at {held:p}, which NK never grants"
        ));
    }
    true
}

/// [`FsRtlInitializeOplock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlinitializeoplock):
/// nothing, as on Windows.
pub extern "C" fn FsRtlInitializeOplock(_oplock: *mut *mut c_void) {}

/// [`FsRtlUninitializeOplock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtluninitializeoplock):
/// nothing to free for a null oplock.
///
/// # Safety
/// `oplock` points to the file system's field.
pub unsafe extern "C" fn FsRtlUninitializeOplock(oplock: *mut *mut c_void) {
    // SAFETY: per the contract.
    unsafe { none(oplock, "FsRtlUninitializeOplock") };
}

/// [`FsRtlCheckOplock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlcheckoplock):
/// the operation goes on.
///
/// # Safety
/// `oplock` points to the file system's field.
pub unsafe extern "C" fn FsRtlCheckOplock(
    oplock: *mut *mut c_void,
    _irp: *mut IRP,
    _context: *mut c_void,
    _completion: *mut c_void,
    _post: *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { none(oplock, "FsRtlCheckOplock") };
    STATUS_SUCCESS
}

/// [`FsRtlCheckOplockEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlcheckoplockex):
/// the operation goes on, whatever the flags.
///
/// # Safety
/// `oplock` points to the file system's field.
pub unsafe extern "C" fn FsRtlCheckOplockEx(
    oplock: *mut *mut c_void,
    _irp: *mut IRP,
    _flags: u32,
    _context: *mut c_void,
    _completion: *mut c_void,
    _post: *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { none(oplock, "FsRtlCheckOplockEx") };
    STATUS_SUCCESS
}

/// [`FsRtlOplockBreakH`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtloplockbreakh):
/// no handle oplock to break.
///
/// # Safety
/// `oplock` points to the file system's field.
pub unsafe extern "C" fn FsRtlOplockBreakH(
    oplock: *mut *mut c_void,
    _irp: *mut IRP,
    _flags: u32,
    _context: *mut c_void,
    _completion: *mut c_void,
    _post: *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { none(oplock, "FsRtlOplockBreakH") };
    STATUS_SUCCESS
}

/// [`FsRtlOplockIsFastIoPossible`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtloplockisfastiopossible):
/// with no oplock, fast I/O is possible.
///
/// # Safety
/// `oplock` points to the file system's field.
pub unsafe extern "C" fn FsRtlOplockIsFastIoPossible(oplock: *mut *mut c_void) -> u8 {
    // SAFETY: per the contract.
    u8::from(unsafe { none(oplock, "FsRtlOplockIsFastIoPossible") })
}

/// [`FsRtlCurrentBatchOplock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlcurrentbatchoplock):
/// no batch oplock is held.
///
/// # Safety
/// `oplock` points to the file system's field.
pub unsafe extern "C" fn FsRtlCurrentBatchOplock(oplock: *mut *mut c_void) -> u8 {
    // SAFETY: per the contract.
    unsafe { none(oplock, "FsRtlCurrentBatchOplock") };
    0
}

/// [`FsRtlCurrentOplockH`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlcurrentoplockh):
/// no handle oplock is held.
///
/// # Safety
/// `oplock` points to the file system's field.
pub unsafe extern "C" fn FsRtlCurrentOplockH(oplock: *mut *mut c_void) -> u8 {
    // SAFETY: per the contract.
    unsafe { none(oplock, "FsRtlCurrentOplockH") };
    0
}

/// [`FsRtlOplockIsSharedRequest`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtloplockissharedrequest):
/// whether a file-system control request asks for a shared oplock: a
/// level 2 request, or an oplock request whose input's flags do not
/// have bit 2, as the pinned kernel reads them.
///
/// # Safety
/// `irp` is a file-system control request at its current location, with
/// its input in `SystemBuffer` for an oplock request.
pub unsafe extern "C" fn FsRtlOplockIsSharedRequest(irp: *mut IRP) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let location: *const IO_STACK_LOCATION = (*irp).CurrentStackLocation;
        let code = (*location).Parameters[2] as u32;
        match code {
            REQUEST_OPLOCK => {
                let input = (*irp).SystemBuffer.cast::<u32>();
                u8::from(input.add(1).read_unaligned() & 4 == 0)
            }
            REQUEST_OPLOCK_LEVEL_2 => 1,
            _ => 0,
        }
    }
}
