//! Byte-range locks (`FILE_LOCK`), as far as a file system meets them
//! when no process has locked a range.
//!
//! The kernel's record of a stream's locks hangs on the file lock's
//! `LockInformation`, made with the first lock. NK takes none: the
//! routines that lock (`FsRtlProcessFileLock`, `FsRtlPrivateLock`) are
//! traps. The rest do what the pinned kernel does with no record:
//! every access is allowed, no lock is waiting, an unlock finds no
//! range locked (`STATUS_RANGE_NOT_LOCKED`). A record that is not null
//! stops the system by name, since NK cannot have made it.

#![allow(non_snake_case)]

use crate::kd;
use core::ffi::c_void;
use nk_ntabi::fsrtl::FILE_LOCK;
use nk_ntabi::io::IRP;
use nk_ntabi::status::{NTSTATUS, STATUS_RANGE_NOT_LOCKED};

/// Whether the file lock has no record of locks; stop the system if it
/// has one.
///
/// # Safety
/// `lock` is an initialised file lock.
unsafe fn unlocked(lock: *const FILE_LOCK, routine: &str) -> bool {
    // SAFETY: per the contract.
    let record = unsafe { (&raw const (*lock).LockInformation).read_unaligned() };
    if !record.is_null() {
        kd::bugcheck(format_args!(
            "{routine}: a record of byte-range locks at {record:p}, which NK never makes"
        ));
    }
    true
}

/// [`FsRtlInitializeFileLock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlinitializefilelock):
/// the routines, no record, the counter of requests in progress zero;
/// the rest is left as it was, as on Windows.
///
/// # Safety
/// `lock` is the file system's writable file lock.
pub unsafe extern "C" fn FsRtlInitializeFileLock(
    lock: *mut FILE_LOCK,
    complete: *mut c_void,
    unlock: *mut c_void,
) {
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*lock).CompleteLockIrpRoutine).write_unaligned(complete);
        (&raw mut (*lock).LockInformation).write_unaligned(core::ptr::null_mut());
        (&raw mut (*lock).FastIoIsQuestionable).write(0);
        (&raw mut (*lock).UnlockRoutine).write_unaligned(unlock);
        (&raw mut (*lock).LockRequestsInProgress).write_unaligned(0);
    }
}

/// [`FsRtlUninitializeFileLock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtluninitializefilelock):
/// nothing to free without a record.
///
/// # Safety
/// `lock` is an initialised file lock.
pub unsafe extern "C" fn FsRtlUninitializeFileLock(lock: *mut FILE_LOCK) {
    // SAFETY: per the contract.
    unsafe { unlocked(lock, "FsRtlUninitializeFileLock") };
}

/// [`FsRtlCheckLockForReadAccess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlchecklockforreadaccess):
/// the read is allowed.
///
/// # Safety
/// `lock` is an initialised file lock.
pub unsafe extern "C" fn FsRtlCheckLockForReadAccess(lock: *mut FILE_LOCK, _irp: *mut IRP) -> u8 {
    // SAFETY: per the contract.
    u8::from(unsafe { unlocked(lock, "FsRtlCheckLockForReadAccess") })
}

/// [`FsRtlCheckLockForWriteAccess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlchecklockforwriteaccess):
/// the write is allowed.
///
/// # Safety
/// `lock` is an initialised file lock.
pub unsafe extern "C" fn FsRtlCheckLockForWriteAccess(lock: *mut FILE_LOCK, _irp: *mut IRP) -> u8 {
    // SAFETY: per the contract.
    u8::from(unsafe { unlocked(lock, "FsRtlCheckLockForWriteAccess") })
}

/// [`FsRtlCheckLockForOplockRequest`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlchecklockforoplockrequest):
/// no lock stands in the way of an oplock.
///
/// # Safety
/// `lock` is an initialised file lock.
pub unsafe extern "C" fn FsRtlCheckLockForOplockRequest(
    lock: *mut FILE_LOCK,
    _allocation_size: *mut i64,
) -> u8 {
    // SAFETY: per the contract.
    u8::from(unsafe { unlocked(lock, "FsRtlCheckLockForOplockRequest") })
}

/// [`FsRtlFastCheckLockForRead`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlfastchecklockforread):
/// the read is allowed.
///
/// # Safety
/// `lock` is an initialised file lock.
pub unsafe extern "C" fn FsRtlFastCheckLockForRead(
    lock: *mut FILE_LOCK,
    _start: *mut i64,
    _length: *mut i64,
    _key: u32,
    _file: *mut c_void,
    _process: *mut c_void,
) -> u8 {
    // SAFETY: per the contract.
    u8::from(unsafe { unlocked(lock, "FsRtlFastCheckLockForRead") })
}

/// [`FsRtlFastCheckLockForWrite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlfastchecklockforwrite):
/// the write is allowed.
///
/// # Safety
/// `lock` is an initialised file lock.
pub unsafe extern "C" fn FsRtlFastCheckLockForWrite(
    lock: *mut FILE_LOCK,
    _start: *mut i64,
    _length: *mut i64,
    _key: u32,
    _file: *mut c_void,
    _process: *mut c_void,
) -> u8 {
    // SAFETY: per the contract.
    u8::from(unsafe { unlocked(lock, "FsRtlFastCheckLockForWrite") })
}

/// `FsRtlAreThereWaitingFileLocks` (`ntifs.h`): no lock request waits.
///
/// # Safety
/// `lock` is null or an initialised file lock.
pub unsafe extern "C" fn FsRtlAreThereWaitingFileLocks(lock: *mut FILE_LOCK) -> u8 {
    if !lock.is_null() {
        // SAFETY: per the contract.
        unsafe { unlocked(lock, "FsRtlAreThereWaitingFileLocks") };
    }
    0
}

/// [`FsRtlFastUnlockSingle`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlfastunlocksingle):
/// no range is locked.
///
/// # Safety
/// `lock` is an initialised file lock.
pub unsafe extern "C" fn FsRtlFastUnlockSingle(
    lock: *mut FILE_LOCK,
    _file: *mut c_void,
    _start: *mut i64,
    _length: *mut i64,
    _process: *mut c_void,
    _key: u32,
    _context: *mut c_void,
    _already_synchronized: u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { unlocked(lock, "FsRtlFastUnlockSingle") };
    STATUS_RANGE_NOT_LOCKED
}

/// [`FsRtlFastUnlockAll`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlfastunlockall):
/// no range is locked.
///
/// # Safety
/// `lock` is an initialised file lock.
pub unsafe extern "C" fn FsRtlFastUnlockAll(
    lock: *mut FILE_LOCK,
    _file: *mut c_void,
    _process: *mut c_void,
    _context: *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { unlocked(lock, "FsRtlFastUnlockAll") };
    STATUS_RANGE_NOT_LOCKED
}

/// [`FsRtlFastUnlockAllByKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlfastunlockallbykey):
/// no range is locked.
///
/// # Safety
/// `lock` is an initialised file lock.
pub unsafe extern "C" fn FsRtlFastUnlockAllByKey(
    lock: *mut FILE_LOCK,
    _file: *mut c_void,
    _process: *mut c_void,
    _key: u32,
    _context: *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { unlocked(lock, "FsRtlFastUnlockAllByKey") };
    STATUS_RANGE_NOT_LOCKED
}
