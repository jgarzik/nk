//! Remove locks: a count of the requests in progress on a device, and a
//! way to wait for them to drain before the device goes away.
//!
//! The lock is the driver's memory, laid out as Windows lays out the
//! free-build `IO_REMOVE_LOCK`: a removed flag, a count that starts at
//! one, and an event set when the count reaches zero. The `Ex` routines
//! are what the documented macros expand to.

#![allow(non_snake_case)]

use crate::ke::wait;
use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, AtomicU8, Ordering};
use nk_ntabi::io::IO_REMOVE_LOCK;
use nk_ntabi::status::*;

/// The device is being removed.
pub const STATUS_DELETE_PENDING: NTSTATUS = 0xC000_0056u32 as NTSTATUS;

/// # Safety
/// `lock` points to a live `IO_REMOVE_LOCK`.
unsafe fn count<'a>(lock: *mut IO_REMOVE_LOCK) -> &'a AtomicI32 {
    // SAFETY: per the contract.
    unsafe { AtomicI32::from_ptr(&raw mut (*lock).IoCount) }
}

/// # Safety
/// `lock` points to a live `IO_REMOVE_LOCK`.
unsafe fn removed<'a>(lock: *mut IO_REMOVE_LOCK) -> &'a AtomicU8 {
    // SAFETY: per the contract.
    unsafe { AtomicU8::from_ptr(&raw mut (*lock).Removed) }
}

/// [`IoInitializeRemoveLockEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioinitializeremovelock).
/// The tag and limits are for checked builds; only the common part of
/// the lock is touched.
///
/// # Safety
/// `lock` points to writable storage for an `IO_REMOVE_LOCK`.
pub unsafe extern "C" fn IoInitializeRemoveLockEx(
    lock: *mut IO_REMOVE_LOCK,
    _allocate_tag: u32,
    _max_locked_minutes: u32,
    _high_watermark: u32,
    _remlock_size: u32,
) {
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*lock).Removed).write(0);
        (&raw mut (*lock).IoCount).write(1);
        wait::KeInitializeEvent(&raw mut (*lock).RemoveEvent, 1, 0);
    }
}

/// [`IoAcquireRemoveLockEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioacquireremovelock):
/// count a request in, unless the device is being removed.
///
/// # Safety
/// `lock` is a live, initialised `IO_REMOVE_LOCK`.
pub unsafe extern "C" fn IoAcquireRemoveLockEx(
    lock: *mut IO_REMOVE_LOCK,
    _tag: *mut c_void,
    _file: *const u8,
    _line: u32,
    _remlock_size: u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        count(lock).fetch_add(1, Ordering::AcqRel);
        if removed(lock).load(Ordering::Acquire) == 0 {
            return STATUS_SUCCESS;
        }
        // Too late: count it back out, and wake the remover if that was
        // the last.
        if count(lock).fetch_sub(1, Ordering::AcqRel) == 1 {
            wait::KeSetEvent(&raw mut (*lock).RemoveEvent, 0, 0);
        }
        STATUS_DELETE_PENDING
    }
}

/// [`IoReleaseRemoveLockEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioreleaseremovelock):
/// count a request out.
///
/// # Safety
/// `lock` is a live, initialised `IO_REMOVE_LOCK` the caller acquired.
pub unsafe extern "C" fn IoReleaseRemoveLockEx(
    lock: *mut IO_REMOVE_LOCK,
    _tag: *mut c_void,
    _remlock_size: u32,
) {
    // SAFETY: per the contract.
    unsafe {
        if count(lock).fetch_sub(1, Ordering::AcqRel) == 1 {
            wait::KeSetEvent(&raw mut (*lock).RemoveEvent, 0, 0);
        }
    }
}

/// [`IoReleaseRemoveLockAndWaitEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioreleaseremovelockandwait):
/// mark the device as being removed, give up the caller's own count and
/// the one the lock started with, and wait for every other request to
/// be counted out.
///
/// # Safety
/// `lock` is a live, initialised `IO_REMOVE_LOCK` the caller acquired;
/// the caller is at `PASSIVE_LEVEL`.
pub unsafe extern "C" fn IoReleaseRemoveLockAndWaitEx(
    lock: *mut IO_REMOVE_LOCK,
    _tag: *mut c_void,
    _remlock_size: u32,
) {
    // SAFETY: per the contract.
    unsafe {
        removed(lock).store(1, Ordering::Release);
        count(lock).fetch_sub(1, Ordering::AcqRel);
        if count(lock).fetch_sub(1, Ordering::AcqRel) > 1 {
            wait::wait(Some((&raw mut (*lock).RemoveEvent).cast()), None);
        }
    }
}
