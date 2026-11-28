//! Change notification: the synchronisation object a file system keeps
//! per volume for its list of directories being watched, and the
//! routines that walk that list.
//!
//! The object (`REAL_NOTIFY_SYNC` in the pinned kernel, 0x48 bytes from
//! the pool) is a fast mutex its owner may take again: the owning thread
//! and a count follow the mutex. The list is the file system's
//! `LIST_ENTRY`; a watch is added to it only by
//! `FsRtlNotifyFullChangeDirectory`, which is a trap, so the list is
//! always empty and reporting a change or cleaning up a handle finds no
//! watch to complete. A watch on the list stops the system by name,
//! since NK cannot have put it there.

#![allow(non_snake_case)]

use crate::kd;
use crate::ke::mutex::{
    ExAcquireFastMutexUnsafe, ExReleaseFastMutexUnsafe, KeInitializeGuardedMutex,
};
use crate::mm::pool;
use crate::ps::KeGetCurrentThread;
use core::ffi::c_void;
use nk_ntabi::ke::{FAST_MUTEX, LIST_ENTRY};

/// The pool tag of the object.
const TAG: u32 = u32::from_le_bytes(*b"FSrN");

/// The pinned kernel's `REAL_NOTIFY_SYNC`.
#[repr(C)]
struct Sync {
    mutex: FAST_MUTEX,
    owner: *mut c_void,
    count: u32,
}

const _: () = assert!(size_of::<Sync>() == 0x48);

/// [`FsRtlNotifyInitializeSync`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlnotifyinitializesync):
/// a free object in `*sync`, null without memory.
///
/// # Safety
/// `sync` is writable.
pub unsafe extern "C" fn FsRtlNotifyInitializeSync(sync: *mut *mut c_void) {
    let object = pool::alloc(size_of::<Sync>(), TAG).cast::<Sync>();
    // SAFETY: per the contract; the object is a fresh pool block.
    unsafe {
        if !object.is_null() {
            KeInitializeGuardedMutex(&raw mut (*object).mutex);
            (&raw mut (*object).owner).write(core::ptr::null_mut());
            (&raw mut (*object).count).write(0);
        }
        sync.write_unaligned(object.cast());
    }
}

/// [`FsRtlNotifyUninitializeSync`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlnotifyuninitializesync):
/// free the object.
///
/// # Safety
/// `sync` points to null or an object nothing holds.
pub unsafe extern "C" fn FsRtlNotifyUninitializeSync(sync: *mut *mut c_void) {
    // SAFETY: per the contract.
    unsafe {
        let object = sync.read_unaligned();
        if !object.is_null() {
            let _ = pool::free(object.cast());
            sync.write_unaligned(core::ptr::null_mut());
        }
    }
}

/// Take the object, again if this thread holds it, and look at the list:
/// it must be empty. Give the object up.
///
/// # Safety
/// `sync` is an initialised object; `list` is the file system's list
/// head; the caller is in a critical region, as for a fast mutex taken
/// without raising the IRQL.
unsafe fn walk(sync: *mut c_void, list: *mut LIST_ENTRY, routine: &str) {
    let sync = sync.cast::<Sync>();
    let me = KeGetCurrentThread();
    // SAFETY: per the contract.
    unsafe {
        if (&raw const (*sync).owner).read() != me {
            ExAcquireFastMutexUnsafe(&raw mut (*sync).mutex);
            (&raw mut (*sync).owner).write(me);
        }
        (&raw mut (*sync).count).write((*sync).count + 1);
        let first = (&raw const (*list).Flink).read_unaligned();
        if first != list {
            kd::bugcheck(format_args!(
                "{routine}: a directory watch at {first:p}, which NK never registers"
            ));
        }
        let count = (*sync).count - 1;
        (&raw mut (*sync).count).write(count);
        if count == 0 {
            (&raw mut (*sync).owner).write(core::ptr::null_mut());
            ExReleaseFastMutexUnsafe(&raw mut (*sync).mutex);
        }
    }
}

/// [`FsRtlNotifyFullReportChange`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlnotifyfullreportchange):
/// a change in a directory, with no watch to tell.
///
/// # Safety
/// As [`walk`].
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn FsRtlNotifyFullReportChange(
    sync: *mut c_void,
    list: *mut LIST_ENTRY,
    _full_name: *mut c_void,
    _target_offset: u16,
    _stream: *mut c_void,
    _normalized_parent: *mut c_void,
    _filter: u32,
    _action: u32,
    _context: *mut c_void,
) {
    // SAFETY: per the contract.
    unsafe { walk(sync, list, "FsRtlNotifyFullReportChange") }
}

/// [`FsRtlNotifyCleanup`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlnotifycleanup):
/// a handle closed, with no watch of its to complete.
///
/// # Safety
/// As [`walk`].
pub unsafe extern "C" fn FsRtlNotifyCleanup(
    sync: *mut c_void,
    list: *mut LIST_ENTRY,
    _fs_context: *mut c_void,
) {
    // SAFETY: per the contract.
    unsafe { walk(sync, list, "FsRtlNotifyCleanup") }
}
