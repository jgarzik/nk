//! What the kernel does for file systems with the header at the front
//! of each stream's control block (`FSRTL_ADVANCED_FCB_HEADER`).
//!
//! The header is the file system's memory, set up by code compiled into
//! the driver; NK reads and writes it through raw pointers, under the
//! lock the header itself carries.

#![allow(non_snake_case)]

use crate::ex::pushlock;
use crate::kd;
use crate::ke::mutex;
use crate::ke::seh::{self, Guard};
use nk_ntabi::fsrtl::*;

/// Take the lock that guards a header's `FilterContexts`: its push
/// lock, in a critical region, or the file system's fast mutex in a
/// header too old to have a push lock.
///
/// # Safety
/// `header` is an initialised advanced header, at or below `APC_LEVEL`.
unsafe fn lock_contexts(header: *mut FSRTL_ADVANCED_FCB_HEADER) {
    // SAFETY: per the contract; the lock is where the version says.
    unsafe {
        if fcb_header_version((*header).Common.ReservedAndVersion) >= FSRTL_FCB_HEADER_V1 {
            mutex::KeEnterCriticalRegion();
            pushlock::ExAcquirePushLockExclusiveEx(&raw mut (*header).PushLock, 0);
        } else {
            mutex::ExAcquireFastMutex((*header).FastMutex);
        }
    }
}

/// Give up what [`lock_contexts`] took.
///
/// # Safety
/// The caller holds the lock of this header.
unsafe fn unlock_contexts(header: *mut FSRTL_ADVANCED_FCB_HEADER) {
    // SAFETY: per the contract.
    unsafe {
        if fcb_header_version((*header).Common.ReservedAndVersion) >= FSRTL_FCB_HEADER_V1 {
            pushlock::ExReleasePushLockEx(&raw mut (*header).PushLock, 0);
            mutex::KeLeaveCriticalRegion();
        } else {
            mutex::ExReleaseFastMutex((*header).FastMutex);
        }
    }
}

/// [`FsRtlTeardownPerStreamContexts`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlteardownperstreamcontexts):
/// a file system is about to free a stream's control block; take every
/// context filters attached to the stream off the header's list and
/// call each one's `FreeCallback`, which frees it.
///
/// As the pinned kernel does it: a list seen empty without the lock is
/// left alone; otherwise the first context is unlinked under the lock,
/// the lock given up, the callback called, and the lock taken again,
/// until the list is empty. So a callback runs with no lock of the
/// header's held and outside the critical region, may take the lock
/// itself, and a context attached meanwhile is torn down too. A list
/// whose links do not lead back stops the system, as Windows' fast fail
/// does.
///
/// A header that is not advanced, or whose `Flags2` does not say
/// filters may attach contexts, has no list to read: nothing is done.
/// (Windows reads the list without looking at the flags; a file system
/// may only pass a header that has one.)
///
/// # Safety
/// `header` is the header of a stream's control block, initialised as
/// `FsRtlSetupAdvancedHeader` does, that no other thread is using; the
/// caller is at or below `APC_LEVEL`.
pub unsafe extern "C" fn FsRtlTeardownPerStreamContexts(header: *mut FSRTL_ADVANCED_FCB_HEADER) {
    // SAFETY: per the contract; the driver's memory is read and written
    // field by field, never borrowed.
    unsafe {
        if (*header).Common.Flags & FSRTL_FLAG_ADVANCED_HEADER == 0
            || (*header).Common.Flags2 & FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS == 0
        {
            return;
        }
        let head = &raw mut (*header).FilterContexts;
        if (*head).Flink == head {
            return;
        }
        lock_contexts(header);
        loop {
            let entry = (*head).Flink;
            if entry == head {
                break;
            }
            let next = (*entry).Flink;
            if (*entry).Blink != head || (*next).Blink != entry {
                kd::bugcheck(format_args!(
                    "0x00000139 KERNEL_SECURITY_CHECK_FAILURE: the stream contexts of the \
                     header at {header:p} are not a list at {entry:p} (parameters 0x3, 0, 0, 0)"
                ));
            }
            (*head).Flink = next;
            (*next).Blink = head;
            // `Links` is a context's first field.
            let context = entry.cast::<FSRTL_PER_STREAM_CONTEXT>();
            unlock_contexts(header);
            // The filter's routine, called whatever the field holds, as
            // Windows calls it. If it raises, this frame is unwound
            // owing nothing: the context is off the list and no lock is
            // held.
            let free = (&raw const (*context).FreeCallback).cast::<usize>().read();
            seh::call(free, [context.addr(), 0, 0, 0], &Guard::Nothing);
            lock_contexts(header);
        }
        unlock_contexts(header);
    }
}
