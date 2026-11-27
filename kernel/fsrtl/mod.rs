//! The file-system runtime library: what the kernel does for file
//! systems. Here, the header at the front of each stream's control
//! block (`FSRTL_ADVANCED_FCB_HEADER`).
//!
//! The header is the file system's memory, set up by code compiled into
//! the driver; NK reads and writes it through raw pointers, under the
//! lock the header itself carries.

#![allow(non_snake_case)]

use crate::ex::pushlock;
use crate::kd;
use crate::ke::mutex;
use crate::ke::seh::{self, Guard};
use crate::ob::object::ObRef;

/// The pool tag of the block a nesting-level request writes back to.
const TAG_NESTING: u32 = u32::from_le_bytes(*b"FsNe");
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

/// [`FsRtlIsSystemPagingFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlissystempagingfile):
/// whether `file` is one of the system's paging files. Windows looks
/// the file object up in its list of paging files; NK pages nothing to
/// disk and has no such file.
pub extern "C" fn FsRtlIsSystemPagingFile(_file: *const core::ffi::c_void) -> u32 {
    0
}

/// The control code `FsRtlGetVirtualDiskNestingLevel` asks a disk with
/// (storage family, function 0x464). A virtual disk answers how deep it
/// is nested; any other disk refuses it.
const IOCTL_STORAGE_GET_NESTING: u32 = 0x002D_1190;

/// [`FsRtlGetVirtualDiskNestingLevel`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlgetvirtualdisknestinglevel):
/// how many virtual disks `device`'s disk is nested in. The disk is
/// asked, with hard errors off, as Windows asks it; a disk that refuses
/// is no virtual disk, and the refusal is the answer, the level zero.
/// Only a disk or CD-ROM device, or a file system on one, or a virtual
/// disk, is asked: anything else is `STATUS_INVALID_PARAMETER`.
///
/// Partial: a disk that answers is a virtual disk, which NK has none of;
/// its answer stops the system by name.
///
/// # Safety
/// `device` is a live device object; `level` is writable and `flags`
/// writable or null. Called at `PASSIVE_LEVEL`.
pub unsafe extern "C" fn FsRtlGetVirtualDiskNestingLevel(
    device: *mut nk_ntabi::io::DEVICE_OBJECT,
    level: *mut u32,
    flags: *mut u32,
) -> nk_ntabi::status::NTSTATUS {
    use nk_ntabi::io::{IO_STATUS_BLOCK, KEVENT};
    use nk_ntabi::status::*;
    /// `FILE_DEVICE_CD_ROM`, `_CD_ROM_FILE_SYSTEM`, `_DISK`,
    /// `_DISK_FILE_SYSTEM` and `_VIRTUAL_DISK`.
    const ASKED: [u32; 5] = [0x02, 0x03, 0x07, 0x08, 0x24];
    crate::ke::irql::expect_passive("FsRtlGetVirtualDiskNestingLevel");
    // SAFETY: per the contract. The event, status block and answer are
    // in a pool block that stays until the request has been seen to
    // complete, or for good if its driver kept it.
    unsafe {
        level.write(0);
        if !flags.is_null() {
            flags.write(0);
        }
        if !ASKED.contains(&(*device).DeviceType) {
            return STATUS_INVALID_PARAMETER;
        }
        /// What the request writes back: its event, status and answer.
        #[repr(C)]
        struct Waiting {
            done: KEVENT,
            status_block: IO_STATUS_BLOCK,
            answer: [u8; 0x14],
        }
        let waiting = crate::mm::pool::alloc(size_of::<Waiting>(), TAG_NESTING).cast::<Waiting>();
        if waiting.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let done = &raw mut (*waiting).done;
        crate::ke::wait::KeInitializeEvent(done, 0, 0);
        (&raw mut (*waiting).status_block).write(IO_STATUS_BLOCK {
            Status: STATUS_PENDING,
            Information: 0,
        });
        let held = ObRef::adopt(crate::io::device::IoGetAttachedDeviceReference(device).cast());
        let top = held.cast::<nk_ntabi::io::DEVICE_OBJECT>();
        let request = crate::io::build::IoBuildDeviceIoControlRequest(
            IOCTL_STORAGE_GET_NESTING,
            top,
            core::ptr::null_mut(),
            0,
            (&raw mut (*waiting).answer).cast(),
            0x14,
            0,
            done,
            &raw mut (*waiting).status_block,
        );
        if request.is_null() {
            let _ = crate::mm::pool::free(waiting.cast());
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let was_enabled = crate::ps::IoSetThreadHardErrorMode(0);
        let returned = crate::io::irp::IofCallDriver(top, request);
        crate::ps::IoSetThreadHardErrorMode(was_enabled);
        if returned != STATUS_PENDING && crate::ke::wait::KeReadStateEvent(done) == 0 {
            // The driver may still complete the request, or pass it
            // down: the block it writes and the stack it names stay
            // (as `io::stack` leaves a request).
            kd::verify(format_args!(
                "a driver returned {:#010x} for IOCTL_STORAGE_GET_NESTING without completing \
                 the request",
                returned as u32
            ));
            held.into_raw();
            return returned;
        }
        crate::ke::wait::wait(Some(done.cast()), None);
        drop(held);
        let status = (&raw const (*waiting).status_block).read().Status;
        let _ = crate::mm::pool::free(waiting.cast());
        if !nt_success(status) {
            return status;
        }
        crate::kd::bugcheck(format_args!(
            "FsRtlGetVirtualDiskNestingLevel: the disk answered as a virtual disk, which NK does \
             not implement"
        ))
    }
}
