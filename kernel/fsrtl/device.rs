//! What the runtime library asks a file system's devices, and the small
//! answers it gives about the volume: Windows' `FsRtlIssueDeviceIoControl`
//! and the routines over it, the correlation id of a volume, the
//! extra-create-parameter list of a create request, whether the volume
//! start-up applications have run, and the disk counters.

#![allow(non_snake_case)]

use crate::kd;
use crate::mm::pool;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nk_ntabi::io::{DEVICE_OBJECT, IO_STATUS_BLOCK, IRP, KEVENT};
use nk_ntabi::status::*;

/// The pool tag of a request's block.
const TAG: u32 = u32::from_le_bytes(*b"FSio");

/// `IOCTL_MOUNTDEV_QUERY_STABLE_GUID`.
const IOCTL_MOUNTDEV_QUERY_STABLE_GUID: u32 = 0x004D_0018;

/// `IRP_CREATE_OPERATION` in an IRP's `Flags`.
const IRP_CREATE_OPERATION: u32 = 0x80;

/// Send a device-control request with `input` to `device` itself, as
/// `FsRtlIssueDeviceIoControl` does, `stack_flags` or'ed into its stack
/// location's `Flags`, and wait for it. The status and, on success, the
/// first `Information` bytes of an `output_length`-byte answer.
///
/// The event, status block and buffers are in one pool block, which a
/// driver that returns without completing the request keeps for good
/// (as `io::stack` leaves a request).
///
/// # Safety
/// `device` is a live device object. Called at `PASSIVE_LEVEL`.
pub unsafe fn io_control(
    device: *mut DEVICE_OBJECT,
    code: u32,
    stack_flags: u8,
    input: &[u8],
    output_length: usize,
) -> (NTSTATUS, Vec<u8>) {
    #[repr(C)]
    struct Waiting {
        done: KEVENT,
        status_block: IO_STATUS_BLOCK,
    }
    let header = size_of::<Waiting>();
    let block = pool::alloc(header + input.len() + output_length, TAG);
    if block.is_null() {
        return (STATUS_INSUFFICIENT_RESOURCES, Vec::new());
    }
    // SAFETY: per the contract; the block is fresh and large enough.
    unsafe {
        let waiting = block.cast::<Waiting>();
        let done = &raw mut (*waiting).done;
        crate::ke::wait::KeInitializeEvent(done, 0, 0);
        (&raw mut (*waiting).status_block).write(IO_STATUS_BLOCK {
            Status: STATUS_PENDING,
            Information: 0,
        });
        let input_at = block.add(header);
        core::ptr::copy_nonoverlapping(input.as_ptr(), input_at, input.len());
        let output_at = input_at.add(input.len());
        let request: *mut IRP = crate::io::build::IoBuildDeviceIoControlRequest(
            code,
            device,
            input_at.cast(),
            input.len() as u32,
            output_at.cast(),
            output_length as u32,
            0,
            done,
            &raw mut (*waiting).status_block,
        );
        if request.is_null() {
            let _ = pool::free(block);
            return (STATUS_INSUFFICIENT_RESOURCES, Vec::new());
        }
        let next = (*request).CurrentStackLocation.sub(1);
        (*next).Flags |= stack_flags;
        let returned = crate::io::irp::IofCallDriver(device, request);
        if returned != STATUS_PENDING && crate::ke::wait::KeReadStateEvent(done) == 0 {
            kd::verify(format_args!(
                "a driver returned {:#010x} for control code {code:#x} without completing \
                 the request",
                returned as u32
            ));
            return (returned, Vec::new());
        }
        crate::ke::wait::wait(Some(done.cast()), None);
        let IO_STATUS_BLOCK {
            Status: status,
            Information: information,
        } = (&raw const (*waiting).status_block).read();
        let mut answer = Vec::new();
        if nt_success(status) {
            let n = information.min(output_length);
            if answer.try_reserve_exact(n).is_ok() {
                answer.extend_from_slice(core::slice::from_raw_parts(output_at, n));
            }
        }
        let _ = pool::free(block);
        (status, answer)
    }
}

/// [`FsRtlVolumeDeviceToCorrelationId`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlvolumedevicetocorrelationid):
/// the volume's stable GUID, as its device answers
/// `IOCTL_MOUNTDEV_QUERY_STABLE_GUID`; for a volume that does not
/// answer, the GUID of its name (`IoVolumeDeviceToGuid`), as Windows
/// falls back.
///
/// # Safety
/// `device` is a volume's device object; `guid` is writable for 16
/// bytes. Called at `PASSIVE_LEVEL`.
pub unsafe extern "C" fn FsRtlVolumeDeviceToCorrelationId(
    device: *mut DEVICE_OBJECT,
    guid: *mut [u8; 16],
) -> NTSTATUS {
    // SAFETY: per the contract.
    let (status, answer) =
        unsafe { io_control(device, IOCTL_MOUNTDEV_QUERY_STABLE_GUID, 0, &[], 16) };
    if !nt_success(status) {
        // SAFETY: per the contract.
        return unsafe { crate::io::guid::IoVolumeDeviceToGuid(device, guid.cast()) };
    }
    let mut out = [0u8; 16];
    let n = answer.len().min(16);
    out[..n].copy_from_slice(&answer[..n]);
    // SAFETY: per the contract.
    unsafe { guid.write_unaligned(out) };
    status
}

/// [`FsRtlGetEcpListFromIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlgetecplistfromirp):
/// a create request's list of extra create parameters (null: NK's
/// creates carry none), or `STATUS_INVALID_PARAMETER` for any other
/// request; the list is where Windows keeps it, `UserBuffer`.
///
/// # Safety
/// `irp` is a request; `list` is writable.
pub unsafe extern "C" fn FsRtlGetEcpListFromIrp(
    irp: *mut IRP,
    list: *mut *mut core::ffi::c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if (*irp).Flags & IRP_CREATE_OPERATION == 0 {
            return STATUS_INVALID_PARAMETER;
        }
        list.write_unaligned((*irp).UserBuffer);
    }
    STATUS_SUCCESS
}

/// `FsRtlAreVolumeStartupApplicationsComplete`: whether the programs
/// Windows runs on volumes at start-up (`autochk`) have finished. User
/// mode tells the kernel; NK runs none, so as on Windows before then,
/// false.
pub extern "C" fn FsRtlAreVolumeStartupApplicationsComplete() -> u8 {
    0
}

/// The bytes file systems read from and wrote to disks: Windows keeps
/// them per processor, and nothing reads them back.
static DISK_READ: AtomicU64 = AtomicU64::new(0);
static DISK_WRITTEN: AtomicU64 = AtomicU64::new(0);

/// [`FsRtlUpdateDiskCounters`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlupdatediskcounters):
/// add to the bytes read from and written to disks.
pub extern "C" fn FsRtlUpdateDiskCounters(read: u64, written: u64) {
    if read != 0 {
        DISK_READ.fetch_add(read, Ordering::Relaxed);
    }
    if written != 0 {
        DISK_WRITTEN.fetch_add(written, Ordering::Relaxed);
    }
}
