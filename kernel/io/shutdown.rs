//! Shutdown notification: the devices whose drivers asked for an
//! `IRP_MJ_SHUTDOWN` before the machine goes off.
//!
//! Two queues, as Windows keeps them. The first is told before the file
//! systems are shut down, the last-chance queue after. Between them each
//! file system registered on the disk, CD-ROM and tape queues is sent
//! its `IRP_MJ_SHUTDOWN` (Windows' `IopShutdownBaseFileSystems`), and
//! from then on nothing is mounted. Windows' `PopGracefulShutdown`
//! waits for the cache manager's lazy writer right after this step
//! (`CcWaitForCurrentLazyWriterActivity`): the place for NK's cache
//! manager to do the same is the end of `shutdown_file_systems`.
//! Each queue is sent newest registration first, to the top of the
//! registered device's stack, one request at a time and waited for.

use super::stack;
use crate::ke::spinlock::{Rank, SpinLock};
use crate::ob::object;
use alloc::vec::Vec;
use nk_ntabi::io::{DEVICE_OBJECT, IRP_MJ_SHUTDOWN};
use nk_ntabi::status::*;

/// `DO_SHUTDOWN_REGISTERED`: the device is in a shutdown queue.
pub const DO_SHUTDOWN_REGISTERED: u32 = 0x0000_0800;

/// A registered device. The queue holds a reference to it.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Device(*mut DEVICE_OBJECT);

// SAFETY: the pointer names a device object the queue holds a reference
// to.
unsafe impl Send for Device {}

/// The queues: (before the file systems, last chance), oldest first.
static QUEUES: SpinLock<(Vec<Device>, Vec<Device>)> =
    SpinLock::new(Rank::Shutdown, (Vec::new(), Vec::new()));

/// Queue `device`; its driver is sent a shutdown request.
///
/// # Safety
/// `device` is a live device object.
unsafe fn register(device: *mut DEVICE_OBJECT, last_chance: bool) -> NTSTATUS {
    let mut queues = QUEUES.lock();
    let queue = if last_chance {
        &mut queues.1
    } else {
        &mut queues.0
    };
    if queue.try_reserve(1).is_err() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: per the contract; the queue's reference keeps the object.
    unsafe {
        object::reference(device.cast());
        (*device).Flags |= DO_SHUTDOWN_REGISTERED;
    }
    queue.push(Device(device));
    STATUS_SUCCESS
}

/// [`IoRegisterShutdownNotification`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioregistershutdownnotification).
///
/// # Safety
/// `device` is a live device object.
#[allow(non_snake_case)]
pub unsafe extern "C" fn IoRegisterShutdownNotification(device: *mut DEVICE_OBJECT) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { register(device, false) }
}

/// [`IoRegisterLastChanceShutdownNotification`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioregisterlastchanceshutdownnotification).
///
/// # Safety
/// `device` is a live device object.
#[allow(non_snake_case)]
pub unsafe extern "C" fn IoRegisterLastChanceShutdownNotification(
    device: *mut DEVICE_OBJECT,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { register(device, true) }
}

/// [`IoUnregisterShutdownNotification`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iounregistershutdownnotification):
/// take `device` out of both queues. Also done when the device is
/// deleted.
///
/// # Safety
/// `device` is a live device object.
#[allow(non_snake_case)]
pub unsafe extern "C" fn IoUnregisterShutdownNotification(device: *mut DEVICE_OBJECT) {
    let removed = {
        let mut queues = QUEUES.lock();
        let before = queues.0.len() + queues.1.len();
        queues.0.retain(|&d| d != Device(device));
        queues.1.retain(|&d| d != Device(device));
        before - queues.0.len() - queues.1.len()
    };
    // SAFETY: per the contract; each entry held a reference.
    unsafe {
        (*device).Flags &= !DO_SHUTDOWN_REGISTERED;
        for _ in 0..removed {
            object::dereference(device.cast());
        }
    }
}

/// Send each base file system's control device, at the top of its
/// stack, its shutdown request, waiting for each; from then on no
/// volume mounts (`io::fs`).
fn shutdown_file_systems() {
    super::fs::stop_mounting();
    let mut sent = Vec::new();
    while let Some(device) = super::fs::next_base(&sent) {
        sent.push(device);
        // SAFETY: `next_base` counted the device for this.
        let (status, _) = unsafe { stack::send_synchronous(device, IRP_MJ_SHUTDOWN, 0, [0; 4]) };
        super::fs::trace(format_args!(
            "file system {device:p} shut down: {:#x}",
            status as u32
        ));
        // SAFETY: as above.
        unsafe { super::device::dereference(device) };
    }
    // What the file systems left dirty is written now, as Windows waits
    // for the lazy writer here.
    crate::cc::lazy::shutdown_flush();
}

/// Send every registered device its shutdown request: the first queue,
/// then the file systems, then the last-chance queue. A queued device
/// leaves its queue as it is sent, and its reference is given up
/// after. Called at `PASSIVE_LEVEL` by whatever ends a run.
pub fn shutdown_system() {
    for last_chance in [false, true] {
        if last_chance {
            shutdown_file_systems();
        }
        loop {
            // One at a time, newest first; the lock is not held across
            // a driver's dispatch routine.
            let next = {
                let mut queues = QUEUES.lock();
                let queue = if last_chance {
                    &mut queues.1
                } else {
                    &mut queues.0
                };
                queue.pop()
            };
            let Some(Device(device)) = next else { break };
            // SAFETY: the queue's reference, now ours, keeps the device.
            let (status, _) =
                unsafe { stack::send_synchronous(device, IRP_MJ_SHUTDOWN, 0, [0; 4]) };
            if !nt_success(status) {
                kprintln!(
                    "io: a device's shutdown request failed: {:#010x}",
                    status as u32
                );
            }
            // SAFETY: as above.
            unsafe {
                (*device).Flags &= !DO_SHUTDOWN_REGISTERED;
                object::dereference(device.cast());
            }
        }
    }
}
