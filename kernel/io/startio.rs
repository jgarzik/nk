//! The device queue a driver with a `StartIo` routine keeps its
//! requests in: [`IoStartPacket`], [`IoStartNextPacket`],
//! [`IoSetStartIoAttributes`]
//! ([queued I/O](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/startio-routines-in-lower-level-drivers)).
//!
//! The queue is the device object's `DeviceQueue`, a `KDEVICE_QUEUE`
//! with Windows' meaning: while the device is busy with one request
//! (`CurrentIrp`), others wait in the queue, linked through the
//! `KDEVICE_QUEUE_ENTRY` in each IRP (`Tail.Overlay.DeviceQueueEntry`),
//! in order of arrival or of the key they were queued with. The queue's
//! own spin lock guards it, and it is the driver's kind of lock: a
//! driver's cancel routine takes a waiting request out under it.
//!
//! What the driver chose with `IoSetStartIoAttributes` is kept where
//! Windows keeps it, in the device object extension's `StartIoFlags`.
//! With deferred start, a call of `IoStartNextPacket` made while one is
//! already running for the device (from `StartIo` itself, say) is
//! noted there and carried out by the outer call when it gets back,
//! as the pinned kernel does it: `StartIo` does not recurse.

#![allow(non_snake_case)]

use super::{device, irp};
use crate::kd;
use crate::ke::seh::{self, Guard};
use crate::ke::{irql, kspin};
use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use nk_ntabi::io::*;

/// The device queue entry of `request`.
///
/// # Safety
/// `request` is a live IRP.
unsafe fn entry_of(request: *mut IRP) -> *mut KDEVICE_QUEUE_ENTRY {
    // SAFETY: per the contract: the entry overlays the driver context.
    unsafe { request.byte_add(IRP_DEVICE_QUEUE_ENTRY).cast() }
}

/// Put `entry` in the queue if the device is busy; otherwise mark the
/// device busy and say `false`: the request is the caller's to start.
/// A queued entry goes behind every entry whose key is no greater than
/// `key`, or at the end if there is no key (`KeInsertDeviceQueue`,
/// `KeInsertByKeyDeviceQueue`).
///
/// # Safety
/// `queue` is a device's queue and `entry` an entry that is in none.
unsafe fn insert(
    queue: *mut KDEVICE_QUEUE,
    entry: *mut KDEVICE_QUEUE_ENTRY,
    key: Option<u32>,
) -> bool {
    // SAFETY: per the contract; the list belongs to the queue's lock.
    unsafe {
        let lock = &raw mut (*queue).Lock;
        let old = kspin::KeAcquireSpinLockRaiseToDpc(lock);
        let busy = (&raw mut (*queue).Busy).cast::<u8>();
        let queued = busy.read() != 0;
        if queued {
            let head = &raw mut (*queue).DeviceListHead;
            // The entry it goes in front of: the head, for the end.
            let mut next = head;
            if let Some(key) = key {
                (*entry).SortKey = key;
                next = (*head).Flink;
                while next != head && (*next.cast::<KDEVICE_QUEUE_ENTRY>()).SortKey <= key {
                    next = (*next).Flink;
                }
            }
            let link = &raw mut (*entry).DeviceListEntry;
            let previous = (*next).Blink;
            (*link).Flink = next;
            (*link).Blink = previous;
            (*previous).Flink = link;
            (*next).Blink = link;
        } else {
            busy.write(1);
        }
        (*entry).Inserted = u8::from(queued);
        kspin::KeReleaseSpinLock(lock, old);
        queued
    }
}

/// Take the first entry out of the queue, or, if none waits, mark the
/// device not busy and return null (`KeRemoveDeviceQueue`).
///
/// # Safety
/// `queue` is a device's queue.
unsafe fn remove(queue: *mut KDEVICE_QUEUE) -> *mut KDEVICE_QUEUE_ENTRY {
    // SAFETY: per the contract; the list belongs to the queue's lock,
    // and a queued entry is part of a live IRP.
    unsafe {
        let lock = &raw mut (*queue).Lock;
        let old = kspin::KeAcquireSpinLockRaiseToDpc(lock);
        let head = &raw mut (*queue).DeviceListHead;
        let first = (*head).Flink;
        let entry = if first == head {
            (&raw mut (*queue).Busy).cast::<u8>().write(0);
            core::ptr::null_mut()
        } else {
            let next = (*first).Flink;
            (*head).Flink = next;
            (*next).Blink = head;
            let entry = first.cast::<KDEVICE_QUEUE_ENTRY>();
            (*entry).Inserted = 0;
            entry
        };
        kspin::KeReleaseSpinLock(lock, old);
        entry
    }
}

/// The device's `StartIoFlags`, for reading and writing in one step.
///
/// # Safety
/// `device` is a live device object.
unsafe fn start_io_flags<'a>(device: *mut DEVICE_OBJECT) -> &'a AtomicU32 {
    // SAFETY: per the contract.
    unsafe { AtomicU32::from_ptr(&raw mut (*device::extra(device)).StartIoFlags) }
}

/// What `IoStartPacket` owes if `StartIo` or the cancel routine it
/// calls is unwound: the IRQL it raised.
///
/// # Safety
/// `old` is the IRQL `IoStartPacket` raised from.
unsafe fn lower(old: *mut c_void) {
    irql::lower(old.addr() as u8);
}

/// Call the driver's `StartIo` for `request`, now the device's current
/// one.
///
/// # Safety
/// `device` is a live device object at `DISPATCH_LEVEL`, and `request`
/// a request of its driver's that it queued.
unsafe fn start(device: *mut DEVICE_OBJECT, request: *mut IRP, guard: &Guard) {
    // SAFETY: per the contract.
    unsafe {
        let routine = (*(*device).DriverObject).DriverStartIo;
        if routine.is_null() {
            kd::bugcheck(format_args!(
                "IoStartPacket: the driver of device {device:p} has no StartIo routine"
            ));
        }
        seh::call(routine.addr(), [device.addr(), request.addr(), 0, 0], guard);
    }
}

/// [`IoStartPacket`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iostartpacket):
/// start `request` on the device if it is idle, by calling the driver's
/// `StartIo` at `DISPATCH_LEVEL`; otherwise queue it, by `key` if there
/// is one. `cancel` becomes the request's cancel routine under the
/// cancel spin lock. A request already cancelled when it is queued has
/// the routine called at once; one that is started keeps the routine,
/// for `StartIo` to take out, unless the driver said its requests are
/// not cancellable once started.
///
/// # Safety
/// `device` is a live device object whose driver has a `StartIo`
/// routine; `request` is a request the driver holds; `key` is null or
/// readable.
pub unsafe extern "C" fn IoStartPacket(
    device: *mut DEVICE_OBJECT,
    request: *mut IRP,
    key: *const u32,
    cancel: Option<DRIVER_CANCEL>,
) {
    // SAFETY: per the contract.
    unsafe {
        let old = irql::raise(irql::DISPATCH_LEVEL);
        let guard = Guard::Undo {
            undo: lower,
            context: core::ptr::without_provenance_mut(usize::from(old)),
        };
        let mut cancel_irql = 0;
        if let Some(cancel) = cancel {
            irp::IoAcquireCancelSpinLock(&raw mut cancel_irql);
            (*request).CancelRoutine = cancel as *mut c_void;
        }
        let key = (!key.is_null()).then(|| key.read_unaligned());
        if !insert(&raw mut (*device).DeviceQueue, entry_of(request), key) {
            (*device).CurrentIrp = request;
            if cancel.is_some() {
                if start_io_flags(device).load(Ordering::Acquire) & DOE_SIO_NO_CANCEL != 0 {
                    (*request).CancelRoutine = core::ptr::null_mut();
                }
                irp::IoReleaseCancelSpinLock(cancel_irql);
            }
            start(device, request, &guard);
        } else if let Some(cancel) = cancel {
            if (*request).Cancel != 0 {
                // Cancelled before it was queued: the routine is
                // entered as `IoCancelIrp` enters it, the cancel lock
                // its to release.
                (*request).CancelRoutine = core::ptr::null_mut();
                (*request).CancelIrql = cancel_irql;
                seh::call(
                    cancel as usize,
                    [device.addr(), request.addr(), 0, 0],
                    &guard,
                );
            } else {
                irp::IoReleaseCancelSpinLock(cancel_irql);
            }
        }
        irql::lower(old);
    }
}

/// Start the next request waiting for the device, if there is one
/// (the pinned kernel's `IopStartNextPacket`).
///
/// # Safety
/// `device` is a live device object at `DISPATCH_LEVEL`.
unsafe fn start_next(device: *mut DEVICE_OBJECT, cancelable: bool) {
    // SAFETY: per the contract; a queued entry is part of a live IRP.
    unsafe {
        let mut cancel_irql = 0;
        if cancelable {
            irp::IoAcquireCancelSpinLock(&raw mut cancel_irql);
        }
        (*device).CurrentIrp = core::ptr::null_mut();
        let entry = remove(&raw mut (*device).DeviceQueue);
        if entry.is_null() {
            if cancelable {
                irp::IoReleaseCancelSpinLock(cancel_irql);
            }
            return;
        }
        let request = entry.byte_sub(IRP_DEVICE_QUEUE_ENTRY).cast::<IRP>();
        (*device).CurrentIrp = request;
        if cancelable {
            if start_io_flags(device).load(Ordering::Acquire) & DOE_SIO_NO_CANCEL != 0 {
                (*request).CancelRoutine = core::ptr::null_mut();
            }
            irp::IoReleaseCancelSpinLock(cancel_irql);
        }
        // The caller's IRQL is its own: nothing is owed for an unwind.
        start(device, request, &Guard::Nothing);
    }
}

/// [`IoStartNextPacket`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iostartnextpacket):
/// the device is done with its current request: start the next one
/// waiting, or leave the device idle. `cancelable` says the driver's
/// requests have cancel routines, so the queue is worked under the
/// cancel spin lock.
///
/// With deferred start (`IoSetStartIoAttributes`) a call made while
/// another is at work for the device only leaves word, in
/// `StartIoFlags`, and that other call starts the next request when it
/// is back from `StartIo`.
///
/// # Safety
/// `device` is a live device object whose driver has a `StartIo`
/// routine, and the caller is at `DISPATCH_LEVEL`.
pub unsafe extern "C" fn IoStartNextPacket(device: *mut DEVICE_OBJECT, cancelable: u8) {
    const ASKED: u32 = DOE_SIO_NO_KEY | DOE_SIO_CANCELABLE;
    // SAFETY: per the contract.
    unsafe {
        let flags = start_io_flags(device);
        if flags.load(Ordering::Acquire) & DOE_SIO_DEFERRED == 0 {
            start_next(device, cancelable != 0);
            return;
        }
        let extension = device::extra(device);
        let count = AtomicI32::from_ptr(&raw mut (*extension).StartIoCount);
        let mut asked = DOE_SIO_NO_KEY
            | if cancelable != 0 {
                DOE_SIO_CANCELABLE
            } else {
                0
            };
        loop {
            if count.fetch_add(1, Ordering::AcqRel) != 0 {
                // Another call is at work: it will see this.
                flags.fetch_or(asked, Ordering::AcqRel);
            } else {
                flags.fetch_and(!ASKED, Ordering::AcqRel);
                start_next(device, asked & DOE_SIO_CANCELABLE != 0);
            }
            if count.fetch_sub(1, Ordering::AcqRel) != 1 {
                return;
            }
            // The last call out carries out what was asked meanwhile.
            asked = flags.load(Ordering::Acquire) & ASKED;
            if asked & DOE_SIO_NO_KEY == 0 {
                return;
            }
        }
    }
}

/// [`IoSetStartIoAttributes`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iosetstartioattributes):
/// the driver chooses deferred start, so that `StartIo` is not entered
/// again from within itself, and whether its requests stop being
/// cancellable once started. Either choice stays, as on Windows.
///
/// # Safety
/// `device` is a live device object.
pub unsafe extern "C" fn IoSetStartIoAttributes(
    device: *mut DEVICE_OBJECT,
    deferred_start: u8,
    non_cancelable: u8,
) {
    let mut chosen = 0;
    if deferred_start != 0 {
        chosen |= DOE_SIO_DEFERRED;
    }
    if non_cancelable != 0 {
        chosen |= DOE_SIO_NO_CANCEL;
    }
    // SAFETY: per the contract.
    unsafe { start_io_flags(device) }.fetch_or(chosen, Ordering::AcqRel);
}
