//! Device objects: `IoCreateDevice`, `IoDeleteDevice`.

#![allow(non_snake_case)]

use super::TAG_DEVICE;
use crate::mm::pool;
use crate::{kd, ke, ob, rtl};
use nk_ntabi::io::*;
use nk_ntabi::status::*;

/// NK's private per-device block, where Windows keeps its `DEVOBJ_EXTENSION`.
/// The first fields mirror the public head of that structure.
#[repr(C)]
struct DeviceExtra {
    kind: i16,
    size: u16,
    device: *mut DEVICE_OBJECT,
    /// `IoDeleteDevice` was called while the device was still open.
    delete_pending: bool,
}

/// `IO_TYPE_DEVICE_OBJECT_EXTENSION`
const EXTRA_TYPE: i16 = 0x0D;
/// `KDEVICE_QUEUE.Type` (`DeviceQueueObject`).
const DEVICE_QUEUE_OBJECT: i16 = 0x14;
/// The object's `Size` field is 16 bits.
const MAX_EXTENSION: u32 = 0xFFFF - size_of::<DEVICE_OBJECT>() as u32;

/// Stop if `device` is not a device object: a driver passed garbage.
///
/// # Safety
/// `device` must be readable for two bytes.
pub unsafe fn check(device: *mut DEVICE_OBJECT, caller: &str) {
    // SAFETY: per the contract.
    if device.is_null() || unsafe { (*device).Type } != IO_TYPE_DEVICE {
        kd::bugcheck(format_args!("{caller}: {device:p} is not a device object"));
    }
}

/// `IoCreateDevice`.
///
/// # Safety
/// `driver` must be a driver object from this kernel, `name` null or a
/// valid counted string, and `device_out` writable.
pub unsafe extern "C" fn IoCreateDevice(
    driver: *mut DRIVER_OBJECT,
    extension_size: u32,
    name: *const UNICODE_STRING,
    device_type: u32,
    characteristics: u32,
    exclusive: u8,
    device_out: *mut *mut DEVICE_OBJECT,
) -> NTSTATUS {
    if extension_size > MAX_EXTENSION {
        return STATUS_INVALID_PARAMETER;
    }
    // Device object, then the driver's extension, then NK's private block.
    let ext = (extension_size as usize).next_multiple_of(16);
    let total = size_of::<DEVICE_OBJECT>() + ext + size_of::<DeviceExtra>();
    let device = pool::alloc_zeroed(total, TAG_DEVICE).cast::<DEVICE_OBJECT>();
    if device.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: `name` is valid per the contract.
    let name = unsafe { rtl::copy_unicode(name) };
    // SAFETY: `device` is a fresh, zeroed, exclusively owned block of
    // `total` bytes, 16-byte aligned as the pool guarantees; `driver` and
    // `device_out` are valid per the contract.
    unsafe {
        let extra = device
            .cast::<u8>()
            .add(size_of::<DEVICE_OBJECT>() + ext)
            .cast::<DeviceExtra>();
        (*extra).kind = EXTRA_TYPE;
        (*extra).size = size_of::<DeviceExtra>() as u16;
        (*extra).device = device;

        (*device).Type = IO_TYPE_DEVICE;
        (*device).Size = (size_of::<DEVICE_OBJECT>() as u32 + extension_size) as u16;
        (*device).DriverObject = driver;
        (*device).DeviceType = device_type;
        (*device).Characteristics = characteristics;
        (*device).StackSize = 1;
        (*device).DeviceObjectExtension = extra.cast();
        if extension_size != 0 {
            (*device).DeviceExtension = device.add(1).cast();
        }
        // Cleared by the I/O manager once the driver's entry returns.
        (*device).Flags = DO_DEVICE_INITIALIZING;
        if exclusive != 0 {
            (*device).Flags |= DO_EXCLUSIVE;
        }
        ke::event::init(&raw mut (*device).DeviceLock, EVENT_SYNCHRONIZATION, true);
        let queue = &raw mut (*device).DeviceQueue;
        (*queue).Type = DEVICE_QUEUE_OBJECT;
        (*queue).Size = size_of::<KDEVICE_QUEUE>() as i16;
        (*queue).DeviceListHead.Flink = &raw mut (*queue).DeviceListHead;
        (*queue).DeviceListHead.Blink = &raw mut (*queue).DeviceListHead;

        if !name.is_empty() {
            let status = ob::insert(&name, ob::Target::Device(device));
            if !nt_success(status) {
                let _ = pool::free(device.cast());
                return status;
            }
            (*device).Flags |= DO_DEVICE_HAS_NAME;
        }
        // Newest device first, as on Windows.
        (*device).NextDevice = (*driver).DeviceObject;
        (*driver).DeviceObject = device;
        device_out.write_unaligned(device);
    }
    STATUS_SUCCESS
}

/// # Safety
/// `device` must be a live device object.
unsafe fn extra(device: *mut DEVICE_OBJECT) -> *mut DeviceExtra {
    // SAFETY: `IoCreateDevice` stored this pointer.
    unsafe { (*device).DeviceObjectExtension.cast() }
}

/// # Safety
/// `device` must be a live device object with no remaining users.
unsafe fn destroy(device: *mut DEVICE_OBJECT) {
    // SAFETY: per the contract; clearing Type makes a stale pointer fail
    // `check` instead of looking valid.
    unsafe { (*device).Type = 0 };
    if let Err(e) = pool::free(device.cast()) {
        kd::bugcheck(format_args!("freeing device object {device:p}: {e:?}"));
    }
}

/// `IoDeleteDevice`: remove a device object. If files are still open on
/// it, it disappears from the namespace and the driver's list now and is
/// freed when the last one closes.
///
/// # Safety
/// `device` must be a device object created by `IoCreateDevice`.
pub unsafe extern "C" fn IoDeleteDevice(device: *mut DEVICE_OBJECT) {
    // SAFETY: `device` is readable per the contract; `check` validates it.
    unsafe {
        check(device, "IoDeleteDevice");
        if (*extra(device)).delete_pending {
            kd::bugcheck(format_args!("IoDeleteDevice: {device:p} deleted twice"));
        }
        ob::remove_device(device);
        // Unlink from the driver's singly linked device list.
        let mut link = &raw mut (*(*device).DriverObject).DeviceObject;
        while !(*link).is_null() && *link != device {
            link = &raw mut (**link).NextDevice;
        }
        if *link == device {
            *link = (*device).NextDevice;
        }
        (*device).NextDevice = core::ptr::null_mut();
        if (*device).ReferenceCount > 0 {
            (*extra(device)).delete_pending = true;
        } else {
            destroy(device);
        }
    }
}

/// Count an open file against the device.
///
/// # Safety
/// `device` must be a live device object.
pub unsafe fn reference(device: *mut DEVICE_OBJECT) {
    // SAFETY: per the contract.
    unsafe { (*device).ReferenceCount += 1 };
}

/// Drop an open file's count; free the device if it was deleted meanwhile.
///
/// # Safety
/// `device` must be a live device object with a positive count.
pub unsafe fn dereference(device: *mut DEVICE_OBJECT) {
    // SAFETY: per the contract.
    unsafe {
        (*device).ReferenceCount -= 1;
        if (*device).ReferenceCount == 0 && (*extra(device)).delete_pending {
            destroy(device);
        }
    }
}
