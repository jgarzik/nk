//! Device objects: `IoCreateDevice`, `IoDeleteDevice`.
//!
//! A device is an object-manager object, so a handle can be opened to
//! it. It has two counts, as on Windows: `ReferenceCount` in the device
//! itself (open files, work items on their way), which decides when a
//! deleted device stops being one, and the object's pointer count,
//! which decides when its memory goes. `IoCreateDevice` holds one
//! pointer reference; the device gives it up when it is deleted and
//! unreferenced.

#![allow(non_snake_case)]

use crate::ke::{Rank, SpinLock};
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
    let Some(body) = ob::object::create(&ob::object::DEVICE_TYPE, total) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    let device = body.cast::<DEVICE_OBJECT>();
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
        ke::wait::KeInitializeEvent(&raw mut (*device).DeviceLock, 1, 1);
        let queue = &raw mut (*device).DeviceQueue;
        (*queue).Type = DEVICE_QUEUE_OBJECT;
        (*queue).Size = size_of::<KDEVICE_QUEUE>() as i16;
        (*queue).DeviceListHead.Flink = &raw mut (*queue).DeviceListHead;
        (*queue).DeviceListHead.Blink = &raw mut (*queue).DeviceListHead;

        if !name.is_empty() {
            let status = ob::insert(&name, ob::Target::Device(device));
            if !nt_success(status) {
                ob::object::dereference(body);
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
    unsafe {
        (*device).Type = 0;
        ob::object::dereference(device.cast());
    }
}

/// The object manager's call when the last pointer to a device has
/// gone: free the security descriptor it was given.
///
/// # Safety
/// `body` is a device object nothing refers to any more.
pub unsafe fn deleted(body: *mut u8) {
    // SAFETY: per the contract; the descriptor is a pool block of the
    // kernel's, put there by `replace_security`.
    unsafe {
        let descriptor = (*body.cast::<DEVICE_OBJECT>()).SecurityDescriptor;
        if !descriptor.is_null() {
            let _ = pool::free(descriptor.cast());
        }
    }
}

/// Give `device` the security descriptor `make` builds from the one it
/// has (null if none): a pool block, which the device then owns. `None`
/// from `make` changes nothing and is passed on.
///
/// # Safety
/// `device` is a device object the caller holds a pointer reference to.
pub unsafe fn replace_security(
    device: *mut DEVICE_OBJECT,
    make: impl FnOnce(*const u8) -> Option<*mut u8>,
) -> Option<()> {
    // SAFETY: per the contract. The pointer belongs to the database
    // lock, so two changes at once cannot both build on the same old
    // descriptor; the old block is freed once nothing can find it.
    unsafe {
        let old = {
            let _database = DATABASE.lock();
            let old = (*device).SecurityDescriptor;
            let new = make(old.cast())?;
            (*device).SecurityDescriptor = new.cast();
            old
        };
        if !old.is_null() {
            let _ = pool::free(old.cast());
        }
    }
    Some(())
}

/// One lock over every device's reference count, its delete-pending
/// mark and its security descriptor pointer, as on Windows (the I/O database lock). "The count has reached
/// zero" and "deletion is pending" are decided together or not at all:
/// whichever of `IoDeleteDevice` and the last dereference comes second
/// sees both, under the lock, and it alone frees the device, after
/// letting go.
static DATABASE: SpinLock<()> = SpinLock::new(Rank::IoDatabase, ());

/// `IoDeleteDevice`: remove a device object. If it is still referenced
/// (files open on it, work items on their way), it disappears from the
/// namespace and the driver's list now and is freed when the last
/// reference goes.
///
/// # Safety
/// `device` must be a device object created by `IoCreateDevice`.
pub unsafe extern "C" fn IoDeleteDevice(device: *mut DEVICE_OBJECT) {
    // SAFETY: `device` is readable per the contract; `check` validates it.
    unsafe {
        check(device, "IoDeleteDevice");
        ob::remove_device(device);
        let unreferenced = {
            let _database = DATABASE.lock();
            if (*extra(device)).delete_pending {
                kd::bugcheck(format_args!("IoDeleteDevice: {device:p} deleted twice"));
            }
            // Unlink from the driver's singly linked device list.
            let mut link = &raw mut (*(*device).DriverObject).DeviceObject;
            while !(*link).is_null() && *link != device {
                link = &raw mut (**link).NextDevice;
            }
            if *link == device {
                *link = (*device).NextDevice;
            }
            (*device).NextDevice = core::ptr::null_mut();
            (*extra(device)).delete_pending = true;
            (*device).ReferenceCount == 0
        };
        if unreferenced {
            destroy(device);
        }
    }
}

/// Take a reference on the device: an open file, a work item on its way.
///
/// # Safety
/// `device` must be a live device object.
pub unsafe fn reference(device: *mut DEVICE_OBJECT) {
    let _database = DATABASE.lock();
    // SAFETY: per the contract; the count belongs to the lock.
    unsafe { (*device).ReferenceCount += 1 };
}

/// Drop a reference; free the device if it was deleted meanwhile and
/// this was the last.
///
/// # Safety
/// `device` must be a live device object the caller holds a reference
/// on, which it gives up.
pub unsafe fn dereference(device: *mut DEVICE_OBJECT) {
    // SAFETY: per the contract. Nothing of the device is read after the
    // lock is dropped unless this call is the one to free it.
    unsafe {
        let last = {
            let _database = DATABASE.lock();
            (*device).ReferenceCount -= 1;
            (*device).ReferenceCount == 0 && (*extra(device)).delete_pending
        };
        if last {
            destroy(device);
        }
    }
}
