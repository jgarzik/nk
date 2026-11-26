//! Device objects: `IoCreateDevice`, `IoDeleteDevice`.
//!
//! A device is an object-manager object, so a handle can be opened to
//! it. It has two counts, as on Windows: `ReferenceCount` in the device
//! itself (open files, work items on their way), which decides when a
//! deleted device stops being one, and the object's pointer count,
//! which decides when its memory goes. `IoCreateDevice` holds one
//! pointer reference; the device gives it up when it is deleted and
//! unreferenced.
//!
//! Devices are stacked: `IoAttachDeviceToDeviceStack` puts one on top
//! of another's stack, and a request for any device of a stack is sent
//! to the top ([`top`]). The chain up is `AttachedDevice`, the chain
//! down the extension's `AttachedTo`, as on Windows, and both belong to
//! the database lock.
//!
//! `DeviceObjectExtension` points to a `DEVOBJ_EXTENSION` laid out as
//! Windows', behind the driver's own extension in the device's block.
//! What the I/O manager keeps about a device is kept there, in the
//! fields Windows keeps it in.

#![allow(non_snake_case)]

use crate::ke::seh::{self, Guard};
use crate::ke::{Rank, SpinLock};
use crate::mm::pool;
use crate::{kd, ke, ob, rtl};
use nk_ntabi::io::*;
use nk_ntabi::status::*;

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
    // Device object, then the driver's extension, then the I/O manager's
    // (`DEVOBJ_EXTENSION`), in one block and nothing after, as on Windows.
    let ext = (extension_size as usize).next_multiple_of(16);
    let total = size_of::<DEVICE_OBJECT>() + ext + size_of::<DEVOBJ_EXTENSION>();
    // SAFETY: `name` is valid per the contract.
    let name = unsafe { rtl::copy_unicode(name) };
    // A device with a name is an object with a name: `\Device\Null` is
    // `Null` in the directory `\Device`.
    let created = if name.is_empty() {
        ob::object::create(&ob::object::DEVICE_TYPE, total)
    } else {
        ob::object::create_named(&ob::object::DEVICE_TYPE, total, ob::leaf(&name))
    };
    let Some(body) = created else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    let device = body.cast::<DEVICE_OBJECT>();
    // SAFETY: `device` is a fresh, zeroed, exclusively owned block of
    // `total` bytes, 16-byte aligned as the pool guarantees; `driver` and
    // `device_out` are valid per the contract.
    unsafe {
        let extra = device
            .cast::<u8>()
            .add(size_of::<DEVICE_OBJECT>() + ext)
            .cast::<DEVOBJ_EXTENSION>();
        // Windows leaves `Size` zero.
        (*extra).Type = IO_TYPE_DEVICE_OBJECT_EXTENSION;
        (*extra).DeviceObject = device;

        (*device).Type = IO_TYPE_DEVICE;
        (*device).Size = (size_of::<DEVICE_OBJECT>() as u32 + extension_size) as u16;
        (*device).DriverObject = driver;
        (*device).DeviceType = device_type;
        (*device).Characteristics = characteristics;
        (*device).StackSize = 1;
        (*device).DeviceObjectExtension = extra;
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
            let status = ob::insert(&name, body);
            if !nt_success(status) {
                ob::object::dereference(body);
                return status;
            }
            (*device).Flags |= DO_DEVICE_HAS_NAME;
        }
        // Newest device first, as on Windows. The list belongs to the
        // database lock: devices are deleted, and others created, at the
        // same time.
        {
            let _database = DATABASE.lock();
            (*device).NextDevice = (*driver).DeviceObject;
            (*driver).DeviceObject = device;
        }
        device_out.write_unaligned(device);
    }
    STATUS_SUCCESS
}

/// The I/O manager's extension of `device`.
///
/// # Safety
/// `device` must be a live device object.
pub(super) unsafe fn extra(device: *mut DEVICE_OBJECT) -> *mut DEVOBJ_EXTENSION {
    // SAFETY: `IoCreateDevice` stored this pointer.
    unsafe { (*device).DeviceObjectExtension }
}

/// What `ExtensionFlags` says that keeps a device from being opened or
/// attached to: it is going away.
const DOE_GOING: u32 =
    DOE_UNLOAD_PENDING | DOE_DELETE_PENDING | DOE_REMOVE_PENDING | DOE_REMOVE_PROCESSED;

/// # Safety
/// `device` must be a live device object with no remaining users.
unsafe fn destroy(device: *mut DEVICE_OBJECT) {
    // SAFETY: per the contract; clearing Type makes a stale pointer fail
    // `check` instead of looking valid.
    unsafe {
        // The device below would be left pointing at freed memory, as
        // Windows leaves it.
        let below = (*extra(device)).AttachedTo;
        if !below.is_null() {
            kd::bugcheck(format_args!(
                "IoDeleteDevice: {device:p} was deleted while still attached to {below:p} \
                 (IoDetachDevice was not called)"
            ));
        }
        (*device).Type = 0;
        ob::object::dereference(device.cast());
    }
}

/// The object manager's call when the last pointer to a device has
/// gone: free the security descriptor it was given, and the power
/// manager's block.
///
/// # Safety
/// `body` is a device object nothing refers to any more.
pub unsafe extern "C" fn deleted(body: *mut core::ffi::c_void) {
    // SAFETY: per the contract; the descriptor is a pool block of the
    // kernel's, put there by `replace_security`.
    unsafe {
        let descriptor = (*body.cast::<DEVICE_OBJECT>()).SecurityDescriptor;
        if !descriptor.is_null() {
            let _ = pool::free(descriptor.cast());
        }
        crate::po::run_down(body.cast());
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

/// One lock over every device's reference count, its `ExtensionFlags`
/// (delete pending among them), its place in a stack (`AttachedDevice`
/// and the extension's `AttachedTo`) and its security descriptor pointer, as on Windows (the I/O database lock). "The count has reached
/// zero" and "deletion is pending" are decided together or not at all:
/// whichever of `IoDeleteDevice` and the last dereference comes second
/// sees both, under the lock, and it alone frees the device, after
/// letting go.
static DATABASE: SpinLock<()> = SpinLock::new(Rank::IoDatabase, ());

/// Take the database lock, for what else of the I/O manager's Windows
/// keeps under it: a driver object's list of extensions.
pub(super) fn database() -> crate::ke::spinlock::Guard<'static, ()> {
    DATABASE.lock()
}

/// [`IoDeleteDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iodeletedevice):
/// remove a device object. If it is still referenced (files open on
/// it, work items on their way) or another device is still attached to
/// it, it disappears from the namespace and the driver's list now and
/// is freed when the last reference has gone and that device has
/// detached ([`complete_delete`]).
///
/// A device is detached from the one below before it is deleted.
/// Windows frees one that is not and leaves the device below pointing
/// at freed memory; NK stops, naming both.
///
/// # Safety
/// `device` must be a device object created by `IoCreateDevice`.
pub unsafe extern "C" fn IoDeleteDevice(device: *mut DEVICE_OBJECT) {
    // SAFETY: `device` is readable per the contract; `check` validates it.
    unsafe {
        check(device, "IoDeleteDevice");
        ob::remove(device.cast());
        let unreferenced = {
            let database = DATABASE.lock();
            if (*extra(device)).ExtensionFlags & DOE_DELETE_PENDING != 0 {
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
            (*extra(device)).ExtensionFlags |= DOE_DELETE_PENDING;
            ((*device).ReferenceCount == 0).then_some(database)
        };
        if let Some(database) = unreferenced {
            complete_delete(device, database);
        }
    }
}

/// The `FastIoDetachDevice` routine of the driver of `device`, if it
/// has one.
///
/// # Safety
/// `device` is a live device object, whose driver's fast I/O table, if
/// it has one, is readable.
unsafe fn detach_routine(device: *mut DEVICE_OBJECT) -> Option<usize> {
    // SAFETY: per the contract; the table is the driver's memory and is
    // read field by field.
    unsafe {
        let table = (*(*device).DriverObject).FastIoDispatch.cast::<u8>();
        if table.is_null() {
            return None;
        }
        let size = table.cast::<u32>().read();
        let offset = fast_io_routine_offset(size, FAST_IO_DETACH_DEVICE)?;
        let routine = table.add(offset).cast::<usize>().read();
        (routine != 0).then_some(routine)
    }
}

/// Finish deleting `device`, which is marked delete-pending and has no
/// references, with the database lock held (`database`, given up here).
///
/// With nothing attached to it, it is freed. Otherwise the driver of
/// the device attached to it is told through its
/// [`FastIoDetachDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-fast_io_detach_device)
/// routine, if it has one, as the pinned kernel tells it; the device is
/// freed if that driver detached, and stays, deletion pending, until
/// [`IoDetachDevice`] if not.
///
/// # Safety
/// `device` is a live device object in that state.
unsafe fn complete_delete(
    device: *mut DEVICE_OBJECT,
    database: crate::ke::spinlock::Guard<'_, ()>,
) {
    // SAFETY: per the contract. The device is counted across the call
    // into the driver, so nothing frees it meanwhile.
    unsafe {
        let attached = (*device).AttachedDevice;
        if attached.is_null() {
            drop(database);
            destroy(device);
            return;
        }
        let Some(routine) = detach_routine(attached) else {
            return;
        };
        (*device).ReferenceCount += 1;
        drop(database);
        // Nothing is held across the routine but that count, which an
        // unwind leaves: the device then stays.
        seh::call(
            routine,
            [attached.addr(), device.addr(), 0, 0],
            &Guard::Nothing,
        );
        let unused = {
            let _database = DATABASE.lock();
            (*device).ReferenceCount -= 1;
            (*device).ReferenceCount == 0 && (*device).AttachedDevice.is_null()
        };
        if unused {
            destroy(device);
        }
    }
}

/// The top of the stack `device` is in, with the database lock held.
///
/// # Safety
/// `device` is a live device object and the caller holds the lock.
unsafe fn top_locked(mut device: *mut DEVICE_OBJECT) -> *mut DEVICE_OBJECT {
    // SAFETY: per the contract: the chain belongs to the lock, and a
    // device with another attached to it is not freed.
    unsafe {
        while !(*device).AttachedDevice.is_null() {
            device = (*device).AttachedDevice;
        }
    }
    device
}

/// The device at the top of the stack `device` is in: where a request
/// for any device of the stack is sent
/// ([`IoGetAttachedDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iogetattacheddevice)).
/// No reference is taken: it is the caller's to know that the stack
/// stays as it is, as it is a Windows driver's.
///
/// # Safety
/// `device` is a live device object.
pub unsafe fn top(device: *mut DEVICE_OBJECT) -> *mut DEVICE_OBJECT {
    let _database = DATABASE.lock();
    // SAFETY: per the contract.
    unsafe { top_locked(device) }
}

/// [`IoAttachDeviceToDeviceStack`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioattachdevicetodevicestack):
/// put `source` on top of the stack `target` is in. Returns the device
/// it was attached to, which was the top, or null if that device is
/// still initialising, is going away, or has as deep a stack as an IRP
/// can serve.
///
/// What the pinned kernel hands on is handed on: `source` gets a
/// `StackSize` one more than the device it is attached to, that
/// device's `AlignmentRequirement` and `SectorSize`, its
/// `DO_DEVICE_IRP_REQUIRES_EXTENSION` flag and its start-pending mark;
/// the device attached to counts the attachment in `Spare1`.
///
/// # Safety
/// Both are live device objects, and `source` is attached to nothing.
pub unsafe extern "C" fn IoAttachDeviceToDeviceStack(
    source: *mut DEVICE_OBJECT,
    target: *mut DEVICE_OBJECT,
) -> *mut DEVICE_OBJECT {
    // SAFETY: per the contract; `check` validates both. The chain and
    // the extensions' flags belong to the database lock.
    unsafe {
        check(source, "IoAttachDeviceToDeviceStack");
        check(target, "IoAttachDeviceToDeviceStack");
        let _database = DATABASE.lock();
        let top = top_locked(target);
        let flags = (*extra(top)).ExtensionFlags;
        if (*top).Flags & DO_DEVICE_INITIALIZING != 0
            || flags & DOE_GOING != 0
            || (*top).StackSize >= MAXIMUM_ATTACH_STACK_SIZE
        {
            return core::ptr::null_mut();
        }
        (*source).StackSize = (*top).StackSize + 1;
        (*source).AlignmentRequirement = (*top).AlignmentRequirement;
        (*source).SectorSize = (*top).SectorSize;
        (*extra(source)).ExtensionFlags |= flags & DOE_START_PENDING;
        (*source).Flags |= (*top).Flags & DO_DEVICE_IRP_REQUIRES_EXTENSION;
        (*top).AttachedDevice = source;
        (*top).Spare1 = (*top).Spare1.wrapping_add(1);
        (*extra(source)).AttachedTo = top;
        top
    }
}

/// [`IoDetachDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iodetachdevice):
/// take the device attached to `target` off it. If `target` was deleted
/// meanwhile and has no references, it is freed now.
///
/// # Safety
/// `target` is a live device object with a device attached to it.
pub unsafe extern "C" fn IoDetachDevice(target: *mut DEVICE_OBJECT) {
    // SAFETY: per the contract; `check` validates it.
    unsafe {
        check(target, "IoDetachDevice");
        let unused = {
            let database = DATABASE.lock();
            let attached = (*target).AttachedDevice;
            if attached.is_null() {
                kd::bugcheck(format_args!(
                    "IoDetachDevice: nothing is attached to {target:p}"
                ));
            }
            (*extra(attached)).AttachedTo = core::ptr::null_mut();
            (*target).AttachedDevice = core::ptr::null_mut();
            ((*extra(target)).ExtensionFlags & DOE_DELETE_PENDING != 0
                && (*target).ReferenceCount == 0)
                .then_some(database)
        };
        if let Some(database) = unused {
            complete_delete(target, database);
        }
    }
}

/// [`IoGetAttachedDeviceReference`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetattacheddevicereference):
/// the top of the stack `device` is in, with a pointer reference the
/// caller gives up with `ObDereferenceObject`.
///
/// # Safety
/// `device` is a live device object.
pub unsafe extern "C" fn IoGetAttachedDeviceReference(
    device: *mut DEVICE_OBJECT,
) -> *mut DEVICE_OBJECT {
    // SAFETY: per the contract; the top is live while the lock that
    // owns the chain is held, and referenced before it is dropped.
    unsafe {
        check(device, "IoGetAttachedDeviceReference");
        let _database = DATABASE.lock();
        let top = top_locked(device);
        ob::object::reference(top.cast());
        top
    }
}

/// [`IoGetDeviceAttachmentBaseRef`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iogetdeviceattachmentbaseref):
/// the bottom of the stack `device` is in, with a pointer reference the
/// caller gives up with `ObDereferenceObject`.
///
/// # Safety
/// `device` is a live device object.
pub unsafe extern "C" fn IoGetDeviceAttachmentBaseRef(
    device: *mut DEVICE_OBJECT,
) -> *mut DEVICE_OBJECT {
    // SAFETY: per the contract; as `IoGetAttachedDeviceReference`.
    unsafe {
        check(device, "IoGetDeviceAttachmentBaseRef");
        let _database = DATABASE.lock();
        let mut base = device;
        while !(*extra(base)).AttachedTo.is_null() {
            base = (*extra(base)).AttachedTo;
        }
        ob::object::reference(base.cast());
        base
    }
}

/// Take a reference on a device found by name, for a file about to be
/// opened on it, unless it has been deleted since it was found, or is
/// otherwise going away or not yet started (`ExtensionFlags`), as
/// Windows refuses the open.
///
/// # Safety
/// `device` is a device object whose memory the caller keeps alive (a
/// pointer reference).
pub unsafe fn reference_unless_deleted(device: *mut DEVICE_OBJECT) -> bool {
    let _database = DATABASE.lock();
    // SAFETY: per the contract; the mark and the count belong to the
    // lock. The private block is part of the device's own allocation.
    unsafe {
        if (*extra(device)).ExtensionFlags & (DOE_GOING | DOE_START_PENDING) != 0 {
            return false;
        }
        (*device).ReferenceCount += 1;
    }
    true
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
            let database = DATABASE.lock();
            (*device).ReferenceCount -= 1;
            ((*device).ReferenceCount == 0
                && (*extra(device)).ExtensionFlags & DOE_DELETE_PENDING != 0)
                .then_some(database)
        };
        if let Some(database) = last {
            complete_delete(device, database);
        }
    }
}
