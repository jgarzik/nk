//! Tests of what the I/O manager keeps for a driver beside its requests:
//! the extensions of its driver object, work items in memory of the
//! driver's own, and the error log.
//!
//! The drivers are the test's own, made as `stack` makes them.

use super::stack;
use crate::ex::work;
use crate::io::driver;
use crate::ke::wait;
use crate::mm::pool;
use crate::test::{Group, Report, Slot};
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::ex::IO_WORKITEM;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &["io.driver-extension", "work.caller-memory", "io.error-log"],
    run,
    manual: false,
};

pub static GROUPS: &[&Group] = &[&GROUP];

/// A dispatch routine for a driver that is sent nothing.
///
/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn refuse(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { crate::io::irp::invalid_device_request(device, request) }
}

/// A driver object's extensions are zeroed, found again by the address
/// they were allocated under, one to an address, and freed with the
/// driver object. Returns the facts checked.
fn driver_extension() -> Result<u32, &'static str> {
    let blocks = pool::usage().blocks;
    let object = stack::make_driver(refuse)?;
    // Two addresses of the driver's own, as a driver names its
    // extensions by its entry points.
    let ids = [0u8; 2];
    let (first, second) = (
        (&raw const ids[0]).cast_mut().cast::<c_void>(),
        (&raw const ids[1]).cast_mut().cast::<c_void>(),
    );
    // SAFETY: a driver object of the test's, with its extension; the
    // out pointers are the test's own.
    let result = unsafe {
        (|| {
            if !driver::IoGetDriverObjectExtension(object, first).is_null() {
                return Err("an extension was found before any was allocated");
            }
            let mut small = core::ptr::null_mut();
            let mut large = core::ptr::null_mut();
            if driver::IoAllocateDriverObjectExtension(object, first, 24, &raw mut small)
                != STATUS_SUCCESS
                || driver::IoAllocateDriverObjectExtension(object, second, 0x3000, &raw mut large)
                    != STATUS_SUCCESS
            {
                return Err("a driver-object extension could not be allocated");
            }
            if small.is_null() || large.is_null() || small == large {
                return Err("two extensions are not two blocks");
            }
            let zeroed = |at: *mut c_void, len: usize| {
                core::slice::from_raw_parts(at.cast::<u8>(), len)
                    .iter()
                    .all(|byte| *byte == 0)
            };
            if !zeroed(small, 24) || !zeroed(large, 0x3000) {
                return Err("a driver-object extension was not zeroed");
            }
            small.cast::<u8>().write_bytes(0x11, 24);
            large.cast::<u8>().write_bytes(0x22, 0x3000);
            if driver::IoGetDriverObjectExtension(object, first) != small
                || driver::IoGetDriverObjectExtension(object, second) != large
            {
                return Err("an extension was not found again by its address");
            }
            // What Windows keeps in front of each, where it keeps it.
            let newest = (*(*object).DriverExtension).ClientDriverExtension;
            if newest.is_null()
                || newest.add(1).cast::<c_void>() != large
                || (*newest).ClientIdentificationAddress != second
                || (*newest).NextExtension.add(1).cast::<c_void>() != small
            {
                return Err("the extensions are not listed in the driver extension");
            }
            // One to an address, and the out pointer says so.
            let mut again = small;
            if driver::IoAllocateDriverObjectExtension(object, first, 8, &raw mut again)
                != STATUS_OBJECT_NAME_COLLISION
                || !again.is_null()
            {
                return Err("a second extension under one address was not refused");
            }
            // More than a 32-bit size can describe with its header.
            let mut huge = small;
            if driver::IoAllocateDriverObjectExtension(
                object,
                (&raw const huge).cast_mut().cast(),
                MAXIMUM_DRIVER_OBJECT_EXTENSION + 1,
                &raw mut huge,
            ) != STATUS_INSUFFICIENT_RESOURCES
                || !huge.is_null()
            {
                return Err("an extension too large to describe was not refused");
            }
            if driver::IoGetDriverObjectExtension(object, (&raw mut again).cast()).is_null() {
                Ok(9)
            } else {
                Err("an extension was found under an address none was allocated by")
            }
        })()
    };
    // SAFETY: the driver has no devices.
    unsafe { stack::free_driver(object) };
    let result = result?;
    if pool::usage().blocks != blocks {
        return Err("the extensions were not freed with the driver object");
    }
    Ok(result + 1)
}

/// The work item in the driver's own memory, what its routine was last
/// handed, and how often it ran.
static ITEM: Slot<IO_WORKITEM> = Slot::new();
static RAN: Slot<KEVENT> = Slot::new();
static HANDED: [AtomicUsize; 3] = [const { AtomicUsize::new(0) }; 3];
static RUNS: AtomicUsize = AtomicUsize::new(0);
/// The count the item's device had while its routine ran.
static COUNTED: AtomicUsize = AtomicUsize::new(0);

/// # Safety
/// Called as the routine of a work item queued by `IoQueueWorkItemEx`.
unsafe extern "C" fn work_ex(object: *mut c_void, context: *mut c_void, item: *mut IO_WORKITEM) {
    HANDED[0].store(object.addr(), Ordering::Release);
    HANDED[1].store(context.addr(), Ordering::Release);
    HANDED[2].store(item.addr(), Ordering::Release);
    // SAFETY: the object is a live device or driver object: the item
    // keeps a device until this routine has returned.
    unsafe {
        if object.cast::<i16>().read() == IO_TYPE_DEVICE {
            let count = (*object.cast::<DEVICE_OBJECT>()).ReferenceCount;
            COUNTED.store(count as usize, Ordering::Release);
        }
        RUNS.fetch_add(1, Ordering::AcqRel);
        wait::KeSetEvent(RAN.ptr(), 0, 0);
    }
}

/// # Safety
/// Called as the routine of a work item queued by `IoQueueWorkItem`.
unsafe extern "C" fn work_plain(device: *mut DEVICE_OBJECT, context: *mut c_void) {
    // SAFETY: as `work_ex`; nothing is handed in the third place.
    unsafe { work_ex(device.cast(), context, core::ptr::null_mut()) };
}

/// Queue the item with `IoQueueWorkItemEx` and wait for its routine.
/// Says whether the routine was handed `object`, `context` and the
/// item.
///
/// # Safety
/// The item is initialised for `object` and not queued.
unsafe fn run_ex(object: *mut c_void, context: usize) -> bool {
    // SAFETY: per the contract; static storage for the event.
    unsafe {
        wait::KeInitializeEvent(RAN.ptr(), 0, 0);
        work::IoQueueWorkItemEx(ITEM.ptr(), Some(work_ex), 1, context as *mut c_void);
        wait::wait(Some(RAN.ptr().cast()), None);
    }
    [object.addr(), context, ITEM.ptr().addr()]
        .iter()
        .zip(&HANDED)
        .all(|(expected, seen)| seen.load(Ordering::Acquire) == *expected)
}

/// Wait until the worker that ran the item's routine has let go of the
/// device it counted, which it does once the routine has returned. The
/// wait has no time limit: a count that is never given back hangs the
/// test, and the boot with it.
///
/// # Safety
/// `device` is a live device of the test's.
unsafe fn settle(device: *mut DEVICE_OBJECT) {
    // SAFETY: per the contract.
    while unsafe { (&raw const (*device).ReferenceCount).read_volatile() } != 0 {
        crate::ke::thread::yield_now();
    }
}

/// A work item in the driver's own memory, of the size the I/O manager
/// names, is initialised for a device or a driver object, queued, and
/// queued again; its routine is handed the item, and a device is
/// counted while it runs. Returns the facts checked.
fn caller_memory_work_item() -> Result<u32, &'static str> {
    if work::IoSizeofWorkItem() as usize != size_of::<IO_WORKITEM>()
        || work::IoSizeofWorkItem() != 0x58
    {
        return Err("IoSizeofWorkItem is not the size of Windows' work item");
    }
    let object = stack::make_driver(refuse)?;
    let result = (|| {
        let device = stack::make_device(object, stack::PDO, None)?;
        RUNS.store(0, Ordering::Release);
        // SAFETY: a device and a driver object of the test's; static
        // storage for the item, which held something else.
        let result = unsafe {
            ITEM.ptr()
                .cast::<u8>()
                .write_bytes(0xA5, size_of::<IO_WORKITEM>());
            work::IoInitializeWorkItem(device.cast(), ITEM.ptr());
            let item = ITEM.ptr();
            let result = (|| {
                if !(*item).WorkItem.List.Flink.is_null()
                    || (*item).IoObject != device.cast()
                    || (*item).Type != 1
                    || !(*item).WorkOnBehalfThread.is_null()
                {
                    return Err("IoInitializeWorkItem did not set the item up as Windows does");
                }
                for round in 0..3 {
                    if !run_ex(device.cast(), 0x1000 + round) {
                        return Err("the routine was not handed its device, context and item");
                    }
                    if COUNTED.load(Ordering::Acquire) != 1 {
                        return Err("the device was not counted while the routine ran");
                    }
                    settle(device);
                }
                // The older call, on the same item: nothing is handed
                // in the item's place.
                wait::KeInitializeEvent(RAN.ptr(), 0, 0);
                work::IoQueueWorkItem(item, Some(work_plain), 1, 0x2000 as *mut c_void);
                wait::wait(Some(RAN.ptr().cast()), None);
                if HANDED[1].load(Ordering::Acquire) != 0x2000
                    || HANDED[2].load(Ordering::Acquire) != 0
                    || (*item).Type != 0
                {
                    return Err("IoQueueWorkItem did not run the item as one of the older kind");
                }
                settle(device);
                work::IoUninitializeWorkItem(item);
                // For a driver object, which is not counted.
                work::IoInitializeWorkItem(object.cast(), item);
                if !run_ex(object.cast(), 0x3000) {
                    return Err("the routine was not handed its driver object");
                }
                work::IoUninitializeWorkItem(item);
                Ok(9)
            })();
            crate::io::device::IoDeleteDevice(device);
            result
        };
        if result.is_ok() && RUNS.load(Ordering::Acquire) != 5 {
            return Err("the routine did not run once for each time it was queued");
        }
        result
    })();
    // SAFETY: its device is gone.
    unsafe { stack::free_driver(object) };
    result
}

/// An error-log packet is allocated within Windows' sizes, zeroed, for
/// a device or a driver object, which it holds until it is written;
/// writing it frees it. Returns the facts checked.
fn error_log() -> Result<u32, &'static str> {
    use crate::io::errlog;
    use crate::ob::object;
    let driver_object = stack::make_driver(refuse)?;
    let result = (|| {
        let device = stack::make_device(driver_object, stack::PDO, Some("\\Device\\NkErrorLog"))?;
        let blocks = pool::usage().blocks;
        // SAFETY: a device and a driver object of the test's; packets
        // are written, which frees them, before either goes.
        let result = unsafe {
            (|| {
                // The pointer counts the two objects have now.
                let counts = || {
                    let device_count = object::reference(device.cast());
                    object::dereference(device.cast());
                    let driver_count = object::reference(driver_object.cast());
                    object::dereference(driver_object.cast());
                    (device_count, driver_count)
                };
                let before = counts();
                let not_an_object = 0u64;
                for (object, size) in [
                    (device.cast::<c_void>(), 0x2F),
                    (device.cast(), ERROR_LOG_MAXIMUM_SIZE + 1),
                    (core::ptr::null_mut(), 0x40),
                    ((&raw const not_an_object).cast_mut().cast(), 0x40),
                ] {
                    if !errlog::IoAllocateErrorLogEntry(object, size).is_null() {
                        return Err("an error-log packet Windows refuses was allocated");
                    }
                }
                for size in [0x30, 0x41, ERROR_LOG_MAXIMUM_SIZE] {
                    let packet = errlog::IoAllocateErrorLogEntry(device.cast(), size)
                        .cast::<IO_ERROR_LOG_PACKET>();
                    if packet.is_null() {
                        return Err("an error-log packet could not be allocated");
                    }
                    let zeroed =
                        core::slice::from_raw_parts(packet.cast::<u8>(), usize::from(size))
                            .iter()
                            .all(|byte| *byte == 0);
                    let header = packet.cast::<ERROR_LOG_ENTRY>().sub(1);
                    let held = counts() == (before.0 + 1, before.1 + 1);
                    let described = (*header).Type == IO_TYPE_ERROR_LOG
                        && (*header).Size as usize == error_log_allocation(size).unwrap_or(0)
                        && (*header).DeviceObject == device
                        && (*header).DriverObject == driver_object;
                    // As a driver fills one in: the last byte it asked
                    // for is its own.
                    (*packet).ErrorCode = 0xC004_000Bu32 as NTSTATUS;
                    (*packet).FinalStatus = STATUS_DEVICE_NOT_READY;
                    (*packet).UniqueErrorValue = u32::from(size);
                    (*packet).MajorFunctionCode = IRP_MJ_READ;
                    packet.cast::<u8>().add(usize::from(size) - 1).write(0xEE);
                    errlog::IoWriteErrorLogEntry(packet.cast());
                    if !zeroed || !held || !described {
                        return Err(
                            "an error-log packet is not zeroed, or does not hold its device",
                        );
                    }
                    if counts() != before || pool::usage().blocks != blocks {
                        return Err("writing an error-log packet did not free it");
                    }
                }
                // For a driver object: no device is named.
                let packet = errlog::IoAllocateErrorLogEntry(driver_object.cast(), 0x30);
                if packet.is_null() {
                    return Err("an error-log packet could not be allocated for a driver object");
                }
                let header = packet.cast::<ERROR_LOG_ENTRY>().sub(1);
                let named = (*header).DeviceObject.is_null()
                    && (*header).DriverObject == driver_object
                    && counts() == (before.0, before.1 + 1);
                errlog::IoWriteErrorLogEntry(packet);
                if !named || counts() != before || pool::usage().blocks != blocks {
                    return Err("a driver object's error-log packet does not hold it alone");
                }
                Ok(12)
            })()
        };
        // SAFETY: nothing holds the device any more.
        unsafe { crate::io::device::IoDeleteDevice(device) };
        result
    })();
    // SAFETY: its device is gone.
    unsafe { stack::free_driver(driver_object) };
    result
}

fn run(report: &mut Report, _: &BootInfo) {
    let mut numbered = |name: &str, result: Result<u32, &'static str>| match result {
        Ok(n) => report.ok_with(name, format_args!("{n} checked")),
        Err(why) => report.fail(name, format_args!("{why}")),
    };
    numbered("io.driver-extension", driver_extension());
    numbered("work.caller-memory", caller_memory_work_item());
    numbered("io.error-log", error_log());
}
