//! Tests of work items and the worker threads.

use crate::ex::work;
use crate::io::device;
use crate::mm::pool;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::{DEVICE_OBJECT, DRIVER_EXTENSION, DRIVER_OBJECT};

pub static GROUP: Group = Group {
    names: &["work.runs", "work.many", "work.io", "work.delete-race"],
    run,
    manual: false,
};

fn counted(r: &mut Report, name: &str, what: &str, result: Result<u64, &'static str>) {
    match result {
        Ok(n) => r.ok_with(name, format_args!("{what} {n}")),
        Err(why) => r.fail(name, format_args!("{why}")),
    }
}

/// Run `test` with a device object of a driver made up for the purpose.
fn with_device(
    test: impl FnOnce(*mut DEVICE_OBJECT) -> Result<u64, &'static str>,
) -> Result<u64, &'static str> {
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let driver = pool::alloc_zeroed(size, u32::from_le_bytes(*b"Test")).cast::<DRIVER_OBJECT>();
    if driver.is_null() {
        return Err("no memory for a driver object");
    }
    let mut device_object = core::ptr::null_mut();
    // SAFETY: a zeroed driver object is enough to hang a nameless device
    // on; both are freed below.
    let status = unsafe {
        device::IoCreateDevice(
            driver,
            0,
            core::ptr::null(),
            0x22,
            0,
            0,
            &raw mut device_object,
        )
    };
    let result = if status == 0 {
        let result = test(device_object);
        // SAFETY: created just above, with nothing referring to it.
        unsafe { device::IoDeleteDevice(device_object) };
        result
    } else {
        Err("could not create a device object")
    };
    let _ = pool::free(driver.cast());
    result
}

fn run(r: &mut Report, _: &BootInfo) {
    counted(r, "work.runs", "routines run:", work::runs_test());
    counted(r, "work.many", "items, each run once:", work::many_test());
    counted(r, "work.io", "routines run:", with_device(work::io_test));
    counted(r, "work.delete-race", "devices deleted:", delete_race());
}

/// The driver object the delete-race test hangs its devices on.
static DRIVER: core::sync::atomic::AtomicPtr<DRIVER_OBJECT> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

fn delete_race() -> Result<u64, &'static str> {
    fn make_device() -> Option<*mut DEVICE_OBJECT> {
        let driver = DRIVER.load(core::sync::atomic::Ordering::Acquire);
        let mut device_object = core::ptr::null_mut();
        // SAFETY: the test's own zeroed driver object.
        let status = unsafe {
            device::IoCreateDevice(
                driver,
                0,
                core::ptr::null(),
                0x22,
                0,
                0,
                &raw mut device_object,
            )
        };
        (status == 0).then_some(device_object)
    }
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let driver = pool::alloc_zeroed(size, u32::from_le_bytes(*b"Test")).cast::<DRIVER_OBJECT>();
    if driver.is_null() {
        return Err("no memory for a driver object");
    }
    DRIVER.store(driver, core::sync::atomic::Ordering::Release);
    let result = work::delete_race_test(make_device);
    let _ = pool::free(driver.cast());
    result
}

/// A work routine that returns with the IRQL raised must stop the system.
pub static BAD_RETURN: Group = Group {
    names: &["neg.work-bad-irql"],
    run: bad_return,
    manual: true,
};

fn bad_return(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.work-bad-irql");
    work::bad_return_test();
    r.fail(
        "neg.work-bad-irql",
        format_args!("a work routine returned at a raised IRQL, and nothing happened"),
    );
}
