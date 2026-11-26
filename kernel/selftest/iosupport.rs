//! Tests of what the I/O manager keeps for a driver beside its requests:
//! the extensions of its driver object.
//!
//! The drivers are the test's own, made as `stack` makes them.

use super::stack;
use crate::io::driver;
use crate::mm::pool;
use crate::test::{Group, Report};
use core::ffi::c_void;
use nk_bootinfo::BootInfo;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &["io.driver-extension"],
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

fn run(report: &mut Report, _: &BootInfo) {
    let mut numbered = |name: &str, result: Result<u32, &'static str>| match result {
        Ok(n) => report.ok_with(name, format_args!("{n} checked")),
        Err(why) => report.fail(name, format_args!("{why}")),
    };
    numbered("io.driver-extension", driver_extension());
}
