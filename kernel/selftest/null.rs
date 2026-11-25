//! Microsoft's inbox `null.sys`, unmodified, from Windows 10.
//!
//! Expected results are what the Null device does on Windows: a read
//! reports end of file with no bytes, a write accepts every byte.

use super::{module, resources};
use crate::io::driver;
use crate::io::file::{self, IoResult};
use crate::{ob, test};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::FILE_OBJECT;
use nk_ntabi::status::*;

const DEVICE: &str = "\\Device\\Null";
/// `FILE_DEVICE_NULL`
const FILE_DEVICE_NULL: u32 = 0x15;
/// `FILE_DEVICE_SECURE_OPEN`
const SECURE_OPEN: u32 = 0x100;

fn device_checks() -> Result<(), &'static str> {
    let name: alloc::vec::Vec<u16> = DEVICE.encode_utf16().collect();
    let device = ob::lookup_device(&name).ok_or("\\Device\\Null was not created")?;
    // SAFETY: the namespace only holds live device objects.
    let (kind, characteristics, flags) = unsafe {
        (
            (*device).DeviceType,
            (*device).Characteristics,
            (*device).Flags,
        )
    };
    if kind != FILE_DEVICE_NULL {
        return Err("device type is not FILE_DEVICE_NULL");
    }
    if characteristics & SECURE_OPEN == 0 {
        return Err("FILE_DEVICE_SECURE_OPEN is not set");
    }
    if flags & nk_ntabi::io::DO_DEVICE_INITIALIZING != 0 {
        return Err("device is still marked initializing after DriverEntry");
    }
    Ok(())
}

fn read_test(file: *mut FILE_OBJECT) -> Result<(), &'static str> {
    let mut buffer = [0xAAu8; 64];
    // SAFETY: `file` is open for the duration of the tests.
    let r = unsafe { file::read(file, &mut buffer) }
        .map_err(|_| "read was not completed synchronously")?;
    if r != (IoResult {
        status: STATUS_END_OF_FILE,
        information: 0,
    }) {
        return Err("read must return STATUS_END_OF_FILE with 0 bytes");
    }
    if buffer != [0xAA; 64] {
        return Err("read wrote into the caller's buffer");
    }
    Ok(())
}

fn write_test(file: *mut FILE_OBJECT) -> Result<(), &'static str> {
    for len in [0usize, 1, 64, 5000] {
        let data = alloc::vec![0x5Au8; len];
        // SAFETY: `file` is open for the duration of the tests.
        let r = unsafe { file::write(file, &data) }
            .map_err(|_| "write was not completed synchronously")?;
        if r != (IoResult {
            status: STATUS_SUCCESS,
            information: len,
        }) {
            return Err("write must succeed and report every byte written");
        }
    }
    Ok(())
}

/// A request type the driver does not handle keeps the kernel's default.
fn ioctl_test(file: *mut FILE_OBJECT) -> Result<(), &'static str> {
    let code = nk_ntabi::io::ctl_code(FILE_DEVICE_NULL, 0x800, nk_ntabi::io::METHOD_BUFFERED, 0);
    let mut out = [0u8; 8];
    // SAFETY: `file` is open for the duration of the tests.
    let r = unsafe { file::device_control(file, code, b"ping", &mut out) }
        .map_err(|_| "ioctl was not completed")?;
    if r.status != STATUS_INVALID_DEVICE_REQUEST {
        return Err("an unhandled request type must fail with STATUS_INVALID_DEVICE_REQUEST");
    }
    Ok(())
}

pub fn run(info: &BootInfo) {
    let Some(image) = module(info, "null.sys") else {
        return test::skip(
            "null",
            format_args!("module null.sys not provided (no fixture for this architecture)"),
        );
    };
    let before = resources();
    let object = match driver::load("Null", image) {
        Ok(object) => object,
        Err(e) => return test::fail("null.load", format_args!("{e:?}")),
    };
    test::ok("null.load");
    test::run("null.device", device_checks);

    match file::open(DEVICE) {
        Ok(file) => {
            test::ok("null.open");
            test::run("null.read", || read_test(file));
            test::run("null.write", || write_test(file));
            test::run("null.unhandled-request", || ioctl_test(file));
            // SAFETY: `file` came from `open` and is closed exactly once.
            match unsafe { file::close(file) } {
                Ok(IoResult {
                    status: STATUS_SUCCESS,
                    ..
                }) => test::ok("null.close"),
                other => test::fail("null.close", format_args!("{other:?}")),
            }
        }
        Err(status) => test::fail("null.open", format_args!("status {status:#x}")),
    }
    if file::open("\\Device\\NoSuchDevice") == Err(STATUS_OBJECT_NAME_NOT_FOUND) {
        test::ok("io.open.missing-name");
    } else {
        test::fail(
            "io.open.missing-name",
            format_args!("opening a name that does not exist must fail"),
        );
    }

    match driver::unload(object) {
        Ok(()) if file::open(DEVICE).is_err() => test::ok("null.unload"),
        Ok(()) => test::fail(
            "null.unload",
            format_args!("device still opens after unload"),
        ),
        Err(why) => test::fail("null.unload", format_args!("{why}")),
    }
    let after = resources();
    if after == before {
        test::ok("null.no-leak");
    } else {
        test::fail(
            "null.no-leak",
            format_args!("before {before:?}, after {after:?}"),
        );
    }
}
