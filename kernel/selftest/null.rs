//! Microsoft's inbox `null.sys`, unmodified, from Windows 10.
//!
//! Expected results are what the Null device does on Windows: a read
//! reports end of file with no bytes, a write accepts every byte.

use super::resources;
use crate::io::file::{self, IoResult};
use crate::io::service::{self, ServiceError};
use crate::ldr;
use crate::ob;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_ntabi::status::*;

const DEVICE: &str = "\\Device\\Null";
/// `FILE_DEVICE_NULL`
const FILE_DEVICE_NULL: u32 = 0x15;
/// `FILE_DEVICE_SECURE_OPEN`
const SECURE_OPEN: u32 = 0x100;

fn device_checks() -> Result<(), &'static str> {
    let name: alloc::vec::Vec<u16> = DEVICE.encode_utf16().collect();
    let (body, _) = ob::lookup(None, &name).map_err(|_| "\\Device\\Null was not created")?;
    // SAFETY: the look-up's reference keeps the object's memory, and is
    // given up once the fields are read; they are read only if it is a
    // device.
    let (kind, characteristics, flags) = unsafe {
        let device = body.cast::<nk_ntabi::io::DEVICE_OBJECT>();
        let fields = core::ptr::eq(
            ob::object::type_of(body),
            &raw const ob::object::DEVICE_TYPE,
        )
        .then(|| {
            (
                (*device).DeviceType,
                (*device).Characteristics,
                (*device).Flags,
            )
        });
        ob::object::dereference(body);
        fields.ok_or("\\Device\\Null is not a device")?
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

fn read_test(file: u64) -> Result<(), &'static str> {
    let mut buffer = [0xAAu8; 64];
    let r = file::read(file, &mut buffer).map_err(|_| "read was not completed synchronously")?;
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

fn write_test(file: u64) -> Result<(), &'static str> {
    for len in [0usize, 1, 64, 5000] {
        let data = alloc::vec![0x5Au8; len];
        let r = file::write(file, &data).map_err(|_| "write was not completed synchronously")?;
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
fn ioctl_test(file: u64) -> Result<(), &'static str> {
    let code = nk_ntabi::io::ctl_code(FILE_DEVICE_NULL, 0x800, nk_ntabi::io::METHOD_BUFFERED, 0);
    let mut out = [0u8; 8];
    let r = file::device_control(file, code, b"ping", &mut out)
        .map_err(|_| "ioctl was not completed")?;
    if r.status != STATUS_INVALID_DEVICE_REQUEST {
        return Err("an unhandled request type must fail with STATUS_INVALID_DEVICE_REQUEST");
    }
    Ok(())
}

pub static GROUP: Group = Group {
    names: &[
        "null.load",
        "null.device",
        "null.open",
        "null.read",
        "null.write",
        "null.unhandled-request",
        "null.close",
        "io.open.missing-name",
        "null.unload",
        "null.no-leak",
    ],
    run,
    manual: false,
};

fn run(r: &mut Report, _: &BootInfo) {
    if ldr::boot_file("null.sys").is_none() {
        return r.skip_rest(format_args!("module null.sys not provided"));
    }
    // Null starts at boot when the hive says so. It is stopped for the
    // test, which loads and unloads it and counts what that leaves
    // behind, and started again at the end.
    let at_boot = service::running("Null");
    if at_boot && let Err(why) = service::stop("Null") {
        return r.fail("null.load", format_args!("could not stop Null: {why}"));
    }
    let before = resources();
    // A registry without the hive has no key for it: make one, as
    // `sc create` would.
    let started = match service::start("Null") {
        Err(ServiceError::NoKey) => {
            service::create("Null", "null.sys").and_then(|()| service::start("Null"))
        }
        other => other,
    };
    if let Err(e) = started {
        return r.fail("null.load", format_args!("{e:?}"));
    }
    r.ok("null.load");
    r.check("null.device", device_checks);

    match super::open(DEVICE) {
        Ok(file) => {
            r.ok("null.open");
            r.check("null.read", || read_test(file));
            r.check("null.write", || write_test(file));
            r.check("null.unhandled-request", || ioctl_test(file));
            match file::close(file) {
                STATUS_SUCCESS => r.ok("null.close"),
                other => r.fail("null.close", format_args!("status {other:#x}")),
            }
        }
        Err(status) => r.fail("null.open", format_args!("status {status:#x}")),
    }
    if super::open("\\Device\\NoSuchDevice") == Err(STATUS_OBJECT_NAME_NOT_FOUND) {
        r.ok("io.open.missing-name");
    } else {
        r.fail(
            "io.open.missing-name",
            format_args!("opening a name that does not exist must fail"),
        );
    }

    match service::stop("Null") {
        Ok(()) if super::open(DEVICE).is_err() => r.ok("null.unload"),
        Ok(()) => r.fail(
            "null.unload",
            format_args!("device still opens after unload"),
        ),
        Err(why) => r.fail("null.unload", format_args!("{why}")),
    }
    let after = resources();
    let restarted = !at_boot || service::start("Null").is_ok();
    if after != before {
        r.fail(
            "null.no-leak",
            format_args!("before {before:?}, after {after:?}"),
        );
    } else if !restarted {
        r.fail(
            "null.no-leak",
            format_args!("Null could not be started again"),
        );
    } else {
        r.ok("null.no-leak");
    }
}
