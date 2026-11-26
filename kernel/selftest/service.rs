//! The drivers that start at boot: the order the registry gives, and
//! what became of each before the tests began. And the image of a
//! service whose key does not name one. And a driver starting a
//! service by its key (`ZwLoadDriver`).

use super::resources;
use crate::io::service;
use crate::test::{Group, Report};
use crate::{cm, ldr};
use alloc::string::String;
use core::fmt::Write;
use nk_bootinfo::BootInfo;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &[
        "io.service.boot-start",
        "io.service.default-image",
        "io.service.zw-load-missing",
        "io.service.zw-load",
    ],
    run,
    manual: false,
};

/// The fixture hive's boot-start drivers, in the order of their groups
/// in its `ServiceGroupOrder`: `Base`, then `File System`, which the
/// drivers' keys spell `File system`. That group has no tag list, so
/// Msfs comes before Npfs as their keys do.
const FIXTURE_ORDER: [&str; 3] = ["Null", "Msfs", "Npfs"];

/// Each boot-start service whose image is among the boot files is
/// running, and each whose image is not was passed over. Returns what
/// became of each, in order.
fn boot_start() -> Result<String, &'static str> {
    let services = cm::boot_start()?;
    if !services.iter().map(|(name, _)| &name[..]).eq(FIXTURE_ORDER) {
        return Err("the hive's boot-start services are not Null, then the file systems");
    }
    let mut seen = String::new();
    for (name, _) in &services {
        let file = service::image(name).map_err(|_| "a boot-start service names no image")?;
        let present = ldr::boot_file(&file).is_some();
        if present != service::running(name) {
            return Err(if present {
                "a boot-start driver whose image is a boot file is not running"
            } else {
                "a driver is running whose image is not a boot file"
            });
        }
        let _ = write!(
            seen,
            "{name} {}, ",
            if present { "running" } else { "skipped" }
        );
    }
    seen.truncate(seen.len() - 2);
    Ok(seen)
}

/// A service of this name has no key until a test makes one, and a
/// boot file `<name>.sys` on both architectures.
const PLAIN: &str = "nkc-irql";

/// A key without `ImagePath`, as Windows' own service keys are: the
/// image is `<name>.sys`, and the driver starts from it.
fn default_image() -> Result<(), &'static str> {
    // `SERVICE_KERNEL_DRIVER`, `SERVICE_DEMAND_START`, as numbers.
    let values: [(&str, u32, &[u8]); 2] = [
        ("Type", 4, &1u32.to_le_bytes()),
        ("Start", 4, &3u32.to_le_bytes()),
    ];
    let key = alloc::format!("Machine\\System\\CurrentControlSet\\Services\\{PLAIN}");
    cm::write(&key, &values).map_err(|_| "the key could not be made")?;
    if service::image(PLAIN).ok().as_deref() != Some("nkc-irql.sys") {
        return Err("a key without ImagePath does not mean <name>.sys");
    }
    let before = resources();
    service::start(PLAIN).map_err(|_| "the service did not start from its default image")?;
    let ran = service::running(PLAIN);
    service::stop(PLAIN)?;
    if !ran {
        return Err("the service started and is not running");
    }
    if resources() != before {
        return Err("starting and stopping the service left something behind");
    }
    Ok(())
}

/// `ZwLoadDriver` for the key `path`.
fn zw_load(path: &str) -> NTSTATUS {
    let mut text: alloc::vec::Vec<u16> = path.encode_utf16().collect();
    let name = UNICODE_STRING {
        Length: (text.len() * 2) as u16,
        MaximumLength: (text.len() * 2) as u16,
        Buffer: text.as_mut_ptr(),
    };
    // SAFETY: a counted string over a local.
    unsafe { service::ZwLoadDriver(&raw const name) }
}

/// A service key that is not there, as `acpi.sys` asks for `acpiex`:
/// the status of opening the key.
fn zw_load_missing() -> Result<(), &'static str> {
    let missing = [
        (
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\acpiex",
            STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        (
            "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\NkNone",
            STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        (
            "\\Registry\\Machine\\NkNone\\Services\\x",
            STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        ("\\NkNoDirectory\\x", STATUS_OBJECT_PATH_NOT_FOUND),
        ("\\Device", STATUS_OBJECT_TYPE_MISMATCH),
        ("acpiex", STATUS_OBJECT_PATH_SYNTAX_BAD),
        ("", STATUS_OBJECT_PATH_SYNTAX_BAD),
    ];
    for (path, expected) in missing {
        if zw_load(path) != expected {
            return Err("a service key that is not there was not reported as the open reports it");
        }
    }
    Ok(())
}

/// A driver starts a service by its key, in any letter case; a second
/// start says the image is loaded already.
fn zw_load_starts() -> Result<(), &'static str> {
    service::create(PLAIN, "nkc-irql.sys").map_err(|_| "the key could not be made")?;
    let path = alloc::format!("\\registry\\MACHINE\\System\\CurrentControlSet\\Services\\{PLAIN}");
    let before = resources();
    if zw_load(&path) != STATUS_SUCCESS {
        return Err("ZwLoadDriver did not start the service");
    }
    let ran = service::running(PLAIN);
    let again = zw_load(&path);
    service::stop(PLAIN)?;
    if !ran || again != STATUS_IMAGE_ALREADY_LOADED {
        return Err("the driver is not running, or was started twice");
    }
    if resources() != before {
        return Err("starting and stopping the service left something behind");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("io.service.zw-load-missing", zw_load_missing);
    if ldr::boot_file("nkc-irql.sys").is_some() {
        r.check("io.service.default-image", default_image);
        r.check("io.service.zw-load", zw_load_starts);
    } else {
        r.skip(
            "io.service.zw-load",
            format_args!("module nkc-irql.sys not provided"),
        );
        r.skip(
            "io.service.default-image",
            format_args!("module nkc-irql.sys not provided"),
        );
    }
    if ldr::boot_file(nk_bootinfo::HIVE_MODULE).is_none() {
        return r.skip(
            "io.service.boot-start",
            format_args!("no SYSTEM hive provided"),
        );
    }
    match boot_start() {
        Ok(seen) => r.ok_with("io.service.boot-start", format_args!("{seen}")),
        Err(why) => r.fail("io.service.boot-start", format_args!("{why}")),
    }
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
