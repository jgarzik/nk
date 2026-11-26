//! Microsoft's storage stack, unmodified, from Windows 10, on the
//! machine's AHCI controller: `acpi.sys`, `pci.sys` (with `pshed.dll`),
//! `storahci.sys` on `storport.sys`, `disk.sys` on `classpnp.sys`.
//!
//! The group runs alone (`test=stor.load`), on a machine that has the
//! disk: what it leaves running is the machine's device tree.
//!
//! `stor.io` is the proof of disk I/O (`diskio.rs`) against the disk
//! the stack makes of the machine's data disk. It runs once that
//! device exists, and until then is skipped, saying so.

use super::diskio;
use crate::io::service;
use crate::ldr;
use crate::ob;
use crate::pnp::node::{self, State};
use crate::pnp::registry;
use crate::test::{Group, Report};
use alloc::format;
use alloc::string::String;
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["stor.load", "stor.enumerate", "stor.io"],
    run,
    manual: true,
};

/// The services of the stack, which the registry starts at boot.
const SERVICES: [&str; 4] = ["ACPI", "pci", "storahci", "disk"];

/// Every image of the stack: the services' and the libraries their
/// imports bring in.
const IMAGES: [&str; 7] = [
    "acpi.sys",
    "pci.sys",
    "pshed.dll",
    "storport.sys",
    "storahci.sys",
    "classpnp.sys",
    "disk.sys",
];

/// Every driver of the stack was started at boot from its service key,
/// and every image of the stack is loaded.
fn load() -> Result<(), &'static str> {
    if let Some(stopped) = SERVICES.iter().find(|name| !service::running(name)) {
        kprintln!("stor: service {stopped} is not running");
        return Err("a driver of the stack was not started at boot");
    }
    if let Some(absent) = IMAGES.iter().find(|file| ldr::module_named(file).is_none()) {
        kprintln!("stor: image {absent} is not loaded");
        return Err("an image of the stack is not loaded");
    }
    Ok(())
}

/// A device of the path from the root to the disk, as the reference
/// Windows has it (`TREE.md` of the recorded trace): its instance path,
/// its parent's, its first hardware identifier, its service as the
/// device's key names it, its class, and whether NK starts it yet.
struct Expected {
    instance: &'static str,
    parent: &'static str,
    hardware_id: &'static str,
    service: &'static str,
    class: &'static str,
    started: bool,
}

const COMPUTER: &str = "{4d36e966-e325-11ce-bfc1-08002be10318}";
const SYSTEM: &str = "{4d36e97d-e325-11ce-bfc1-08002be10318}";

/// The path as far as NK brings it up. A device NK finds and does not
/// start yet is listed with `started: false`, and the test holds NK to
/// that too: it is changed in the commit that starts the device.
const PATH: [Expected; 2] = [
    Expected {
        instance: "ROOT\\ACPI_HAL\\0000",
        parent: "HTREE\\ROOT\\0",
        hardware_id: "acpiapic",
        service: "\\Driver\\ACPI_HAL",
        class: COMPUTER,
        started: true,
    },
    Expected {
        instance: "ACPI_HAL\\PNP0C08\\0",
        parent: "ROOT\\ACPI_HAL\\0000",
        hardware_id: "ACPI_HAL\\PNP0C08",
        service: "ACPI",
        class: SYSTEM,
        started: false,
    },
];

/// The devices of the path exist where Windows has them, with its
/// identifiers, services and classes, and are started as far as NK
/// starts them. Returns how many are started.
fn enumerate() -> Result<usize, &'static str> {
    let mut started = 0;
    for expected in &PATH {
        let found = node::by_instance(expected.instance).and_then(node::get);
        let Some(found) = found else {
            kprintln!("stor: there is no device {}", expected.instance);
            return Err("a device of the path was not found");
        };
        let parent = node::get(found.parent).map(|above| above.instance);
        let key = registry::enum_key(expected.instance);
        let wrong = if parent.as_deref() != Some(expected.parent) {
            Some("is not below the device Windows has it below")
        } else if found.hardware_ids.first().map(String::as_str) != Some(expected.hardware_id)
            || registry::strings(&key, "HardwareID") != found.hardware_ids
        {
            Some("does not have Windows' hardware identifiers, in the node and the key")
        } else if registry::string(&key, "Service").as_deref() != Some(expected.service) {
            Some("is not given the service Windows gives it")
        } else if registry::string(&key, "ClassGUID").as_deref() != Some(expected.class) {
            Some("is not in the class Windows has it in")
        } else if (found.state == State::Started) != expected.started {
            Some("is not as far as this test says NK brings it")
        } else {
            None
        };
        if let Some(wrong) = wrong {
            kprintln!("stor: {} {wrong}", expected.instance);
            return Err("a device of the path is not as Windows has it");
        }
        started += usize::from(found.state == State::Started);
    }
    // What the HAL offers the ACPI device is what Windows' HAL offers:
    // the requirements and the boot configuration the reference
    // machine recorded are 13032 and 8140 bytes, 406 interrupts each.
    let configuration = format!("{}\\LogConf", registry::enum_key("ACPI_HAL\\PNP0C08\\0"));
    let size = |name: &str| crate::cm::read(&configuration, name).map(|(_, data)| data.len());
    if size("BasicConfigVector") != Ok(13032) || size("BootConfig") != Ok(8140) {
        return Err("the ACPI device's LogConf is not the size Windows recorded");
    }
    Ok(started)
}

/// The first disk's device, as `disk.sys` names it; `\??\PhysicalDrive0`
/// is its link.
const DISK: &str = "\\Device\\Harddisk0\\DR0";

/// Whether an object called `name` is in the namespace.
fn exists(name: &str) -> bool {
    let wide: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    match ob::lookup(None, &wide) {
        Ok((body, rest)) => {
            // SAFETY: the look-up's reference.
            unsafe { ob::object::dereference(body) };
            rest.is_empty()
        }
        Err(_) => false,
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    crate::test::keeps_what_it_started();
    if let Some(absent) = IMAGES.iter().find(|file| ldr::boot_file(file).is_none()) {
        r.skip_rest(format_args!("module {absent} not provided"));
        return;
    }
    r.check("stor.load", load);
    match enumerate() {
        Ok(started) => r.ok_with(
            "stor.enumerate",
            format_args!("{started} of {} devices of the path started", PATH.len()),
        ),
        Err(why) => r.fail("stor.enumerate", format_args!("{why}")),
    }
    if !exists(DISK) {
        r.skip(
            "stor.io",
            format_args!("the disk device {DISK} does not exist yet"),
        );
        return;
    }
    match diskio::disk_io(DISK) {
        Ok(counts) => r.ok_with("stor.io", format_args!("{counts}")),
        Err(why) => r.fail("stor.io", format_args!("{why}")),
    }
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
