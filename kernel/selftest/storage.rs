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
/// device's key names it, its class, and the drivers of its stack, top
/// first.
struct Expected {
    instance: &'static str,
    parent: &'static str,
    hardware_id: &'static str,
    service: &'static str,
    class: &'static str,
    stack: &'static [&'static str],
}

const COMPUTER: &str = "{4d36e966-e325-11ce-bfc1-08002be10318}";
const SYSTEM: &str = "{4d36e97d-e325-11ce-bfc1-08002be10318}";
const HDC: &str = "{4d36e96a-e325-11ce-bfc1-08002be10318}";
const DISK_DRIVE: &str = "{4d36e967-e325-11ce-bfc1-08002be10318}";

const ACPI_HAL: &str = "ROOT\\ACPI_HAL\\0000";
const ACPI: &str = "ACPI_HAL\\PNP0C08\\0";
const PCI_ROOT: &str = "ACPI\\PNP0A08\\0";
const AHCI: &str = "PCI\\VEN_8086&DEV_2922&SUBSYS_11001AF4&REV_02\\3&11583659&0&FA";
const DISK_INSTANCE: &str = "SCSI\\Disk&Ven_QEMU&Prod_HARDDISK\\4&35424867&0&000000";

/// The path. The stacks are Windows' but for the disk's, which on
/// Windows has `partmgr` on top: NK builds it without the class
/// filters that have no image (`doc/design/absent.md`).
const PATH: [Expected; 5] = [
    Expected {
        instance: ACPI_HAL,
        parent: "HTREE\\ROOT\\0",
        hardware_id: "acpiapic",
        service: "\\Driver\\ACPI_HAL",
        class: COMPUTER,
        stack: &["ACPI_HAL", "PnpManager"],
    },
    Expected {
        instance: ACPI,
        parent: ACPI_HAL,
        hardware_id: "ACPI_HAL\\PNP0C08",
        service: "ACPI",
        class: SYSTEM,
        stack: &["ACPI", "ACPI_HAL"],
    },
    Expected {
        instance: PCI_ROOT,
        parent: ACPI,
        hardware_id: "ACPI\\VEN_PNP&DEV_0A08",
        service: "pci",
        class: SYSTEM,
        stack: &["pci", "ACPI"],
    },
    Expected {
        instance: AHCI,
        parent: PCI_ROOT,
        hardware_id: "PCI\\VEN_8086&DEV_2922&SUBSYS_11001AF4&REV_02",
        service: "storahci",
        class: HDC,
        stack: &["storahci", "ACPI", "pci"],
    },
    Expected {
        instance: DISK_INSTANCE,
        parent: AHCI,
        hardware_id: "SCSI\\DiskQEMU____________HARDDISK2.5+",
        service: "disk",
        class: DISK_DRIVE,
        stack: &["disk", "storahci"],
    },
];

/// The devices of the path exist where Windows has them, with its
/// identifiers, services, classes and stacks, each started.
fn enumerate() -> Result<(), &'static str> {
    for expected in &PATH {
        let found = node::by_instance(expected.instance).and_then(node::get);
        let Some(found) = found else {
            kprintln!("stor: there is no device {}", expected.instance);
            return Err("a device of the path was not found");
        };
        let parent = node::get(found.parent).map(|above| above.instance);
        let key = registry::enum_key(expected.instance);
        // SAFETY: the tree's device.
        let stack = unsafe {
            crate::pnp::engine::stack_drivers(found.pdo as *mut nk_ntabi::io::DEVICE_OBJECT)
        };
        let wanted: alloc::vec::Vec<String> = expected
            .stack
            .iter()
            .map(|driver| format!("\\Driver\\{driver}"))
            .collect();
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
        } else if found.state != State::Started {
            Some("is not started")
        } else if !stack
            .iter()
            .map(|name| name.to_ascii_lowercase())
            .eq(wanted.iter().map(|name| name.to_ascii_lowercase()))
        {
            kprintln!("stor: its stack is {stack:?}");
            Some("does not have the stack Windows gives it")
        } else {
            None
        };
        if let Some(wrong) = wrong {
            kprintln!("stor: {} {wrong}", expected.instance);
            return Err("a device of the path is not as Windows has it");
        }
    }
    // What the HAL offers the ACPI device is what Windows' HAL offers:
    // the requirements and the boot configuration the reference
    // machine recorded are 13032 and 8140 bytes, 406 interrupts each.
    let configuration = format!("{}\\LogConf", registry::enum_key(ACPI));
    let size = |name: &str| crate::cm::read(&configuration, name).map(|(_, data)| data.len());
    if size("BasicConfigVector") != Ok(13032) || size("BootConfig") != Ok(8140) {
        return Err("the ACPI device's LogConf is not the size Windows recorded");
    }
    controller_resources()
}

/// The AHCI controller was given what Windows gives it (`TREE.md`): its
/// ports and its registers where firmware put them, and one
/// message-signalled interrupt, which its settings from the driver
/// database allow.
fn controller_resources() -> Result<(), &'static str> {
    use nk_pnp::resources::{ResourceList, TYPE_MEMORY, TYPE_PORT};
    let found = node::by_instance(AHCI)
        .and_then(node::get)
        .ok_or("the controller has no node")?;
    let settings = format!(
        "{}\\Device Parameters\\Interrupt Management\\MessageSignaledInterruptProperties",
        registry::enum_key(AHCI)
    );
    if registry::dword(&settings, "MSISupported") != Some(1) {
        return Err("the controller's key does not say it supports messages");
    }
    let (raw, _) = ResourceList::parse(&found.raw).ok_or("the controller has no resources")?;
    let (translated, _) =
        ResourceList::parse(&found.translated).ok_or("the controller has no translated list")?;
    // Its ports and its registers stay where firmware put them, as on
    // Windows (0x6040 and 0x81010000 on the reference machine, whose
    // firmware had one device fewer to place).
    let (boot, _) =
        ResourceList::parse(&found.boot).ok_or("the controller has no boot configuration")?;
    let range = |list: &ResourceList, kind: u8| {
        list.partials()
            .find(|partial| partial.kind == kind)
            .and_then(|partial| partial.as_range())
    };
    for (kind, length) in [(TYPE_PORT, 0x20), (TYPE_MEMORY, 0x1000)] {
        let given = range(&raw, kind);
        if given.is_none_or(|(_, given)| given != length) || given != range(&boot, kind) {
            kprintln!(
                "stor: the controller was given {given:x?}; firmware had it at {:x?}",
                range(&boot, kind)
            );
            return Err("the controller is not where firmware put it");
        }
    }
    let interrupt = |list: &ResourceList| {
        let found: alloc::vec::Vec<_> = list
            .partials()
            .filter(|partial| partial.as_interrupt().is_some())
            .cloned()
            .collect();
        found
    };
    let (raw, translated) = (interrupt(&raw), interrupt(&translated));
    let ([raw], [translated]) = (&raw[..], &translated[..]) else {
        return Err("the controller does not have one interrupt");
    };
    // Raw: flags 3 (latched, message), the token, one message.
    if !raw.is_message() || raw.flags != 3 || raw.as_interrupt() != Some((0, 1, 0xFFFF_FFFE, 0)) {
        kprintln!("stor: the controller's raw interrupt is {raw:x?}");
        return Err("the controller's interrupt is not one message, as Windows gave it");
    }
    let Some((level, _, vector, affinity)) = translated.as_interrupt() else {
        return Err("the translated interrupt is not an interrupt");
    };
    if !translated.is_message()
        || crate::hal::interrupt::message(vector).is_none()
        || u32::from(level) != vector >> 4
        || affinity == 0
    {
        return Err("the translated interrupt is not a message vector the hardware layer gave out");
    }
    Ok(())
}

/// The first disk's device, as `disk.sys` names it; `\\??\\PhysicalDrive0`
/// is its link.
pub(super) const DISK: &str = "\\Device\\Harddisk0\\DR0";

/// Whether an object called `name` is in the namespace.
pub(super) fn exists(name: &str) -> bool {
    let wide: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    match ob::lookup(None, &wide) {
        Ok((_, rest)) => rest.is_empty(),
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
    r.check("stor.enumerate", enumerate);
    if !exists(DISK) {
        r.skip(
            "stor.io",
            format_args!("the disk device {DISK} does not exist yet"),
        );
        return;
    }
    match diskio::disk_io(DISK, diskio::Beyond::Skip) {
        Ok(counts) => r.ok_with("stor.io", format_args!("{counts}")),
        Err(why) => r.fail("stor.io", format_args!("{why}")),
    }
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
