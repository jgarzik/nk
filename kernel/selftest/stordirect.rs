//! Microsoft's storage stack on the machine's AHCI controller, with
//! the controller enumerated by a bus driver of the test's own
//! (`ahcibus.rs`) in place of `pci.sys`: `storahci.sys` on
//! `storport.sys` on the controller, and `disk.sys` on `classpnp.sys`
//! on the disk Storport finds.
//!
//! The group runs alone (`test=stor.direct`), on a machine that has
//! the controller; what it leaves running is the stack. It exists
//! beside the real path (`storage.rs`), never with it: if the device
//! tree already has the controller, because `pci.sys` enumerated it,
//! the tests are skipped saying so (`doc/TESTING.md`).

use super::ahcibus::{self, Bus};
use super::{diskio, storage};
use crate::ldr;
use crate::pnp::node::{self, Node, State};
use crate::pnp::{self, registry};
use crate::test::{Group, Report};
use alloc::format;
use alloc::string::String;
use nk_bootinfo::BootInfo;
use nk_ntabi::io::DEVICE_OBJECT;
use nk_pnp::resources::{ResourceList, TYPE_INTERRUPT, TYPE_MEMORY, TYPE_PORT};

pub static GROUP: Group = Group {
    names: &[
        "stor.direct",
        "stor.direct.controller",
        "stor.direct.disk",
        "stor.direct.io",
    ],
    run,
    manual: true,
};

pub static GROUPS: &[&Group] = &[&GROUP];

/// The images of the stack above the bus.
const IMAGES: [&str; 4] = ["storport.sys", "storahci.sys", "classpnp.sys", "disk.sys"];

/// The classes Windows has the two devices in: `HDC` and `DiskDrive`.
const HDC: &str = "{4d36e96a-e325-11ce-bfc1-08002be10318}";
const DISK_DRIVE: &str = "{4d36e967-e325-11ce-bfc1-08002be10318}";

/// The disk's identifiers on the reference Windows (`TREE.md` of the
/// recorded trace): Storport makes them of the disk's INQUIRY data.
const DISK_DEVICE_ID: &str = "SCSI\\Disk&Ven_QEMU&Prod_HARDDISK";
const DISK_HARDWARE_IDS: [&str; 6] = [
    "SCSI\\DiskQEMU____________HARDDISK2.5+",
    "SCSI\\DiskQEMU____________HARDDISK",
    "SCSI\\DiskQEMU____",
    "SCSI\\QEMU____________HARDDISK2",
    "QEMU____________HARDDISK2",
    "GenDisk",
];
const DISK_COMPATIBLE_IDS: [&str; 2] = ["SCSI\\Disk", "SCSI\\RAW"];

/// The names of the drivers on the stack of `pdo`, top first.
fn stack(pdo: usize) -> alloc::vec::Vec<String> {
    // SAFETY: a device the tree holds.
    unsafe { pnp::engine::stack_drivers(pdo as *mut DEVICE_OBJECT) }
}

/// The controller's device is started on the test's bus with
/// `storahci` as its driver, installed as Windows installs it, and was
/// given what the reference machine's controller has: its I/O ports,
/// the page of memory its sixth address register names, and one
/// interrupt.
fn controller(bus: &Bus) -> Result<String, &'static str> {
    let found = node::get(bus.child() as usize).ok_or("the controller has no device node")?;
    if found.state != State::Started {
        kprintln!(
            "stor.direct: {} is {:?}, problem {}",
            found.instance,
            found.state,
            found.problem
        );
        return Err("the controller's device is not started");
    }
    let key = registry::enum_key(&found.instance);
    if registry::string(&key, "Service").as_deref() != Some("storahci")
        || registry::string(&key, "ClassGUID").as_deref() != Some(HDC)
    {
        return Err("the controller is not installed with Windows' service and class");
    }
    if stack(found.pdo) != ["\\Driver\\storahci", &format!("\\Driver\\{}", ahcibus::BUS)] {
        return Err("the controller's stack is not storahci on the bus's device");
    }
    let (raw, _) = ResourceList::parse(&found.raw).ok_or("the controller was given nothing")?;
    let range = |kind: u8| {
        raw.partials()
            .find(|partial| partial.kind == kind)
            .and_then(|partial| partial.as_range())
    };
    let (Some((ports, 0x20)), Some((memory, 0x1000))) = (range(TYPE_PORT), range(TYPE_MEMORY))
    else {
        return Err("the controller was not given 0x20 ports and a page of memory");
    };
    let mut abar = [0u8; 4];
    crate::hal::pci::read(bus.function(), 0x24, &mut abar);
    if u64::from(u32::from_le_bytes(abar)) != memory {
        return Err("the controller's sixth address register does not hold the memory given");
    }
    let interrupts = raw
        .partials()
        .filter(|partial| partial.kind == TYPE_INTERRUPT)
        .count();
    if interrupts != 1 {
        return Err("the controller was not given one interrupt");
    }
    Ok(format!(
        "{}: ports {ports:#x}, memory {memory:#x}",
        found.instance
    ))
}

/// The disk Storport found on the controller is where Windows has it,
/// with Windows' identifiers, and `disk.sys` started on it and made
/// its device.
fn disk(bus: &Bus) -> Result<String, &'static str> {
    let above = node::get(bus.child() as usize).ok_or("the controller has no device node")?;
    let disks: alloc::vec::Vec<Node> = above
        .children
        .iter()
        .filter_map(|pdo| node::get(*pdo))
        .collect();
    let [found] = &disks[..] else {
        return Err("the controller does not have exactly one child");
    };
    // The instance: bus 0, target 0, unit 0 behind the controller's
    // prefix, as on Windows.
    let prefix = above
        .child_prefix
        .ok_or("the controller has no prefix for its children")?;
    if found.instance != format!("{DISK_DEVICE_ID}\\{prefix}&000000") {
        kprintln!("stor.direct: the disk is {}", found.instance);
        return Err("the disk's instance path is not the one Windows gives it");
    }
    if found.hardware_ids != DISK_HARDWARE_IDS || found.compatible_ids != DISK_COMPATIBLE_IDS {
        return Err("the disk does not have Windows' identifiers");
    }
    let key = registry::enum_key(&found.instance);
    if registry::string(&key, "Service").as_deref() != Some("disk")
        || registry::string(&key, "ClassGUID").as_deref() != Some(DISK_DRIVE)
    {
        return Err("the disk is not installed with Windows' service and class");
    }
    if found.state != State::Started {
        kprintln!(
            "stor.direct: {} is {:?}, problem {}",
            found.instance,
            found.state,
            found.problem
        );
        return Err("the disk's device is not started");
    }
    if stack(found.pdo) != ["\\Driver\\disk", "\\Driver\\storahci"] {
        return Err("the disk's stack is not disk on storahci");
    }
    if !storage::exists(storage::DISK) {
        return Err("disk.sys did not make \\Device\\Harddisk0\\DR0");
    }
    Ok(found.instance.clone())
}

fn run(r: &mut Report, _: &BootInfo) {
    crate::test::keeps_what_it_started();
    let Some(function) = ahcibus::find() else {
        r.skip_rest(format_args!("no AHCI controller on this machine"));
        return;
    };
    if let Some(absent) = IMAGES.iter().find(|file| ldr::boot_file(file).is_none()) {
        r.skip_rest(format_args!("module {absent} not provided"));
        return;
    }
    // The real bus driver's device for the controller, if it made one,
    // is the controller's: this test then has nothing to enumerate.
    let prefix = format!("{}\\", ahcibus::device_id(function));
    let taken = node::all().into_iter().any(|pdo| {
        node::with(pdo, |found| {
            found.instance.len() > prefix.len()
                && found.instance[..prefix.len()].eq_ignore_ascii_case(&prefix)
        }) == Some(true)
    });
    if taken {
        r.skip_rest(format_args!(
            "the machine's own bus driver enumerated the controller"
        ));
        return;
    }
    let bus = match Bus::new(function) {
        Ok(bus) => bus,
        Err(why) => {
            r.fail("stor.direct", format_args!("{why}"));
            r.skip_rest(format_args!("the test's bus could not be made"));
            return;
        }
    };
    pnp::settle();
    r.ok_with(
        "stor.direct",
        format_args!(
            "the controller at 00:{:02x}.{} is {}",
            function.device,
            function.function,
            ahcibus::device_id(function)
        ),
    );
    match controller(&bus) {
        Ok(what) => r.ok_with("stor.direct.controller", format_args!("{what}")),
        Err(why) => r.fail("stor.direct.controller", format_args!("{why}")),
    }
    match disk(&bus) {
        Ok(what) => r.ok_with("stor.direct.disk", format_args!("{what}")),
        Err(why) => r.fail("stor.direct.disk", format_args!("{why}")),
    }
    if storage::exists(storage::DISK) {
        match diskio::disk_io(storage::DISK) {
            Ok(counts) => r.ok_with("stor.direct.io", format_args!("{counts}")),
            Err(why) => r.fail("stor.direct.io", format_args!("{why}")),
        }
    } else {
        r.fail("stor.direct.io", format_args!("there is no disk device"));
    }
    // The stack stays, and the bus under it.
    core::mem::forget(bus);
}
