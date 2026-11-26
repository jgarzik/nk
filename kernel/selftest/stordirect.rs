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
use nk_disk::answer::Adapter;
use nk_ntabi::io::DEVICE_OBJECT;
use nk_pnp::resources::{
    INTERRUPT_LATCHED, INTERRUPT_MESSAGE, MESSAGE_TOKEN, ResourceList, TYPE_INTERRUPT, TYPE_MEMORY,
    TYPE_PORT,
};

pub static GROUP: Group = Group {
    names: &[
        "stor.direct",
        "stor.direct.failed-start",
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

/// The disk's INQUIRY data as Storport records it in the device map on
/// the reference machine (`DISK-ORACLE.md` of the recorded trace).
const INQUIRY: [u8; 36] = [
    0x00, 0x00, 0x00, 0x02, 0x37, 0x00, 0x00, 0x02, 0x51, 0x45, 0x4D, 0x55, 0x20, 0x20, 0x20, 0x20,
    0x48, 0x41, 0x52, 0x44, 0x44, 0x49, 0x53, 0x4B, 0x00, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x32, 0x2E, 0x35, 0x2B,
];

/// What the reference machine's disk answers for its adapter
/// (`DISK-ORACLE.md`): 128 KiB a transfer over at most 33 pages,
/// buffers at even addresses, on a SATA bus.
const ADAPTER: Adapter = Adapter {
    maximum_transfer_length: 0x20000,
    maximum_physical_pages: 33,
    alignment_mask: 1,
    bus_type: BUS_TYPE_SATA,
};
const BUS_TYPE_SATA: u32 = 11;

/// How many interrupt vectors the hardware layer has given out.
fn vectors_given() -> usize {
    (0..1024)
        .filter(|vector| crate::hal::interrupt::info(*vector).is_some())
        .count()
}

/// A start of the controller that fails is undone: the bus's device
/// refuses the start request Storport passes down first, so
/// `storahci`'s start fails with the device's stack built and its
/// resources assigned. The manager then has the stack taken down and
/// takes back what it gave: the device is left failed with nothing on
/// it but the bus's device, no resources and no interrupt vector; and
/// when the controller leaves the bus the device goes. Done twice,
/// the second round leaves the kernel holding exactly what the first
/// left it holding. Returns the device's instance path.
fn failed_start(bus: &Bus) -> Result<String, &'static str> {
    let vectors = vectors_given();
    let mut held = [None; 2];
    let mut instance = String::new();
    for round in &mut held {
        bus.plug(true)?;
        pnp::settle();
        let pdo = bus.child() as usize;
        let found = node::get(pdo).ok_or("the controller has no device node")?;
        if found.state != State::Failed || found.problem != node::CM_PROB_FAILED_START {
            return Err("a controller that refuses its start is not left failed to start");
        }
        if !found.raw.is_empty() || !found.translated.is_empty() || !found.vectors.is_empty() {
            return Err("a controller that failed to start still holds resources");
        }
        if vectors_given() != vectors {
            return Err("a controller that failed to start still holds an interrupt vector");
        }
        if stack(pdo) != [format!("\\Driver\\{}", ahcibus::BUS)] {
            return Err("storahci's device is still on a controller that failed to start");
        }
        bus.unplug();
        pnp::settle();
        if !bus.child().is_null() || node::by_instance(&found.instance).is_some() {
            return Err("a controller that left the bus still has a device");
        }
        // The round's installation goes too: its key and its driver
        // key. Every round, and the start that follows, is then the
        // controller's first: installed from the driver database, and
        // asked for its requirements with its key written.
        let key = registry::enum_key(&found.instance);
        if let Some(driver) = registry::string(&key, "Driver") {
            let _ = crate::cm::delete_tree(&registry::class_key(&driver));
        }
        let _ = crate::cm::delete_tree(&key);
        instance = found.instance;
        *round = Some(super::resources());
    }
    if held[0] != held[1] {
        kprintln!("stor.direct: after one failed start {:?}", held[0]);
        kprintln!("stor.direct: after another     {:?}", held[1]);
        return Err("a failed start leaves something behind each time");
    }
    Ok(instance)
}

/// The names of the drivers on the stack of `pdo`, top first.
fn stack(pdo: usize) -> alloc::vec::Vec<String> {
    // SAFETY: a device the tree holds.
    unsafe { pnp::engine::stack_drivers(pdo as *mut DEVICE_OBJECT) }
}

/// The controller's device is started on the test's bus with
/// `storahci` as its driver, installed as Windows installs it, and was
/// given what the reference machine's controller has: its I/O ports,
/// the page of memory its sixth address register names, and one
/// interrupt, which is connected and has been served.
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
    // The one interrupt is a message, as on the reference machine: the
    // raw descriptor latched and message-signalled, one message, the
    // vector the token Windows puts there.
    let message = raw
        .partials()
        .find(|partial| partial.kind == TYPE_INTERRUPT)
        .filter(|partial| partial.flags == INTERRUPT_LATCHED | INTERRUPT_MESSAGE)
        .and_then(|partial| partial.as_interrupt());
    if !matches!(message, Some((_, 1, MESSAGE_TOKEN, _))) {
        return Err("the controller's interrupt is not one message, as Windows gives it");
    }
    // Storport connected the interrupt, and the controller has
    // interrupted: the disk was found by commands whose completion
    // the service routine saw and a DPC of Storport's reported.
    let (translated, _) = ResourceList::parse(&found.translated)
        .ok_or("the controller's resources are untranslated")?;
    let (_, _, vector, _) = translated
        .partials()
        .find(|partial| partial.kind == TYPE_INTERRUPT)
        .and_then(|partial| partial.as_interrupt())
        .ok_or("the controller's interrupt is untranslated")?;
    let (connected, calls) = crate::ke::kinterrupt::served(vector);
    if connected != 1 {
        return Err("storahci's is not the one service routine connected to the vector");
    }
    if calls == 0 {
        return Err("the controller's service routine was never called");
    }
    // The bus programmed the controller's message capability with the
    // address and data the hardware layer has for the vector, one
    // message, enabled: the interrupts counted above were messages.
    let to = crate::hal::interrupt::message(vector)
        .ok_or("the hardware layer has no message for the controller's vector")?;
    if ahcibus::message_programmed(bus.function()) != Some((true, 1, to.address, to.data as u16)) {
        return Err("the controller's message capability does not hold the vector's message");
    }
    Ok(format!(
        "{}: ports {ports:#x}, memory {memory:#x}, one message on vector {vector:#x}, served {calls} times",
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
    // What Storport and the class driver record of the port and the
    // unit, as the reference machine's registry has it.
    let port = "Machine\\Hardware\\DeviceMap\\Scsi\\Scsi Port 0";
    let unit = format!("{port}\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0");
    let inquiry = crate::cm::read(&unit, "InquiryData").map(|(_, data)| data);
    if registry::string(port, "Driver").as_deref() != Some("storahci")
        || registry::dword(port, "Dma64BitAddresses") != Some(1)
        || !crate::cm::exists(&format!("{port}\\Scsi Bus 0\\Initiator Id 255"))
        || registry::string(&unit, "Identifier").as_deref() != Some("QEMU    HARDDISK")
        || registry::string(&unit, "DeviceType").as_deref() != Some("DiskPeripheral")
        || inquiry.as_deref() != Ok(&INQUIRY[..])
    {
        return Err("the device map does not describe the port and the disk as Windows' does");
    }
    // The link user mode opens the disk by.
    if !storage::exists("\\GLOBAL??\\PhysicalDrive0") {
        return Err("disk.sys did not make the link PhysicalDrive0");
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
    match failed_start(&bus) {
        Ok(what) => r.ok_with(
            "stor.direct.failed-start",
            format_args!("{what}: twice refused, taken down and gone"),
        ),
        Err(why) => r.fail("stor.direct.failed-start", format_args!("{why}")),
    }
    // The controller comes back, and this time starts.
    if !bus.child().is_null() {
        bus.unplug();
        pnp::settle();
    }
    if let Err(why) = bus.plug(false) {
        r.fail("stor.direct", format_args!("{why}"));
        r.skip_rest(format_args!("the controller could not be put on the bus"));
        return;
    }
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
        let began = crate::ke::time::interrupt_time();
        let proof = diskio::disk_io(storage::DISK, diskio::Beyond::Skip);
        let took = (crate::ke::time::interrupt_time() - began) / 10_000;
        match proof {
            // The disk's own answers are the reference machine's.
            Ok(counts) if counts.bus_type != BUS_TYPE_SATA || counts.adapter != Some(ADAPTER) => {
                kprintln!(
                    "stor.direct: bus type {}, adapter {:?}",
                    counts.bus_type,
                    counts.adapter
                );
                r.fail(
                    "stor.direct.io",
                    format_args!("the disk's adapter is not as the reference machine's"),
                );
            }
            Ok(counts) => r.ok_with(
                "stor.direct.io",
                format_args!("{counts}; flushed; {took} ms"),
            ),
            Err(why) => r.fail("stor.direct.io", format_args!("{why}")),
        }
    } else {
        r.fail("stor.direct.io", format_args!("there is no disk device"));
    }
    // The stack stays, and the bus under it.
    core::mem::forget(bus);
}
