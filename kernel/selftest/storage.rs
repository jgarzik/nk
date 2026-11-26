//! Microsoft's storage stack, unmodified, from Windows 10, on the
//! machine's AHCI controller: `acpi.sys`, `pci.sys` (with `pshed.dll`),
//! `storahci.sys` on `storport.sys`, `disk.sys` on `classpnp.sys`.
//!
//! The group runs alone (`test=stor.load`), on a machine that has the
//! disk: what it leaves running is the machine's device tree.

use crate::io::service;
use crate::ldr;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["stor.load"],
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

fn run(r: &mut Report, _: &BootInfo) {
    crate::test::keeps_what_it_started();
    if let Some(absent) = IMAGES.iter().find(|file| ldr::boot_file(file).is_none()) {
        r.skip("stor.load", format_args!("module {absent} not provided"));
        return;
    }
    r.check("stor.load", load);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
