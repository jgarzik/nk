//! Microsoft's storage stack, unmodified, from Windows 10, on the
//! machine's AHCI controller: `acpi.sys`, `pci.sys` (with `pshed.dll`),
//! `storahci.sys` on `storport.sys`, `disk.sys` on `classpnp.sys`.
//!
//! The group runs alone (`test=stor.load`), on a machine that has the
//! disk: what it leaves running is the machine's device tree.

use crate::ldr::{self, TestImporter};
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["stor.load"],
    run,
    manual: true,
};

/// The libraries of the stack, in the order their importers need them.
const LIBRARIES: [&str; 2] = ["pshed.dll", "classpnp.sys"];

/// Every library of the stack binds to NK's exports and initialises.
fn load() -> Result<(), &'static str> {
    for file in LIBRARIES {
        let importer = TestImporter::of(file)
            .map_err(|_| "a library did not load, or its DllInitialize failed")?;
        // The stack stays loaded: the machine's devices are its.
        core::mem::forget(importer);
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    crate::test::keeps_what_it_started();
    if let Some(absent) = LIBRARIES.iter().find(|file| ldr::boot_file(file).is_none()) {
        r.skip("stor.load", format_args!("module {absent} not provided"));
        return;
    }
    r.check("stor.load", load);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
