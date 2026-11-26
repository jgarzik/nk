//! Microsoft's export drivers, unmodified, from Windows 10: libraries
//! other drivers import from. Each is loaded the way an importer's
//! load brings it in: mapped, bound to NK's exports, its
//! `DllInitialize` called; then given up again, which calls its
//! `DllUnload` and unloads it. Every name it asks for with
//! `MmGetSystemRoutineAddress` must be there, or it would take a path
//! it does not take on Windows.

use super::resources;
use crate::export;
use crate::ldr::{self, TestImporter};
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["ms.wpprecorder"],
    run,
    manual: false,
};

/// Load `file` as a library and unload it again.
fn library(file: &str) -> Result<(), &'static str> {
    let before = resources();
    let absent = export::absent_lookups();
    let importer = TestImporter::of(file)
        .map_err(|_| "the library did not load, or its DllInitialize failed")?;
    if ldr::module_named(file).is_none() {
        return Err("the library is not among the loaded images");
    }
    if export::absent_lookups() != absent {
        return Err("the library asked by name for a routine NK does not export");
    }
    drop(importer);
    if ldr::module_named(file).is_some() {
        return Err("the library stayed loaded: it has no DllUnload, or its DllUnload failed");
    }
    if resources() != before {
        return Err("loading and unloading the library left something behind");
    }
    Ok(())
}

/// Report on the library in `file`, if it is among the boot files.
fn report(r: &mut Report, name: &str, file: &str) {
    if ldr::boot_file(file).is_none() {
        r.skip(name, format_args!("module {file} not provided"));
    } else {
        r.check(name, || library(file));
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    report(r, "ms.wpprecorder", "wpprecorder.sys");
}
