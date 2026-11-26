//! The drivers that start at boot: the order the registry gives, and
//! what became of each before the tests began.

use crate::io::service;
use crate::test::{Group, Report};
use crate::{cm, ldr};
use alloc::string::String;
use core::fmt::Write;
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &["io.service.boot-start"],
    run,
    manual: false,
};

/// The fixture hive's boot-start drivers, in the order of their groups
/// in its `ServiceGroupOrder`: `Base`, then `File System`.
const FIXTURE_ORDER: [&str; 2] = ["Null", "Npfs"];

/// Each boot-start service whose image is among the boot files is
/// running, and each whose image is not was passed over. Returns what
/// became of each, in order.
fn boot_start() -> Result<String, &'static str> {
    let services = cm::boot_start()?;
    if !services.iter().map(|(name, _)| &name[..]).eq(FIXTURE_ORDER) {
        return Err("the hive's boot-start services are not Null, then Npfs");
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

fn run(r: &mut Report, _: &BootInfo) {
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
