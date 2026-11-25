//! The loader must refuse images it cannot run, and say why; and it
//! must know which image an address is in.

use super::resources;
use crate::io::service;
use crate::ldr::{self, LoadError};
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_pe::PeError;

/// Load `file`, expecting a refusal that `expected` recognises, and
/// expecting the failed load to give back everything it allocated.
fn expect_refusal(
    r: &mut Report,
    name: &str,
    module_name: &str,
    expected: impl FnOnce(&LoadError) -> bool,
) {
    let Some(file) = ldr::boot_file(module_name) else {
        return r.skip(name, format_args!("module {module_name} not provided"));
    };
    let before = resources();
    let result = ldr::load(module_name, file);
    let verdict = match &result {
        Err(e) if expected(e) => Ok(()),
        Err(e) => {
            kprintln!("ldr: {module_name}: {e:?}");
            Err("rejected for the wrong reason")
        }
        Ok(_) => Err("the image was loaded"),
    };
    // The error owns strings from the pool: release it before counting.
    drop(result);
    match verdict {
        Ok(()) if resources() != before => {
            r.fail(name, format_args!("rejected, but leaked memory"))
        }
        Ok(()) => r.ok(name),
        Err(why) => r.fail(name, format_args!("{why}")),
    }
}

pub static GROUP: Group = Group {
    names: &[
        "ldr.reject.wrong-machine",
        "ldr.reject.unresolved-import",
        "ldr.module.kernel",
        "ldr.module.driver",
    ],
    run,
    manual: false,
};

/// The kernel's own image is in the table, under Windows' name for it.
fn kernel_module() -> Result<(), &'static str> {
    let here = kernel_module as *const () as u64;
    let module = ldr::module_containing(here).ok_or("the kernel's code is in no image")?;
    if module.name() != b"ntoskrnl.exe" {
        return Err("the kernel's image is not called ntoskrnl.exe");
    }
    if module.base != nk_bootinfo::KERNEL_BASE {
        return Err("the kernel's image is not at the kernel's base");
    }
    if ldr::module_containing(module.base + module.size).is_some_and(|m| m.base == module.base) {
        return Err("the kernel's image reaches past its end");
    }
    Ok(())
}

/// A driver's image is in the table, by its file name, exactly while
/// the driver is loaded.
fn driver_module() -> Result<(), &'static str> {
    service::create("SIoctl", "sioctl.sys").map_err(|_| "no service key")?;
    let object = service::start("SIoctl").map_err(|_| "load failed")?;
    // SAFETY: a driver object the kernel just made; these two fields
    // are written once, before the driver's entry point runs.
    let (start, size) = unsafe {
        (
            (&raw const (*object).DriverStart).read() as u64,
            u64::from((&raw const (*object).DriverSize).read()),
        )
    };
    let verdict = match ldr::module_containing(start + size - 1) {
        Some(m) if m.name() != b"sioctl.sys" => Err("the image has another name"),
        Some(m) if (m.base, m.size) != (start, size) => Err("the image has another range"),
        Some(_) => Ok(()),
        None => Err("the driver's code is in no image"),
    };
    service::stop("SIoctl")?;
    verdict?;
    if ldr::module_containing(start).is_some() {
        return Err("the image is still listed after its driver was unloaded");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("ldr.module.kernel", kernel_module);
    if ldr::boot_file("sioctl.sys").is_some() {
        r.check("ldr.module.driver", driver_module);
    } else {
        r.skip(
            "ldr.module.driver",
            format_args!("module sioctl.sys not provided"),
        );
    }
    // A real driver built for the other architecture.
    expect_refusal(
        r,
        "ldr.reject.wrong-machine",
        "wrongarch.sys",
        |e| match e {
            LoadError::Pe(PeError::WrongMachine(m)) => {
                kprintln!("ldr: refused image for machine {m:#06x}");
                true
            }
            _ => false,
        },
    );
    // A real driver that needs a module the kernel does not provide: the
    // KMDF sample imports the framework loader.
    expect_refusal(
        r,
        "ldr.reject.unresolved-import",
        "unresolved.sys",
        |e| match e {
            LoadError::Unresolved { module, symbol } => {
                kprintln!("ldr: refused image, unresolved import {module}!{symbol}");
                true
            }
            _ => false,
        },
    );
}
