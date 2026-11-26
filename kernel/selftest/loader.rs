//! The loader must refuse images it cannot run, and say why; and it
//! must know which image an address is in.

use super::resources;
use crate::io::service;
use crate::ldr::{self, LoadError};
use crate::test::{Group, Report};
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::{DRIVER_OBJECT, DRIVER_UNLOAD};
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
        "ldr.import.kernel-names",
        "ldr.module.driver",
        "io.driver.unload-reentered",
    ],
    run,
    manual: false,
};

/// The kernel's own image is in the table, under Windows' name for it,
/// with the function table its frames are walked by.
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
    // The kernel's own frames are walked by its function table.
    if module.pdata.size == 0 {
        return Err("the kernel's image has no function table");
    }
    if u64::from(module.pdata.rva) + u64::from(module.pdata.size) > module.size {
        return Err("the kernel's function table lies outside its image");
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

/// The unload routine of the driver being unloaded, and whether the
/// other driver was stopped and started while it was.
static ITS_UNLOAD: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static RESTARTED: AtomicBool = AtomicBool::new(false);

/// What another thread may do while a driver's unload routine runs:
/// unload the driver loaded before it, and load it again. Then the
/// driver's own routine.
///
/// # Safety
/// Called as the unload routine of the driver whose routine is in
/// `ITS_UNLOAD`.
unsafe extern "C" fn unload_meanwhile(driver: *mut DRIVER_OBJECT) {
    RESTARTED.store(
        service::stop("SIoctl").is_ok() && service::start("SIoctl").is_ok(),
        Ordering::Release,
    );
    // SAFETY: per the contract: the routine the driver set for itself.
    unsafe {
        let unload: DRIVER_UNLOAD = core::mem::transmute(ITS_UNLOAD.load(Ordering::Acquire));
        unload(driver);
    }
}

/// A driver's unload routine runs with no lock held, so other drivers
/// are loaded and unloaded meanwhile and the table of drivers changes.
/// The unload then removes its own driver's record and frees its own
/// driver's image, wherever the record has got to.
fn unload_reentered() -> Result<(), &'static str> {
    service::create("SIoctl", "sioctl.sys").map_err(|_| "no service key")?;
    service::create("cancel", "cancel.sys").map_err(|_| "no service key")?;
    service::start("SIoctl").map_err(|_| "load failed")?;
    let Ok(second) = service::start("cancel") else {
        service::stop("SIoctl")?;
        return Err("load failed");
    };
    RESTARTED.store(false, Ordering::Release);
    // SAFETY: a running driver's object; the field is the driver's to
    // set, and it set it in its entry point.
    unsafe {
        let Some(unload) = (&raw const (*second).DriverUnload).read() else {
            return Err("the driver has no unload routine");
        };
        ITS_UNLOAD.store(unload as *mut (), Ordering::Release);
        (&raw mut (*second).DriverUnload).write(Some(unload_meanwhile));
    }
    let stopped = service::stop("cancel");
    if !RESTARTED.load(Ordering::Acquire) {
        return Err("another driver could not be unloaded and loaded during an unload routine");
    }
    if service::running("cancel") || !service::running("SIoctl") {
        return Err("unloading a driver took another driver's record and left its own");
    }
    stopped?;
    service::stop("SIoctl")
}

/// The names an import from the kernel may go by, and the one routine
/// imported by number.
fn kernel_names() -> Result<(), &'static str> {
    use crate::export::{resolve, resolve_ordinal};
    let routine = resolve(b"ntoskrnl.exe", b"KeSetEvent");
    if routine.is_none() || resolve(b"HAL.dll", b"KeSetEvent") != routine {
        return Err("the kernel and the HAL are not one table");
    }
    let persisted = resolve(b"ntoskrnl.exe", b"KsrQueryMetadata");
    if persisted.is_none()
        || resolve(b"ext-ms-win-ntos-ksr-l1-1-3.dll", b"KsrQueryMetadata") != persisted
        || resolve(b"EXT-MS-WIN-NTOS-KSR-L1-1-1.DLL", b"KsrQueryMetadata") != persisted
    {
        return Err("an import from the API set NK hosts was not bound to the kernel's routine");
    }
    if resolve(b"ext-ms-win-ntos-other-l1-1-0.dll", b"KeSetEvent").is_some()
        || resolve(b"nosuch.sys", b"KeSetEvent").is_some()
    {
        return Err("a module that is not the kernel resolved to the kernel's table");
    }
    let by_number = resolve_ordinal(b"ntoskrnl.exe", 4);
    if by_number.is_none() || by_number != resolve(b"ntoskrnl.exe", b"ExAllocateTimerInternal2") {
        return Err("the routine imported by number was not bound to its export");
    }
    if resolve_ordinal(b"ntoskrnl.exe", 5).is_some() || resolve_ordinal(b"nosuch.sys", 4).is_some()
    {
        return Err("a number NK does not know, or another module's, was bound");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("ldr.module.kernel", kernel_module);
    r.check("ldr.import.kernel-names", kernel_names);
    if ldr::boot_file("sioctl.sys").is_some() && ldr::boot_file("cancel.sys").is_some() {
        r.check("io.driver.unload-reentered", unload_reentered);
    } else {
        r.skip(
            "io.driver.unload-reentered",
            format_args!("modules sioctl.sys and cancel.sys not provided"),
        );
    }
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

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
