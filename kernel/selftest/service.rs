//! The drivers that start at boot: the order the registry gives, and
//! what became of each before the tests began. And the image of a
//! service whose key does not name one. And a driver starting a
//! service by its key (`ZwLoadDriver`).

use super::resources;
use crate::io::{device, driver, irp, service};
use crate::ke::{thread, time};
use crate::test::{Group, Report};
use crate::{cm, ldr};
use alloc::string::String;
use core::ffi::c_void;
use core::fmt::Write;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &[
        "io.service.boot-start",
        "io.service.default-image",
        "io.service.zw-load-missing",
        "io.service.zw-load",
    ],
    run,
    manual: false,
};

/// The fixture hive's boot-start drivers, in the order of their groups
/// in its `ServiceGroupOrder`: `Base`, then `File System`, which the
/// drivers' keys spell `File system`. That group has no tag list, so
/// Msfs comes before Npfs as their keys do.
const FIXTURE_ORDER: [&str; 3] = ["Null", "Msfs", "Npfs"];

/// Each boot-start service whose image is among the boot files is
/// running, and each whose image is not was passed over. Returns what
/// became of each, in order.
fn boot_start() -> Result<String, &'static str> {
    let services = cm::boot_start()?;
    if !services.iter().map(|(name, _)| &name[..]).eq(FIXTURE_ORDER) {
        return Err("the hive's boot-start services are not Null, then the file systems");
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

/// A service of this name has no key until a test makes one, and a
/// boot file `<name>.sys` on both architectures.
const PLAIN: &str = "nkc-irql";

/// A key without `ImagePath`, as Windows' own service keys are: the
/// image is `<name>.sys`, and the driver starts from it.
fn default_image() -> Result<(), &'static str> {
    // `SERVICE_KERNEL_DRIVER`, `SERVICE_DEMAND_START`, as numbers.
    let values: [(&str, u32, &[u8]); 2] = [
        ("Type", 4, &1u32.to_le_bytes()),
        ("Start", 4, &3u32.to_le_bytes()),
    ];
    let key = alloc::format!("Machine\\System\\CurrentControlSet\\Services\\{PLAIN}");
    cm::write(&key, &values).map_err(|_| "the key could not be made")?;
    if service::image(PLAIN).ok().as_deref() != Some("nkc-irql.sys") {
        return Err("a key without ImagePath does not mean <name>.sys");
    }
    let before = resources();
    service::start(PLAIN).map_err(|_| "the service did not start from its default image")?;
    let ran = service::running(PLAIN);
    service::stop(PLAIN)?;
    if !ran {
        return Err("the service started and is not running");
    }
    if resources() != before {
        return Err("starting and stopping the service left something behind");
    }
    Ok(())
}

/// `ZwLoadDriver` for the key `path`.
fn zw_load(path: &str) -> NTSTATUS {
    let mut text: alloc::vec::Vec<u16> = path.encode_utf16().collect();
    let name = UNICODE_STRING {
        Length: (text.len() * 2) as u16,
        MaximumLength: (text.len() * 2) as u16,
        Buffer: text.as_mut_ptr(),
    };
    // SAFETY: a counted string over a local.
    unsafe { service::ZwLoadDriver(&raw const name) }
}

/// A service key that is not there, as `acpi.sys` asks for `acpiex`:
/// the status of opening the key.
fn zw_load_missing() -> Result<(), &'static str> {
    let missing = [
        (
            "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\acpiex",
            STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        (
            "\\REGISTRY\\MACHINE\\SYSTEM\\CURRENTCONTROLSET\\SERVICES\\NkNone",
            STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        (
            "\\Registry\\Machine\\NkNone\\Services\\x",
            STATUS_OBJECT_NAME_NOT_FOUND,
        ),
        ("\\NkNoDirectory\\x", STATUS_OBJECT_PATH_NOT_FOUND),
        ("\\Device", STATUS_OBJECT_TYPE_MISMATCH),
        ("acpiex", STATUS_OBJECT_PATH_SYNTAX_BAD),
        ("", STATUS_OBJECT_PATH_SYNTAX_BAD),
    ];
    for (path, expected) in missing {
        if zw_load(path) != expected {
            return Err("a service key that is not there was not reported as the open reports it");
        }
    }
    Ok(())
}

/// A driver starts a service by its key, in any letter case; a second
/// start says the image is loaded already.
fn zw_load_starts() -> Result<(), &'static str> {
    service::create(PLAIN, "nkc-irql.sys").map_err(|_| "the key could not be made")?;
    let path = alloc::format!("\\registry\\MACHINE\\System\\CurrentControlSet\\Services\\{PLAIN}");
    let before = resources();
    if zw_load(&path) != STATUS_SUCCESS {
        return Err("ZwLoadDriver did not start the service");
    }
    let ran = service::running(PLAIN);
    let again = zw_load(&path);
    service::stop(PLAIN)?;
    if !ran || again != STATUS_IMAGE_ALREADY_LOADED {
        return Err("the driver is not running, or was started twice");
    }
    if resources() != before {
        return Err("starting and stopping the service left something behind");
    }

    // Regression test #8: IoOpenDriverRegistryKey must succeed during
    // DriverEntry (`ready == false`) while `service::running` stays false.
    {
        let before_init = resources();
        let opened = driver::with_initializing_driver(PLAIN, |drv| {
            let not_ready = !service::running(PLAIN);
            let mut key_handle: *mut c_void = core::ptr::null_mut();
            // SAFETY: `drv` is a live initializing driver object; `key_handle` is writable.
            let st = unsafe {
                driver::IoOpenDriverRegistryKey(drv, 0, 0x000F_003F, 0, &raw mut key_handle)
            };
            if st == STATUS_SUCCESS && !key_handle.is_null() {
                let _ = crate::ob::handle::close(key_handle as u64);
            }
            not_ready && st == STATUS_SUCCESS && !key_handle.is_null()
        })
        .map_err(|_| "could not create initializing driver for IoOpenDriverRegistryKey test")?;
        let _ = cm::delete_tree(&alloc::format!(
            "Machine\\System\\CurrentControlSet\\Services\\{PLAIN}\\Parameters"
        ));
        if !opened {
            return Err("IoOpenDriverRegistryKey failed during DriverEntry initialization");
        }
        let after_init = resources();
        if after_init != before_init {
            kprintln!("service: init leak before={before_init:?} after={after_init:?}");
            return Err("IoOpenDriverRegistryKey DriverEntry test leaked resources");
        }
    }

    // Regression test #3: duplicate ZwUnloadDriver and concurrent import
    // binding must both be refused once unload is claimed.
    {
        static REAL_UNLOAD: AtomicUsize = AtomicUsize::new(0);
        static IN_UNLOAD: AtomicBool = AtomicBool::new(false);
        static RELEASE_UNLOAD: AtomicBool = AtomicBool::new(false);
        static UNLOAD_CALLS: AtomicU32 = AtomicU32::new(0);
        static FIRST_DONE: AtomicBool = AtomicBool::new(false);
        static FIRST_STATUS: AtomicI32 = AtomicI32::new(-1);

        /// # Safety
        /// Called as `DriverUnload` for the wrapped driver.
        unsafe extern "C" fn paused_unload(drv: *mut DRIVER_OBJECT) {
            UNLOAD_CALLS.fetch_add(1, Ordering::AcqRel);
            IN_UNLOAD.store(true, Ordering::Release);
            while !RELEASE_UNLOAD.load(Ordering::Acquire) {
                thread::yield_now();
            }
            let real = REAL_UNLOAD.load(Ordering::Acquire);
            if real != 0 {
                // SAFETY: original `DriverUnload` of `nkc-irql.sys`.
                let f: DRIVER_UNLOAD = unsafe { core::mem::transmute(real) };
                // SAFETY: per the contract.
                unsafe { f(drv) };
            }
        }
        fn unload_worker(_: usize) {
            let p =
                alloc::format!("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\{PLAIN}");
            let mut text: alloc::vec::Vec<u16> = p.encode_utf16().collect();
            let name = UNICODE_STRING {
                Length: (text.len() * 2) as u16,
                MaximumLength: (text.len() * 2) as u16,
                Buffer: text.as_mut_ptr(),
            };
            // SAFETY: counted string over local buffer.
            let st = unsafe { service::ZwUnloadDriver(&raw const name) };
            FIRST_STATUS.store(st, Ordering::Release);
            FIRST_DONE.store(true, Ordering::Release);
        }

        let before_race = resources();
        if zw_load(&path) != STATUS_SUCCESS {
            return Err("ZwLoadDriver failed for unload-race test");
        }
        let drv = driver::running(PLAIN).ok_or("loaded driver not found for unload-race test")?;
        // SAFETY: `drv` is a live driver object owned by this test.
        let orig = unsafe { (*drv).DriverUnload }.ok_or("nkc-irql has no DriverUnload")?;
        REAL_UNLOAD.store(orig as usize, Ordering::Release);
        IN_UNLOAD.store(false, Ordering::Release);
        RELEASE_UNLOAD.store(false, Ordering::Release);
        UNLOAD_CALLS.store(0, Ordering::Release);
        FIRST_DONE.store(false, Ordering::Release);
        FIRST_STATUS.store(-1, Ordering::Release);
        // SAFETY: temporarily wrap `DriverUnload` to hold the unload window open.
        unsafe { (*drv).DriverUnload = Some(paused_unload) };

        let threads_before = thread::count();
        thread::create(unload_worker, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)
            .map_err(|_| "could not spawn unload worker thread")?;
        while !IN_UNLOAD.load(Ordering::Acquire) {
            thread::yield_now();
        }
        // Duplicate ZwUnloadDriver must fail without re-entering DriverUnload.
        let dup_status = {
            let mut text: alloc::vec::Vec<u16> = path.encode_utf16().collect();
            let name = UNICODE_STRING {
                Length: (text.len() * 2) as u16,
                MaximumLength: (text.len() * 2) as u16,
                Buffer: text.as_mut_ptr(),
            };
            // SAFETY: counted string over local buffer.
            unsafe { service::ZwUnloadDriver(&raw const name) }
        };
        // Concurrent importer binding must be refused while unloading is claimed.
        let bind_refused = ldr::TestImporter::of("nkc-irql.sys").is_err();
        let marked_unloading = ldr::module_named("nkc-irql.sys").is_some_and(|m| m.unloading);

        RELEASE_UNLOAD.store(true, Ordering::Release);
        while !FIRST_DONE.load(Ordering::Acquire) {
            thread::yield_now();
        }
        thread::settle(threads_before);
        if FIRST_STATUS.load(Ordering::Acquire) != STATUS_SUCCESS {
            return Err("first ZwUnloadDriver did not succeed");
        }
        if dup_status == STATUS_SUCCESS || UNLOAD_CALLS.load(Ordering::Acquire) != 1 {
            return Err("duplicate ZwUnloadDriver was not refused or ran DriverUnload twice");
        }
        if !marked_unloading || !bind_refused {
            return Err("import binding was not refused while driver unload was claimed");
        }
        let after_race = resources();
        if after_race != before_race {
            kprintln!("service: race leak before={before_race:?} after={after_race:?}");
            return Err("unload-race test left resources behind");
        }
    }

    // Regression test #4: IoSetCompletionRoutineEx must pin the driver image
    // across DriverUnload until trampolines finish (both invoked and suppressed).
    {
        static EX_REAL_UNLOAD: AtomicUsize = AtomicUsize::new(0);
        static EX_UNLOAD_RETURNED: AtomicBool = AtomicBool::new(false);
        static EX_STOP_DONE: AtomicBool = AtomicBool::new(false);
        static EX_STOP_OK: AtomicBool = AtomicBool::new(false);
        static EX_CB_INVOKED: AtomicU32 = AtomicU32::new(0);
        static EX_CB_SUPPRESSED: AtomicU32 = AtomicU32::new(0);
        static EX_IMAGE_LIVE_IN_CB: AtomicBool = AtomicBool::new(false);

        /// # Safety
        /// Called as `DriverUnload` wrapper.
        unsafe extern "C" fn track_unload(drv: *mut DRIVER_OBJECT) {
            let real = EX_REAL_UNLOAD.load(Ordering::Acquire);
            if real != 0 {
                // SAFETY: original `DriverUnload`.
                let f: DRIVER_UNLOAD = unsafe { core::mem::transmute(real) };
                // SAFETY: per the contract.
                unsafe { f(drv) };
            }
            EX_UNLOAD_RETURNED.store(true, Ordering::Release);
        }
        /// # Safety
        /// Called by `IoSetCompletionRoutineEx` trampoline.
        unsafe extern "C" fn cb_invoked(
            _: *mut DEVICE_OBJECT,
            _: *mut IRP,
            _: *mut c_void,
        ) -> NTSTATUS {
            EX_IMAGE_LIVE_IN_CB.store(
                ldr::module_named("nkc-irql.sys").is_some(),
                Ordering::Release,
            );
            EX_CB_INVOKED.fetch_add(1, Ordering::AcqRel);
            STATUS_SUCCESS
        }
        /// # Safety
        /// Must never be called (all invoke flags are 0).
        unsafe extern "C" fn cb_suppressed(
            _: *mut DEVICE_OBJECT,
            _: *mut IRP,
            _: *mut c_void,
        ) -> NTSTATUS {
            EX_CB_SUPPRESSED.fetch_add(1, Ordering::AcqRel);
            STATUS_SUCCESS
        }
        fn stop_worker(_: usize) {
            EX_STOP_OK.store(service::stop(PLAIN).is_ok(), Ordering::Release);
            EX_STOP_DONE.store(true, Ordering::Release);
        }

        let before_ex = resources();
        if zw_load(&path) != STATUS_SUCCESS {
            return Err("ZwLoadDriver failed for completion-pin test");
        }
        let drv =
            driver::running(PLAIN).ok_or("loaded driver not found for completion-pin test")?;
        // SAFETY: live driver object.
        let orig = unsafe { (*drv).DriverUnload }.ok_or("nkc-irql has no DriverUnload")?;
        EX_REAL_UNLOAD.store(orig as usize, Ordering::Release);
        EX_UNLOAD_RETURNED.store(false, Ordering::Release);
        EX_STOP_DONE.store(false, Ordering::Release);
        EX_STOP_OK.store(false, Ordering::Release);
        EX_CB_INVOKED.store(0, Ordering::Release);
        EX_CB_SUPPRESSED.store(0, Ordering::Release);
        EX_IMAGE_LIVE_IN_CB.store(false, Ordering::Release);
        // SAFETY: wrap `DriverUnload` to observe when it returns.
        unsafe { (*drv).DriverUnload = Some(track_unload) };

        let mut dev: *mut DEVICE_OBJECT = core::ptr::null_mut();
        // SAFETY: live driver object, output pointer writable.
        if unsafe { device::IoCreateDevice(drv, 0, core::ptr::null(), 0x22, 0, 0, &raw mut dev) }
            != STATUS_SUCCESS
        {
            let _ = service::stop(PLAIN);
            return Err("could not create temporary device for completion-pin test");
        }
        let irp_a = irp::IoAllocateIrp(2, 0);
        let irp_b = irp::IoAllocateIrp(2, 0);
        if irp_a.is_null() || irp_b.is_null() {
            if !irp_a.is_null() {
                // SAFETY: fresh IRP.
                unsafe { irp::IoFreeIrp(irp_a) };
            }
            if !irp_b.is_null() {
                // SAFETY: fresh IRP.
                unsafe { irp::IoFreeIrp(irp_b) };
            }
            // SAFETY: temporary device.
            unsafe { device::IoDeleteDevice(dev) };
            let _ = service::stop(PLAIN);
            return Err("could not allocate IRPs for completion-pin test");
        }
        // SAFETY: `dev` and IRPs are live with 2 stack locations.
        let (sa, sb) = unsafe {
            let sa = irp::IoSetCompletionRoutineEx(
                dev,
                irp_a,
                Some(cb_invoked),
                core::ptr::null_mut(),
                1,
                0,
                0,
            );
            let sb = irp::IoSetCompletionRoutineEx(
                dev,
                irp_b,
                Some(cb_suppressed),
                core::ptr::null_mut(),
                0,
                0,
                0,
            );
            // Verify freeing or reusing an uncompleted IRP with
            // IoSetCompletionRoutineEx installed releases its wrapper, device
            // reference, and driver unload pin so ZwUnloadDriver never hangs.
            let mut cleanup_ok = true;
            let irp_free = irp::IoAllocateIrp(2, 0);
            let irp_reuse = irp::IoAllocateIrp(2, 0);
            if !irp_free.is_null() && !irp_reuse.is_null() {
                let sf = irp::IoSetCompletionRoutineEx(
                    dev,
                    irp_free,
                    Some(cb_suppressed),
                    core::ptr::null_mut(),
                    1,
                    1,
                    1,
                );
                let sr = irp::IoSetCompletionRoutineEx(
                    dev,
                    irp_reuse,
                    Some(cb_suppressed),
                    core::ptr::null_mut(),
                    1,
                    1,
                    1,
                );
                irp::IoReuseIrp(irp_reuse, STATUS_SUCCESS);
                irp::IoFreeIrp(irp_reuse);
                irp::IoFreeIrp(irp_free);
                cleanup_ok = sf == STATUS_SUCCESS && sr == STATUS_SUCCESS;
            }
            // Delete the device immediately so `(*drv).DeviceObject` is NULL
            // before unload runs; only the completion pins keep the image live.
            device::IoDeleteDevice(dev);
            if cleanup_ok {
                (sa, sb)
            } else {
                (STATUS_UNSUCCESSFUL, STATUS_UNSUCCESSFUL)
            }
        };
        if sa != STATUS_SUCCESS || sb != STATUS_SUCCESS {
            return Err("IoSetCompletionRoutineEx failed");
        }

        let threads_before = thread::count();
        thread::create(stop_worker, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)
            .map_err(|_| "could not spawn stop worker thread")?;
        while !EX_UNLOAD_RETURNED.load(Ordering::Acquire) {
            thread::yield_now();
        }
        time::stall(20_000);
        let pinned_after_unload =
            !EX_STOP_DONE.load(Ordering::Acquire) && ldr::module_named("nkc-irql.sys").is_some();

        // Complete IRP A (invokes callback while image is still mapped).
        // SAFETY: `irp_a` is owned by this test; step down one location as a lower driver sees it.
        unsafe {
            (*irp_a).CurrentLocation -= 1;
            (*irp_a).CurrentStackLocation = (*irp_a).CurrentStackLocation.sub(1);
            (*irp_a).IoStatus.Status = STATUS_SUCCESS;
            irp::IofCompleteRequest(irp_a, 0);
        }
        time::stall(10_000);
        let still_pinned_by_suppressed =
            !EX_STOP_DONE.load(Ordering::Acquire) && ldr::module_named("nkc-irql.sys").is_some();

        // Complete IRP B (status suppresses callback, trampoline still unpins).
        // SAFETY: `irp_b` is owned by this test.
        unsafe {
            (*irp_b).CurrentLocation -= 1;
            (*irp_b).CurrentStackLocation = (*irp_b).CurrentStackLocation.sub(1);
            (*irp_b).IoStatus.Status = STATUS_SUCCESS;
            irp::IofCompleteRequest(irp_b, 0);
        }
        while !EX_STOP_DONE.load(Ordering::Acquire) {
            thread::yield_now();
        }
        thread::settle(threads_before);
        if !pinned_after_unload
            || !still_pinned_by_suppressed
            || !EX_IMAGE_LIVE_IN_CB.load(Ordering::Acquire)
            || EX_CB_INVOKED.load(Ordering::Acquire) != 1
            || EX_CB_SUPPRESSED.load(Ordering::Acquire) != 0
            || !EX_STOP_OK.load(Ordering::Acquire)
            || ldr::module_named("nkc-irql.sys").is_some()
        {
            return Err("IoSetCompletionRoutineEx did not pin driver image through unload");
        }
        let after_ex = resources();
        if after_ex != before_ex {
            kprintln!("service: ex leak before={before_ex:?} after={after_ex:?}");
            return Err("completion-pin test left resources behind");
        }
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("io.service.zw-load-missing", zw_load_missing);
    if ldr::boot_file("nkc-irql.sys").is_some() {
        r.check("io.service.default-image", default_image);
        r.check("io.service.zw-load", zw_load_starts);
    } else {
        r.skip(
            "io.service.zw-load",
            format_args!("module nkc-irql.sys not provided"),
        );
        r.skip(
            "io.service.default-image",
            format_args!("module nkc-irql.sys not provided"),
        );
    }
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

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
