//! Driver services: a driver is started from its key under
//! `...\Services`, as on Windows, and stopped by its service name.
//!
//! The key says which image (`ImagePath`; without one, the file in
//! `System32\drivers` named for the service); the image is a boot file
//! (`ldr::boot_file`), NK's `System32\drivers` until there is a file
//! system. [`create`] writes a key the way the service control manager
//! does for `sc create`; a key may equally come from the hive, and the
//! hive's boot-start and system-start drivers are started at boot
//! ([`start_boot_services`]).

use super::driver::{self, DriverError};
use crate::{cm, ldr};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use nk_ntabi::io::DRIVER_OBJECT;
use nk_ntabi::status::*;

/// Where service keys live, from the registry's root.
const SERVICES: &str = "Machine\\System\\CurrentControlSet\\Services";

/// `IoCreateArcName` (undocumented; `ntddk.h` declares it): give the
/// disk `device` its ARC names (`\ArcName\multi(0)disk(0)rdisk(N)`),
/// as links to its partitions, if the loader named it among the disks
/// it saw. Windows matches the disk against the loader's table of ARC
/// disks and answers `STATUS_NOT_SUPPORTED` when the table holds none
/// that matches; `partmgr.sys` notes a success. NK's loader is UEFI's
/// and its table is empty, so that is the answer for every disk, as on
/// Windows with such a loader, and no name is made.
#[allow(non_snake_case)]
pub extern "C" fn IoCreateArcName(_device: *mut nk_ntabi::io::DEVICE_OBJECT) -> NTSTATUS {
    STATUS_NOT_SUPPORTED
}

/// Whether the boot-start and system-start drivers have all been
/// started: Windows' second phase of initialisation has begun.
static STARTED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Bytes of `BOOTDISK_INFORMATION_LITE` before its entries: the number
/// of entries.
const BOOT_DISK_HEADER: usize = 4;

/// `IoGetBootDiskInformationLite` (undocumented; `ntddk.h` declares it):
/// a pool block the caller frees, listing the disks the loader booted
/// from and found the system on. NK's loader is UEFI's: it names no ARC
/// disk, so the list is empty, as Windows' is for a loader that names
/// none. Once the system has started, `STATUS_TOO_LATE`, as on Windows.
///
/// # Safety
/// `information` is writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn IoGetBootDiskInformationLite(information: *mut *mut u8) -> NTSTATUS {
    if STARTED.load(core::sync::atomic::Ordering::Acquire) {
        return STATUS_TOO_LATE;
    }
    let block = crate::mm::pool::alloc(BOOT_DISK_HEADER, u32::from_le_bytes(*b"IoBd"));
    if block.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: a fresh block of the header's size; per the contract.
    unsafe {
        block.cast::<u32>().write_unaligned(0);
        information.write(block);
    }
    STATUS_SUCCESS
}

/// Registry value types.
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;

/// `SERVICE_KERNEL_DRIVER`, `SERVICE_DEMAND_START`,
/// `SERVICE_ERROR_NORMAL`: what `sc create type= kernel` writes.
const KERNEL_DRIVER: u32 = 1;
const DEMAND_START: u32 = 3;
const ERROR_NORMAL: u32 = 1;

#[derive(Debug)]
pub enum ServiceError {
    /// The service has no key, or its `ImagePath` names no file.
    NoKey,
    /// The image the key names is not among the boot files.
    NoImage(String),
    /// The service's driver is already running.
    Running,
    NoMemory,
    Driver(DriverError),
}

impl ServiceError {
    /// The status Windows' `ZwLoadDriver` gives for it. Observed on the
    /// reference Windows (`doc/DESIGN.md`, Exports): a driver that is
    /// running already, and what `LoadError::status` names. A service
    /// without a key or without its file is not found.
    pub fn status(&self) -> NTSTATUS {
        match self {
            Self::NoKey | Self::NoImage(_) => STATUS_OBJECT_NAME_NOT_FOUND,
            Self::Running => STATUS_IMAGE_ALREADY_LOADED,
            Self::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
            Self::Driver(error) => error.status(),
        }
    }
}

fn key(name: &str) -> String {
    format!("{SERVICES}\\{name}")
}

/// Make the key of the demand-start driver service `name`, whose image
/// is the boot file `file`. An existing key is given the same values.
pub fn create(name: &str, file: &str) -> Result<(), ServiceError> {
    let path: Vec<u8> = format!("\\SystemRoot\\System32\\drivers\\{file}")
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    cm::write(
        &key(name),
        &[
            ("Type", REG_DWORD, &KERNEL_DRIVER.to_le_bytes()),
            ("Start", REG_DWORD, &DEMAND_START.to_le_bytes()),
            ("ErrorControl", REG_DWORD, &ERROR_NORMAL.to_le_bytes()),
            ("ImagePath", REG_EXPAND_SZ, &path),
        ],
    )
    .map_err(|_| ServiceError::NoMemory)
}

/// The boot file that is the image of the service `name`: the last
/// part of its key's `ImagePath`, or `<name>.sys` for a key without
/// one, which is the file Windows takes from `System32\drivers` then.
pub fn image(name: &str) -> Result<String, ServiceError> {
    let Ok((_, path)) = cm::read(&key(name), "ImagePath") else {
        return if cm::exists(&key(name)) {
            Ok(format!("{name}.sys"))
        } else {
            Err(ServiceError::NoKey)
        };
    };
    let path: Vec<u16> = path
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    match String::from_utf16(nk_rtl::image_file(&path)) {
        Ok(file) if !file.is_empty() => Ok(file),
        _ => Err(ServiceError::NoKey),
    }
}

/// Whether the driver of the service `name` is running.
pub fn running(name: &str) -> bool {
    driver::running(name).is_some()
}

/// Start the driver of the service `name`: find its image ([`image`]),
/// load it and run its entry point.
pub fn start(name: &str) -> Result<*mut DRIVER_OBJECT, ServiceError> {
    let file = image(name)?;
    if driver::running(name).is_some() {
        return Err(ServiceError::Running);
    }
    let Some(image) = ldr::boot_file(&file) else {
        return Err(ServiceError::NoImage(file));
    };
    driver::load(name, &file, image).map_err(ServiceError::Driver)
}

/// `SERVICE_ERROR_CRITICAL`: a boot without this driver has failed.
const ERROR_CRITICAL: u32 = 3;

/// Start the drivers the registry says start at boot: `Start` 0 (boot)
/// and 1 (system), in the order `cm::boot_start` gives. Windows' loader
/// and I/O manager do this before anything else runs.
///
/// A service whose image is not among the boot files is passed over,
/// with a line in the log: the boot files stand for a driver directory
/// that holds only what a test image was given. Any other failure is
/// logged, and fails the boot if the key's
/// [`ErrorControl`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicew)
/// is critical. (Windows then restarts with the last-known-good control
/// set and fails only if that is what was running; NK has one control
/// set to run.)
pub fn start_boot_services() -> Result<(), &'static str> {
    for (name, error_control) in cm::boot_start()? {
        match start(&name) {
            Ok(_) => {
                kprintln!("io: boot-start service {name} started");
                // The devices this driver serves are started, and what
                // they bring enumerated, before the next driver's turn,
                // as on Windows.
                crate::pnp::settle();
            }
            Err(ServiceError::NoImage(file)) => {
                kprintln!("io: boot-start service {name} skipped: no boot file {file}");
            }
            Err(e) => {
                kprintln!("io: boot-start service {name} failed: {e:?}");
                crate::pnp::driver_failed(&name);
                if error_control == ERROR_CRITICAL {
                    return Err("a boot-start driver whose failure is critical did not start");
                }
            }
        }
    }
    // From here on a device's driver is loaded when the device needs
    // it. The boot drivers' reinitialisation routines run once the
    // devices they serve have been started.
    crate::pnp::boot_drivers_loaded();
    driver::reinitialize_boot_drivers();
    // NK has started: the third of the points where Windows calls the
    // other reinitialisation routines.
    STARTED.store(true, core::sync::atomic::Ordering::Release);
    driver::reinitialize_drivers();
    Ok(())
}

/// Stop the service `name`: have its driver unload, and free it.
pub fn stop(name: &str) -> Result<(), &'static str> {
    driver::unload(driver::running(name).ok_or("the service is not running")?)
}

/// [`ZwLoadDriver`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwloaddriver):
/// start the driver whose service key `driver_service_name` names, by
/// its full path from the namespace's root
/// (`\Registry\Machine\System\CurrentControlSet\Services\<name>`), and
/// return what its entry point returned, or why it never ran
/// ([`ServiceError::status`]). A name that leads to no key fails with
/// what the namespace or the registry says of it, as Windows' routine
/// fails with the status of opening the key. A kernel-mode caller
/// needs no privilege.
///
/// A key that exists elsewhere than under `...\Services`, which
/// Windows would load from all the same, stops the system by name:
/// the ledger's "partial".
///
/// # Safety
/// `driver_service_name` is null or points to a counted string.
#[allow(non_snake_case)]
pub unsafe extern "C" fn ZwLoadDriver(
    driver_service_name: *const nk_ntabi::io::UNICODE_STRING,
) -> NTSTATUS {
    // SAFETY: per the contract.
    let path = unsafe { crate::rtl::copy_unicode(driver_service_name) };
    let (root, rest) = match crate::ob::lookup(None, &path) {
        Ok(found) => found,
        Err(status) => return status,
    };
    // SAFETY: the look-up's reference; the type is read before it is
    // given up.
    let is_key = unsafe {
        let is_key = core::ptr::eq(
            crate::ob::object::type_of(root),
            &raw const crate::ob::object::KEY_TYPE,
        );
        crate::ob::object::dereference(root);
        is_key
    };
    if !is_key {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }
    // What follows `\Registry`, without its backslash.
    let rest = rest.get(1..).unwrap_or(&[]);
    let services: Vec<u16> = SERVICES.encode_utf16().chain([u16::from(b'\\')]).collect();
    let name = rest
        .split_at_checked(services.len())
        .filter(|(prefix, name)| {
            nk_rtl::names_equal(prefix, &services)
                && !name.is_empty()
                && !name.contains(&u16::from(b'\\'))
        })
        .and_then(|(_, name)| String::from_utf16(name).ok());
    let Some(name) = name else {
        let rest = String::from_utf16_lossy(rest);
        if !cm::exists(&rest) {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        crate::kd::bugcheck(format_args!(
            "ZwLoadDriver: loading a driver from the key \\Registry\\{rest}, which is not a key \
             of ...\\Services, is not implemented"
        ));
    };
    match start(&name) {
        Ok(_) => {
            driver::reinitialize_drivers();
            STATUS_SUCCESS
        }
        Err(error) => error.status(),
    }
}
