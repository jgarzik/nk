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
            Ok(_) => kprintln!("io: boot-start service {name} started"),
            Err(ServiceError::NoImage(file)) => {
                kprintln!("io: boot-start service {name} skipped: no boot file {file}");
            }
            Err(e) => {
                kprintln!("io: boot-start service {name} failed: {e:?}");
                if error_control == ERROR_CRITICAL {
                    return Err("a boot-start driver whose failure is critical did not start");
                }
            }
        }
    }
    driver::reinitialize_boot_drivers();
    Ok(())
}

/// Stop the service `name`: have its driver unload, and free it.
pub fn stop(name: &str) -> Result<(), &'static str> {
    driver::unload(driver::running(name).ok_or("the service is not running")?)
}
