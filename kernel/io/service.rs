//! Driver services: a driver is started from its key under
//! `...\Services`, as on Windows, and stopped by its service name.
//!
//! The key says which image (`ImagePath`); the image is a boot file
//! (`ldr::boot_file`), NK's `System32\drivers` until there is a file
//! system. [`create`] writes a key the way the service control manager
//! does for `sc create`; a key may equally come from the hive.

use super::driver::{self, DriverError};
use crate::{cm, ldr};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use nk_ntabi::io::DRIVER_OBJECT;

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
#[expect(dead_code, reason = "fields are read through Debug in test reports")]
pub enum ServiceError {
    /// The service has no key, or the key no usable `ImagePath`.
    NoKey,
    /// The image the key names is not among the boot files.
    NoImage(String),
    /// The service's driver is already running.
    Running,
    NoMemory,
    Driver(DriverError),
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

/// Start the driver of the service `name`: find its image by the key's
/// `ImagePath`, load it and run its entry point.
pub fn start(name: &str) -> Result<*mut DRIVER_OBJECT, ServiceError> {
    let (_, path) = cm::read(&key(name), "ImagePath").map_err(|_| ServiceError::NoKey)?;
    let path: Vec<u16> = path
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let file = String::from_utf16(nk_rtl::image_file(&path)).map_err(|_| ServiceError::NoKey)?;
    if driver::running(name).is_some() {
        return Err(ServiceError::Running);
    }
    let Some(image) = ldr::boot_file(&file) else {
        return Err(ServiceError::NoImage(file));
    };
    driver::load(name, &file, image).map_err(ServiceError::Driver)
}

/// Stop the service `name`: have its driver unload, and free it.
pub fn stop(name: &str) -> Result<(), &'static str> {
    driver::unload(driver::running(name).ok_or("the service is not running")?)
}
