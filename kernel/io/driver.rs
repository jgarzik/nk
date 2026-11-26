//! Driver objects: load an image, call its entry point, unload it.
//! `io::service` decides which image and when; nothing else loads a
//! driver.

use super::irp;
use crate::ke::seh::{self, Guard, Unhandled};
use crate::ke::{Rank, SpinLock, irql};
use crate::ldr::{self, Image, LoadError};
use crate::ob;
use alloc::vec::Vec;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

/// Kernel-side record of a loaded driver. The strings back the counted
/// strings in the driver object and the registry path given to its entry.
struct Record {
    object: *mut DRIVER_OBJECT,
    image: Image,
    _driver_name: Vec<u16>,
    _registry_path: Vec<u16>,
}

// SAFETY: the pointer is an identity for a pool object the record owns.
unsafe impl Send for Record {}

static DRIVERS: SpinLock<Vec<Record>> = SpinLock::new(Rank::Drivers, Vec::new());

#[derive(Debug)]
pub enum DriverError {
    Load(LoadError),
    NoMemory,
    /// The driver object could not be named `\Driver\<service>`.
    Name(NTSTATUS),
    /// The driver's own entry point refused to initialise.
    EntryFailed(NTSTATUS),
}

fn wide(prefix: &str, name: &str) -> Vec<u16> {
    prefix
        .encode_utf16()
        .chain(name.encode_utf16())
        .chain([0])
        .collect()
}

fn counted(s: &mut [u16]) -> UNICODE_STRING {
    let bytes = (s.len() - 1) * 2;
    UNICODE_STRING {
        Length: bytes as u16,
        MaximumLength: (bytes + 2) as u16,
        Buffer: s.as_mut_ptr(),
    }
}

/// The running driver of the service `name`, if it is running.
pub(super) fn running(name: &str) -> Option<*mut DRIVER_OBJECT> {
    DRIVERS
        .lock()
        .iter()
        .find(|r| {
            // `\Driver\<name>` and its terminator.
            let service = &r._driver_name[8..r._driver_name.len() - 1];
            nk_rtl::names_equal(service, &name.encode_utf16().collect::<Vec<u16>>())
        })
        .map(|r| r.object)
}

/// Load the driver in `file`, the contents of the image called
/// `file_name`, and run its entry point. `name` is its service, whose
/// key exists.
pub(super) fn load(
    name: &str,
    file_name: &str,
    file: &[u8],
) -> Result<*mut DRIVER_OBJECT, DriverError> {
    irql::expect_passive("loading a driver");
    let image = ldr::load(file_name, file).map_err(DriverError::Load)?;
    let mut driver_name = wide("\\Driver\\", name);
    // The driver object is an object called `\Driver\<service>`, with
    // its extension behind it.
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let path = &driver_name[..driver_name.len() - 1];
    let Some(body) = ob::object::create_named(&ob::object::DRIVER_TYPE, size, ob::leaf(path))
    else {
        ldr::unload(&image);
        return Err(DriverError::NoMemory);
    };
    let object = body.cast::<DRIVER_OBJECT>();
    // SAFETY: a named object made above; `free` takes the name away
    // before it gives up the reference.
    let named = unsafe { ob::insert(path, body) };
    if !nt_success(named) {
        // SAFETY: the creating reference of an object nothing else has.
        unsafe { ob::object::dereference(body) };
        ldr::unload(&image);
        return Err(DriverError::Name(named));
    }
    let mut registry_path = wide(
        "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\",
        name,
    );
    let mut registry = counted(&mut registry_path);

    // SAFETY: `object` is a fresh zeroed block holding a DRIVER_OBJECT
    // followed by its DRIVER_EXTENSION. `image.entry` is the entry point
    // of an image that was just mapped, relocated and bound, with the
    // driver-entry signature every kernel driver has.
    let status = unsafe {
        let extension = object.add(1).cast::<DRIVER_EXTENSION>();
        (*extension).DriverObject = object;
        (*extension).ServiceKeyName = counted(&mut driver_name[8..]);
        (*object).Type = IO_TYPE_DRIVER;
        (*object).Size = size_of::<DRIVER_OBJECT>() as i16;
        (*object).DriverStart = image.base as PVOID;
        (*object).DriverSize = image.size as u32;
        (*object).DriverExtension = extension;
        (*object).DriverName = counted(&mut driver_name);
        let entry: DRIVER_INITIALIZE = core::mem::transmute(image.entry as usize);
        (*object).DriverInit = Some(entry);
        // Every request type starts out rejected, as on Windows.
        (*object).MajorFunction = [Some(irp::invalid_device_request); IRP_MJ_MAXIMUM_FUNCTION + 1];
        // Reached only from starting a service, which no driver does:
        // an exception the entry point lets out is unhandled in a
        // system thread, as on Windows, where one runs it.
        seh::call(
            entry as usize,
            [object.addr(), (&raw mut registry).addr(), 0, 0],
            &Guard::Base(Unhandled::SystemThread),
        ) as u32 as NTSTATUS
    };
    if !nt_success(status) {
        // Windows does not call the unload routine of a driver whose entry
        // failed; the driver must have cleaned up after itself.
        free(object, &image);
        return Err(DriverError::EntryFailed(status));
    }
    // SAFETY: the driver object and its device list are live; devices made
    // during entry become usable now.
    unsafe {
        let mut device = (*object).DeviceObject;
        while !device.is_null() {
            (*device).Flags &= !DO_DEVICE_INITIALIZING;
            device = (*device).NextDevice;
        }
    }
    let mut drivers = DRIVERS.lock();
    // Room for exactly one more, as unloading leaves exactly enough: the
    // table's memory then depends only on how many drivers are loaded.
    drivers.reserve_exact(1);
    drivers.push(Record {
        object,
        image,
        _driver_name: driver_name,
        _registry_path: registry_path,
    });
    Ok(object)
}

fn free(object: *mut DRIVER_OBJECT, image: &Image) {
    // SAFETY: `object` is a driver object this module made and named;
    // clearing Type makes a stale pointer recognisable. The name goes
    // before the reference the object was made with.
    unsafe {
        ob::remove(object.cast());
        (*object).Type = 0;
        ob::object::dereference(object.cast());
    }
    ldr::unload(image);
}

/// Unload a driver: call its unload routine, then free its object and
/// image. Fails, leaving the driver loaded, if it has no unload routine.
///
/// The routine runs with no lock held, and other drivers are loaded and
/// unloaded meanwhile: where the driver's record is in the table is
/// looked up afterwards, under the lock hold that removes it.
pub(super) fn unload(object: *mut DRIVER_OBJECT) -> Result<(), &'static str> {
    irql::expect_passive("unloading a driver");
    let listed = |drivers: &[Record]| drivers.iter().position(|r| r.object == object);
    if listed(&DRIVERS.lock()).is_none() {
        return Err("not a loaded driver");
    }
    // SAFETY: `object` is a live driver object (it has a record), and its
    // unload routine, if set, was set by the driver itself.
    let leftover = unsafe {
        let routine = (*object)
            .DriverUnload
            .ok_or("driver has no unload routine")?;
        seh::call(
            routine as usize,
            [object.addr(), 0, 0, 0],
            &Guard::Base(Unhandled::SystemThread),
        );
        !(*object).DeviceObject.is_null()
    };
    let record = {
        let mut drivers = DRIVERS.lock();
        let index = listed(&drivers).ok_or("not a loaded driver")?;
        let record = drivers.swap_remove(index);
        // An empty table holds no memory, so leak checks see none.
        drivers.shrink_to_fit();
        record
    };
    if leftover {
        // The image still backs live device objects: keep it mapped.
        core::mem::forget(record);
        return Err("unload routine left device objects behind");
    }
    free(record.object, &record.image);
    Ok(())
}

impl DriverError {
    /// The status Windows' `ZwLoadDriver` gives for it.
    pub fn status(&self) -> NTSTATUS {
        match self {
            Self::Load(error) => error.status(),
            Self::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
            Self::Name(status) | Self::EntryFailed(status) => *status,
        }
    }
}
