//! Driver objects: load an image, call its entry point, unload it.
//! `io::service` decides which image and when; nothing else loads a
//! driver.

use super::{device, irp};
use crate::ke::seh::{self, Guard, Unhandled};
use crate::ke::{Rank, SpinLock, irql};
use crate::ldr::{self, Image, LoadError};
use crate::mm::pool;
use crate::ob;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

/// Kernel-side record of a loaded driver. The strings back the counted
/// strings in the driver object and the registry path given to its entry.
struct Record {
    object: *mut DRIVER_OBJECT,
    /// The image the driver is; `None` for a driver that is part of
    /// the kernel ([`builtin`]).
    image: Option<Image>,
    _driver_name: Vec<u16>,
    _registry_path: Vec<u16>,
    /// True once `DriverEntry` has succeeded (so `IoOpenDriverRegistryKey` can
    /// find the service path during `DriverEntry` while `running` only reports
    /// fully initialised drivers).
    ready: bool,
    /// True once an unload has claimed this driver; prevents duplicate unloads.
    unloading: bool,
    /// Active `IoSetCompletionRoutineEx` registrations pinning this driver's
    /// image until their trampolines finish.
    active_completions: usize,
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
pub fn running(name: &str) -> Option<*mut DRIVER_OBJECT> {
    DRIVERS
        .lock()
        .iter()
        .find(|r| {
            r.ready && !r.unloading && {
                // `\Driver\<name>` and its terminator.
                let service = &r._driver_name[8..r._driver_name.len() - 1];
                nk_rtl::names_equal(service, &name.encode_utf16().collect::<Vec<u16>>())
            }
        })
        .map(|r| r.object)
}

/// Pin `driver` for an installed `IoSetCompletionRoutineEx` so [`unload`] waits
/// for the completion trampoline to finish before unmapping its image.
pub(super) fn pin_completion(driver: *mut DRIVER_OBJECT) -> bool {
    let mut drivers = DRIVERS.lock();
    if let Some(record) = drivers.iter_mut().find(|r| r.object == driver) {
        record.active_completions += 1;
        true
    } else {
        false
    }
}

/// Release a pin taken by [`pin_completion`] after the completion trampoline
/// has finished.
pub(super) fn unpin_completion(driver: *mut DRIVER_OBJECT) {
    let mut drivers = DRIVERS.lock();
    if let Some(record) = drivers.iter_mut().find(|r| r.object == driver) {
        record.active_completions = record.active_completions.saturating_sub(1);
    }
}

/// Load the driver in `file`, the contents of the image called
/// `file_name`, and run its entry point. `name` is its service, whose
/// key exists; `boot`, that it starts with the boot drivers
/// (`ldr::load_boot`).
pub(super) fn load(
    name: &str,
    file_name: &str,
    file: &[u8],
    boot: bool,
) -> Result<*mut DRIVER_OBJECT, DriverError> {
    irql::expect_passive("loading a driver");
    let loaded = if boot {
        ldr::load_boot(file_name, file)
    } else {
        ldr::load(file_name, file)
    };
    let image = loaded.map_err(DriverError::Load)?;
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
    let entry_addr = image.entry as usize;
    let image_base = image.base;
    let image_size = image.size;
    // Publish the record with `ready: false` BEFORE calling `DriverEntry` so
    // `IoOpenDriverRegistryKey` can locate the service path during entry
    // without reporting the driver as running yet. The backing `Vec<u16>`
    // buffers stay at stable heap addresses while `Record` lives in `DRIVERS`.
    // SAFETY: `object` is a fresh zeroed block holding a DRIVER_OBJECT
    // followed by its DRIVER_EXTENSION.
    unsafe {
        let extension = object.add(1).cast::<DRIVER_EXTENSION>();
        (*extension).DriverObject = object;
        (*extension).ServiceKeyName = counted(&mut driver_name[8..]);
        (*object).Type = IO_TYPE_DRIVER;
        (*object).Size = size_of::<DRIVER_OBJECT>() as i16;
        (*object).DriverStart = image_base as PVOID;
        (*object).DriverSize = image_size as u32;
        (*object).DriverExtension = extension;
        (*object).DriverName = counted(&mut driver_name);
        let entry: DRIVER_INITIALIZE = core::mem::transmute(entry_addr);
        (*object).DriverInit = Some(entry);
        // Every request type starts out rejected, as on Windows.
        (*object).MajorFunction = [Some(irp::invalid_device_request); IRP_MJ_MAXIMUM_FUNCTION + 1];
    }
    {
        let mut drivers = DRIVERS.lock();
        drivers.reserve_exact(1);
        drivers.push(Record {
            object,
            image: Some(image),
            _driver_name: driver_name,
            _registry_path: registry_path,
            ready: false,
            unloading: false,
            active_completions: 0,
        });
    }
    // SAFETY: `entry_addr` is the entry point of the mapped image; `object`
    // and `registry` live through the call.
    let status = unsafe {
        // An exception the entry point lets out is unhandled in a
        // system thread, as on Windows, where one runs it. That holds
        // too when a driver started the service (`ZwLoadDriver`):
        // Windows would search that driver's frames for a handler, NK
        // stops the system.
        seh::call(
            entry_addr,
            [object.addr(), (&raw mut registry).addr(), 0, 0],
            &Guard::Base(Unhandled::SystemThread),
        ) as u32 as NTSTATUS
    };
    if !nt_success(status) {
        let record = {
            let mut drivers = DRIVERS.lock();
            let index = drivers
                .iter()
                .position(|r| r.object == object)
                .expect("driver record inserted before DriverEntry");
            let record = drivers.swap_remove(index);
            drivers.shrink_to_fit();
            record
        };
        // Windows does not call the unload routine of a driver whose entry
        // failed; the driver must have cleaned up after itself. One that
        // left a device behind has its image and object kept, as
        // `unload` keeps them: the device's dispatch routines and its
        // `DriverObject` point into them. On Windows the devices keep
        // the driver object, and so its image, alive.
        // SAFETY: the object is this module's; its device list was
        // written by the driver, which has returned.
        if unsafe { !(*object).DeviceObject.is_null() } {
            crate::kd::verify(format_args!(
                "{name}: DriverEntry failed ({:#010x}) and left device objects behind; the \
                 driver is kept loaded",
                status as u32
            ));
            // Kept whole, as `unload` keeps a record: the object
            // points into its name and registry path too.
            core::mem::forget(record);
            return Err(DriverError::EntryFailed(status));
        }
        // SAFETY: the object is this module's, out of the records, and has no device.
        unsafe { free(record.object, record.image.as_ref()) };
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
    {
        let mut drivers = DRIVERS.lock();
        if let Some(record) = drivers.iter_mut().find(|r| r.object == object) {
            record.ready = true;
        }
    }
    Ok(object)
}

/// Make the driver object `\Driver\<name>` of a driver that is part of
/// the kernel: the Plug and Play manager's own, the HAL's, a test's.
/// It has no image and no service key; `setup` gives it its dispatch
/// routines and its `AddDevice`, as an entry point would. Found by its
/// name like any running driver ([`running`]).
pub fn builtin(
    name: &str,
    setup: impl FnOnce(*mut DRIVER_OBJECT),
) -> Result<*mut DRIVER_OBJECT, DriverError> {
    builtin_in("\\Driver\\", name, setup)
}

/// [`builtin`] for a driver object in the directory `prefix` names:
/// `\FileSystem\` for the kernel's own file system (`io::raw`).
pub fn builtin_in(
    prefix: &str,
    name: &str,
    setup: impl FnOnce(*mut DRIVER_OBJECT),
) -> Result<*mut DRIVER_OBJECT, DriverError> {
    let mut driver_name = wide(prefix, name);
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let path = &driver_name[..driver_name.len() - 1];
    let body = ob::object::create_named(&ob::object::DRIVER_TYPE, size, ob::leaf(path))
        .ok_or(DriverError::NoMemory)?;
    let object = body.cast::<DRIVER_OBJECT>();
    // SAFETY: a named object made above; `remove_builtin` takes the
    // name away before it gives up the reference.
    let named = unsafe { ob::insert(path, body) };
    if !nt_success(named) {
        // SAFETY: the creating reference of an object nothing else has.
        unsafe { ob::object::dereference(body) };
        return Err(DriverError::Name(named));
    }
    // SAFETY: a fresh zeroed block holding a DRIVER_OBJECT followed by
    // its DRIVER_EXTENSION, which nothing else knows yet.
    unsafe {
        let extension = object.add(1).cast::<DRIVER_EXTENSION>();
        (*extension).DriverObject = object;
        (*extension).ServiceKeyName = counted(&mut driver_name[prefix.len()..]);
        (*object).Type = IO_TYPE_DRIVER;
        (*object).Size = size_of::<DRIVER_OBJECT>() as i16;
        (*object).DriverExtension = extension;
        (*object).DriverName = counted(&mut driver_name);
        (*object).MajorFunction = [Some(irp::invalid_device_request); IRP_MJ_MAXIMUM_FUNCTION + 1];
    }
    setup(object);
    let mut drivers = DRIVERS.lock();
    drivers.reserve_exact(1);
    drivers.push(Record {
        object,
        image: None,
        _driver_name: driver_name,
        _registry_path: Vec::new(),
        ready: true,
        unloading: false,
        active_completions: 0,
    });
    Ok(object)
}

/// Take a driver made by [`builtin`] away again. Its devices are gone:
/// the caller deleted them.
pub fn remove_builtin(object: *mut DRIVER_OBJECT) {
    let record = {
        let mut drivers = DRIVERS.lock();
        let Some(index) = drivers
            .iter()
            .position(|r| r.object == object && r.image.is_none())
        else {
            return;
        };
        let record = drivers.swap_remove(index);
        drivers.shrink_to_fit();
        record
    };
    // SAFETY: the object is this module's, out of the records, and has no device.
    unsafe { free(record.object, None) };
}

/// Free a driver object this module made, and its image.
///
/// # Safety
/// `object` is a driver object this module made, out of the records,
/// with no device left.
unsafe fn free(object: *mut DRIVER_OBJECT, image: Option<&Image>) {
    // SAFETY: `object` is a driver object this module made and named;
    // clearing Type makes a stale pointer recognisable. The name goes
    // before the reference the object was made with.
    unsafe {
        ob::remove(object.cast());
        (*object).Type = 0;
        ob::object::dereference(object.cast());
    }
    if let Some(image) = image {
        ldr::unload(image);
    }
}

/// Unload a driver: call its unload routine, then free its object and
/// image. Fails, leaving the driver loaded, if it has no unload routine.
///
/// The routine runs with no lock held, and other drivers are loaded and
/// unloaded meanwhile: where the driver's record is in the table is
/// looked up afterwards, under the lock hold that removes it.
///
/// Safe although `object` is a raw pointer: it is found among this
/// module's records before it is used (doc/UNSAFE.md, rule 1).
pub(super) fn unload(object: *mut DRIVER_OBJECT) -> Result<(), &'static str> {
    irql::expect_passive("unloading a driver");
    let listed = |drivers: &[Record]| {
        drivers
            .iter()
            .position(|r| r.object == object && r.image.is_some())
    };
    // Atomically claim the unload on the driver record before dropping DRIVERS,
    // so two concurrent ZwUnloadDriver calls cannot both enter DriverUnload,
    // and then claim the module under the loader mutex so no concurrent load
    // can bind a new importer before the image is unmapped.
    let (routine, base, shared) = {
        let mut drivers = DRIVERS.lock();
        let Some(index) = listed(&drivers) else {
            return Err("not a loaded driver");
        };
        let record = &mut drivers[index];
        if !record.ready {
            return Err("not a loaded driver");
        }
        if record.unloading {
            return Err("driver is already unloading");
        }
        // SAFETY: `object` is a live driver object owned by this module.
        let Some(routine) = (unsafe { (*object).DriverUnload }) else {
            return Err("driver has no unload routine");
        };
        let image = record.image.as_ref().expect("checked is_some above");
        record.unloading = true;
        (routine, image.base, image.shared)
    };
    if !ldr::begin_unload_at(base, shared) {
        let mut drivers = DRIVERS.lock();
        if let Some(record) = drivers.iter_mut().find(|r| r.object == object) {
            record.unloading = false;
        }
        return Err("driver still has active importers");
    }
    // SAFETY: `object` is exclusively claimed for unload; `routine` is its
    // `DriverUnload`.
    let leftover = unsafe {
        seh::call(
            routine as usize,
            [object.addr(), 0, 0, 0],
            &Guard::Base(Unhandled::SystemThread),
        );
        !(*object).DeviceObject.is_null()
    };
    // Wait for any active `IoSetCompletionRoutineEx` trampolines referencing
    // this driver to finish before unmapping its image. Sleep briefly rather
    // than yield_now so a higher-priority unloader cannot starve a lower-
    // priority completion thread on a single-CPU system.
    while DRIVERS
        .lock()
        .iter()
        .any(|r| r.object == object && r.active_completions > 0)
    {
        // SAFETY: relative delay wait at PASSIVE_LEVEL with no object.
        unsafe { crate::ke::wait::wait(None, Some(-10_000)) };
    }
    let record = {
        let mut drivers = DRIVERS.lock();
        let index = listed(&drivers).ok_or("not a loaded driver")?;
        let record = drivers.swap_remove(index);
        // An empty table holds no memory, so leak checks see none.
        drivers.shrink_to_fit();
        record
    };
    if leftover {
        // The image still backs live device objects: keep it mapped (and keep
        // the module marked unloading so no new imports bind to it).
        core::mem::forget(record);
        return Err("unload routine left device objects behind");
    }
    // SAFETY: the object is this module's, out of the records, has no device,
    // and all extended completion trampolines have finished.
    unsafe { free(record.object, record.image.as_ref()) };
    Ok(())
}

/// Exercise the `ready: false` initialization window used during `DriverEntry`
/// for selftests: inserts a service-backed record with `ready: false`, runs
/// `probe` (which can call `IoOpenDriverRegistryKey`), and tears it down.
pub(crate) fn with_initializing_driver<R>(
    name: &str,
    probe: impl FnOnce(*mut DRIVER_OBJECT) -> R,
) -> Result<R, DriverError> {
    let mut driver_name = wide("\\Driver\\", name);
    let size = size_of::<DRIVER_OBJECT>() + size_of::<DRIVER_EXTENSION>();
    let path = &driver_name[..driver_name.len() - 1];
    let body = ob::object::create_named(&ob::object::DRIVER_TYPE, size, ob::leaf(path))
        .ok_or(DriverError::NoMemory)?;
    let object = body.cast::<DRIVER_OBJECT>();
    // SAFETY: fresh named object.
    let named = unsafe { ob::insert(path, body) };
    if !nt_success(named) {
        // SAFETY: creating reference of an unused object.
        unsafe { ob::object::dereference(body) };
        return Err(DriverError::Name(named));
    }
    let registry_path = wide(
        "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\",
        name,
    );
    // SAFETY: fresh zeroed DRIVER_OBJECT + DRIVER_EXTENSION.
    unsafe {
        let extension = object.add(1).cast::<DRIVER_EXTENSION>();
        (*extension).DriverObject = object;
        (*extension).ServiceKeyName = counted(&mut driver_name[8..]);
        (*object).Type = IO_TYPE_DRIVER;
        (*object).Size = size_of::<DRIVER_OBJECT>() as i16;
        (*object).DriverExtension = extension;
        (*object).DriverName = counted(&mut driver_name);
        (*object).MajorFunction = [Some(irp::invalid_device_request); IRP_MJ_MAXIMUM_FUNCTION + 1];
    }
    {
        let mut drivers = DRIVERS.lock();
        drivers.reserve_exact(1);
        drivers.push(Record {
            object,
            image: None,
            _driver_name: driver_name,
            _registry_path: registry_path,
            ready: false,
            unloading: false,
            active_completions: 0,
        });
    }
    let out = probe(object);
    let record = {
        let mut drivers = DRIVERS.lock();
        let index = drivers
            .iter()
            .position(|r| r.object == object)
            .expect("temporary initializing driver record");
        let record = drivers.swap_remove(index);
        drivers.shrink_to_fit();
        record
    };
    // SAFETY: owned temporary driver object with no devices.
    unsafe { free(record.object, None) };
    Ok(out)
}

/// Pool tag of driver-object extensions, as Windows spells it.
const TAG_EXTENSION: u32 = u32::from_le_bytes(*b"Driv");

/// `DRIVER_REGKEY_TYPE` values for [`IoOpenDriverRegistryKey`].
const DRIVER_REGKEY_PARAMETERS: u32 = 0;
const DRIVER_REGKEY_PERSISTENT_STATE: u32 = 1;
const DRIVER_REGKEY_SHARED_PERSISTENT_STATE: u32 = 2;

/// [`IoOpenDriverRegistryKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioopendriverregistrykey):
/// open (creating if absent) the driver-specific registry key (`Parameters` or
/// persistent state) beneath the service key of `driver_object`.
///
/// # Safety
/// `driver_object` is a live driver object; `driver_reg_key` is writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn IoOpenDriverRegistryKey(
    driver_object: *mut DRIVER_OBJECT,
    reg_key_type: u32,
    desired_access: u32,
    flags: u32,
    driver_reg_key: *mut *mut c_void,
) -> NTSTATUS {
    irql::expect_passive("IoOpenDriverRegistryKey");
    if driver_object.is_null() || driver_reg_key.is_null() || flags != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: checked non-null; per the contract.
    unsafe { driver_reg_key.write_unaligned(core::ptr::null_mut()) };
    let suffix = match reg_key_type {
        DRIVER_REGKEY_PARAMETERS => "\\Parameters",
        DRIVER_REGKEY_PERSISTENT_STATE => "\\Parameters\\PersistentState",
        DRIVER_REGKEY_SHARED_PERSISTENT_STATE => "\\Parameters\\SharedPersistentState",
        _ => return STATUS_INVALID_PARAMETER,
    };
    let base_path = {
        let drivers = DRIVERS.lock();
        drivers
            .iter()
            .find(|r| r.object == driver_object)
            .map(|r| r._registry_path.clone())
    };
    let Some(mut path) = base_path.filter(|p| p.len() > 1) else {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    };
    // Drop trailing NUL before appending suffix.
    if path.last() == Some(&0) {
        path.pop();
    }
    path.extend(suffix.encode_utf16());
    let name = UNICODE_STRING {
        Length: (path.len() * 2) as u16,
        MaximumLength: (path.len() * 2) as u16,
        Buffer: path.as_mut_ptr(),
    };
    const ATTRIBUTES: u32 = 0x40 | 0x200; // OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE
    let attributes = nk_ntabi::ob::OBJECT_ATTRIBUTES {
        Length: size_of::<nk_ntabi::ob::OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: core::ptr::null_mut(),
        ObjectName: &raw const name,
        Attributes: ATTRIBUTES,
        SecurityDescriptor: core::ptr::null_mut(),
        SecurityQualityOfService: core::ptr::null_mut(),
    };
    // SAFETY: `attributes` and `name` live through the call; `driver_reg_key` is writable.
    unsafe {
        crate::cm::ZwCreateKey(
            driver_reg_key,
            desired_access,
            &raw const attributes,
            0,
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
        )
    }
}

/// [`IoAllocateDriverObjectExtension`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioallocatedriverobjectextension):
/// give a driver object `size` zeroed bytes that the driver finds again
/// by `id`, and that go when the driver object does. A second
/// extension by the same `id` is refused
/// (`STATUS_OBJECT_NAME_COLLISION`).
///
/// # Safety
/// `driver` is a live driver object with its extension; `extension` is
/// writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn IoAllocateDriverObjectExtension(
    driver: *mut DRIVER_OBJECT,
    id: *mut c_void,
    size: u32,
    extension: *mut *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract. The list belongs to the database lock;
    // the block is made before the lock is taken and freed after it is
    // dropped.
    unsafe {
        extension.write(core::ptr::null_mut());
        if size > MAXIMUM_DRIVER_OBJECT_EXTENSION {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let total = size_of::<IO_CLIENT_EXTENSION>() + size as usize;
        let new = pool::alloc_zeroed(total, TAG_EXTENSION).cast::<IO_CLIENT_EXTENSION>();
        if new.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        (*new).ClientIdentificationAddress = id;
        let taken = {
            let _database = device::database();
            let head = &raw mut (*(*driver).DriverExtension).ClientDriverExtension;
            let mut other = head.read();
            while !other.is_null() && (*other).ClientIdentificationAddress != id {
                other = (*other).NextExtension;
            }
            if other.is_null() {
                (*new).NextExtension = head.read();
                head.write(new);
            }
            !other.is_null()
        };
        if taken {
            let _ = pool::free(new.cast());
            return STATUS_OBJECT_NAME_COLLISION;
        }
        extension.write(new.add(1).cast());
    }
    STATUS_SUCCESS
}

/// [`IoGetDriverObjectExtension`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetdriverobjectextension):
/// the extension the driver allocated by `id`, or null.
///
/// # Safety
/// `driver` is a live driver object with its extension.
#[allow(non_snake_case)]
pub unsafe extern "C" fn IoGetDriverObjectExtension(
    driver: *mut DRIVER_OBJECT,
    id: *mut c_void,
) -> *mut c_void {
    // SAFETY: per the contract; the list belongs to the database lock,
    // and an extension stays until the driver object goes.
    unsafe {
        let _database = device::database();
        let mut found = (*(*driver).DriverExtension).ClientDriverExtension;
        while !found.is_null() && (*found).ClientIdentificationAddress != id {
            found = (*found).NextExtension;
        }
        if found.is_null() {
            core::ptr::null_mut()
        } else {
            found.add(1).cast()
        }
    }
}

/// The object manager's call when the last pointer to a driver object
/// has gone: free the extensions the driver allocated for it, and the
/// copy of its file-system filter callbacks
/// (`fsrtl::filter::FsRtlRegisterFileSystemFilterCallbacks`).
///
/// # Safety
/// `body` is a driver object nothing refers to any more.
pub unsafe extern "C" fn deleted(body: *mut c_void) {
    // SAFETY: per the contract; each block came from
    // `IoAllocateDriverObjectExtension`. A driver object made without
    // an extension has none.
    unsafe {
        let extension = (*body.cast::<DRIVER_OBJECT>()).DriverExtension;
        if extension.is_null() {
            return;
        }
        let mut next = (*extension).ClientDriverExtension;
        (*extension).ClientDriverExtension = core::ptr::null_mut();
        while !next.is_null() {
            let this = next;
            next = (*this).NextExtension;
            let _ = pool::free(this.cast());
        }
        let callbacks = (*extension).FsFilterCallbacks;
        (*extension).FsFilterCallbacks = core::ptr::null_mut();
        if !callbacks.is_null() {
            let _ = pool::free(callbacks.cast());
        }
    }
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

/// `DRVO_REINIT_REGISTERED`: the driver has a routine waiting in the
/// reinitialisation queue.
const DRVO_REINIT_REGISTERED: u32 = 0x8;
/// `DRVO_BOOTREINIT_REGISTERED`: the driver has a routine waiting in
/// the boot-reinitialisation queue.
const DRVO_BOOTREINIT_REGISTERED: u32 = 0x20;

/// A routine a driver asked to have called later.
struct Reinitialize {
    driver: *mut DRIVER_OBJECT,
    routine: usize,
    context: usize,
}

// SAFETY: the pointer names a driver object the entry holds a reference
// to; the rest are numbers.
unsafe impl Send for Reinitialize {}

/// The two reinitialisation queues.
struct Queues {
    /// Called once, after every boot driver has initialised.
    boot: Vec<Reinitialize>,
    /// Whether `boot` has been run: a routine registered for it after
    /// that is never called, as on Windows.
    boot_run: bool,
    /// Called at the next of Windows' three points ([`reinitialize_drivers`]).
    later: Vec<Reinitialize>,
}

static REINITIALIZE: SpinLock<Queues> = SpinLock::new(
    Rank::Drivers,
    Queues {
        boot: Vec::new(),
        boot_run: false,
        later: Vec::new(),
    },
);

/// Queue `routine` of `driver` in the boot queue or the other, and mark
/// the driver as having one there.
///
/// # Safety
/// `driver` is a live driver object.
unsafe fn register_reinitialize(
    driver: *mut DRIVER_OBJECT,
    routine: usize,
    context: usize,
    boot: bool,
) {
    let mut queues = REINITIALIZE.lock();
    if boot && queues.boot_run {
        return;
    }
    let queue = if boot {
        &mut queues.boot
    } else {
        &mut queues.later
    };
    // Without memory the routine is not called: Windows drops the
    // registration the same way.
    if queue.try_reserve(1).is_err() {
        return;
    }
    // SAFETY: per the contract; the queue's reference keeps the driver
    // object until its routine has been called.
    unsafe {
        ob::object::reference(driver.cast());
        (*driver).Flags |= if boot {
            DRVO_BOOTREINIT_REGISTERED
        } else {
            DRVO_REINIT_REGISTERED
        };
    }
    queue.push(Reinitialize {
        driver,
        routine,
        context,
    });
}

/// [`IoRegisterBootDriverReinitialization`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ioregisterbootdriverreinitialization):
/// have `routine` called, with `context`, after every boot driver's
/// entry point has run and the devices they serve have been started. A
/// routine may register again from within itself, to be called once
/// more. Registered after the queue has been run, it is not called.
///
/// # Safety
/// `driver` is a live driver object; `routine` is a
/// `DRIVER_REINITIALIZE` routine of that driver.
#[allow(non_snake_case)]
pub unsafe extern "C" fn IoRegisterBootDriverReinitialization(
    driver: *mut DRIVER_OBJECT,
    routine: usize,
    context: usize,
) {
    // SAFETY: per the contract.
    unsafe { register_reinitialize(driver, routine, context, true) }
}

/// [`IoRegisterDriverReinitialization`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-ioregisterdriverreinitialization):
/// have `routine` called, with `context`, at the next of the points
/// [`reinitialize_drivers`] names. A routine that registers again from
/// within itself is called again at the point after.
///
/// # Safety
/// `driver` is a live driver object; `routine` is a
/// `DRIVER_REINITIALIZE` routine of that driver.
#[allow(non_snake_case)]
pub unsafe extern "C" fn IoRegisterDriverReinitialization(
    driver: *mut DRIVER_OBJECT,
    routine: usize,
    context: usize,
) {
    // SAFETY: per the contract.
    unsafe { register_reinitialize(driver, routine, context, false) }
}

/// Call one queued routine: its driver object, its context and the
/// number of times a reinitialisation routine of that driver has now
/// been called. Gives up the queue's reference after.
///
/// # Safety
/// `entry` came out of a queue.
unsafe fn call_reinitialize(entry: Reinitialize, flag: u32) {
    // SAFETY: the queue's reference keeps the driver object; the
    // routine is the driver's, of the documented signature, called at
    // `PASSIVE_LEVEL` in a system thread, where an exception it lets
    // out is unhandled.
    unsafe {
        let extension = (*entry.driver).DriverExtension;
        (*extension).Count += 1;
        let count = (*extension).Count;
        (*entry.driver).Flags &= !flag;
        seh::call(
            entry.routine,
            [entry.driver.addr(), entry.context, count as usize, 0],
            &Guard::Base(Unhandled::SystemThread),
        );
        ob::object::dereference(entry.driver.cast());
    }
}

/// Call the routines boot drivers registered for reinitialisation, in
/// the order registered, those registered meanwhile included, and close
/// the queue.
pub fn reinitialize_boot_drivers() {
    loop {
        let next = {
            let mut queues = REINITIALIZE.lock();
            if queues.boot.is_empty() {
                queues.boot_run = true;
                queues.boot.shrink_to_fit();
                return;
            }
            queues.boot.remove(0)
        };
        // SAFETY: out of the queue.
        unsafe { call_reinitialize(next, DRVO_BOOTREINIT_REGISTERED) };
    }
}

/// Call the routines drivers registered with
/// `IoRegisterDriverReinitialization`, in the order registered. Windows
/// does this at three points, and NK at the same: after a driver is
/// loaded for a device, after one is loaded by `ZwLoadDriver`, and when
/// the system has finished starting. A routine registered while the
/// queue is being called waits for the next point (NK's choice: the
/// documentation promises only "later").
pub fn reinitialize_drivers() {
    let due = core::mem::take(&mut REINITIALIZE.lock().later);
    for entry in due {
        // SAFETY: out of the queue.
        unsafe { call_reinitialize(entry, DRVO_REINIT_REGISTERED) };
    }
}
