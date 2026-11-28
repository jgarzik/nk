//! Tests of the Plug and Play manager, on both architectures: the tree
//! every boot has, and a bus of the test's own under the root.
//!
//! The drivers are here, in Rust, written as WDM drivers are: a bus
//! driver that reports its own device (as the HAL does) and enumerates
//! children on it, a function driver, and two filters. What is under
//! test is the manager's side: what it asks a new device, the key it
//! writes, the driver it finds in the driver database, the order of
//! `AddDevice`, the resources a device is started with, and what
//! happens when a start fails or a device goes.

use crate::arch::InterruptTestSource;
use crate::cm;
use crate::hal::interrupt as routing;
use crate::io::{device, driver, file, irp};
use crate::ke::{thread, time};
use crate::pnp::node::{self, State};
use crate::pnp::root::{complete, complete_unchanged, pool_string, relations_of};
use crate::pnp::{self, query, registry};
use crate::test::{Group, Report};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{
    AtomicBool, AtomicI32, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering,
};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::*;
use nk_ntabi::pnp::*;
use nk_ntabi::status::*;
use nk_pnp::ids;
use nk_pnp::resources::*;

pub static GROUP: Group = Group {
    names: &[
        "pnp.root",
        "pnp.hal-device",
        "pnp.enumerate",
        "pnp.match",
        "pnp.properties",
        "pnp.add-device-order",
        "pnp.start-resources",
        "pnp.dependency",
        "pnp.invalidate-relations",
        "pnp.failed-start",
        "pnp.invalid-instance-id",
        "pnp.interface",
        "pnp.invalidate-state",
        "pnp.removed",
        "pnp.re-enumerated",
    ],
    run,
    manual: false,
};

pub static GROUPS: &[&Group] = &[&GROUP];

const BUS: &str = "NkPnpBus";
const FUNCTION: &str = "NkPnpFn";
const LOWER: &str = "NkPnpLow";
const UPPER: &str = "NkPnpUp";
/// A filter the class names that has neither key nor image.
const ABSENT: &str = "NkPnpNone";

const CLASS: &str = "{4e4b0001-7465-7374-8000-00504e500001}";
const DEVICE_ID: &str = "NKPNP\\DEV";
const HARDWARE_IDS: &str = "NKPNP\\DEV&REV_01\0NKPNP\\DEV\0";
const COMPATIBLE_IDS: &str = "NKPNP\\GENERIC\0NKPNP\\ANY\0";
const DESCRIPTION: &str = "NK test device";
const LOCATION: &str = "slot of the test bus";

const DATABASE: &str = "Machine\\System\\DriverDatabase";
const PACKAGE: &str = "nkpnp.inf_test";

/// The memory the children require: a page each, where nothing is.
const MEMORY: u64 = 0xC_4E4B_0000;
const PAGE: u32 = 0x1000;

/// What a device of the test's is.
#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    /// The bus driver's device on the reported physical device.
    BusFunction = 1,
    /// A child the bus driver enumerates.
    Child,
    /// The function driver's or a filter's device on a child.
    Layer,
}

#[repr(C)]
struct Extension {
    role: Role,
    /// What the device is attached to; null for a child.
    lower: *mut DEVICE_OBJECT,
    /// For a child: which one, from 1. For a layer: its driver, by the
    /// order `AddDevice` should be called in.
    number: u32,
}

/// The children the bus has, and how many of them it reports.
static CHILDREN: [AtomicPtr<DEVICE_OBJECT>; 3] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; 3];
static PRESENT: AtomicU32 = AtomicU32::new(0);
/// The interrupt line the children require; `u32::MAX` for none.
static LINE: AtomicU32 = AtomicU32::new(u32::MAX);
/// Which child's start the function driver fails; 0 for none.
static FAILING: AtomicU32 = AtomicU32::new(0);

/// The calls of `AddDevice`, in order: the layer numbers, a digit each.
static ADDED: AtomicU64 = AtomicU64::new(0);
/// What the function driver was started with, last: the raw memory
/// range's start, the raw interrupt's number, the translated
/// interrupt's vector and level, and the descriptor counts of both
/// lists.
static RAW_MEMORY: AtomicU64 = AtomicU64::new(0);
static RAW_LINE: AtomicU32 = AtomicU32::new(0);
static VECTOR: AtomicU32 = AtomicU32::new(0);
static LEVEL: AtomicU32 = AtomicU32::new(0);
static COUNTS: AtomicU32 = AtomicU32::new(0);
/// What the function driver answers a query for the device's state
/// with: `PNP_DEVICE_STATE` bits.
static DEVICE_STATE: AtomicU32 = AtomicU32::new(0);
/// How many removal requests reached a layer.
static REMOVED: AtomicUsize = AtomicUsize::new(0);

/// # Safety
/// `device` is a device of the test's.
unsafe fn extension(device: *mut DEVICE_OBJECT) -> *mut Extension {
    // SAFETY: per the contract: `make` gave it the extension.
    unsafe { (*device).DeviceExtension.cast() }
}

fn make(
    driver: *mut DRIVER_OBJECT,
    role: Role,
    number: u32,
) -> Result<*mut DEVICE_OBJECT, &'static str> {
    let mut made = core::ptr::null_mut();
    let characteristics = if role == Role::Child { 0x80 } else { 0 };
    // SAFETY: a driver object of the test's; no name; `made` writable.
    let status = unsafe {
        device::IoCreateDevice(
            driver,
            size_of::<Extension>() as u32,
            core::ptr::null(),
            0x22,
            characteristics,
            0,
            &raw mut made,
        )
    };
    if !nt_success(status) {
        return Err("could not create a device of the test's");
    }
    // SAFETY: the device just made and its extension.
    unsafe {
        extension(made).write(Extension {
            role,
            lower: core::ptr::null_mut(),
            number,
        });
    }
    Ok(made)
}

/// `IoSkipCurrentIrpStackLocation` and `IoCallDriver`.
///
/// # Safety
/// `request` is at the location of a device attached to `lower`.
unsafe fn pass_down(lower: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        (*request).CurrentLocation += 1;
        (*request).CurrentStackLocation = (*request).CurrentStackLocation.add(1);
        irp::IofCallDriver(lower, request)
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// The flags of the memory a child requires once its key holds the
/// settings its installation copies there: as pci.sys builds other
/// requirements for a device whose `Device Parameters` allow messages.
const INSTALLED_FLAGS: u16 = 0x80;

/// Whether the child `device` has been installed: its key holds the
/// device settings of the driver database's configuration.
fn settings_installed(device: *mut DEVICE_OBJECT) -> bool {
    node::get(device as usize).is_some_and(|found| {
        let key = registry::enum_key(&found.instance);
        !found.instance.is_empty()
            && registry::dword(&format!("{key}\\Device Parameters\\Settings"), "Depth") == Some(7)
    })
}

/// What a child requires: a page of memory at a place of its own, and
/// the test's interrupt line, shared. The memory's flags say whether
/// the child was `installed` when it was asked.
fn child_requirements(number: u32, installed: bool) -> Requirements {
    let at = MEMORY + u64::from(number) * u64::from(PAGE);
    let mut descriptors = alloc::vec![IoDescriptor::range(
        0,
        TYPE_MEMORY,
        1,
        if installed { INSTALLED_FLAGS } else { 0 },
        Wanted {
            length: u64::from(PAGE),
            alignment: u64::from(PAGE),
            minimum: at,
            maximum: at + u64::from(PAGE) - 1
        }
    )];
    let line = LINE.load(Ordering::Acquire);
    if line != u32::MAX {
        descriptors.push(IoDescriptor::interrupt(0, SHARE_SHARED, 0, line, line));
    }
    Requirements {
        interface: 0,
        bus: 0,
        slot: number,
        lists: alloc::vec![IoList {
            version: 1,
            revision: 1,
            descriptors,
        }],
    }
}

/// Complete `request` with a block the manager frees, or for want of
/// memory.
///
/// # Safety
/// `request` is an IRP its caller owns.
unsafe fn answer(request: *mut IRP, block: usize) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        match block {
            0 => complete(request, STATUS_INSUFFICIENT_RESOURCES, 0),
            block => complete(request, STATUS_SUCCESS, block),
        }
    }
}

/// A child's answers: what a bus driver answers for its device.
///
/// # Safety
/// `request` is a Plug and Play IRP at the child's location.
unsafe fn child_pnp(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let number = (*extension(device)).number;
        let location = (*request).CurrentStackLocation;
        let parameters = (*location).Parameters;
        match (*location).MinorFunction {
            IRP_MN_QUERY_ID => {
                let text = match parameters[0] as u32 {
                    BUS_QUERY_DEVICE_ID => wide(DEVICE_ID),
                    // The third child's would name a key below another
                    // device's: not an instance identifier.
                    BUS_QUERY_INSTANCE_ID if number == 3 => wide("1\\Control"),
                    BUS_QUERY_INSTANCE_ID => wide(&format!("{number}")),
                    BUS_QUERY_HARDWARE_IDS => wide(HARDWARE_IDS),
                    BUS_QUERY_COMPATIBLE_IDS => wide(COMPATIBLE_IDS),
                    _ => return complete_unchanged(request),
                };
                answer(request, pool_string(&text))
            }
            IRP_MN_QUERY_DEVICE_TEXT => {
                let text = match parameters[0] as u32 {
                    DEVICE_TEXT_DESCRIPTION => wide(DESCRIPTION),
                    DEVICE_TEXT_LOCATION_INFORMATION => wide(LOCATION),
                    _ => return complete_unchanged(request),
                };
                answer(request, pool_string(&text))
            }
            IRP_MN_QUERY_CAPABILITIES => {
                let capabilities = parameters[0] as *mut DEVICE_CAPABILITIES;
                (&raw mut (*capabilities).Flags).write(DEVICE_CAPABILITY_SILENT_INSTALL);
                (&raw mut (*capabilities).Address).write(number);
                complete(request, STATUS_SUCCESS, 0)
            }
            IRP_MN_QUERY_RESOURCE_REQUIREMENTS => {
                let bytes = child_requirements(number, settings_installed(device)).to_bytes();
                let block = crate::mm::pool::alloc(bytes.len(), pnp::TAG);
                if !block.is_null() {
                    block.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len());
                }
                answer(request, block as usize)
            }
            IRP_MN_START_DEVICE => complete(request, STATUS_SUCCESS, 0),
            IRP_MN_SURPRISE_REMOVAL => complete(request, STATUS_SUCCESS, 0),
            IRP_MN_QUERY_DEVICE_RELATIONS if parameters[0] as u32 == TARGET_DEVICE_RELATION => {
                // `relations_of` references each reported device for the caller.
                answer(request, relations_of(&[device as usize]))
            }
            IRP_MN_REMOVE_DEVICE => {
                // A device the bus no longer has goes for good.
                let gone = PRESENT.load(Ordering::Acquire) < number;
                let status = complete(request, STATUS_SUCCESS, 0);
                if gone {
                    CHILDREN[number as usize - 1].store(core::ptr::null_mut(), Ordering::Release);
                    device::IoDeleteDevice(device);
                }
                status
            }
            _ => complete_unchanged(request),
        }
    }
}

/// The function driver records what it is started with.
///
/// # Safety
/// `parameters` are those of a start request.
unsafe fn record_start(parameters: [u64; 4]) {
    // SAFETY: per the contract: two resource lists, or null.
    let lists = unsafe {
        [parameters[0], parameters[1]].map(|list| {
            (list != 0)
                .then(|| query::resource_list_at(list as usize))
                .flatten()
                .and_then(|bytes| ResourceList::parse(&bytes))
                .map(|(list, _)| list)
                .unwrap_or_default()
        })
    };
    let [raw, translated] = lists;
    COUNTS.store(
        (raw.partials().count() as u32) << 16 | translated.partials().count() as u32,
        Ordering::Release,
    );
    for partial in raw.partials() {
        if let Some((start, _)) = partial.as_range() {
            RAW_MEMORY.store(start, Ordering::Release);
        }
        if let Some((_, _, vector, _)) = partial.as_interrupt() {
            RAW_LINE.store(vector, Ordering::Release);
        }
    }
    for partial in translated.partials() {
        if let Some((level, _, vector, _)) = partial.as_interrupt() {
            VECTOR.store(vector, Ordering::Release);
            LEVEL.store(u32::from(level), Ordering::Release);
        }
    }
}

/// Pass open/cleanup/close requests down the test stack, completing at the PDO.
///
/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn dispatch_file(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: live IRP at this device's stack location.
    unsafe {
        let own = extension(device);
        if matches!((*own).role, Role::Child | Role::BusFunction) {
            return complete(request, STATUS_SUCCESS, 0);
        }
        let lower = (*own).lower;
        (*request).CurrentLocation += 1;
        (*request).CurrentStackLocation = (*request).CurrentStackLocation.add(1);
        irp::IofCallDriver(lower, request)
    }
}

/// The one dispatch routine of the test's drivers, for Plug and Play
/// requests.
///
/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn dispatch(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: a live request at the location of a device of the test's.
    unsafe {
        let own = extension(device);
        let location = (*request).CurrentStackLocation;
        let minor = (*location).MinorFunction;
        let parameters = (*location).Parameters;
        let lower = (*own).lower;
        match (*own).role {
            Role::Child => child_pnp(device, request),
            Role::BusFunction => {
                if minor == IRP_MN_QUERY_DEVICE_RELATIONS && parameters[0] as u32 == BUS_RELATIONS {
                    let present = PRESENT.load(Ordering::Acquire) as usize;
                    let children: Vec<usize> = CHILDREN[..present]
                        .iter()
                        .map(|child| child.load(Ordering::Acquire) as usize)
                        .collect();
                    match relations_of(&children) {
                        0 => return complete(request, STATUS_INSUFFICIENT_RESOURCES, 0),
                        list => {
                            (*request).IoStatus.Status = STATUS_SUCCESS;
                            (*request).IoStatus.Information = list;
                        }
                    }
                }
                pass_down(lower, request)
            }
            Role::Layer => {
                if minor == IRP_MN_START_DEVICE && (*own).number == 2 {
                    let child = crate::ob::object::ObRef::adopt(
                        device::IoGetDeviceAttachmentBaseRef(device).cast(),
                    );
                    let number = (*extension(child.cast())).number;
                    drop(child);
                    if number == FAILING.load(Ordering::Acquire) {
                        return complete(request, STATUS_DEVICE_NOT_READY, 0);
                    }
                    record_start(parameters);
                    (*request).IoStatus.Status = STATUS_SUCCESS;
                }
                if minor == IRP_MN_QUERY_PNP_DEVICE_STATE && (*own).number == 2 {
                    (*request).IoStatus.Status = STATUS_SUCCESS;
                    (*request).IoStatus.Information = DEVICE_STATE.load(Ordering::Acquire) as usize;
                }
                if minor == IRP_MN_REMOVE_DEVICE {
                    REMOVED.fetch_add(1, Ordering::AcqRel);
                    (*request).IoStatus.Status = STATUS_SUCCESS;
                    let status = pass_down(lower, request);
                    device::IoDetachDevice(lower);
                    device::IoDeleteDevice(device);
                    return status;
                }
                pass_down(lower, request)
            }
        }
    }
}

/// `AddDevice` of the function driver and the filters: a device of the
/// driver's on top of the stack.
///
/// # Safety
/// Called as an `AddDevice` routine.
unsafe extern "C" fn add_device(driver: *mut DRIVER_OBJECT, pdo: *mut DEVICE_OBJECT) -> NTSTATUS {
    // The driver's number is in its extension's count, which nothing
    // else uses for a driver that is part of the kernel.
    // SAFETY: a driver object of the test's.
    let number = unsafe { (*(*driver).DriverExtension).Count };
    ADDED.store(
        ADDED.load(Ordering::Acquire) * 10 + u64::from(number),
        Ordering::Release,
    );
    let Ok(made) = make(driver, Role::Layer, number) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: the device just made, and the physical device object the
    // manager passed.
    unsafe {
        let lower = device::IoAttachDeviceToDeviceStack(made, pdo);
        if lower.is_null() {
            device::IoDeleteDevice(made);
            return STATUS_NO_SUCH_DEVICE;
        }
        (*extension(made)).lower = lower;
        (*made).Flags &= !DO_DEVICE_INITIALIZING;
    }
    STATUS_SUCCESS
}

/// The registry the test writes: the class with its filters, and the
/// driver database's record for the children's second compatible...
/// first compatible identifier.
fn write_registry() -> Result<(), &'static str> {
    let sz = |text: &str| ids::sz(text);
    let multi = |strings: &[&str]| -> Vec<u8> {
        ids::to_multi_sz(strings)
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    let mut version = alloc::vec![0xFFu8, 0xFF, 9, 0, 0, 0, 0, 0];
    version.extend_from_slice(&ids::guid_from_text(CLASS).ok_or("the class is not a GUID")?);
    let package = format!("{DATABASE}\\DriverPackages\\{PACKAGE}");
    let configuration = format!("{package}\\Configurations\\NkInstall");
    type Values = Vec<(&'static str, u32, Vec<u8>)>;
    let writes: [(String, Values); 7] = [
        (
            registry::class_key(CLASS),
            alloc::vec![
                ("Class", 1, sz("NkPnpTest")),
                ("LowerFilters", 7, multi(&[ABSENT, LOWER])),
                ("UpperFilters", 7, multi(&[UPPER])),
            ],
        ),
        (
            format!("{DATABASE}\\DeviceIds\\NKPNP\\GENERIC"),
            alloc::vec![("nkpnp.inf", 3, alloc::vec![1, 0xFF, 0, 0])],
        ),
        (
            format!("{DATABASE}\\DriverInfFiles\\nkpnp.inf"),
            alloc::vec![("Active", 1, sz(PACKAGE))],
        ),
        (
            package.clone(),
            alloc::vec![("Version", 3, version), ("Provider", 1, sz("NK"))],
        ),
        (
            format!("{package}\\Descriptors\\NKPNP\\GENERIC"),
            alloc::vec![
                ("Configuration", 1, sz("NkInstall")),
                ("Description", 1, sz("%nkpnp.desc%")),
                ("Manufacturer", 1, sz("%nk%")),
            ],
        ),
        (
            configuration.clone(),
            alloc::vec![("Service", 1, sz(FUNCTION))],
        ),
        (
            format!("{configuration}\\Device\\Settings"),
            alloc::vec![("Depth", 4, alloc::vec![7, 0, 0, 0])],
        ),
    ];
    for (key, values) in &writes {
        let values: Vec<(&str, u32, &[u8])> = values
            .iter()
            .map(|(name, kind, data)| (*name, *kind, &data[..]))
            .collect();
        cm::write_path(key, &values).map_err(|_| "the test's registry could not be written")?;
    }
    Ok(())
}

/// Delete every key the test and the manager wrote for it.
fn delete_registry(bus_prefix: Option<&str>) {
    let control_set = "Machine\\System\\CurrentControlSet";
    for key in [
        registry::class_key(CLASS),
        format!("{DATABASE}\\DeviceIds\\NKPNP"),
        format!("{DATABASE}\\DriverInfFiles\\nkpnp.inf"),
        format!("{DATABASE}\\DriverPackages\\{PACKAGE}"),
        format!("{control_set}\\Enum\\ROOT\\{BUS}"),
        format!("{control_set}\\Enum\\NKPNP"),
        format!("{control_set}\\Control\\DeviceClasses\\{CLASS}"),
        registry::service_key(FUNCTION),
    ] {
        let _ = cm::delete_tree(&key);
    }
    if bus_prefix.is_some() {
        let hash = ids::parent_hash(&format!("ROOT\\{BUS}\\0000"));
        cm::delete_value(
            &format!("{control_set}\\Enum"),
            &ids::next_parent_id_value(1, hash),
        );
    }
}

/// The drivers, the bus's devices and the registry of the test, taken
/// down when this goes.
struct Bench {
    drivers: Vec<*mut DRIVER_OBJECT>,
    reported: *mut DEVICE_OBJECT,
    function: *mut DEVICE_OBJECT,
}

impl Bench {
    fn new() -> Result<Self, &'static str> {
        let mut bench = Bench {
            drivers: Vec::new(),
            reported: core::ptr::null_mut(),
            function: core::ptr::null_mut(),
        };
        ADDED.store(0, Ordering::Release);
        REMOVED.store(0, Ordering::Release);
        FAILING.store(0, Ordering::Release);
        DEVICE_STATE.store(0, Ordering::Release);
        PRESENT.store(0, Ordering::Release);
        let line = InterruptTestSource::find().map_or(u32::MAX, |source| source.line().gsi);
        LINE.store(line, Ordering::Release);
        write_registry()?;
        for (number, name) in [(0, BUS), (1, LOWER), (2, FUNCTION), (3, UPPER)] {
            let made = driver::builtin(name, |object| {
                // SAFETY: the driver object being set up.
                unsafe {
                    (*object).MajorFunction[usize::from(IRP_MJ_PNP)] = Some(dispatch);
                    (*object).MajorFunction[usize::from(IRP_MJ_CREATE)] = Some(dispatch_file);
                    (*object).MajorFunction[usize::from(IRP_MJ_CLEANUP)] = Some(dispatch_file);
                    (*object).MajorFunction[usize::from(IRP_MJ_CLOSE)] = Some(dispatch_file);
                    let extension = (*object).DriverExtension;
                    (*extension).Count = number;
                    if number != 0 {
                        (*extension).AddDevice = add_device as PVOID;
                    }
                }
            })
            .map_err(|_| "a driver object of the test's could not be made")?;
            bench.drivers.push(made);
        }
        let bus = bench.drivers[0];
        for (at, slot) in CHILDREN.iter().enumerate() {
            let child = make(bus, Role::Child, at as u32 + 1)?;
            // SAFETY: the device just made.
            unsafe { (*child).Flags &= !DO_DEVICE_INITIALIZING };
            slot.store(child, Ordering::Release);
        }
        bench.reported = pnp::report_detected_device(BUS, Some("Internal"))
            .map_err(|_| "the bus's device could not be reported")?;
        bench.function = make(bus, Role::BusFunction, 0)?;
        // SAFETY: devices just made: the bus driver attaches to the
        // device it reported, as a driver's `AddDevice` would.
        unsafe {
            let lower = device::IoAttachDeviceToDeviceStack(bench.function, bench.reported);
            if lower.is_null() {
                return Err("the bus's device could not be attached");
            }
            (*extension(bench.function)).lower = lower;
            (*bench.function).Flags &= !DO_DEVICE_INITIALIZING;
        }
        Ok(bench)
    }

    /// Have the bus report `count` children, and tell the manager.
    fn report(&self, count: u32) {
        PRESENT.store(count, Ordering::Release);
        // SAFETY: the device the bus reported.
        unsafe { pnp::export::IoInvalidateDeviceRelations(self.reported, BUS_RELATIONS) };
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let prefix = node::with(self.reported as usize, |node| node.child_prefix.clone()).flatten();
        // The bus loses its children, then its own devices go.
        if !self.reported.is_null() {
            self.report(0);
            pnp::settle();
        }
        // SAFETY: devices of the test's: the bus's function device is
        // detached and deleted before the device it reported is taken
        // back; a child the manager never saw is the bus driver's to
        // delete.
        unsafe {
            if !self.function.is_null() {
                let lower = (*extension(self.function)).lower;
                if !lower.is_null() {
                    device::IoDetachDevice(lower);
                }
                device::IoDeleteDevice(self.function);
            }
            if !self.reported.is_null() {
                pnp::remove_reported_device(self.reported);
            }
            for slot in &CHILDREN {
                let child = slot.swap(core::ptr::null_mut(), Ordering::AcqRel);
                if !child.is_null() {
                    device::IoDeleteDevice(child);
                }
            }
        }
        for made in self.drivers.drain(..) {
            driver::remove_builtin(made);
        }
        delete_registry(prefix.as_deref());
    }
}

/// The node of the test's child `number`.
fn child(number: usize) -> Option<node::Node> {
    node::get(CHILDREN[number - 1].load(Ordering::Acquire) as usize)
}

/// The root of the tree: `HTREE\ROOT\0`, started, with its key and the
/// manager's driver.
fn root() -> Result<(), &'static str> {
    let root = pnp::root::root();
    let found = node::get(root as usize).ok_or("the root device has no node")?;
    if found.instance != "HTREE\\ROOT\\0" || found.state != State::Started || found.level != 0 {
        return Err("the root is not HTREE\\ROOT\\0, started, at depth 0");
    }
    if driver::running("PnpManager").is_none() {
        return Err("there is no \\Driver\\PnpManager");
    }
    // Windows' values of the root's key.
    let key = registry::enum_key("HTREE\\ROOT\\0");
    if registry::dword(&key, "Capabilities") != Some(0x70)
        || registry::dword(&key, "ConfigFlags") != Some(0)
        || registry::dword(&key, "UINumber") != Some(0)
    {
        return Err("the root's key does not hold Windows' values");
    }
    Ok(())
}

/// The HAL's device and its child, as Windows has them.
fn hal_device() -> Result<(), &'static str> {
    let hal = node::by_instance("ROOT\\ACPI_HAL\\0000")
        .and_then(node::get)
        .ok_or("there is no ROOT\\ACPI_HAL\\0000")?;
    if hal.state != State::Started || !hal.reported || hal.parent != pnp::root::root() as usize {
        return Err("the HAL's device is not a started, reported child of the root");
    }
    let key = registry::enum_key(&hal.instance);
    if registry::dword(&key, "DeviceReported") != Some(1)
        || registry::string(&key, "Service").as_deref() != Some("\\Driver\\ACPI_HAL")
        || registry::strings(&key, "CompatibleIDs")
            != ["DETECTEDInternal\\ACPI_HAL", "DETECTED\\ACPI_HAL"]
    {
        return Err("the HAL's device's key does not hold what Windows' report writes");
    }
    // SAFETY: the tree's device.
    let stack = unsafe { pnp::engine::stack_drivers(hal.pdo as *mut DEVICE_OBJECT) };
    if stack != ["\\Driver\\ACPI_HAL", "\\Driver\\PnpManager"] {
        return Err("the HAL's device's stack is not ACPI_HAL on PnpManager");
    }
    let acpi = node::by_instance("ACPI_HAL\\PNP0C08\\0")
        .and_then(node::get)
        .ok_or("there is no ACPI_HAL\\PNP0C08\\0")?;
    if acpi.parent != hal.pdo
        || acpi.level != 2
        || acpi.hardware_ids != ["ACPI_HAL\\PNP0C08", "*PNP0C08"]
        || !acpi.compatible_ids.is_empty()
    {
        return Err("the ACPI device is not the HAL's child with Windows' identifiers");
    }
    let key = registry::enum_key(&acpi.instance);
    if registry::dword(&key, "Capabilities") != Some(0x30)
        || registry::strings(&key, "HardwareID") != ["ACPI_HAL\\PNP0C08", "*PNP0C08"]
    {
        return Err("the ACPI device's key does not hold Windows' values");
    }
    Ok(())
}

/// A child the bus reports is asked who it is and gets Windows' kind
/// of instance path and key.
fn enumerate(bench: &Bench) -> Result<(), &'static str> {
    let found = child(1).ok_or("the bus's child has no node")?;
    let bus = format!("ROOT\\{BUS}\\0000");
    let prefix = ids::parent_id_prefix(1, ids::parent_hash(&bus), 0);
    if found.instance != format!("{DEVICE_ID}\\{prefix}&1") {
        return Err("the child's instance path is not its parent's prefix and its own number");
    }
    if registry::string(&registry::enum_key(&bus), "ParentIdPrefix").as_deref() != Some(&prefix) {
        return Err("the bus's key does not hold the prefix");
    }
    if found.parent != bench.reported as usize || found.level != 2 {
        return Err("the child is not below the bus's device");
    }
    if found.hardware_ids != ["NKPNP\\DEV&REV_01", "NKPNP\\DEV"]
        || found.compatible_ids != ["NKPNP\\GENERIC", "NKPNP\\ANY"]
        || found.description.as_deref() != Some(DESCRIPTION)
        || found.address != 1
    {
        return Err("the node does not hold what the bus driver answered");
    }
    let key = registry::enum_key(&found.instance);
    if registry::strings(&key, "HardwareID") != found.hardware_ids
        || registry::strings(&key, "CompatibleIDs") != found.compatible_ids
        || registry::dword(&key, "Capabilities") != Some(0x20)
        || registry::string(&key, "LocationInformation").as_deref() != Some(LOCATION)
        || registry::string(&key, "ContainerID").is_none()
    {
        return Err("the child's key does not hold its identity");
    }
    match cm::read(&format!("{key}\\LogConf"), "BasicConfigVector") {
        // Asked again once installed, when its settings were there.
        Ok((10, bytes)) if bytes == child_requirements(1, true).to_bytes() => {}
        _ => return Err("LogConf\\BasicConfigVector is not the child's requirements as installed"),
    }
    if found.requirements != child_requirements(1, true).to_bytes() {
        return Err("the node does not hold the requirements the installed device states");
    }
    // SAFETY: the tree's device.
    let flags = unsafe { (*(found.pdo as *mut DEVICE_OBJECT)).Flags };
    if flags & 0x1000 == 0 {
        return Err("the child is not marked DO_BUS_ENUMERATED_DEVICE");
    }
    Ok(())
}

/// The driver database's record for the child's first compatible
/// identifier was applied: the values device installation writes.
fn matched() -> Result<(), &'static str> {
    let found = child(1).ok_or("the bus's child has no node")?;
    let key = registry::enum_key(&found.instance);
    if registry::string(&key, "Service").as_deref() != Some(FUNCTION)
        || registry::string(&key, "ClassGUID").as_deref() != Some(CLASS)
        || registry::dword(&key, "ConfigFlags") != Some(0)
    {
        return Err("the child's key does not name the service and the class of the record");
    }
    if registry::string(&key, "DeviceDesc").as_deref()
        != Some("@nkpnp.inf,%nkpnp.desc%;NK test device")
    {
        return Err("DeviceDesc does not name the INF's string");
    }
    let driver = registry::string(&key, "Driver").ok_or("the child has no driver key")?;
    if driver != format!("{CLASS}\\0000") {
        return Err("the driver key is not the class's first");
    }
    let driver_key = format!("Machine\\System\\CurrentControlSet\\Control\\Class\\{driver}");
    if registry::string(&driver_key, "InfPath").as_deref() != Some("nkpnp.inf")
        || registry::string(&driver_key, "InfSection").as_deref() != Some("NkInstall")
        || registry::string(&driver_key, "MatchingDeviceId").as_deref() != Some("nkpnp\\generic")
    {
        return Err("the driver key does not say what was installed");
    }
    if registry::dword(&format!("{key}\\Device Parameters\\Settings"), "Depth") != Some(7) {
        return Err("the configuration's device settings were not copied");
    }
    if found.service.as_deref() != Some(FUNCTION) || found.class.as_deref() != Some(CLASS) {
        return Err("the node does not name the service and the class");
    }
    Ok(())
}

/// One property of a device, as a driver asks for it: the status, the
/// length reported, and the bytes.
fn property_of(device: *mut DEVICE_OBJECT, which: u32, room: usize) -> (NTSTATUS, u32, Vec<u8>) {
    let mut buffer = alloc::vec![0xEEu8; room];
    let mut length = 0xEEEE_EEEE;
    // SAFETY: a live device object, a buffer of `room` bytes and a
    // length to write.
    let status = unsafe {
        pnp::export::IoGetDeviceProperty(
            device,
            which,
            room as u32,
            buffer.as_mut_ptr(),
            &raw mut length,
        )
    };
    buffer.truncate((length as usize).min(room));
    (status, length, buffer)
}

/// `IoGetDeviceProperty` and `IoOpenDeviceRegistryKey` on the started
/// child: what the node and the key hold, by the rules of the
/// routines.
fn properties(bench: &Bench) -> Result<(), &'static str> {
    let found = child(1).ok_or("the bus's child has no node")?;
    let pdo = found.pdo as *mut DEVICE_OBJECT;
    let multi = |strings: &[&str]| -> Vec<u8> {
        ids::to_multi_sz(strings)
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect()
    };
    // DevicePropertyHardwareID (1), with room and without.
    let hardware = multi(&["NKPNP\\DEV&REV_01", "NKPNP\\DEV"]);
    if property_of(pdo, 1, 256) != (STATUS_SUCCESS, hardware.len() as u32, hardware.clone()) {
        return Err("the hardware identifiers are not the property's value");
    }
    let (status, length, bytes) = property_of(pdo, 1, 4);
    if status != STATUS_BUFFER_TOO_SMALL || length != hardware.len() as u32 || bytes != [0xEE; 4] {
        return Err("a buffer too small was not refused with the length needed, untouched");
    }
    // The description is the text behind the INF's token (0); the
    // enumerator (15) the first part of the instance path; the address
    // (16) what the bus driver said; the class (5, 6) what was
    // installed; no removal is expected (19: 1).
    let expected: [(u32, Vec<u8>); 6] = [
        (0, ids::sz(DESCRIPTION)),
        (15, ids::sz("NKPNP")),
        (16, 1u32.to_le_bytes().to_vec()),
        (5, ids::sz("NkPnpTest")),
        (6, ids::sz(CLASS)),
        (19, 1u32.to_le_bytes().to_vec()),
    ];
    for (which, value) in expected {
        if property_of(pdo, which, 256) != (STATUS_SUCCESS, value.len() as u32, value) {
            kprintln!("pnp: property {which} is not as expected");
            return Err("a property does not hold the device's value");
        }
    }
    // The device has a name the I/O manager made (11).
    let (status, _, name) = property_of(pdo, 11, 256);
    if status != STATUS_SUCCESS || !ids::from_sz(&name).starts_with("\\Device\\") {
        return Err("the physical device object's name is not a name in \\Device");
    }
    // The bus driver gave no bus information (12), and a friendly name
    // (9) nobody wrote: not found. Property 23 does not exist, and the
    // translated boot configuration (4) is not kept.
    for (which, status) in [
        (12, STATUS_OBJECT_NAME_NOT_FOUND),
        (9, STATUS_OBJECT_NAME_NOT_FOUND),
        (23, STATUS_INVALID_PARAMETER_2),
        (4, STATUS_INVALID_PARAMETER_2),
    ] {
        if property_of(pdo, which, 256) != (status, 0, Vec::new()) {
            return Err("a property the device lacks was not refused as Windows refuses it");
        }
    }
    // A device that is not a physical device object has no properties.
    if property_of(bench.function, 1, 256).0 != STATUS_INVALID_DEVICE_REQUEST {
        return Err("a function device object was taken for a physical one");
    }
    // A property a driver gives the device is kept, with its type, in
    // the device's key where Windows keeps it, and comes back; taken
    // away, it is not found.
    let category = ids::guid_from_text(CLASS).ok_or("the class is not a GUID")?;
    let name = DEVPROPKEY {
        fmtid: category,
        pid: 12,
    };
    let get = |room: usize| {
        let mut buffer = alloc::vec![0xEEu8; room];
        let (mut length, mut kind) = (0xEEEE_EEEE, 0xEEEE_EEEE);
        // SAFETY: a live device object, a key, a buffer of `room`
        // bytes, and two numbers to write.
        let status = unsafe {
            pnp::export::IoGetDevicePropertyData(
                pdo,
                &raw const name,
                0,
                0,
                room as u32,
                buffer.as_mut_ptr(),
                &raw mut length,
                &raw mut kind,
            )
        };
        (status, length, kind, buffer)
    };
    let set = |kind: u32, value: &[u8]| {
        // SAFETY: as above; the value is readable.
        unsafe {
            pnp::export::IoSetDevicePropertyData(
                pdo,
                &raw const name,
                0,
                1,
                kind,
                value.len() as u32,
                value.as_ptr(),
            )
        }
    };
    if get(8) != (STATUS_OBJECT_NAME_NOT_FOUND, 0, 0, alloc::vec![0xEE; 8]) {
        return Err("a property nobody set was found");
    }
    // `DEVPROP_TYPE_UINT32` is 7.
    if set(7, &0x1234_5678u32.to_le_bytes()) != STATUS_SUCCESS {
        return Err("a property could not be set");
    }
    let stored = format!(
        "{key}\\Properties\\{CLASS}\\000C",
        key = registry::enum_key(&found.instance)
    );
    if cm::read(&stored, "") != Ok((0xFFFF_0007, 0x1234_5678u32.to_le_bytes().to_vec())) {
        return Err("the property is not kept where Windows keeps it");
    }
    if get(4) != (STATUS_SUCCESS, 4, 7, 0x1234_5678u32.to_le_bytes().to_vec()) {
        return Err("the property did not come back with its type and size");
    }
    if get(3) != (STATUS_BUFFER_TOO_SMALL, 4, 7, alloc::vec![0xEE; 3]) {
        return Err("a buffer too small was not refused with the size needed");
    }
    if set(0, &[]) != STATUS_SUCCESS || get(8).0 != STATUS_OBJECT_NAME_NOT_FOUND {
        return Err("a property taken away is still found");
    }
    // The system's configuration information is one structure, of the
    // version Windows' has, for drivers to count in.
    let configuration = pnp::export::IoGetConfigurationInformation();
    // SAFETY: the structure the routine hands out, the test's to read
    // and write as a driver's is.
    unsafe {
        if configuration != pnp::export::IoGetConfigurationInformation()
            || (*configuration).Version != 0x28
        {
            return Err("the configuration information is not one structure of version 0x28");
        }
        let disks = (*configuration).DiskCount;
        (*configuration).DiskCount = disks + 1;
        if (*pnp::export::IoGetConfigurationInformation()).DiskCount != disks + 1 {
            return Err("a count written through the pointer did not stay");
        }
        (*configuration).DiskCount = disks;
    }
    // The device key and the driver key open; the device key is the one
    // the settings were copied into.
    let key = registry::enum_key(&found.instance);
    let parameters = format!("{key}\\Device Parameters");
    let before = cm::open_count(&parameters).ok_or("there is no Device Parameters key")?;
    for (kind, path) in [(1, parameters.clone()), (2, driver_key_of(&key)?)] {
        let mut handle = core::ptr::null_mut();
        // SAFETY: a live device object and a handle to write.
        let status =
            unsafe { pnp::export::IoOpenDeviceRegistryKey(pdo, kind, 0x2_0019, &raw mut handle) };
        if status != STATUS_SUCCESS || handle.is_null() {
            return Err("a key of the device did not open");
        }
        let opened = cm::open_count(&path);
        crate::ob::handle::close(handle as u64);
        if opened.is_none_or(|count| count == 0) || cm::open_count(&path) >= opened {
            return Err("the handle is not one to the device's key");
        }
    }
    if cm::open_count(&parameters) != Some(before) {
        return Err("a handle to the device key was left open");
    }
    let mut handle = core::ptr::null_mut();
    // SAFETY: as above.
    let status = unsafe {
        pnp::export::IoOpenDeviceRegistryKey(bench.function, 1, 0x2_0019, &raw mut handle)
    };
    if status != STATUS_INVALID_DEVICE_REQUEST || !handle.is_null() {
        return Err("a key was opened for a device that is not a physical device object");
    }
    Ok(())
}

/// The driver key the device's key names, from the registry's root.
fn driver_key_of(key: &str) -> Result<String, &'static str> {
    let driver = registry::string(key, "Driver").ok_or("the child has no driver key")?;
    Ok(format!(
        "Machine\\System\\CurrentControlSet\\Control\\Class\\{driver}"
    ))
}

/// What the notification callback saw: arrivals and removals of the
/// test's interface, and whether each came with the link's name and
/// the context registered.
static ARRIVALS: AtomicU32 = AtomicU32::new(0);
static REMOVALS: AtomicU32 = AtomicU32::new(0);
static NOTIFIED_WRONG: AtomicU32 = AtomicU32::new(0);
/// The link the callback expects, as UTF-16 in a block of the test's.
static EXPECTED_LINK: AtomicPtr<Vec<u16>> = AtomicPtr::new(core::ptr::null_mut());
const NOTIFY_CONTEXT: usize = 0x4E4B_504E;

/// The notification callback of the test.
///
/// # Safety
/// Called as a notification callback for interface changes.
unsafe extern "C" fn notified(
    structure: *const DEVICE_INTERFACE_CHANGE_NOTIFICATION,
    context: usize,
) -> NTSTATUS {
    // SAFETY: the structure of an interface change, valid during the
    // call; the expected name is the test's, set before any call.
    unsafe {
        let name = crate::rtl::copy_unicode((*structure).SymbolicLinkName);
        let expected = &*EXPECTED_LINK.load(Ordering::Acquire);
        let class = ids::guid_from_text(CLASS);
        if context != NOTIFY_CONTEXT
            || name != *expected
            || (*structure).Version != 1
            || usize::from((*structure).Size) != size_of::<DEVICE_INTERFACE_CHANGE_NOTIFICATION>()
            || Some((*structure).InterfaceClassGuid) != class
            || crate::ke::irql::current() != 0
        {
            NOTIFIED_WRONG.fetch_add(1, Ordering::AcqRel);
        }
        match (*structure).Event {
            GUID_DEVICE_INTERFACE_ARRIVAL => ARRIVALS.fetch_add(1, Ordering::AcqRel),
            GUID_DEVICE_INTERFACE_REMOVAL => REMOVALS.fetch_add(1, Ordering::AcqRel),
            _ => NOTIFIED_WRONG.fetch_add(1, Ordering::AcqRel),
        };
    }
    STATUS_SUCCESS
}

/// A device interface of the started child: registered under Windows'
/// name and key, enabled and disabled, with a registered callback told
/// of each.
fn interface(bench: &Bench) -> Result<(), &'static str> {
    use pnp::interface::{IoRegisterDeviceInterface, IoSetDeviceInterfaceState};
    use pnp::notify::{IoRegisterPlugPlayNotification, IoUnregisterPlugPlayNotificationEx};
    let found = child(1).ok_or("the bus's child has no node")?;
    let pdo = found.pdo as *mut DEVICE_OBJECT;
    let class = ids::guid_from_text(CLASS).ok_or("the class is not a GUID")?;
    let expected = format!("\\??\\{}#{CLASS}", found.instance.replace('\\', "#"));
    let mut wide_link: Vec<u16> = expected.encode_utf16().collect();
    EXPECTED_LINK.store(&raw mut wide_link, Ordering::Release);
    for counter in [&ARRIVALS, &REMOVALS, &NOTIFIED_WRONG] {
        counter.store(0, Ordering::Release);
    }
    let mut name = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: core::ptr::null_mut(),
    };
    let register = |device, name: *mut UNICODE_STRING| {
        // SAFETY: a live device object, a GUID, no reference string and
        // a string to write.
        unsafe { IoRegisterDeviceInterface(device, &raw const class, core::ptr::null(), name) }
    };
    if register(bench.function, &raw mut name) != STATUS_INVALID_DEVICE_REQUEST {
        return Err("an interface was registered for a function device object");
    }
    if register(pdo, &raw mut name) != STATUS_SUCCESS {
        return Err("the interface was not registered");
    }
    // SAFETY: the string the registration handed out.
    let link = String::from_utf16_lossy(&unsafe { crate::rtl::copy_unicode(&raw const name) });
    let result = (|| {
        if link != expected {
            return Err("the link's name is not the device's path and the class");
        }
        let mut again = UNICODE_STRING { ..name };
        if register(pdo, &raw mut again) != STATUS_OBJECT_NAME_EXISTS {
            return Err("registering again did not say the interface exists");
        }
        // SAFETY: the string the second registration handed out.
        unsafe { crate::rtl::print::RtlFreeUnicodeString(&raw mut again) };
        let key = format!(
            "Machine\\System\\CurrentControlSet\\Control\\DeviceClasses\\{CLASS}\\##?#{}#{CLASS}",
            found.instance.replace('\\', "#")
        );
        if registry::string(&key, "DeviceInstance").as_deref() != Some(&found.instance)
            || registry::string(&format!("{key}\\#"), "SymbolicLink").as_deref()
                != Some(&expected.replacen("\\??\\", "\\\\?\\", 1))
        {
            return Err("the interface is not recorded under DeviceClasses as Windows records it");
        }
        // A property of the interface is kept with its record; one for
        // a link nobody registered is refused.
        let property = DEVPROPKEY {
            fmtid: class,
            pid: 3,
        };
        let set = |name: *const UNICODE_STRING| {
            // SAFETY: a counted string, a key and four bytes to read.
            unsafe {
                pnp::interface::IoSetDeviceInterfacePropertyData(
                    name,
                    &raw const property,
                    0,
                    0,
                    7,
                    4,
                    7u32.to_le_bytes().as_ptr(),
                )
            }
        };
        if set(&raw const name) != STATUS_SUCCESS
            || cm::read(&format!("{key}\\#\\Properties\\{CLASS}\\0003"), "")
                != Ok((0xFFFF_0007, 7u32.to_le_bytes().to_vec()))
        {
            return Err("the interface's property was not kept with its record");
        }
        let mut stranger: Vec<u16> = "\\??\\NkNoSuchInterface".encode_utf16().collect();
        let stranger = UNICODE_STRING {
            Length: (stranger.len() * 2) as u16,
            MaximumLength: (stranger.len() * 2) as u16,
            Buffer: stranger.as_mut_ptr(),
        };
        if set(&raw const stranger) != STATUS_OBJECT_NAME_NOT_FOUND {
            return Err("a property was set for an interface nobody registered");
        }
        let mut handle = core::ptr::null_mut();
        // SAFETY: a driver object and a callback of the test's, a GUID
        // and a handle to write.
        let registered = unsafe {
            IoRegisterPlugPlayNotification(
                EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE,
                0,
                (&raw const class).cast(),
                bench.drivers[0],
                notified as *const () as usize,
                NOTIFY_CONTEXT,
                &raw mut handle,
            )
        };
        if registered != STATUS_SUCCESS || handle.is_null() {
            return Err("the notification was not registered");
        }
        let switch = |on: bool| {
            // SAFETY: the name the registration handed out.
            unsafe { IoSetDeviceInterfaceState(&raw const name, u8::from(on)) }
        };
        let seen = || {
            (
                ARRIVALS.load(Ordering::Acquire),
                REMOVALS.load(Ordering::Acquire),
            )
        };
        let wait_seen = |target: (u32, u32)| {
            pnp::notify::wait_idle();
            seen() == target
        };
        let linked = || {
            crate::ob::lookup(None, &wide_link)
                .is_ok_and(|(body, rest)| body.body() == pdo.cast() && rest.is_empty())
        };
        let checks = (|| {
            // Disabling answers success whatever came of it, as Windows'
            // routine does; nothing is told.
            if switch(false) != STATUS_SUCCESS || !wait_seen((0, 0)) {
                return Err("disabling an interface that is not enabled did not answer success");
            }
            if switch(true) != STATUS_SUCCESS || !wait_seen((1, 0)) || !linked() {
                return Err("enabling did not make the link and tell the callback");
            }
            if registry::dword(&format!("{key}\\#\\Control"), "Linked") != Some(1) {
                return Err("the registry does not say the interface is linked");
            }
            if switch(true) != STATUS_OBJECT_NAME_EXISTS || !wait_seen((1, 0)) {
                return Err("enabling twice did not say the interface is enabled");
            }
            // A second registration that asks for what exists is told
            // at once (synchronously before registration returns).
            let mut second = core::ptr::null_mut();
            // SAFETY: as above.
            let registered = unsafe {
                IoRegisterPlugPlayNotification(
                    EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE,
                    PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                    (&raw const class).cast(),
                    bench.drivers[0],
                    notified as *const () as usize,
                    NOTIFY_CONTEXT,
                    &raw mut second,
                )
            };
            if registered != STATUS_SUCCESS || seen() != (2, 0) {
                return Err("a registration for existing interfaces was not told of the one");
            }
            // SAFETY: the handle just handed out.
            if unsafe { IoUnregisterPlugPlayNotificationEx(second) } != STATUS_SUCCESS {
                return Err("the second registration could not be taken back");
            }
            if switch(false) != STATUS_SUCCESS || !wait_seen((2, 1)) || linked() {
                return Err("disabling did not remove the link and tell the callback once");
            }
            // The device's start being undone disables what is enabled.
            if switch(true) != STATUS_SUCCESS || !wait_seen((3, 1)) {
                return Err("the interface could not be enabled again");
            }
            Ok(())
        })();
        // SAFETY: the handle the registration handed out.
        let back = unsafe { IoUnregisterPlugPlayNotificationEx(handle) };
        checks?;
        if back != STATUS_SUCCESS {
            return Err("the registration could not be taken back");
        }
        // Taken back, the callback hears nothing more.
        if switch(false) != STATUS_SUCCESS || !wait_seen((3, 1)) {
            return Err("a callback was called after its registration was taken back");
        }
        if switch(true) != STATUS_SUCCESS {
            return Err("the interface could not be left enabled");
        }
        if NOTIFIED_WRONG.load(Ordering::Acquire) != 0 {
            return Err("a callback was not handed the link, the class and its context");
        }
        // A category that does not exist is refused.
        let mut none = core::ptr::null_mut();
        // SAFETY: as above.
        let refused = unsafe {
            IoRegisterPlugPlayNotification(
                1,
                0,
                core::ptr::null(),
                bench.drivers[0],
                notified as *const () as usize,
                0,
                &raw mut none,
            )
        };
        if refused != STATUS_INVALID_DEVICE_REQUEST {
            return Err("a reserved event category was accepted");
        }

        // Regression tests for PnP notification lifecycle:
        // (a) external unregister racing an active callback preserves ownership
        //     and releases references cleanly;
        // (b) self-unregister from inside a callback succeeds and releases refs;
        // (c) queued work for an unregistered handle never fires on a new
        //     registration reusing the same heap address (ABA).
        static RACE_ENTERED: AtomicBool = AtomicBool::new(false);
        static RACE_RELEASE: AtomicBool = AtomicBool::new(false);
        static RACE_UNREG_DONE: AtomicBool = AtomicBool::new(false);
        static SELF_HANDLE: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(core::ptr::null_mut());
        static SELF_STATUS: AtomicI32 = AtomicI32::new(-1);
        static SELF_HITS: AtomicU32 = AtomicU32::new(0);
        static ABA_HITS: AtomicU32 = AtomicU32::new(0);

        /// # Safety
        /// Called as a PnP notification callback.
        unsafe extern "C" fn race_cb(_: *mut core::ffi::c_void, _: usize) -> NTSTATUS {
            RACE_ENTERED.store(true, Ordering::Release);
            while !RACE_RELEASE.load(Ordering::Acquire) {
                thread::yield_now();
            }
            STATUS_SUCCESS
        }
        fn release_helper(_: usize) {
            while !RACE_ENTERED.load(Ordering::Acquire) {
                thread::yield_now();
            }
            time::stall(20_000);
            RACE_RELEASE.store(true, Ordering::Release);
            RACE_UNREG_DONE.store(true, Ordering::Release);
        }
        /// # Safety
        /// Called as a PnP notification callback.
        unsafe extern "C" fn self_unreg_cb(_: *mut core::ffi::c_void, _: usize) -> NTSTATUS {
            SELF_HITS.fetch_add(1, Ordering::AcqRel);
            let h = SELF_HANDLE.load(Ordering::Acquire);
            // SAFETY: handle of this registration.
            let st = unsafe { IoUnregisterPlugPlayNotificationEx(h) };
            SELF_STATUS.store(st, Ordering::Release);
            STATUS_SUCCESS
        }
        /// # Safety
        /// Called as a PnP notification callback.
        unsafe extern "C" fn aba_cb(_: *mut core::ffi::c_void, _: usize) -> NTSTATUS {
            ABA_HITS.fetch_add(1, Ordering::AcqRel);
            STATUS_SUCCESS
        }

        // (a) External unregister racing an active callback.
        RACE_ENTERED.store(false, Ordering::Release);
        RACE_RELEASE.store(false, Ordering::Release);
        RACE_UNREG_DONE.store(false, Ordering::Release);
        let mut race_h = core::ptr::null_mut();
        // SAFETY: live driver object and callback.
        if unsafe {
            IoRegisterPlugPlayNotification(
                EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE,
                0,
                (&raw const class).cast(),
                bench.drivers[0],
                race_cb as *const () as usize,
                0,
                &raw mut race_h,
            )
        } != STATUS_SUCCESS
        {
            return Err("could not register external-race notification");
        }
        let _ = thread::create(release_helper, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)
            .map_err(|_| "could not spawn race release thread")?;
        if switch(false) != STATUS_SUCCESS {
            return Err("could not toggle interface for external-race test");
        }
        while !RACE_ENTERED.load(Ordering::Acquire) {
            thread::yield_now();
        }
        // SAFETY: racing against active `race_cb` on worker thread.
        let race_st = unsafe { IoUnregisterPlugPlayNotificationEx(race_h) };
        while !RACE_UNREG_DONE.load(Ordering::Acquire) {
            thread::yield_now();
        }
        pnp::notify::wait_idle();
        if race_st != STATUS_SUCCESS {
            return Err("external unregister racing active callback failed");
        }
        // SAFETY: second unregister of the same handle must be rejected.
        if unsafe { IoUnregisterPlugPlayNotificationEx(race_h) } != STATUS_INVALID_PARAMETER {
            return Err("duplicate unregister after external race was not refused");
        }

        // (b) Self-unregister from inside callback.
        SELF_HITS.store(0, Ordering::Release);
        SELF_STATUS.store(-1, Ordering::Release);
        let mut self_h = core::ptr::null_mut();
        // SAFETY: live driver object and callback.
        if unsafe {
            IoRegisterPlugPlayNotification(
                EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE,
                0,
                (&raw const class).cast(),
                bench.drivers[0],
                self_unreg_cb as *const () as usize,
                0,
                &raw mut self_h,
            )
        } != STATUS_SUCCESS
        {
            return Err("could not register self-unregister notification");
        }
        SELF_HANDLE.store(self_h, Ordering::Release);
        if switch(true) != STATUS_SUCCESS {
            return Err("could not enable interface for self-unregister test");
        }
        pnp::notify::wait_idle();
        if SELF_HITS.load(Ordering::Acquire) != 1
            || SELF_STATUS.load(Ordering::Acquire) != STATUS_SUCCESS
        {
            return Err("self-unregister from callback did not succeed");
        }
        if switch(false) != STATUS_SUCCESS {
            return Err("could not disable interface after self-unregister");
        }
        pnp::notify::wait_idle();
        if SELF_HITS.load(Ordering::Acquire) != 1 {
            return Err("self-unregistered callback fired again");
        }

        // (c) Queued work must not invoke a replacement registration at a reused address.
        ABA_HITS.store(0, Ordering::Release);
        let mut old_h = core::ptr::null_mut();
        // SAFETY: live driver object and callback.
        if unsafe {
            IoRegisterPlugPlayNotification(
                EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE,
                0,
                (&raw const class).cast(),
                bench.drivers[0],
                notified as *const () as usize,
                NOTIFY_CONTEXT,
                &raw mut old_h,
            )
        } != STATUS_SUCCESS
        {
            return Err("could not register ABA old handle");
        }
        if switch(true) != STATUS_SUCCESS {
            return Err("could not enable interface for ABA test");
        }
        // Immediately unregister old_h and register a new handle that may reuse its Box address.
        let mut new_h = core::ptr::null_mut();
        // SAFETY: `old_h` came from `IoRegisterPlugPlayNotification`.
        let unreg_old = unsafe { IoUnregisterPlugPlayNotificationEx(old_h) };
        // SAFETY: live driver object, class GUID, and callback.
        let reg_new = unsafe {
            IoRegisterPlugPlayNotification(
                EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE,
                0,
                (&raw const class).cast(),
                bench.drivers[0],
                aba_cb as *const () as usize,
                0,
                &raw mut new_h,
            )
        };
        pnp::notify::wait_idle();
        // SAFETY: unregister replacement handle.
        let unreg_new = unsafe { IoUnregisterPlugPlayNotificationEx(new_h) };
        if unreg_old != STATUS_SUCCESS
            || reg_new != STATUS_SUCCESS
            || unreg_new != STATUS_SUCCESS
            || ABA_HITS.load(Ordering::Acquire) != 0
        {
            return Err("queued PnP work invoked replacement registration (ABA)");
        }
        Ok(())
    })();
    // SAFETY: the string the registration handed out.
    unsafe { crate::rtl::print::RtlFreeUnicodeString(&raw mut name) };
    EXPECTED_LINK.store(core::ptr::null_mut(), Ordering::Release);
    result
}

/// `AddDevice` is called lowest first: the class's lower filter, the
/// function driver, the class's upper filter. A filter with no image
/// is left out.
fn add_device_order() -> Result<u64, &'static str> {
    let found = child(1).ok_or("the bus's child has no node")?;
    let order = ADDED.load(Ordering::Acquire);
    if order != 123 {
        return Err("AddDevice was not called for the lower filter, the driver, the upper filter");
    }
    if found.drivers != [LOWER, FUNCTION, UPPER] {
        return Err("the node does not list the drivers added");
    }
    // SAFETY: the tree's device.
    let stack = unsafe { pnp::engine::stack_drivers(found.pdo as *mut DEVICE_OBJECT) };
    let expected = [UPPER, FUNCTION, LOWER, BUS].map(|name| format!("\\Driver\\{name}"));
    if stack != expected {
        return Err("the stack is not upper filter, driver, lower filter, bus");
    }
    Ok(order)
}

/// The child was started with the resources its requirements name, raw
/// and translated, and they are recorded.
fn start_resources() -> Result<(u32, u32), &'static str> {
    let found = child(1).ok_or("the bus's child has no node")?;
    if found.state != State::Started {
        return Err("the child is not started");
    }
    let line = LINE.load(Ordering::Acquire);
    let expected = if line == u32::MAX { 1 } else { 2 };
    if COUNTS.load(Ordering::Acquire) != expected << 16 | expected {
        return Err("the start request did not carry both lists with every resource");
    }
    if RAW_MEMORY.load(Ordering::Acquire) != MEMORY + u64::from(PAGE) {
        return Err("the raw list does not hold the child's memory");
    }
    let (raw, _) = ResourceList::parse(&found.raw).ok_or("the node has no raw list")?;
    // The memory it was given is the memory it required once installed.
    if raw.partials().next().map(|memory| memory.flags) != Some(INSTALLED_FLAGS) {
        return Err("the device was not given what it requires as an installed device");
    }
    let key = registry::enum_key(&found.instance);
    match cm::read(&format!("{key}\\Control"), "AllocConfig") {
        Ok((8, bytes)) if bytes == raw.to_bytes() => {}
        _ => return Err("Control\\AllocConfig is not the raw list"),
    }
    let service = format!("{}\\Enum", registry::service_key(FUNCTION));
    if registry::dword(&service, "Count") != Some(1)
        || registry::string(&service, "0").as_deref() != Some(&found.instance)
    {
        return Err("the service's Enum key does not list the device");
    }
    if line == u32::MAX {
        return Ok((0, 0));
    }
    let (vector, level) = (
        VECTOR.load(Ordering::Acquire),
        LEVEL.load(Ordering::Acquire),
    );
    if RAW_LINE.load(Ordering::Acquire) != line {
        return Err("the raw list does not hold the interrupt line");
    }
    let info = routing::info(vector).ok_or("the translated vector is not one given out")?;
    if u32::from(info.level) != level || info.line.map(|l| l.gsi) != Some(line) {
        return Err("the translated interrupt is not the line's vector and level");
    }
    if found.vectors != [vector] {
        return Err("the node does not hold the vector");
    }
    // The device's interrupt connection data says how the line is
    // delivered: one controller input, the line's number, the vector.
    let property = registry::property_key(
        &found.instance,
        &nk_pnp::connection::CONNECTION_DATA_CATEGORY,
        nk_pnp::connection::CONNECTION_DATA_NUMBER,
    );
    let Ok((_, data)) = cm::read(&property, "") else {
        return Err("the device has no interrupt connection data");
    };
    let word = |at: usize| u32::from_le_bytes(data[at..at + 4].try_into().unwrap());
    if data.len() != 96 || word(0) != 1 || word(8) != 0 || word(12) != vector || word(64) != line {
        return Err("the connection data is not one controller input, the line and its vector");
    }
    Ok((line, vector))
}

/// The second child, reported after `IoInvalidateDeviceRelations`, is
/// found by a worker and its start, which its driver fails, is undone:
/// the devices added are removed, the vector and the memory are free
/// again, and the node says why.
fn failed_start() -> Result<(), &'static str> {
    let found = child(2).ok_or("the second child has no node")?;
    if found.state != State::Failed || found.problem != node::CM_PROB_FAILED_START {
        return Err("the second child is not failed with CM_PROB_FAILED_START");
    }
    if REMOVED.load(Ordering::Acquire) != 3 {
        return Err("the three devices added were not each told the device is removed");
    }
    // SAFETY: the tree's device.
    let stack = unsafe { pnp::engine::stack_drivers(found.pdo as *mut DEVICE_OBJECT) };
    if stack != [format!("\\Driver\\{BUS}")] {
        return Err("devices are still attached to the failed device");
    }
    if !found.raw.is_empty() || !found.vectors.is_empty() {
        return Err("the failed device still holds resources");
    }
    let key = registry::enum_key(&found.instance);
    if cm::read(&format!("{key}\\Control"), "AllocConfig").is_ok() {
        return Err("Control\\AllocConfig outlived the failed start");
    }
    // The first child shares the line and still has it.
    let first = child(1).ok_or("the first child has no node")?;
    if first.state != State::Started {
        return Err("the first child did not stay started");
    }
    if let [vector] = first.vectors[..]
        && routing::info(vector).is_none()
    {
        return Err("the failed start took the first child's vector away");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("pnp.root", root);
    r.check("pnp.hal-device", hal_device);
    let bench = match Bench::new() {
        Ok(bench) => bench,
        Err(why) => {
            r.skip_rest(format_args!("{why}"));
            return;
        }
    };
    // The bus's own device is identified, then its first child found
    // and started.
    PRESENT.store(1, Ordering::Release);
    pnp::settle();
    r.check("pnp.enumerate", || enumerate(&bench));
    r.check("pnp.match", matched);
    r.check("pnp.properties", || properties(&bench));
    match add_device_order() {
        Ok(order) => r.ok_with("pnp.add-device-order", format_args!("order {order}")),
        Err(why) => r.fail("pnp.add-device-order", format_args!("{why}")),
    }
    let started = start_resources();
    match started {
        Ok((0, _)) => r.ok_with("pnp.start-resources", format_args!("memory; no test line")),
        Ok(_) => r.ok_with("pnp.start-resources", format_args!("memory and a line")),
        Err(why) => r.fail("pnp.start-resources", format_args!("{why}")),
    }
    // A second child appears; the function driver fails its start.
    FAILING.store(2, Ordering::Release);
    // It depends on a device named by a string nobody is bound to yet.
    let mut provider: Vec<u16> = "\\NKPNP.PROVIDER".encode_utf16().collect();
    let provider = UNICODE_STRING {
        Length: (provider.len() * 2) as u16,
        MaximumLength: (provider.len() * 2) as u16,
        Buffer: provider.as_mut_ptr(),
    };
    let second = CHILDREN[1].load(Ordering::Acquire);
    // SAFETY: a live device object of the test's and a counted string.
    let reserved = unsafe { pnp::depend::IoReserveDependency(second, &raw const provider, 1) };
    bench.report(2);
    // The worker thread does the rest: wait for it by doing the same.
    pnp::settle();
    r.check("pnp.dependency", || {
        use pnp::depend::{IoReserveDependency, IoResolveDependency, IoSetDependency};
        if reserved != STATUS_SUCCESS {
            return Err("the dependency was not reserved");
        }
        let waiting = child(2).ok_or("the second child has no node")?;
        if waiting.state != State::Identified
            || waiting.problem != node::CM_PROB_WAITING_ON_DEPENDENCY
            || !waiting.drivers.is_empty()
        {
            return Err("a device whose provider is not there was not left waiting");
        }
        let first = CHILDREN[0].load(Ordering::Acquire);
        // SAFETY: live device objects of the test's and a counted
        // string; null where the routine is to refuse it.
        unsafe {
            if IoReserveDependency(second, &raw const provider, 0) != STATUS_INVALID_PARAMETER
                || IoReserveDependency(second, &raw const provider, 4) != STATUS_INVALID_PARAMETER
                || IoReserveDependency(core::ptr::null_mut(), &raw const provider, 1)
                    != STATUS_INVALID_PARAMETER
                || IoSetDependency(second, second, 1) != STATUS_UNSUCCESSFUL
                || IoSetDependency(second, core::ptr::null_mut(), 1) != STATUS_INVALID_PARAMETER
            {
                return Err("a malformed dependency was not refused as Windows refuses it");
            }
            // The string is bound to the first child, which is started:
            // the second no longer waits.
            if IoResolveDependency(&raw const provider, first) != STATUS_SUCCESS {
                return Err("the string could not be bound to a device");
            }
        }
        pnp::settle();
        let now = child(2).ok_or("the second child has no node")?;
        if now.problem == node::CM_PROB_WAITING_ON_DEPENDENCY {
            return Err("the device still waits after its provider was bound and is started");
        }
        Ok(())
    });
    r.check("pnp.invalidate-relations", || {
        child(2)
            .map(|_| ())
            .ok_or("the child reported after IoInvalidateDeviceRelations was not found")
    });
    r.check("pnp.failed-start", failed_start);
    // A third child, whose bus driver answers an instance identifier
    // with a backslash in it: Windows takes no such identifier.
    bench.report(3);
    pnp::settle();
    r.check("pnp.invalid-instance-id", || {
        let found = child(3).ok_or("the third child has no node")?;
        if found.state != State::Failed || found.problem != node::CM_PROB_INVALID_DATA {
            return Err("the child is not failed with CM_PROB_INVALID_DATA");
        }
        let first = child(1).ok_or("the first child has no node")?;
        let key = registry::enum_key(&first.instance);
        if cm::values(&format!("{key}\\Control"))
            .iter()
            .any(|(name, _, _)| name == "Capabilities")
            || cm::subkeys(&key).len() != 4
        {
            return Err("the identifier was used as a path into the first child's key");
        }
        Ok(())
    });
    r.check("pnp.interface", || interface(&bench));
    // The first child's driver says the device's state changed, and
    // then that it failed (`PNP_DEVICE_FAILED`): the manager asks, and
    // takes the device down. Its node tells of the NUMA node first.
    let vector = started.ok().map(|(_, vector)| vector);
    let before = REMOVED.load(Ordering::Acquire);
    r.check("pnp.invalidate-state", || {
        let first = CHILDREN[0].load(Ordering::Acquire);
        let mut numa = 0xEEEE;
        // SAFETY: live device objects of the test's, and a number to
        // write.
        unsafe {
            if pnp::export::IoGetDeviceNumaNode(first, &raw mut numa) != STATUS_SUCCESS || numa != 0
            {
                return Err("the device is not on node 0");
            }
            if pnp::export::IoGetDeviceNumaNode(bench.function, &raw mut numa)
                != STATUS_INVALID_PARAMETER
            {
                return Err("a function device object was given a node");
            }
            // Nothing changed: the device stays.
            pnp::export::IoInvalidateDeviceState(first);
            pnp::settle();
            if child(1).is_none_or(|node| node.state != State::Started) {
                return Err("a device whose state is unchanged did not stay started");
            }
            DEVICE_STATE.store(query::PNP_DEVICE_FAILED, Ordering::Release);
            pnp::export::IoInvalidateDeviceState(first);
        }
        pnp::settle();
        let found = child(1).ok_or("the first child has no node")?;
        if found.state != State::Failed || found.problem != node::CM_PROB_FAILED_POST_START {
            return Err("the device its driver calls failed is not failed with problem 43");
        }
        if REMOVED.load(Ordering::Acquire) != before + 3 {
            return Err("the failed device's three devices were not told it is removed");
        }
        if !found.raw.is_empty() || !found.vectors.is_empty() {
            return Err("the failed device still holds resources");
        }
        let property = registry::property_key(
            &found.instance,
            &nk_pnp::connection::CONNECTION_DATA_CATEGORY,
            nk_pnp::connection::CONNECTION_DATA_NUMBER,
        );
        if cm::exists(&property) {
            return Err("the failed device still has interrupt connection data");
        }
        // Its interface, left enabled, is disabled with it.
        let link: Vec<u16> = format!("\\??\\{}#{CLASS}", found.instance.replace('\\', "#"))
            .encode_utf16()
            .collect();
        if crate::ob::lookup(None, &link).is_ok() {
            return Err("the failed device's interface is still linked");
        }
        Ok(())
    });
    // The bus loses its children: each is removed, and what it held is
    // free again.
    bench.report(0);
    pnp::settle();
    r.check("pnp.removed", || {
        if child(1).is_some() || child(2).is_some() {
            return Err("the children the bus no longer reports still have nodes");
        }
        if !cm::subkeys(&format!(
            "Machine\\System\\CurrentControlSet\\Control\\DeviceClasses\\{CLASS}"
        ))
        .is_empty()
        {
            return Err("a removed device's interface is still recorded");
        }
        if CHILDREN
            .iter()
            .any(|c| !c.load(Ordering::Acquire).is_null())
        {
            return Err("the bus driver was not told to delete its children");
        }
        if vector.is_some_and(|vector| vector != 0 && routing::info(vector).is_some()) {
            return Err("the removed child's vector is still given out");
        }
        Ok(())
    });
    // The first child comes back: a new device object for a device
    // whose key is still there from its installation. What it requires
    // depends on that key, and its bus driver is asked once, before
    // anything is installed: the device must have its name by then.
    r.check("pnp.re-enumerated", || {
        let again = make(bench.drivers[0], Role::Child, 1)?;
        // SAFETY: the device just made.
        unsafe { (*again).Flags &= !DO_DEVICE_INITIALIZING };
        CHILDREN[0].store(again, Ordering::Release);
        DEVICE_STATE.store(0, Ordering::Release);
        bench.report(1);
        pnp::settle();
        let found = child(1).ok_or("the device that came back has no node")?;
        let mut result = if found.requirements != child_requirements(1, true).to_bytes() {
            Err("its bus driver did not find its key when asked what it requires")
        } else if found.state != State::Started {
            Err("the device that came back was not started")
        } else {
            Ok(())
        };
        // Register a target-device subscriber that owns the last open handle
        // and closes it ONLY from its GUID_TARGET_DEVICE_REMOVE_COMPLETE
        // callback: surprise removal must deliver the notification first so
        // deferred IRP_MN_REMOVE_DEVICE does not deadlock.
        static TD_FILE_HANDLE: AtomicU64 = AtomicU64::new(0);
        static TD_NOTIFY_HANDLE: AtomicPtr<core::ffi::c_void> =
            AtomicPtr::new(core::ptr::null_mut());
        static TD_FIRED: AtomicU32 = AtomicU32::new(0);
        /// # Safety
        /// Called as a PnP target-device notification callback.
        unsafe extern "C" fn td_remove_cb(notif: *mut core::ffi::c_void, _: usize) -> NTSTATUS {
            // SAFETY: notification header from `notify::device_removed`.
            let event = unsafe { (*notif.cast::<TARGET_DEVICE_REMOVAL_NOTIFICATION>()).Event };
            if event == GUID_TARGET_DEVICE_REMOVE_COMPLETE {
                TD_FIRED.fetch_add(1, Ordering::AcqRel);
                let nh = TD_NOTIFY_HANDLE.swap(core::ptr::null_mut(), Ordering::AcqRel);
                if !nh.is_null() {
                    // SAFETY: self-unregister this callback's registration.
                    let _ = unsafe { pnp::notify::IoUnregisterPlugPlayNotificationEx(nh) };
                }
                let fh = TD_FILE_HANDLE.swap(0, Ordering::AcqRel);
                if fh != 0 {
                    file::close(fh);
                }
            }
            STATUS_SUCCESS
        }
        if result.is_ok() {
            let class = ids::guid_from_text(CLASS).ok_or("the class is not a GUID")?;
            let mut link_name: UNICODE_STRING = UNICODE_STRING {
                Length: 0,
                MaximumLength: 0,
                Buffer: core::ptr::null_mut(),
            };
            // SAFETY: live PDO and class GUID.
            let reg_if = unsafe {
                pnp::interface::IoRegisterDeviceInterface(
                    again,
                    &raw const class,
                    core::ptr::null(),
                    &raw mut link_name,
                )
            };
            if reg_if == STATUS_SUCCESS {
                // SAFETY: registered interface string.
                let _ =
                    unsafe { pnp::interface::IoSetDeviceInterfaceState(&raw const link_name, 1) };
                // SAFETY: `link_name` was initialised by `IoRegisterDeviceInterface`.
                let wide = unsafe { crate::rtl::copy_unicode(&raw const link_name) };
                let link_str = String::from_utf16_lossy(&wide);
                // SAFETY: string allocated by IoRegisterDeviceInterface.
                unsafe { crate::rtl::print::RtlFreeUnicodeString(&raw mut link_name) };
                match file::open(&file::OpenRequest::new(&link_str)) {
                    Ok((fh, _)) => {
                        let mut fobj: *mut core::ffi::c_void = core::ptr::null_mut();
                        // SAFETY: open file handle.
                        let ref_st = unsafe {
                            crate::ob::handle::ObReferenceObjectByHandle(
                                fh as *mut core::ffi::c_void,
                                0,
                                crate::ob::object::IoFileObjectType.value(),
                                KERNEL_MODE,
                                &raw mut fobj,
                                core::ptr::null_mut(),
                            )
                        };
                        if ref_st == STATUS_SUCCESS {
                            TD_FIRED.store(0, Ordering::Release);
                            TD_FILE_HANDLE.store(fh, Ordering::Release);
                            let mut nh = core::ptr::null_mut();
                            // SAFETY: open FILE_OBJECT and live driver object.
                            let nr = unsafe {
                                pnp::notify::IoRegisterPlugPlayNotification(
                                    EVENT_CATEGORY_TARGET_DEVICE_CHANGE,
                                    0,
                                    fobj,
                                    bench.drivers[0],
                                    td_remove_cb as *const () as usize,
                                    0,
                                    &raw mut nh,
                                )
                            };
                            // SAFETY: balance ObReferenceObjectByHandle.
                            unsafe { crate::ob::object::dereference(fobj.cast()) };
                            if nr == STATUS_SUCCESS {
                                TD_NOTIFY_HANDLE.store(nh, Ordering::Release);
                            } else {
                                TD_FILE_HANDLE.store(0, Ordering::Release);
                                file::close(fh);
                                result =
                                    Err("could not register target-device change notification");
                            }
                        } else {
                            file::close(fh);
                            result = Err("could not reference opened file object");
                        }
                    }
                    Err(_) => result = Err("could not open re-enumerated child device"),
                }
            } else {
                result = Err("could not register interface on re-enumerated child");
            }
        }
        bench.report(0);
        pnp::settle();
        // Wait for worker callback to close the handle and PnP engine to finish removal.
        let deadline = time::interrupt_time() + 5_000 * 10_000;
        while (child(1).is_some() || !CHILDREN[0].load(Ordering::Acquire).is_null())
            && time::interrupt_time() < deadline
        {
            pnp::notify::wait_idle();
            pnp::settle();
            thread::yield_now();
        }
        // Clean up if anything failed before callback ran.
        let leftover_nh = TD_NOTIFY_HANDLE.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !leftover_nh.is_null() {
            // SAFETY: valid handle.
            let _ = unsafe { pnp::notify::IoUnregisterPlugPlayNotificationEx(leftover_nh) };
        }
        let leftover_fh = TD_FILE_HANDLE.swap(0, Ordering::AcqRel);
        if leftover_fh != 0 {
            file::close(leftover_fh);
        }
        if result.is_ok() && TD_FIRED.load(Ordering::Acquire) != 1 {
            result =
                Err("GUID_TARGET_DEVICE_REMOVE_COMPLETE did not fire once on surprise removal");
        }
        if child(1).is_some() || !CHILDREN[0].load(Ordering::Acquire).is_null() {
            return Err("the device that came back was not removed again");
        }
        result
    });
    drop(bench);
}
