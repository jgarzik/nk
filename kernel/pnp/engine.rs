//! What the Plug and Play manager does to a device: identify it, add
//! its drivers, give it resources, start it, ask it for its children,
//! and take it down again.
//!
//! One thread at a time does any of this: whoever holds the engine's
//! mutex ([`serialised`]). Requests that arrive from drivers
//! (`IoInvalidateDeviceRelations`) are queued and carried out by the
//! engine's own thread, which takes the mutex like anyone else; the
//! boot and the tests call [`settle`] and have everything done when it
//! returns. The engine's thread is not one of the system's worker
//! threads, as Windows' device-action worker is not: the engine waits
//! for drivers with its mutex held, and drivers complete what it waits
//! for from work items, so a work queue's threads must never be found
//! waiting for the engine.
//! The mutex is held across requests to device stacks and calls of
//! `AddDevice`, which may wait; no spin lock is.
//!
//! The order of what a device is asked is Windows' (`PiProcessNewDeviceNode`,
//! `PipCallDriverAddDevice`, `PnpStartDevice` and what follows it in
//! the pinned kernel): `doc/DESIGN.md`, Plug and Play.

use super::node::{self, Node, State};
use super::{query, registry};
use crate::io::{self, device, service};
use crate::ke::seh::{self, Guard, Unhandled};
use crate::ke::{Rank, SpinLock, mutex, wait};
use crate::ob::object;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};
use nk_ntabi::io::*;
use nk_ntabi::ke::{KEVENT, KMUTANT};
use nk_ntabi::pnp::*;
use nk_ntabi::status::*;
use nk_pnp::assign::{self, Claims};
use nk_pnp::connection::{Delivery, Source, connection_data};
use nk_pnp::resources::{Partial, Requirements, ResourceList, TYPE_INTERRUPT};
use nk_pnp::{database, ids, relations};

/// `DO_BUS_ENUMERATED_DEVICE`: the device was reported by a bus driver.
const DO_BUS_ENUMERATED_DEVICE: u32 = 0x1000;

/// The engine's mutex, the event its thread waits for, and what only
/// the mutex's holder touches: which resources every device holds.
struct Engine {
    mutex: UnsafeCell<MaybeUninit<KMUTANT>>,
    /// Set when a request has been queued: a synchronisation event.
    wake: UnsafeCell<MaybeUninit<KEVENT>>,
    claims: UnsafeCell<Claims>,
}

// SAFETY: the mutex and the event are reached through the kernel's
// routines for them, which lock for themselves; the claims only by the
// thread that holds the mutex (`with_claims`).
unsafe impl Sync for Engine {}

static ENGINE: Engine = Engine {
    mutex: UnsafeCell::new(MaybeUninit::uninit()),
    wake: UnsafeCell::new(MaybeUninit::uninit()),
    claims: UnsafeCell::new(Claims::new()),
};

/// Set once every boot-start driver has had its turn: from then on a
/// device's driver is loaded when the device needs it.
static BOOT_DRIVERS_LOADED: AtomicBool = AtomicBool::new(false);

/// What a driver asked for, to be done by a worker thread.
enum Action {
    /// Ask this device, which the entry holds a reference to, for its
    /// children again.
    Enumerate(usize),
    /// Ask this device, which the entry holds a reference to, for its
    /// state again.
    Requery(usize),
    /// Look at every device again: something a device waited for may
    /// have come.
    Look,
}

struct Requests {
    actions: Vec<Action>,
    /// Boot-start services whose driver failed to initialise: a device
    /// that needs one is not started.
    failed: Vec<String>,
}

static REQUESTS: SpinLock<Requests> = SpinLock::new(
    Rank::DeviceTree,
    Requests {
        actions: Vec::new(),
        failed: Vec::new(),
    },
);

/// The priority of the engine's thread: that of the system's delayed
/// worker threads.
const PRIORITY: u8 = 12;

/// Make the engine's mutex and start its thread. Once, before anything
/// else here is used.
pub fn init() -> Result<(), &'static str> {
    // SAFETY: the storage of the mutex and of the event, initialised
    // here before any use: a synchronisation event, not signalled.
    unsafe {
        mutex::KeInitializeMutex(ENGINE.mutex.get().cast(), 0);
        wait::KeInitializeEvent(ENGINE.wake.get().cast(), 1, 0);
    }
    crate::ke::thread::create(thread, 0, PRIORITY, crate::ke::thread::ANYWHERE).map(|_| ())
}

/// The engine's thread: whenever a request has been queued, do
/// everything there is to do.
fn thread(_: usize) {
    loop {
        // SAFETY: the engine's event, initialised by `init`.
        unsafe { wait::wait(Some(ENGINE.wake.get().cast()), None) };
        settle();
    }
}

/// Run `f` as the one piece of Plug and Play work in progress. The
/// mutex may be taken again by the thread that holds it.
fn serialised<R>(f: impl FnOnce() -> R) -> R {
    crate::ke::irql::expect_passive("Plug and Play work");
    let mutex = ENGINE.mutex.get();
    // SAFETY: the engine's mutex, initialised by `init`; released by
    // the thread that took it.
    unsafe {
        wait::wait(Some(mutex.cast()), None);
        let result = f();
        mutex::KeReleaseMutex(mutex.cast(), 0);
        result
    }
}

/// Run `f` on the table of claims. For the thread that holds the
/// engine's mutex; `f` calls nothing that comes back here.
fn with_claims<R>(f: impl FnOnce(&mut Claims) -> R) -> R {
    // SAFETY: per the contract above, this is the only reference.
    f(unsafe { &mut *ENGINE.claims.get() })
}

/// Queue `action` for the engine's thread and wake it. `false` if there
/// is no memory: the action is then not done. Callable at
/// `DISPATCH_LEVEL`.
fn request(action: Action) -> bool {
    {
        let mut requests = REQUESTS.lock();
        if requests.actions.try_reserve(1).is_err() {
            return false;
        }
        requests.actions.push(action);
    }
    // SAFETY: the engine's event, initialised by `init`.
    unsafe { wait::KeSetEvent(ENGINE.wake.get().cast(), 0, 0) };
    true
}

/// Have the device `pdo` asked for its children again, by the engine's
/// thread: what `IoInvalidateDeviceRelations` asks for.
///
/// # Safety
/// `pdo` is a live device object.
pub unsafe fn enumerate_later(pdo: *mut DEVICE_OBJECT) {
    // SAFETY: per the contract.
    unsafe { later(pdo, Action::Enumerate(pdo as usize)) }
}

/// Have the device `pdo` asked for its state again, by the engine's
/// thread: what `IoInvalidateDeviceState` asks for.
///
/// # Safety
/// `pdo` is a live device object.
pub unsafe fn requery_later(pdo: *mut DEVICE_OBJECT) {
    // SAFETY: per the contract.
    unsafe { later(pdo, Action::Requery(pdo as usize)) }
}

/// Have the engine's thread look at every device again: a dependency
/// was stated or resolved.
pub fn look_later() {
    request(Action::Look);
}

/// Queue `action`, which names `pdo`.
///
/// # Safety
/// `pdo` is a live device object.
unsafe fn later(pdo: *mut DEVICE_OBJECT, action: Action) {
    // SAFETY: per the contract; the reference is the queued action's,
    // given back when it has been carried out or could not be queued.
    unsafe {
        object::reference(pdo.cast());
        if !request(action) {
            object::dereference(pdo.cast());
        }
    }
}

/// Ask the started device `pdo` for its state: one its drivers now
/// call failed, disabled or removed is taken down as after a start.
fn requery(pdo: usize) {
    // SAFETY: the tree's device; the engine's mutex is held, at
    // `PASSIVE_LEVEL`.
    let state = unsafe { query::device_state(pdo as *mut DEVICE_OBJECT) };
    if state & (query::PNP_DEVICE_FAILED | query::PNP_DEVICE_DISABLED | query::PNP_DEVICE_REMOVED)
        != 0
    {
        if let Some(found) = node::get(pdo) {
            for child in found.children {
                remove(child, false);
            }
        }
        give_up(
            pdo,
            node::CM_PROB_FAILED_POST_START,
            format_args!("its drivers report it unusable (device state {state:#x})"),
        );
    }
}

/// Every boot-start driver has had its turn: from now on a driver is
/// loaded when a device needs it.
pub fn boot_drivers_loaded() {
    BOOT_DRIVERS_LOADED.store(true, Ordering::Release);
    settle();
}

/// The boot-start service `name` failed to initialise.
pub fn driver_failed(name: &str) {
    let mut requests = REQUESTS.lock();
    if requests.failed.try_reserve(1).is_ok() {
        requests.failed.push(name.into());
    }
}

fn has_failed(name: &str) -> bool {
    REQUESTS
        .lock()
        .failed
        .iter()
        .any(|failed| failed.eq_ignore_ascii_case(name))
}

/// Do everything there is to do: what drivers asked for, and then
/// whatever any device is waiting for that can now be done, until
/// nothing moves.
pub fn settle() {
    serialised(|| {
        loop {
            let next = {
                let mut requests = REQUESTS.lock();
                if requests.actions.is_empty() {
                    requests.actions = Vec::new();
                    None
                } else {
                    Some(requests.actions.remove(0))
                }
            };
            match next {
                Some(Action::Enumerate(pdo)) => {
                    if node::with(pdo, |node| node.state == State::Started) == Some(true) {
                        enumerate(pdo);
                    }
                    // SAFETY: the action's reference.
                    unsafe { object::dereference(pdo as *mut u8) };
                }
                Some(Action::Requery(pdo)) => {
                    if node::with(pdo, |node| node.state == State::Started) == Some(true) {
                        requery(pdo);
                    }
                    // SAFETY: the action's reference.
                    unsafe { object::dereference(pdo as *mut u8) };
                }
                Some(Action::Look) => {}
                None => {
                    let mut moved = false;
                    for pdo in node::all() {
                        moved |= advance(pdo);
                    }
                    if !moved {
                        break;
                    }
                }
            }
        }
    });
}

/// Take the device `pdo` one step further, if a step can be taken.
fn advance(pdo: usize) -> bool {
    let Some((state, enumerated)) = node::with(pdo, |node| (node.state, node.enumerated)) else {
        return false;
    };
    match state {
        State::New => {
            identify(pdo);
            true
        }
        State::Identified => add_drivers(pdo),
        State::Stacked => {
            start(pdo);
            true
        }
        State::Started if !enumerated => {
            enumerate(pdo);
            true
        }
        State::Started | State::Failed => false,
    }
}

/// The device will not be started: say why, in the node and the log.
fn fail(pdo: usize, problem: u32, why: core::fmt::Arguments<'_>) {
    let instance = node::with(pdo, |node| {
        node.state = State::Failed;
        node.problem = problem;
        node.instance.clone()
    })
    .unwrap_or_default();
    kprintln!("pnp: {instance}: not started, problem {problem}: {why}");
}

/// Ask a newly reported device who it is, and make its key.
fn identify(pdo: usize) {
    let device = pdo as *mut DEVICE_OBJECT;
    let Some(mut found) = node::get(pdo) else {
        return;
    };
    // SAFETY: the tree holds a reference to the device; the engine's
    // mutex is held, at `PASSIVE_LEVEL`.
    unsafe {
        if !found.reported {
            // An enumerator and a device, one backslash between.
            let id = query::id(device, BUS_QUERY_DEVICE_ID)
                .ok()
                .and_then(|mut ids| ids.pop())
                .and_then(|id| ids::fixed_up(&id, ids::MAX_ID, ids::Separators::Exactly(1)))
                .filter(|id| id.split('\\').all(|part| !part.is_empty()));
            match id {
                Some(id) => found.device_id = id,
                None => {
                    return fail(
                        pdo,
                        node::CM_PROB_INVALID_DATA,
                        format_args!("its bus driver gave no valid device identifier"),
                    );
                }
            }
        }
        match query::capabilities(device) {
            Ok((flags, address, number)) => {
                found.capabilities = flags;
                found.address = address;
                found.ui_number = number;
            }
            Err(status) => {
                return fail(
                    pdo,
                    node::CM_PROB_INVALID_DATA,
                    format_args!(
                        "the query for its capabilities failed ({:#010x})",
                        status as u32
                    ),
                );
            }
        }
        found.description = query::text(device, DEVICE_TEXT_DESCRIPTION);
        found.location = query::text(device, DEVICE_TEXT_LOCATION_INFORMATION);
        if !found.reported {
            // No backslash: the identifier is one key's name. A bus
            // driver that answers none, or fails the query for any
            // reason but want of memory, has a device without one, as
            // on Windows (`PnpQueryID`): ACPI's devices without `_UID`.
            let instance = match query::id(device, BUS_QUERY_INSTANCE_ID).as_deref() {
                Ok([id]) => {
                    let fixed = ids::fixed_up(id, ids::MAX_ID, ids::Separators::Exactly(0))
                        .filter(|id| !id.is_empty());
                    let Some(fixed) = fixed else {
                        node::with(pdo, |node| node.instance = found.device_id.clone());
                        return fail(
                            pdo,
                            node::CM_PROB_INVALID_DATA,
                            format_args!("its bus driver gave an invalid instance identifier"),
                        );
                    };
                    Some(fixed)
                }
                Err(&STATUS_INSUFFICIENT_RESOURCES) => {
                    node::with(pdo, |node| node.instance = found.device_id.clone());
                    return fail(
                        pdo,
                        node::CM_PROB_OUT_OF_MEMORY,
                        format_args!("no memory for its instance identifier"),
                    );
                }
                _ => None,
            };
            let unique = found.capabilities & DEVICE_CAPABILITY_UNIQUE_ID != 0;
            let prefix = if unique && instance.is_some() {
                String::new()
            } else {
                let parent =
                    node::with(found.parent, |above| (above.instance.clone(), above.level));
                let Some((path, level)) = parent else {
                    return;
                };
                match registry::parent_prefix(&path, level) {
                    Ok(prefix) => {
                        node::with(found.parent, |above| {
                            above.child_prefix = Some(prefix.clone());
                        });
                        prefix
                    }
                    Err(_) => {
                        return fail(
                            pdo,
                            node::CM_PROB_OUT_OF_MEMORY,
                            format_args!("no memory for its parent's prefix"),
                        );
                    }
                }
            };
            found.instance =
                ids::instance_path(&found.device_id, instance.as_deref(), unique, &prefix);
            if node::by_instance(&found.instance).is_some_and(|other| other != pdo) {
                // Windows stops for this (`PNP_DETECTED_FATAL_ERROR`);
                // NK leaves the second device unstarted.
                node::with(pdo, |node| node.instance = found.instance.clone());
                return fail(
                    pdo,
                    node::CM_PROB_DUPLICATE_DEVICE,
                    format_args!("another device has the same instance path"),
                );
            }
            // The device has its name from here on, and its key: a bus
            // driver that is asked for the device's requirements next
            // may look in the key for what an earlier installation left
            // there, as it can on Windows, where the instance key is
            // made before those queries.
            let named = (found.instance.clone(), found.device_id.clone());
            node::with(pdo, |node| (node.instance, node.device_id) = named);
            if crate::cm::write_path(&registry::enum_key(&found.instance), &[]).is_err() {
                return fail(
                    pdo,
                    node::CM_PROB_OUT_OF_MEMORY,
                    format_args!("its key could not be made"),
                );
            }
        }
        // A list with an invalid identifier in it is no list.
        let list = |kind| {
            query::id(device, kind)
                .ok()
                .and_then(|list| ids::fixed_up_list(&list))
                .unwrap_or_default()
        };
        found.hardware_ids = list(BUS_QUERY_HARDWARE_IDS);
        found.compatible_ids = list(BUS_QUERY_COMPATIBLE_IDS);
        if found.reported {
            // What the report itself stated comes behind what the
            // device's driver answers.
            let stated = node::with(pdo, |node| node.compatible_ids.clone()).unwrap_or_default();
            for id in stated {
                if !found.compatible_ids.contains(&id) {
                    found.compatible_ids.push(id);
                }
            }
        }
        found.bus = query::bus_information(device);
        found.requirements = query::requirements(device);
        found.boot = query::resources(device);
    }
    if registry::write_identity(&found).is_err() {
        node::with(pdo, |node| node.instance = found.instance.clone());
        return fail(
            pdo,
            node::CM_PROB_OUT_OF_MEMORY,
            format_args!("its key could not be written"),
        );
    }
    // What firmware configured is kept for the device until it is
    // given its resources: nobody else is put there meanwhile.
    if let Some((list, _)) = ResourceList::parse(&found.boot) {
        let ranges: Option<Vec<Option<assign::Range>>> =
            list.partials().map(assign::held_by).collect();
        let Some(ranges) = ranges else {
            node::with(pdo, |node| node.instance = found.instance.clone());
            return fail(
                pdo,
                node::CM_PROB_INVALID_DATA,
                format_args!("its boot configuration names a range that does not exist"),
            );
        };
        let ranges: Vec<assign::Range> = ranges.into_iter().flatten().collect();
        with_claims(|claims| claims.keep(pdo, &ranges));
    }
    // SAFETY: as above.
    unsafe { query::pnp(device, IRP_MN_DEVICE_ENUMERATED, [0; 4]) };
    kprintln!("pnp: {}: found", found.instance);
    found.state = State::Identified;
    node::with(pdo, |node| *node = found);
}

/// A driver named for a device's stack, and whether it is a filter.
struct Wanted {
    name: String,
    filter: bool,
}

/// Find the device's drivers and call their `AddDevice`, lowest first.
/// Returns whether anything changed: a device whose drivers are not
/// all running yet, while boot-start drivers are still being started,
/// waits as it is.
fn add_drivers(pdo: usize) -> bool {
    let device = pdo as *mut DEVICE_OBJECT;
    let Some(found) = node::get(pdo) else {
        return false;
    };
    // A device waits for the devices it depends on to have started.
    if !found.reported && super::depend::blocked(pdo) {
        if !node::with(pdo, |node| {
            node.problem = node::CM_PROB_WAITING_ON_DEPENDENCY;
            core::mem::replace(&mut node.held_back, true)
        })
        .unwrap_or(true)
        {
            kprintln!("pnp: {}: waits for a device it depends on", found.instance);
        }
        return false;
    }
    if found.problem == node::CM_PROB_WAITING_ON_DEPENDENCY {
        node::with(pdo, |node| {
            node.problem = node::PROBLEM_NONE;
            node.held_back = false;
        });
    }
    let key = registry::enum_key(&found.instance);
    // A device seen for the first time is installed from the driver
    // database: NK's stand-in for device installation.
    let installed = registry::string(&key, "ClassGUID").is_some()
        || registry::string(&key, "Driver").is_some()
        || (!found.reported && registry::string(&key, "Service").is_some());
    if !installed
        && let Some(record) = registry::find_driver(&found.hardware_ids, &found.compatible_ids)
    {
        if registry::install(&found, &record).is_err() {
            fail(
                pdo,
                node::CM_PROB_OUT_OF_MEMORY,
                format_args!("its key could not be written"),
            );
            return true;
        }
        kprintln!(
            "pnp: {}: installed from {} [{}], matched on {}",
            found.instance,
            record.inf,
            record.section,
            record.id
        );
        // What the device requires may depend on what installation
        // just put in its key: pci.sys offers a message-signalled
        // interrupt only to a device whose `Device Parameters` say it
        // supports one. On Windows the device was installed before
        // this boot and its bus driver found the settings when first
        // asked; here it is asked again, now that they are there.
        // SAFETY: the tree's device; the engine's mutex is held, at
        // `PASSIVE_LEVEL`.
        let requirements = unsafe { query::requirements(device) };
        if requirements != found.requirements {
            node::with(pdo, |node| node.requirements = requirements);
            if let Some(now) = node::get(pdo) {
                let _ = registry::write_identity(&now);
            }
        }
    }
    let class = registry::string(&key, "ClassGUID");
    node::with(pdo, |node| node.class = class.clone());
    if found.reported {
        // The driver that reported the device serves it: its device is
        // on the stack, and the device counts as started.
        node::with(pdo, |node| node.state = State::Started);
        // What its driver enabled while it set the device up exists now
        // (`volmgr.sys` enables its manager's interface in its own
        // `AddDevice`, before the device counts as started).
        super::interface::device_started(pdo);
        kprintln!("pnp: {}: started (reported by its driver)", found.instance);
        return true;
    }
    let service =
        registry::string(&key, "Service").map(|value| String::from(database::service_name(&value)));
    let Some(service) = service else {
        if found.capabilities & DEVICE_CAPABILITY_RAW_DEVICE_OK != 0 {
            node::with(pdo, |node| node.state = State::Stacked);
            return true;
        }
        fail(
            pdo,
            node::CM_PROB_FAILED_INSTALL,
            format_args!("no driver is installed for it"),
        );
        return true;
    };
    // Lower filters of the device, then of its class; the function
    // driver; upper filters of the device, then of its class.
    let class_key = class.as_deref().map(registry::class_key);
    let filters = |name: &str| {
        let mut list = registry::strings(&key, name);
        if let Some(class_key) = &class_key {
            list.extend(registry::strings(class_key, name));
        }
        list.into_iter().map(|name| Wanted { name, filter: true })
    };
    let wanted: Vec<Wanted> = filters("LowerFilters")
        .chain([Wanted {
            name: service.clone(),
            filter: false,
        }])
        .chain(filters("UpperFilters"))
        .collect();
    let mut drivers: Vec<(String, *mut DRIVER_OBJECT)> = Vec::new();
    let mut left_out: Vec<String> = Vec::new();
    for Wanted { name, filter } in wanted {
        let kind = if filter { "filter" } else { "driver" };
        let running = match io::driver::running(&name) {
            Some(driver) => Some(driver),
            None if has_failed(&name) => {
                fail(
                    pdo,
                    node::CM_PROB_FAILED_DRIVER_ENTRY,
                    format_args!("its {kind} {name} failed to initialise"),
                );
                return true;
            }
            None => match service::image(&name) {
                Ok(file) if crate::ldr::boot_file(&file).is_some() => {
                    if !BOOT_DRIVERS_LOADED.load(Ordering::Acquire) {
                        // Its turn among the boot-start drivers has
                        // not come: the device waits.
                        return false;
                    }
                    match start_service(&name) {
                        Ok(driver) => Some(driver),
                        Err(problem) => {
                            fail(
                                pdo,
                                problem,
                                format_args!("its {kind} {name} did not start"),
                            );
                            return true;
                        }
                    }
                }
                _ if filter => {
                    // NK's stated difference from Windows, which fails
                    // the device: `doc/DESIGN.md`, What is absent.
                    left_out.push(name.clone());
                    None
                }
                _ => {
                    fail(
                        pdo,
                        node::CM_PROB_DRIVER_FAILED_LOAD,
                        format_args!("its driver {name} has no image"),
                    );
                    return true;
                }
            },
        };
        if let Some(driver) = running {
            drivers.push((name, driver));
        }
    }
    for name in &left_out {
        kprintln!(
            "pnp: {}: filter {name} has no image; the stack is built without it",
            found.instance
        );
    }
    for (at, (name, driver)) in drivers.iter().enumerate() {
        kprintln!("pnp: {}: AddDevice of {name}", found.instance);
        // SAFETY: a running driver's object and its extension; the
        // routine is the driver's `AddDevice`, called at
        // `PASSIVE_LEVEL` from a system thread with the driver object
        // and the physical device object, as Windows calls it.
        let status = unsafe {
            let add = (*(**driver).DriverExtension).AddDevice;
            if add.is_null() {
                STATUS_NOT_SUPPORTED
            } else {
                seh::call(
                    add as usize,
                    [driver.addr(), pdo, 0, 0],
                    &Guard::Base(Unhandled::SystemThread),
                ) as u32 as NTSTATUS
            }
        };
        if !nt_success(status) {
            // The devices attached so far go: their drivers are told
            // the device is removed.
            if at != 0 {
                // SAFETY: the tree's device, at `PASSIVE_LEVEL`.
                unsafe { query::pnp(device, IRP_MN_REMOVE_DEVICE, [0; 4]) };
            }
            fail(
                pdo,
                node::CM_PROB_FAILED_ADD,
                format_args!("AddDevice of {name} failed ({:#010x})", status as u32),
            );
            return true;
        }
    }
    node::with(pdo, |node| {
        node.service = Some(service);
        node.drivers = drivers.into_iter().map(|(name, _)| name).collect();
        node.state = State::Stacked;
    });
    true
}

/// Start the service `name` for a device that needs it. The problem
/// code if it does not start.
fn start_service(name: &str) -> Result<*mut DRIVER_OBJECT, u32> {
    /// `SERVICE_DISABLED`.
    const DISABLED: u32 = 4;
    if registry::dword(&registry::service_key(name), "Start") == Some(DISABLED) {
        return Err(node::CM_PROB_DISABLED_SERVICE);
    }
    match service::start(name) {
        Ok(driver) => {
            kprintln!("pnp: service {name} started for a device");
            io::driver::reinitialize_drivers();
            Ok(driver)
        }
        Err(service::ServiceError::Driver(io::driver::DriverError::EntryFailed(status))) => {
            kprintln!(
                "pnp: service {name} failed to initialise ({:#010x})",
                status as u32
            );
            driver_failed(name);
            Err(node::CM_PROB_FAILED_DRIVER_ENTRY)
        }
        Err(error) => {
            kprintln!("pnp: service {name} did not load: {error:?}");
            Err(node::CM_PROB_DRIVER_FAILED_LOAD)
        }
    }
}

/// A resource list for a driver to read: a copy in the pool, freed
/// when this goes. Null for an empty list.
struct Handed(*mut u8);

impl Handed {
    fn new(list: &[u8]) -> Option<Self> {
        if list.is_empty() {
            return Some(Self(core::ptr::null_mut()));
        }
        let block = crate::mm::pool::alloc(list.len(), super::TAG);
        if block.is_null() {
            return None;
        }
        // SAFETY: a fresh block of the list's length.
        unsafe { block.copy_from_nonoverlapping(list.as_ptr(), list.len()) };
        Some(Self(block))
    }
}

impl Drop for Handed {
    fn drop(&mut self) {
        if !self.0.is_null() {
            let _ = crate::mm::pool::free(self.0);
        }
    }
}

/// What a device was given, in every form it is kept in.
struct Given {
    raw: Vec<u8>,
    translated: Vec<u8>,
    ranges: Vec<assign::Range>,
    interrupts: Vec<io::interrupt::Resource>,
    vectors: Vec<u32>,
    /// The device's interrupt connection data, the value of the
    /// property a bus driver reads it from; empty for a device without
    /// translated interrupts.
    connection: Vec<u8>,
}

/// Give back the vectors a device's interrupts were translated to.
fn release_vectors(vectors: &[u32]) {
    for vector in vectors {
        crate::hal::interrupt::release(*vector);
    }
}

/// Choose the device's resources out of its requirements (as its
/// drivers filtered them) and translate them. The problem code and the
/// reason if that cannot be done.
fn give(found: &Node, filtered: &[u8]) -> Result<Given, (u32, &'static str)> {
    let nothing = Given {
        raw: Vec::new(),
        translated: Vec::new(),
        ranges: Vec::new(),
        interrupts: Vec::new(),
        vectors: Vec::new(),
        connection: Vec::new(),
    };
    if filtered.is_empty() {
        return Ok(nothing);
    }
    let invalid = (
        node::CM_PROB_INVALID_DATA,
        "its resource requirements are malformed",
    );
    let requirements = Requirements::parse(filtered).ok_or(invalid)?;
    let boot: Vec<Partial> = ResourceList::parse(&found.boot)
        .map(|(list, _)| list.partials().cloned().collect())
        .unwrap_or_default();
    // Its ancestors do not stand in its way, nor what was kept for it.
    let pdo = found.pdo;
    let exempt = |holder: usize| node::is_at_or_above(holder, pdo);
    let assignment = with_claims(|claims| {
        requirements
            .lists
            .iter()
            .find_map(|list| assign::assign(list, &boot, claims, &exempt).ok())
    })
    .ok_or((
        node::CM_PROB_NORMAL_CONFLICT,
        "the resources it requires are not free",
    ))?;
    if assignment.partials.is_empty() {
        return Ok(nothing);
    }
    let mut given = Given {
        ranges: assignment.ranges,
        ..nothing
    };
    // A child of the HAL's own device states vectors, not lines: they
    // are what they are.
    let as_stated = crate::hal::bus::is_hal_device(found.parent);
    let mut translated = Vec::new();
    for partial in &assignment.partials {
        if partial.kind != TYPE_INTERRUPT || as_stated {
            translated.push(partial.clone());
            continue;
        }
        match translate_interrupt(partial) {
            Ok((resources, partials, vector)) => {
                given.interrupts.extend(resources);
                given.vectors.push(vector);
                translated.extend(partials);
            }
            Err(_) => {
                release_vectors(&given.vectors);
                return Err((
                    node::CM_PROB_NORMAL_CONFLICT,
                    "an interrupt it requires could not be given a vector",
                ));
            }
        }
    }
    if !given.interrupts.is_empty() {
        let deliveries: Vec<Delivery> = given.interrupts.iter().filter_map(delivery).collect();
        if deliveries.len() != given.interrupts.len() {
            release_vectors(&given.vectors);
            return Err((
                node::CM_PROB_NORMAL_CONFLICT,
                "the hardware layer does not say how an interrupt it gave out is delivered",
            ));
        }
        given.connection = connection_data(&deliveries);
    }
    given.raw = ResourceList::of(
        requirements.interface,
        requirements.bus,
        assignment.partials,
    )
    .to_bytes();
    given.translated =
        ResourceList::of(requirements.interface, requirements.bus, translated).to_bytes();
    Ok(given)
}

/// How a translated interrupt is delivered, for the device's
/// connection data: a message's address and data, a line's number and
/// signalling, as the hardware layer set them up.
fn delivery(resource: &io::interrupt::Resource) -> Option<Delivery> {
    use crate::hal::interrupt::{self as hal, Polarity, Trigger};
    let translated = resource.translated;
    let source = if resource.message {
        let message = hal::message(translated.vector)?;
        Source::Message {
            address: message.address,
            data: message.data,
        }
    } else {
        let line = hal::info(translated.vector)?.line?;
        Source::Line {
            gsi: line.gsi,
            edge: line.trigger == Trigger::Edge,
            low: line.polarity == Polarity::Low,
        }
    };
    Some(Delivery {
        vector: translated.vector,
        irql: translated.level,
        affinity: translated.affinity,
        source,
    })
}

/// Give a raw interrupt a vector. Returns what `io::interrupt` is told
/// of it, the translated descriptors, and the vector to give back.
fn translate_interrupt(
    partial: &Partial,
) -> Result<(Vec<io::interrupt::Resource>, Vec<Partial>, u32), NTSTATUS> {
    use crate::hal::interrupt::{self as hal, Line, Polarity, Raw, Trigger};
    let (_, count, number, _) = partial.as_interrupt().ok_or(STATUS_INVALID_PARAMETER)?;
    let message = partial.is_message();
    let shared = partial.share == nk_pnp::resources::SHARE_SHARED;
    let raw = if message {
        Raw::Messages(u32::from(count))
    } else {
        // An ISA interrupt signals as firmware says; any other line as
        // its descriptor says, which names the trigger and leaves the
        // polarity to the architecture's convention.
        let isa = u8::try_from(number).ok().and_then(hal::isa);
        Raw::Line(isa.unwrap_or_else(|| {
            let edge = partial.flags & nk_pnp::resources::INTERRUPT_LATCHED != 0;
            Line {
                gsi: number,
                trigger: if edge { Trigger::Edge } else { Trigger::Level },
                polarity: if edge {
                    Polarity::High
                } else {
                    crate::arch::level_line_polarity()
                },
            }
        }))
    };
    let first = hal::translate(raw, u64::MAX)?;
    let messages = if message { u32::from(count) } else { 1 };
    let mut resources = Vec::new();
    let mut partials = Vec::new();
    for at in 0..messages {
        let one = hal::Translated {
            vector: first.vector + at,
            ..first
        };
        resources.push(io::interrupt::Resource {
            translated: one,
            message,
            shared,
        });
        partials.push(Partial::interrupt(
            partial.share,
            partial.flags,
            u16::from(one.level),
            0,
            one.vector,
            one.affinity,
        ));
    }
    Ok((resources, partials, first.vector))
}

/// Take from the device everything `start` gave it.
fn take_back(pdo: usize) {
    let vectors = node::with(pdo, |node| {
        node.raw = Vec::new();
        node.translated = Vec::new();
        core::mem::take(&mut node.vectors)
    })
    .unwrap_or_default();
    io::interrupt::withdraw(pdo as *mut DEVICE_OBJECT);
    release_vectors(&vectors);
    if let Some(instance) = node::with(pdo, |node| node.instance.clone()) {
        registry::clear_connection(&instance);
    }
    with_claims(|claims| claims.release(pdo));
}

/// Give the device its resources and start it.
fn start(pdo: usize) {
    let device = pdo as *mut DEVICE_OBJECT;
    let Some(found) = node::get(pdo) else {
        return;
    };
    // SAFETY: the tree's device; the engine's mutex is held, at
    // `PASSIVE_LEVEL`.
    let filtered = match unsafe { query::filtered(device, &found.requirements) } {
        Ok(filtered) => filtered,
        Err(status) => {
            return give_up(
                pdo,
                node::CM_PROB_FAILED_START,
                format_args!(
                    "filtering its resource requirements failed ({:#010x})",
                    status as u32
                ),
            );
        }
    };
    let given = match give(&found, &filtered) {
        Ok(given) => given,
        Err((problem, why)) => return give_up(pdo, problem, format_args!("{why}")),
    };
    // What was kept for the device from its boot configuration gives
    // way to what it now holds.
    let recorded = with_claims(|claims| {
        claims.release(pdo);
        claims.claim(pdo, &given.ranges)
    }) && io::interrupt::assign(device, &given.interrupts);
    let lists = (Handed::new(&given.raw), Handed::new(&given.translated));
    node::with(pdo, |node| {
        node.raw = given.raw.clone();
        node.translated = given.translated.clone();
        node.vectors = given.vectors.clone();
    });
    let (true, (Some(raw), Some(translated))) = (recorded, lists) else {
        return give_up(
            pdo,
            node::CM_PROB_OUT_OF_MEMORY,
            format_args!("no memory for its resources"),
        );
    };
    let _ = registry::write_allocation(&found.instance, &filtered, &given.raw);
    if !given.connection.is_empty()
        && registry::write_connection(&found.instance, &given.connection).is_err()
    {
        return give_up(
            pdo,
            node::CM_PROB_OUT_OF_MEMORY,
            format_args!("no memory for its interrupt connection data"),
        );
    }
    kprintln!("pnp: {}: starting", found.instance);
    let parameters = start_device_parameters(raw.0 as u64, translated.0 as u64);
    // From here the device's drivers may register it with the runtime
    // power framework, as on Windows (`PnpStartDevice`).
    // SAFETY: as above; the lists stay until the request has completed.
    let (status, _) = unsafe {
        crate::po::fx::prepare_device(device);
        query::pnp(device, IRP_MN_START_DEVICE, parameters)
    };
    if !nt_success(status) {
        return give_up(
            pdo,
            node::CM_PROB_FAILED_START,
            format_args!("its drivers failed to start it ({:#010x})", status as u32),
        );
    }
    // SAFETY: as above.
    let (capabilities, state) =
        unsafe { (query::capabilities(device), query::device_state(device)) };
    if state & (query::PNP_DEVICE_FAILED | query::PNP_DEVICE_DISABLED | query::PNP_DEVICE_REMOVED)
        != 0
    {
        return give_up(
            pdo,
            node::CM_PROB_FAILED_POST_START,
            format_args!("its drivers report it unusable (device state {state:#x})"),
        );
    }
    node::with(pdo, |node| {
        if let Ok((flags, address, number)) = capabilities {
            node.capabilities = flags;
            node.address = address;
            node.ui_number = number;
        }
        node.state = State::Started;
    });
    if let Some(now) = node::get(pdo) {
        let _ = registry::write_identity(&now);
    }
    if let Some(service) = &found.service {
        let _ = registry::service_serves(service, &found.instance);
    }
    // The interfaces its drivers enabled while it started exist now.
    super::interface::device_started(pdo);
    let stack = if found.drivers.is_empty() {
        String::from("no driver: a raw device")
    } else {
        found.drivers.join(", ")
    };
    kprintln!("pnp: {}: started ({stack})", found.instance);
}

/// The device's start failed after its drivers were added: tell them
/// the device is removed, so that they detach and delete what they
/// attached, take back what it was given, and leave it failed.
fn give_up(pdo: usize, problem: u32, why: core::fmt::Arguments<'_>) {
    super::interface::device_stopped(pdo, false);
    // SAFETY: the tree's device; the engine's mutex is held, at
    // `PASSIVE_LEVEL`.
    unsafe {
        query::pnp(pdo as *mut DEVICE_OBJECT, IRP_MN_REMOVE_DEVICE, [0; 4]);
        crate::po::fx::abandon_device(pdo as *mut DEVICE_OBJECT);
    }
    take_back(pdo);
    if let Some(found) = node::get(pdo) {
        registry::clear_allocation(&found.instance);
    }
    node::with(pdo, |node| node.drivers = Vec::new());
    fail(pdo, problem, why);
}

/// Ask the started device `pdo` for its children; make nodes for those
/// that are new, and take down those that are gone.
fn enumerate(pdo: usize) {
    let device = pdo as *mut DEVICE_OBJECT;
    let Some((known, level, instance)) = node::with(pdo, |node| {
        node.enumerated = true;
        (node.children.clone(), node.level, node.instance.clone())
    }) else {
        return;
    };
    // SAFETY: the tree's device; the engine's mutex is held, at
    // `PASSIVE_LEVEL`.
    let reported = match unsafe { query::relations(device, BUS_RELATIONS) } {
        Ok(Some(reported)) => reported,
        Ok(None) => return,
        Err(status) => {
            kprintln!(
                "pnp: {instance}: the query for its children failed ({:#010x})",
                status as u32
            );
            return;
        }
    };
    let change = relations::change(&known, &reported);
    if !change.repeated.is_empty() {
        crate::kd::verify(format_args!(
            "the bus driver of {instance} reported a child more than once"
        ));
    }
    // The driver referenced each device it reported, for the manager.
    // The tree keeps one reference per device, taken when the device
    // was first reported: the others are given back.
    let mut seen: Vec<usize> = Vec::new();
    for child in &reported {
        let first = !seen.contains(child);
        if first {
            seen.push(*child);
        }
        if !(first && change.arrived.contains(child)) {
            // SAFETY: the reference the driver took for this report.
            unsafe { object::dereference(*child as *mut u8) };
        }
    }
    for child in change.arrived {
        let Some(address) = node::insert(Node::new(child, pdo, level + 1)) else {
            // No memory: the device is reported again another time.
            // SAFETY: the reference the driver took.
            unsafe { object::dereference(child as *mut u8) };
            continue;
        };
        // SAFETY: a live device object the tree now holds a reference
        // to; the fields are written through pointers, the device being
        // its bus driver's to write too.
        unsafe {
            let child = child as *mut DEVICE_OBJECT;
            let flags = &raw mut (*child).Flags;
            flags.write(flags.read() | DO_BUS_ENUMERATED_DEVICE);
            (&raw mut (*(*child).DeviceObjectExtension).DeviceNode).write(address as PVOID);
        }
    }
    for child in change.gone {
        remove(child, true);
    }
}

/// Take the device `pdo` and everything below it out of the tree,
/// children first: its drivers are told it is removed (after being
/// told it is gone without warning, if `surprise`), what it was given
/// is taken back, and the tree's reference to it is dropped.
pub fn remove(pdo: usize, surprise: bool) {
    let Some(found) = node::get(pdo) else {
        return;
    };
    for child in &found.children {
        remove(*child, surprise);
    }
    let device = pdo as *mut DEVICE_OBJECT;
    // SAFETY: the tree's device; the engine's mutex is held, at
    // `PASSIVE_LEVEL`. The reference dropped last is the tree's.
    unsafe {
        super::interface::device_stopped(pdo, true);
        super::depend::forget(pdo);
        if found.state == State::Started && surprise {
            query::pnp(device, IRP_MN_SURPRISE_REMOVAL, [0; 4]);
        }
        // Whatever is on the stack hears of it, be that only the bus
        // driver, which deletes a device its bus no longer has. A
        // reported device's stack is its reporter's to take down.
        if !found.reported {
            query::pnp(device, IRP_MN_REMOVE_DEVICE, [0; 4]);
        }
        // What its drivers left with the power framework goes, as
        // Windows' `IopRemoveDevice` sees to.
        crate::po::fx::abandon_device(device);
        take_back(pdo);
        if let Some(service) = &found.service {
            registry::service_stopped_serving(service, &found.instance);
        }
        registry::clear_allocation(&found.instance);
        (&raw mut (*(*device).DeviceObjectExtension).DeviceNode).write(core::ptr::null_mut());
        node::remove(pdo);
        kprintln!("pnp: {}: removed", found.instance);
        object::dereference(device.cast());
    }
}

/// [`remove`], for a caller that does not hold the engine's mutex.
pub fn remove_now(pdo: usize, surprise: bool) {
    serialised(|| remove(pdo, surprise));
}

/// The last device a driver's `AddDevice` attached on the way up from
/// `pdo`: the top of its stack.
///
/// # Safety
/// `pdo` is a live device object.
pub unsafe fn stack_drivers(pdo: *mut DEVICE_OBJECT) -> Vec<String> {
    let mut names = Vec::new();
    // SAFETY: per the contract. Each device of the stack is referenced
    // while its driver's name is read; the chain up is read under the
    // device database lock by `IoGetAttachedDeviceReference` only for
    // the top, so the walk goes down from there.
    unsafe {
        let top = device::IoGetAttachedDeviceReference(pdo);
        let mut at = top;
        while !at.is_null() {
            let driver = (*at).DriverObject;
            let name = crate::rtl::copy_unicode(&raw const (*driver).DriverName);
            names.push(String::from_utf16_lossy(&name));
            at = (*(*at).DeviceObjectExtension).AttachedTo;
        }
        object::dereference(top.cast());
    }
    names
}
