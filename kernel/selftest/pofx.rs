//! The runtime power framework, driven as a driver drives it: a device
//! registered as components, activated and idled, its callbacks
//! watched.

use super::po::Pair;
use crate::ke::{self, irql, wait};
use crate::mm::pool;
use crate::po::fx;
use crate::test::{Group, Report, Slot};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::ex::GUID;
use nk_ntabi::ke::KEVENT;
use nk_ntabi::po::*;
use nk_ntabi::status::*;
use nk_po::fx::{FLAG_ASYNC_ONLY, FLAG_BLOCKING};

pub static GROUP: Group = Group {
    names: &["po.fx-register", "po.fx-active-idle", "po.fx-no-extension"],
    run,
    manual: false,
};

fn run(r: &mut Report, _: &BootInfo) {
    let mut numbered = |name: &str, result: Result<u32, &'static str>| match result {
        Ok(n) => r.ok_with(name, format_args!("{n} checked")),
        Err(why) => r.fail(name, format_args!("{why}")),
    };
    numbered("po.fx-register", register());
    numbered("po.fx-active-idle", active_idle());
    numbered("po.fx-no-extension", no_extension());
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];

/// The context the test's device registers with.
const CONTEXT: usize = 0x00C0_FFEE;

/// What a callback was: `KIND << 16 | component << 8 | IRQL`, with
/// `ELSEWHERE` if it ran in a thread other than the test's.
const ACTIVE: u32 = 1;
const IDLE: u32 = 2;
const ELSEWHERE: u32 = 1 << 31;
static LOG: [AtomicU32; 16] = [const { AtomicU32::new(0) }; 16];
static LOGGED: AtomicUsize = AtomicUsize::new(0);
/// The test's thread.
static TEST_THREAD: AtomicUsize = AtomicUsize::new(0);
/// Whether the idle-condition callback completes the transition
/// itself, as `storport.sys` and `pci.sys` do.
static COMPLETES: AtomicU32 = AtomicU32::new(1);
/// How often a callback NK never makes was made, or one was handed a
/// context that is not the device's.
static WRONG: AtomicU32 = AtomicU32::new(0);
/// The device's handle, for the idle-condition callback.
static HANDLE: AtomicUsize = AtomicUsize::new(0);
/// Set when a callback has been made.
static TOLD: Slot<KEVENT> = Slot::new();

const fn event(kind: u32, component: u32, level: u8) -> u32 {
    kind << 16 | component << 8 | level as u32
}

fn log(kind: u32, context: *mut c_void, component: u32) {
    if context.addr() != CONTEXT {
        WRONG.fetch_add(1, Ordering::AcqRel);
    }
    let mut what = event(kind, component, irql::current());
    if ke::pcr::current_thread().addr() != TEST_THREAD.load(Ordering::Acquire) {
        what |= ELSEWHERE;
    }
    let at = LOGGED.fetch_add(1, Ordering::AcqRel);
    if let Some(slot) = LOG.get(at) {
        slot.store(what, Ordering::Release);
    }
}

/// What has been logged since the last call.
fn logged() -> Vec<u32> {
    let n = LOGGED.swap(0, Ordering::AcqRel).min(LOG.len());
    LOG[..n].iter().map(|e| e.load(Ordering::Acquire)).collect()
}

/// Wait until `count` callbacks have been logged.
fn await_logged(count: usize) {
    while LOGGED.load(Ordering::Acquire) < count {
        // SAFETY: the event the callbacks set, initialised by the test.
        unsafe {
            wait::wait(Some(TOLD.ptr().cast()), None);
            wait::KeClearEvent(TOLD.ptr());
        }
    }
}

/// The driver's `ComponentActiveConditionCallback`.
///
/// # Safety
/// Called as one.
unsafe extern "C" fn active_condition(context: *mut c_void, component: u32) {
    log(ACTIVE, context, component);
    // SAFETY: the test's event.
    unsafe { wait::KeSetEvent(TOLD.ptr(), 0, 0) };
}

/// The driver's `ComponentIdleConditionCallback`.
///
/// # Safety
/// Called as one.
unsafe extern "C" fn idle_condition(context: *mut c_void, component: u32) {
    log(IDLE, context, component);
    // SAFETY: the test's device and event.
    unsafe {
        if COMPLETES.load(Ordering::Acquire) != 0 {
            let handle = core::ptr::without_provenance_mut(HANDLE.load(Ordering::Acquire));
            fx::PoFxCompleteIdleCondition(handle, component);
        }
        wait::KeSetEvent(TOLD.ptr(), 0, 0);
    }
}

/// A callback NK never makes: a change of F-state, the device's power
/// required or not, a request of the platform extension's, a directed
/// transition.
///
/// # Safety
/// Never called.
unsafe extern "C" fn never() {
    WRONG.fetch_add(1, Ordering::AcqRel);
}

fn callbacks() -> PO_FX_CALLBACKS {
    PO_FX_CALLBACKS {
        ComponentActiveConditionCallback: active_condition as *mut c_void,
        ComponentIdleConditionCallback: idle_condition as *mut c_void,
        ComponentIdleStateCallback: never as *mut c_void,
        DevicePowerRequiredCallback: never as *mut c_void,
        DevicePowerNotRequiredCallback: never as *mut c_void,
        PowerControlCallback: never as *mut c_void,
    }
}

const NO_CALLBACKS: PO_FX_CALLBACKS = PO_FX_CALLBACKS {
    ComponentActiveConditionCallback: core::ptr::null_mut(),
    ComponentIdleConditionCallback: core::ptr::null_mut(),
    ComponentIdleStateCallback: core::ptr::null_mut(),
    DevicePowerRequiredCallback: core::ptr::null_mut(),
    DevicePowerNotRequiredCallback: core::ptr::null_mut(),
    PowerControlCallback: core::ptr::null_mut(),
};

const ID: GUID = GUID {
    Data1: 0x4E4B_0001,
    Data2: 0,
    Data3: 0,
    Data4: [0; 8],
};

/// A version 1 device with one component.
#[repr(C)]
struct DeviceV1 {
    head: PO_FX_DEVICE_V1,
    components: [PO_FX_COMPONENT_V1; 1],
}

/// A version 2 device with two components.
#[repr(C)]
struct DeviceV2 {
    head: PO_FX_DEVICE_V2,
    components: [PO_FX_COMPONENT_V2; 2],
}

/// A version 3 device with two components.
#[repr(C)]
struct DeviceV3 {
    head: PO_FX_DEVICE_V3,
    components: [PO_FX_COMPONENT_V2; 2],
}

fn component_v2(idle_states: u32, deepest_wakeable: u32) -> PO_FX_COMPONENT_V2 {
    PO_FX_COMPONENT_V2 {
        Id: ID,
        Flags: 0,
        DeepestWakeableIdleState: deepest_wakeable,
        IdleStateCount: idle_states,
        // Never read: NK asks for no F-state.
        IdleStates: core::ptr::null_mut(),
        ProviderCount: 0,
        Providers: core::ptr::null_mut(),
    }
}

fn device_v1(callbacks: PO_FX_CALLBACKS, components: u32, idle_states: u32) -> DeviceV1 {
    DeviceV1 {
        head: PO_FX_DEVICE_V1 {
            Version: PO_FX_VERSION_V1,
            ComponentCount: components,
            Callbacks: callbacks,
            DeviceContext: core::ptr::without_provenance_mut(CONTEXT),
        },
        components: [PO_FX_COMPONENT_V1 {
            Id: ID,
            IdleStateCount: idle_states,
            DeepestWakeableIdleState: 0,
            IdleStates: core::ptr::null_mut(),
        }],
    }
}

fn device_v2(callbacks: PO_FX_CALLBACKS, idle_states: [u32; 2]) -> DeviceV2 {
    DeviceV2 {
        head: PO_FX_DEVICE_V2 {
            Version: PO_FX_VERSION_V2,
            Flags: 0,
            Callbacks: callbacks,
            DeviceContext: core::ptr::without_provenance_mut(CONTEXT),
            ComponentCount: 2,
        },
        components: [
            component_v2(idle_states[0], 0),
            component_v2(idle_states[1], 0),
        ],
    }
}

fn device_v3(up: usize, down: usize) -> DeviceV3 {
    DeviceV3 {
        head: PO_FX_DEVICE_V3 {
            Version: PO_FX_VERSION_V3,
            Flags: 0x6,
            Callbacks: callbacks(),
            DirectedPowerUpCallback: core::ptr::without_provenance_mut(up),
            DirectedPowerDownCallback: core::ptr::without_provenance_mut(down),
            DirectedFxTimeoutInSeconds: 77,
            DeviceContext: core::ptr::without_provenance_mut(CONTEXT),
            ComponentCount: 2,
        },
        components: [component_v2(3, 2), component_v2(1, 0)],
    }
}

/// Register what `described` describes for the pair's function device.
///
/// # Safety
/// `described` is a `PO_FX_DEVICE`.
unsafe fn try_register<T>(pair: &Pair, described: &T) -> (NTSTATUS, *mut c_void) {
    let mut handle = core::ptr::null_mut();
    // SAFETY: per the contract; a device of the test's.
    let status = unsafe {
        fx::PoFxRegisterDevice(
            pair.fdo,
            core::ptr::from_ref(described).cast(),
            &raw mut handle,
        )
    };
    (status, handle)
}

fn start_test() {
    TEST_THREAD.store(ke::pcr::current_thread().addr(), Ordering::Release);
    WRONG.store(0, Ordering::Release);
    COMPLETES.store(1, Ordering::Release);
    logged();
    // SAFETY: static storage for an event nothing waits on.
    unsafe { wait::KeInitializeEvent(TOLD.ptr(), 0, 0) };
}

/// A device is registered only once the Plug and Play manager has
/// begun to start it, and only as components the pinned kernel
/// accepts; each version of the description is read; a registration
/// left behind goes when the device is removed. Returns the facts
/// checked.
fn register() -> Result<u32, &'static str> {
    start_test();
    let blocks = pool::usage().blocks;
    let devices = fx::test_devices();
    let checked = (|| {
        let pair = Pair::build()?;
        let good = device_v1(NO_CALLBACKS, 1, 1);
        // SAFETY: descriptions in locals, laid out as their versions.
        unsafe {
            let mut handle = core::ptr::null_mut();
            if fx::PoFxRegisterDevice(
                core::ptr::null_mut(),
                (&raw const good).cast(),
                &raw mut handle,
            ) != STATUS_INVALID_PARAMETER
            {
                return Err("a registration for no device was not refused");
            }
            if try_register(&pair, &good).0 != STATUS_INVALID_PARAMETER {
                return Err("a device with no device node was registered");
            }
            pair.enumerated(true);
            if try_register(&pair, &good).0 != STATUS_DEVICE_NOT_READY {
                return Err("a device that is not being started was registered");
            }
            fx::prepare_device(pair.pdo);

            let mut unknown = device_v1(NO_CALLBACKS, 1, 1);
            unknown.head.Version = 4;
            let refused: [(NTSTATUS, &str); 6] = [
                (
                    try_register(&pair, &unknown).0,
                    "a version Windows does not define was registered",
                ),
                (
                    try_register(&pair, &device_v1(NO_CALLBACKS, 0, 1)).0,
                    "a device with no component was registered",
                ),
                (
                    try_register(&pair, &device_v1(callbacks(), 1, 0)).0,
                    "a component with no F-state was registered",
                ),
                (
                    try_register(&pair, &device_v2(NO_CALLBACKS, [1, 2])).0,
                    "a component with low-power states and no callbacks was registered",
                ),
                (
                    try_register(&pair, &device_v3(0x1000, 0)).0,
                    "one directed callback without the other was registered",
                ),
                (
                    try_register(&pair, &device_v3(0, 0x2000)).0,
                    "one directed callback without the other was registered",
                ),
            ];
            for (status, why) in refused {
                if status != STATUS_INVALID_PARAMETER {
                    return Err(why);
                }
            }
            if fx::test_devices() != devices {
                return Err("a refused registration left a device behind");
            }

            // Version 1.
            let (status, handle) = try_register(&pair, &good);
            if status != STATUS_SUCCESS || handle.is_null() {
                return Err("a version 1 device was not registered");
            }
            let state = fx::test_state(handle);
            if state.devices != devices + 1
                || state.parts != [(1, true, 0, 0)]
                || state.started
                || state.other_callbacks != [0; 4]
            {
                return Err("a version 1 device was not registered as it was described");
            }
            fx::PoFxUnregisterDevice(handle);

            // Version 3, as `storport.sys` registers.
            let (status, handle) = try_register(&pair, &device_v3(0x1000, 0x2000));
            if status != STATUS_SUCCESS {
                return Err("a version 3 device was not registered");
            }
            let state = fx::test_state(handle);
            let never = never as *const () as usize;
            if state.parts != [(1, true, 0, 0), (1, true, 0, 0)]
                || state.flags != 0x6
                || state.directed != [0x1000, 0x2000]
                || state.directed_timeout != 77
                || state.other_callbacks != [never; 4]
            {
                return Err("a version 3 device was not registered as it was described");
            }

            // Left behind by its driver: it goes when the device is
            // removed, and the device is no longer prepared.
            fx::abandon_device(pair.pdo);
            if fx::test_devices() != devices {
                return Err("a registration was not taken away when its device was removed");
            }
            if try_register(&pair, &good).0 != STATUS_DEVICE_NOT_READY {
                return Err("a removed device could still be registered");
            }
        }
        Ok(13)
    })();
    if checked.is_ok() && pool::usage().blocks != blocks {
        return Err("a registration was not freed");
    }
    checked
}

/// The registered device of the two tests below.
struct Registered {
    pair: Pair,
    handle: *mut c_void,
}

impl Registered {
    fn new() -> Result<Self, &'static str> {
        start_test();
        let pair = Pair::build()?;
        pair.enumerated(true);
        // SAFETY: a device of the test's, described in a local.
        let (status, handle) = unsafe {
            fx::prepare_device(pair.pdo);
            try_register(&pair, &device_v2(callbacks(), [1, 2]))
        };
        if status != STATUS_SUCCESS {
            return Err("the test's device was not registered");
        }
        HANDLE.store(handle.addr(), Ordering::Release);
        Ok(Self { pair, handle })
    }

    /// Each component's activations outstanding, and whether it is at
    /// rest.
    fn parts(&self) -> Vec<(u32, bool)> {
        fx::test_state(self.handle)
            .parts
            .iter()
            .map(|&(count, at_rest, ..)| (count, at_rest))
            .collect()
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        // SAFETY: the registration made above, which no thread uses.
        unsafe {
            fx::PoFxUnregisterDevice(self.handle);
            fx::abandon_device(self.pair.pdo);
        }
    }
}

/// Components are counted and their driver told, in order: nothing
/// while a component the driver holds stays active; the idle condition
/// at `DISPATCH_LEVEL` when the last activation goes, finished by the
/// driver's completion; the active condition in the caller's thread, or
/// from a worker when asked for or when it follows a completion.
/// Returns the facts checked.
fn active_idle() -> Result<u32, &'static str> {
    let devices = fx::test_devices();
    let blocks = pool::usage().blocks;
    let checked = (|| {
        let device = Registered::new()?;
        let handle = device.handle;
        let passive = irql::PASSIVE_LEVEL;
        let dispatch = irql::DISPATCH_LEVEL;
        // SAFETY: the test's registration.
        unsafe {
            // The driver holds component 0 before power management
            // starts; starting gives up registration's activation of
            // each: 0 stays active, untold, and 1 becomes idle.
            fx::PoFxActivateComponent(handle, 0, 0);
            if !logged().is_empty() || device.parts() != [(2, true), (1, true)] {
                return Err("activating an active component told the driver something");
            }
            fx::PoFxStartDevicePowerManagement(handle);
            if logged() != [event(IDLE, 1, dispatch)] {
                return Err("starting power management did not idle the unused component alone");
            }
            if device.parts() != [(1, true), (0, true)] || !fx::test_state(handle).started {
                return Err("starting power management did not give up each activation");
            }

            // The first activation of an idle component: told here,
            // before the call returns.
            fx::PoFxActivateComponent(handle, 1, 0);
            if logged() != [event(ACTIVE, 1, passive)] {
                return Err("activating an idle component did not tell the driver at once");
            }
            // A second activation, and giving it up: nothing.
            fx::PoFxActivateComponent(handle, 1, 0);
            fx::PoFxIdleComponent(handle, 1, 0);
            if !logged().is_empty() || device.parts()[1] != (1, true) {
                return Err("a component that stayed active was reported");
            }

            // The last activation goes, and the driver takes its time
            // to complete: the component is not idle yet, and an
            // activation meanwhile waits.
            COMPLETES.store(0, Ordering::Release);
            fx::PoFxIdleComponent(handle, 1, 0);
            if logged() != [event(IDLE, 1, dispatch)] || device.parts()[1] != (0, false) {
                return Err("idling a component did not leave it waiting for its driver");
            }
            fx::PoFxActivateComponent(handle, 1, 0);
            if !logged().is_empty() || device.parts()[1] != (1, false) {
                return Err("a component was told active while it was still becoming idle");
            }
            // The driver completes: a worker tells it the component is
            // active again.
            fx::PoFxCompleteIdleCondition(handle, 1);
            await_logged(1);
            if logged() != [event(ACTIVE, 1, passive) | ELSEWHERE] {
                return Err("completing the idle condition did not activate the component");
            }
            COMPLETES.store(1, Ordering::Release);

            // From another thread, when asked for.
            fx::PoFxIdleComponent(handle, 1, FLAG_ASYNC_ONLY);
            await_logged(1);
            if logged() != [event(IDLE, 1, dispatch) | ELSEWHERE] {
                return Err("an idling asked for from another thread was not made from one");
            }
            // A blocking activation returns when the driver has been
            // told. The idle transition above may still be finishing
            // in the worker: the activation waits for that too.
            fx::PoFxActivateComponent(handle, 1, FLAG_BLOCKING);
            let told = logged();
            if told.len() != 1 || told[0] & !ELSEWHERE != event(ACTIVE, 1, passive) {
                return Err("a blocking activation returned before the driver was told");
            }
            if device.parts() != [(1, true), (1, true)] {
                return Err("the components are not active and at rest");
            }
            // Component 0 at last: the driver's own activation goes.
            fx::PoFxIdleComponent(handle, 0, FLAG_BLOCKING);
            if logged() != [event(IDLE, 0, dispatch)] || device.parts()[0] != (0, true) {
                return Err("a blocking idling returned before the component was idle");
            }
            if WRONG.load(Ordering::Acquire) != 0 {
                return Err(
                    "a callback NK never makes was made, or one was handed the wrong context",
                );
            }
        }
        Ok(14)
    })();
    if checked.is_ok() && (fx::test_devices() != devices || pool::usage().blocks != blocks) {
        return Err("the test's registration was not freed");
    }
    checked
}

/// What a driver tells the framework is recorded, and what it asks of
/// a platform extension is answered as Windows answers with none.
/// Returns the facts checked.
fn no_extension() -> Result<u32, &'static str> {
    let device = Registered::new()?;
    let handle = device.handle;
    // SAFETY: the test's registration; locals for what is written.
    unsafe {
        fx::PoFxSetComponentLatency(handle, 1, 5_000);
        fx::PoFxSetComponentResidency(handle, 0, 9_000);
        fx::PoFxSetDeviceIdleTimeout(handle, u64::MAX);
        fx::PoFxReportDevicePoweredOn(handle);
        fx::PoFxRegisterDripsWatchdogCallback(
            handle,
            core::ptr::without_provenance_mut(0x3000),
            1,
            core::ptr::without_provenance_mut(0x4000),
        );
        fx::PoFxCompleteIdleState(handle, 1);
        fx::PoFxNotifySurprisePowerOn(device.pair.pdo);
        fx::PoFxNotifySurprisePowerOn(core::ptr::null_mut());
        let state = fx::test_state(handle);
        if state.parts != [(1, true, 0, 9_000), (1, true, 5_000, 0)] {
            return Err("a component's latency or residency was not recorded");
        }
        if state.idle_timeout != 0x3FFF_FFFF_FFFF_FFFF {
            return Err("the idle timeout was not recorded, capped as Windows caps it");
        }
        if !state.reported_on || state.watchdog != Some((0x3000, true, 0x4000)) {
            return Err("what the driver reported or registered was not recorded");
        }

        let mut returned = 0xAAAAusize;
        let status = fx::PoFxPowerControl(
            handle,
            &ID,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            0,
            &raw mut returned,
        );
        if status != STATUS_NOT_SUPPORTED || returned != 0 {
            return Err("a power control request was not refused as with no extension");
        }
        if fx::PoFxRegisterCrashdumpDevice(handle) != STATUS_NOT_SUPPORTED
            || fx::PoFxRegisterCrashdumpDevice(core::ptr::null_mut()) != STATUS_INVALID_PARAMETER
            || fx::PoFxPowerOnCrashdumpDevice(handle, core::ptr::null_mut()) != STATUS_UNSUCCESSFUL
            || fx::PoFxPowerOnCrashdumpDevice(core::ptr::null_mut(), core::ptr::null_mut())
                != STATUS_INVALID_PARAMETER
        {
            return Err("a crash dump device was not answered as with no extension");
        }

        // Performance states: one set, or none.
        let sets = |count: u32| [count, 0, 0, 0];
        let (one, none) = (sets(1), sets(0));
        let mut out = core::ptr::null_mut();
        let perf = |flags, input: *const [u32; 4], output| {
            fx::PoFxRegisterComponentPerfStates(
                handle,
                0,
                flags,
                core::ptr::null_mut(),
                input.cast(),
                output,
            )
        };
        if perf(0, &raw const one, core::ptr::null_mut()) != STATUS_NOT_IMPLEMENTED
            || perf(0, core::ptr::null(), &raw mut out) != STATUS_NOT_IMPLEMENTED
            || perf(0, core::ptr::null(), core::ptr::null_mut()) != STATUS_INVALID_PARAMETER
            || perf(0, &raw const one, &raw mut out) != STATUS_INVALID_PARAMETER
            || perf(1, &raw const none, core::ptr::null_mut()) != STATUS_INVALID_PARAMETER
            || perf(1, &raw const one, core::ptr::null_mut()) != STATUS_SUCCESS
            || perf(1, &raw const one, core::ptr::null_mut()) != STATUS_INVALID_PARAMETER
            || !out.is_null()
        {
            return Err("performance states were not answered as with no extension");
        }
        if WRONG.load(Ordering::Acquire) != 0 || !logged().is_empty() {
            return Err("a callback was made for what is only recorded");
        }
    }
    Ok(8)
}
