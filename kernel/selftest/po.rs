//! The power manager.
//!
//! The drivers are here, in Rust, written the way WDM drivers in C are
//! and calling the exports a real driver calls: a bus driver's device
//! and a function driver's attached on top of it, which ask the power
//! manager for power requests and are sent them.

use super::stack::{self, FDO, PDO, layer};
use crate::io::{device, irp};
use crate::ke::wait;
use crate::mm::pool;
use crate::po::{request, setting};
use crate::test::{Group, Report, Slot};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU32, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::ex::GUID;
use nk_ntabi::io::*;
use nk_ntabi::ke::KEVENT;
use nk_ntabi::pnp::*;
use nk_ntabi::status::*;
use nk_po::setting::{GUID_ACDC_POWER_SOURCE, GUID_CONSOLE_DISPLAY_STATE};

pub static GROUP: Group = Group {
    names: &[
        "po.information",
        "po.request-power-irp",
        "po.power-state",
        "po.setting-callback",
        "po.setting-unregister",
        "po.coalescing",
        "po.power-action",
    ],
    run,
    manual: false,
};

fn run(r: &mut Report, _: &BootInfo) {
    r.check("po.information", crate::po::test);
    let mut numbered = |name: &str, result: Result<u32, &'static str>| match result {
        Ok(n) => r.ok_with(name, format_args!("{n} checked")),
        Err(why) => r.fail(name, format_args!("{why}")),
    };
    numbered("po.request-power-irp", request_power_irp());
    numbered("po.power-state", power_state());
    numbered("po.setting-callback", setting_callback());
    numbered("po.setting-unregister", setting_unregister());
    numbered("po.coalescing", coalescing());
    r.check("po.power-action", crate::po::action::test);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];

/// What happened, in order: `EVENT << 8 | minor function`.
const AT_FUNCTION: u32 = 1;
const AT_BUS: u32 = 2;
const COMPLETED: u32 = 3;
static LOG: [AtomicU32; 32] = [const { AtomicU32::new(0) }; 32];
static LOGGED: AtomicUsize = AtomicUsize::new(0);

const fn event(kind: u32, minor: u8) -> u32 {
    kind << 8 | minor as u32
}

fn log(kind: u32, minor: u8) {
    let at = LOGGED.fetch_add(1, Ordering::AcqRel);
    if let Some(slot) = LOG.get(at) {
        slot.store(event(kind, minor), Ordering::Release);
    }
}

/// What has happened since the last call.
fn logged() -> Vec<u32> {
    let n = LOGGED.swap(0, Ordering::AcqRel).min(LOG.len());
    LOG[..n].iter().map(|e| e.load(Ordering::Acquire)).collect()
}

/// The last request that reached the bus driver: how many stack
/// locations it had, the status it arrived with, its parameters, and
/// whether its location named the bus driver's device.
static STACK_COUNT: AtomicU32 = AtomicU32::new(0);
static ARRIVED_STATUS: AtomicU32 = AtomicU32::new(0);
static PARAMETERS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
static WRONG: AtomicU32 = AtomicU32::new(0);
/// The set of the device's power state the bus driver holds, and the
/// wait-wake it holds.
static HELD: AtomicPtr<IRP> = AtomicPtr::new(core::ptr::null_mut());
static WAKE: AtomicPtr<IRP> = AtomicPtr::new(core::ptr::null_mut());
/// What the completion function was last handed: the device, the
/// state, the context, the request's status.
static TOLD: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];

/// The function driver's dispatch routine: a power request is passed
/// down as a driver that has nothing to do for it passes it.
///
/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn function_dispatch(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: a live IRP being dispatched to a device of the test's.
    unsafe {
        let location = (*request).CurrentStackLocation;
        if (*location).MajorFunction != IRP_MJ_POWER {
            return irp::invalid_device_request(device, request);
        }
        log(AT_FUNCTION, (*location).MinorFunction);
        irp::PoStartNextPowerIrp(request);
        // `IoSkipCurrentIrpStackLocation`.
        (*request).CurrentLocation += 1;
        (*request).CurrentStackLocation = location.add(1);
        irp::PoCallDriver((*layer(device)).lower, request)
    }
}

/// The bus driver's cancel routine: complete the wait-wake it holds as
/// cancelled.
///
/// # Safety
/// Called as a cancel routine, holding the cancel spin lock.
unsafe extern "C" fn wake_cancel(_: *mut DEVICE_OBJECT, request: *mut IRP) {
    // SAFETY: per the contract: whoever took the cancel routine out
    // completes the request, and that was `IoCancelIrp`.
    unsafe {
        irp::IoReleaseCancelSpinLock((*request).CancelIrql);
        WAKE.store(core::ptr::null_mut(), Ordering::Release);
        (*request).IoStatus.Status = STATUS_CANCELLED;
        irp::IofCompleteRequest(request, 0);
    }
}

/// The bus driver's dispatch routine. A wait-wake is held, cancellable,
/// as a bus driver holds one until its device signals; a set to D3 is
/// held until the test completes it; any other set is recorded with
/// `PoSetPowerState` and completed; a query is completed.
///
/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn bus_dispatch(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: a live IRP being dispatched to a device of the test's.
    unsafe {
        let location = (*request).CurrentStackLocation;
        if (*location).MajorFunction != IRP_MJ_POWER {
            return irp::invalid_device_request(device, request);
        }
        let minor = (*location).MinorFunction;
        let parameters = (*location).Parameters;
        log(AT_BUS, minor);
        STACK_COUNT.store((*request).StackCount as u32, Ordering::Release);
        ARRIVED_STATUS.store((*request).IoStatus.Status as u32, Ordering::Release);
        for (slot, value) in PARAMETERS.iter().zip(parameters) {
            slot.store(value as usize, Ordering::Release);
        }
        if (*location).DeviceObject != device {
            WRONG.fetch_add(1, Ordering::AcqRel);
        }
        let state = parameters[2] as u32;
        match minor {
            IRP_MN_WAIT_WAKE => {
                // `IoMarkIrpPending`, `IoSetCancelRoutine`, then look
                // whether the request was cancelled before there was a
                // routine to call.
                (*location).Control |= SL_PENDING_RETURNED;
                WAKE.store(request, Ordering::Release);
                let routine = AtomicPtr::from_ptr(&raw mut (*request).CancelRoutine);
                routine.store(wake_cancel as *mut c_void, Ordering::SeqCst);
                if irp::cancel_flag(request).load(Ordering::SeqCst) != 0
                    && !routine
                        .swap(core::ptr::null_mut(), Ordering::SeqCst)
                        .is_null()
                {
                    WAKE.store(core::ptr::null_mut(), Ordering::Release);
                    (*request).IoStatus.Status = STATUS_CANCELLED;
                    irp::IofCompleteRequest(request, 0);
                }
                STATUS_PENDING
            }
            IRP_MN_SET_POWER if state == POWER_DEVICE_D3 => {
                (*location).Control |= SL_PENDING_RETURNED;
                HELD.store(request, Ordering::Release);
                STATUS_PENDING
            }
            _ => {
                if minor == IRP_MN_SET_POWER {
                    request::PoSetPowerState(device, POWER_STATE_TYPE_DEVICE, state);
                }
                (*request).IoStatus.Status = STATUS_SUCCESS;
                irp::IofCompleteRequest(request, 0);
                STATUS_SUCCESS
            }
        }
    }
}

/// The function driver's completion function for the requests it asks
/// for.
///
/// # Safety
/// Called as a `REQUEST_POWER_COMPLETE`.
unsafe extern "C" fn power_complete(
    device: *mut DEVICE_OBJECT,
    minor: u8,
    state: u32,
    context: *mut c_void,
    status: *mut IO_STATUS_BLOCK,
) {
    log(COMPLETED, minor);
    TOLD[0].store(device.addr(), Ordering::Release);
    TOLD[1].store(state as usize, Ordering::Release);
    TOLD[2].store(context.addr(), Ordering::Release);
    // SAFETY: per the contract: the request's status block.
    TOLD[3].store(
        unsafe { (*status).Status } as u32 as usize,
        Ordering::Release,
    );
}

/// What the completion function was last handed.
fn told() -> [usize; 4] {
    core::array::from_fn(|i| TOLD[i].load(Ordering::Acquire))
}

/// A bus driver's device and a function driver's attached to it.
pub(super) struct Pair {
    drivers: [*mut DRIVER_OBJECT; 2],
    pub(super) pdo: *mut DEVICE_OBJECT,
    pub(super) fdo: *mut DEVICE_OBJECT,
}

/// What stands in for a device node: the power manager only asks
/// whether the bottom of a stack has one.
static NODE: AtomicU32 = AtomicU32::new(0);

impl Pair {
    pub(super) fn build() -> Result<Self, &'static str> {
        let mut pair = Pair {
            drivers: [core::ptr::null_mut(); 2],
            pdo: core::ptr::null_mut(),
            fdo: core::ptr::null_mut(),
        };
        // On a failure half way, `Drop` takes down what was made.
        pair.drivers[0] = stack::make_driver(bus_dispatch)?;
        pair.drivers[1] = stack::make_driver(function_dispatch)?;
        pair.pdo = stack::make_device(pair.drivers[0], PDO, None)?;
        pair.fdo = stack::make_device(pair.drivers[1], FDO, None)?;
        // SAFETY: devices of the test's; the function driver keeps what
        // it was attached to, as its `AddDevice` does.
        unsafe {
            (*layer(pair.fdo)).lower = device::IoAttachDeviceToDeviceStack(pair.fdo, pair.pdo);
            if (*layer(pair.fdo)).lower != pair.pdo {
                return Err("the function driver's device was not attached to the bus driver's");
            }
        }
        Ok(pair)
    }

    /// Say whether the bus driver's device has a device node, as the
    /// Plug and Play manager gives one to a device a bus driver
    /// reports.
    pub(super) fn enumerated(&self, has_node: bool) {
        let node = if has_node {
            NODE.as_ptr().cast()
        } else {
            core::ptr::null_mut()
        };
        // SAFETY: a device of the test's; its extension is the I/O
        // manager's, whose `DeviceNode` nothing else of NK writes.
        unsafe { (*(*self.pdo).DeviceObjectExtension).DeviceNode = node };
    }
}

impl Drop for Pair {
    fn drop(&mut self) {
        // SAFETY: devices and drivers of the test's, taken down top
        // first.
        unsafe {
            if !self.fdo.is_null() {
                if !(*layer(self.fdo)).lower.is_null() {
                    device::IoDetachDevice(self.pdo);
                }
                device::IoDeleteDevice(self.fdo);
            }
            if !self.pdo.is_null() {
                (*(*self.pdo).DeviceObjectExtension).DeviceNode = core::ptr::null_mut();
                device::IoDeleteDevice(self.pdo);
            }
            for driver in self.drivers {
                if !driver.is_null() {
                    stack::free_driver(driver);
                }
            }
        }
    }
}

/// Ask for a power request for the function driver's device.
///
/// # Safety
/// `pair` is built; `out` is null or writable.
unsafe fn ask(pair: &Pair, minor: u8, state: u32, context: usize, out: *mut *mut IRP) -> NTSTATUS {
    // SAFETY: per the contract; the completion function is one.
    unsafe {
        request::PoRequestPowerIrp(
            pair.fdo,
            minor,
            state,
            power_complete as *mut c_void,
            core::ptr::without_provenance_mut(context),
            out,
        )
    }
}

/// A driver asks for power requests and is sent them: built as Windows
/// builds one, down from the top of the stack, its completion function
/// told what Windows tells it; a device's queries and sets one at a
/// time and in order; a wait-wake at once, held below, marked and
/// cancelled. Returns the facts checked.
fn request_power_irp() -> Result<u32, &'static str> {
    let blocks = pool::usage().blocks;
    let checked = (|| {
        let pair = Pair::build()?;
        logged();
        let junk = core::ptr::without_provenance_mut::<IRP>(1);
        let mut out = junk;
        // SAFETY: a stack of the test's, whose drivers are above.
        unsafe {
            // A stack the Plug and Play manager does not know.
            if ask(&pair, IRP_MN_SET_POWER, POWER_DEVICE_D0, 0, &raw mut out)
                != STATUS_INVALID_DEVICE_REQUEST
                || !out.is_null()
            {
                return Err("a power request for a stack with no device node was not refused");
            }
            pair.enumerated(true);
            out = junk;
            if ask(&pair, IRP_MN_POWER_SEQUENCE, 0, 0, &raw mut out) != STATUS_INVALID_PARAMETER_2
                || !out.is_null()
                || !logged().is_empty()
            {
                return Err("a power request of a kind a driver may not ask for was not refused");
            }

            // A set, completed below at once.
            if ask(
                &pair,
                IRP_MN_SET_POWER,
                POWER_DEVICE_D0,
                0x1111,
                core::ptr::null_mut(),
            ) != STATUS_PENDING
            {
                return Err("PoRequestPowerIrp did not return STATUS_PENDING");
            }
            let set = IRP_MN_SET_POWER;
            if logged()
                != [
                    event(AT_FUNCTION, set),
                    event(AT_BUS, set),
                    event(COMPLETED, set),
                ]
            {
                return Err("a set of the power state did not go down the stack and complete");
            }
            if told()
                != [
                    pair.fdo.addr(),
                    POWER_DEVICE_D0 as usize,
                    0x1111,
                    STATUS_SUCCESS as u32 as usize,
                ]
            {
                return Err("the completion function was not told what Windows tells it");
            }
            let parameters: [u64; 4] =
                core::array::from_fn(|i| PARAMETERS[i].load(Ordering::Acquire) as u64);
            if parameters
                != power_parameters(
                    0,
                    POWER_STATE_TYPE_DEVICE,
                    POWER_DEVICE_D0,
                    POWER_ACTION_NONE,
                )
                || STACK_COUNT.load(Ordering::Acquire) != 3
                || ARRIVED_STATUS.load(Ordering::Acquire) != STATUS_NOT_SUPPORTED as u32
            {
                return Err("a power request was not built as Windows builds one");
            }

            // A set held below: the query asked for next waits for it.
            let query = IRP_MN_QUERY_POWER;
            if ask(&pair, set, POWER_DEVICE_D3, 0x2222, core::ptr::null_mut()) != STATUS_PENDING
                || logged() != [event(AT_FUNCTION, set), event(AT_BUS, set)]
            {
                return Err("a set of the power state did not reach the bus driver");
            }
            let held = HELD.swap(core::ptr::null_mut(), Ordering::AcqRel);
            if ask(&pair, query, POWER_DEVICE_D0, 0x3333, core::ptr::null_mut()) != STATUS_PENDING
                || !logged().is_empty()
            {
                return Err("a query was sent while the device's set was still out");
            }
            // A wait-wake does not wait.
            let wake_event = IRP_MN_WAIT_WAKE;
            out = junk;
            if ask(
                &pair,
                wake_event,
                POWER_SYSTEM_SLEEPING3,
                0x4444,
                &raw mut out,
            ) != STATUS_PENDING
                || logged() != [event(AT_FUNCTION, wake_event), event(AT_BUS, wake_event)]
            {
                return Err("a wait-wake was not sent at once");
            }
            let wake = WAKE.load(Ordering::Acquire);
            let parameters: [u64; 4] =
                core::array::from_fn(|i| PARAMETERS[i].load(Ordering::Acquire) as u64);
            if out != wake
                || wake.is_null()
                || parameters != wait_wake_parameters(POWER_SYSTEM_SLEEPING3)
            {
                return Err("a wait-wake was not handed back and built as Windows builds one");
            }
            if request::test_state(pair.pdo).0 != 3 {
                return Err("the power manager does not have three requests out");
            }
            // The mark is a wait-wake's alone.
            request::PoSetSystemWake(held);
            if request::PoGetSystemWake(held) != 0 || request::PoGetSystemWake(wake) != 0 {
                return Err("a request was marked as having woken the system before it was");
            }
            request::PoSetSystemWake(wake);
            if request::PoGetSystemWake(wake) != 1 {
                return Err("a wait-wake marked as having woken the system does not say so");
            }

            // The bus driver completes the set: its completion function
            // runs, and then the query goes down.
            (*held).IoStatus.Status = STATUS_SUCCESS;
            irp::IofCompleteRequest(held, 0);
            if logged()
                != [
                    event(COMPLETED, set),
                    event(AT_FUNCTION, query),
                    event(AT_BUS, query),
                    event(COMPLETED, query),
                ]
            {
                return Err("the query that waited was not sent when the set completed");
            }
            if told()[2] != 0x3333 {
                return Err("the query's completion function was not told its context");
            }

            // The wait-wake is cancelled, as a driver cancels one.
            if irp::IoCancelIrp(wake) != 1 || logged() != [event(COMPLETED, wake_event)] {
                return Err("cancelling a wait-wake did not complete it");
            }
            if told()
                != [
                    pair.fdo.addr(),
                    POWER_SYSTEM_SLEEPING3 as usize,
                    0x4444,
                    STATUS_CANCELLED as u32 as usize,
                ]
            {
                return Err("a cancelled wait-wake's completion function was not told so");
            }

            // No completion function.
            if request::PoRequestPowerIrp(
                pair.fdo,
                query,
                POWER_DEVICE_D0,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            ) != STATUS_PENDING
                || logged() != [event(AT_FUNCTION, query), event(AT_BUS, query)]
            {
                return Err("a request with no completion function was not sent");
            }
            if request::test_state(pair.pdo).0 != 0 {
                return Err("a completed request is still on the power manager's list");
            }
            if WRONG.load(Ordering::Acquire) != 0 {
                return Err("a request's location did not name the device it was sent to");
            }
        }
        Ok(17)
    })();
    if checked.is_ok() && pool::usage().blocks != blocks {
        return Err("a power request, or a device's power block, was not freed");
    }
    checked
}

/// `PoSetPowerState` records a device's and the system's state in the
/// device object and returns the one before; no watchdog runs; the
/// flags for the platform's idle state are recorded for a device with
/// a device node. Returns the facts checked.
fn power_state() -> Result<u32, &'static str> {
    let pair = Pair::build()?;
    // SAFETY: devices of the test's.
    unsafe {
        let flags = || (*(*pair.fdo).DeviceObjectExtension).PowerFlags;
        let set = |kind, state| request::PoSetPowerState(pair.fdo, kind, state);
        if flags() != 0 {
            return Err("a new device has a power state recorded");
        }
        if set(POWER_STATE_TYPE_DEVICE, POWER_DEVICE_D0) != POWER_DEVICE_UNSPECIFIED
            || set(POWER_STATE_TYPE_DEVICE, POWER_DEVICE_D3) != POWER_DEVICE_D0
            || set(POWER_STATE_TYPE_SYSTEM, POWER_SYSTEM_WORKING) != POWER_SYSTEM_UNSPECIFIED
            || set(POWER_STATE_TYPE_SYSTEM, POWER_SYSTEM_SLEEPING1) != POWER_SYSTEM_WORKING
            || set(POWER_STATE_TYPE_DEVICE, POWER_DEVICE_D0) != POWER_DEVICE_D3
        {
            return Err("PoSetPowerState did not return the state recorded before");
        }
        if flags() != (POWER_DEVICE_D0 << 4 | POWER_SYSTEM_SLEEPING1) {
            return Err("the power states are not recorded where Windows records them");
        }
        if set(2, 3) != 0 || flags() != (POWER_DEVICE_D0 << 4 | POWER_SYSTEM_SLEEPING1) {
            return Err("a kind of power state Windows does not define was recorded");
        }

        let mut seconds = 0xAAAA_AAAAu32;
        if request::PoQueryWatchdogTime(pair.pdo, &raw mut seconds) != 0 || seconds != 0xAAAA_AAAA {
            return Err("a watchdog was reported for a device's power request");
        }

        let drips = |device, flags| request::PoDirectedDripsSetDeviceFlags(device, flags);
        if drips(core::ptr::null_mut(), 1) != STATUS_INVALID_PARAMETER
            || drips(pair.pdo, 1) != STATUS_INVALID_PARAMETER
        {
            return Err("flags were taken for no device, or one with no device node");
        }
        pair.enumerated(true);
        if drips(pair.pdo, 0x40) != STATUS_INVALID_PARAMETER || request::test_state(pair.pdo).1 != 0
        {
            return Err("a flag Windows does not define was taken");
        }
        if drips(pair.pdo, 0x01) != STATUS_SUCCESS
            || drips(pair.pdo, 0x24) != STATUS_SUCCESS
            || request::test_state(pair.pdo).1 != 0x25
        {
            return Err("a device's flags were not recorded");
        }
        // The same through `ZwPowerInformation`, as `storport.sys`
        // sets and clears them.
        if crate::po::test_drips(true, pair.pdo, 0x10, 0x10) != STATUS_INVALID_PARAMETER
            || crate::po::test_drips(true, pair.pdo, 0x40, 0x18) != STATUS_INVALID_PARAMETER
            || crate::po::test_drips(true, pair.pdo, 0x10, 0x18) != STATUS_SUCCESS
            || request::test_state(pair.pdo).1 != 0x35
        {
            return Err("the internal request did not set a device's flags");
        }
        if crate::po::test_drips(false, core::ptr::null_mut(), 0x10, 0x18)
            != STATUS_INVALID_PARAMETER
            || crate::po::test_drips(false, pair.pdo, 0x14, 0x18) != STATUS_SUCCESS
            || request::test_state(pair.pdo).1 != 0x21
        {
            return Err("the internal request did not clear a device's flags");
        }
    }
    Ok(11)
}

/// What a setting's callback was handed, by which registration it is
/// (its context): the setting's first word, the value, its length.
static HANDED: [[AtomicU32; 3]; 4] = [const { [const { AtomicU32::new(0) }; 3] }; 4];
/// How often each registration's callback has run.
static CALLS: [AtomicU32; 4] = [const { AtomicU32::new(0) }; 4];
/// Set when a callback has run.
static CALLED: Slot<KEVENT> = Slot::new();
/// Whether the next callback takes its own registration back; the
/// event that tells it that its handle is known; the handle; and what
/// taking it back returned.
static TAKES_ITSELF_BACK: AtomicU32 = AtomicU32::new(0);
static HANDLE_KNOWN: Slot<KEVENT> = Slot::new();
static OWN: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static OWN_STATUS: AtomicU32 = AtomicU32::new(0);
/// How long a callback stays in itself, in milliseconds.
static STAY: AtomicU32 = AtomicU32::new(0);
/// Set as a callback is entered, and once it has stayed.
static ENTERED: Slot<KEVENT> = Slot::new();
static STAYED: AtomicU32 = AtomicU32::new(0);

/// A driver's power setting callback.
///
/// # Safety
/// Called as a `POWER_SETTING_CALLBACK`.
unsafe extern "C" fn setting_changed(
    setting: *const GUID,
    value: *mut c_void,
    length: u32,
    context: *mut c_void,
) -> NTSTATUS {
    let which = context.addr() & 3;
    // SAFETY: per the contract: a GUID, and `length` bytes of value,
    // which this reads only if they are the four expected.
    unsafe {
        HANDED[which][0].store((*setting).Data1, Ordering::Release);
        let read = if length == 4 {
            value.cast::<u32>().read_unaligned()
        } else {
            u32::MAX
        };
        HANDED[which][1].store(read, Ordering::Release);
        HANDED[which][2].store(length, Ordering::Release);
        if TAKES_ITSELF_BACK.swap(0, Ordering::AcqRel) != 0 {
            wait::wait(Some(HANDLE_KNOWN.ptr().cast()), None);
            let own = OWN.swap(core::ptr::null_mut(), Ordering::AcqRel);
            let status = setting::PoUnregisterPowerSettingCallback(own);
            OWN_STATUS.store(status as u32, Ordering::Release);
        }
        let stay = STAY.swap(0, Ordering::AcqRel);
        if stay != 0 {
            wait::KeSetEvent(ENTERED.ptr(), 0, 0);
            let interval = -i64::from(stay) * 10_000;
            wait::KeDelayExecutionThread(0, 0, &raw const interval);
            STAYED.store(1, Ordering::Release);
        }
        CALLS[which].fetch_add(1, Ordering::AcqRel);
        wait::KeSetEvent(CALLED.ptr(), 0, 0);
    }
    STATUS_SUCCESS
}

/// Register the test's callback for `setting`, as registration `which`.
fn register(setting: &GUID, which: usize) -> (NTSTATUS, *mut c_void) {
    let mut handle = core::ptr::null_mut();
    // SAFETY: a GUID, the callback above, a local for the handle.
    let status = unsafe {
        setting::PoRegisterPowerSettingCallback(
            core::ptr::null_mut(),
            setting,
            setting_changed as *mut c_void,
            core::ptr::without_provenance_mut(which),
            &raw mut handle,
        )
    };
    (status, handle)
}

/// Wait until registration `which` has been called `times` times.
fn await_calls(which: usize, times: u32) {
    while CALLS[which].load(Ordering::Acquire) < times {
        // SAFETY: the event the callback sets, initialised by the test.
        unsafe {
            wait::wait(Some(CALLED.ptr().cast()), None);
            wait::KeClearEvent(CALLED.ptr());
        }
    }
}

fn reset_calls() {
    for which in 0..CALLS.len() {
        CALLS[which].store(0, Ordering::Release);
        for word in &HANDED[which] {
            word.store(0, Ordering::Release);
        }
    }
    // SAFETY: static storage for events nothing waits on.
    unsafe {
        wait::KeInitializeEvent(CALLED.ptr(), 0, 0);
        wait::KeInitializeEvent(ENTERED.ptr(), 0, 0);
    }
}

/// `GUID_DISK_IDLE_TIMEOUT`, which `classpnp.sys` registers for: a
/// setting of the power scheme's, which has no value on NK.
const GUID_DISK_IDLE_TIMEOUT: GUID = GUID {
    Data1: 0x58E3_9BA8,
    Data2: 0xB8E6,
    Data3: 0x4EF6,
    Data4: [0x90, 0xD0, 0x89, 0xAE, 0x32, 0xB2, 0x58, 0xD6],
};

/// `GUID_SESSION_DISPLAY_STATUS`, which belongs to a session.
const GUID_SESSION_DISPLAY_STATUS: GUID = GUID {
    Data1: 0x2B84_C20E,
    Data2: 0xAD23,
    Data3: 0x4DDF,
    Data4: [0x93, 0xDB, 0x05, 0xFF, 0xBD, 0x7E, 0xFC, 0xA5],
};

/// A callback registered for a setting that has a value is called once
/// with it, from a worker thread: the power source is AC, the console's
/// display on. One registered for a setting with no value is not
/// called; a session's setting is refused. Returns the facts checked.
fn setting_callback() -> Result<u32, &'static str> {
    reset_calls();
    let before = setting::test_state(core::ptr::null_mut()).0;
    // Registered first, so that it would be called first if it were
    // called at all.
    let (status, scheme) = register(&GUID_DISK_IDLE_TIMEOUT, 0);
    if status != STATUS_SUCCESS || scheme.is_null() {
        return Err("a registration for a setting of the power scheme's was refused");
    }
    let (status, source) = register(&GUID_ACDC_POWER_SOURCE, 1);
    if status != STATUS_SUCCESS || source.is_null() || source == scheme {
        return Err("a registration for the power source was refused");
    }
    let (status, display) = register(&GUID_CONSOLE_DISPLAY_STATE, 2);
    if status != STATUS_SUCCESS || display.is_null() {
        return Err("a registration for the state of the display was refused");
    }
    let (status, session) = register(&GUID_SESSION_DISPLAY_STATUS, 3);
    if status != STATUS_INVALID_PARAMETER || !session.is_null() {
        return Err("a registration for a session's setting was not refused");
    }
    await_calls(1, 1);
    await_calls(2, 1);
    let handed = |which: usize| -> [u32; 3] {
        core::array::from_fn(|i| HANDED[which][i].load(Ordering::Acquire))
    };
    if handed(1) != [GUID_ACDC_POWER_SOURCE.Data1, 0, 4] {
        return Err("the power source was not reported as AC");
    }
    if handed(2) != [GUID_CONSOLE_DISPLAY_STATE.Data1, 1, 4] {
        return Err("the console's display was not reported as on");
    }
    if CALLS[0].load(Ordering::Acquire) != 0 || CALLS[3].load(Ordering::Acquire) != 0 {
        return Err("a callback was called for a setting that has no value");
    }
    if setting::test_state(core::ptr::null_mut()).0 != before + 3 {
        return Err("the power manager does not have the three registrations");
    }
    for handle in [scheme, source, display] {
        if setting::PoUnregisterPowerSettingCallback(handle) != STATUS_SUCCESS {
            return Err("a registration could not be taken back");
        }
    }
    if setting::PoUnregisterPowerSettingCallback(source) != STATUS_INVALID_PARAMETER
        || setting::PoUnregisterPowerSettingCallback(core::ptr::null_mut())
            != STATUS_INVALID_PARAMETER
    {
        return Err("a handle that names no registration was not refused");
    }
    if CALLS[1].load(Ordering::Acquire) != 1 || CALLS[2].load(Ordering::Acquire) != 1 {
        return Err("a callback was called more than once for a setting that did not change");
    }
    if setting::test_state(core::ptr::null_mut()).0 != before {
        return Err("a registration taken back is still there");
    }
    Ok(12)
}

/// A registration taken back from another thread while its callback
/// runs waits for the callback; taken back from inside its callback, it
/// goes when the callback returns. Returns the facts checked.
fn setting_unregister() -> Result<u32, &'static str> {
    reset_calls();
    let before = setting::test_state(core::ptr::null_mut()).0;

    // From another thread, while the callback is in itself: the call
    // returns only when the callback has.
    STAYED.store(0, Ordering::Release);
    STAY.store(30, Ordering::Release);
    let (status, slow) = register(&GUID_ACDC_POWER_SOURCE, 1);
    if status != STATUS_SUCCESS {
        return Err("a registration was refused");
    }
    // SAFETY: the event the callback sets as it is entered.
    unsafe { wait::wait(Some(ENTERED.ptr().cast()), None) };
    if setting::PoUnregisterPowerSettingCallback(slow) != STATUS_SUCCESS {
        return Err("a registration whose callback was running could not be taken back");
    }
    if STAYED.swap(0, Ordering::AcqRel) != 1 {
        return Err("a registration was taken back while its callback was still running");
    }
    if setting::PoUnregisterPowerSettingCallback(slow) != STATUS_INVALID_PARAMETER
        || setting::test_state(core::ptr::null_mut()).0 != before
    {
        return Err("a registration taken back after its callback is still there");
    }

    // From inside: the callback waits to be told which handle is its
    // own, which is known only once it is registered.
    // SAFETY: static storage for an event nothing waits on.
    unsafe { wait::KeInitializeEvent(HANDLE_KNOWN.ptr(), 0, 0) };
    OWN_STATUS.store(u32::MAX, Ordering::Release);
    TAKES_ITSELF_BACK.store(1, Ordering::Release);
    let (status, own) = register(&GUID_CONSOLE_DISPLAY_STATE, 2);
    if status != STATUS_SUCCESS {
        return Err("a registration was refused");
    }
    OWN.store(own, Ordering::Release);
    // SAFETY: the event above.
    unsafe { wait::KeSetEvent(HANDLE_KNOWN.ptr(), 0, 0) };
    await_calls(2, 1);
    if OWN_STATUS.load(Ordering::Acquire) != STATUS_SUCCESS as u32 {
        return Err("a callback could not take its own registration back");
    }
    // The registration goes when the callback returns: soon.
    let millisecond = -10_000i64;
    for _ in 0..1000 {
        if setting::test_state(core::ptr::null_mut()).0 == before {
            break;
        }
        // SAFETY: a relative interval in a local.
        unsafe { wait::KeDelayExecutionThread(0, 0, &raw const millisecond) };
    }
    if setting::test_state(core::ptr::null_mut()).0 != before {
        return Err("a registration taken back from inside its callback is still there");
    }
    if setting::PoUnregisterPowerSettingCallback(own) != STATUS_INVALID_PARAMETER {
        return Err("a registration that took itself back could be taken back again");
    }
    Ok(7)
}

/// A coalescing callback is registered and taken back; it is never
/// called. Returns the facts checked.
fn coalescing() -> Result<u32, &'static str> {
    let blocks = pool::usage().blocks;
    let mut handles = [core::ptr::null_mut(); 2];
    for (which, handle) in handles.iter_mut().enumerate() {
        // SAFETY: a local for the handle; the routine is never called.
        let status = unsafe {
            setting::PoRegisterCoalescingCallback(
                core::ptr::without_provenance_mut(0x1000 + which),
                which as u8,
                handle,
                core::ptr::without_provenance_mut(0x2000 + which),
            )
        };
        if status != STATUS_SUCCESS || handle.is_null() {
            return Err("a coalescing callback could not be registered");
        }
    }
    if handles[0] == handles[1] {
        return Err("two coalescing registrations have one handle");
    }
    for (which, handle) in handles.into_iter().enumerate() {
        if setting::test_state(handle).1 != Some((0x1000 + which, which == 1, 0x2000 + which)) {
            return Err("a coalescing registration was not recorded");
        }
        setting::PoUnregisterCoalescingCallback(handle);
        if setting::test_state(handle).1.is_some() {
            return Err("a coalescing registration taken back is still there");
        }
    }
    if pool::usage().blocks != blocks {
        return Err("a coalescing registration was not freed");
    }
    Ok(7)
}
