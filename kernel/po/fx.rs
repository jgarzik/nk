//! The runtime power framework (PoFx): a driver's devices as sets of
//! components, each active or idle.
//!
//! The counting and the order of what a driver is told are
//! `nk_po::fx`'s. NK never puts a component in a low-power F-state and
//! never powers a device down for being idle, so the callbacks that
//! ask a driver for either (`ComponentIdleStateCallback`,
//! `DevicePowerNotRequiredCallback`, `DevicePowerRequiredCallback`, the
//! directed ones) are recorded and never called, and there is no
//! platform extension (PEP) behind any of it (`doc/DESIGN.md`,
//! "Power").

use super::{POWER, Power, dope};
use crate::ex::work::ExQueueWorkItem;
use crate::io::device;
use crate::ke::bugcheck::KeBugCheckEx;
use crate::ke::seh::{self, Guard};
use crate::ke::{self, irql};
use crate::mm::pool;
use crate::ob::object::{self, ObRef};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use nk_ntabi::ex::{DELAYED_WORK_QUEUE, GUID, WORK_QUEUE_ITEM};
use nk_ntabi::io::DEVICE_OBJECT;
use nk_ntabi::ke::{KEVENT, LIST_ENTRY};
use nk_ntabi::po::*;
use nk_ntabi::status::*;
use nk_po::fx::{Component, Described, FLAG_ASYNC_ONLY, FLAG_BLOCKING, Tell, registration};

/// Pool tag of a registered device.
const TAG_FX: u32 = u32::from_le_bytes(*b"PoFx");

/// `INTERNAL_POWER_ERROR`, and the first parameters the pinned kernel
/// gives it for a driver's misuse of the framework (`PopFxBugCheck`).
const INTERNAL_POWER_ERROR: u32 = 0xA0;
const FX_ALREADY_REGISTERED: usize = 0x600;
const FX_NOT_ACTIVATED: usize = 0x608;
const FX_NOTHING_TO_COMPLETE: usize = 0x613;
const FX_BAD_ARGUMENT: usize = 0x614;
const FX_WATCHDOG_REGISTERED: usize = 0x622;
const FX_NO_DIRECTED_TRANSITION: usize = 0x910;

/// The longest idle timeout the pinned kernel records.
const LONGEST_IDLE_TIMEOUT: u64 = 0x3FFF_FFFF_FFFF_FFFF;

/// One component of a registered device.
struct Part {
    state: Component,
    /// Set while the component is at rest (`Component::at_rest`):
    /// what a blocking call waits on.
    rest: KEVENT,
    /// What the driver has said it can tolerate, recorded and never
    /// acted on (`PoFxSetComponentLatency`,
    /// `PoFxSetComponentResidency`).
    latency: u64,
    residency: u64,
}

/// A registered device. Its address is the driver's handle. Read and
/// written under [`POWER`].
struct Fx {
    /// The bottom of the device's stack, held by a pointer reference.
    base: *mut DEVICE_OBJECT,
    callbacks: PO_FX_CALLBACKS,
    /// `DirectedPowerUpCallback` and `DirectedPowerDownCallback`.
    directed: [usize; 2],
    context: usize,
    /// `Flags` and `DirectedFxTimeoutInSeconds`, as given.
    flags: u64,
    directed_timeout: u32,
    parts: Vec<Part>,
    /// Whether `PoFxStartDevicePowerManagement` has been called.
    started: bool,
    /// `PoFxSetDeviceIdleTimeout`, recorded and never acted on.
    idle_timeout: u64,
    /// `PoFxRegisterDripsWatchdogCallback`: the routine, whether the
    /// device's children are included, the driver object to match.
    watchdog: Option<(usize, bool, usize)>,
    /// Whether `PoFxReportDevicePoweredOn` has been called.
    reported_on: bool,
    /// Whether the device is on the worker's list.
    queued: bool,
    /// How many workers are making this device's callbacks.
    serving: u32,
    /// The event a thread waits on, in `PoFxUnregisterDevice`, for
    /// those workers to finish; 0 if none waits.
    leaving: usize,
}

/// The one work item that makes the callbacks owed to drivers that
/// asked for them from another thread: queued when a device comes to
/// be on the list and no worker is serving it (`Power::fx_working`).
struct WorkItem(UnsafeCell<WORK_QUEUE_ITEM>);

// SAFETY: touched only by the work queue's routines, and queued only
// while it is on no queue, which `Power::fx_working` sees to.
unsafe impl Sync for WorkItem {}

static WORKER: WorkItem = WorkItem(UnsafeCell::new(WORK_QUEUE_ITEM {
    List: LIST_ENTRY {
        Flink: core::ptr::null_mut(),
        Blink: core::ptr::null_mut(),
    },
    WorkerRoutine: Some(serve),
    Parameter: core::ptr::null_mut(),
}));

/// Stop the system as the pinned kernel does for a driver's misuse of
/// the framework.
fn misuse(code: usize, p2: usize, p3: usize, p4: usize) -> ! {
    KeBugCheckEx(INTERNAL_POWER_ERROR, code, p2, p3, p4)
}

/// Run `f` on the device `handle` names, under the lock. A handle that
/// names no registered device is a driver's error that Windows does
/// not check for; NK stops, naming `routine`.
fn with<R>(routine: &str, handle: *mut c_void, f: impl FnOnce(&mut Power, &mut Fx) -> R) -> R {
    let mut power = POWER.lock();
    if !power.fx.contains(&handle.addr()) {
        crate::kd::bugcheck(format_args!(
            "{routine}: {handle:p} is not a device registered with PoFxRegisterDevice"
        ));
    }
    // SAFETY: a device on the list is a live `Fx`, NK's own memory,
    // which only code holding the lock touches.
    f(&mut power, unsafe { &mut *handle.cast::<Fx>() })
}

/// Run `f` on a device that is known to be live: one a worker is
/// serving, or one the calling driver has just been found to have
/// registered.
///
/// # Safety
/// `handle` is a registered device, or one whose `serving` count the
/// caller holds.
unsafe fn locked<R>(handle: *mut c_void, f: impl FnOnce(&mut Power, &mut Fx) -> R) -> R {
    let mut power = POWER.lock();
    // SAFETY: per the contract; touched under the lock only.
    f(&mut power, unsafe { &mut *handle.cast::<Fx>() })
}

/// The component `index` of `fx`; an index past the last stops the
/// system, as on Windows.
fn part(fx: &mut Fx, handle: *mut c_void, index: u32) -> &mut Part {
    match fx.parts.get_mut(index as usize) {
        Some(part) => part,
        None => misuse(FX_BAD_ARGUMENT, handle.addr(), index as usize, 2),
    }
}

/// Make a component's event say whether it is at rest. Under the lock.
fn mark(part: &mut Part) {
    // SAFETY: the component's own event, initialised when the device
    // was registered.
    unsafe {
        if part.state.at_rest() {
            ke::wait::KeSetEvent(&raw mut part.rest, 0, 0);
        } else {
            ke::wait::KeClearEvent(&raw mut part.rest);
        }
    }
}

/// Put `fx` on the worker's list. Returns whether a worker is to be
/// started ([`start_worker`], once the lock is released). The list was
/// given room for every registered device when each was registered.
fn enqueue(power: &mut Power, fx: &mut Fx, handle: *mut c_void) -> bool {
    if fx.queued {
        return false;
    }
    fx.queued = true;
    power.fx_work.push(handle.addr());
    !core::mem::replace(&mut power.fx_working, true)
}

fn start_worker() {
    // SAFETY: the item is on no queue: a worker is started only when
    // none is at work or queued.
    unsafe { ExQueueWorkItem(WORKER.0.get(), DELAYED_WORK_QUEUE) };
}

/// Give the IRQL a callback was raised for back, if the callback is
/// unwound.
///
/// # Safety
/// `context` is the level to return to.
unsafe fn lower(context: *mut c_void) {
    irql::lower(context.addr() as u8);
}

/// Tell the driver what is owed about component `index`, one thing
/// after another, until nothing is: the active-condition callback at
/// the IRQL of this thread, the idle-condition callback at
/// `DISPATCH_LEVEL`, where the pinned kernel makes it (under the
/// component's spin lock, `PopFxIdleWorker`). A device with no
/// idle-condition callback is taken to have completed at once, as by
/// the pinned kernel.
///
/// # Safety
/// As [`locked`]; the device's callbacks may be called.
unsafe fn drive(handle: *mut c_void, index: u32) {
    loop {
        // SAFETY: per the contract.
        let (tell, context, callbacks) = unsafe {
            locked(handle, |_, fx| {
                let (context, callbacks) = (fx.context, fx.callbacks);
                let part = &mut fx.parts[index as usize];
                let tell = part.state.owed();
                mark(part);
                (tell, context, callbacks)
            })
        };
        let arguments = [context, index as usize, 0, 0];
        match tell {
            None => return,
            Some(Tell::Active) => {
                let routine = callbacks.ComponentActiveConditionCallback;
                if !routine.is_null() {
                    // SAFETY: the routine the driver registered.
                    // Nothing is held: if it is unwound the component
                    // stays as it is, its transition never finished.
                    unsafe { seh::call(routine.addr(), arguments, &Guard::Nothing) };
                }
                // SAFETY: per the contract.
                unsafe {
                    locked(handle, |_, fx| {
                        let part = &mut fx.parts[index as usize];
                        part.state.told_active();
                        mark(part);
                    });
                }
            }
            Some(Tell::Idle) => {
                let routine = callbacks.ComponentIdleConditionCallback;
                if !routine.is_null() {
                    let old = irql::raise(irql::DISPATCH_LEVEL);
                    let guard = Guard::Undo {
                        undo: lower,
                        context: core::ptr::without_provenance_mut(usize::from(old)),
                    };
                    // SAFETY: the routine the driver registered. If it
                    // is unwound the IRQL is given back and the
                    // component stays in its transition.
                    unsafe { seh::call(routine.addr(), arguments, &guard) };
                    irql::lower(old);
                }
                // SAFETY: per the contract.
                unsafe {
                    locked(handle, |_, fx| {
                        let part = &mut fx.parts[index as usize];
                        if routine.is_null() {
                            let _ = part.state.idle_completed();
                        }
                        part.state.told_idle();
                        mark(part);
                    });
                }
            }
        }
    }
}

/// Wait until component `index` is at rest.
///
/// # Safety
/// `handle` is a registered device and stays one; the caller is below
/// `DISPATCH_LEVEL`.
unsafe fn await_rest(handle: *mut c_void, index: u32) {
    loop {
        // SAFETY: per the contract.
        let (at_rest, rest) = unsafe {
            locked(handle, |_, fx| {
                let part = &mut fx.parts[index as usize];
                (part.state.at_rest(), &raw mut part.rest)
            })
        };
        if at_rest {
            return;
        }
        // SAFETY: the component's event, which stays with the device.
        unsafe { ke::wait::wait(Some(rest.cast()), None) };
    }
}

/// The worker's routine: for each device on the list, tell its driver
/// what is owed about each of its components.
///
/// # Safety
/// Called as a work routine.
unsafe extern "C" fn serve(_: *mut c_void) {
    loop {
        let next = {
            let mut power = POWER.lock();
            if power.fx_work.is_empty() {
                power.fx_working = false;
                None
            } else {
                let handle = power.fx_work.remove(0);
                // SAFETY: a device on the list is live; under the
                // lock.
                let fx = unsafe { &mut *(handle as *mut Fx) };
                fx.queued = false;
                fx.serving += 1;
                Some((handle as *mut c_void, fx.parts.len() as u32))
            }
        };
        let Some((handle, parts)) = next else {
            return;
        };
        for index in 0..parts {
            // SAFETY: the count taken above keeps the device.
            unsafe { drive(handle, index) };
        }
        // SAFETY: as above.
        let leaving = unsafe {
            locked(handle, |_, fx| {
                fx.serving -= 1;
                if fx.serving == 0 { fx.leaving } else { 0 }
            })
        };
        if leaving != 0 {
            // SAFETY: the event in the frame of the thread that waits
            // to unregister the device, which stays until it is set.
            unsafe { ke::wait::KeSetEvent(leaving as *mut KEVENT, 0, 0) };
        }
    }
}

/// What a driver described, read out of its memory.
struct Read {
    flags: u64,
    callbacks: PO_FX_CALLBACKS,
    directed: [usize; 2],
    directed_timeout: u32,
    context: usize,
    /// Each component's `IdleStateCount`, `DeepestWakeableIdleState`
    /// and how many providers it names.
    components: Vec<(u32, u32, u32)>,
    /// The providers named, component after component.
    providers: Vec<u32>,
}

/// Read a `PO_FX_DEVICE` of any of its three versions. `Err` is the
/// status to refuse it with.
///
/// # Safety
/// `described` is a `PO_FX_DEVICE` as the driver's version lays it
/// out, with the components and provider lists it names.
unsafe fn read(described: *const c_void) -> Result<Read, NTSTATUS> {
    // SAFETY: per the contract; every field is read by raw pointer.
    unsafe {
        let version = described.cast::<u32>().read_unaligned();
        let (head, count, first, v1) = match version {
            PO_FX_VERSION_V1 => {
                let device = described.cast::<PO_FX_DEVICE_V1>();
                (
                    (
                        0,
                        (&raw const (*device).Callbacks).read_unaligned(),
                        [0; 2],
                        0,
                        (&raw const (*device).DeviceContext).read_unaligned().addr(),
                    ),
                    (&raw const (*device).ComponentCount).read_unaligned(),
                    PO_FX_DEVICE_V1_COMPONENTS,
                    true,
                )
            }
            PO_FX_VERSION_V2 => {
                let device = described.cast::<PO_FX_DEVICE_V2>();
                (
                    (
                        (&raw const (*device).Flags).read_unaligned(),
                        (&raw const (*device).Callbacks).read_unaligned(),
                        [0; 2],
                        0,
                        (&raw const (*device).DeviceContext).read_unaligned().addr(),
                    ),
                    (&raw const (*device).ComponentCount).read_unaligned(),
                    PO_FX_DEVICE_V2_COMPONENTS,
                    false,
                )
            }
            PO_FX_VERSION_V3 => {
                let device = described.cast::<PO_FX_DEVICE_V3>();
                let up = (&raw const (*device).DirectedPowerUpCallback).read_unaligned();
                let down = (&raw const (*device).DirectedPowerDownCallback).read_unaligned();
                // Both or neither.
                if up.is_null() != down.is_null() {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                (
                    (
                        (&raw const (*device).Flags).read_unaligned(),
                        (&raw const (*device).Callbacks).read_unaligned(),
                        [up.addr(), down.addr()],
                        (&raw const (*device).DirectedFxTimeoutInSeconds).read_unaligned(),
                        (&raw const (*device).DeviceContext).read_unaligned().addr(),
                    ),
                    (&raw const (*device).ComponentCount).read_unaligned(),
                    PO_FX_DEVICE_V3_COMPONENTS,
                    false,
                )
            }
            _ => return Err(STATUS_INVALID_PARAMETER),
        };
        if count == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let mut components = Vec::new();
        components
            .try_reserve_exact(count as usize)
            .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        let mut providers = Vec::new();
        let first = described.cast::<u8>().add(first);
        for index in 0..count as usize {
            if v1 {
                let component = first.cast::<PO_FX_COMPONENT_V1>().add(index);
                components.push((
                    (&raw const (*component).IdleStateCount).read_unaligned(),
                    (&raw const (*component).DeepestWakeableIdleState).read_unaligned(),
                    0,
                ));
                continue;
            }
            let component = first.cast::<PO_FX_COMPONENT_V2>().add(index);
            let named = (&raw const (*component).ProviderCount).read_unaligned();
            components.push((
                (&raw const (*component).IdleStateCount).read_unaligned(),
                (&raw const (*component).DeepestWakeableIdleState).read_unaligned(),
                named,
            ));
            // A count the device cannot have is refused before the
            // list it would describe is read.
            if named >= count {
                return Err(STATUS_INVALID_PARAMETER);
            }
            providers
                .try_reserve(named as usize)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            let list = (&raw const (*component).Providers).read_unaligned();
            for at in 0..named as usize {
                providers.push(list.add(at).read_unaligned());
            }
        }
        let (flags, callbacks, directed, directed_timeout, context) = head;
        Ok(Read {
            flags,
            callbacks,
            directed,
            directed_timeout,
            context,
            components,
            providers,
        })
    }
}

/// Whether the pinned kernel accepts what was read
/// (`nk_po::fx::registration`).
fn accepted(read: &Read) -> Result<bool, NTSTATUS> {
    let mut described = Vec::new();
    described
        .try_reserve_exact(read.components.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let mut rest = read.providers.as_slice();
    for &(idle_states, deepest_wakeable, named) in &read.components {
        let (providers, after) = rest.split_at(named as usize);
        rest = after;
        described.push(Described {
            idle_states,
            deepest_wakeable,
            providers,
        });
    }
    let callbacks = &read.callbacks;
    let three = !callbacks.ComponentActiveConditionCallback.is_null()
        && !callbacks.ComponentIdleConditionCallback.is_null()
        && !callbacks.ComponentIdleStateCallback.is_null();
    Ok(registration(&described, three))
}

/// The Plug and Play manager is about to start the device whose stack
/// has `pdo` at the bottom: from now on its drivers may register it
/// with the framework. Windows' `PnpStartDevice` calls
/// `PoFxPrepareDevice` here, and `PoFxRegisterDevice` refuses a device
/// that was not prepared.
///
/// # Safety
/// `pdo` is a live device object, the bottom of its stack.
pub unsafe fn prepare_device(pdo: *mut DEVICE_OBJECT) {
    let mut power = POWER.lock();
    // SAFETY: per the contract; under the lock.
    unsafe {
        let block = dope(&mut power, pdo);
        // With no memory for the block the device is not prepared, and
        // its drivers' registration is refused.
        if !block.is_null() {
            (*block).fx_prepared = true;
        }
    }
}

/// The Plug and Play manager is removing the device whose stack has
/// `pdo` at the bottom: it is no longer prepared, and a registration
/// its drivers left behind is taken away, as Windows' `IopRemoveDevice`
/// does (`PoFxAbandonDevice`).
///
/// # Safety
/// `pdo` is a live device object, the bottom of its stack. Called at
/// `PASSIVE_LEVEL`.
pub unsafe fn abandon_device(pdo: *mut DEVICE_OBJECT) {
    let left = {
        let _power = POWER.lock();
        // SAFETY: per the contract; under the lock.
        unsafe {
            let block = (*(*pdo).DeviceObjectExtension).Dope.cast::<super::Dope>();
            if block.is_null() {
                0
            } else {
                (*block).fx_prepared = false;
                (*block).fx
            }
        }
    };
    if left != 0 {
        // SAFETY: the device's registration, which its drivers did not
        // take back.
        unsafe { unregister(core::ptr::without_provenance_mut(left)) };
    }
}

/// [`PoFxRegisterDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxregisterdevice):
/// register a device, described as a set of components, with the
/// framework. Each component starts active, with one activation that
/// `PoFxStartDevicePowerManagement` gives up.
///
/// Refused as by the pinned kernel: `STATUS_INVALID_PARAMETER` for no
/// device, a version other than 1, 2 or 3, one directed callback
/// without the other, a stack whose bottom device has no device node,
/// or components the kernel does not accept
/// (`nk_po::fx::registration`); `STATUS_DEVICE_NOT_READY` for a device
/// the Plug and Play manager has not begun to start. A second
/// registration of one device stops the system, as on Windows.
///
/// Partial: a component that names providers stops the system: NK
/// does not implement dependencies between components.
///
/// # Safety
/// `pdo` is null or a live device object; `described` is a
/// `PO_FX_DEVICE`; `handle` is writable.
pub unsafe extern "C" fn PoFxRegisterDevice(
    pdo: *mut DEVICE_OBJECT,
    described: *const c_void,
    handle: *mut *mut c_void,
) -> NTSTATUS {
    irql::expect_passive("registering a device with the power framework");
    if pdo.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract.
    let read = match unsafe { read(described) } {
        Ok(read) => read,
        Err(status) => return status,
    };
    // SAFETY: per the contract; the reference keeps the bottom of the
    // stack for as long as the registration lasts.
    unsafe {
        // Given up on a refusal; the registration's once it is made.
        let held = ObRef::adopt(device::IoGetDeviceAttachmentBaseRef(pdo).cast());
        let base = held.cast::<DEVICE_OBJECT>();
        if (*(*base).DeviceObjectExtension).DeviceNode.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        {
            let mut power = POWER.lock();
            let block = dope(&mut power, base);
            if block.is_null() || !(*block).fx_prepared {
                drop(power);
                return STATUS_DEVICE_NOT_READY;
            }
        }
        match accepted(&read) {
            Ok(true) => {}
            Ok(false) => return STATUS_INVALID_PARAMETER,
            Err(status) => return status,
        }
        if !read.providers.is_empty() {
            crate::kd::bugcheck(format_args!(
                "PoFxRegisterDevice: a component names the components it depends on; NK does \
                 not implement dependencies between components"
            ));
        }
        let mut parts = Vec::new();
        if parts.try_reserve_exact(read.components.len()).is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        for _ in &read.components {
            parts.push(Part {
                state: Component::new(),
                // An all-zero event is a valid value; it is
                // initialised below, where it stays.
                rest: core::mem::zeroed(),
                latency: 0,
                residency: 0,
            });
        }
        for part in &mut parts {
            // A component as registered is at rest.
            ke::wait::KeInitializeEvent(&raw mut part.rest, 0, 1);
        }
        let fx = pool::alloc(size_of::<Fx>(), TAG_FX).cast::<Fx>();
        if fx.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        fx.write(Fx {
            base,
            callbacks: read.callbacks,
            directed: read.directed,
            context: read.context,
            flags: read.flags,
            directed_timeout: read.directed_timeout,
            parts,
            started: false,
            idle_timeout: 0,
            watchdog: None,
            reported_on: false,
            queued: false,
            serving: 0,
            leaving: 0,
        });
        let registered = {
            let mut power = POWER.lock();
            let block = dope(&mut power, base);
            if (*block).fx != 0 {
                misuse(FX_ALREADY_REGISTERED, base.addr(), 0, 0);
            }
            // Room on the worker's list for every registered device.
            let devices = power.fx.len() + 1;
            let room =
                power.fx.try_reserve(1).is_ok() && power.fx_work.try_reserve(devices).is_ok();
            if room {
                power.fx.push(fx.addr());
                (*block).fx = fx.addr();
            }
            room
        };
        if !registered {
            fx.drop_in_place();
            let _ = pool::free(fx.cast());
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        held.into_raw();
        handle.write(fx.cast());
    }
    STATUS_SUCCESS
}

/// Take the registration `handle` names away: off the lists, once no
/// worker is making its callbacks, and free it.
///
/// # Safety
/// `handle` is a registered device no thread of its driver is using.
/// Called at `PASSIVE_LEVEL`.
unsafe fn unregister(handle: *mut c_void) {
    // An all-zero event is a valid value; it is initialised before
    // anything can see it.
    // SAFETY: as said.
    let mut quiet: KEVENT = unsafe { core::mem::zeroed() };
    // SAFETY: a local nothing waits on yet.
    unsafe { ke::wait::KeInitializeEvent(&raw mut quiet, 0, 0) };
    let wait = with("PoFxUnregisterDevice", handle, |power, fx| {
        power.fx.retain(|&live| live != handle.addr());
        power.fx_work.retain(|&queued| queued != handle.addr());
        if power.fx.is_empty() {
            // Empty lists hold no memory.
            power.fx = Vec::new();
            power.fx_work = Vec::new();
        }
        // SAFETY: the device's bottom, kept by the registration; its
        // block is the one the registration was recorded in.
        unsafe {
            let block = (*(*fx.base).DeviceObjectExtension)
                .Dope
                .cast::<super::Dope>();
            if !block.is_null() {
                (*block).fx = 0;
            }
        }
        if fx.serving != 0 {
            fx.leaving = (&raw mut quiet).addr();
        }
        fx.serving != 0
    });
    // SAFETY: the device is off every list: nothing reaches it now but
    // the workers counted in `serving`, which this waits for.
    unsafe {
        if wait {
            ke::wait::wait(Some((&raw mut quiet).cast()), None);
        }
        let fx = handle.cast::<Fx>();
        let base = (*fx).base;
        fx.drop_in_place();
        let _ = pool::free(fx.cast());
        object::dereference(base.cast());
    }
}

/// [`PoFxUnregisterDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxunregisterdevice):
/// take a device's registration back. Waits for the callbacks a worker
/// is making for it.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`, and no other thread of the
/// driver is using it.
pub unsafe extern "C" fn PoFxUnregisterDevice(handle: *mut c_void) {
    irql::expect_passive("taking a device back from the power framework");
    // SAFETY: per the contract.
    unsafe { unregister(handle) };
}

/// The flags of an activation or an idling, checked as the pinned
/// kernel checks them: both at once is no request at all.
fn checked_flags(handle: *mut c_void, index: u32, flags: u32) -> (bool, bool) {
    let blocking = flags & FLAG_BLOCKING != 0;
    let other_thread = flags & FLAG_ASYNC_ONLY != 0;
    if blocking && other_thread {
        misuse(FX_BAD_ARGUMENT, handle.addr(), index as usize, 1);
    }
    (blocking, other_thread)
}

/// After a component's count changed: have the driver told what is
/// owed, here or from a worker, and wait for the component to be at
/// rest if the caller asked to.
///
/// # Safety
/// `handle` is a registered device and `index` one of its components.
unsafe fn settle(handle: *mut c_void, index: u32, blocking: bool, other_thread: bool) {
    // SAFETY: per the contract.
    unsafe {
        if other_thread {
            if locked(handle, |power, fx| enqueue(power, fx, handle)) {
                start_worker();
            }
        } else {
            drive(handle, index);
        }
        if blocking {
            await_rest(handle, index);
        }
    }
}

/// [`PoFxActivateComponent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxactivatecomponent):
/// the driver is about to use component `index`. If the component was
/// idle the driver's `ComponentActiveConditionCallback` is called: in
/// this thread, before the call returns, unless `PO_FX_FLAG_ASYNC_ONLY`
/// asks for another thread; after an idle transition still under way
/// has finished. `PO_FX_FLAG_BLOCKING` waits until the component is
/// active.
///
/// Stops the system as the pinned kernel does for both flags at once,
/// a blocking call at `DISPATCH_LEVEL`, or a component the device
/// does not have.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`.
pub unsafe extern "C" fn PoFxActivateComponent(handle: *mut c_void, index: u32, flags: u32) {
    if flags & FLAG_BLOCKING != 0 && irql::current() >= irql::DISPATCH_LEVEL {
        misuse(FX_BAD_ARGUMENT, handle.addr(), index as usize, 0);
    }
    let (blocking, other_thread) = checked_flags(handle, index, flags);
    with("PoFxActivateComponent", handle, |_, fx| {
        let part = part(fx, handle, index);
        part.state.activate();
        mark(part);
    });
    // SAFETY: the device was found registered, with this component.
    unsafe { settle(handle, index, blocking, other_thread) };
}

/// [`PoFxIdleComponent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxidlecomponent):
/// the driver has stopped using component `index`. When the last
/// activation goes, the driver's `ComponentIdleConditionCallback` is
/// called, at `DISPATCH_LEVEL`, and the component is idle once the
/// driver has answered with `PoFxCompleteIdleCondition`. The flags are
/// `PoFxActivateComponent`'s. The component stays in F0: NK asks for
/// no low-power state.
///
/// Stops the system as the pinned kernel does for a component with no
/// activation outstanding.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`.
pub unsafe extern "C" fn PoFxIdleComponent(handle: *mut c_void, index: u32, flags: u32) {
    let (blocking, other_thread) = checked_flags(handle, index, flags);
    if blocking {
        irql::expect_passive("idling a component and waiting for it");
    }
    with("PoFxIdleComponent", handle, |_, fx| {
        let part = part(fx, handle, index);
        if part.state.idle().is_err() {
            misuse(FX_NOT_ACTIVATED, handle.addr(), 0, 0);
        }
        mark(part);
    });
    // SAFETY: the device was found registered, with this component.
    unsafe { settle(handle, index, blocking, other_thread) };
}

/// [`PoFxCompleteIdleCondition`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxcompleteidlecondition):
/// the driver has finished what its idle-condition callback began for
/// component `index`. If the component has been activated meanwhile,
/// a worker tells the driver it is active again. Called when no idle
/// transition waits for it, it stops the system, as on Windows.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`.
pub unsafe extern "C" fn PoFxCompleteIdleCondition(handle: *mut c_void, index: u32) {
    let start = with("PoFxCompleteIdleCondition", handle, |power, fx| {
        let part = part(fx, handle, index);
        if part.state.idle_completed().is_err() {
            misuse(FX_NOTHING_TO_COMPLETE, handle.addr(), index as usize, 2);
        }
        mark(part);
        // The transition is over (the callback had returned) and
        // something is owed: not from inside the driver's own call.
        let owed = part.state.settled().is_some() && !part.state.at_rest();
        owed && enqueue(power, fx, handle)
    });
    if start {
        start_worker();
    }
}

/// [`PoFxStartDevicePowerManagement`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxstartdevicepowermanagement):
/// registration is complete. As the pinned kernel does, this gives up
/// the activation each component was registered with, waiting for
/// each: a component the driver has not activated becomes idle, and
/// the driver is told.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`.
pub unsafe extern "C" fn PoFxStartDevicePowerManagement(handle: *mut c_void) {
    let parts = with("PoFxStartDevicePowerManagement", handle, |_, fx| {
        fx.started = true;
        fx.parts.len() as u32
    });
    for index in 0..parts {
        // SAFETY: per the contract.
        unsafe { PoFxIdleComponent(handle, index, FLAG_BLOCKING) };
    }
}

/// [`PoFxCompleteIdleState`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxcompleteidlestate):
/// the driver has finished a change of F-state. NK never asks for one
/// (`ComponentIdleStateCallback` is never called), so there is nothing
/// to finish; the pinned kernel does nothing either when none is
/// pending.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`.
pub unsafe extern "C" fn PoFxCompleteIdleState(handle: *mut c_void, index: u32) {
    with("PoFxCompleteIdleState", handle, |_, fx| {
        part(fx, handle, index);
    });
}

/// [`PoFxCompleteDevicePowerNotRequired`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxcompletedevicepowernotrequired):
/// the driver has answered `DevicePowerNotRequiredCallback`. NK never
/// makes that callback: a device's power is always required. A call
/// with none to answer stops the system, as on Windows.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`.
pub unsafe extern "C" fn PoFxCompleteDevicePowerNotRequired(handle: *mut c_void) {
    with("PoFxCompleteDevicePowerNotRequired", handle, |_, _| ());
    misuse(FX_NOTHING_TO_COMPLETE, handle.addr(), 0, 0)
}

/// [`PoFxReportDevicePoweredOn`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxreportdevicepoweredon):
/// the device is in D0. Recorded. On Windows this releases what waited
/// for a device the framework had asked to be powered up; NK never
/// asks, so nothing waits.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`.
pub unsafe extern "C" fn PoFxReportDevicePoweredOn(handle: *mut c_void) {
    with("PoFxReportDevicePoweredOn", handle, |_, fx| {
        fx.reported_on = true;
    });
}

/// [`PoFxSetComponentLatency`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxsetcomponentlatency):
/// how long a wake from a low-power state the driver tolerates for a
/// component. Recorded and never acted on.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`.
pub unsafe extern "C" fn PoFxSetComponentLatency(handle: *mut c_void, index: u32, latency: u64) {
    with("PoFxSetComponentLatency", handle, |_, fx| {
        part(fx, handle, index).latency = latency;
    });
}

/// [`PoFxSetComponentResidency`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxsetcomponentresidency):
/// how long the driver expects a component to stay idle. Recorded and
/// never acted on.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`.
pub unsafe extern "C" fn PoFxSetComponentResidency(
    handle: *mut c_void,
    index: u32,
    residency: u64,
) {
    with("PoFxSetComponentResidency", handle, |_, fx| {
        part(fx, handle, index).residency = residency;
    });
}

/// [`PoFxSetDeviceIdleTimeout`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxsetdeviceidletimeout):
/// how long all of a device's components are idle before Windows says
/// its power is not required. Recorded, capped as by the pinned
/// kernel, and never acted on: NK never says so.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`.
pub unsafe extern "C" fn PoFxSetDeviceIdleTimeout(handle: *mut c_void, timeout: u64) {
    with("PoFxSetDeviceIdleTimeout", handle, |_, fx| {
        fx.idle_timeout = timeout.min(LONGEST_IDLE_TIMEOUT);
    });
}

/// [`PoFxPowerControl`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxpowercontrol):
/// send a request to the platform extension. NK has none, and the
/// pinned kernel's answer when no extension takes the request is
/// NK's: `STATUS_NOT_SUPPORTED`, nothing returned.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`; `returned` is null or
/// writable.
pub unsafe extern "C" fn PoFxPowerControl(
    handle: *mut c_void,
    _code: *const GUID,
    _input: *mut c_void,
    _input_size: usize,
    _output: *mut c_void,
    _output_size: usize,
    returned: *mut usize,
) -> NTSTATUS {
    with("PoFxPowerControl", handle, |_, _| ());
    if !returned.is_null() {
        // SAFETY: per the contract.
        unsafe { returned.write(0) };
    }
    STATUS_NOT_SUPPORTED
}

/// `PO_FX_FLAG_PERF_PEP_OPTIONAL`: register the states even if the
/// platform extension does not handle them.
const PERF_PEP_OPTIONAL: u64 = 1;

/// [`PoFxRegisterComponentPerfStates`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxregistercomponentperfstates):
/// register a component's performance states. With no platform
/// extension the pinned kernel answers `STATUS_NOT_IMPLEMENTED` when
/// the extension is asked for the states (no `input`) or must handle
/// them (no `PO_FX_FLAG_PERF_PEP_OPTIONAL`), and
/// `STATUS_INVALID_PARAMETER` for both or neither of `input` and
/// `output`, or states that are no sets at all.
///
/// Partial: states the driver describes and manages itself
/// (`PO_FX_FLAG_PERF_PEP_OPTIONAL`), which Windows registers, stop the
/// system: NK does not implement performance states.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`; `input` is null or a
/// `PO_FX_COMPONENT_PERF_INFO`.
pub unsafe extern "C" fn PoFxRegisterComponentPerfStates(
    handle: *mut c_void,
    index: u32,
    flags: u64,
    _callback: *mut c_void,
    input: *const c_void,
    output: *mut *mut c_void,
) -> NTSTATUS {
    with("PoFxRegisterComponentPerfStates", handle, |_, fx| {
        part(fx, handle, index);
    });
    if input.is_null() {
        return if output.is_null() {
            STATUS_INVALID_PARAMETER
        } else {
            STATUS_NOT_IMPLEMENTED
        };
    }
    if !output.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract: the structure begins with
    // `PerfStateSetsCount`.
    if unsafe { input.cast::<u32>().read_unaligned() } == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if flags & PERF_PEP_OPTIONAL == 0 {
        return STATUS_NOT_IMPLEMENTED;
    }
    crate::kd::bugcheck(format_args!(
        "PoFxRegisterComponentPerfStates: NK does not implement performance states a driver \
         manages itself (PO_FX_FLAG_PERF_PEP_OPTIONAL)"
    ))
}

/// [`PoFxRegisterCrashdumpDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxregistercrashdumpdevice):
/// ask that the platform extension can power the device up for a crash
/// dump. With no extension for the device the pinned kernel answers
/// `STATUS_NOT_SUPPORTED`; with no handle, `STATUS_INVALID_PARAMETER`.
///
/// # Safety
/// `handle` is null or came from `PoFxRegisterDevice`.
pub unsafe extern "C" fn PoFxRegisterCrashdumpDevice(handle: *mut c_void) -> NTSTATUS {
    if handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    with("PoFxRegisterCrashdumpDevice", handle, |_, _| ());
    STATUS_NOT_SUPPORTED
}

/// [`PoFxPowerOnCrashdumpDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxpoweroncrashdumpdevice):
/// have the platform extension power the device up for a crash dump.
/// No device is registered for that on NK
/// (`PoFxRegisterCrashdumpDevice` never succeeds), and the pinned
/// kernel's answer for such a device is `STATUS_UNSUCCESSFUL`; with no
/// handle, `STATUS_INVALID_PARAMETER`. Callable as the system stops:
/// nothing is locked.
pub extern "C" fn PoFxPowerOnCrashdumpDevice(
    handle: *mut c_void,
    _context: *mut c_void,
) -> NTSTATUS {
    if handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_UNSUCCESSFUL
}

/// [`PoFxNotifySurprisePowerOn`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxnotifysurprisepoweron):
/// a device was powered on as a side effect of powering another.
/// Windows tells the platform extension; NK has none to tell.
pub extern "C" fn PoFxNotifySurprisePowerOn(_pdo: *mut DEVICE_OBJECT) {}

/// [`PoFxRegisterDripsWatchdogCallback`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxregisterdripswatchdogcallback):
/// have a routine called when the device keeps the platform out of its
/// low-power idle state for too long. Recorded and never called: NK
/// has no such state. A second registration for one device stops the
/// system, as on Windows.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`.
pub unsafe extern "C" fn PoFxRegisterDripsWatchdogCallback(
    handle: *mut c_void,
    callback: *mut c_void,
    include_children: u8,
    driver: *mut c_void,
) {
    with("PoFxRegisterDripsWatchdogCallback", handle, |_, fx| {
        if fx.watchdog.is_some() {
            misuse(FX_WATCHDOG_REGISTERED, handle.addr(), 0, 0);
        }
        fx.watchdog = Some((callback.addr(), include_children != 0, driver.addr()));
    });
}

/// [`PoFxCompleteDirectedPowerDown`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxcompletedirectedpowerdown):
/// the driver has finished a power-down the framework directed. NK
/// directs none (`DirectedPowerDownCallback` is never called), and a
/// call with none in progress stops the system, as on Windows.
///
/// # Safety
/// `handle` came from `PoFxRegisterDevice`.
pub unsafe extern "C" fn PoFxCompleteDirectedPowerDown(handle: *mut c_void) {
    with("PoFxCompleteDirectedPowerDown", handle, |_, _| ());
    misuse(FX_NO_DIRECTED_TRANSITION, 1, handle.addr(), 0)
}

/// What the self-tests look at.
pub struct TestState {
    /// How many devices are registered.
    pub devices: usize,
    /// The device's components: activations outstanding, whether at
    /// rest, latency, residency.
    pub parts: Vec<(u32, bool, u64, u64)>,
    pub started: bool,
    pub idle_timeout: u64,
    pub flags: u64,
    pub directed: [usize; 2],
    pub directed_timeout: u32,
    pub watchdog: Option<(usize, bool, usize)>,
    pub reported_on: bool,
    pub other_callbacks: [usize; 4],
}

/// For the self-tests: the state of the device `handle` names.
pub fn test_state(handle: *mut c_void) -> TestState {
    with("the power framework's test", handle, |power, fx| {
        TestState {
            devices: power.fx.len(),
            parts: fx
                .parts
                .iter()
                .map(|part| {
                    (
                        part.state.count(),
                        part.state.at_rest(),
                        part.latency,
                        part.residency,
                    )
                })
                .collect(),
            started: fx.started,
            idle_timeout: fx.idle_timeout,
            flags: fx.flags,
            directed: fx.directed,
            directed_timeout: fx.directed_timeout,
            watchdog: fx.watchdog,
            reported_on: fx.reported_on,
            other_callbacks: [
                fx.callbacks.ComponentIdleStateCallback.addr(),
                fx.callbacks.DevicePowerRequiredCallback.addr(),
                fx.callbacks.DevicePowerNotRequiredCallback.addr(),
                fx.callbacks.PowerControlCallback.addr(),
            ],
        }
    })
}

/// For the self-tests: how many devices are registered.
pub fn test_devices() -> usize {
    POWER.lock().fx.len()
}
