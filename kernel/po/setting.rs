//! Registrations with the power manager: for the value of a power
//! setting, and for the coalescing of I/O.
//!
//! Which settings have a value, and the bookkeeping of who is told, are
//! `nk_po::setting`'s. The calls are made as Windows makes them: from a
//! worker thread, at `PASSIVE_LEVEL`, with nothing held.

use super::POWER;
use crate::ex::work::ExQueueWorkItem;
use crate::ke::seh::{self, Guard};
use crate::ke::{self, irql};
use core::cell::UnsafeCell;
use core::ffi::c_void;
use nk_ntabi::ex::{DELAYED_WORK_QUEUE, GUID, WORK_QUEUE_ITEM};
use nk_ntabi::io::DEVICE_OBJECT;
use nk_ntabi::ke::{KEVENT, LIST_ENTRY};
use nk_ntabi::status::*;
use nk_po::setting::{Refused, Unregistered};

/// The one work item that makes the calls owed: queued when a call
/// comes to be owed and no worker is making them (`Power::telling`).
struct WorkItem(UnsafeCell<WORK_QUEUE_ITEM>);

// SAFETY: touched only by the work queue's routines, and queued only
// while it is on no queue, which `Power::telling` sees to.
unsafe impl Sync for WorkItem {}

static WORKER: WorkItem = WorkItem(UnsafeCell::new(WORK_QUEUE_ITEM {
    List: LIST_ENTRY {
        Flink: core::ptr::null_mut(),
        Blink: core::ptr::null_mut(),
    },
    WorkerRoutine: Some(tell),
    Parameter: core::ptr::null_mut(),
}));

/// The worker's routine: make every call that is owed, oldest
/// registration first, each with the setting's GUID, its value and the
/// value's length, and the registration's context.
///
/// # Safety
/// Called as a work routine.
unsafe extern "C" fn tell(_: *mut c_void) {
    let thread = ke::pcr::current_thread().addr();
    loop {
        let call = {
            let mut power = POWER.lock();
            let call = power.settings.next_call(thread);
            if call.is_none() {
                power.telling = false;
            }
            call
        };
        let Some(call) = call else {
            return;
        };
        if call.callback == 0 {
            crate::kd::bugcheck(format_args!(
                "a power setting callback was registered with no routine"
            ));
        }
        let (setting, value) = (call.setting, call.value);
        // SAFETY: the routine a driver registered, which stays
        // registered until this call has returned: unregistering waits
        // for it. The GUID and the value are this frame's copies. An
        // exception it lets out stops the system at the worker's base.
        unsafe {
            seh::call(
                call.callback,
                [
                    (&raw const setting).addr(),
                    (&raw const value).addr(),
                    value.len(),
                    call.context,
                ],
                &Guard::Nothing,
            );
        }
        let waiter = POWER.lock().settings.returned(call.handle);
        if let Some(waiter) = waiter {
            // SAFETY: the event in the frame of the thread that waits
            // to unregister, which stays until it is set.
            unsafe { ke::wait::KeSetEvent(waiter as *mut KEVENT, 0, 0) };
        }
    }
}

/// [`PoRegisterPowerSettingCallback`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-poregisterpowersettingcallback):
/// have `callback` called with the value of the power setting
/// `setting`. A setting that has a value on NK (`nk_po::setting`: the
/// power source and the state of the console's display) is told once,
/// soon, from a worker thread; one that has none is registered and
/// never told. A setting that belongs to a session is refused with
/// `STATUS_INVALID_PARAMETER`, as by the pinned kernel.
///
/// Partial: NK's settings never change, and the settings of a power
/// scheme never get a value.
///
/// # Safety
/// `setting` is readable; `callback` is a routine of the type Windows
/// documents, callable until the registration is taken back; `handle`
/// is null or writable.
pub unsafe extern "C" fn PoRegisterPowerSettingCallback(
    _device: *mut DEVICE_OBJECT,
    setting: *const GUID,
    callback: *mut c_void,
    context: *mut c_void,
    handle: *mut *mut c_void,
) -> NTSTATUS {
    irql::expect_passive("registering for a power setting");
    // SAFETY: per the contract.
    let setting = unsafe { setting.read_unaligned() };
    let (registered, start) = {
        let mut power = POWER.lock();
        match power
            .settings
            .register(setting, callback.addr(), context.addr())
        {
            Ok((registered, owed)) => {
                let start = owed && !power.telling;
                power.telling |= owed;
                (registered, start)
            }
            Err(Refused::SessionSpecific) => return STATUS_INVALID_PARAMETER,
            Err(Refused::NoMemory) => return STATUS_INSUFFICIENT_RESOURCES,
        }
    };
    if !handle.is_null() {
        // SAFETY: per the contract.
        unsafe { handle.write(core::ptr::without_provenance_mut(registered)) };
    }
    if start {
        // SAFETY: the item is on no queue: a worker is started only
        // when none is at work or queued.
        unsafe { ExQueueWorkItem(WORKER.0.get(), DELAYED_WORK_QUEUE) };
    }
    STATUS_SUCCESS
}

/// [`PoUnregisterPowerSettingCallback`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pounregisterpowersettingcallback):
/// take a registration back. If its callback is running in another
/// thread, this waits until it has returned; called from the callback
/// itself, the registration goes when the callback returns. A handle
/// that names no registration, or one already being taken back, is
/// refused with `STATUS_INVALID_PARAMETER`.
pub extern "C" fn PoUnregisterPowerSettingCallback(handle: *mut c_void) -> NTSTATUS {
    // An all-zero event is a valid value; it is initialised before
    // anything can see it.
    // SAFETY: as said.
    let mut returned: KEVENT = unsafe { core::mem::zeroed() };
    // SAFETY: a local nothing waits on yet.
    unsafe { ke::wait::KeInitializeEvent(&raw mut returned, 0, 0) };
    let thread = ke::pcr::current_thread().addr();
    let outcome =
        POWER
            .lock()
            .settings
            .unregister(handle.addr(), thread, (&raw mut returned).addr());
    match outcome {
        Unregistered::Gone | Unregistered::WhenItReturns => STATUS_SUCCESS,
        Unregistered::Invalid => STATUS_INVALID_PARAMETER,
        Unregistered::Wait => {
            // SAFETY: the event above, which the worker sets when the
            // callback has returned and the registration is gone.
            unsafe { ke::wait::wait(Some((&raw mut returned).cast()), None) };
            STATUS_SUCCESS
        }
    }
}

/// A coalescing callback a driver registered.
pub(super) struct Coalescing {
    handle: usize,
    callback: usize,
    client_owns_disk: bool,
    context: usize,
}

/// `PoRegisterCoalescingCallback` (declared in the WDK's headers, not
/// documented): have `callback` told when the system starts or stops coalescing
/// I/O, which Windows does while the platform is in its low-power idle
/// state. The registration is kept; NK never coalesces, so the
/// callback is never called. As the pinned kernel's, the routine
/// looks at none of its arguments.
///
/// # Safety
/// `handle` is writable.
pub unsafe extern "C" fn PoRegisterCoalescingCallback(
    callback: *mut c_void,
    client_owns_disk: u8,
    handle: *mut *mut c_void,
    context: *mut c_void,
) -> NTSTATUS {
    let mut power = POWER.lock();
    if power.coalescing.try_reserve(1).is_err() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    power.coalescing_made += 1;
    let registered = power.coalescing_made << 4;
    power.coalescing.push(Coalescing {
        handle: registered,
        callback: callback.addr(),
        client_owns_disk: client_owns_disk != 0,
        context: context.addr(),
    });
    // SAFETY: per the contract.
    unsafe { handle.write(core::ptr::without_provenance_mut(registered)) };
    STATUS_SUCCESS
}

/// `PoUnregisterCoalescingCallback` (declared in the WDK's headers, not
/// documented): take a coalescing registration back. A handle that names none is a
/// driver's error, which Windows does not check for: it is reported.
pub extern "C" fn PoUnregisterCoalescingCallback(handle: *mut c_void) {
    let known = {
        let mut power = POWER.lock();
        let at = power
            .coalescing
            .iter()
            .position(|registration| registration.handle == handle.addr());
        let known = at.map(|at| power.coalescing.remove(at)).is_some();
        if power.coalescing.is_empty() {
            // An empty list holds no memory.
            power.coalescing = alloc::vec::Vec::new();
        }
        known
    };
    if !known {
        crate::kd::verify(format_args!(
            "PoUnregisterCoalescingCallback was given {handle:p}, which is no registration"
        ));
    }
}

/// For the self-tests: how many registrations there are for power
/// settings, and the coalescing registration `handle` names: its
/// routine, whether its client owns the disk, and its context.
pub fn test_state(handle: *mut c_void) -> (usize, Option<(usize, bool, usize)>) {
    let power = POWER.lock();
    (
        power.settings.len(),
        power
            .coalescing
            .iter()
            .find(|registration| registration.handle == handle.addr())
            .map(|r| (r.callback, r.client_owns_disk, r.context)),
    )
}
