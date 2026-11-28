//! The power requests a driver asks the power manager to make, and the
//! power state a driver records for its device.
//!
//! A request made here is built as the pinned kernel builds one
//! (`PopRequestPowerIrp`, `PopAllocateIrp`): an IRP with one stack
//! location more than the stack is deep. The topmost location is the
//! power manager's own and holds its record of the request; the
//! location below it carries the request and the power manager's
//! completion routine, which calls the driver's completion function,
//! sends the device's next request and frees the IRP.

use super::{POWER, dope};
use crate::io::{device, irp};
use crate::ke::seh::{self, Guard};
use crate::mm::pool;
use crate::ob::object::{self, ObRef};
use core::ffi::c_void;
use nk_ntabi::io::*;
use nk_ntabi::pnp::*;
use nk_ntabi::status::*;
use nk_po::request::{Kind, kind};

/// Pool tag of the record of a request.
const TAG_REQUEST: u32 = u32::from_le_bytes(*b"PoIr");

/// The power manager's record of a request it made for a driver.
struct Request {
    irp: *mut IRP,
    /// The device the driver named, which its completion function is
    /// told.
    device: *mut DEVICE_OBJECT,
    /// The bottom and the top of the stack that device is in, each
    /// held by a pointer reference until the request has completed.
    base: *mut DEVICE_OBJECT,
    top: *mut DEVICE_OBJECT,
    minor: u8,
    state: u32,
    completion: usize,
    context: usize,
    /// Whether a driver has marked the request, a wait-wake, as having
    /// woken the system (`PoSetSystemWake`).
    system_wake: bool,
}

/// [`PoRequestPowerIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-porequestpowerirp):
/// make a power request and send it to the top of the stack `device`
/// is in: a wait-wake, or a query or a set of the device's power
/// state. Returns `STATUS_PENDING`: `completion`, if given, is called
/// with `context` when the request has completed, and the power
/// manager then frees the IRP.
///
/// A wait-wake is sent at once. A query or a set waits until the one
/// sent before it to the same stack has completed. A minor function
/// other than these three is refused with
/// `STATUS_INVALID_PARAMETER_2`, and a stack whose bottom device has no
/// device node with `STATUS_INVALID_DEVICE_REQUEST`, as the pinned
/// kernel refuses them.
///
/// Partial: NK runs no watchdog on a request, and no platform
/// extension is told of it.
///
/// # Safety
/// `device` is a live device object; `completion` is null or a
/// `REQUEST_POWER_COMPLETE`; `irp_out` is null or writable.
pub unsafe extern "C" fn PoRequestPowerIrp(
    device: *mut DEVICE_OBJECT,
    minor: u8,
    state: u32,
    completion: *mut c_void,
    context: *mut c_void,
    irp_out: *mut *mut IRP,
) -> NTSTATUS {
    // SAFETY: per the contract. The record and the IRP are this
    // routine's until the request is sent or made to wait; the two
    // references keep the stack's ends until it has completed.
    unsafe {
        if !irp_out.is_null() {
            irp_out.write(core::ptr::null_mut());
        }
        let Some(kind) = kind(minor) else {
            return STATUS_INVALID_PARAMETER_2;
        };
        // Given up on the way out, unless the request is sent or made
        // to wait: its record holds them then.
        let ends = (
            ObRef::adopt(device::IoGetAttachedDeviceReference(device).cast()),
            ObRef::adopt(device::IoGetDeviceAttachmentBaseRef(device).cast()),
        );
        let (top, base) = (
            ends.0.cast::<DEVICE_OBJECT>(),
            ends.1.cast::<DEVICE_OBJECT>(),
        );
        if (*(*base).DeviceObjectExtension).DeviceNode.is_null() {
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        let record = pool::alloc(size_of::<Request>(), TAG_REQUEST).cast::<Request>();
        if record.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let request = irp::alloc((*top).StackSize + 1);
        if request.is_null() {
            let _ = pool::free(record.cast());
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        record.write(Request {
            irp: request,
            device,
            base,
            top,
            minor,
            state,
            completion: completion.addr(),
            context: context.addr(),
            system_wake: false,
        });
        (*request).IoStatus.Status = STATUS_NOT_SUPPORTED;
        // The topmost location is the power manager's.
        let own = irp::next_location(request);
        (*own).Context = record.cast();
        (*request).CurrentLocation -= 1;
        (*request).CurrentStackLocation = own;
        let location = irp::next_location(request);
        (*location).MajorFunction = IRP_MJ_POWER;
        (*location).MinorFunction = minor;
        (*location).Parameters = match kind {
            Kind::WaitWake => wait_wake_parameters(state),
            Kind::InTurn => power_parameters(0, POWER_STATE_TYPE_DEVICE, state, POWER_ACTION_NONE),
        };
        (*location).CompletionRoutine = Some(completed);
        (*location).Context = record.cast();
        (*location).Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
        // Before the request is sent: it may complete, and be freed, at
        // once.
        if !irp_out.is_null() {
            irp_out.write(request);
        }
        let send = {
            let mut power = POWER.lock();
            if power.requests.try_reserve(1).is_err() {
                None
            } else {
                let send = match kind {
                    Kind::WaitWake => Some(true),
                    Kind::InTurn => {
                        let block = dope(&mut power, base);
                        if block.is_null() {
                            None
                        } else {
                            (*block)
                                .turns
                                .asked(request.addr())
                                .ok()
                                .map(|now| now.is_some())
                        }
                    }
                };
                if send.is_some() {
                    power.requests.push(record.addr());
                }
                send
            }
        };
        if send.is_some() {
            // The record's now, given up when the request completes.
            ends.0.into_raw();
            ends.1.into_raw();
        }
        match send {
            Some(true) => {
                // Nothing is owed if the dispatch routine is unwound:
                // the request is its driver's.
                irp::call_driver(top, request, &Guard::Nothing);
            }
            Some(false) => {}
            None => {
                if !irp_out.is_null() {
                    irp_out.write(core::ptr::null_mut());
                }
                irp::free(request);
                let _ = pool::free(record.cast());
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
        STATUS_PENDING
    }
}

/// The arguments of a driver's completion function, for [`pass_on`].
struct Completion {
    function: usize,
    device: *mut DEVICE_OBJECT,
    minor: u8,
    state: u32,
    context: usize,
    status: *mut IO_STATUS_BLOCK,
}

/// Call a driver's completion function with its five arguments: one
/// more than `seh::call` passes.
///
/// # Safety
/// `call` is a `Completion` whose function is a
/// `REQUEST_POWER_COMPLETE` that may be called now.
unsafe extern "C" fn pass_on(call: *const Completion) {
    // SAFETY: per the contract.
    unsafe {
        let call = &*call;
        let function = core::mem::transmute::<usize, REQUEST_POWER_COMPLETE>(call.function);
        function(
            call.device,
            call.minor,
            call.state,
            core::ptr::without_provenance_mut(call.context),
            call.status,
        );
    }
}

/// The power manager's completion routine: a request it made has come
/// back to the top of its stack. The driver's completion function is
/// called, in whatever thread and at whatever IRQL the request was
/// completed; then the device's next request is sent and this one is
/// freed.
///
/// # Safety
/// Called as the completion routine of a request `PoRequestPowerIrp`
/// made, with its record.
unsafe extern "C" fn completed(
    _device: *mut DEVICE_OBJECT,
    request: *mut IRP,
    context: *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract: the record is this request's, and
    // stays until this routine frees it; its references keep the two
    // devices.
    unsafe {
        let record = context.cast::<Request>();
        let (base, top) = ((*record).base, (*record).top);
        if (*record).completion != 0 {
            let call = Completion {
                function: (*record).completion,
                device: (*record).device,
                minor: (*record).minor,
                state: (*record).state,
                context: (*record).context,
                status: &raw mut (*request).IoStatus,
            };
            // Nothing is held. If the function is unwound the request
            // stays as it is, and the device's later requests wait
            // behind it.
            seh::call(
                pass_on as *const () as usize,
                [(&raw const call).addr(), 0, 0, 0],
                &Guard::Nothing,
            );
        }
        let next = {
            let mut power = POWER.lock();
            power.requests.retain(|&live| live != record.addr());
            let next = match kind((*record).minor) {
                Some(Kind::InTurn) => {
                    let block = dope(&mut power, base);
                    // The block was there when the request was asked
                    // for, and stays as long as the device does.
                    let next = (*block).turns.completed();
                    next.and_then(|irp| {
                        power
                            .requests
                            .iter()
                            .map(|&live| live as *mut Request)
                            .find(|&live| (*live).irp.addr() == irp)
                    })
                }
                _ => None,
            };
            if power.requests.is_empty() {
                // An empty list holds no memory.
                power.requests = alloc::vec::Vec::new();
            }
            next
        };
        if let Some(next) = next {
            // As Windows: from the thread that completed the one
            // before. The next request's own references keep its
            // stack.
            irp::call_driver((*next).top, (*next).irp, &Guard::Nothing);
        }
        let _ = pool::free(record.cast());
        irp::free(request);
        object::dereference(top.cast());
        object::dereference(base.cast());
    }
    STATUS_MORE_PROCESSING_REQUIRED
}

/// Run `f` on the power manager's record of `request`, if `request` is
/// a wait-wake the power manager made that has not completed. The
/// pointer is only compared.
fn with_wait_wake<R>(request: *mut IRP, f: impl FnOnce(&mut bool) -> R) -> Option<R> {
    let power = POWER.lock();
    power
        .requests
        .iter()
        .map(|&live| live as *mut Request)
        // SAFETY: a record on the list is live while the lock is held.
        .find(|&live| unsafe { (*live).irp == request && (*live).minor == IRP_MN_WAIT_WAKE })
        // SAFETY: as above; the flag is read and written under the
        // lock.
        .map(|live| f(unsafe { &mut (*live).system_wake }))
}

/// [`PoSetSystemWake`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-posetsystemwake):
/// mark a wait-wake request as one that woke the system. A request
/// that is not a wait-wake is left alone, as on Windows; so is one the
/// power manager did not make, which has no such mark (Windows reads
/// the mark out of whatever such an IRP's topmost location holds).
pub extern "C" fn PoSetSystemWake(request: *mut IRP) {
    with_wait_wake(request, |mark| *mark = true);
}

/// [`PoSetSystemWakeDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-posetsystemwakedevice):
/// record that `device` contributed to waking the system. NK remains in S0
/// continuously, so no wake source tracking is needed.
pub extern "C" fn PoSetSystemWakeDevice(_device: *mut DEVICE_OBJECT) {}

/// [`PoGetSystemWake`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pogetsystemwake):
/// whether a wait-wake request has been marked as one that woke the
/// system. `FALSE` for any other request.
pub extern "C" fn PoGetSystemWake(request: *mut IRP) -> u8 {
    u8::from(with_wait_wake(request, |mark| *mark).unwrap_or(false))
}

/// [`PoSetPowerState`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-posetpowerstate):
/// record the power state a driver reports for its device, and return
/// the one recorded before. The record is the device object's own
/// (`PowerFlags`, `nk_po::state`); nobody is told, as nobody is by the
/// pinned kernel's.
///
/// # Safety
/// `device` is a live device object.
pub unsafe extern "C" fn PoSetPowerState(
    device: *mut DEVICE_OBJECT,
    state_type: u32,
    state: u32,
) -> u32 {
    let _power = POWER.lock();
    // SAFETY: per the contract; the word is read and written under the
    // lock.
    unsafe {
        let flags = &raw mut (*(*device).DeviceObjectExtension).PowerFlags;
        let (now, before) = nk_po::state::record(flags.read(), state_type, state);
        flags.write(now);
        before
    }
}

/// [`PoQueryWatchdogTime`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-poquerywatchdogtime):
/// how long the watchdog of the power request in progress for a device
/// has left. `FALSE`, and nothing written: NK runs no watchdog on a
/// power request, which is the pinned kernel's answer for a device
/// whose request has none.
pub extern "C" fn PoQueryWatchdogTime(_pdo: *mut DEVICE_OBJECT, _seconds: *mut u32) -> u8 {
    0
}

/// The flags of a device the pinned kernel accepts for the platform's
/// low-power idle state.
const DRIPS_DEFINED: u32 = 0x3F;

/// `PoDirectedDripsSetDeviceFlags` (exported, not documented): how a device is to be treated when
/// the platform is put into its low-power idle state. The flags are
/// recorded and never acted on: NK has no such state. Refused with
/// `STATUS_INVALID_PARAMETER`, as by the pinned kernel, for no device,
/// a device with no device node, or a flag beyond the six defined.
///
/// # Safety
/// `device` is null or a live device object.
pub unsafe extern "C" fn PoDirectedDripsSetDeviceFlags(
    device: *mut DEVICE_OBJECT,
    flags: u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if device.is_null()
            || (*(*device).DeviceObjectExtension).DeviceNode.is_null()
            || flags & !DRIPS_DEFINED != 0
        {
            return STATUS_INVALID_PARAMETER;
        }
        let mut power = POWER.lock();
        let block = dope(&mut power, device);
        if block.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        (*block).drips_flags |= flags;
    }
    STATUS_SUCCESS
}

/// What the pinned kernel's `PoDirectedDripsClearDeviceFlags` does,
/// which drivers reach through `ZwPowerInformation`: take `flags` back
/// from those recorded for `device`. Refused as
/// [`PoDirectedDripsSetDeviceFlags`] refuses.
///
/// # Safety
/// `device` is null or a live device object.
pub unsafe fn drips_clear_device_flags(device: *mut DEVICE_OBJECT, flags: u32) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if device.is_null()
            || (*(*device).DeviceObjectExtension).DeviceNode.is_null()
            || flags & !DRIPS_DEFINED != 0
        {
            return STATUS_INVALID_PARAMETER;
        }
        let _power = POWER.lock();
        // A device with no block has no flags to take back.
        let block = (*(*device).DeviceObjectExtension)
            .Dope
            .cast::<super::Dope>();
        if !block.is_null() {
            (*block).drips_flags &= !flags;
        }
    }
    STATUS_SUCCESS
}

/// For the self-tests: how many requests made for drivers have not
/// completed, and the flags recorded for `device`.
///
/// # Safety
/// `device` is a live device object.
pub unsafe fn test_state(device: *mut DEVICE_OBJECT) -> (usize, u32) {
    let power = POWER.lock();
    // SAFETY: per the contract; read under the lock.
    let flags = unsafe {
        let block = (*(*device).DeviceObjectExtension)
            .Dope
            .cast::<super::Dope>();
        if block.is_null() {
            0
        } else {
            (*block).drips_flags
        }
    };
    (power.requests.len(), flags)
}
