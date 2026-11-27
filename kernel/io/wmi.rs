//! WMI, with no consumer: devices register as data providers, are asked
//! for their registration as Windows asks, and after that nothing ever
//! asks them anything. Events they fire are taken and dropped.
//!
//! The bookkeeping is `nk_etw::wmi::Registry`, under one lock. The
//! registration request is sent from a system worker thread through the
//! ordinary IRP path. What is and is not done is in `doc/DESIGN.md`,
//! "Tracing".

#![allow(non_snake_case)]

use super::{device, irp};
use crate::ex::work::ExQueueWorkItem;
use crate::ke::seh::Guard;
use crate::ke::{Rank, SpinLock, pcr, wait};
use crate::mm::pool;
use crate::ob::object::ObRef;
use crate::{kd, ob};
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use nk_etw::wmi::{self as rules, Deregistered, Registered, Registry};
use nk_ntabi::etw::*;
use nk_ntabi::ex::{DELAYED_WORK_QUEUE, WORK_QUEUE_ITEM};
use nk_ntabi::io::*;
use nk_ntabi::ke::{KEVENT, LIST_ENTRY};
use nk_ntabi::status::*;

/// The devices registered, and the requests owed them.
static WMI: SpinLock<Registry> = SpinLock::new(Rank::IoWmi, Registry::new());

/// The one work item that sends the requests: queued when a request
/// comes to wait and no worker is sending (`Registry` says when).
struct WorkItem(UnsafeCell<WORK_QUEUE_ITEM>);

// SAFETY: touched only by the work queue's routines, and queued only
// while it is on no queue, which `Registry` sees to.
unsafe impl Sync for WorkItem {}

static WORKER: WorkItem = WorkItem(UnsafeCell::new(WORK_QUEUE_ITEM {
    List: LIST_ENTRY {
        Flink: core::ptr::null_mut(),
        Blink: core::ptr::null_mut(),
    },
    WorkerRoutine: Some(send_registrations),
    Parameter: core::ptr::null_mut(),
}));

/// Start the worker: Windows sends registration requests from the
/// delayed work queue.
fn start_worker() {
    // SAFETY: the item is on no queue: the registry starts a worker only
    // when none is at work or queued.
    unsafe { ExQueueWorkItem(WORKER.0.get(), DELAYED_WORK_QUEUE) };
}

/// Pool tag of the buffer a driver writes its registration into.
const TAG: u32 = u32::from_le_bytes(*b"WmiD");
/// The size of the first buffer offered, as on Windows.
const FIRST_BUFFER: usize = 0x2000;
/// What a driver reports as written when all it wrote is the size it
/// needs.
const NEEDED_ONLY: usize = size_of::<u32>();

/// The worker's routine: send every request that waits.
///
/// # Safety
/// Called as a work routine.
unsafe extern "C" fn send_registrations(_: *mut c_void) {
    loop {
        let Some(work) = WMI.lock().next_work() else {
            return;
        };
        // SAFETY: the device is registered, which holds a reference to
        // it, and deregistering waits for this request to come back.
        unsafe { ask(work.device as *mut DEVICE_OBJECT, work.update) };
        WMI.lock().work_done(work.device);
    }
}

/// Ask `device` for its registration, as Windows does: the newer
/// request first, the older if the driver fails that; a larger buffer
/// when the driver says how large. The answer is checked and let go:
/// with no consumer, nothing would ever read it.
///
/// One rule is NK's own: a driver that asks for a buffer no larger than
/// the one it was given is not asked again. Windows goes on for ever.
///
/// # Safety
/// `device` is a live device object that stays so until this returns.
/// Called at `PASSIVE_LEVEL`.
unsafe fn ask(device: *mut DEVICE_OBJECT, update: bool) {
    let mut size = FIRST_BUFFER;
    loop {
        // Not zeroed, as on Windows.
        let buffer = pool::alloc(size, TAG);
        if buffer.is_null() {
            return;
        }
        // SAFETY: per the contract; the buffer is `size` bytes.
        let (minor, status, written) = unsafe {
            match send(device, IRP_MN_REGINFO_EX, update, buffer, size) {
                (status, _) if !nt_success(status) && status != STATUS_BUFFER_TOO_SMALL => {
                    let (status, written) = send(device, IRP_MN_REGINFO, update, buffer, size);
                    (IRP_MN_REGINFO, status, written)
                }
                (status, written) => (IRP_MN_REGINFO_EX, status, written),
            }
        };
        let needs_more = status == STATUS_BUFFER_TOO_SMALL || written == NEEDED_ONLY;
        // The rules run on a copy of what the driver reports written, no
        // more than the buffer holds: the driver has had the buffer's
        // address.
        let length = written.min(size);
        let mut reply: Vec<u8> = Vec::new();
        if reply.try_reserve_exact(length).is_ok() {
            // SAFETY: `length` bytes of the buffer into room for them.
            unsafe {
                core::ptr::copy_nonoverlapping(buffer.cast_const(), reply.as_mut_ptr(), length);
                reply.set_len(length);
            }
        }
        let _ = pool::free(buffer);
        if needs_more {
            let needed = reply
                .first_chunk::<NEEDED_ONLY>()
                .map_or(0, |bytes| u32::from_le_bytes(*bytes) as usize);
            if needed <= size {
                return;
            }
            size = needed;
            continue;
        }
        if nt_success(status)
            && let Some(pdos) = rules::registration_pdos(&reply, minor == IRP_MN_REGINFO_EX)
        {
            // The driver referenced each physical device object for
            // WMI, which keeps only the names of the data blocks: the
            // references go back.
            for pdo in pdos {
                // SAFETY: an object the driver referenced on WMI's
                // behalf.
                unsafe { ob::object::dereference(pdo as *mut u8) };
            }
            if let Some(guids) = rules::registration_guids(&reply) {
                WMI.lock().set_guids(device.addr(), guids);
            }
        }
        return;
    }
}

/// The completion routine of a registration request: tell the sender,
/// who keeps the IRP.
///
/// # Safety
/// Called as a completion routine whose context is the sender's event.
unsafe extern "C" fn completed(
    _: *mut DEVICE_OBJECT,
    _: *mut IRP,
    context: *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { wait::KeSetEvent(context.cast(), 0, 0) };
    STATUS_MORE_PROCESSING_REQUIRED
}

/// Send one `IRP_MJ_SYSTEM_CONTROL` registration request to `device`
/// and wait for it: the status it completed with and the bytes the
/// driver says it wrote.
///
/// The IRP is built as Windows builds it: a stack location of WMI's own
/// above the driver's, the buffer as the system buffer, the status
/// preset to `STATUS_NOT_SUPPORTED`, a completion routine that takes
/// the IRP back. The request goes to the top of the stack the device
/// is in, sized for that stack, and still names the device that
/// registered as its provider: a filter above passes it down.
///
/// # Safety
/// `device` is a live device object; `buffer` is `size` bytes of pool.
unsafe fn send(
    device: *mut DEVICE_OBJECT,
    minor: u8,
    update: bool,
    buffer: *mut u8,
    size: usize,
) -> (NTSTATUS, usize) {
    // SAFETY: per the contract.
    unsafe {
        // Held while the request is with the stack.
        let held = ObRef::adopt(device::IoGetAttachedDeviceReference(device).cast());
        let top = held.cast::<DEVICE_OBJECT>();
        let request = irp::alloc((*top).StackSize.saturating_add(1));
        if request.is_null() {
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        // An all-zero event is a valid value; it is initialised just
        // below, and outlives the request.
        let mut done: KEVENT = core::mem::zeroed();
        wait::KeInitializeEvent(&raw mut done, 0, 0);
        // WMI's own location.
        (*request).CurrentLocation -= 1;
        (*request).CurrentStackLocation = (*request).CurrentStackLocation.sub(1);
        (*request).SystemBuffer = buffer.cast();
        (*request).Thread = pcr::current_thread().cast();
        (*request).IoStatus.Status = STATUS_NOT_SUPPORTED;
        let location = irp::next_location(request);
        (*location).MajorFunction = IRP_MJ_SYSTEM_CONTROL;
        (*location).MinorFunction = minor;
        // `Parameters.WMI`: ProviderId, DataPath, BufferSize, Buffer.
        (*location).Parameters = [
            device.addr() as u64,
            u64::from(update),
            size as u64,
            buffer.addr() as u64,
        ];
        (*location).CompletionRoutine = Some(completed);
        (*location).Context = (&raw mut done).cast();
        (*location).Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
        // Nothing is owed if the routine does not return: beneath it is
        // the worker, where an exception is unhandled.
        let returned = irp::call_driver(top, request, &Guard::Nothing);
        if returned != STATUS_PENDING && wait::KeReadStateEvent(&raw mut done) == 0 {
            // The driver neither completed the request nor said it
            // would. It may still hold the IRP: leave it be.
            kd::verify(format_args!(
                "a driver returned {returned:#010x} from IRP_MJ_SYSTEM_CONTROL without \
                 completing the request"
            ));
            // Kept with the request the driver may still hold.
            held.into_raw();
            return (returned, 0);
        }
        wait::wait(Some((&raw mut done).cast()), None);
        let result = ((*request).IoStatus.Status, (*request).IoStatus.Information);
        irp::free(request);
        result
    }
}

/// `WMIREG_ACTION_*`, and the two flags that go with an action.
const REGISTER: u32 = 1;
const DEREGISTER: u32 = 2;
const REREGISTER: u32 = 3;
const UPDATE_GUIDS: u32 = 4;
const BLOCK_IRPS: u32 = 5;
/// `WMIREG_FLAG_TRACE_PROVIDER` and the trace-notification bits that go
/// with it: the bits the pinned kernel takes off an action.
const TRACE_BITS: u32 = 0x00F1_0000;
const FLAG_CALLBACK: u32 = 0x8000_0000;

fn register(device: *mut DEVICE_OBJECT) -> NTSTATUS {
    // The registration holds the device object; given back if it turns
    // out to be registered already, and when it is deregistered.
    // SAFETY: a live device object, checked by the caller.
    unsafe { ob::object::reference(device.cast()) };
    let registered = WMI.lock().register(device.addr());
    match registered {
        Registered::Exists => {
            // SAFETY: the reference taken above.
            unsafe { ob::object::dereference(device.cast()) };
            STATUS_OBJECT_NAME_EXISTS
        }
        Registered::New { start, .. } => {
            if start {
                start_worker();
            }
            STATUS_SUCCESS
        }
    }
}

fn deregister(device: *mut DEVICE_OBJECT) -> NTSTATUS {
    loop {
        let deregistered = WMI.lock().deregister(device.addr());
        match deregistered {
            Deregistered::Absent => return STATUS_INVALID_PARAMETER,
            Deregistered::Removed => {
                // SAFETY: the reference the registration held.
                unsafe { ob::object::dereference(device.cast()) };
                return STATUS_SUCCESS;
            }
            // A request is with the driver: wait for it to come back,
            // as Windows does, a millisecond at a time.
            Deregistered::Busy => {
                // SAFETY: no object is waited on.
                unsafe { wait::wait(None, Some(-10_000)) };
            }
        }
    }
}

/// [`IoWMIRegistrationControl`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iowmiregistrationcontrol).
///
/// Registering returns at once; a worker thread then sends the device
/// `IRP_MN_REGINFO_EX`, and `IRP_MN_REGINFO` if the driver fails that.
/// Deregistering waits for a request that is with the driver. Statuses
/// are Windows': a device registered already
/// (`STATUS_OBJECT_NAME_EXISTS`, a success), one not registered and an
/// unknown action (`STATUS_INVALID_PARAMETER`).
///
/// An action that carries `WMIREG_FLAG_TRACE_PROVIDER`, and with it the
/// bits that ask for trace notifications (what `partmgr.sys` and
/// `volmgr.sys` pass), is taken without those bits, as the pinned kernel
/// takes it while WMI runs: the device is registered as any other. No
/// trace session exists to enable it, so the notifications are never
/// due.
///
/// Partial: a registration by callback (`WMIREG_FLAG_CALLBACK`, which
/// names a routine where the device would be) is the way WPP registered
/// before `EtwRegisterClassicProvider` existed. NK does not take it and
/// answers `STATUS_UNSUCCESSFUL`, as Windows does while WMI is not
/// running.
///
/// # Safety
/// `device` is a live device object, unless the action is by callback.
/// Called at `PASSIVE_LEVEL`.
pub unsafe extern "C" fn IoWMIRegistrationControl(device: *mut c_void, action: u32) -> NTSTATUS {
    if action & FLAG_CALLBACK != 0 {
        return STATUS_UNSUCCESSFUL;
    }
    let action = action & !TRACE_BITS;
    let device = device.cast::<DEVICE_OBJECT>();
    // SAFETY: per the contract.
    unsafe { device::check(device, "IoWMIRegistrationControl") };
    match action {
        REGISTER => register(device),
        DEREGISTER => deregister(device),
        REREGISTER => match deregister(device) {
            status if nt_success(status) => register(device),
            status => status,
        },
        UPDATE_GUIDS => {
            let start = WMI.lock().update(device.addr());
            match start {
                None => STATUS_INVALID_PARAMETER,
                Some(start) => {
                    if start {
                        start_worker();
                    }
                    STATUS_SUCCESS
                }
            }
        }
        BLOCK_IRPS => {
            if WMI.lock().block(device.addr()) {
                STATUS_SUCCESS
            } else {
                STATUS_INVALID_PARAMETER
            }
        }
        _ => STATUS_INVALID_PARAMETER,
    }
}

/// `WMIGUID_NOTIFICATION`, and the access that asks for a trace
/// provider's block: opens that are for events, not for data.
const WMIGUID_NOTIFICATION: u32 = 0x4;
const TRACELOG_REGISTER_GUIDS: u32 = 0x0004_0000;

/// [`IoWMIOpenBlock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iowmiopenblock):
/// open a WMI data block, by its GUID, to query it, set it or run its
/// methods. A block no registered device's registration names is not
/// there: `STATUS_WMI_GUID_NOT_FOUND`, as the pinned kernel answers
/// such an open (`WmipOpenBlock`), and nothing is written.
///
/// NK is no WMI consumer: it keeps the names of the blocks devices
/// register and never asks a device for one. Opening a block that is
/// registered, or opening one for its events (which Windows allows
/// before anyone registers it), stops the system by name: the
/// ledger's "partial".
///
/// # Safety
/// `guid` is readable; `data_block_object` is writable.
pub unsafe extern "C" fn IoWMIOpenBlock(
    guid: *const GUID,
    desired_access: u32,
    _data_block_object: *mut *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract: a GUID is sixteen bytes.
    let name = unsafe { guid.cast::<[u8; 16]>().read_unaligned() };
    if desired_access & (WMIGUID_NOTIFICATION | TRACELOG_REGISTER_GUIDS) != 0 {
        kd::bugcheck(format_args!(
            "IoWMIOpenBlock: opening the WMI block {name:02x?} for its events (access \
             {desired_access:#x}) is not implemented"
        ));
    }
    if !WMI.lock().registers(&name) {
        return STATUS_WMI_GUID_NOT_FOUND;
    }
    kd::bugcheck(format_args!(
        "IoWMIOpenBlock: the WMI data block {name:02x?} is registered by a driver, and querying \
         a registered block is not implemented"
    ))
}

/// [`IoWMIDeviceObjectToProviderId`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iowmideviceobjecttoproviderid):
/// the provider id a registered device has; zero for one that is not
/// registered. Callable at `DISPATCH_LEVEL`.
pub extern "C" fn IoWMIDeviceObjectToProviderId(device: *mut DEVICE_OBJECT) -> u32 {
    WMI.lock().provider_id(device.addr())
}

/// [`IoWMIWriteEvent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iowmiwriteevent):
/// fire a WMI event. Nobody has asked for any, so the event is dropped:
/// the block, which is the kernel's from the moment it says yes, is
/// freed. Windows frees it from a worker thread a moment later; no
/// driver can tell.
///
/// An event marked as a trace event (`WNODE_FLAG_TRACED_GUID`) goes to
/// the trace session its header names, and stays the caller's: there
/// is no session (`STATUS_INVALID_HANDLE`), after Windows' two checks
/// of its size.
///
/// # Safety
/// `event` is a pool block that begins with a `WNODE_HEADER`. Called at
/// `DISPATCH_LEVEL` or below.
pub unsafe extern "C" fn IoWMIWriteEvent(event: *mut c_void) -> NTSTATUS {
    let header = event.cast::<WNODE_HEADER>();
    // SAFETY: per the contract.
    let (size, flags) = unsafe {
        (
            (&raw const (*header).BufferSize).read_unaligned(),
            (&raw const (*header).Flags).read_unaligned(),
        )
    };
    if flags & (WNODE_FLAG_TRACED_GUID | WNODE_FLAG_LOG_WNODE) != 0 {
        if (size as usize) < size_of::<WNODE_HEADER>() {
            return STATUS_BUFFER_TOO_SMALL;
        }
        let traced = flags & WNODE_FLAG_TRACED_GUID != 0;
        let limit = if traced { 0xFFFF } else { 0x7FFF_FFFF };
        if size > limit {
            return STATUS_BUFFER_OVERFLOW;
        }
        if traced {
            return STATUS_INVALID_HANDLE;
        }
    }
    // SAFETY: per the contract; anything but a pool block stops the
    // system, as freeing it does on Windows.
    unsafe { pool::ExFreePoolWithTag(event, 0) };
    STATUS_SUCCESS
}
