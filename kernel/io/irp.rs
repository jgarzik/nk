//! I/O request packets: allocation, dispatch to a driver, completion.

#![allow(non_snake_case)]

use super::TAG_IRP;
use crate::ke::seh::{self, Guard};
use crate::mm::pool;
use crate::{kd, ke};
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use nk_ntabi::io::*;
use nk_ntabi::status::*;

/// What NK keeps about an IRP it allocated itself, behind the stack
/// locations and outside what Windows lays out: the locations are
/// cleared as the request completes, and an IRP in a driver's own
/// memory (`IoInitializeIrp`) has no such block.
#[repr(C)]
struct Private {
    /// How many bytes the requestor's own buffer (`UserBuffer`) holds,
    /// for a buffered request whose results are copied to it on
    /// completion ([`ROOM_KNOWN`]).
    room: usize,
    flags: usize,
}

/// `Private.flags`: `room` has been set.
const ROOM_KNOWN: usize = 1;
/// `Private.flags`: the requestor keeps the IRP when it completes, and
/// frees it itself.
const REQUESTOR_KEEPS: usize = 2;

/// Make `packet_size` bytes at `irp` an IRP with `locations` stack
/// locations, positioned one past the first of them, so that the
/// sender fills in the "next" location and `call_driver` steps onto
/// it.
///
/// # Safety
/// `irp` is writable for `packet_size` bytes, which hold an IRP and
/// that many locations, and nothing else uses them.
unsafe fn init(irp: *mut IRP, packet_size: u16, locations: i8) {
    // SAFETY: per the contract.
    unsafe {
        core::ptr::write_bytes(irp.cast::<u8>(), 0, usize::from(packet_size));
        (*irp).Type = IO_TYPE_IRP;
        (*irp).Size = packet_size;
        (*irp).StackCount = locations;
        (*irp).CurrentLocation = locations + 1;
        (*irp).ApcEnvironment = ORIGINAL_APC_ENVIRONMENT;
        (*irp).CurrentStackLocation = irp
            .add(1)
            .cast::<IO_STACK_LOCATION>()
            .add(locations as usize);
        let head = &raw mut (*irp).ThreadListEntry;
        (*head).Flink = head;
        (*head).Blink = head;
    }
}

/// Allocate an IRP with `stack_size` stack locations, as `IoAllocateIrp`
/// does.
pub fn alloc(stack_size: i8) -> *mut IRP {
    // The IRP and its stack locations, as large as Windows makes them,
    // then NK's own block.
    let (locations, size) = irp_size(stack_size);
    let irp = pool::alloc_zeroed(size + size_of::<Private>(), TAG_IRP).cast::<IRP>();
    if irp.is_null() {
        return irp;
    }
    // SAFETY: `irp` is a fresh zeroed block large enough for the IRP and
    // its stack locations, which follow it directly.
    unsafe { init(irp, size as u16, locations as i8) };
    irp
}

/// NK's block behind `irp`, if `irp` is an IRP NK allocated that is
/// still the size it was allocated with: the pool knows.
///
/// # Safety
/// `irp` is a live IRP.
unsafe fn private(irp: *mut IRP) -> Option<*mut Private> {
    // SAFETY: per the contract.
    let size = usize::from(unsafe { (*irp).Size });
    match pool::info(irp.cast()) {
        Some((block, TAG_IRP)) if block == size + size_of::<Private>() => {
            // SAFETY: the block is that long, so NK's part follows the
            // IRP and its locations.
            Some(unsafe { irp.cast::<u8>().add(size).cast() })
        }
        _ => None,
    }
}

/// Say how many bytes the requestor's own buffer (`UserBuffer`) holds:
/// a driver that reports more than that as returned stops the system
/// instead of overrunning the buffer.
///
/// # Safety
/// `irp` came from [`alloc`] and has not been sent.
pub unsafe fn set_requestor_room(irp: *mut IRP, room: usize) {
    // SAFETY: per the contract: the block is there.
    unsafe {
        let Some(private) = private(irp) else {
            kd::bugcheck(format_args!("IRP {irp:p} is not one NK allocated"));
        };
        (*private).room = room;
        (*private).flags |= ROOM_KNOWN;
    }
}

/// Have final completion leave `irp` allocated: the requestor frees it
/// once it has seen the completion, which the request's event tells it.
///
/// # Safety
/// `irp` came from [`alloc`] and has not been sent.
pub unsafe fn requestor_keeps(irp: *mut IRP) {
    // SAFETY: per the contract: the block is there.
    unsafe {
        let Some(private) = private(irp) else {
            kd::bugcheck(format_args!("IRP {irp:p} is not one NK allocated"));
        };
        (*private).flags |= REQUESTOR_KEEPS;
    }
}

/// The stack location the next driver will see (`IoGetNextIrpStackLocation`).
///
/// # Safety
/// `irp` must be a live IRP with a location left below the current one.
pub unsafe fn next_location(irp: *mut IRP) -> *mut IO_STACK_LOCATION {
    // SAFETY: per the contract.
    unsafe { (*irp).CurrentStackLocation.sub(1) }
}

/// Send `irp` to the driver that owns `device`: what `IofCallDriver` does.
/// Returns the dispatch routine's status. `guard` is what the caller
/// owes if an exception unwinds the dispatch routine.
///
/// # Safety
/// `device` must be a live device object and `irp` a live IRP whose next
/// stack location has been set up.
pub unsafe fn call_driver(device: *mut DEVICE_OBJECT, irp: *mut IRP, guard: &Guard) -> NTSTATUS {
    // SAFETY: per the contract. The dispatch table always holds a routine:
    // `driver::load` fills every slot with the invalid-request handler.
    unsafe {
        (*irp).CurrentLocation -= 1;
        if (*irp).CurrentLocation <= 0 {
            kd::bugcheck(format_args!(
                "IoCallDriver: IRP {irp:p} has no stack location left"
            ));
        }
        (*irp).CurrentStackLocation = (*irp).CurrentStackLocation.sub(1);
        let location = (*irp).CurrentStackLocation;
        (*location).DeviceObject = device;
        let driver = (*device).DriverObject;
        let major = usize::from((*location).MajorFunction);
        match (*driver).MajorFunction.get(major).copied().flatten() {
            Some(dispatch) => {
                seh::call(dispatch as usize, [device.addr(), irp.addr(), 0, 0], guard) as u32
                    as NTSTATUS
            }
            None => kd::bugcheck(format_args!(
                "IoCallDriver: no dispatch routine for major function {major:#x}"
            )),
        }
    }
}

/// The dispatch routine every driver starts with for every request type:
/// fail the request as invalid for the device. Plug and Play and power
/// requests are no exception: the pinned kernel fills a new driver
/// object's whole table with one routine, which completes the request
/// with this status whatever its major function.
///
/// # Safety
/// `irp` must be a live IRP being dispatched.
pub unsafe extern "C" fn invalid_device_request(
    _device: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        (*irp).IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IofCompleteRequest(irp, 0);
    }
    STATUS_INVALID_DEVICE_REQUEST
}

/// `IofCompleteRequest` (`IoCompleteRequest`): the driver is done with
/// the IRP. Runs completion routines of the drivers above it, then
/// finishes the request and frees the IRP.
///
/// # Safety
/// `irp` must be a live IRP that the caller owns and has not completed.
pub unsafe extern "C" fn IofCompleteRequest(irp: *mut IRP, _priority_boost: i8) {
    // SAFETY: per the contract; each check below turns a broken contract
    // into a named bugcheck instead of memory corruption.
    unsafe {
        if irp.is_null() || (*irp).Type != IO_TYPE_IRP {
            kd::bugcheck(format_args!("IoCompleteRequest: {irp:p} is not an IRP"));
        }
        let top = (*irp).StackCount + 1;
        if (*irp).CurrentLocation > top {
            kd::bugcheck(format_args!(
                "MULTIPLE_IRP_COMPLETE_REQUESTS: IRP {irp:p} completed twice"
            ));
        }
        if (*irp).IoStatus.Status == STATUS_PENDING {
            kd::bugcheck(format_args!(
                "IoCompleteRequest: IRP {irp:p} completed with STATUS_PENDING"
            ));
        }

        // Unwind the stack: each location's completion routine may run.
        let mut location = (*irp).CurrentStackLocation;
        (*irp).CurrentLocation += 1;
        (*irp).CurrentStackLocation = location.add(1);
        while (*irp).CurrentLocation <= top {
            let control = (*location).Control;
            (*irp).PendingReturned = control & SL_PENDING_RETURNED;
            let status = (*irp).IoStatus.Status;
            let wanted = completion_routine_wanted(control, status, (*irp).Cancel != 0);
            let (routine, context) = ((*location).CompletionRoutine, (*location).Context);
            core::ptr::write_bytes(location, 0, 1);
            if let (true, Some(routine)) = (wanted, routine) {
                // The routine is told the device of the location above.
                let device = if (*irp).CurrentLocation == top {
                    core::ptr::null_mut()
                } else {
                    (*(*irp).CurrentStackLocation).DeviceObject
                };
                // Nothing is held across the routine: an unwind
                // through it leaves the IRP as the routine left it.
                let status = seh::call(
                    routine as usize,
                    [device.addr(), irp.addr(), context.addr(), 0],
                    &Guard::Nothing,
                );
                if status as u32 as NTSTATUS == STATUS_MORE_PROCESSING_REQUIRED {
                    return; // the routine took the IRP back
                }
            } else if (*irp).PendingReturned != 0 && (*irp).CurrentLocation <= (*irp).StackCount {
                (*(*irp).CurrentStackLocation).Control |= SL_PENDING_RETURNED;
            }
            location = location.add(1);
            (*irp).CurrentLocation += 1;
            (*irp).CurrentStackLocation = (*irp).CurrentStackLocation.add(1);
        }
        finish(irp);
    }
}

/// Final completion: hand the results to the requestor, tell it by its
/// event if it left one, and free the IRP, as Windows' I/O manager frees
/// a request that completes all the way up. NK's own requestor
/// (`io::file`) keeps its IRPs instead ([`requestor_keeps`]) and frees
/// them when it has seen the completion. Windows does this part in the
/// requesting thread, by an APC; NK does it wherever the request was
/// completed, which is at `DISPATCH_LEVEL` or below.
///
/// The requestor's status block gets the request's final status, which
/// is the fault if the results could not be copied to a user-mode
/// requestor. The IRP keeps the status its driver completed it with:
/// the requestor holds the driver to that one.
///
/// # Safety
/// `irp` must be a live IRP whose stack has fully unwound.
unsafe fn finish(irp: *mut IRP) {
    // SAFETY: per the contract.
    unsafe {
        let mut result = (*irp).IoStatus;
        let status = result.Status;
        let flags = (*irp).Flags;
        // Read before the requestor is told: it may free the IRP then.
        let (room, keeps) = match private(irp) {
            Some(private) => (
                ((*private).flags & ROOM_KNOWN != 0).then_some((*private).room),
                (*private).flags & REQUESTOR_KEEPS != 0,
            ),
            None => (None, false),
        };
        if flags & IRP_BUFFERED_IO != 0 {
            let buffer = (*irp).SystemBuffer.cast::<u8>();
            // Results are copied out unless the request failed outright
            // (warnings still return data).
            if flags & IRP_INPUT_OPERATION != 0 && !nt_error(status) && !buffer.is_null() {
                let count = (*irp).IoStatus.Information;
                // The driver reports how much it wrote. A count larger
                // than the buffer it was given means it overran it.
                match pool::info(buffer) {
                    Some((size, _)) if count <= size => {}
                    _ => kd::bugcheck(format_args!(
                        "driver completed a buffered request with Information={count:#x}, larger than its buffer"
                    )),
                }
                // Nor may it report more than the requestor has room
                // for: the system buffer is as large as the larger of
                // input and output, the requestor's buffer only as
                // large as the output.
                if let Some(room) = room
                    && count > room
                {
                    kd::bugcheck(format_args!(
                        "a driver completed a buffered request with Information={count:#x}, more than the {room:#x} bytes its requestor has room for"
                    ));
                }
                let requestor = (*irp).UserBuffer.cast::<u8>();
                if (*irp).RequestorMode == KERNEL_MODE {
                    core::ptr::copy_nonoverlapping(buffer, requestor, count);
                } else if crate::mm::user::copy(requestor, buffer, count).is_err() {
                    // User mode's buffer was probed when the request was
                    // made and may be gone by now: the request ends
                    // with the fault, as the exception Windows catches
                    // here becomes its final status.
                    result.Status = STATUS_ACCESS_VIOLATION;
                }
            }
            if flags & IRP_DEALLOCATE_BUFFER != 0
                && !buffer.is_null()
                && let Err(e) = pool::free(buffer)
            {
                kd::bugcheck(format_args!("freeing a request's system buffer: {e:?}"));
            }
        }
        super::mdl::release_chain(irp);
        if !(*irp).UserIosb.is_null() {
            (*irp).UserIosb.write(result);
        }
        let event = (*irp).UserEvent;
        if !keeps {
            free(irp);
        }
        if !event.is_null() {
            // Last: from here a requestor that keeps its IRP may free
            // it, and one that does not may let go of the event.
            ke::wait::KeSetEvent(event, 0, 0);
        }
    }
}

/// Free an IRP (`IoFreeIrp`).
///
/// # Safety
/// `irp` must be a live IRP that no driver still holds.
pub unsafe fn free(irp: *mut IRP) {
    // SAFETY: per the contract; clearing Type makes a stale pointer fail
    // the check in `IofCompleteRequest`. The IRP's extension block, if
    // it has one, goes with it.
    unsafe {
        super::irpext::freed(irp);
        (*irp).Type = 0;
    }
    if let Err(e) = pool::free(irp.cast()) {
        kd::bugcheck(format_args!("freeing IRP {irp:p}: {e:?}"));
    }
}

/// [`IoAllocateIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioallocateirp):
/// an IRP of a driver's own, with `stack_size` stack locations, or null.
/// Nothing is charged to a process: NK keeps no quota.
pub extern "C" fn IoAllocateIrp(stack_size: i8, _charge_quota: u8) -> *mut IRP {
    if stack_size <= 0 {
        return core::ptr::null_mut();
    }
    alloc(stack_size)
}

/// [`IoFreeIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iofreeirp).
///
/// # Safety
/// `irp` is an IRP from `IoAllocateIrp` that no driver still holds.
pub unsafe extern "C" fn IoFreeIrp(irp: *mut IRP) {
    // SAFETY: per the contract.
    unsafe {
        if (*irp).Type != IO_TYPE_IRP {
            kd::bugcheck(format_args!("IoFreeIrp: {irp:p} is not an IRP"));
        }
        free(irp);
    }
}

/// [`IoInitializeIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioinitializeirp):
/// make `packet_size` bytes of the caller's an IRP with `stack_size`
/// stack locations. Everything in them is cleared, the allocation
/// flags included, as on Windows.
///
/// # Safety
/// `irp` is writable for `packet_size` bytes, which no request uses.
pub unsafe extern "C" fn IoInitializeIrp(irp: *mut IRP, packet_size: u16, stack_size: i8) {
    let (_, needed) = irp_size(stack_size);
    if stack_size < 1 || usize::from(packet_size) < needed {
        kd::bugcheck(format_args!(
            "IoInitializeIrp: {packet_size:#x} bytes do not hold an IRP with {stack_size} \
             stack locations"
        ));
    }
    // SAFETY: per the contract. An IRP NK allocated has NK's block
    // behind it, which is cleared with the request it described.
    unsafe {
        let own = matches!(
            pool::info(irp.cast()),
            Some((block, TAG_IRP)) if block == usize::from(packet_size) + size_of::<Private>()
        );
        init(irp, packet_size, stack_size);
        if own {
            irp.cast::<u8>()
                .add(usize::from(packet_size))
                .cast::<Private>()
                .write(Private { room: 0, flags: 0 });
        }
    }
}

/// [`IoReuseIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioreuseirp):
/// make an IRP of the caller's ready to be sent again, with `status` as
/// its status. It keeps its size, its stack locations, the
/// allocation flags the pinned kernel keeps ([`REUSE_KEEPS`]), and of
/// its extensions the block and the activity id (`irpext`).
///
/// # Safety
/// `irp` is an IRP of the caller's that no driver holds.
pub unsafe extern "C" fn IoReuseIrp(irp: *mut IRP, status: NTSTATUS) {
    // SAFETY: per the contract.
    unsafe {
        if (*irp).Type != IO_TYPE_IRP {
            kd::bugcheck(format_args!("IoReuseIrp: {irp:p} is not an IRP"));
        }
        if !(*irp).CancelRoutine.is_null() {
            kd::bugcheck(format_args!(
                "IoReuseIrp: IRP {irp:p} still has a cancel routine"
            ));
        }
        let kept = (*irp).AllocationFlags & REUSE_KEEPS;
        let extension = super::irpext::before_reuse(irp);
        IoInitializeIrp(irp, (*irp).Size, (*irp).StackCount);
        (*irp).AllocationFlags = kept;
        super::irpext::after_reuse(irp, extension);
        (*irp).IoStatus.Status = status;
    }
}

/// The bits of `IRP.AllocationFlags` that `IoReuseIrp` of the pinned
/// kernel carries over. NK sets one of them: that the IRP has an
/// extension block.
const REUSE_KEEPS: u8 = 0x6D;

/// [`IoGetRequestorProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-iogetrequestorprocess):
/// the process of the thread that made the request, or null for a
/// request no thread made (`Tail.Overlay.Thread` null: an IRP a driver
/// allocated itself). Read as the pinned kernel reads it:
///
/// | The IRP | Answer |
/// | --- | --- |
/// | marked [`IRP_ISSUING_PROCESS_IN_OVERLAY`] | `Overlay`'s first word, less its low three bits, whatever the thread |
/// | no thread | null |
/// | `ApcEnvironment` original | the thread's own process (`KTHREAD.Process`) |
/// | `ApcEnvironment` attached | the process the thread is attached to (`KTHREAD.ApcState.Process`), as it stands now |
/// | any other `ApcEnvironment` | null |
///
/// Every thread of NK's is in the System process, so a request NK
/// sends for a thread answers `PsInitialSystemProcess`. No reference is
/// taken, as on Windows.
///
/// # Safety
/// `irp` is a live IRP, and its thread, if it names one, a live thread.
pub unsafe extern "C" fn IoGetRequestorProcess(irp: *mut IRP) -> *mut core::ffi::c_void {
    use nk_ntabi::thread as thread_layout;
    // SAFETY: per the contract; both are read field by field.
    unsafe {
        if (*irp).Flags & IRP_ISSUING_PROCESS_IN_OVERLAY != 0 {
            return ((*irp).Overlay[0] as usize & !7) as *mut core::ffi::c_void;
        }
        let thread = (*irp).Thread.cast::<u8>();
        if thread.is_null() {
            return core::ptr::null_mut();
        }
        let process = match (*irp).ApcEnvironment {
            ORIGINAL_APC_ENVIRONMENT => thread_layout::PROCESS,
            ATTACHED_APC_ENVIRONMENT => thread_layout::APC_STATE_PROCESS,
            _ => return core::ptr::null_mut(),
        };
        thread.add(process).cast::<*mut core::ffi::c_void>().read()
    }
}

/// [`IofCallDriver`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iofcalldriver):
/// what `IoCallDriver` compiles to. A driver sends a request to another.
/// An exception the other's dispatch routine lets out passes through to
/// the sender's handlers, and NK holds nothing across the call.
///
/// # Safety
/// `device` is a live device object and `irp` a live IRP whose next
/// stack location the caller has set up.
pub unsafe extern "C" fn IofCallDriver(device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { call_driver(device, irp, &Guard::Nothing) }
}

/// The completion routine [`IoForwardIrpSynchronously`] sets: wake the
/// forwarder, and keep the request for it.
///
/// # Safety
/// `context` is the forwarder's event.
unsafe extern "C" fn forwarded(
    _device: *mut DEVICE_OBJECT,
    _irp: *mut IRP,
    context: *mut core::ffi::c_void,
) -> NTSTATUS {
    // SAFETY: per the contract; the forwarder waits on it.
    unsafe { crate::ke::wait::KeSetEvent(context.cast(), 0, 0) };
    STATUS_MORE_PROCESSING_REQUIRED
}

/// [`IoForwardIrpSynchronously`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioforwardirpsynchronously):
/// pass `irp` down to `device` with the caller's stack location copied
/// to the next, and wait for the drivers below to complete it. The
/// request comes back to the caller, its status in `IoStatus`, for the
/// caller to complete. FALSE, and nothing sent, if the request has no
/// location left below the current one.
///
/// # Safety
/// `device` is a live device object and `irp` a live IRP its caller
/// owns. Called at `PASSIVE_LEVEL`.
pub unsafe extern "C" fn IoForwardIrpSynchronously(
    device: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> u8 {
    crate::ke::irql::expect_passive("IoForwardIrpSynchronously");
    // SAFETY: per the contract. The event lives on this stack until the
    // completion routine has set it and this has seen it set.
    unsafe {
        if (*irp).CurrentLocation <= 1 {
            return 0;
        }
        let current = (*irp).CurrentStackLocation;
        let next = next_location(irp);
        // `IoCopyCurrentIrpStackLocationToNext`: all but the completion
        // routine, its context and its control bits.
        (*next).MajorFunction = (*current).MajorFunction;
        (*next).MinorFunction = (*current).MinorFunction;
        (*next).Flags = (*current).Flags;
        (*next).Parameters = (*current).Parameters;
        (*next).DeviceObject = (*current).DeviceObject;
        (*next).FileObject = (*current).FileObject;
        let mut done: KEVENT = core::mem::zeroed();
        crate::ke::wait::KeInitializeEvent(&raw mut done, 0, 0);
        (*next).CompletionRoutine = Some(forwarded);
        (*next).Context = (&raw mut done).cast();
        (*next).Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
        if IofCallDriver(device, irp) == STATUS_PENDING {
            crate::ke::wait::wait(Some((&raw mut done).cast()), None);
        }
    }
    1
}

/// [`PoCallDriver`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pocalldriver):
/// send a power request to the next driver. Since Windows Vista a power
/// request is sent as any other; the pinned kernel's `PoCallDriver` is
/// a call of `IofCallDriver` and nothing more.
///
/// # Safety
/// As [`IofCallDriver`].
pub unsafe extern "C" fn PoCallDriver(device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { IofCallDriver(device, irp) }
}

/// [`PoStartNextPowerIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-postartnextpowerirp):
/// nothing, since Windows Vista: the power manager no longer holds the
/// next power request back until a driver calls this. The pinned
/// kernel's returns at once.
pub extern "C" fn PoStartNextPowerIrp(_irp: *mut IRP) {}

/// The cancel spin lock: one lock for the whole system, which a driver's
/// cancel routine is entered holding and must release. It is a driver's
/// kind of lock (taken here, released there), so it is not one of NK's
/// ranked locks.
static CANCEL_LOCK: AtomicBool = AtomicBool::new(false);

/// [`IoAcquireCancelSpinLock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioacquirecancelspinlock):
/// take the cancel lock, raising the IRQL to `DISPATCH_LEVEL`; the level
/// before goes to `*irql`.
///
/// # Safety
/// `irql` points to room for a `KIRQL`.
pub unsafe extern "C" fn IoAcquireCancelSpinLock(irql: *mut u8) {
    let old = ke::irql::current();
    if old < ke::irql::DISPATCH_LEVEL {
        crate::arch::set_irql(ke::irql::DISPATCH_LEVEL);
    }
    while CANCEL_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
    // SAFETY: per the contract.
    unsafe { irql.write(old) };
}

/// [`IoReleaseCancelSpinLock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioreleasecancelspinlock):
/// release the cancel lock and set the IRQL to `irql`.
pub extern "C" fn IoReleaseCancelSpinLock(irql: u8) {
    if !CANCEL_LOCK.swap(false, Ordering::Release) {
        kd::verify(format_args!("the cancel spin lock released while not held"));
    }
    crate::arch::set_irql(irql);
}

/// A request's cancel flag (`Irp->Cancel`), for reading and writing
/// in step with its cancel routine.
///
/// # Safety
/// `irp` is a live IRP.
pub unsafe fn cancel_flag<'a>(irp: *mut IRP) -> &'a core::sync::atomic::AtomicU8 {
    // SAFETY: per the contract.
    unsafe { core::sync::atomic::AtomicU8::from_ptr(&raw mut (*irp).Cancel) }
}

/// [`IoCancelIrp`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocancelirp):
/// mark the IRP cancelled and, if its driver left a cancel routine,
/// call it, with the cancel lock held, for the routine to release.
/// Returns whether a routine was called.
///
/// # Safety
/// `irp` is a live IRP that will not be freed during the call.
pub unsafe extern "C" fn IoCancelIrp(irp: *mut IRP) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let mut old = 0;
        IoAcquireCancelSpinLock(&raw mut old);
        // The flag, then the routine; whoever makes a request
        // cancellable installs the routine, then reads the flag. Both
        // orders must be seen by both sides: sequentially consistent
        // operations (`doc/DESIGN.md`).
        cancel_flag(irp).store(1, Ordering::SeqCst);
        // Taken out in one step: the driver takes it out the same way
        // when it means to complete the request itself.
        let routine = AtomicPtr::from_ptr(&raw mut (*irp).CancelRoutine)
            .swap(core::ptr::null_mut(), Ordering::SeqCst);
        if routine.is_null() {
            IoReleaseCancelSpinLock(old);
            return 0;
        }
        if (*irp).CurrentLocation > (*irp).StackCount + 1 {
            kd::bugcheck(format_args!(
                "0x00000048 CANCEL_STATE_IN_COMPLETED_IRP: IRP {irp:p} was completed with its \
                 cancel routine still set"
            ));
        }
        (*irp).CancelIrql = old;
        // The cancel lock and the IRQL it raised are the routine's to
        // give back; nothing else is held across it.
        let device = (*(*irp).CurrentStackLocation).DeviceObject;
        seh::call(
            routine.addr(),
            [device.addr(), irp.addr(), 0, 0],
            &Guard::Nothing,
        );
        1
    }
}
