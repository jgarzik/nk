//! I/O request packets: allocation, dispatch to a driver, completion.

#![allow(non_snake_case)]

use super::TAG_IRP;
use crate::ke::seh::{self, Guard};
use crate::mm::pool;
use crate::{kd, ke};
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use nk_ntabi::io::*;
use nk_ntabi::status::*;

/// Allocate an IRP with `stack_size` stack locations, as `IoAllocateIrp`
/// does: positioned one past the first location, so the caller fills in
/// the "next" location and `call_driver` steps onto it.
pub fn alloc(stack_size: i8) -> *mut IRP {
    // The IRP and its stack locations, as large as Windows makes them,
    // then a word of NK's own (`requestor_room`).
    let (locations, size) = irp_size(stack_size);
    let irp = pool::alloc_zeroed(size + size_of::<usize>(), TAG_IRP).cast::<IRP>();
    if irp.is_null() {
        return irp;
    }
    // SAFETY: `irp` is a fresh zeroed block large enough for the IRP and
    // its stack locations, which follow it directly.
    unsafe {
        (*irp).Type = IO_TYPE_IRP;
        (*irp).Size = size as u16;
        (*irp).StackCount = locations as i8;
        (*irp).CurrentLocation = locations as i8 + 1;
        (*irp).CurrentStackLocation = irp.add(1).cast::<IO_STACK_LOCATION>().add(locations);
        let head = &raw mut (*irp).ThreadListEntry;
        (*head).Flink = head;
        (*head).Blink = head;
    }
    irp
}

/// How many bytes the requestor's own buffer (`UserBuffer`) holds, for
/// a buffered request whose results are copied to it on completion. It
/// is kept after the stack locations, outside what Windows lays out,
/// because the locations are cleared as the request completes.
///
/// # Safety
/// `irp` came from [`alloc`].
pub unsafe fn requestor_room(irp: *mut IRP) -> *mut usize {
    // SAFETY: per the contract: `alloc` left room for it there.
    unsafe {
        irp.add(1)
            .cast::<IO_STACK_LOCATION>()
            .add((*irp).StackCount as usize)
            .cast()
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
/// fail the request as invalid for the device.
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

/// Final completion: hand the results to the requestor and tell it. A
/// requestor that left an event to be told by owns the IRP and frees it
/// when it has seen the completion; an IRP nobody waits for is freed
/// here. Windows does this part in the requesting thread, by an APC; NK
/// does it wherever the request was completed, which is at
/// `DISPATCH_LEVEL` or below.
///
/// # Safety
/// `irp` must be a live IRP whose stack has fully unwound.
unsafe fn finish(irp: *mut IRP) {
    // SAFETY: per the contract.
    unsafe {
        let status = (*irp).IoStatus.Status;
        let flags = (*irp).Flags;
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
                let room = requestor_room(irp).read();
                if count > room {
                    kd::bugcheck(format_args!(
                        "a driver completed a buffered request with Information={count:#x}, more than the {room:#x} bytes its requestor has room for"
                    ));
                }
                core::ptr::copy_nonoverlapping(buffer, (*irp).UserBuffer.cast::<u8>(), count);
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
            (*irp).UserIosb.write((*irp).IoStatus);
        }
        if (*irp).UserEvent.is_null() {
            free(irp);
        } else {
            // Last: from here the requestor may free the IRP.
            ke::wait::KeSetEvent((*irp).UserEvent, 0, 0);
        }
    }
}

/// Free an IRP (`IoFreeIrp`).
///
/// # Safety
/// `irp` must be a live IRP that no driver still holds.
pub unsafe fn free(irp: *mut IRP) {
    // SAFETY: per the contract; clearing Type makes a stale pointer fail
    // the check in `IofCompleteRequest`.
    unsafe { (*irp).Type = 0 };
    if let Err(e) = pool::free(irp.cast()) {
        kd::bugcheck(format_args!("freeing IRP {irp:p}: {e:?}"));
    }
}

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
