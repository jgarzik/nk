//! I/O request packets: allocation, dispatch to a driver, completion.

#![allow(non_snake_case)]

use super::TAG_IRP;
use crate::mm::pool;
use crate::{kd, ke};
use nk_ntabi::io::*;
use nk_ntabi::status::*;

/// Allocate an IRP with `stack_size` stack locations, as `IoAllocateIrp`
/// does: positioned one past the first location, so the caller fills in
/// the "next" location and `call_driver` steps onto it.
pub fn alloc(stack_size: i8) -> *mut IRP {
    let locations = stack_size.max(1) as usize;
    let size = size_of::<IRP>() + locations * size_of::<IO_STACK_LOCATION>();
    let irp = pool::alloc_zeroed(size, TAG_IRP).cast::<IRP>();
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

/// The stack location the next driver will see (`IoGetNextIrpStackLocation`).
///
/// # Safety
/// `irp` must be a live IRP with a location left below the current one.
pub unsafe fn next_location(irp: *mut IRP) -> *mut IO_STACK_LOCATION {
    // SAFETY: per the contract.
    unsafe { (*irp).CurrentStackLocation.sub(1) }
}

/// Send `irp` to the driver that owns `device`: what `IofCallDriver` does.
/// Returns the dispatch routine's status.
///
/// # Safety
/// `device` must be a live device object and `irp` a live IRP whose next
/// stack location has been set up.
pub unsafe fn call_driver(device: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
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
            Some(dispatch) => dispatch(device, irp),
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
            let wanted = (nt_success(status) && control & SL_INVOKE_ON_SUCCESS != 0)
                || (!nt_success(status) && control & SL_INVOKE_ON_ERROR != 0)
                || ((*irp).Cancel != 0 && control & SL_INVOKE_ON_CANCEL != 0);
            let (routine, context) = ((*location).CompletionRoutine, (*location).Context);
            core::ptr::write_bytes(location, 0, 1);
            if let (true, Some(routine)) = (wanted, routine) {
                // The routine is told the device of the location above.
                let device = if (*irp).CurrentLocation == top {
                    core::ptr::null_mut()
                } else {
                    (*(*irp).CurrentStackLocation).DeviceObject
                };
                if routine(device, irp, context) == STATUS_MORE_PROCESSING_REQUIRED {
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

/// Final completion: hand results to the requestor and free the IRP.
/// Windows does this in the requesting thread; with one thread it is here.
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
            let failed = status as u32 >> 30 == 3;
            if flags & IRP_INPUT_OPERATION != 0 && !failed && !buffer.is_null() {
                let count = (*irp).IoStatus.Information;
                // The driver reports how much it wrote. A count larger
                // than the buffer it was given means it overran it.
                match pool::info(buffer) {
                    Some((size, _)) if count <= size => {}
                    _ => kd::bugcheck(format_args!(
                        "driver completed a buffered request with Information={count:#x}, larger than its buffer"
                    )),
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
        if !(*irp).UserEvent.is_null() {
            ke::event::set((*irp).UserEvent);
        }
        free(irp);
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
