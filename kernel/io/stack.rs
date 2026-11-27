//! Requests the kernel itself sends to a device stack and waits for:
//! what the Plug and Play manager asks of a device's drivers.
//!
//! [`send_synchronous`] is NK's own (Windows' counterpart is the
//! unexported `IopSynchronousCall`): no driver calls it.

use super::{device, irp};
use crate::ke::seh::Guard;
use crate::ke::{self, irql};
use crate::ob::object::ObRef;
use alloc::boxed::Box;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

/// Where a request's results go, and what is set when they are there.
/// Boxed: if the dispatch routine is unwound the request is still its
/// driver's, and what the request points to must stay.
struct Waiting {
    status_block: IO_STATUS_BLOCK,
    done: KEVENT,
}

/// Build a request of `major` and `minor` with `parameters`, send it to
/// the top of the stack `device` is in, and wait for it. Returns the
/// status the request completed with and its `IoStatus.Information`,
/// which for a query is often a pointer to what the driver allocated.
///
/// A Plug and Play or a power request starts out with the status
/// `STATUS_NOT_SUPPORTED`, as Windows requires of whoever sends one: a
/// driver that does not handle the request passes it on or completes
/// it unchanged, and that status coming back says nobody handled it.
/// Every other request starts out with zero.
///
/// The request is the kernel's, in the name of the calling thread, for
/// kernel mode, and has no file object. The top of the stack is found
/// and referenced once: the IRP has a location for each device of the
/// stack as it is then. A driver that returns other than
/// `STATUS_PENDING` without completing the request may still hold it:
/// the request, and the reference to the top of the stack, are left
/// to it, the breach is reported (`NK-VERIFY`), and the status the
/// driver returned is the answer.
///
/// # Safety
/// `device` is a live device object, and `parameters` names nothing
/// that goes away before the request has completed. The caller is at
/// `PASSIVE_LEVEL`.
pub unsafe fn send_synchronous(
    device: *mut DEVICE_OBJECT,
    major: u8,
    minor: u8,
    parameters: [u64; 4],
) -> (NTSTATUS, usize) {
    // SAFETY: the caller's contract is this routine's.
    unsafe { send_synchronous_from(device, major, minor, parameters, None) }
}

/// As [`send_synchronous`], with the request starting out at the
/// status and `IoStatus.Information` given in `start`: what Windows
/// does for the Plug and Play requests whose answer drivers build up
/// as the request travels (`IRP_MN_FILTER_RESOURCE_REQUIREMENTS`
/// starts out successful, holding the list to filter).
///
/// # Safety
/// As [`send_synchronous`].
pub unsafe fn send_synchronous_from(
    device: *mut DEVICE_OBJECT,
    major: u8,
    minor: u8,
    parameters: [u64; 4],
    start: Option<(NTSTATUS, usize)>,
) -> (NTSTATUS, usize) {
    irql::expect_passive("sending a request to a device stack and waiting for it");
    // SAFETY: per the contract. The reference keeps the top's memory;
    // the boxed block stays where it is until the request has been
    // seen to complete.
    unsafe {
        let held = ObRef::adopt(device::IoGetAttachedDeviceReference(device).cast());
        let top = held.cast::<DEVICE_OBJECT>();
        let request = irp::alloc((*top).StackSize);
        if request.is_null() {
            return (STATUS_INSUFFICIENT_RESOURCES, 0);
        }
        // An all-zero event is a valid value; it is initialised below.
        let mut waiting = Box::new(Waiting {
            status_block: IO_STATUS_BLOCK {
                Status: STATUS_PENDING,
                Information: 0,
            },
            done: core::mem::zeroed(),
        });
        ke::wait::KeInitializeEvent(&raw mut waiting.done, 0, 0);
        (*request).UserIosb = &raw mut waiting.status_block;
        (*request).UserEvent = &raw mut waiting.done;
        irp::requestor_keeps(request);
        (*request).RequestorMode = KERNEL_MODE;
        (*request).Thread = ke::pcr::current_thread().cast();
        if matches!(major, IRP_MJ_PNP | IRP_MJ_POWER) {
            (*request).IoStatus.Status = STATUS_NOT_SUPPORTED;
        }
        if let Some((status, information)) = start {
            (*request).IoStatus.Status = status;
            (*request).IoStatus.Information = information;
        }
        let location = irp::next_location(request);
        (*location).MajorFunction = major;
        (*location).MinorFunction = minor;
        (*location).Parameters = parameters;
        // Nothing is owed if the routine is unwound: the request and
        // what it points to are left as they are.
        let returned = irp::call_driver(top, request, &Guard::Nothing);
        if returned != STATUS_PENDING && ke::wait::KeReadStateEvent(&raw mut waiting.done) == 0 {
            crate::kd::verify(format_args!(
                "a driver returned {:#010x} for a request (major {major:#x}, minor {minor:#x}) \
                 it had not completed",
                returned as u32
            ));
            // The driver may still pass the request down or complete
            // it: the stack it names stays referenced, and the block
            // its completion writes stays where it is.
            Box::leak(waiting);
            held.into_raw();
            return (returned, 0);
        }
        ke::wait::wait(Some((&raw mut waiting.done).cast()), None);
        irp::free(request);
        let result = (&raw const waiting.status_block).read();
        (result.Status, result.Information)
    }
}
