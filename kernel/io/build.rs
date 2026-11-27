//! Requests a driver has the I/O manager build for it, to send to
//! another driver and wait for:
//! [`IoBuildSynchronousFsdRequest`], [`IoBuildDeviceIoControlRequest`],
//! and [`IoSynchronousCallDriver`], which sends any request and waits;
//! and [`IoBuildAsynchronousFsdRequest`], which the caller completes
//! itself.
//!
//! A built request is the I/O manager's unless a completion routine of
//! the caller's keeps it: when it has completed all the
//! way up, final completion hands the results to the caller's buffers
//! and status block, frees the IRP with its system buffer and its MDL,
//! and sets the caller's event (`irp::finish`). The caller never frees
//! it. Windows does that part in the thread that built the request, by
//! an APC; NK does it wherever the request was completed.
//!
//! The caller's buffers are kernel memory and are passed the way the
//! device or the control code asks for: copied through a system buffer,
//! described by an MDL with its pages locked, or handed over as they
//! are.

#![allow(non_snake_case)]

use super::{TAG_IO_BUFFER, irp, mdl};
use crate::ke::{self, seh::Guard};
use crate::mm::pool;
use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, Ordering};
use nk_ntabi::io::*;
use nk_ntabi::status::*;

/// A new IRP for `device`'s stack, in the name of the calling thread,
/// with the priority hint the pinned kernel gives a built request.
///
/// # Safety
/// `device` is a live device object.
unsafe fn new_request(device: *mut DEVICE_OBJECT) -> *mut IRP {
    // SAFETY: per the contract.
    unsafe {
        let request = irp::alloc((*device).StackSize);
        if !request.is_null() {
            (*request).Thread = ke::pcr::current_thread().cast();
            (*request).Flags = IRP_PRIORITY_HINT_NORMAL;
        }
        request
    }
}

/// Free a request that could not be built.
///
/// # Safety
/// `request` is a fresh IRP no driver has seen.
unsafe fn discard(request: *mut IRP) -> *mut IRP {
    // SAFETY: per the contract; what it has is the I/O manager's.
    unsafe {
        let system = (*request).SystemBuffer;
        if !system.is_null() {
            let _ = pool::free(system.cast());
        }
        mdl::release_chain(request);
        irp::free(request);
    }
    core::ptr::null_mut()
}

/// Give `request` a system buffer of `len` bytes holding the first
/// `copy` bytes of `from`. `false` without memory.
///
/// # Safety
/// `request` is a fresh IRP; `from` is readable for `copy` bytes, which
/// are no more than `len`.
unsafe fn buffered(request: *mut IRP, len: usize, from: *const u8, copy: usize) -> bool {
    let system = pool::alloc(len, TAG_IO_BUFFER);
    if system.is_null() {
        return false;
    }
    // SAFETY: per the contract; the block has room.
    unsafe {
        core::ptr::copy_nonoverlapping(from, system, copy);
        (*request).SystemBuffer = system.cast();
    }
    true
}

/// Describe `len` bytes at `buffer` by an MDL of `request`'s and lock
/// the pages for `operation`. `false` without memory, or if the buffer
/// is not all there: Windows catches the exception the probe raises.
///
/// # Safety
/// `request` is a fresh IRP.
unsafe fn direct(request: *mut IRP, buffer: *mut c_void, len: u32, operation: u32) -> bool {
    // SAFETY: per the contract; the MDL is the request's from here.
    unsafe {
        let described = mdl::IoAllocateMdl(buffer, len, 0, 0, request);
        !described.is_null() && mdl::probe_and_lock(described, KERNEL_MODE, operation).is_ok()
    }
}

/// A read, write, flush, shutdown, power or Plug and Play request of
/// `major` for `device`'s stack, with its buffer set up: what the two
/// FSD builders share. Null without memory, or if a direct-I/O device's
/// buffer cannot be locked.
///
/// As in the pinned kernel, a flush, a shutdown, a power and a Plug and
/// Play request get no buffer; every other gets `buffer` the way the
/// device asks for (`DO_BUFFERED_IO`, `DO_DIRECT_IO`, neither), `length`
/// as its transfer length and, if `starting_offset` is given, what it
/// points to as its byte offset.
///
/// # Safety
/// `device` is a live device object; `buffer` is kernel memory valid
/// for `length` bytes until the request completes, as is
/// `status_block`; `starting_offset` is null or readable.
unsafe fn fsd_request(
    major: u32,
    device: *mut DEVICE_OBJECT,
    buffer: *mut c_void,
    length: u32,
    starting_offset: *const i64,
    status_block: *mut IO_STATUS_BLOCK,
) -> *mut IRP {
    // SAFETY: per the contract.
    unsafe {
        let request = new_request(device);
        if request.is_null() {
            return request;
        }
        let location = irp::next_location(request);
        (*location).MajorFunction = major as u8;
        if !fsd_request_has_no_buffer(major) {
            let write = major == u32::from(IRP_MJ_WRITE);
            let flags = (*device).Flags;
            let built = if flags & DO_BUFFERED_IO != 0 {
                let copy = if write { length as usize } else { 0 };
                (*request).Flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER;
                if !write {
                    // Results are copied back to the caller's buffer.
                    (*request).Flags |= IRP_INPUT_OPERATION;
                    (*request).UserBuffer = buffer;
                    irp::set_requestor_room(request, length as usize);
                }
                length == 0 || buffered(request, length as usize, buffer.cast(), copy)
            } else if flags & DO_DIRECT_IO != 0 {
                // A read writes the pages; anything else reads them.
                let operation = if major == u32::from(IRP_MJ_READ) {
                    IO_WRITE_ACCESS
                } else {
                    IO_READ_ACCESS
                };
                direct(request, buffer, length, operation)
            } else {
                (*request).UserBuffer = buffer;
                true
            };
            if !built {
                return discard(request);
            }
            // `Parameters.Read` and `Parameters.Write` are laid out
            // alike.
            let offset = if starting_offset.is_null() {
                0
            } else {
                starting_offset.read_unaligned()
            };
            (*location).Parameters = rw_parameters(length, offset);
        }
        (*request).UserIosb = status_block;
        request
    }
}

/// [`IoBuildSynchronousFsdRequest`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iobuildsynchronousfsdrequest):
/// a request of `major` for `device`'s stack ([`fsd_request`]), which
/// the caller sends with `IoCallDriver` and waits for on `event`.
///
/// # Safety
/// As [`fsd_request`]; `event` is valid until the request completes.
pub unsafe extern "C" fn IoBuildSynchronousFsdRequest(
    major: u32,
    device: *mut DEVICE_OBJECT,
    buffer: *mut c_void,
    length: u32,
    starting_offset: *const i64,
    event: *mut KEVENT,
    status_block: *mut IO_STATUS_BLOCK,
) -> *mut IRP {
    // SAFETY: per the contract.
    unsafe {
        let request = fsd_request(major, device, buffer, length, starting_offset, status_block);
        if !request.is_null() {
            (*request).UserEvent = event;
        }
        request
    }
}

/// [`IoBuildAsynchronousFsdRequest`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iobuildasynchronousfsdrequest):
/// [`IoBuildSynchronousFsdRequest`] with no event. A caller whose
/// completion routine keeps the request (`STATUS_MORE_PROCESSING_REQUIRED`)
/// frees it, unlocking and freeing its MDL first, as `partmgr.sys` does
/// after each sector it reads; one that lets it complete has final
/// completion free it.
///
/// # Safety
/// As [`fsd_request`].
pub unsafe extern "C" fn IoBuildAsynchronousFsdRequest(
    major: u32,
    device: *mut DEVICE_OBJECT,
    buffer: *mut c_void,
    length: u32,
    starting_offset: *const i64,
    status_block: *mut IO_STATUS_BLOCK,
) -> *mut IRP {
    // SAFETY: per the contract.
    unsafe { fsd_request(major, device, buffer, length, starting_offset, status_block) }
}

/// [`IoBuildDeviceIoControlRequest`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iobuilddeviceiocontrolrequest):
/// a device control request, or an internal one, for `device`'s stack,
/// with its buffers set up as the control code's method asks, as
/// Microsoft documents them. Null without memory, or if a direct
/// method's buffer cannot be locked.
///
/// # Safety
/// `device` is a live device object; the buffers are kernel memory
/// valid for their lengths until the request completes, as are `event`
/// and `status_block`.
pub unsafe extern "C" fn IoBuildDeviceIoControlRequest(
    code: u32,
    device: *mut DEVICE_OBJECT,
    input: *mut c_void,
    input_len: u32,
    output: *mut c_void,
    output_len: u32,
    internal: u8,
    event: *mut KEVENT,
    status_block: *mut IO_STATUS_BLOCK,
) -> *mut IRP {
    // SAFETY: per the contract.
    unsafe {
        let request = new_request(device);
        if request.is_null() {
            return request;
        }
        let location = irp::next_location(request);
        (*location).MajorFunction = if internal != 0 {
            IRP_MJ_INTERNAL_DEVICE_CONTROL
        } else {
            IRP_MJ_DEVICE_CONTROL
        };
        (*location).Parameters = ioctl_parameters(output_len, input_len, code, 0);
        let copied = if input.is_null() {
            0
        } else {
            input_len as usize
        };
        let built = match code & 3 {
            METHOD_BUFFERED => {
                if input_len == 0 && output_len == 0 {
                    true
                } else {
                    // One system buffer serves both directions.
                    (*request).Flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER;
                    (*request).UserBuffer = output;
                    if !output.is_null() {
                        (*request).Flags |= IRP_INPUT_OPERATION;
                        irp::set_requestor_room(request, output_len as usize);
                    }
                    let len = input_len.max(output_len) as usize;
                    buffered(request, len, input.cast(), copied)
                }
            }
            method @ (METHOD_IN_DIRECT | METHOD_OUT_DIRECT) => {
                let operation = if method == METHOD_IN_DIRECT {
                    IO_READ_ACCESS
                } else {
                    IO_WRITE_ACCESS
                };
                let input_ready = input.is_null() || {
                    (*request).Flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER;
                    input_len == 0 || buffered(request, copied, input.cast(), copied)
                };
                input_ready && (output.is_null() || direct(request, output, output_len, operation))
            }
            _ => {
                // METHOD_NEITHER: both addresses as they are.
                (*request).UserBuffer = output;
                (*location).Parameters[3] = input.addr() as u64;
                true
            }
        };
        if !built {
            return discard(request);
        }
        (*request).UserIosb = status_block;
        (*request).UserEvent = event;
        request
    }
}

/// The completion routine of [`IoSynchronousCallDriver`]: tell the
/// sender, and keep the request for it.
///
/// # Safety
/// Called as a completion routine whose context is the sender's event.
unsafe extern "C" fn sent(_: *mut DEVICE_OBJECT, _: *mut IRP, event: *mut c_void) -> NTSTATUS {
    // SAFETY: per the contract; the sender waits for the event before
    // it lets go of it.
    unsafe { ke::wait::KeSetEvent(event.cast(), 0, 0) };
    STATUS_MORE_PROCESSING_REQUIRED
}

/// [`IoSynchronousCallDriver`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iosynchronouscalldriver):
/// send `request` to `device` and wait until the drivers below are done
/// with it. The request comes back to the caller uncompleted, as from a
/// completion routine that answers `STATUS_MORE_PROCESSING_REQUIRED`:
/// it is the caller's to complete or free. Returns the status the
/// request was completed with if it was pended, and what the dispatch
/// routine returned if not, as the pinned kernel does.
///
/// # Safety
/// As `IoCallDriver`; the caller has set no completion routine in the
/// next stack location, and is at an IRQL where it may wait.
pub unsafe extern "C" fn IoSynchronousCallDriver(
    device: *mut DEVICE_OBJECT,
    request: *mut IRP,
) -> NTSTATUS {
    // SAFETY: per the contract. An all-zero event is a valid value; it
    // is initialised just below and outlives the request's way down
    // and back, which is waited for here.
    unsafe {
        let mut done: KEVENT = core::mem::zeroed();
        let done = &raw mut done;
        ke::wait::KeInitializeEvent(done, 0, 0);
        let location = irp::next_location(request);
        (*location).CompletionRoutine = Some(sent);
        (*location).Context = done.cast();
        (*location).Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
        // An exception out of the dispatch routine passes through to
        // the caller's handlers: the request, and the event it points
        // to in this frame, are then the driver's that raised.
        let status = irp::call_driver(device, request, &Guard::Nothing);
        if status != STATUS_PENDING {
            return status;
        }
        ke::wait::wait(Some(done.cast()), None);
        (*request).IoStatus.Status
    }
}

/// [`IoSetMasterIrpStatus`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-iosetmasterirpstatus):
/// fold the status one part of a split request completed with into the
/// master request's (`nk_ntabi::io::master_irp_status`). Parts complete
/// on any processor: the status is replaced in one atomic step.
///
/// # Safety
/// `master` is a live IRP.
pub unsafe extern "C" fn IoSetMasterIrpStatus(master: *mut IRP, status: NTSTATUS) {
    // SAFETY: per the contract; the status word is only ever written
    // whole.
    let word = unsafe { AtomicI32::from_ptr(&raw mut (*master).IoStatus.Status) };
    let mut current = word.load(Ordering::Acquire);
    while let Some(new) = master_irp_status(current, status) {
        match word.compare_exchange_weak(current, new, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(seen) => current = seen,
        }
    }
}
