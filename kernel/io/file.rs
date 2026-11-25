//! The requestor side of I/O: open a device by name, read, write, send
//! control codes, close. This is what system services such as
//! `NtCreateFile` and `NtDeviceIoControlFile` do on Windows, minus handles
//! and user mode; the kernel's self-tests are the only caller so far.
//!
//! Each call builds a real IRP and sends it to the driver's dispatch
//! routine. Buffers are passed the way the device or control code asks
//! for: buffered, direct, or neither.

use super::{TAG_FILE, TAG_IO_BUFFER, device, irp};
use crate::mm::pool;
use crate::{ke, ob};
use alloc::vec::Vec;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

/// What a request came back with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoResult {
    pub status: NTSTATUS,
    pub information: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoError {
    NoMemory,
    /// The driver returned without completing the request. Waiting for a
    /// pended request needs threads, which do not exist yet.
    NotCompleted {
        dispatch_status: NTSTATUS,
    },
    /// The dispatch routine returned a different status than it completed
    /// the request with, which the driver contract forbids.
    StatusMismatch {
        dispatch_status: NTSTATUS,
        completed: NTSTATUS,
    },
    /// The control code asks for a buffer method not implemented yet.
    UnsupportedMethod,
}

/// `IO_SECURITY_CONTEXT`, passed to create requests.
#[repr(C)]
struct SecurityContext {
    security_qos: PVOID,
    access_state: PVOID,
    desired_access: u32,
    full_create_options: u32,
}

/// `FILE_GENERIC_READ | FILE_GENERIC_WRITE`
const GENERIC_READ_WRITE: u32 = 0x0012_019F;
/// `FILE_OPEN` disposition with `FILE_NON_DIRECTORY_FILE |
/// FILE_SYNCHRONOUS_IO_NONALERT`, as `Parameters.Create.Options` packs them.
const CREATE_OPTIONS: u32 = 1 << 24 | 0x40 | 0x20;

/// Fill in the common requestor fields and send the IRP. Consumes it.
///
/// # Safety
/// `irp` must be a fresh IRP whose next stack location is set up for
/// `file`'s device.
unsafe fn submit(file: *mut FILE_OBJECT, irp: *mut IRP) -> Result<IoResult, IoError> {
    let mut iosb = IO_STATUS_BLOCK {
        Status: STATUS_PENDING,
        Information: 0,
    };
    let mut event = ke::event::new_notification();
    // SAFETY: per the contract; `iosb` and `event` outlive the request
    // because completion is synchronous or reported as an error.
    unsafe {
        (*irp).UserIosb = &raw mut iosb;
        (*irp).UserEvent = &raw mut event;
        (*irp).RequestorMode = KERNEL_MODE;
        (*irp).Thread = ke::pcr::current_thread().cast();
        (*irp).OriginalFileObject = file;
        (*irp::next_location(irp)).FileObject = file;
        let dispatch_status = irp::call_driver((*file).DeviceObject, irp);
        if !ke::event::is_signaled(&raw const event) {
            // The driver still owns the IRP, which points at our stack.
            // Nothing can complete it later without threads; say so.
            return Err(IoError::NotCompleted { dispatch_status });
        }
        if dispatch_status != iosb.Status {
            return Err(IoError::StatusMismatch {
                dispatch_status,
                completed: iosb.Status,
            });
        }
    }
    Ok(IoResult {
        status: iosb.Status,
        information: iosb.Information,
    })
}

/// A new IRP for `file`'s device with its next location's function set.
///
/// # Safety
/// `file` must be a live file object.
unsafe fn request(
    file: *mut FILE_OBJECT,
    major: u8,
    parameters: [u64; 4],
) -> Result<*mut IRP, IoError> {
    // SAFETY: per the contract.
    unsafe {
        let irp = irp::alloc((*(*file).DeviceObject).StackSize);
        if irp.is_null() {
            return Err(IoError::NoMemory);
        }
        let location = irp::next_location(irp);
        (*location).MajorFunction = major;
        (*location).Parameters = parameters;
        Ok(irp)
    }
}

/// Open the device called `name` (for example `\Device\Null`, or a
/// symbolic link to one). Returns the file object or the failure status.
pub fn open(name: &str) -> Result<*mut FILE_OBJECT, NTSTATUS> {
    let wide: Vec<u16> = name.encode_utf16().collect();
    let device = ob::lookup_device(&wide).ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let file = pool::alloc_zeroed(size_of::<FILE_OBJECT>(), TAG_FILE).cast::<FILE_OBJECT>();
    if file.is_null() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    let mut security = SecurityContext {
        security_qos: core::ptr::null_mut(),
        access_state: core::ptr::null_mut(),
        desired_access: GENERIC_READ_WRITE,
        full_create_options: CREATE_OPTIONS & 0xFF_FFFF,
    };
    // SAFETY: `device` came from the namespace, so it is live; `file` is a
    // fresh zeroed block of the right size.
    let result = unsafe {
        if (*device).Flags & DO_DEVICE_INITIALIZING != 0 {
            let _ = pool::free(file.cast());
            return Err(STATUS_NO_SUCH_DEVICE);
        }
        (*file).Type = IO_TYPE_FILE;
        (*file).Size = size_of::<FILE_OBJECT>() as i16;
        (*file).DeviceObject = device;
        (*file).Flags = FO_SYNCHRONOUS_IO;
        ke::event::init(&raw mut (*file).Lock, EVENT_SYNCHRONIZATION, false);
        ke::event::init(&raw mut (*file).Event, EVENT_NOTIFICATION, false);
        (*file).IrpList.Flink = &raw mut (*file).IrpList;
        (*file).IrpList.Blink = &raw mut (*file).IrpList;
        device::reference(device);
        let parameters = [&raw mut security as u64, u64::from(CREATE_OPTIONS), 0, 0];
        request(file, IRP_MJ_CREATE, parameters).and_then(|irp| submit(file, irp))
    };
    let status = match result {
        Ok(r) if nt_success(r.status) => return Ok(file),
        Ok(r) => r.status,
        Err(IoError::NoMemory) => STATUS_INSUFFICIENT_RESOURCES,
        Err(_) => STATUS_UNSUCCESSFUL,
    };
    // SAFETY: the create failed, so nothing else holds `file` or its
    // device reference.
    unsafe {
        device::dereference(device);
        let _ = pool::free(file.cast());
    }
    Err(status)
}

/// Close a file from `open`: a cleanup request (last handle gone), a close
/// request (last reference gone), then the file object is freed. Returns
/// the result of the close request.
///
/// # Safety
/// `file` must have come from `open` and not been closed.
pub unsafe fn close(file: *mut FILE_OBJECT) -> Result<IoResult, IoError> {
    // SAFETY: per the contract. A driver may legitimately not handle
    // cleanup, so its result is not the caller's concern.
    unsafe {
        let _ = request(file, IRP_MJ_CLEANUP, [0; 4]).and_then(|irp| submit(file, irp));
        let result = request(file, IRP_MJ_CLOSE, [0; 4]).and_then(|irp| submit(file, irp));
        let device = (*file).DeviceObject;
        (*file).Type = 0;
        let _ = pool::free(file.cast());
        device::dereference(device);
        result
    }
}

/// Read or write. `buffer` is filled by a read and sent by a write.
///
/// # Safety
/// `file` must be an open file; `buffer` must be valid for `len` bytes
/// (writable for a read).
unsafe fn transfer(
    file: *mut FILE_OBJECT,
    major: u8,
    buffer: *mut u8,
    len: usize,
) -> Result<IoResult, IoError> {
    // SAFETY: per the contract.
    unsafe {
        let irp = request(
            file,
            major,
            rw_parameters(len as u32, (*file).CurrentByteOffset),
        )?;
        let flags = (*(*file).DeviceObject).Flags;
        if flags & DO_BUFFERED_IO != 0 {
            if len != 0 {
                let system = pool::alloc(len, TAG_IO_BUFFER);
                if system.is_null() {
                    irp::free(irp);
                    return Err(IoError::NoMemory);
                }
                (*irp).SystemBuffer = system.cast();
                (*irp).Flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER;
                if major == IRP_MJ_READ {
                    (*irp).Flags |= IRP_INPUT_OPERATION;
                    (*irp).UserBuffer = buffer.cast();
                } else {
                    core::ptr::copy_nonoverlapping(buffer, system, len);
                }
            }
        } else if flags & DO_DIRECT_IO != 0 {
            irp::free(irp);
            return Err(IoError::UnsupportedMethod);
        } else {
            // Neither: the driver gets the caller's buffer as it is.
            (*irp).UserBuffer = buffer.cast();
        }
        submit(file, irp)
    }
}

/// Read up to `buffer.len()` bytes.
///
/// # Safety
/// `file` must be an open file.
pub unsafe fn read(file: *mut FILE_OBJECT, buffer: &mut [u8]) -> Result<IoResult, IoError> {
    // SAFETY: `buffer` is a valid writable slice; `file` per the contract.
    unsafe { transfer(file, IRP_MJ_READ, buffer.as_mut_ptr(), buffer.len()) }
}

/// Write `buffer`.
///
/// # Safety
/// `file` must be an open file.
pub unsafe fn write(file: *mut FILE_OBJECT, buffer: &[u8]) -> Result<IoResult, IoError> {
    // SAFETY: a write only reads the buffer; `file` per the contract.
    unsafe { transfer(file, IRP_MJ_WRITE, buffer.as_ptr().cast_mut(), buffer.len()) }
}

/// Send a device control request. The control code's low two bits say how
/// the buffers travel.
///
/// # Safety
/// `file` must be an open file.
pub unsafe fn device_control(
    file: *mut FILE_OBJECT,
    code: u32,
    input: &[u8],
    output: &mut [u8],
) -> Result<IoResult, IoError> {
    // SAFETY: per the contract; the slices are valid for their lengths.
    unsafe {
        let parameters = ioctl_parameters(output.len() as u32, input.len() as u32, code, 0);
        let irp = request(file, IRP_MJ_DEVICE_CONTROL, parameters)?;
        match code & 3 {
            METHOD_BUFFERED => {
                // One system buffer serves both directions: input is
                // copied in, and the driver's output is copied back out
                // of it on completion.
                let len = input.len().max(output.len());
                if len != 0 {
                    let system = pool::alloc(len, TAG_IO_BUFFER);
                    if system.is_null() {
                        irp::free(irp);
                        return Err(IoError::NoMemory);
                    }
                    core::ptr::copy_nonoverlapping(input.as_ptr(), system, input.len());
                    (*irp).SystemBuffer = system.cast();
                    (*irp).Flags = IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER;
                    if !output.is_empty() {
                        (*irp).Flags |= IRP_INPUT_OPERATION;
                        (*irp).UserBuffer = output.as_mut_ptr().cast();
                    }
                }
            }
            _ => {
                irp::free(irp);
                return Err(IoError::UnsupportedMethod);
            }
        }
        submit(file, irp)
    }
}
