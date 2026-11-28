//! `ZwCreateFile` and `ZwOpenFile`: a driver opens a name. The open
//! itself is the requestor's ([`file::open_as`]); here the driver's
//! arguments are read and its results written.
//!
//! Windows checks the parameters of a create only for a user-mode
//! caller, or when a kernel-mode caller asks for it
//! (`IO_CHECK_CREATE_PARAMETERS` of `IoCreateFile`): a driver's share
//! access, disposition and options go to the device's driver as they
//! are, and so they do here.

#![allow(non_snake_case)]

use super::file::{self, Extra, Kind, OpenRequest};
use crate::ob::handle::OBJ_KERNEL_HANDLE;
use core::ffi::c_void;
use nk_ntabi::io::*;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::*;

/// `OBJ_INHERIT`, `OBJ_CASE_INSENSITIVE`, `OBJ_FORCE_ACCESS_CHECK`
/// and `OBJ_VALID_ATTRIBUTES` (`wdm.h`).
const OBJ_INHERIT: u32 = 0x2;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const OBJ_FORCE_ACCESS_CHECK: u32 = 0x400;

/// [`ZwCreateFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ntcreatefile):
/// open or create what the object attributes name, for kernel mode,
/// and give a handle to it. The name is looked up in the object
/// namespace, from its root or from the attributes' root directory (a
/// directory object, or an open file whose device parses the name);
/// what the namespace says about a name that leads nowhere is the
/// status. The handle is the kernel handle with `OBJ_KERNEL_HANDLE`
/// and the System process's own without. The handle and the status
/// block are written when the create succeeds, and only then, as on
/// Windows.
///
/// The gaps the ledger's "partial" stands for: an extended-attribute
/// buffer is refused with `STATUS_EAS_NOT_SUPPORTED`, and a security
/// quality of service in the attributes with
/// `STATUS_NOT_IMPLEMENTED`. A security descriptor in the attributes
/// is not looked at: nothing checks access to an object, and no
/// driver NK runs stores one. Names compare case-insensitively
/// whatever the attributes say, which is Windows' default too; the
/// device's driver is told which was asked for (`SL_CASE_SENSITIVE`).
///
/// # Safety
/// `file_handle` and `io_status_block` are writable;
/// `object_attributes` is null or points to an `OBJECT_ATTRIBUTES`
/// whose name is null or a counted string; `allocation_size` is null
/// or points to a size.
pub unsafe extern "C" fn NtCreateFile(
    file_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    allocation_size: *const i64,
    file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    ea_buffer: *const c_void,
    ea_length: u32,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract; captured fault-safely when `UserMode`.
    let Some(oa) =
        (match unsafe { crate::svc::capture::capture_object_attributes(object_attributes, mode) } {
            Ok(oa) => oa,
            Err(status) => return status,
        })
    else {
        return STATUS_INVALID_PARAMETER;
    };
    let allocation_size = if allocation_size.is_null() {
        0
    } else {
        // SAFETY: per the contract; captured fault-safely when `UserMode`.
        match unsafe { crate::svc::capture::read(allocation_size, mode) } {
            Ok(v) => v,
            Err(status) => return status,
        }
    };
    if !ea_buffer.is_null() && ea_length != 0 {
        return STATUS_EAS_NOT_SUPPORTED;
    }
    if oa.qos.is_some() {
        return STATUS_NOT_IMPLEMENTED;
    }
    let root = oa.root;
    let name = oa.name.unwrap_or_default();
    let attributes = oa.attributes;
    let mut location_flags = 0;
    if attributes & OBJ_CASE_INSENSITIVE == 0 {
        location_flags |= SL_CASE_SENSITIVE;
    }
    if attributes & OBJ_FORCE_ACCESS_CHECK != 0 {
        location_flags |= SL_FORCE_ACCESS_CHECK;
    }
    let request = OpenRequest {
        name: "",
        root: (!root.is_null()).then_some(root as u64),
        desired_access,
        share_access,
        create_options,
        disposition: create_disposition,
        kind: Kind::File,
        requestor_mode: mode,
    };
    let extra = Extra {
        file_attributes: file_attributes as u16,
        allocation_size,
        location_flags,
        inherit: attributes & OBJ_INHERIT != 0,
        process_handle: attributes & OBJ_KERNEL_HANDLE == 0,
    };
    match file::open_as(&request, &name, &extra) {
        Ok((handle, result)) => {
            let iosb = IO_STATUS_BLOCK {
                Status: result.status,
                Information: result.information,
            };
            // SAFETY: per the contract; written fault-safely when `UserMode`.
            let write = unsafe {
                crate::svc::capture::write(file_handle, handle as *mut c_void, mode)
                    .and_then(|()| crate::svc::capture::write(io_status_block, iosb, mode))
            };
            if let Err(status) = write {
                let _ = crate::ob::handle::close(handle);
                return status;
            }
            result.status
        }
        Err(status) => status,
    }
}

/// [`ZwOpenFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenfile):
/// [`ZwCreateFile`] for what exists already (`FILE_OPEN`), with no
/// attributes, allocation size or extended attributes, as Windows'
/// own routine calls the common one.
///
/// # Safety
/// As [`ZwCreateFile`].
pub unsafe extern "C" fn NtOpenFile(
    file_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    io_status_block: *mut IO_STATUS_BLOCK,
    share_access: u32,
    open_options: u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        NtCreateFile(
            file_handle,
            desired_access,
            object_attributes,
            io_status_block,
            core::ptr::null(),
            0,
            share_access,
            FILE_OPEN,
            open_options,
            core::ptr::null(),
            0,
        )
    }
}

/// [`NtReadFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwreadfile):
/// read up to `length` bytes from `file_handle` at `byte_offset` (or the
/// file's current byte offset if null).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn NtReadFile(
    file_handle: *mut c_void,
    event: *mut c_void,
    _apc_routine: *const c_void,
    _apc_context: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    buffer: *mut u8,
    length: u32,
    byte_offset: *const i64,
    _key: *const u32,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    let len = length as usize;
    let off = if byte_offset.is_null() {
        None
    } else {
        // SAFETY: per the contract.
        match unsafe { crate::svc::capture::read(byte_offset, mode) } {
            Ok(v) if v < 0 => None,
            Ok(v) => Some(v),
            Err(st) => return st,
        }
    };
    let mut kbuf = alloc::vec![0u8; len];
    let h = file_handle as u64;
    let res = match off {
        Some(pos) => file::read_at(h, pos, &mut kbuf),
        None => file::read(h, &mut kbuf),
    };
    match res {
        Ok(r) => {
            let n = r.information.min(len);
            if n > 0 {
                // SAFETY: per the contract; `copy_to_caller` probes user pointers.
                let cp = unsafe { crate::svc::capture::copy_to_caller(buffer, &kbuf[..n], mode) };
                if let Err(st) = cp {
                    return st;
                }
            }
            let iosb = IO_STATUS_BLOCK {
                Status: r.status,
                Information: r.information,
            };
            // SAFETY: per the contract.
            if let Err(st) = unsafe { crate::svc::capture::write(io_status_block, iosb, mode) } {
                return st;
            }
            if !event.is_null() {
                // SAFETY: caller supplied an event handle to signal on completion.
                let _ = unsafe { crate::ob::event::NtSetEvent(event, core::ptr::null_mut()) };
            }
            r.status
        }
        Err(e) => match e {
            file::IoError::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
            file::IoError::Handle(s) | file::IoError::Refused(s) => s,
            file::IoError::NotCompleted { dispatch_status: s }
            | file::IoError::StatusMismatch {
                dispatch_status: s, ..
            } => s,
        },
    }
}

/// `NtQueryAttributesFile`: query `FILE_BASIC_INFORMATION` (40 bytes) for the
/// file named by `object_attributes`.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQueryAttributesFile(
    object_attributes: *const OBJECT_ATTRIBUTES,
    file_information: *mut u8,
) -> NTSTATUS {
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract.
    let Some(oa) =
        (match unsafe { crate::svc::capture::capture_object_attributes(object_attributes, mode) } {
            Ok(oa) => oa,
            Err(st) => return st,
        })
    else {
        return STATUS_INVALID_PARAMETER;
    };
    let name = oa.name.unwrap_or_default();
    let req = OpenRequest {
        name: "",
        root: (!oa.root.is_null()).then_some(oa.root as u64),
        desired_access: FILE_READ_ATTRIBUTES,
        share_access: 0x7,
        create_options: FILE_SYNCHRONOUS_IO_NONALERT,
        disposition: FILE_OPEN,
        kind: Kind::File,
        requestor_mode: mode,
    };
    let extra = Extra {
        file_attributes: 0,
        allocation_size: 0,
        location_flags: if oa.attributes & OBJ_CASE_INSENSITIVE == 0 {
            SL_CASE_SENSITIVE
        } else {
            0
        },
        inherit: false,
        process_handle: false,
    };
    let (h, _) = match file::open_as(&req, &name, &extra) {
        Ok(res) => res,
        Err(st) => return st,
    };
    let mut basic = [0u8; 40];
    let q = file::query_information(h, 4, &mut basic);
    file::close(h);
    match q {
        Ok(r) if nt_success(r.status) => {
            // SAFETY: per the contract.
            match unsafe { crate::svc::capture::copy_to_caller(file_information, &basic, mode) } {
                Ok(()) => STATUS_SUCCESS,
                Err(st) => st,
            }
        }
        Ok(r) => r.status,
        Err(e) => match e {
            file::IoError::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
            file::IoError::Handle(s) | file::IoError::Refused(s) => s,
            file::IoError::NotCompleted { dispatch_status: s }
            | file::IoError::StatusMismatch {
                dispatch_status: s, ..
            } => s,
        },
    }
}

/// [`NtWriteFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwwritefile):
/// write `length` bytes from `buffer` to `file_handle` at `byte_offset` (or
/// the file's current byte offset if null).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn NtWriteFile(
    file_handle: *mut c_void,
    event: *mut c_void,
    _apc_routine: *const c_void,
    _apc_context: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    buffer: *const u8,
    length: u32,
    byte_offset: *const i64,
    _key: *const u32,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    let len = length as usize;
    let mut kbuf = alloc::vec![0u8; len];
    if len > 0 {
        // SAFETY: per the contract; `copy_from_caller` probes user pointers.
        if let Err(st) = unsafe { crate::svc::capture::copy_from_caller(&mut kbuf, buffer, mode) } {
            return st;
        }
    }
    let off = if byte_offset.is_null() {
        None
    } else {
        // SAFETY: per the contract.
        match unsafe { crate::svc::capture::read(byte_offset, mode) } {
            Ok(v) if v < 0 => None,
            Ok(v) => Some(v),
            Err(st) => return st,
        }
    };
    let h = file_handle as u64;
    let res = match off {
        Some(pos) => file::write_at(h, pos, &kbuf),
        None => file::write(h, &kbuf),
    };
    match res {
        Ok(r) => {
            let iosb = IO_STATUS_BLOCK {
                Status: r.status,
                Information: r.information,
            };
            // SAFETY: per the contract.
            if let Err(st) = unsafe { crate::svc::capture::write(io_status_block, iosb, mode) } {
                return st;
            }
            if !event.is_null() {
                // SAFETY: caller supplied an event handle to signal on completion.
                let _ = unsafe { crate::ob::event::NtSetEvent(event, core::ptr::null_mut()) };
            }
            r.status
        }
        Err(e) => match e {
            file::IoError::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
            file::IoError::Handle(s) | file::IoError::Refused(s) => s,
            file::IoError::NotCompleted { dispatch_status: s }
            | file::IoError::StatusMismatch {
                dispatch_status: s, ..
            } => s,
        },
    }
}

pub use crate::svc::zw::{ZwCreateFile, ZwOpenFile};
