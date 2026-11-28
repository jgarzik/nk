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

/// [`NtQueryVolumeInformationFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntqueryvolumeinformationfile).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQueryVolumeInformationFile(
    file_handle: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    fs_information: *mut u8,
    length: u32,
    fs_information_class: u32,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    let len = length as usize;
    let mut kbuf = alloc::vec![0u8; len];
    match file::query_volume_information(file_handle as u64, fs_information_class, &mut kbuf) {
        Ok(r) => {
            let n = r.information.min(len);
            if n > 0 {
                // SAFETY: per the contract; `copy_to_caller` probes user pointers.
                let cp = unsafe {
                    crate::svc::capture::copy_to_caller(fs_information, &kbuf[..n], mode)
                };
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

fn io_error_to_status(e: file::IoError) -> NTSTATUS {
    match e {
        file::IoError::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
        file::IoError::Handle(s) | file::IoError::Refused(s) => s,
        file::IoError::NotCompleted { dispatch_status: s }
        | file::IoError::StatusMismatch {
            dispatch_status: s, ..
        } => s,
    }
}

/// Common implementation of `NtDeviceIoControlFile` and `NtFsControlFile`.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
#[allow(clippy::too_many_arguments)]
unsafe fn nt_control_file(
    is_fsctl: bool,
    file_handle: *mut c_void,
    event: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    control_code: u32,
    input_buffer: *const u8,
    input_buffer_length: u32,
    output_buffer: *mut u8,
    output_buffer_length: u32,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    let in_len = if input_buffer.is_null() {
        0
    } else {
        input_buffer_length as usize
    };
    let out_len = if output_buffer.is_null() {
        0
    } else {
        output_buffer_length as usize
    };
    let mut kin = alloc::vec![0u8; in_len];
    if in_len > 0 {
        // SAFETY: per the contract; `copy_from_caller` probes user pointers.
        let cp = unsafe { crate::svc::capture::copy_from_caller(&mut kin, input_buffer, mode) };
        if let Err(st) = cp {
            return st;
        }
    }
    let mut kout = alloc::vec![0u8; out_len];
    let res = if is_fsctl {
        file::fs_control(file_handle as u64, control_code, &kin, &mut kout)
    } else {
        file::device_control(file_handle as u64, control_code, &kin, &mut kout)
    };
    match res {
        Ok(r) => {
            let n = r.information.min(out_len);
            if n > 0 {
                // SAFETY: per the contract; `copy_to_caller` probes user pointers.
                let cp =
                    unsafe { crate::svc::capture::copy_to_caller(output_buffer, &kout[..n], mode) };
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
        Err(e) => io_error_to_status(e),
    }
}

/// [`NtDeviceIoControlFile`](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntdeviceiocontrolfile).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn NtDeviceIoControlFile(
    file_handle: *mut c_void,
    event: *mut c_void,
    _apc_routine: *const c_void,
    _apc_context: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    io_control_code: u32,
    input_buffer: *const u8,
    input_buffer_length: u32,
    output_buffer: *mut u8,
    output_buffer_length: u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        nt_control_file(
            false,
            file_handle,
            event,
            io_status_block,
            io_control_code,
            input_buffer,
            input_buffer_length,
            output_buffer,
            output_buffer_length,
        )
    }
}

/// [`NtFsControlFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntfscontrolfile).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn NtFsControlFile(
    file_handle: *mut c_void,
    event: *mut c_void,
    _apc_routine: *const c_void,
    _apc_context: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    fs_control_code: u32,
    input_buffer: *const u8,
    input_buffer_length: u32,
    output_buffer: *mut u8,
    output_buffer_length: u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        nt_control_file(
            true,
            file_handle,
            event,
            io_status_block,
            fs_control_code,
            input_buffer,
            input_buffer_length,
            output_buffer,
            output_buffer_length,
        )
    }
}

/// [`NtQueryInformationFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwqueryinformationfile).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQueryInformationFile(
    file_handle: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *mut u8,
    length: u32,
    file_information_class: u32,
) -> NTSTATUS {
    const FILE_ACCESS_INFORMATION: u32 = 8;
    const FILE_POSITION_INFORMATION: u32 = 14;
    const FILE_MODE_INFORMATION: u32 = 16;
    const FILE_ALIGNMENT_INFORMATION: u32 = 17;

    let mode = crate::svc::capture::mode();
    let len = length as usize;

    // Classes answered directly by the I/O manager from `FILE_OBJECT` / handle
    // table (Windows `NtQueryInformationFile` handles these without an IRP).
    if matches!(
        file_information_class,
        FILE_ACCESS_INFORMATION
            | FILE_POSITION_INFORMATION
            | FILE_MODE_INFORMATION
            | FILE_ALIGNMENT_INFORMATION
    ) {
        let (held, info) = match crate::ob::handle::reference_for(
            file_handle as u64,
            Some(&raw const crate::ob::object::FILE_TYPE),
            0,
            crate::svc::capture::handle_mode(mode),
        ) {
            Ok(found) => found,
            Err(st) => return st,
        };
        let fo = held.body().cast::<nk_ntabi::io::FILE_OBJECT>();
        let mut small = [0u8; 8];
        let needed: usize = match file_information_class {
            FILE_ACCESS_INFORMATION => {
                small[..4].copy_from_slice(&info.granted.to_le_bytes());
                4
            }
            FILE_POSITION_INFORMATION => {
                // SAFETY: `held` keeps `FILE_OBJECT` alive.
                let pos = unsafe { (*fo).CurrentByteOffset };
                small[..8].copy_from_slice(&pos.to_le_bytes());
                8
            }
            FILE_MODE_INFORMATION => {
                const FO_WRITE_THROUGH: u32 = 0x0000_0004;
                const FO_NO_INTERMEDIATE_BUFFERING: u32 = 0x0000_0008;
                const FO_SEQUENTIAL_ONLY: u32 = 0x0000_0020;
                // SAFETY: `held` keeps `FILE_OBJECT` alive.
                let flags = unsafe { (*fo).Flags };
                let mut fmode = 0u32;
                if (flags & FO_WRITE_THROUGH) != 0 {
                    fmode |= 0x02;
                }
                if (flags & FO_SEQUENTIAL_ONLY) != 0 {
                    fmode |= 0x04;
                }
                if (flags & FO_NO_INTERMEDIATE_BUFFERING) != 0 {
                    fmode |= 0x08;
                }
                if (flags & nk_ntabi::io::FO_SYNCHRONOUS_IO) != 0 {
                    fmode |= if (flags & nk_ntabi::io::FO_ALERTABLE_IO) != 0 {
                        0x10
                    } else {
                        0x20
                    };
                }
                small[..4].copy_from_slice(&fmode.to_le_bytes());
                4
            }
            FILE_ALIGNMENT_INFORMATION => {
                // SAFETY: `held` keeps `FILE_OBJECT` and its `DeviceObject` alive.
                let align = unsafe {
                    let dev = (*fo).DeviceObject;
                    if dev.is_null() {
                        0u32
                    } else {
                        (*dev).AlignmentRequirement
                    }
                };
                small[..4].copy_from_slice(&align.to_le_bytes());
                4
            }
            _ => unreachable!(),
        };
        if len < needed {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        // SAFETY: per the contract; `copy_to_caller` probes user pointers.
        let cp = unsafe {
            crate::svc::capture::copy_to_caller(file_information, &small[..needed], mode)
        };
        if let Err(st) = cp {
            return st;
        }
        let iosb = IO_STATUS_BLOCK {
            Status: STATUS_SUCCESS,
            Information: needed,
        };
        // SAFETY: per the contract.
        if let Err(st) = unsafe { crate::svc::capture::write(io_status_block, iosb, mode) } {
            return st;
        }
        return STATUS_SUCCESS;
    }

    let mut kbuf = alloc::vec![0u8; len];
    match file::query_information(file_handle as u64, file_information_class, &mut kbuf) {
        Ok(r) => {
            let n = r.information.min(len);
            if n > 0 {
                // SAFETY: per the contract; `copy_to_caller` probes user pointers.
                let cp = unsafe {
                    crate::svc::capture::copy_to_caller(file_information, &kbuf[..n], mode)
                };
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
            r.status
        }
        Err(e) => io_error_to_status(e),
    }
}

/// [`NtSetInformationFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwsetinformationfile).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtSetInformationFile(
    file_handle: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *const u8,
    length: u32,
    file_information_class: u32,
) -> NTSTATUS {
    const FILE_POSITION_INFORMATION: u32 = 14;
    const FILE_MODE_INFORMATION: u32 = 16;

    let mode = crate::svc::capture::mode();
    let len = length as usize;
    let mut kbuf = alloc::vec![0u8; len];
    if len > 0 {
        // SAFETY: per the contract; `copy_from_caller` probes user pointers.
        let cp =
            unsafe { crate::svc::capture::copy_from_caller(&mut kbuf, file_information, mode) };
        if let Err(st) = cp {
            return st;
        }
    }
    if file_information_class == FILE_POSITION_INFORMATION
        || file_information_class == FILE_MODE_INFORMATION
    {
        let (held, _) = match crate::ob::handle::reference_for(
            file_handle as u64,
            Some(&raw const crate::ob::object::FILE_TYPE),
            0,
            crate::svc::capture::handle_mode(mode),
        ) {
            Ok(found) => found,
            Err(st) => return st,
        };
        let fo = held.body().cast::<nk_ntabi::io::FILE_OBJECT>();
        if file_information_class == FILE_POSITION_INFORMATION {
            if len < 8 {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            let pos = i64::from_le_bytes(kbuf[..8].try_into().unwrap_or([0; 8]));
            if pos < 0 {
                return STATUS_INVALID_PARAMETER;
            }
            // SAFETY: `held` keeps `FILE_OBJECT` alive.
            unsafe { (*fo).CurrentByteOffset = pos };
        } else if len < 4 {
            return STATUS_INFO_LENGTH_MISMATCH;
        }
        let iosb = IO_STATUS_BLOCK {
            Status: STATUS_SUCCESS,
            Information: 0,
        };
        // SAFETY: per the contract.
        if let Err(st) = unsafe { crate::svc::capture::write(io_status_block, iosb, mode) } {
            return st;
        }
        return STATUS_SUCCESS;
    }
    match file::set_information(file_handle as u64, file_information_class, &kbuf) {
        Ok(r) => {
            let iosb = IO_STATUS_BLOCK {
                Status: r.status,
                Information: r.information,
            };
            // SAFETY: per the contract.
            if let Err(st) = unsafe { crate::svc::capture::write(io_status_block, iosb, mode) } {
                return st;
            }
            r.status
        }
        Err(e) => io_error_to_status(e),
    }
}

/// [`NtQueryDirectoryFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerydirectoryfile).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn NtQueryDirectoryFile(
    file_handle: *mut c_void,
    event: *mut c_void,
    _apc_routine: *const c_void,
    _apc_context: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *mut u8,
    length: u32,
    file_information_class: u32,
    return_single_entry: u8,
    file_name: *const UNICODE_STRING,
    restart_scan: u8,
) -> NTSTATUS {
    let mut flags = 0u8;
    if restart_scan != 0 {
        flags |= nk_ntabi::io::SL_RESTART_SCAN;
    }
    if return_single_entry != 0 {
        flags |= nk_ntabi::io::SL_RETURN_SINGLE_ENTRY;
    }
    // SAFETY: per the contract.
    unsafe {
        nt_query_directory_common(
            file_handle,
            event,
            io_status_block,
            file_information,
            length,
            file_information_class,
            flags,
            file_name,
        )
    }
}

/// [`NtQueryDirectoryFileEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerydirectoryfileex).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn NtQueryDirectoryFileEx(
    file_handle: *mut c_void,
    event: *mut c_void,
    _apc_routine: *const c_void,
    _apc_context: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *mut u8,
    length: u32,
    file_information_class: u32,
    query_flags: u32,
    file_name: *const UNICODE_STRING,
) -> NTSTATUS {
    // `SL_QUERY_DIRECTORY_MASK` maps `SL_RETURN_SINGLE_ENTRY (0x1)`, `SL_RESTART_SCAN (0x2)`,
    // `SL_INDEX_SPECIFIED (0x4)` into IRP stack flags.
    let mut flags = 0u8;
    if (query_flags & 0x1) != 0 {
        flags |= nk_ntabi::io::SL_RETURN_SINGLE_ENTRY;
    }
    if (query_flags & 0x2) != 0 {
        flags |= nk_ntabi::io::SL_RESTART_SCAN;
    }
    if (query_flags & 0x4) != 0 {
        flags |= nk_ntabi::io::SL_INDEX_SPECIFIED;
    }
    // SAFETY: per the contract.
    unsafe {
        nt_query_directory_common(
            file_handle,
            event,
            io_status_block,
            file_information,
            length,
            file_information_class,
            flags,
            file_name,
        )
    }
}

/// Shared implementation of `NtQueryDirectoryFile` / `NtQueryDirectoryFileEx`.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
#[allow(clippy::too_many_arguments)]
unsafe fn nt_query_directory_common(
    file_handle: *mut c_void,
    event: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
    file_information: *mut u8,
    length: u32,
    file_information_class: u32,
    flags: u8,
    file_name: *const UNICODE_STRING,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    let pattern = if file_name.is_null() {
        None
    } else {
        // SAFETY: per the contract.
        match unsafe { crate::svc::capture::capture_unicode_string(file_name, mode) } {
            Ok(w) => Some(w),
            Err(st) => return st,
        }
    };
    let len = length as usize;
    let mut kbuf = alloc::vec![0u8; len];
    match file::query_directory(
        file_handle as u64,
        file_information_class,
        pattern.as_deref(),
        flags,
        0,
        &mut kbuf,
    ) {
        Ok(r) => {
            let n = r.information.min(len);
            if n > 0 {
                // SAFETY: per the contract; `copy_to_caller` probes user pointers.
                let cp = unsafe {
                    crate::svc::capture::copy_to_caller(file_information, &kbuf[..n], mode)
                };
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
        Err(e) => io_error_to_status(e),
    }
}

/// [`NtFlushBuffersFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwflushbuffersfile).
///
/// # Safety
/// `io_status_block` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtFlushBuffersFile(
    file_handle: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    match file::flush(file_handle as u64) {
        Ok(r) => {
            let iosb = IO_STATUS_BLOCK {
                Status: r.status,
                Information: r.information,
            };
            // SAFETY: per the contract.
            if let Err(st) = unsafe { crate::svc::capture::write(io_status_block, iosb, mode) } {
                return st;
            }
            r.status
        }
        Err(e) => io_error_to_status(e),
    }
}

/// [`NtFlushBuffersFileEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntflushbuffersfileex).
///
/// # Safety
/// `io_status_block` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtFlushBuffersFileEx(
    file_handle: *mut c_void,
    _flags: u32,
    _parameters: *const c_void,
    _parameters_size: u32,
    io_status_block: *mut IO_STATUS_BLOCK,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { NtFlushBuffersFile(file_handle, io_status_block) }
}

/// [`NtQueryFullAttributesFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwqueryfullattributesfile):
/// query `FILE_NETWORK_OPEN_INFORMATION` (56 bytes) for `object_attributes`.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQueryFullAttributesFile(
    object_attributes: *const OBJECT_ATTRIBUTES,
    file_information: *mut u8,
) -> NTSTATUS {
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
    const FILE_NETWORK_OPEN_INFORMATION: u32 = 34;
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
    let mut net_info = [0u8; 56];
    let q = file::query_information(h, FILE_NETWORK_OPEN_INFORMATION, &mut net_info);
    file::close(h);
    match q {
        Ok(r) if nt_success(r.status) => {
            // SAFETY: per the contract.
            let cp =
                unsafe { crate::svc::capture::copy_to_caller(file_information, &net_info, mode) };
            match cp {
                Ok(()) => STATUS_SUCCESS,
                Err(st) => st,
            }
        }
        Ok(r) => r.status,
        Err(e) => io_error_to_status(e),
    }
}

/// [`NtDeleteFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntdeletefile).
///
/// # Safety
/// `object_attributes` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtDeleteFile(object_attributes: *const OBJECT_ATTRIBUTES) -> NTSTATUS {
    const DELETE_ACCESS: u32 = 0x0001_0000;
    const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;
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
        desired_access: DELETE_ACCESS,
        share_access: 0x7,
        create_options: FILE_DELETE_ON_CLOSE | FILE_SYNCHRONOUS_IO_NONALERT,
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
    file::close(h);
    STATUS_SUCCESS
}

/// [`NtCancelIoFile`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcanceliofile).
///
/// # Safety
/// `io_status_block` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtCancelIoFile(
    file_handle: *mut c_void,
    io_status_block: *mut IO_STATUS_BLOCK,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    if let Err(st) = crate::ob::handle::reference_for(
        file_handle as u64,
        Some(&raw const crate::ob::object::FILE_TYPE),
        0,
        crate::svc::capture::handle_mode(mode),
    ) {
        return st;
    }
    let iosb = IO_STATUS_BLOCK {
        Status: STATUS_SUCCESS,
        Information: 0,
    };
    // SAFETY: per the contract.
    if let Err(st) = unsafe { crate::svc::capture::write(io_status_block, iosb, mode) } {
        return st;
    }
    STATUS_SUCCESS
}

pub use crate::svc::zw::{ZwCreateFile, ZwOpenFile};
