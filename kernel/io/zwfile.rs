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
const OBJ_VALID_ATTRIBUTES: u32 = 0x1FF2;

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
    if object_attributes.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract; the driver's memory, read field by
    // field through its pointer.
    let (length, root, name, attributes, qos, allocation_size) = unsafe {
        (
            (&raw const (*object_attributes).Length).read_unaligned(),
            (&raw const (*object_attributes).RootDirectory).read_unaligned(),
            crate::rtl::copy_unicode((&raw const (*object_attributes).ObjectName).read_unaligned()),
            (&raw const (*object_attributes).Attributes).read_unaligned(),
            (&raw const (*object_attributes).SecurityQualityOfService).read_unaligned(),
            if allocation_size.is_null() {
                0
            } else {
                allocation_size.read_unaligned()
            },
        )
    };
    if length as usize != size_of::<OBJECT_ATTRIBUTES>() || attributes & !OBJ_VALID_ATTRIBUTES != 0
    {
        return STATUS_INVALID_PARAMETER;
    }
    if !ea_buffer.is_null() && ea_length != 0 {
        return STATUS_EAS_NOT_SUPPORTED;
    }
    if !qos.is_null() {
        return STATUS_NOT_IMPLEMENTED;
    }
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
        requestor_mode: crate::ke::thread::previous_mode(),
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
            // SAFETY: per the contract.
            unsafe {
                file_handle.write_unaligned(handle as *mut c_void);
                (&raw mut (*io_status_block).Status).write_unaligned(result.status);
                (&raw mut (*io_status_block).Information).write_unaligned(result.information);
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

pub use crate::svc::zw::{ZwCreateFile, ZwOpenFile};
