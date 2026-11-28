//! Tokens by handle: the `Zw` calls a driver makes to open a token,
//! copy one and ask it about itself.
//!
//! The caller is kernel mode: a handle's access is not checked, and
//! every handle opened is a kernel handle or the System process's own,
//! as the attributes ask (`ob::handle`).

use super::token;
use crate::ob::handle::{self, ObOpenObjectByPointer};
use crate::ob::object::{self, ObRef};
use core::ffi::c_void;
use nk_ntabi::io::KERNEL_MODE;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::se::SECURITY_QUALITY_OF_SERVICE;
use nk_ntabi::status::*;
use nk_ob::handles::Mode;
use nk_se::information::{class_known, token_information_buffer};
use nk_se::token::TokenType;

/// The object a handle names, if it is of type `ty`, with what the
/// handle was granted.
fn referenced(
    handle: *mut c_void,
    ty: &'static object::ObjectType,
) -> Result<(ObRef, u32), NTSTATUS> {
    handle::reference_for(
        handle as u64,
        Some(core::ptr::from_ref(ty)),
        0,
        Mode::Kernel,
    )
    .map(|(body, information)| (body, information.granted))
}

/// A handle to `token` with `access` and the attributes given, written
/// to `*opened`.
///
/// # Safety
/// `token` is a token object the caller holds a reference to; `opened`
/// is writable for a handle.
pub(super) unsafe fn open(
    token: *mut u8,
    access: u32,
    attributes: u32,
    opened: *mut *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        ObOpenObjectByPointer(
            token.cast(),
            attributes,
            core::ptr::null_mut(),
            access,
            &raw const object::TOKEN_TYPE,
            KERNEL_MODE,
            opened,
        )
    }
}

/// [`ZwOpenProcessTokenEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwopenprocesstokenex):
/// a handle to the primary token of the process a handle names.
///
/// # Safety
/// `token_handle` is writable for a handle.
pub unsafe extern "C" fn NtOpenProcessTokenEx(
    process_handle: *mut c_void,
    desired_access: u32,
    handle_attributes: u32,
    token_handle: *mut *mut c_void,
) -> NTSTATUS {
    let process = match referenced(process_handle, &object::PROCESS_TYPE) {
        Ok((process, _)) => process,
        Err(status) => return status,
    };
    // SAFETY: per the contract; the process and its token are
    // referenced from the look-ups to the last lines.
    unsafe {
        let primary =
            ObRef::adopt(crate::ps::process::PsReferencePrimaryToken(process.cast()).cast::<u8>());
        open(
            primary.body(),
            desired_access,
            handle_attributes,
            token_handle,
        )
    }
}

/// [`ZwDuplicateToken`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwduplicatetoken):
/// a new token that is a copy of the one a handle names, of the type
/// asked, and a handle to it. Its impersonation level is that of the
/// object attributes' quality of service, or the source token's own
/// when there is none; `Token::duplicate_level` says which levels a
/// copy of an impersonation token may have. No access asked for means
/// the access the source handle has. A type that is neither primary
/// nor impersonation is `STATUS_INVALID_PARAMETER`.
///
/// # Safety
/// `object_attributes` is null or points to object attributes, whose
/// quality of service is null or points to one; `new_handle` is
/// writable for a handle.
pub unsafe extern "C" fn NtDuplicateToken(
    existing_handle: *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    effective_only: u8,
    token_type: u32,
    new_handle: *mut *mut c_void,
) -> NTSTATUS {
    let new_type = match token_type {
        1 => TokenType::Primary,
        2 => TokenType::Impersonation,
        _ => return STATUS_INVALID_PARAMETER,
    };
    // SAFETY: per the contract. The attributes are the driver's
    // memory, read field by field.
    let (attributes, requested) = unsafe {
        if object_attributes.is_null() {
            (0, None)
        } else {
            let qos = (&raw const (*object_attributes).SecurityQualityOfService)
                .read_unaligned()
                .cast::<SECURITY_QUALITY_OF_SERVICE>();
            (
                (&raw const (*object_attributes).Attributes).read_unaligned(),
                (!qos.is_null()).then(|| (&raw const (*qos).ImpersonationLevel).read_unaligned()),
            )
        }
    };
    let (source, granted) = match referenced(existing_handle, &object::TOKEN_TYPE) {
        Ok(found) => found,
        Err(status) => return status,
    };
    // SAFETY: per the contract; the source is referenced until the
    // last line, the copy until its handle holds it.
    unsafe {
        let source = source.body();
        match token::of(source).duplicate_level(new_type, requested) {
            Err(_) => STATUS_BAD_IMPERSONATION_LEVEL,
            Ok(level) => match token::duplicate(source, new_type, level, effective_only != 0) {
                None => STATUS_INSUFFICIENT_RESOURCES,
                Some(copy) => {
                    let access = if desired_access == 0 {
                        granted
                    } else {
                        desired_access
                    };
                    open(ObRef::adopt(copy).body(), access, attributes, new_handle)
                }
            },
        }
    }
}

/// [`ZwQueryInformationToken`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwqueryinformationtoken):
/// what the token a handle names answers for `class`, in the caller's
/// buffer (`nk_se::information::token_information_buffer`). In
/// Windows' order: a class there is not is refused before the handle
/// is looked at; a class this token has no answer for
/// (`STATUS_INVALID_INFO_CLASS`) leaves `*return_length` alone; else
/// `*return_length` is the length the answer takes, whether or not it
/// fits (`STATUS_BUFFER_TOO_SMALL`).
///
/// # Safety
/// `buffer` is writable for `length` bytes; `return_length` is
/// writable.
pub unsafe extern "C" fn NtQueryInformationToken(
    token_handle: *mut c_void,
    class: u32,
    buffer: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    if !class_known(class) {
        return STATUS_INVALID_INFO_CLASS;
    }
    let source = match referenced(token_handle, &object::TOKEN_TYPE) {
        Ok((source, _)) => source,
        Err(status) => return status,
    };
    // SAFETY: per the contract; the token is referenced until the
    // last line.
    unsafe {
        match token_information_buffer(token::of(source.body()), class, buffer as u64) {
            Err(_) => STATUS_INVALID_INFO_CLASS,
            Ok(answer) => {
                return_length.write_unaligned(answer.len() as u32);
                if answer.len() > length as usize {
                    STATUS_BUFFER_TOO_SMALL
                } else {
                    buffer.copy_from_nonoverlapping(answer.as_ptr(), answer.len());
                    STATUS_SUCCESS
                }
            }
        }
    }
}

pub use crate::svc::zw::{ZwDuplicateToken, ZwOpenProcessTokenEx, ZwQueryInformationToken};
