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
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::*;
use nk_se::information::{class_known, token_information_buffer};
use nk_se::token::TokenType;

/// The object a handle names, if it is of type `ty`, with what the
/// handle was granted. Also resolves Windows 10 token pseudo-handles
/// (`-4` = current process token, `-5` = current thread token, `-6` = effective token).
fn referenced(
    handle: *mut c_void,
    ty: &'static object::ObjectType,
) -> Result<(ObRef, u32), NTSTATUS> {
    if core::ptr::eq(ty, &raw const object::TOKEN_TYPE) {
        let raw = handle as isize;
        match raw {
            -4 => {
                // SAFETY: `PsGetCurrentProcess` returns the live calling `EPROCESS`.
                let tok = unsafe {
                    crate::ps::process::PsReferencePrimaryToken(
                        crate::ps::process::PsGetCurrentProcess(),
                    )
                };
                if tok.is_null() {
                    return Err(STATUS_NO_TOKEN);
                }
                // SAFETY: `PsReferencePrimaryToken` returned a new reference.
                return Ok((unsafe { ObRef::adopt(tok.cast()) }, 0x000F_01FF));
            }
            -5 => {
                // SAFETY: `ke::thread::current` is the live calling thread.
                let imp = unsafe { super::impersonate::reference(crate::ke::thread::current()) };
                let Some(imp) = imp else {
                    return Err(STATUS_NO_TOKEN);
                };
                // SAFETY: `impersonate::reference` returned a new reference.
                return Ok((unsafe { ObRef::adopt(imp.token) }, 0x000F_01FF));
            }
            -6 => {
                // SAFETY: `ke::thread::current` is the live calling thread.
                let imp = unsafe { super::impersonate::reference(crate::ke::thread::current()) };
                if let Some(imp) = imp {
                    // SAFETY: `impersonate::reference` returned a new reference.
                    return Ok((unsafe { ObRef::adopt(imp.token) }, 0x000F_01FF));
                }
                // SAFETY: `PsGetCurrentProcess` returns the live calling `EPROCESS`.
                let tok = unsafe {
                    crate::ps::process::PsReferencePrimaryToken(
                        crate::ps::process::PsGetCurrentProcess(),
                    )
                };
                if tok.is_null() {
                    return Err(STATUS_NO_TOKEN);
                }
                // SAFETY: `PsReferencePrimaryToken` returned a new reference.
                return Ok((unsafe { ObRef::adopt(tok.cast()) }, 0x000F_01FF));
            }
            _ => {}
        }
    }
    let hmode = crate::svc::capture::handle_mode(crate::svc::capture::mode());
    handle::reference_for(handle as u64, Some(core::ptr::from_ref(ty)), 0, hmode)
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
    let mode = crate::svc::capture::mode();
    let mut handle = core::ptr::null_mut();
    // SAFETY: per the contract; write handle into a kernel local first, then
    // write back fault-safely when `UserMode`.
    let status = unsafe {
        ObOpenObjectByPointer(
            token.cast(),
            attributes,
            core::ptr::null_mut(),
            access,
            &raw const object::TOKEN_TYPE,
            mode,
            &raw mut handle,
        )
    };
    if status != STATUS_SUCCESS {
        return status;
    }
    // SAFETY: per the contract; fault-protected for `UserMode`.
    if let Err(err) = unsafe { crate::svc::capture::write(opened, handle, mode) } {
        let _ = handle::close_for(handle as u64, crate::svc::capture::handle_mode(mode));
        return err;
    }
    STATUS_SUCCESS
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
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract; fault-protected for `UserMode`.
    let (attributes, requested) =
        match unsafe { crate::svc::capture::capture_object_attributes(object_attributes, mode) } {
            Ok(Some(oa)) => (oa.attributes, oa.qos.map(|q| q.ImpersonationLevel)),
            Ok(None) => (0, None),
            Err(status) => return status,
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
    let mode = crate::svc::capture::mode();
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
                if let Err(status) =
                    crate::svc::capture::write(return_length, answer.len() as u32, mode)
                {
                    return status;
                }
                if answer.len() > length as usize {
                    STATUS_BUFFER_TOO_SMALL
                } else {
                    match crate::svc::capture::copy_to_caller(buffer, &answer, mode) {
                        Ok(()) => STATUS_SUCCESS,
                        Err(status) => status,
                    }
                }
            }
        }
    }
}

/// `NtQuerySecurityAttributesToken`: NK does not attach security attributes
/// to tokens; returns `STATUS_NOT_FOUND` (matching Windows when the named
/// attribute is absent, as expected by `ntdll!LdrpInitializeProcess`).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQuerySecurityAttributesToken(
    token_handle: *mut c_void,
    _attributes: *const c_void,
    _number_of_attributes: u32,
    _buffer: *mut c_void,
    _length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    if let Err(st) = referenced(token_handle, &object::TOKEN_TYPE) {
        return st;
    }
    if !return_length.is_null() {
        // SAFETY: per the contract; `capture::write` probes user pointers.
        if let Err(st) = unsafe { crate::svc::capture::write(return_length, 0u32, mode) } {
            return st;
        }
    }
    STATUS_NOT_FOUND
}

pub use crate::svc::zw::{ZwDuplicateToken, ZwOpenProcessTokenEx, ZwQueryInformationToken};
