//! The security descriptor of an object a driver keeps: made for a new
//! object, read part by part, and changed.
//!
//! The rules are `nk_se::assign` and `nk_se::descriptor`. A descriptor
//! these routines hand out is one self-relative pool block, the
//! caller's to keep and to free (`SeDeassignSecurity`, `ExFreePool`),
//! as [SeAssignSecurity] documents. Nothing here knows the object
//! manager's own store of descriptors (`ob::security`): a file system
//! that wants its descriptor shared and counted hands the block to
//! that store itself.
//!
//! [SeAssignSecurity]: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seassignsecurity

use super::access::mapping_of;
use super::{Copies, token};
use crate::mm::pool;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_ntabi::ob::GENERIC_MAPPING;
use nk_ntabi::se::SECURITY_SUBJECT_CONTEXT;
use nk_ntabi::status::*;
use nk_se::assign::{AssignError, Creation, assign_security};
use nk_se::descriptor::{SetError, query_security, set_security};

/// Pool tag of the descriptors handed out, Windows' own (`SeSd`).
const TAG: u32 = u32::from_le_bytes(*b"SeSd");

/// Copies of the parts of a driver's descriptor; of none, for a null
/// pointer. `Err` without memory.
///
/// # Safety
/// `sd` is null or a security descriptor whose parts are where it
/// says.
unsafe fn optional(sd: *const c_void) -> Result<Option<Copies>, NTSTATUS> {
    if sd.is_null() {
        return Ok(None);
    }
    // SAFETY: per the contract.
    match unsafe { Copies::of(sd.cast()) } {
        Some(copies) => Ok(Some(copies)),
        None => Err(STATUS_INSUFFICIENT_RESOURCES),
    }
}

/// `bytes` in a pool block of their own; null without memory.
fn block(bytes: &[u8]) -> *mut c_void {
    let block = pool::alloc(bytes.len(), TAG);
    if !block.is_null() {
        // SAFETY: a fresh block of that many bytes.
        unsafe { block.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len()) };
    }
    block.cast()
}

/// [`SeAssignSecurity`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seassignsecurity):
/// the security descriptor of a new object, from its parent's, the one
/// its creator supplied and the creator's token, by the rules of
/// `nk_se::assign`. The creator is the captured subject: its client
/// token if it has one, else its primary token.
///
/// Windows lets a creator whose previous mode is kernel mode name any
/// owner and supply a SACL without the privilege. Every thread NK runs
/// is such a creator.
///
/// The pool type is not looked at, as on Windows.
///
/// # Safety
/// `parent` and `explicit` are null or security descriptors whose
/// parts are where they say; `new` is writable; `subject` is a
/// captured subject context; `mapping` points to a mapping.
pub unsafe extern "C" fn SeAssignSecurity(
    parent: *mut c_void,
    explicit: *mut c_void,
    new: *mut *mut c_void,
    is_directory: u8,
    subject: *mut SECURITY_SUBJECT_CONTEXT,
    mapping: *const GENERIC_MAPPING,
    _pool_type: u32,
) -> NTSTATUS {
    // SAFETY: per the contract. The descriptors are the driver's
    // memory: the rules run on copies.
    unsafe {
        new.write_unaligned(core::ptr::null_mut());
        let (parent, explicit) = match (optional(parent), optional(explicit)) {
            (Ok(parent), Ok(explicit)) => (parent, explicit),
            (Err(status), _) | (_, Err(status)) => return status,
        };
        let assigned = assign_security(&Creation {
            parent: parent.as_ref().map(Copies::parts).as_ref(),
            explicit: explicit.as_ref().map(Copies::parts).as_ref(),
            token: token::effective(subject),
            is_directory: is_directory != 0,
            mapping: mapping_of(mapping),
            kernel_mode: true,
        });
        match assigned {
            Ok(descriptor) => {
                let block = block(&descriptor);
                if block.is_null() {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                new.write_unaligned(block);
                STATUS_SUCCESS
            }
            Err(AssignError::InvalidOwner) => STATUS_INVALID_OWNER,
            Err(AssignError::PrivilegeNotHeld) => STATUS_PRIVILEGE_NOT_HELD,
            Err(AssignError::InvalidAcl) => STATUS_INVALID_ACL,
        }
    }
}

/// [`SeDeassignSecurity`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-sedeassignsecurity):
/// free a descriptor [`SeAssignSecurity`] made, and forget it.
///
/// # Safety
/// `descriptor` points to null or to a descriptor from this module
/// that was not freed since.
pub unsafe extern "C" fn SeDeassignSecurity(descriptor: *mut *mut c_void) -> NTSTATUS {
    // SAFETY: per the contract: a pool block.
    unsafe {
        let block = descriptor.read_unaligned();
        if !block.is_null() {
            pool::ExFreePoolWithTag(block, 0);
        }
        descriptor.write_unaligned(core::ptr::null_mut());
    }
    STATUS_SUCCESS
}

/// [`SeQuerySecurityDescriptorInfo`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sequerysecuritydescriptorinfo):
/// copy the parts of an object's descriptor that `information` names
/// into the caller's buffer, self-relative. `*length` receives the
/// length that takes either way; a buffer too short gets nothing
/// (`STATUS_BUFFER_TOO_SMALL`). An object with no descriptor yields an
/// empty one.
///
/// # Safety
/// `information` and `length` point to a 32-bit value each; `out` is
/// writable for `*length` bytes; `object` points to null or to a
/// security descriptor whose parts are where it says.
pub unsafe extern "C" fn SeQuerySecurityDescriptorInfo(
    information: *const u32,
    out: *mut u8,
    length: *mut u32,
    object: *mut *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let object = match optional(object.read_unaligned()) {
            Ok(object) => object,
            Err(status) => return status,
        };
        let room = length.read_unaligned() as usize;
        let mut answer = Vec::new();
        if answer.try_reserve_exact(room).is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        answer.resize(room, 0);
        let written = query_security(
            object.as_ref().map(Copies::parts).as_ref(),
            information.read_unaligned(),
            &mut answer,
        );
        match written {
            Ok(used) => {
                out.copy_from_nonoverlapping(answer.as_ptr(), used);
                length.write_unaligned(used as u32);
                STATUS_SUCCESS
            }
            Err(needed) => {
                length.write_unaligned(needed as u32);
                STATUS_BUFFER_TOO_SMALL
            }
        }
    }
}

/// [`SeSetSecurityDescriptorInfo`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sesetsecuritydescriptorinfo):
/// replace the parts of an object's descriptor that `information`
/// names with those of `modification`, by the rules of
/// `nk_se::descriptor`. The object's new descriptor is a pool block
/// `*object_descriptor` is made to name; the one it had is the
/// caller's to free.
///
/// A new owner must be one the calling thread's subject may make an
/// owner (`Token::valid_owner`), whatever the thread's previous mode:
/// Windows makes no exception for kernel mode here. The object and the
/// pool type are not looked at.
///
/// # Safety
/// `information` points to a 32-bit value; `modification` is a
/// security descriptor whose parts are where it says;
/// `object_descriptor` points to null or to the object's
/// self-relative descriptor; `mapping` points to a mapping.
pub unsafe extern "C" fn SeSetSecurityDescriptorInfo(
    _object: *mut c_void,
    information: *const u32,
    modification: *mut c_void,
    object_descriptor: *mut *mut c_void,
    _pool_type: u32,
    mapping: *const GENERIC_MAPPING,
) -> NTSTATUS {
    // SAFETY: per the contract. Both descriptors are the driver's
    // memory: the rules run on copies.
    unsafe {
        let old = object_descriptor.read_unaligned();
        if old.is_null() {
            return STATUS_NO_SECURITY_ON_OBJECT;
        }
        let information = information.read_unaligned();
        let (Some(old), Some(new)) = (Copies::of(old.cast()), Copies::of(modification.cast()))
        else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        if old.control & nk_se::SE_SELF_RELATIVE == 0 {
            return STATUS_BAD_DESCRIPTOR_FORMAT;
        }
        // The owner's validity is the caller's subject's to give.
        if information & nk_se::OWNER_SECURITY_INFORMATION != 0
            && let Some(owner) = new.parts().owner
        {
            // SAFETY: an all-zero subject context is a valid value.
            let mut subject: SECURITY_SUBJECT_CONTEXT = core::mem::zeroed();
            let subject = &raw mut subject;
            token::SeCaptureSubjectContext(subject);
            let valid = token::effective(subject).valid_owner(owner);
            token::SeReleaseSubjectContext(subject);
            if !valid {
                return STATUS_INVALID_OWNER;
            }
        }
        let old = old.parts();
        let mut current = Vec::new();
        if current.try_reserve_exact(old.relative_length()).is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        current.resize(old.relative_length(), 0);
        let written = old.write_relative(&mut current);
        debug_assert_eq!(written, Ok(current.len()));
        match set_security(
            Some(&current),
            &new.parts(),
            information,
            &mapping_of(mapping),
        ) {
            Ok(descriptor) => {
                let block = block(&descriptor);
                if block.is_null() {
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
                object_descriptor.write_unaligned(block);
                STATUS_SUCCESS
            }
            Err(SetError::NoSecurityOnObject) => STATUS_NO_SECURITY_ON_OBJECT,
            Err(SetError::BadDescriptorFormat) => STATUS_BAD_DESCRIPTOR_FORMAT,
            Err(SetError::InvalidOwner) => STATUS_INVALID_OWNER,
            Err(SetError::InvalidPrimaryGroup) => STATUS_INVALID_PRIMARY_GROUP,
            Err(SetError::InvalidAcl) => STATUS_INVALID_ACL,
        }
    }
}
