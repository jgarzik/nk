//! The access check and the privilege checks, as drivers call them.
//!
//! The rules are `nk_se::access` and `nk_se::privilege`. Here the
//! driver's structures are read through raw pointers, the rules run on
//! copies, and the answers are written back where Windows writes them.

use super::{Copies, token};
use crate::mm::pool;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_ntabi::io::KERNEL_MODE;
use nk_ntabi::ob::GENERIC_MAPPING;
use nk_ntabi::se::{
    ACCESS_STATE, AUX_ACCESS_DATA, INITIAL_PRIVILEGE_COUNT, LUID, LUID_AND_ATTRIBUTES,
    PRIVILEGE_SET, SECURITY_SUBJECT_CONTEXT,
};
use nk_ntabi::status::*;
use nk_se::access::{GenericMapping, Outcome, Request, Status, access_check};
use nk_se::privilege::{privilege_check, single_privilege_check};
use nk_se::token::{Luid, Privilege, SE_PRIVILEGE_USED_FOR_ACCESS};

/// Pool tag of privilege sets, Windows' own (`SePr`).
const TAG_PRIVILEGES: u32 = u32::from_le_bytes(*b"SePr");

/// A driver's generic mapping, or one that maps to nothing when the
/// driver gave none.
///
/// # Safety
/// `mapping` is null or points to a `GENERIC_MAPPING`.
pub(super) unsafe fn mapping_of(mapping: *const GENERIC_MAPPING) -> GenericMapping {
    if mapping.is_null() {
        return GenericMapping {
            read: 0,
            write: 0,
            execute: 0,
            all: 0,
        };
    }
    // SAFETY: per the contract.
    let mapping = unsafe { mapping.read_unaligned() };
    GenericMapping {
        read: mapping.GenericRead,
        write: mapping.GenericWrite,
        execute: mapping.GenericExecute,
        all: mapping.GenericAll,
    }
}

/// The level at which a captured subject impersonates; `None` when it
/// acts as itself.
///
/// # Safety
/// `subject` is a captured subject context.
pub(super) unsafe fn impersonation_level(subject: *const SECURITY_SUBJECT_CONTEXT) -> Option<u32> {
    // SAFETY: per the contract.
    unsafe {
        (!(&raw const (*subject).ClientToken).read().is_null())
            .then(|| (&raw const (*subject).ImpersonationLevel).read())
    }
}

/// A privilege set of `privileges`, each marked as used for access, in
/// a pool block for the driver to free with [`SeFreePrivileges`]. Null
/// without memory, as on Windows, where the check succeeds all the
/// same.
fn privilege_set(privileges: &[Luid]) -> *mut PRIVILEGE_SET {
    let size = size_of::<PRIVILEGE_SET>()
        + size_of::<LUID_AND_ATTRIBUTES>() * privileges.len().saturating_sub(1);
    let set = pool::alloc(size, TAG_PRIVILEGES).cast::<PRIVILEGE_SET>();
    if !set.is_null() {
        // SAFETY: a fresh block with room for the header and one
        // 12-byte entry per privilege; the pool aligns it.
        unsafe {
            (&raw mut (*set).PrivilegeCount).write(privileges.len() as u32);
            (&raw mut (*set).Control).write(0);
            let first = (&raw mut (*set).Privilege).cast::<LUID_AND_ATTRIBUTES>();
            for (i, &luid) in privileges.iter().enumerate() {
                first.add(i).write(LUID_AND_ATTRIBUTES {
                    Luid: LUID {
                        LowPart: luid as u32,
                        HighPart: (luid >> 32) as i32,
                    },
                    Attributes: SE_PRIVILEGE_USED_FOR_ACCESS,
                });
            }
        }
    }
    set
}

/// [`SeAccessCheck`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-seaccesscheck):
/// whether the subject may have `desired` access to an object with
/// this security descriptor, by the rules of `nk_se::access`. The
/// subject is the client token of the captured context if it has one,
/// else the primary token.
///
/// As Windows writes its answers: nothing granted and
/// `STATUS_ACCESS_DENIED` until decided otherwise; the caller's
/// privilege-set pointer null unless a privilege granted a right, when
/// it names a pool block that [`SeFreePrivileges`] frees. For
/// `KernelMode` the descriptor and the subject are not looked at. A
/// null descriptor is a denial.
///
/// `SubjectContextLocked` changes nothing: NK's tokens never change, so
/// there is nothing to hold still for the length of the check.
///
/// # Safety
/// `sd` is null or a security descriptor whose parts are where it
/// says; `subject` is a captured subject context; `privileges` is null
/// or writable; `mapping` points to a mapping; `granted` and `status`
/// are writable.
pub unsafe extern "C" fn SeAccessCheck(
    sd: *mut c_void,
    subject: *mut SECURITY_SUBJECT_CONTEXT,
    _subject_locked: u8,
    desired: u32,
    previously_granted: u32,
    privileges: *mut *mut PRIVILEGE_SET,
    mapping: *const GENERIC_MAPPING,
    access_mode: i8,
    granted: *mut u32,
    status: *mut NTSTATUS,
) -> u8 {
    // SAFETY: per the contract. The descriptor is the driver's memory:
    // the rules run on copies of its parts.
    unsafe {
        granted.write_unaligned(0);
        status.write_unaligned(STATUS_ACCESS_DENIED);
        if !privileges.is_null() {
            privileges.write_unaligned(core::ptr::null_mut());
        }
        let kernel_mode = access_mode == KERNEL_MODE;
        let copies = if kernel_mode {
            // Not looked at: an empty descriptor stands in.
            Copies::empty()
        } else if sd.is_null() {
            return 0;
        } else {
            match Copies::of(sd.cast()) {
                Some(copies) => copies,
                None => {
                    status.write_unaligned(STATUS_INSUFFICIENT_RESOURCES);
                    return 0;
                }
            }
        };
        let Outcome {
            granted: rights,
            status: outcome,
            privileges: used,
        } = access_check(&Request {
            token: token::effective(subject),
            impersonation_level: impersonation_level(subject),
            descriptor: &copies.parts(),
            desired,
            previously_granted,
            mapping: mapping_of(mapping),
            kernel_mode,
        });
        granted.write_unaligned(rights);
        status.write_unaligned(match outcome {
            Status::Success => STATUS_SUCCESS,
            Status::AccessDenied => STATUS_ACCESS_DENIED,
            Status::PrivilegeNotHeld => STATUS_PRIVILEGE_NOT_HELD,
            Status::BadImpersonationLevel => STATUS_BAD_IMPERSONATION_LEVEL,
        });
        if outcome != Status::Success {
            return 0;
        }
        if !privileges.is_null() && !used.is_empty() {
            privileges.write_unaligned(privilege_set(&used));
        }
        1
    }
}

/// Check whether the current thread's subject may be granted `desired` access
/// to an object whose self-relative security descriptor is `sd` (or null if
/// the object has no descriptor attached).
///
/// For `KernelMode` without `force_access_check`, bypasses the descriptor and
/// grants the generic-mapped `desired` rights directly, as Windows does.
///
/// # Safety
/// `sd` is null or points to a valid self-relative security descriptor;
/// `mapping` points to a valid `GENERIC_MAPPING`.
pub unsafe fn check_current_subject(
    sd: *const u8,
    mapping: *const GENERIC_MAPPING,
    desired: u32,
    mode: i8,
    force_access_check: bool,
) -> Result<u32, NTSTATUS> {
    // SAFETY: per the contract.
    let map = unsafe { mapping_of(mapping) };
    let mapped = nk_se::access::map_generic(desired, &map);
    if mode == KERNEL_MODE && !force_access_check {
        return Ok(mapped);
    }
    if sd.is_null() || mapped == 0 {
        return Ok(mapped);
    }
    let mut subject = core::mem::MaybeUninit::<SECURITY_SUBJECT_CONTEXT>::zeroed();
    let mut granted = 0u32;
    let mut status = STATUS_ACCESS_DENIED;
    // SAFETY: local subject context and output slots; `sd` and `mapping` valid
    // per caller contract.
    unsafe {
        token::SeCaptureSubjectContext(subject.as_mut_ptr());
        let allowed = SeAccessCheck(
            sd.cast_mut().cast(),
            subject.as_mut_ptr(),
            0,
            mapped,
            0,
            core::ptr::null_mut(),
            mapping,
            nk_ntabi::io::USER_MODE,
            &raw mut granted,
            &raw mut status,
        );
        token::SeReleaseSubjectContext(subject.as_mut_ptr());
        if allowed != 0 {
            Ok(granted)
        } else {
            Err(status)
        }
    }
}

/// A driver's `LUID` as one number.
fn luid_of(luid: LUID) -> Luid {
    u64::from(luid.LowPart) | u64::from(luid.HighPart as u32) << 32
}

/// The privileges of a driver's set, copied: the count, the control
/// word and each privilege. `None` without memory for the copy.
///
/// # Safety
/// `set` points to a privilege set with the entries its count says.
unsafe fn copied_set(set: *const PRIVILEGE_SET) -> Option<(u32, Vec<Privilege>)> {
    // SAFETY: per the contract.
    unsafe {
        let count = (&raw const (*set).PrivilegeCount).read_unaligned() as usize;
        let control = (&raw const (*set).Control).read_unaligned();
        let first = (&raw const (*set).Privilege).cast::<LUID_AND_ATTRIBUTES>();
        let mut privileges = Vec::new();
        privileges.try_reserve_exact(count).ok()?;
        for i in 0..count {
            let entry = first.add(i).read_unaligned();
            privileges.push(Privilege {
                luid: luid_of(entry.Luid),
                attributes: entry.Attributes,
            });
        }
        Some((control, privileges))
    }
}

/// [`SePrivilegeCheck`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-seprivilegecheck):
/// whether the captured subject holds the privileges of the set,
/// enabled, by the rules of `nk_se::privilege`. Each privilege's
/// attributes are written back with what the check found.
///
/// # Safety
/// `required` points to a privilege set the caller may write;
/// `subject` is a captured subject context.
pub unsafe extern "C" fn SePrivilegeCheck(
    required: *mut PRIVILEGE_SET,
    subject: *mut SECURITY_SUBJECT_CONTEXT,
    access_mode: i8,
) -> u8 {
    if access_mode == KERNEL_MODE {
        return 1;
    }
    // SAFETY: per the contract. The set is the driver's memory: the
    // rules run on a copy and the attributes are written back.
    unsafe {
        let Some((control, mut privileges)) = copied_set(required) else {
            return 0;
        };
        let held = privilege_check(
            token::effective(subject),
            impersonation_level(subject),
            control,
            &mut privileges,
            false,
        );
        let first = (&raw mut (*required).Privilege).cast::<LUID_AND_ATTRIBUTES>();
        for (i, privilege) in privileges.iter().enumerate() {
            (&raw mut (*first.add(i)).Attributes).write_unaligned(privilege.attributes);
        }
        u8::from(held)
    }
}

/// [`SeSinglePrivilegeCheck`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-sesingleprivilegecheck):
/// whether the calling thread's subject holds one privilege, enabled.
pub extern "C" fn SeSinglePrivilegeCheck(privilege: LUID, access_mode: i8) -> u8 {
    // SAFETY: an all-zero subject context is a valid value.
    let mut subject: SECURITY_SUBJECT_CONTEXT = unsafe { core::mem::zeroed() };
    let subject = &raw mut subject;
    // SAFETY: a local, captured for as long as it is used.
    unsafe {
        token::SeCaptureSubjectContext(subject);
        let held = single_privilege_check(
            token::effective(subject),
            impersonation_level(subject),
            luid_of(privilege),
            access_mode == KERNEL_MODE,
        );
        token::SeReleaseSubjectContext(subject);
        u8::from(held)
    }
}

/// The bytes a privilege set of `count` privileges takes.
const fn set_size(count: u32) -> usize {
    core::mem::offset_of!(PRIVILEGE_SET, Privilege)
        + size_of::<LUID_AND_ATTRIBUTES>() * count as usize
}

/// [`SeAppendPrivileges`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-seappendprivileges):
/// add the privileges of `set` to those an open has used
/// (`AUX_ACCESS_DATA.PrivilegesUsed`). While they number three at most
/// they stay in the access state's own set; beyond that they move to a
/// pool block, which `SeDeleteAccessState` frees, and the state says so
/// (`PrivilegesAllocated`). The set's control word is not carried over.
///
/// # Safety
/// `state` is an access state from `SeCreateAccessState`; `set` points
/// to a privilege set with the entries its count says.
pub unsafe extern "C" fn SeAppendPrivileges(
    state: *mut ACCESS_STATE,
    set: *const PRIVILEGE_SET,
) -> NTSTATUS {
    // SAFETY: per the contract. Both structures are the driver's
    // memory: fields are read and written one at a time.
    unsafe {
        let aux = (&raw const (*state).AuxData)
            .read()
            .cast::<AUX_ACCESS_DATA>();
        let used = (&raw const (*aux).PrivilegesUsed).read();
        let (had, more) = (
            (&raw const (*used).PrivilegeCount).read_unaligned(),
            (&raw const (*set).PrivilegeCount).read_unaligned(),
        );
        let target = if had.saturating_add(more) > INITIAL_PRIVILEGE_COUNT {
            let Some(size) = set_size(had).checked_add(set_size(more)) else {
                return STATUS_INSUFFICIENT_RESOURCES;
            };
            let moved = pool::alloc(size, TAG_PRIVILEGES).cast::<PRIVILEGE_SET>();
            if moved.is_null() {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            moved
                .cast::<u8>()
                .copy_from_nonoverlapping(used.cast(), set_size(had));
            if (&raw const (*state).PrivilegesAllocated).read() != 0 {
                pool::ExFreePoolWithTag(used.cast(), 0);
            }
            (&raw mut (*aux).PrivilegesUsed).write(moved);
            (&raw mut (*state).PrivilegesAllocated).write(1);
            moved
        } else {
            used
        };
        target.cast::<u8>().add(set_size(had)).copy_from(
            (&raw const (*set).Privilege).cast(),
            size_of::<LUID_AND_ATTRIBUTES>() * more as usize,
        );
        (&raw mut (*target).PrivilegeCount).write_unaligned(had + more);
    }
    STATUS_SUCCESS
}

/// [`SeFreePrivileges`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-sefreeprivileges):
/// free the privilege set [`SeAccessCheck`] handed out.
///
/// # Safety
/// `privileges` is a privilege set from `SeAccessCheck`, not freed
/// since.
pub unsafe extern "C" fn SeFreePrivileges(privileges: *mut PRIVILEGE_SET) {
    // SAFETY: per the contract: a pool block.
    unsafe { pool::ExFreePoolWithTag(privileges.cast(), 0) };
}
