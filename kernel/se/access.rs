//! The access check and the privilege checks, as drivers call them.
//!
//! The rules are `nk_se::access` and `nk_se::privilege`. Here the
//! driver's structures are read through raw pointers, the rules run on
//! copies, and the answers are written back where Windows writes them.

use super::{Copies, token};
use crate::mm::pool;
use core::ffi::c_void;
use nk_ntabi::io::KERNEL_MODE;
use nk_ntabi::ob::GENERIC_MAPPING;
use nk_ntabi::se::{LUID, LUID_AND_ATTRIBUTES, PRIVILEGE_SET, SECURITY_SUBJECT_CONTEXT};
use nk_ntabi::status::*;
use nk_se::access::{GenericMapping, Outcome, Request, Status, access_check};
use nk_se::token::{Luid, SE_PRIVILEGE_USED_FOR_ACCESS};

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
