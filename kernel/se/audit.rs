//! Auditing: off.
//!
//! NK keeps no audit policy and has nobody to send an audit to (no
//! LSA). That is a configuration Windows has too, with every audit
//! category off, and the routines here do what the pinned kernel's do
//! then: decide that nothing is to be audited, and say so where a
//! driver looks.

use core::ffi::c_void;
use nk_ntabi::io::{KERNEL_MODE, UNICODE_STRING};
use nk_ntabi::se::{ACCESS_STATE, AUX_ACCESS_DATA};

/// [`SeOpenObjectAuditAlarm`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-seopenobjectauditalarm):
/// audit the opening of an object, if that is to be audited. It is
/// not. What Windows writes on that path, and nothing else:
///
/// - for `KernelMode`, nothing at all;
/// - otherwise the access state's `GenerateAudit` is cleared, and,
///   when a security descriptor is given, the auxiliary data's
///   `GenerateStagingEvents`.
///
/// `*GenerateOnClose` is written only when an audit is generated, so
/// here it is left as the caller had it.
///
/// # Safety
/// `access_state` is an access state from `SeCreateAccessState`.
pub unsafe extern "C" fn SeOpenObjectAuditAlarm(
    _object_type_name: *const UNICODE_STRING,
    _object: *mut c_void,
    _absolute_object_name: *const UNICODE_STRING,
    security_descriptor: *mut c_void,
    access_state: *mut ACCESS_STATE,
    _object_created: u8,
    _access_granted: u8,
    access_mode: i8,
    _generate_on_close: *mut u8,
) {
    if access_mode == KERNEL_MODE {
        return;
    }
    // SAFETY: per the contract: the state points to its auxiliary
    // data. Both are the driver's memory, written field by field.
    unsafe {
        if !security_descriptor.is_null() {
            let aux = (&raw const (*access_state).AuxData)
                .read()
                .cast::<AUX_ACCESS_DATA>();
            (&raw mut (*aux).GenerateStagingEvents).write(0);
        }
        (&raw mut (*access_state).GenerateAudit).write(0);
    }
}
