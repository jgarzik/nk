//! Feature configuration: the store through which Windows turns
//! staged features of its own binaries on or off, per machine.
//!
//! NK's store is empty and never changes. A binary that asks about a
//! feature is told there is no configuration for it, and runs the
//! feature in the state it was built with; one that asks to be told of
//! changes is registered and never called.

#![allow(non_snake_case)]

use crate::mm::pool;
use core::ffi::c_void;
use nk_ntabi::status::{
    NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND,
    STATUS_SUCCESS,
};

/// Pool tag of a change registration.
const TAG: u32 = u32::from_le_bytes(*b"NkFc");

/// `RtlQueryFeatureConfigurationChangeStamp` (`wdm.h`): the number of
/// times the store has changed. Never.
pub extern "C" fn RtlQueryFeatureConfigurationChangeStamp() -> u64 {
    0
}

/// `RtlQueryFeatureConfiguration` (`wdm.h`): the configuration of one
/// feature. The store has none: `STATUS_NOT_FOUND`, with the change
/// stamp given if asked for.
///
/// # Safety
/// `change_stamp` is null or points to eight writable bytes.
pub unsafe extern "C" fn RtlQueryFeatureConfiguration(
    _feature: u32,
    _kind: u32,
    change_stamp: *mut u64,
    _configuration: *mut c_void,
) -> NTSTATUS {
    if !change_stamp.is_null() {
        // SAFETY: the caller's.
        unsafe { change_stamp.write_unaligned(0) };
    }
    STATUS_NOT_FOUND
}

/// `RtlRegisterFeatureConfigurationChangeNotification` (`wdm.h`): have
/// `callback` called when the store changes. It is registered, and the
/// store never changes.
///
/// # Safety
/// `registration` points to a writable pointer; `change_stamp` is null
/// or points to eight writable bytes.
pub unsafe extern "C" fn RtlRegisterFeatureConfigurationChangeNotification(
    callback: *const c_void,
    _context: *mut c_void,
    change_stamp: *mut u64,
    registration: *mut *mut c_void,
) -> NTSTATUS {
    if callback.is_null() || registration.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let handle = pool::alloc(size_of::<usize>(), TAG);
    if handle.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: the caller's.
    unsafe {
        if !change_stamp.is_null() {
            change_stamp.write_unaligned(0);
        }
        registration.write_unaligned(handle.cast());
    }
    STATUS_SUCCESS
}

/// `RtlUnregisterFeatureConfigurationChangeNotification` (`wdm.h`).
///
/// # Safety
/// `registration` is what a registration gave, not yet unregistered.
pub unsafe extern "C" fn RtlUnregisterFeatureConfigurationChangeNotification(
    registration: *mut c_void,
) -> NTSTATUS {
    if registration.is_null() || pool::free(registration.cast()).is_err() {
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_SUCCESS
}

/// `RtlNotifyFeatureUsage` (`wdm.h`): count a use of a feature, for
/// Windows' telemetry. NK keeps no such counts; the report is taken.
pub extern "C" fn RtlNotifyFeatureUsage(_report: *const c_void) -> NTSTATUS {
    STATUS_SUCCESS
}

/// For the self-tests.
pub fn test() -> Result<(), &'static str> {
    let mut stamp = 7u64;
    // SAFETY: a local for the stamp; no configuration is written.
    let status =
        unsafe { RtlQueryFeatureConfiguration(1, 0, &raw mut stamp, core::ptr::null_mut()) };
    if status != STATUS_NOT_FOUND || stamp != 0 || RtlQueryFeatureConfigurationChangeStamp() != 0 {
        return Err("a feature had a configuration, or the store a change");
    }
    let mut registration = core::ptr::null_mut();
    // SAFETY: locals; the callback is never called.
    let status = unsafe {
        RtlRegisterFeatureConfigurationChangeNotification(
            test as *const c_void,
            core::ptr::null_mut(),
            &raw mut stamp,
            &raw mut registration,
        )
    };
    if status != STATUS_SUCCESS || registration.is_null() {
        return Err("a change notification was not registered");
    }
    // SAFETY: the registration just made.
    if unsafe { RtlUnregisterFeatureConfigurationChangeNotification(registration) }
        != STATUS_SUCCESS
    {
        return Err("a change notification was not unregistered");
    }
    Ok(())
}
