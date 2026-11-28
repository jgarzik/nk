//! The kernel shim engine, which applies compatibility shims to
//! drivers. NK has none: a shim provider that registers is told what
//! Windows tells one when its engine is not running.

#![allow(non_snake_case)]

use core::ffi::c_void;
use nk_ntabi::status::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};

/// `KseQueryDeviceFlags` (undocumented): query shim compatibility flags for a
/// device. NK has no compatibility shim database, so it writes 0 flags and
/// succeeds (as Windows does when no shim applies to the device).
///
/// # Safety
/// `device_flags` is null or writable.
pub unsafe extern "C" fn KseQueryDeviceFlags(
    _device_key: *const u16,
    _device_class: *const u16,
    device_flags: *mut u64,
) -> NTSTATUS {
    if !device_flags.is_null() {
        // SAFETY: checked non-null; per the contract.
        unsafe { device_flags.write_unaligned(0) };
    }
    STATUS_SUCCESS
}

/// `KseRegisterShim` (undocumented): register a shim with the engine.
/// As in Windows' own routine, no shim is `STATUS_INVALID_PARAMETER`
/// and an engine that is not running is `STATUS_UNSUCCESSFUL`.
pub extern "C" fn KseRegisterShim(
    shim: *const c_void,
    _ignored: *const c_void,
    _flags: u32,
) -> NTSTATUS {
    if shim.is_null() {
        STATUS_INVALID_PARAMETER
    } else {
        STATUS_UNSUCCESSFUL
    }
}
