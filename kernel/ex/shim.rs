//! The kernel shim engine, which applies compatibility shims to
//! drivers. NK has none: a shim provider that registers is told what
//! Windows tells one when its engine is not running.

#![allow(non_snake_case)]

use core::ffi::c_void;
use nk_ntabi::status::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_UNSUCCESSFUL};

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
