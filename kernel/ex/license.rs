//! Licence values: the product policy Windows keeps per edition, which
//! a driver reads by name to learn a limit or whether a feature is
//! licensed.
//!
//! NK holds no product policy. Every name is unknown, which is what
//! Windows answers for a value its policy lacks; the driver then takes
//! its own default. Each name asked for is printed, so that a boot log
//! shows which policies a binary would have read.

#![allow(non_snake_case)]

use crate::rtl;
use core::ffi::c_void;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::status::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND};

/// `ZwQueryLicenseValue` (undocumented; `NtQueryLicenseValue` of
/// `ntdll`): the type and data of the licence value `name`. There is
/// none of any name.
///
/// # Safety
/// `name` is null or points to a valid counted string.
pub unsafe extern "C" fn ZwQueryLicenseValue(
    name: *const UNICODE_STRING,
    _kind: *mut u32,
    _data: *mut c_void,
    _data_size: u32,
    _result_size: *mut u32,
) -> NTSTATUS {
    // SAFETY: the caller's string.
    let name = unsafe { rtl::copy_unicode(name) };
    if name.is_empty() {
        return STATUS_INVALID_PARAMETER;
    }
    kprintln!(
        "ex: licence value {} asked for: NK has no product policy",
        alloc::string::String::from_utf16_lossy(&name)
    );
    STATUS_OBJECT_NAME_NOT_FOUND
}
