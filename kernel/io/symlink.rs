//! Symbolic links to devices: `IoCreateSymbolicLink`, `IoDeleteSymbolicLink`.

#![allow(non_snake_case)]

use crate::{ob, rtl};
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::status::*;

/// `IoCreateSymbolicLink`: make `link_name` another name for the object
/// called `device_name`.
///
/// # Safety
/// Both arguments must point to valid counted strings.
pub unsafe extern "C" fn IoCreateSymbolicLink(
    link_name: *const UNICODE_STRING,
    device_name: *const UNICODE_STRING,
) -> NTSTATUS {
    // SAFETY: per the contract.
    let (link, target) = unsafe { (rtl::copy_unicode(link_name), rtl::copy_unicode(device_name)) };
    if !nk_rtl::is_valid_object_name(&target) {
        return STATUS_OBJECT_NAME_INVALID;
    }
    ob::insert(&link, ob::Target::SymbolicLink(target))
}

/// `IoDeleteSymbolicLink`.
///
/// # Safety
/// `link_name` must point to a valid counted string.
pub unsafe extern "C" fn IoDeleteSymbolicLink(link_name: *const UNICODE_STRING) -> NTSTATUS {
    // SAFETY: per the contract.
    ob::remove_link(&unsafe { rtl::copy_unicode(link_name) })
}
