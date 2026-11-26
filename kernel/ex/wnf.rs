//! The Windows Notification Facility: named states that components
//! publish and subscribe to. NK has none: no state has an instance, so
//! a state name is unknown, which is Windows' answer for a name that
//! neither exists nor is listed in the registry (`nk_ex::wnf`). A name
//! NK's registry does list is one Windows would have made a state for:
//! asking about it stops the system by name.

#![allow(non_snake_case)]

use crate::cm;
use core::ffi::c_void;
use nk_ex::wnf;
use nk_ntabi::status::{NTSTATUS, STATUS_OBJECT_NAME_NOT_FOUND};

/// Where the SYSTEM hive lists the well-known and permanent state
/// names, each a value named by the name's digits.
const LISTED: &str = "Machine\\System\\CurrentControlSet\\Control\\Notifications";

/// The answer for the state `state_name`, asked about through
/// `routine`: not found, unless NK's registry lists it.
///
/// # Safety
/// `state_name` points to a state name.
unsafe fn unknown(routine: &str, state_name: *const u64) -> NTSTATUS {
    // SAFETY: per the contract. Windows reads the name too, before
    // anything else.
    let name = unsafe { state_name.read_unaligned() };
    let digits = wnf::value_name(name);
    let digits = core::str::from_utf8(&digits).unwrap_or("?");
    if wnf::listed_in_system_hive(wnf::lifetime(name)) && cm::read(LISTED, digits).is_ok() {
        crate::kd::bugcheck(format_args!(
            "{routine}: NK does not implement the notification state {digits}, which its registry lists"
        ));
    }
    kprintln!("wnf: state {digits} asked for by {routine}: NK has no such state");
    STATUS_OBJECT_NAME_NOT_FOUND
}

/// `ZwQueryWnfStateData` (undocumented; `NtQueryWnfStateData`): read
/// the data and change stamp of a state. No state exists:
/// `STATUS_OBJECT_NAME_NOT_FOUND`, and nothing is written.
///
/// # Safety
/// `state_name` points to a state name.
pub unsafe extern "C" fn ZwQueryWnfStateData(
    state_name: *const u64,
    _type_id: *const c_void,
    _explicit_scope: *const c_void,
    _change_stamp: *mut u32,
    _buffer: *mut c_void,
    _buffer_size: *mut u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { unknown("ZwQueryWnfStateData", state_name) }
}

/// `ExSubscribeWnfStateChange` (undocumented): have a callback called
/// when a state changes. No state exists:
/// `STATUS_OBJECT_NAME_NOT_FOUND`, and no subscription is made.
///
/// # Safety
/// `state_name` points to a state name.
pub unsafe extern "C" fn ExSubscribeWnfStateChange(
    _subscription: *mut *mut c_void,
    state_name: *const u64,
    _delivery_option: u32,
    _current_change_stamp: u32,
    _callback: *mut c_void,
    _callback_context: *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { unknown("ExSubscribeWnfStateChange", state_name) }
}

/// `ExUnsubscribeWnfStateChange` (undocumented): end a subscription.
/// Nothing for no subscription; NK makes none, so any other is not
/// one, and stops the system.
pub extern "C" fn ExUnsubscribeWnfStateChange(subscription: *mut c_void) {
    if !subscription.is_null() {
        crate::kd::bugcheck(format_args!(
            "ExUnsubscribeWnfStateChange: {subscription:p} is no subscription: NK makes none"
        ));
    }
}
