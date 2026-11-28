//! The Windows Notification Facility: named states that components
//! publish and subscribe to.
//!
//! A well-known or permanent state name listed under
//! `\Registry\Machine\System\CurrentControlSet\Control\Notifications`
//! (such as `41C6013DA3BC0875`, subscribed by `sleepstudyhelper.sys`) exists
//! as an empty, quiescent state (change stamp 0, 0 bytes) that drivers can
//! query and subscribe to cleanly. Any name not listed in the registry is
//! unknown and answered with `STATUS_OBJECT_NAME_NOT_FOUND`, matching Windows.

#![allow(non_snake_case)]

use crate::cm;
use crate::mm::pool;
use core::ffi::c_void;
use nk_ex::wnf;
use nk_ntabi::status::{
    NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER,
    STATUS_OBJECT_NAME_NOT_FOUND, STATUS_SUCCESS,
};

/// Where the SYSTEM hive lists the well-known and permanent state
/// names, each a value named by the name's digits.
const LISTED: &str = "Machine\\System\\CurrentControlSet\\Control\\Notifications";

const TAG_WNF: u32 = u32::from_le_bytes(*b"WnfS");
const SUB_MAGIC: u64 = 0x574E_4653_5542_0001;

#[repr(C)]
struct Subscription {
    magic: u64,
    state_name: u64,
}

/// Whether `state_name` is a well-known or permanent name listed in the
/// SYSTEM hive's `Control\Notifications` table.
fn is_listed(state_name: u64) -> bool {
    if !wnf::listed_in_system_hive(wnf::lifetime(state_name)) {
        return false;
    }
    let digits = wnf::value_name(state_name);
    let Ok(digits) = core::str::from_utf8(&digits) else {
        return false;
    };
    cm::read(LISTED, digits).is_ok()
}

/// `ZwQueryWnfStateData` (undocumented; `NtQueryWnfStateData`): read
/// the data and change stamp of a state. Listed well-known/permanent states
/// answer with change stamp 0 and 0 bytes; unlisted states answer
/// `STATUS_OBJECT_NAME_NOT_FOUND` without touching output buffers.
///
/// # Safety
/// `state_name` points to a state name; optional out pointers are writable.
pub unsafe extern "C" fn NtQueryWnfStateData(
    state_name: *const u64,
    _type_id: *const c_void,
    _explicit_scope: *const c_void,
    change_stamp: *mut u32,
    _buffer: *mut c_void,
    buffer_size: *mut u32,
) -> NTSTATUS {
    if state_name.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract.
    let name = unsafe { state_name.read_unaligned() };
    if !is_listed(name) {
        let digits = wnf::value_name(name);
        let digits = core::str::from_utf8(&digits).unwrap_or("?");
        kprintln!("wnf: state {digits} asked for by ZwQueryWnfStateData: NK has no such state");
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    // SAFETY: optional output pointers are writable per the contract.
    unsafe {
        if !change_stamp.is_null() {
            change_stamp.write_unaligned(0);
        }
        if !buffer_size.is_null() {
            buffer_size.write_unaligned(0);
        }
    }
    STATUS_SUCCESS
}

/// `ExSubscribeWnfStateChange` (undocumented): subscribe to notifications for
/// a state name. Listed well-known/permanent states allocate a subscription
/// handle and succeed (NK publishes no sleep/standby transitions, so callbacks
/// do not fire); unlisted states fail with `STATUS_OBJECT_NAME_NOT_FOUND`.
///
/// # Safety
/// `subscription` is writable; `state_name` points to a state name.
pub unsafe extern "C" fn ExSubscribeWnfStateChange(
    subscription: *mut *mut c_void,
    state_name: *const u64,
    _delivery_option: u32,
    _current_change_stamp: u32,
    _callback: *mut c_void,
    _callback_context: *mut c_void,
) -> NTSTATUS {
    if subscription.is_null() || state_name.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract.
    let name = unsafe { state_name.read_unaligned() };
    if !is_listed(name) {
        let digits = wnf::value_name(name);
        let digits = core::str::from_utf8(&digits).unwrap_or("?");
        kprintln!(
            "wnf: state {digits} asked for by ExSubscribeWnfStateChange: NK has no such state"
        );
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    let block = pool::alloc(size_of::<Subscription>(), TAG_WNF).cast::<Subscription>();
    if block.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: freshly allocated block; `subscription` checked non-null.
    unsafe {
        block.write(Subscription {
            magic: SUB_MAGIC,
            state_name: name,
        });
        subscription.write_unaligned(block.cast());
    }
    STATUS_SUCCESS
}

/// `ExUnsubscribeWnfStateChange` (undocumented): end a subscription returned
/// by [`ExSubscribeWnfStateChange`]. Null is a no-op; a non-null pointer that
/// is not a live subscription stops the system.
pub extern "C" fn ExUnsubscribeWnfStateChange(subscription: *mut c_void) {
    if subscription.is_null() {
        return;
    }
    if pool::info(subscription.cast()) != Some((size_of::<Subscription>(), TAG_WNF)) {
        crate::kd::bugcheck(format_args!(
            "ExUnsubscribeWnfStateChange: {subscription:p} is not a WNF subscription"
        ));
    }
    // SAFETY: validated live pool allocation of `Subscription`.
    let magic = unsafe { (&raw const (*subscription.cast::<Subscription>()).magic).read() };
    if magic != SUB_MAGIC {
        crate::kd::bugcheck(format_args!(
            "ExUnsubscribeWnfStateChange: {subscription:p} is not a WNF subscription"
        ));
    }
    // SAFETY: invalidate magic before freeing.
    unsafe { (&raw mut (*subscription.cast::<Subscription>()).magic).write(0) };
    let _ = pool::free(subscription.cast());
}

/// `ExQueryWnfStateData` (undocumented): read the data of a subscribed WNF
/// state.
///
/// # Safety
/// `subscription` came from `ExSubscribeWnfStateChange`; optional out pointers
/// are writable.
pub unsafe extern "C" fn ExQueryWnfStateData(
    subscription: *mut c_void,
    change_stamp: *mut u32,
    _output_buffer: *mut c_void,
    output_buffer_size: *mut u32,
) -> NTSTATUS {
    if subscription.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if pool::info(subscription.cast()) != Some((size_of::<Subscription>(), TAG_WNF)) {
        crate::kd::bugcheck(format_args!(
            "ExQueryWnfStateData: {subscription:p} is not a WNF subscription"
        ));
    }
    // SAFETY: optional output pointers are writable per the contract.
    unsafe {
        if !change_stamp.is_null() {
            change_stamp.write_unaligned(0);
        }
        if !output_buffer_size.is_null() {
            output_buffer_size.write_unaligned(0);
        }
    }
    STATUS_SUCCESS
}

/// `ZwQueryWnfStateNameInformation` (undocumented): query metadata about a
/// WNF state name (existence, subscribers present, quiescence).
///
/// # Safety
/// `state_name` points to a state name; `info_buffer` is writable for
/// `info_buffer_size` bytes.
pub unsafe extern "C" fn NtQueryWnfStateNameInformation(
    state_name: *const u64,
    name_info_class: u32,
    _explicit_scope: *const c_void,
    info_buffer: *mut c_void,
    info_buffer_size: u32,
) -> NTSTATUS {
    if state_name.is_null() || info_buffer.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    if info_buffer_size < 4 {
        return STATUS_BUFFER_TOO_SMALL;
    }
    // SAFETY: checked non-null.
    let name = unsafe { state_name.read_unaligned() };
    let answer = match name_info_class {
        0 => u32::from(is_listed(name)), // WnfInfoStateNameExist
        1 => 0u32,                       // WnfInfoSubscribersPresent
        2 => 1u32,                       // WnfInfoIsQuiescent
        _ => return STATUS_INVALID_PARAMETER,
    };
    // SAFETY: checked non-null and >= 4 bytes.
    unsafe { info_buffer.cast::<u32>().write_unaligned(answer) };
    STATUS_SUCCESS
}

pub use crate::svc::zw::{ZwQueryWnfStateData, ZwQueryWnfStateNameInformation};
