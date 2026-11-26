//! The errata manager: rules about the machine's flaws, which drivers
//! supply facts for (providers) and ask about (clients).
//!
//! Windows reads the rules from an errata file at boot. NK reads none,
//! so its database is empty, and each routine answers as Windows' does
//! then (`nk_ex::em`): a provider that names an entry type or a
//! callback is told it is not found, and so is a client that asks about
//! a rule, with the rule's state unknown. Drivers treat both as "no
//! erratum applies".

#![allow(non_snake_case)]

use crate::mm::pool;
use crate::ob::object;
use core::ffi::c_void;
use nk_ex::em::{self, Registration};
use nk_ntabi::em::{EM_CALLBACK_REGISTRATION, EM_ENTRY_REGISTRATION};
use nk_ntabi::ex::GUID;
use nk_ntabi::status::{NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS};

/// Windows' pool tag for a provider.
const TAG: u32 = u32::from_le_bytes(*b"EMpr");

/// A registered provider: what its handle points to. It holds a
/// reference to the provider's driver object.
struct Provider {
    driver: *mut c_void,
}

/// `EmProviderRegister` (undocumented): register a driver as a provider
/// of `entry_count` kinds of entry and `callback_count` callbacks, for
/// a handle.
///
/// | Outcome | Status |
/// | --- | --- |
/// | no driver object, no place for the handle, a count without its array, a null GUID or callback in the first registration | `STATUS_INVALID_PARAMETER` |
/// | an entry type or a callback is named | `STATUS_NOT_FOUND`: NK's database is empty |
/// | nothing is named | `STATUS_SUCCESS`, and the driver object is referenced until `EmProviderDeregister` |
///
/// # Safety
/// `entries` and `callbacks` are null or point to as many registrations
/// as their counts say; `handle` is null or points to room for a
/// pointer; `driver` is null or a driver object the caller holds.
pub unsafe extern "C" fn EmProviderRegister(
    driver: *mut c_void,
    entries: *const EM_ENTRY_REGISTRATION,
    entry_count: u32,
    callbacks: *const EM_CALLBACK_REGISTRATION,
    callback_count: u32,
    handle: *mut *mut c_void,
) -> NTSTATUS {
    let registration = Registration {
        no_driver: driver.is_null(),
        no_handle: handle.is_null(),
        entry_count,
        // SAFETY: per the contract, an array of at least one when the
        // count is not zero; a copy, since the driver may write it.
        first_entry: (entry_count != 0 && !entries.is_null())
            .then(|| unsafe { entries.read_unaligned() }),
        callback_count,
        // SAFETY: as above.
        first_callback: (callback_count != 0 && !callbacks.is_null())
            .then(|| unsafe { callbacks.read_unaligned() }),
    };
    if let Err(status) = em::register(&registration) {
        return status;
    }
    let provider = pool::alloc(size_of::<Provider>(), TAG).cast::<Provider>();
    if provider.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: the block just allocated; the caller's driver object,
    // which it holds; the caller's place for the handle.
    unsafe {
        object::ObfReferenceObject(driver);
        provider.write(Provider { driver });
        handle.write_unaligned(provider.cast());
    }
    STATUS_SUCCESS
}

/// `EmProviderDeregister` (undocumented): take back a registration.
/// Nothing happens for no handle.
///
/// # Safety
/// `handle` is null or what `EmProviderRegister` gave, not yet
/// deregistered.
pub unsafe extern "C" fn EmProviderDeregister(handle: *mut c_void) {
    if handle.is_null() {
        return;
    }
    // SAFETY: per the contract, a provider NK allocated, whose driver
    // object it referenced.
    unsafe {
        let provider = handle.cast::<Provider>().read();
        object::ObfDereferenceObject(provider.driver);
    }
    let _ = pool::free(handle.cast());
}

/// `EmClientQueryRuleState` (undocumented): the state of the rule
/// `rule`. The state is set to unknown before anything is looked up;
/// no rule is found.
///
/// # Safety
/// `state` is null or points to room for a `u32`.
pub unsafe extern "C" fn EmClientQueryRuleState(rule: *const GUID, state: *mut u32) -> NTSTATUS {
    let complete = !rule.is_null() && !state.is_null();
    if complete {
        // SAFETY: per the contract.
        unsafe { state.write_unaligned(em::STATE_UNKNOWN) };
    }
    em::rule(complete)
}

/// `EmClientRuleEvaluate` (undocumented): decide the rule `rule` from
/// `count` entries the client supplies. The state is set to unknown
/// before anything is looked up; no rule is found.
///
/// # Safety
/// `state` is null or points to room for a `u32`.
pub unsafe extern "C" fn EmClientRuleEvaluate(
    rule: *const GUID,
    entries: *const c_void,
    count: u32,
    state: *mut u32,
) -> NTSTATUS {
    let complete = !rule.is_null() && !entries.is_null() && !state.is_null() && count != 0;
    if complete {
        // SAFETY: per the contract.
        unsafe { state.write_unaligned(em::STATE_UNKNOWN) };
    }
    em::rule(complete)
}
