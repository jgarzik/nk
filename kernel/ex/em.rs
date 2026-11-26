//! The errata manager: rules about the machine's flaws, which drivers
//! supply facts for (providers) and ask about (clients).
//!
//! Windows reads its database from an errata file at boot. NK reads
//! none (`nk_ex::em`): the entry types and callbacks of its database
//! are those providers register, and it has no rule, so a client is
//! told its rule is not found and the rule's state is unknown. Drivers
//! treat that as "no erratum applies". With no rule, nothing calls a
//! provider's callbacks.

#![allow(non_snake_case)]

use crate::ke::{Rank, SpinLock};
use crate::mm::pool;
use crate::ob::object;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_ex::em::{self, Callback, Database, Entry};
use nk_ntabi::em::{EM_CALLBACK_REGISTRATION, EM_ENTRY_REGISTRATION};
use nk_ntabi::ex::GUID;
use nk_ntabi::status::{
    NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};

/// Windows' pool tag for a provider.
const TAG: u32 = u32::from_le_bytes(*b"EMpr");

static DATABASE: SpinLock<Database> = SpinLock::new(Rank::Errata, Database::new());

/// A registered provider: what its handle points to. It holds a
/// reference to the provider's driver object.
struct Provider {
    registration: u64,
    driver: *mut c_void,
}

/// The GUID at `guid`, none for a null pointer.
///
/// # Safety
/// `guid` is null or points to a GUID.
unsafe fn guid_at(guid: *const GUID) -> Option<GUID> {
    // SAFETY: per the contract.
    (!guid.is_null()).then(|| unsafe { guid.read_unaligned() })
}

/// A vector with room for `count` items, or none for want of memory.
fn room<T>(count: u32) -> Option<Vec<T>> {
    let mut items = Vec::new();
    items.try_reserve_exact(count as usize).ok()?;
    Some(items)
}

/// `EmProviderRegister` (undocumented): register a driver as a provider
/// of `entry_count` kinds of entry and `callback_count` callbacks, for
/// a handle. The driver object is referenced until
/// `EmProviderDeregister`.
///
/// | Refusal | Status |
/// | --- | --- |
/// | no driver object, no place for the handle, a count without its array, an entry type or callback without a GUID, a callback without a routine | `STATUS_INVALID_PARAMETER` |
/// | a callback another routine is registered for | `STATUS_OBJECT_NAME_COLLISION` |
/// | no memory | `STATUS_INSUFFICIENT_RESOURCES` |
///
/// # Safety
/// `entries` and `callbacks` are null or point to as many registrations
/// as their counts say, each GUID pointer in them null or valid;
/// `handle` is null or points to room for a pointer; `driver` is null
/// or a driver object the caller holds.
pub unsafe extern "C" fn EmProviderRegister(
    driver: *mut c_void,
    entries: *const EM_ENTRY_REGISTRATION,
    entry_count: u32,
    callbacks: *const EM_CALLBACK_REGISTRATION,
    callback_count: u32,
    handle: *mut *mut c_void,
) -> NTSTATUS {
    if driver.is_null()
        || handle.is_null()
        || (entry_count != 0 && entries.is_null())
        || (callback_count != 0 && callbacks.is_null())
    {
        return STATUS_INVALID_PARAMETER;
    }
    let (Some(mut wanted_entries), Some(mut wanted_callbacks)) =
        (room::<Entry>(entry_count), room::<Callback>(callback_count))
    else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // Copies: the arrays and the GUIDs are the driver's memory.
    for i in 0..entry_count as usize {
        // SAFETY: per the contract, within the array.
        let entry = unsafe { entries.add(i).read_unaligned() };
        wanted_entries.push(Entry {
            // SAFETY: per the contract.
            guid: unsafe { guid_at(entry.EntryGuid) },
            lazy_callback: entry.LazyEntryCallback.addr(),
            lazy_context: entry.LazyCallbackContext.addr(),
        });
    }
    for i in 0..callback_count as usize {
        // SAFETY: per the contract, within the array.
        let callback = unsafe { callbacks.add(i).read_unaligned() };
        wanted_callbacks.push(Callback {
            // SAFETY: per the contract.
            guid: unsafe { guid_at(callback.CallbackGuid) },
            function: callback.CallbackFunction.addr(),
            context: callback.Context.addr(),
        });
    }
    let provider = pool::alloc(size_of::<Provider>(), TAG).cast::<Provider>();
    if provider.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let registered = DATABASE.lock().register(&wanted_entries, &wanted_callbacks);
    match registered {
        Ok(registration) => {
            // SAFETY: the block just allocated; the caller's driver
            // object, which it holds; the caller's place for the handle.
            unsafe {
                object::ObfReferenceObject(driver);
                provider.write(Provider {
                    registration,
                    driver,
                });
                handle.write_unaligned(provider.cast());
            }
            STATUS_SUCCESS
        }
        Err(status) => {
            let _ = pool::free(provider.cast());
            status
        }
    }
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
    // SAFETY: per the contract, a provider NK allocated.
    let provider = unsafe { handle.cast::<Provider>().read() };
    DATABASE.lock().deregister(provider.registration);
    // SAFETY: the driver object the registration referenced.
    unsafe { object::ObfDereferenceObject(provider.driver) };
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

/// For the self-tests: the routine registered for a callback, and how
/// many providers supply an entry type.
pub fn registered(callback: &GUID, entry: &GUID) -> (Option<usize>, usize) {
    let database = DATABASE.lock();
    (
        database.callback(callback).map(|(function, _)| function),
        database.suppliers(entry),
    )
}
