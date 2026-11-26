//! Event tracing for a system on which nobody listens.
//!
//! NK starts no trace session, so no provider is ever enabled: a
//! registration is real and kept (`nk_etw::provider`), its enable
//! callback is never called, and an event written is dropped with
//! Windows' answer for a provider no session has enabled. The
//! decisions are in `doc/DESIGN.md`, "Tracing".

#![allow(non_snake_case)]

use crate::ke::bugcheck::KeBugCheckEx;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_etw::provider::{Registrations, TraitsError};
use nk_etw::traits;
use nk_ntabi::etw::{
    ETW_ENABLE_CALLBACK, EVENT_DATA_DESCRIPTOR, EVENT_DESCRIPTOR, EVENT_PROVIDER_SET_TRAITS,
    EVENT_PROVIDER_USE_DESCRIPTOR_TYPE, GUID, REGHANDLE,
};
use nk_ntabi::status::*;

/// How many providers can be registered at once.
const MAX_PROVIDERS: usize = 1024;

/// The registered providers. Lock-free: a provider writes at any IRQL.
static PROVIDERS: Registrations<MAX_PROVIDERS> = Registrations::new();

/// How many providers are registered: what a driver leaks if it is
/// unloaded without unregistering.
pub fn registered() -> usize {
    PROVIDERS.count()
}

/// The provider of security auditing events
/// (Microsoft-Windows-Security-Auditing), which only the kernel itself
/// may register.
const SECURITY_PROVIDER: GUID = GUID {
    Data1: 0x5484_9625,
    Data2: 0x5478,
    Data3: 0x4994,
    Data4: [0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28, 0xC3, 0x0D],
};

/// `EVENT_TRACING_FATAL_ERROR`, and its first parameter when a
/// registration handle is not one.
const EVENT_TRACING_FATAL_ERROR: u32 = 0x11D;
const BAD_REGISTRATION: usize = 4;

/// [`EtwRegister`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-etwregister):
/// register a provider. The callback is kept by nobody: no session
/// exists to enable the provider, so it is never called.
///
/// Refused as Windows refuses: the security auditing provider
/// (`STATUS_ACCESS_DENIED`), a context without a callback
/// (`STATUS_INVALID_PARAMETER`), and no room for another registration
/// (`STATUS_NO_MEMORY`).
///
/// # Safety
/// `provider` points to a GUID and `handle` is writable.
pub unsafe extern "C" fn EtwRegister(
    provider: *const GUID,
    callback: Option<ETW_ENABLE_CALLBACK>,
    context: *mut c_void,
    handle: *mut REGHANDLE,
) -> NTSTATUS {
    // SAFETY: per the contract.
    let provider = unsafe {
        handle.write_unaligned(0);
        provider.read_unaligned()
    };
    if provider == SECURITY_PROVIDER {
        return STATUS_ACCESS_DENIED;
    }
    if callback.is_none() && !context.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    match PROVIDERS.register() {
        Some(registration) => {
            // SAFETY: per the contract.
            unsafe { handle.write_unaligned(registration) };
            STATUS_SUCCESS
        }
        None => STATUS_NO_MEMORY,
    }
}

/// [`EtwUnregister`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-etwunregister).
/// A handle of zero is `STATUS_INVALID_HANDLE`. Any other that names no
/// registration (one unregistered already, say) stops the system with
/// `EVENT_TRACING_FATAL_ERROR`, the bugcheck Windows has for a
/// registration handle that is not one; on Windows such a handle points
/// into freed memory and what happens is anything.
pub extern "C" fn EtwUnregister(handle: REGHANDLE) -> NTSTATUS {
    if handle == 0 {
        return STATUS_INVALID_HANDLE;
    }
    if !PROVIDERS.unregister(handle) {
        KeBugCheckEx(
            EVENT_TRACING_FATAL_ERROR,
            BAD_REGISTRATION,
            handle as usize,
            1,
            0,
        );
    }
    STATUS_SUCCESS
}

/// [`EtwSetInformation`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-etwsetinformation).
/// The checks and their order are Windows': the handle, the class
/// (kernel mode may set traits and the descriptor type; any other is
/// `STATUS_INVALID_DEVICE_REQUEST`), the length, that traits are set
/// once (`STATUS_UNSUCCESSFUL`), the blob (`STATUS_FILE_CORRUPT_ERROR`).
/// A handle that is not zero and names no registration is
/// `STATUS_INVALID_HANDLE`.
///
/// Nothing reads what is set: the traits would go into events, and the
/// descriptor type says how a session is to read them.
///
/// # Safety
/// `information` is null or readable for `length` bytes.
pub unsafe extern "C" fn EtwSetInformation(
    handle: REGHANDLE,
    class: u32,
    information: *const c_void,
    length: u32,
) -> NTSTATUS {
    if handle == 0 {
        return STATUS_INVALID_HANDLE;
    }
    let length = length as usize;
    match class {
        EVENT_PROVIDER_SET_TRAITS => {
            if information.is_null() || !(traits::SHORTEST..=traits::LONGEST).contains(&length) {
                return STATUS_INVALID_PARAMETER;
            }
            match PROVIDERS.has_traits(handle) {
                None => return STATUS_INVALID_HANDLE,
                Some(true) => return STATUS_UNSUCCESSFUL,
                Some(false) => {}
            }
            // The rules run on a copy: the blob is the driver's memory.
            let mut blob = Vec::new();
            if blob.try_reserve_exact(length).is_err() {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            // SAFETY: per the contract, `length` readable bytes; the
            // copy has room for them.
            unsafe {
                core::ptr::copy_nonoverlapping(information.cast::<u8>(), blob.as_mut_ptr(), length);
                blob.set_len(length);
            }
            if !traits::well_formed(&blob) {
                return STATUS_FILE_CORRUPT_ERROR;
            }
            match PROVIDERS.set_traits(handle) {
                Ok(()) => STATUS_SUCCESS,
                Err(TraitsError::AlreadySet) => STATUS_UNSUCCESSFUL,
                Err(TraitsError::NotRegistered) => STATUS_INVALID_HANDLE,
            }
        }
        EVENT_PROVIDER_USE_DESCRIPTOR_TYPE => {
            if information.is_null() || length != 1 {
                return STATUS_INVALID_PARAMETER;
            }
            if !PROVIDERS.is_registered(handle) {
                return STATUS_INVALID_HANDLE;
            }
            // SAFETY: per the contract, one readable byte.
            match unsafe { information.cast::<u8>().read() } {
                0 | 1 => STATUS_SUCCESS,
                _ => STATUS_INVALID_PARAMETER,
            }
        }
        _ => STATUS_INVALID_DEVICE_REQUEST,
    }
}

/// [`EtwWriteTransfer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-etwwritetransfer):
/// write an event. No session has the provider enabled, so the event
/// goes nowhere and the answer is success, as Windows gives it without
/// looking at the event. A handle that names no registration is
/// `STATUS_INVALID_HANDLE`. Callable at any IRQL.
pub extern "C" fn EtwWriteTransfer(
    handle: REGHANDLE,
    _descriptor: *const EVENT_DESCRIPTOR,
    _activity: *const GUID,
    _related_activity: *const GUID,
    _data_count: u32,
    _data: *const EVENT_DATA_DESCRIPTOR,
) -> NTSTATUS {
    if PROVIDERS.is_registered(handle) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_HANDLE
    }
}
