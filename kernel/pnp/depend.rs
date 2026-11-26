//! Dependencies between devices, as drivers state them
//! (`IoReserveDependency`, `IoResolveDependency`, `IoSetDependency`).
//! The rules are `nk_pnp::depend`; what follows from them here is that
//! a device's drivers are not added while a device it depends on has
//! not started ([`blocked`]).

#![allow(non_snake_case)]

use super::node::{self, State};
use crate::ke::{Rank, SpinLock};
use alloc::string::String;
use nk_ntabi::io::{DEVICE_OBJECT, UNICODE_STRING};
use nk_ntabi::status::*;
use nk_pnp::depend::{Dependencies, flags_valid};

static DEPENDENCIES: SpinLock<Dependencies> = SpinLock::new(Rank::DeviceTree, Dependencies::new());

/// The text of a counted string.
///
/// # Safety
/// `string` is null or points to a counted string.
unsafe fn text(string: *const UNICODE_STRING) -> String {
    // SAFETY: per the contract.
    String::from_utf16_lossy(&unsafe { crate::rtl::copy_unicode(string) })
}

/// `IoResolveDependency` (exported, not documented): bind the string
/// `id` to `device`, so that dependencies reserved by that string name
/// the device. `acpi.sys` binds each device to its firmware name. A
/// string bound before is bound anew, as the pinned kernel does it.
///
/// Windows also takes a null device (the string then names a provider
/// that has no device yet); NK refuses one (`STATUS_INVALID_PARAMETER`).
///
/// # Safety
/// `id` points to a counted string; `device` is null or a live device
/// object.
pub unsafe extern "C" fn IoResolveDependency(
    id: *const UNICODE_STRING,
    device: *mut DEVICE_OBJECT,
) -> NTSTATUS {
    if id.is_null() || device.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract.
    let id = unsafe { text(id) };
    if DEPENDENCIES.lock().resolve(&id, device as usize) {
        super::engine::look_later();
        STATUS_SUCCESS
    } else {
        STATUS_INSUFFICIENT_RESOURCES
    }
}

/// `IoReserveDependency` (exported, not documented): `dependent` needs
/// the device the string `id` is or will be bound to. The arguments
/// are checked as the pinned kernel checks them: a device, a string
/// that is not empty, and flags that are one or both of the two low
/// bits and nothing else (`STATUS_INVALID_PARAMETER`).
///
/// INFERRED: what the two flag bits tell apart. NK treats a dependency
/// of either kind alike.
///
/// # Safety
/// `dependent` is null or a live device object; `id` is null or points
/// to a counted string.
pub unsafe extern "C" fn IoReserveDependency(
    dependent: *mut DEVICE_OBJECT,
    id: *const UNICODE_STRING,
    flags: u32,
) -> NTSTATUS {
    if dependent.is_null() || id.is_null() || !flags_valid(flags) {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract.
    let id = unsafe { text(id) };
    if id.is_empty() {
        return STATUS_INVALID_PARAMETER;
    }
    if DEPENDENCIES.lock().reserve(dependent as usize, &id, flags) {
        STATUS_SUCCESS
    } else {
        STATUS_INSUFFICIENT_RESOURCES
    }
}

/// `IoSetDependency` (exported, not documented): `dependent` needs
/// `provider`. Checked as the pinned kernel checks it: two devices and
/// valid flags (`STATUS_INVALID_PARAMETER`); a device cannot depend on
/// itself (`STATUS_UNSUCCESSFUL`).
///
/// # Safety
/// Both are null or live device objects.
pub unsafe extern "C" fn IoSetDependency(
    dependent: *mut DEVICE_OBJECT,
    provider: *mut DEVICE_OBJECT,
    flags: u32,
) -> NTSTATUS {
    if dependent.is_null() || provider.is_null() || !flags_valid(flags) {
        return STATUS_INVALID_PARAMETER;
    }
    if dependent == provider {
        return STATUS_UNSUCCESSFUL;
    }
    if DEPENDENCIES
        .lock()
        .set(dependent as usize, provider as usize, flags)
    {
        STATUS_SUCCESS
    } else {
        STATUS_INSUFFICIENT_RESOURCES
    }
}

/// Whether the device `pdo` waits for a device it depends on: one that
/// no device has been bound to yet, or one that is not started.
pub fn blocked(pdo: usize) -> bool {
    let providers = DEPENDENCIES.lock().providers(pdo);
    providers.into_iter().any(|provider| match provider {
        None => true,
        Some(device) => node::with(device, |node| node.state == State::Started) != Some(true),
    })
}

/// The device `pdo` is gone.
pub fn forget(pdo: usize) {
    DEPENDENCIES.lock().forget(pdo);
}
