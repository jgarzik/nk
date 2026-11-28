//! The registry by `RelativeTo` and path: `RtlCheckRegistryKey`,
//! `RtlCreateRegistryKey`, `RtlWriteRegistryValue`,
//! `RtlDeleteRegistryValue`.
//!
//! Each is, in the pinned kernel, one call for the key
//! (`RtlpGetRegistryHandle`: `ZwOpenKey`, or `ZwCreateKey` for all but
//! the check) and one of the system services on it. The key is found
//! as the query tables find theirs (`table::relative`), and made, set
//! and watched as those services do it.

#![allow(non_snake_case)]

use super::table::{by_handle, relative, terminated};
use super::{HIVE, KeyId, create_below_id, delete_value_of, set_value, status};
use nk_ntabi::status::*;

/// Run `with` on the key `relative_to` and `path` name, opened, or
/// made if `create` and it is not there (its parent must be). A key
/// given by handle is the caller's own and is used as it is.
///
/// # Safety
/// `path` is a key handle if `relative_to` says so, and else null or a
/// terminated string.
unsafe fn on_key(
    relative_to: u32,
    path: *const u16,
    create: bool,
    with: impl FnOnce(KeyId) -> NTSTATUS,
) -> NTSTATUS {
    // SAFETY: per the contract.
    let (start, rest) = match unsafe { relative(relative_to, path) } {
        Ok(found) => found,
        Err(status) => return status,
    };
    if by_handle(relative_to) {
        // Held to the end of the call: longer than the registry's lock.
        return with(start.key());
    }
    let key = if create {
        create_below_id(start.key(), &rest, &[]).map(|(key, _)| key)
    } else {
        let mut hive = HIVE.lock();
        let found = hive.open(start.key(), &rest).map_err(status);
        if let Ok(key) = found {
            hive.opened(key);
        }
        found
    };
    // The key the path starts at is let go of with the lock released.
    drop(start);
    match key {
        Ok(key) => {
            let status = with(key);
            HIVE.lock().closed(key);
            status
        }
        Err(status) => status,
    }
}

/// [`RtlCheckRegistryKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcheckregistrykey):
/// whether the key is there: `STATUS_SUCCESS`, or the status of
/// opening it. A handle is not looked at, as on Windows: the answer is
/// `STATUS_SUCCESS`.
///
/// # Safety
/// `path` is a key handle if `relative_to` says so, and else null or a
/// terminated string.
pub unsafe extern "C" fn RtlCheckRegistryKey(relative_to: u32, path: *const u16) -> NTSTATUS {
    if by_handle(relative_to) {
        return STATUS_SUCCESS;
    }
    // SAFETY: per the contract.
    unsafe { on_key(relative_to, path, false, |_| STATUS_SUCCESS) }
}

/// [`RtlCreateRegistryKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcreateregistrykey):
/// make the key if it is not there; the key it is made under must be.
/// A handle is not looked at, as on Windows.
///
/// # Safety
/// As [`RtlCheckRegistryKey`].
pub unsafe extern "C" fn RtlCreateRegistryKey(relative_to: u32, path: *const u16) -> NTSTATUS {
    if by_handle(relative_to) {
        return STATUS_SUCCESS;
    }
    // SAFETY: per the contract.
    unsafe { on_key(relative_to, path, true, |_| STATUS_SUCCESS) }
}

/// [`RtlWriteRegistryValue`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlwriteregistryvalue):
/// set a value of the key, which is made if it is not there. Whoever
/// watches the key is told, as for `ZwSetValueKey`.
///
/// # Safety
/// As [`RtlCheckRegistryKey`]; `value_name` is null or a terminated
/// string; `value_data` is readable for `value_length` bytes.
pub unsafe extern "C" fn RtlWriteRegistryValue(
    relative_to: u32,
    path: *const u16,
    value_name: *const u16,
    value_type: u32,
    value_data: *const u8,
    value_length: u32,
) -> NTSTATUS {
    // SAFETY: per the contract. Name and data are the driver's memory:
    // the registry is given copies, made before its lock is taken.
    let copies = unsafe {
        (
            terminated(value_name),
            crate::se::copied(value_data, value_length as usize),
        )
    };
    let (Some(name), Some(data)) = copies else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: per the contract.
    unsafe {
        on_key(relative_to, path, true, |key| {
            // The type's high byte is not part of it, as on Windows.
            set_value(key, &name, value_type & 0x00FF_FFFF, &data)
        })
    }
}

/// [`RtlDeleteRegistryValue`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtldeleteregistryvalue):
/// take a value away from the key. The key is made if it is not
/// there, as the pinned kernel's routine makes it, and the value is
/// then not found.
///
/// # Safety
/// As [`RtlCheckRegistryKey`]; `value_name` is null or a terminated
/// string.
pub unsafe extern "C" fn RtlDeleteRegistryValue(
    relative_to: u32,
    path: *const u16,
    value_name: *const u16,
) -> NTSTATUS {
    // SAFETY: per the contract.
    let Some(name) = (unsafe { terminated(value_name) }) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: per the contract.
    unsafe { on_key(relative_to, path, true, |key| delete_value_of(key, &name)) }
}
