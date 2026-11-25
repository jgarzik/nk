//! The registry, as drivers reach it: `ZwCreateKey`, `ZwOpenKey`,
//! `ZwQueryValueKey`, `ZwSetValueKey`.
//!
//! One tree in memory (`nk_cm`), under one lock. Nothing is loaded from
//! or saved to a hive file: the registry starts with the keys a driver
//! expects to find and holds what drivers put in it until the machine
//! stops. A key handle is a handle to a small object naming the key.

#![allow(non_snake_case)]

use crate::ke::{Rank, SpinLock};
use crate::ob::{handle, object};
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_cm::{Error, Fit, Hive, KeyId};
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::*;

static HIVE: SpinLock<Hive> = SpinLock::new(Rank::Registry, Hive::new());

/// `REG_CREATED_NEW_KEY`, `REG_OPENED_EXISTING_KEY`.
const CREATED: u32 = 1;
const OPENED: u32 = 2;
/// `KeyValueFullInformation`, `KeyValuePartialInformation`.
const FULL: u32 = 1;
const PARTIAL: u32 = 2;

/// The keys every Windows system has and drivers build on, which no
/// hive file is there to supply.
const INITIAL: &[&str] = &[
    "Machine",
    "Machine\\System",
    "Machine\\System\\CurrentControlSet",
    "Machine\\System\\CurrentControlSet\\Control",
    "Machine\\System\\CurrentControlSet\\Control\\Class",
    "Machine\\System\\CurrentControlSet\\Services",
    "User",
];

/// Make the registry's first keys.
pub fn init() -> Result<(), &'static str> {
    let mut hive = HIVE.lock();
    let root = hive.root().map_err(|_| "no memory for the registry")?;
    for path in INITIAL {
        let path: Vec<u16> = path.encode_utf16().collect();
        hive.create(root, &path)
            .map_err(|_| "the registry's first keys could not be made")?;
    }
    Ok(())
}

/// The pool memory the registry holds, as `(blocks, bytes)`: it keeps
/// what drivers write to it, which a leak check must not count as lost.
pub fn storage() -> (usize, usize) {
    HIVE.lock().storage()
}

fn status(error: Error) -> NTSTATUS {
    match error {
        Error::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
        Error::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
        Error::Deleted => STATUS_KEY_DELETED,
        Error::HasSubkeys => STATUS_CANNOT_DELETE,
    }
}

/// The key a key handle names.
fn key_of(handle: *mut c_void) -> Result<KeyId, NTSTATUS> {
    let body = handle::reference(handle as u64, Some(&raw const object::KEY_TYPE))?;
    // SAFETY: a key object, referenced by the look-up: its body is the
    // key's number, written once when it was made.
    unsafe {
        let key = KeyId::from_index(body.cast::<usize>().read());
        object::dereference(body);
        Ok(key)
    }
}

/// Where the name in `attributes` starts (`None`: at the root), and
/// the path from there. Reads the driver's memory and resolves its
/// handle, so it is called before the registry's lock is taken.
///
/// # Safety
/// `attributes` points to an `OBJECT_ATTRIBUTES` whose name is null or
/// a counted string.
unsafe fn named(
    attributes: *const OBJECT_ATTRIBUTES,
) -> Result<(Option<KeyId>, Vec<u16>), NTSTATUS> {
    if attributes.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: per the contract; the structure is the driver's, read
    // field by field.
    let (root, mut path) = unsafe {
        (
            (&raw const (*attributes).RootDirectory).read_unaligned(),
            crate::rtl::copy_unicode((&raw const (*attributes).ObjectName).read_unaligned()),
        )
    };
    if !root.is_null() {
        // Relative to an open key; such a name does not start at `\`.
        if path.first() == Some(&u16::from(b'\\')) {
            return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        return Ok((Some(key_of(root)?), path));
    }
    if path.first() != Some(&u16::from(b'\\')) {
        return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
    }
    // An absolute name that leads elsewhere in the namespace names no
    // key.
    let below = nk_cm::below_root(&path)
        .ok_or(STATUS_OBJECT_TYPE_MISMATCH)?
        .len();
    path.drain(..path.len() - below);
    Ok((None, path))
}

/// The key a name from [`named`] starts at.
fn start_of(hive: &mut Hive, start: Option<KeyId>) -> Result<KeyId, NTSTATUS> {
    match start {
        Some(key) => Ok(key),
        None => hive.root().map_err(status),
    }
}

/// A handle to `key`, which the caller has counted as opened
/// (`Hive::opened`) under the lock it found the key under; the count is
/// given back if no handle can be made.
fn open(key: KeyId) -> Result<*mut c_void, NTSTATUS> {
    let Some(body) = object::create(&object::KEY_TYPE, size_of::<usize>()) else {
        HIVE.lock().closed(key);
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    };
    // SAFETY: a fresh object of that size; the handle takes its own
    // reference and the creating one is given up.
    unsafe {
        body.cast::<usize>().write(key.index());
        let handle = handle::open(body);
        object::dereference(body);
        Ok(handle as *mut c_void)
    }
}

/// The object manager's call when the last reference to a key object
/// has gone: the key has one handle fewer.
///
/// # Safety
/// `body` is a key object nothing refers to any more.
pub unsafe fn closed(body: *mut u8) {
    // SAFETY: per the contract: the body is the key's number.
    let key = KeyId::from_index(unsafe { body.cast::<usize>().read() });
    HIVE.lock().closed(key);
}

/// Make sure the service key of a driver being loaded exists
/// (`...\Services\<name>`), as the service control manager would have
/// made it on Windows: a driver may keep its settings under it.
pub fn service_key(name: &str) -> Result<(), &'static str> {
    let path: Vec<u16> = alloc::format!("Machine\\System\\CurrentControlSet\\Services\\{name}")
        .encode_utf16()
        .collect();
    let mut hive = HIVE.lock();
    let root = hive.root().map_err(|_| "no memory for the registry")?;
    hive.create(root, &path)
        .map(|_| ())
        .map_err(|_| "no service key")
}

/// [`ZwDeleteKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwdeletekey):
/// delete an open key that has no subkeys. It is gone by name at once;
/// handles still open to it, this one included, are good only for
/// closing.
pub extern "C" fn ZwDeleteKey(key_handle: *mut c_void) -> NTSTATUS {
    let key = match key_of(key_handle) {
        Ok(key) => key,
        Err(status) => return status,
    };
    match HIVE.lock().delete(key) {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => status(error),
    }
}

/// [`ZwOpenKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkey).
/// There are no access checks: the desired access is not looked at.
///
/// # Safety
/// `key_handle` is writable; `attributes` points to an
/// `OBJECT_ATTRIBUTES`.
pub unsafe extern "C" fn ZwOpenKey(
    key_handle: *mut *mut c_void,
    _desired_access: u32,
    attributes: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    // SAFETY: per the contract.
    let found = unsafe { named(attributes) }.and_then(|(start, path)| {
        let mut hive = HIVE.lock();
        let start = start_of(&mut hive, start)?;
        let key = hive.open(start, &path).map_err(status)?;
        hive.opened(key);
        Ok(key)
    });
    match found.and_then(open) {
        Ok(handle) => {
            // SAFETY: per the contract.
            unsafe { key_handle.write_unaligned(handle) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// [`ZwCreateKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatekey):
/// open a key, making it if it is not there. Every key lives in memory,
/// so the options (volatile or not) change nothing; the class is not
/// kept.
///
/// # Safety
/// `key_handle` is writable; `attributes` points to an
/// `OBJECT_ATTRIBUTES`; `disposition` is null or writable.
pub unsafe extern "C" fn ZwCreateKey(
    key_handle: *mut *mut c_void,
    _desired_access: u32,
    attributes: *const OBJECT_ATTRIBUTES,
    _title_index: u32,
    _class: *const UNICODE_STRING,
    _create_options: u32,
    disposition: *mut u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    let made = unsafe { named(attributes) }.and_then(|(start, path)| {
        let mut hive = HIVE.lock();
        let start = start_of(&mut hive, start)?;
        let (key, new) = hive.create(start, &path).map_err(status)?;
        hive.opened(key);
        Ok((key, new))
    });
    match made.and_then(|(key, new)| Ok((open(key)?, new))) {
        Ok((handle, new)) => {
            // SAFETY: per the contract.
            unsafe {
                key_handle.write_unaligned(handle);
                if !disposition.is_null() {
                    disposition.write_unaligned(if new { CREATED } else { OPENED });
                }
            }
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// [`ZwSetValueKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwsetvaluekey).
///
/// # Safety
/// `value_name` is null or a counted string; `data` is readable for
/// `data_size` bytes.
pub unsafe extern "C" fn ZwSetValueKey(
    key_handle: *mut c_void,
    value_name: *const UNICODE_STRING,
    _title_index: u32,
    kind: u32,
    data: *const u8,
    data_size: u32,
) -> NTSTATUS {
    let key = match key_of(key_handle) {
        Ok(key) => key,
        Err(status) => return status,
    };
    // SAFETY: per the contract. Name and data are the driver's memory:
    // the registry is given copies.
    let (name, data) = unsafe {
        let Some(data) = crate::se::copied(data, data_size as usize) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        (crate::rtl::copy_unicode(value_name), data)
    };
    match HIVE.lock().set_value(key, &name, kind, &data) {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => status(error),
    }
}

/// [`ZwQueryValueKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwqueryvaluekey),
/// for `KeyValueFullInformation` (name, type and data) and
/// `KeyValuePartialInformation` (type and data). The other forms are
/// not implemented.
///
/// # Safety
/// `value_name` is null or a counted string; `information` is writable
/// for `length` bytes and `result_length` for four.
pub unsafe extern "C" fn ZwQueryValueKey(
    key_handle: *mut c_void,
    value_name: *const UNICODE_STRING,
    class: u32,
    information: *mut u8,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    if class != PARTIAL && class != FULL {
        return STATUS_NOT_IMPLEMENTED;
    }
    let key = match key_of(key_handle) {
        Ok(key) => key,
        Err(status) => return status,
    };
    // SAFETY: per the contract.
    let name = unsafe { crate::rtl::copy_unicode(value_name) };
    // The answer is put together in the kernel's own memory, under the
    // lock, and copied to the driver's afterwards.
    let answer = {
        let hive = HIVE.lock();
        let (stored_name, kind, data) = match hive.value(key, &name) {
            Ok(value) => value,
            Err(error) => return status(error),
        };
        // Sized first, with no room at all, so that the copy made is
        // no larger than the answer.
        let write = |out: &mut [u8]| match class {
            FULL => nk_cm::full_information(stored_name, kind, data, out),
            _ => nk_cm::partial_information(kind, data, out),
        };
        let room = (length as usize).min(write(&mut []).1);
        let mut out = Vec::new();
        if out.try_reserve_exact(room).is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        out.resize(room, 0);
        let (fit, needed) = write(&mut out);
        (fit, needed, out)
    };
    let (fit, needed, out) = answer;
    // SAFETY: per the contract; `out` is no longer than `length`.
    unsafe {
        result_length.write_unaligned(needed as u32);
        match fit {
            Fit::Nothing => return STATUS_BUFFER_TOO_SMALL,
            Fit::All | Fit::Part => {
                for (i, &byte) in out.iter().enumerate() {
                    information.add(i).write(byte);
                }
            }
        }
    }
    match fit {
        Fit::All => STATUS_SUCCESS,
        _ => STATUS_BUFFER_OVERFLOW,
    }
}
