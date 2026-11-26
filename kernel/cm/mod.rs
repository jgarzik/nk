//! The registry, as drivers reach it: `ZwCreateKey`, `ZwOpenKey`,
//! `ZwDeleteKey`, `ZwEnumerateKey`, `ZwEnumerateValueKey`, `ZwQueryKey`,
//! `ZwQueryValueKey`, `ZwSetValueKey`, `ZwDeleteValueKey`, and the
//! query tables of `RtlQueryRegistryValues` (`table.rs`).
//!
//! One tree in memory (`nk_cm`), under one lock. It starts with the
//! keys every system has and, laid over `Machine\System`, the SYSTEM
//! hive the loader read, if it read one; it holds what drivers put in
//! it until the machine stops. Nothing is written back to a hive file.
//! `CurrentControlSet` is a symbolic link to the control set the hive
//! selects. A key handle is a handle to a small object naming the key.
//!
//! The registry's root is such an object too, called `\Registry` in the
//! object namespace. An absolute name is looked up there like any
//! other; the look-up ends at the root key, and the rest of the path is
//! the registry's to walk.

#![allow(non_snake_case)]

mod table;

pub use table::{RtlQueryRegistryValues, RtlQueryRegistryValuesEx};

use crate::ke::{Rank, SpinLock};
use crate::ob::{handle, object};
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_cm::regf::{Regf, RegfError};
use nk_cm::services::OrderError;
use nk_cm::{Error, Fit, Hive, ImportError, KeyId};
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::*;

static HIVE: SpinLock<Hive> = SpinLock::new(Rank::Registry, Hive::new());

/// `REG_CREATED_NEW_KEY`, `REG_OPENED_EXISTING_KEY`.
const CREATED: u32 = 1;
const OPENED: u32 = 2;
/// `KEY_INFORMATION_CLASS`: the forms a key is described in.
const KEY_BASIC: u32 = 0;
const KEY_NODE: u32 = 1;
const KEY_FULL: u32 = 2;
const KEY_NAME: u32 = 3;
const KEY_CACHED: u32 = 4;
const KEY_FLAGS: u32 = 5;
const KEY_VIRTUALIZATION: u32 = 6;
const KEY_HANDLE_TAGS: u32 = 7;
/// The last form this build of Windows has: `KeyLayerInformation`, the
/// next in the header, is refused like a number that names none.
const KEY_TRUST: u32 = 8;
/// `KEY_VIRTUALIZATION_INFORMATION`: its five flags; 27 bits are
/// reserved.
const VIRTUALIZATION_FLAGS: u32 = 0x1F;
/// `KEY_TRUST_INFORMATION.TrustedKey`: the key is in a hive the system
/// trusts; 31 bits are reserved.
const TRUSTED_KEY: u32 = 1;
/// `KEY_VALUE_INFORMATION_CLASS`: the forms a value is described in.
const VALUE_BASIC: u32 = 0;
const FULL: u32 = 1;
const PARTIAL: u32 = 2;
const VALUE_FULL_ALIGN64: u32 = 3;
const VALUE_PARTIAL_ALIGN64: u32 = 4;

/// `REG_DWORD`.
const REG_DWORD: u32 = 4;

/// The keys every Windows system has before any hive is read, spelled
/// as Windows spells them: a key's full name (`KeyNameInformation`)
/// shows the letter case each was made in.
const SKELETON: &[&str] = &[
    "MACHINE",
    "MACHINE\\HARDWARE",
    "MACHINE\\SYSTEM",
    "MACHINE\\SYSTEM\\Select",
    "USER",
];

/// `Select`'s values on a system that has always booted its first
/// control set (what Windows 10 holds after a clean installation): a
/// hive's own replace them.
const SELECT: &[(&str, u32)] = &[
    ("Current", 1),
    ("Default", 1),
    ("Failed", 0),
    ("LastKnownGood", 1),
];

/// The keys drivers and the kernel build on in the current control
/// set, which no hive need supply.
const CONTROL_SET: &[&str] = &["", "\\Control", "\\Control\\Class", "\\Services"];

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// The time a change to the registry is stamped with: now. A key's
/// last write time is when its values or its list of subkeys last
/// changed; a key copied from a hive file keeps the file's.
fn now() -> u64 {
    crate::ke::time::system_time()
}

/// Stamp `key`, just made, and the key it was made under, whose list
/// of subkeys changed with it.
fn stamp_new(hive: &mut Hive, key: KeyId, time: u64) -> Result<(), Error> {
    hive.set_last_write(key, time)?;
    let parent = hive.parent(key)?;
    hive.set_last_write(parent, time)
}

/// Why a hive file was refused, for the boot log.
fn refusal(error: ImportError) -> &'static str {
    match error {
        ImportError::File(RegfError::Dirty) => {
            "the SYSTEM hive was not written out completely: its log would have to be replayed"
        }
        ImportError::File(RegfError::Corrupt) => "the SYSTEM hive's checksum is wrong",
        ImportError::File(RegfError::NotRegf) => "the SYSTEM hive is not a hive file",
        ImportError::File(_) => "the SYSTEM hive is malformed",
        ImportError::Tree(_) => "no memory for the SYSTEM hive",
    }
}

/// Build the registry in `hive`: the keys every system has, the SYSTEM
/// hive `file` laid over `Machine\System` if there is one, and
/// `CurrentControlSet`, a symbolic link to the control set
/// `Select\Current` names, as on Windows. Returns the root.
fn build(hive: &mut Hive, file: Option<&[u8]>) -> Result<KeyId, &'static str> {
    const NO_MEMORY: &str = "no memory for the registry";
    let now = now();
    // Make a key if it is not there, stamped as made now.
    let make = |hive: &mut Hive, from: KeyId, path: &str| {
        let (key, new) = hive.create(from, &wide(path))?;
        if new {
            stamp_new(hive, key, now)?;
        }
        Ok::<KeyId, Error>(key)
    };
    let root = hive.root().map_err(|_| NO_MEMORY)?;
    for path in SKELETON {
        make(hive, root, path).map_err(|_| NO_MEMORY)?;
    }
    let system = hive
        .open(root, &wide("Machine\\System"))
        .map_err(|_| NO_MEMORY)?;
    let select = hive.open(system, &wide("Select")).map_err(|_| NO_MEMORY)?;
    for (name, number) in SELECT {
        hive.set_value(select, &wide(name), REG_DWORD, &number.to_le_bytes())
            .map_err(|_| NO_MEMORY)?;
    }
    if let Some(file) = file {
        // A hive that is damaged, or needs its log, is not half used.
        let regf = Regf::parse(file).map_err(|e| refusal(e.into()))?;
        nk_cm::import(hive, system, &regf).map_err(refusal)?;
    }
    let current = match hive.value(select, &wide("Current")) {
        Ok((_, REG_DWORD, &[a, b, c, d])) => u32::from_le_bytes([a, b, c, d]),
        _ => return Err("Select\\Current does not name a control set"),
    };
    let set = alloc::format!("ControlSet{current:03}");
    for below in CONTROL_SET {
        make(hive, system, &alloc::format!("{set}{below}")).map_err(|_| NO_MEMORY)?;
    }
    let link = make(hive, system, "CurrentControlSet").map_err(|_| NO_MEMORY)?;
    hive.link_to(
        link,
        &wide(&alloc::format!("\\Registry\\Machine\\System\\{set}")),
    )
    .map_err(|_| NO_MEMORY)?;
    Ok(root)
}

/// Make the registry, from the SYSTEM hive the loader read if it read
/// one (`doc/BOOT.md`), and name its root `\Registry`. A hive that
/// cannot be used fails the boot.
pub fn init() -> Result<(), &'static str> {
    const NO_MEMORY: &str = "no memory for the registry";
    let file = crate::ldr::boot_file(nk_bootinfo::HIVE_MODULE);
    let root = {
        let mut hive = HIVE.lock();
        let root = build(&mut hive, file)?;
        // The key object made below counts as an open of the root.
        hive.opened(root);
        root
    };
    kprintln!(
        "cm: registry {}",
        match file {
            Some(file) => alloc::format!("from the SYSTEM hive ({} bytes)", file.len()),
            None => "without a hive".into(),
        }
    );
    let path: Vec<u16> = "\\Registry".encode_utf16().collect();
    let body = object::create_named(
        &object::KEY_TYPE,
        size_of::<usize>(),
        crate::ob::leaf(&path),
    )
    .ok_or(NO_MEMORY)?;
    // SAFETY: a fresh named key object of that size, made to be called
    // `Registry`; it keeps its name and its reference for ever.
    let named = unsafe {
        body.cast::<usize>().write(root.index());
        crate::ob::insert(&path, body)
    };
    match named {
        STATUS_SUCCESS => Ok(()),
        _ => Err("the registry's root could not be named"),
    }
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

/// The key the name in `attributes` starts at, and the path from
/// there. An absolute name, or one relative to a directory, is looked
/// up in the object namespace, where it must lead to a key: the
/// registry's root, with the rest of the path left over. A name
/// relative to an open key starts at that key.
///
/// Reads the driver's memory and resolves its handle, so it is called
/// before the registry's lock is taken.
///
/// # Safety
/// `attributes` points to an `OBJECT_ATTRIBUTES` whose name is null or
/// a counted string.
unsafe fn named(attributes: *const OBJECT_ATTRIBUTES) -> Result<(KeyId, Vec<u16>), NTSTATUS> {
    if attributes.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    // SAFETY: per the contract; the structure is the driver's, read
    // field by field.
    let (root, path) = unsafe {
        (
            (&raw const (*attributes).RootDirectory).read_unaligned(),
            crate::rtl::copy_unicode((&raw const (*attributes).ObjectName).read_unaligned()),
        )
    };
    if root.is_null() {
        return absolute(&path);
    }
    let root = handle::reference(root as u64, None)?;
    let (body, path) = if is(root, &object::DIRECTORY_TYPE) {
        let found = crate::ob::lookup(Some(root), &path);
        // SAFETY: the reference taken above.
        unsafe { object::dereference(root) };
        found?
    } else if path.first() == Some(&u16::from(b'\\')) {
        // Relative to an open object: not from the top.
        // SAFETY: the reference taken above.
        unsafe { object::dereference(root) };
        return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
    } else {
        (root, path)
    };
    // SAFETY: the reference the look-up or the handle gave.
    Ok((unsafe { key_object(body) }?, path))
}

/// Whether the object `body` is of the type `ty`.
fn is(body: *mut u8, ty: &'static object::ObjectType) -> bool {
    // SAFETY: called with objects the caller holds a reference to.
    core::ptr::eq(unsafe { object::type_of(body) }, ty)
}

/// The key the object `body` is. What leads elsewhere in the namespace
/// names no key.
///
/// # Safety
/// The caller holds a reference to `body`, which is given up here.
unsafe fn key_object(body: *mut u8) -> Result<KeyId, NTSTATUS> {
    // SAFETY: per the contract; a key object's body is the key's
    // number, written once when it was made.
    unsafe {
        let key =
            is(body, &object::KEY_TYPE).then(|| KeyId::from_index(body.cast::<usize>().read()));
        object::dereference(body);
        key.ok_or(STATUS_OBJECT_TYPE_MISMATCH)
    }
}

/// The key the absolute name `path` starts at, and the path from
/// there: the name is looked up in the object namespace, where it must
/// lead to a key, the registry's root, with the rest of the path left
/// over.
fn absolute(path: &[u16]) -> Result<(KeyId, Vec<u16>), NTSTATUS> {
    let (body, rest) = crate::ob::lookup(None, path)?;
    // SAFETY: the reference the look-up took.
    Ok((unsafe { key_object(body) }?, rest))
}

/// A handle to `key`, granted `access`. The caller has counted the key
/// as opened (`Hive::opened`) under the lock it found the key under;
/// the count is given back if no handle can be made.
fn open(key: KeyId, access: u32) -> Result<*mut c_void, NTSTATUS> {
    let Some(body) = object::create(&object::KEY_TYPE, size_of::<usize>()) else {
        HIVE.lock().closed(key);
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    };
    // SAFETY: a fresh object of that size; the handle takes its own
    // reference and the creating one is given up, which without a
    // handle ends the object and gives the key's count back.
    unsafe {
        body.cast::<usize>().write(key.index());
        let handle = handle::open(body, access);
        object::dereference(body);
        handle.map(|handle| handle as *mut c_void)
    }
}

/// The object manager's call when the last reference to a key object
/// has gone: the key has one handle fewer.
///
/// # Safety
/// `body` is a key object nothing refers to any more.
pub unsafe extern "C" fn closed(body: *mut c_void) {
    // SAFETY: per the contract: the body is the key's number.
    let key = KeyId::from_index(unsafe { body.cast::<usize>().read() });
    HIVE.lock().closed(key);
}

/// Give the key at `path` (from the registry's root; its parent
/// exists) the `values`, each a name, a type and data, creating the key
/// if it is not there. For the kernel's own use.
pub fn write(path: &str, values: &[(&str, u32, &[u8])]) -> Result<(), NTSTATUS> {
    let path: Vec<u16> = path.encode_utf16().collect();
    let now = now();
    let mut hive = HIVE.lock();
    let root = hive.root().map_err(status)?;
    let (key, new) = hive.create(root, &path).map_err(status)?;
    if new {
        stamp_new(&mut hive, key, now).map_err(status)?;
    }
    for (name, kind, data) in values {
        let name: Vec<u16> = name.encode_utf16().collect();
        hive.set_value(key, &name, *kind, data).map_err(status)?;
        hive.set_last_write(key, now).map_err(status)?;
    }
    Ok(())
}

/// The type and data of the value `name` of the key at `path` (from
/// the registry's root). For the kernel's own use.
pub fn read(path: &str, name: &str) -> Result<(u32, Vec<u8>), NTSTATUS> {
    let path: Vec<u16> = path.encode_utf16().collect();
    let name: Vec<u16> = name.encode_utf16().collect();
    let mut hive = HIVE.lock();
    let root = hive.root().map_err(status)?;
    let key = hive.open(root, &path).map_err(status)?;
    let (_, kind, data) = hive.value(key, &name).map_err(status)?;
    let mut copy = Vec::new();
    copy.try_reserve_exact(data.len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    copy.extend_from_slice(data);
    Ok((kind, copy))
}

/// The driver services the current control set starts at boot, in the
/// order they start (`nk_cm::services::boot_start`): each one's name
/// and its `ErrorControl`. For the kernel's own use.
pub fn boot_start() -> Result<Vec<(String, u32)>, &'static str> {
    const NO_MEMORY: &str = "no memory for the list of boot-start services";
    let mut hive = HIVE.lock();
    let root = hive.root().map_err(|_| NO_MEMORY)?;
    let set = hive
        .open(root, &wide("Machine\\System\\CurrentControlSet"))
        .map_err(|_| "there is no current control set")?;
    let keys = nk_cm::services::boot_start(&hive, set).map_err(|error| match error {
        OrderError::NoMemory => NO_MEMORY,
        OrderError::Cycle(_) => "boot-start services depend on each other in a circle",
    })?;
    let mut services = Vec::new();
    services
        .try_reserve_exact(keys.len())
        .map_err(|_| NO_MEMORY)?;
    for key in keys {
        let name = hive.info(key).map_or(&[][..], |info| info.name);
        // `SERVICE_ERROR_NORMAL` where the key does not say.
        let error_control = match hive.value(key, &wide("ErrorControl")) {
            Ok((_, REG_DWORD, &[a, b, c, d])) => u32::from_le_bytes([a, b, c, d]),
            _ => 1,
        };
        services.push((String::from_utf16_lossy(name), error_control));
    }
    Ok(services)
}

/// How many handles are open to the key at `path` (from the
/// registry's root), a query table at work counting as one; `None` if
/// there is no such key. For the tests.
pub fn open_count(path: &str) -> Option<u32> {
    let path = wide(path);
    let mut hive = HIVE.lock();
    let root = hive.root().ok()?;
    let key = hive.open(root, &path).ok()?;
    hive.handles(key).ok()
}

/// Whether there is a key at `path` (from the registry's root). For
/// the kernel's own use.
pub fn exists(path: &str) -> bool {
    let path = wide(path);
    let mut hive = HIVE.lock();
    hive.root().is_ok_and(|root| hive.open(root, &path).is_ok())
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
    let now = now();
    let mut hive = HIVE.lock();
    // The key it was a subkey of has changed with it.
    let deleted = hive.parent(key).and_then(|parent| {
        hive.delete(key)?;
        hive.set_last_write(parent, now)
    });
    match deleted {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => status(error),
    }
}

/// [`ZwOpenKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwopenkey).
/// There are no access checks: the handle is granted the access asked
/// for.
///
/// # Safety
/// `key_handle` is writable; `attributes` points to an
/// `OBJECT_ATTRIBUTES`.
pub unsafe extern "C" fn ZwOpenKey(
    key_handle: *mut *mut c_void,
    desired_access: u32,
    attributes: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    // SAFETY: per the contract.
    let found = unsafe { named(attributes) }.and_then(|(start, path)| {
        let mut hive = HIVE.lock();
        let key = hive.open(start, &path).map_err(status)?;
        hive.opened(key);
        Ok(key)
    });
    match found.and_then(|key| open(key, desired_access)) {
        Ok(handle) => {
            // SAFETY: per the contract.
            unsafe { key_handle.write_unaligned(handle) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// The bytes of the counted string `class`; none if it is null.
/// `None` without memory for them.
///
/// # Safety
/// `class` is null or points to a counted string.
unsafe fn class_of(class: *const UNICODE_STRING) -> Option<Vec<u8>> {
    if class.is_null() {
        return Some(Vec::new());
    }
    // SAFETY: per the contract; the structure is the driver's, read
    // field by field.
    unsafe {
        let buffer = (&raw const (*class).Buffer).read_unaligned();
        let length = (&raw const (*class).Length).read_unaligned();
        crate::se::copied(buffer.cast(), usize::from(length))
    }
}

/// [`ZwCreateKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatekey):
/// open a key, making it if it is not there. A new key is given the
/// class; one that exists keeps its own. Every key lives in memory, so
/// the options (volatile or not) change nothing.
///
/// # Safety
/// `key_handle` is writable; `attributes` points to an
/// `OBJECT_ATTRIBUTES`; `class` is null or a counted string;
/// `disposition` is null or writable.
pub unsafe extern "C" fn ZwCreateKey(
    key_handle: *mut *mut c_void,
    desired_access: u32,
    attributes: *const OBJECT_ATTRIBUTES,
    _title_index: u32,
    class: *const UNICODE_STRING,
    _create_options: u32,
    disposition: *mut u32,
) -> NTSTATUS {
    // SAFETY: per the contract. The class is the driver's memory: the
    // registry is given a copy, made before its lock is taken.
    let Some(class) = (unsafe { class_of(class) }) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: per the contract.
    let made = unsafe { named(attributes) }.and_then(|(start, path)| {
        let now = now();
        let mut hive = HIVE.lock();
        let (key, new) = hive.create(start, &path).map_err(status)?;
        if new {
            let classed = hive.set_class(key, &class);
            if let Err(error) = classed.and_then(|()| stamp_new(&mut hive, key, now)) {
                // Without its class it is not the key that was asked
                // for: nothing has seen it yet, and it has no subkeys.
                let _ = hive.delete(key);
                return Err(status(error));
            }
        }
        hive.opened(key);
        Ok((key, new))
    });
    match made.and_then(|(key, new)| Ok((open(key, desired_access)?, new))) {
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
    let now = now();
    let mut hive = HIVE.lock();
    let set = hive.set_value(key, &name, kind, &data);
    match set.and_then(|()| hive.set_last_write(key, now)) {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => status(error),
    }
}

/// [`ZwDeleteValueKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwdeletevaluekey):
/// take a value away from a key. The values after it move up one place
/// in the order they are enumerated in; set again, the value is the
/// key's last.
///
/// # Safety
/// `value_name` is null or a counted string.
pub unsafe extern "C" fn ZwDeleteValueKey(
    key_handle: *mut c_void,
    value_name: *const UNICODE_STRING,
) -> NTSTATUS {
    let key = match key_of(key_handle) {
        Ok(key) => key,
        Err(status) => return status,
    };
    // SAFETY: per the contract. The name is the driver's memory: the
    // registry is given a copy.
    let name = unsafe { crate::rtl::copy_unicode(value_name) };
    let now = now();
    let mut hive = HIVE.lock();
    let deleted = hive.delete_value(key, &name);
    match deleted.and_then(|()| hive.set_last_write(key, now)) {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => status(error),
    }
}

/// Answer a query for an information structure. `format` writes the
/// structure into the buffer it is given, holding the registry's lock
/// while it does, and says how much fitted and how long the whole is;
/// or it fails, and the caller's memory is left as it was.
///
/// The structure is laid over a copy of what the caller's buffer holds
/// and the copy is written back: the bytes a structure leaves alone
/// (between a name and what is aligned after it) keep the caller's
/// values, as on Windows. The caller's memory is read and written with
/// the lock released, so the structure is formatted again if the
/// registry changed its length meanwhile.
///
/// # Safety
/// `information` is readable and writable for `length` bytes and
/// `result_length` writable for four.
unsafe fn inform(
    information: *mut u8,
    length: u32,
    result_length: *mut u32,
    mut format: impl FnMut(&mut [u8]) -> Result<(Fit, usize), NTSTATUS>,
) -> NTSTATUS {
    let mut out = Vec::new();
    let (fit, needed) = loop {
        let (fit, needed) = match format(&mut out) {
            Ok(answer) => answer,
            Err(status) => return status,
        };
        let room = (length as usize).min(needed);
        if out.len() == room {
            break (fit, needed);
        }
        out.clear();
        if out.try_reserve_exact(room).is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        // SAFETY: per the contract; `room` is at most `length`.
        out.extend((0..room).map(|i| unsafe { information.add(i).read() }));
    };
    // SAFETY: per the contract; `out` is no longer than `length`.
    unsafe {
        result_length.write_unaligned(needed as u32);
        if fit != Fit::Nothing {
            for (i, &byte) in out.iter().enumerate() {
                information.add(i).write(byte);
            }
        }
    }
    match fit {
        Fit::All => STATUS_SUCCESS,
        Fit::Part => STATUS_BUFFER_OVERFLOW,
        Fit::Nothing => STATUS_BUFFER_TOO_SMALL,
    }
}

/// Write a key in the form `class`, one of [`KEY_BASIC`], [`KEY_NODE`]
/// and [`KEY_FULL`].
fn key_information(class: u32, key: &nk_cm::KeyInfo<'_>, out: &mut [u8]) -> (Fit, usize) {
    match class {
        KEY_BASIC => nk_cm::key_basic_information(key, out),
        KEY_NODE => nk_cm::key_node_information(key, out),
        _ => nk_cm::key_full_information(key, out),
    }
}

/// Write a value in the form `class`, one of the five up to
/// [`VALUE_PARTIAL_ALIGN64`]. The full form's data start at a multiple
/// of eight bytes in either of its classes.
fn value_information(
    class: u32,
    name: &[u16],
    kind: u32,
    data: &[u8],
    out: &mut [u8],
) -> (Fit, usize) {
    match class {
        VALUE_BASIC => nk_cm::value_basic_information(name, kind, out),
        FULL | VALUE_FULL_ALIGN64 => nk_cm::full_information(name, kind, data, out),
        PARTIAL => nk_cm::partial_information(kind, data, out),
        _ => nk_cm::partial_align64_information(kind, data, out),
    }
}

/// [`ZwEnumerateKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwenumeratekey):
/// describe subkey `index` of a key, counting in the order of the
/// subkeys' names, letter case disregarded. A subkey is described in
/// the basic, node and full forms only, as on Windows; past the last,
/// `STATUS_NO_MORE_ENTRIES`, whatever the buffer.
///
/// # Safety
/// `information` is readable and writable for `length` bytes and
/// `result_length` writable for four.
pub unsafe extern "C" fn ZwEnumerateKey(
    key_handle: *mut c_void,
    index: u32,
    class: u32,
    information: *mut u8,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    if class > KEY_FULL {
        return STATUS_INVALID_PARAMETER;
    }
    let key = match key_of(key_handle) {
        Ok(key) => key,
        Err(status) => return status,
    };
    let format = |out: &mut [u8]| {
        let hive = HIVE.lock();
        let subkey = hive
            .subkey(key, index as usize)
            .map_err(status)?
            .ok_or(STATUS_NO_MORE_ENTRIES)?;
        let info = hive.info(subkey).map_err(status)?;
        Ok(key_information(class, &info, out))
    };
    // SAFETY: per the contract.
    unsafe { inform(information, length, result_length, format) }
}

/// [`ZwQueryKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwquerykey):
/// describe an open key, in every form of `KEY_INFORMATION_CLASS`.
///
/// The name form gives the key's full name from `\REGISTRY`, each part
/// in the letter case it was created in and with any symbolic link
/// followed: the key the handle is open to, not the path it was opened
/// by. The cached form is the counts of the full form and the length
/// of the key's name, without the name: 40 bytes are wanted, the size
/// of the structure, and 36 written.
///
/// The forms that describe what NK has none of answer as Windows does
/// for a key without it: no flags (there are no 32-bit programs to
/// redirect and no keys that must stay), no virtualization, no handle
/// tags. Every key is trusted: the registry holds the system's own hive
/// and nothing a user loaded. Virtualization and trust are words of bit
/// fields, of which Windows writes the flags and leaves the reserved
/// bits as the caller had them. There is no layer form
/// (`KeyLayerInformation`): Windows 10 refuses it,
/// `STATUS_INVALID_PARAMETER`.
///
/// # Safety
/// `information` is readable and writable for `length` bytes and
/// `result_length` writable for four.
pub unsafe extern "C" fn ZwQueryKey(
    key_handle: *mut c_void,
    class: u32,
    information: *mut u8,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    if class > KEY_TRUST {
        return STATUS_INVALID_PARAMETER;
    }
    let key = match key_of(key_handle) {
        Ok(key) => key,
        Err(status) => return status,
    };
    let format = |out: &mut [u8]| {
        let hive = HIVE.lock();
        let info = hive.info(key).map_err(status)?;
        Ok(match class {
            KEY_BASIC | KEY_NODE | KEY_FULL => key_information(class, &info, out),
            KEY_NAME => nk_cm::key_name_information(&hive.path(key).map_err(status)?, out),
            KEY_CACHED => nk_cm::key_cached_information(&info, out),
            // `KEY_FLAGS_INFORMATION`: three words.
            KEY_FLAGS => nk_cm::fixed_information(&[0, 0, 0], out),
            KEY_VIRTUALIZATION => nk_cm::flag_information(0, VIRTUALIZATION_FLAGS, out),
            KEY_HANDLE_TAGS => nk_cm::fixed_information(&[0], out),
            _ => nk_cm::flag_information(TRUSTED_KEY, TRUSTED_KEY, out),
        })
    };
    // SAFETY: per the contract.
    unsafe { inform(information, length, result_length, format) }
}

/// [`ZwEnumerateValueKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwenumeratevaluekey):
/// describe value `index` of a key, counting in the order the values
/// were first set. Past the last, `STATUS_NO_MORE_ENTRIES`, whatever
/// the buffer. There are no layered keys, and a value is not described
/// as part of one (`KeyValueLayerInformation`).
///
/// # Safety
/// `information` is readable and writable for `length` bytes and
/// `result_length` writable for four.
pub unsafe extern "C" fn ZwEnumerateValueKey(
    key_handle: *mut c_void,
    index: u32,
    class: u32,
    information: *mut u8,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    if class > VALUE_PARTIAL_ALIGN64 {
        return STATUS_INVALID_PARAMETER;
    }
    let key = match key_of(key_handle) {
        Ok(key) => key,
        Err(status) => return status,
    };
    let format = |out: &mut [u8]| {
        let hive = HIVE.lock();
        let (name, kind, data) = hive
            .value_at(key, index as usize)
            .map_err(status)?
            .ok_or(STATUS_NO_MORE_ENTRIES)?;
        Ok(value_information(class, name, kind, data, out))
    };
    // SAFETY: per the contract.
    unsafe { inform(information, length, result_length, format) }
}

/// [`ZwQueryValueKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwqueryvaluekey):
/// describe the value of that name, in the forms `ZwEnumerateValueKey`
/// has. The name is matched whatever its letter case and reported as
/// it was set.
///
/// # Safety
/// `value_name` is null or a counted string; `information` is readable
/// and writable for `length` bytes and `result_length` writable for
/// four.
pub unsafe extern "C" fn ZwQueryValueKey(
    key_handle: *mut c_void,
    value_name: *const UNICODE_STRING,
    class: u32,
    information: *mut u8,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    if class > VALUE_PARTIAL_ALIGN64 {
        return STATUS_INVALID_PARAMETER;
    }
    let key = match key_of(key_handle) {
        Ok(key) => key,
        Err(status) => return status,
    };
    // SAFETY: per the contract.
    let name = unsafe { crate::rtl::copy_unicode(value_name) };
    let format = |out: &mut [u8]| {
        let hive = HIVE.lock();
        let (stored_name, kind, data) = hive.value(key, &name).map_err(status)?;
        Ok(value_information(class, stored_name, kind, data, out))
    };
    // SAFETY: per the contract.
    unsafe { inform(information, length, result_length, format) }
}

// ---- tests --------------------------------------------------------------

/// A hive file that needs its log, or whose base block is damaged, or
/// that is cut short, is refused whole; `file`, the hive the loader
/// read, is accepted as it is.
pub fn refused_test(file: &[u8]) -> Result<(), &'static str> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(file.len())
        .map_err(|_| "no memory")?;
    copy.extend_from_slice(file);
    let verdict = |file: &[u8]| build(&mut Hive::new(), Some(file)).map(|_| ());
    if verdict(&copy).is_err() {
        return Err("the hive the kernel booted with was refused the second time");
    }
    // The second sequence number: a write that was begun and not ended.
    // The base block's checksum covers it.
    let sum = |copy: &mut [u8]| {
        let sum = nk_cm::regf::checksum(&copy[..nk_cm::regf::BASE_BLOCK]);
        copy[0x1FC..0x200].copy_from_slice(&sum.to_le_bytes());
    };
    copy[8] ^= 1;
    sum(&mut copy);
    if verdict(&copy) != Err(refusal(ImportError::File(RegfError::Dirty))) {
        return Err("a hive that was not written out completely was not refused as such");
    }
    copy[8] ^= 1;
    sum(&mut copy);
    // A byte of the base block the checksum covers.
    copy[0x30] ^= 0x40;
    if verdict(&copy) != Err(refusal(ImportError::File(RegfError::Corrupt))) {
        return Err("a hive with a damaged base block was not refused as such");
    }
    copy[0x30] ^= 0x40;
    if verdict(&copy[..copy.len() - 4096]) != Err(refusal(ImportError::File(RegfError::BadLength)))
    {
        return Err("a hive cut short was not refused");
    }
    Ok(())
}
