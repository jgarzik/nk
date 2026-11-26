//! The registry, as drivers reach it: `ZwCreateKey`, `ZwOpenKey`,
//! `ZwQueryValueKey`, `ZwSetValueKey`.
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
/// `KeyValueFullInformation`, `KeyValuePartialInformation`.
const FULL: u32 = 1;
const PARTIAL: u32 = 2;

/// `REG_DWORD`.
const REG_DWORD: u32 = 4;

/// The keys every Windows system has before any hive is read.
const SKELETON: &[&str] = &[
    "Machine",
    "Machine\\Hardware",
    "Machine\\System",
    "Machine\\System\\Select",
    "User",
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
    let root = hive.root().map_err(|_| NO_MEMORY)?;
    for path in SKELETON {
        hive.create(root, &wide(path)).map_err(|_| NO_MEMORY)?;
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
        hive.create(system, &wide(&alloc::format!("{set}{below}")))
            .map_err(|_| NO_MEMORY)?;
    }
    let (link, _) = hive
        .create(system, &wide("CurrentControlSet"))
        .map_err(|_| NO_MEMORY)?;
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
    let is = |body: *mut u8, ty: &'static object::ObjectType| {
        // SAFETY: called with objects this function holds a reference to.
        core::ptr::eq(unsafe { object::type_of(body) }, ty)
    };
    let (body, path) = if root.is_null() {
        crate::ob::lookup(None, &path)?
    } else {
        let root = handle::reference(root as u64, None)?;
        if is(root, &object::DIRECTORY_TYPE) {
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
        }
    };
    // SAFETY: the reference the look-up took, given up here; a key
    // object's body is the key's number, written once when it was made.
    unsafe {
        let key =
            is(body, &object::KEY_TYPE).then(|| KeyId::from_index(body.cast::<usize>().read()));
        object::dereference(body);
        // What leads elsewhere in the namespace names no key.
        Ok((key.ok_or(STATUS_OBJECT_TYPE_MISMATCH)?, path))
    }
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
    let mut hive = HIVE.lock();
    let root = hive.root().map_err(status)?;
    let (key, _) = hive.create(root, &path).map_err(status)?;
    for (name, kind, data) in values {
        let name: Vec<u16> = name.encode_utf16().collect();
        hive.set_value(key, &name, *kind, data).map_err(status)?;
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
    match HIVE.lock().delete(key) {
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
    desired_access: u32,
    attributes: *const OBJECT_ATTRIBUTES,
    _title_index: u32,
    _class: *const UNICODE_STRING,
    _create_options: u32,
    disposition: *mut u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    let made = unsafe { named(attributes) }.and_then(|(start, path)| {
        let mut hive = HIVE.lock();
        let (key, new) = hive.create(start, &path).map_err(status)?;
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
