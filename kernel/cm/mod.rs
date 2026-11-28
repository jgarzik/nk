//! The registry, as drivers reach it: `ZwCreateKey`, `ZwOpenKey`,
//! `ZwDeleteKey`, `ZwEnumerateKey`, `ZwEnumerateValueKey`, `ZwQueryKey`,
//! `ZwQueryValueKey`, `ZwSetValueKey`, `ZwDeleteValueKey`, and the
//! query tables of `RtlQueryRegistryValues` (`table.rs`).
//!
//! One tree in memory (`nk_cm`), under one lock. It starts with the
//! keys every system has and, laid over `Machine\System`, the SYSTEM
//! hive the loader read, if it read one, and over that the registry
//! overlay, keys and values as text, if it read one; it holds what
//! drivers put in it until the machine stops. Nothing is written back
//! to a hive file.
//! `CurrentControlSet` is a symbolic link to the control set the hive
//! selects. A key handle is a handle to a small object naming the key.
//!
//! The registry's root is such an object too, called `\Registry` in the
//! object namespace. An absolute name is looked up there like any
//! other; the look-up ends at the root key, and the rest of the path is
//! the registry's to walk.

#![allow(non_snake_case)]

mod helper;
pub mod notify;
mod table;

pub use helper::{
    RtlCheckRegistryKey, RtlCreateRegistryKey, RtlDeleteRegistryValue, RtlWriteRegistryValue,
};
pub use table::{RtlQueryRegistryValues, RtlQueryRegistryValuesEx};

use crate::ke::{Rank, SpinLock};
use crate::ob::object::ObRef;
use crate::ob::{handle, object};
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_cm::manifest::Op;
use nk_cm::notify::{CHANGE_LAST_SET, CHANGE_NAME};
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
    "MACHINE\\HARDWARE\\DEVICEMAP",
    "MACHINE\\HARDWARE\\RESOURCEMAP",
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
/// hive `file` laid over `Machine\System` if there is one, the
/// operations `overlay` carried out there, and `CurrentControlSet`, a
/// symbolic link to the control set `Select\Current` names, as on
/// Windows. Returns the root.
fn build(hive: &mut Hive, file: Option<&[u8]>, overlay: &[Op]) -> Result<KeyId, &'static str> {
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
    // Before anything is read, the control set's number included: the
    // overlay stands for content of the hive.
    nk_cm::manifest::apply(hive, system, overlay, now)
        .map_err(|_| "no memory for the registry overlay")?;
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

/// The operations the registry overlay `text` describes. The overlay
/// is NK's own file (`fixtures/registry-overlay.txt`): one that cannot
/// be read is not used in part, and the line at fault is printed.
fn overlay(text: &[u8]) -> Result<Vec<Op>, &'static str> {
    nk_cm::manifest::parse(text).map_err(|error| {
        kprintln!("cm: registry overlay, {error}");
        "the registry overlay is malformed"
    })
}

/// Make the registry, from the SYSTEM hive and the registry overlay
/// the loader read, where it read one (`doc/BOOT.md`), and name its
/// root `\Registry`. A hive or an overlay that cannot be used fails
/// the boot.
pub fn init() -> Result<(), &'static str> {
    const NO_MEMORY: &str = "no memory for the registry";
    let file = crate::ldr::boot_file(nk_bootinfo::HIVE_MODULE);
    let laid = match crate::ldr::boot_file(nk_bootinfo::OVERLAY_MODULE) {
        Some(text) => overlay(text)?,
        None => Vec::new(),
    };
    let root = {
        let mut hive = HIVE.lock();
        let root = build(&mut hive, file, &laid)?;
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
    if !laid.is_empty() {
        kprintln!("cm: registry overlay of {} keys and values", laid.len());
    }
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

/// A key found through its key object, and the reference to that
/// object, held for as long as this lives.
///
/// A key's number names it only while the key is counted as open: the
/// registry gives the place of a deleted key nobody has open to the
/// next key made. A key object counts as one open until it is freed, so
/// whoever holds a reference to it may take the registry's lock and
/// find that key there, or find it deleted, whatever has been done with
/// the handle meanwhile; never another key.
///
/// Dropped with the registry's lock released: the object's last
/// reference going takes that lock ([`closed`]).
struct Held {
    body: ObRef,
    key: KeyId,
}

impl Held {
    fn key(&self) -> KeyId {
        self.key
    }

    fn body(&self) -> *mut u8 {
        self.body.body()
    }
}

/// The key a key handle names, held open until the call that asked has
/// done with it.
fn key_of(handle: *mut c_void) -> Result<Held, NTSTATUS> {
    let body = handle::reference(handle as u64, Some(&raw const object::KEY_TYPE))?;
    // SAFETY: a key object, referenced by the look-up: its body is the
    // key's number, written once when it was made.
    let key = KeyId::from_index(unsafe { body.cast::<usize>().read() });
    Ok(Held { body, key })
}

/// The key the name in `attributes` starts at, and the path from
/// there. An absolute name, or one relative to a directory, is looked
/// up in the object namespace, where it must lead to a key: the
/// registry's root, with the rest of the path left over. A name
/// relative to an open key starts at that key.
///
/// Reads the driver's memory and resolves its handle, so it is called
/// before the registry's lock is taken; the key it starts at is held
/// until the caller lets go of it, after that lock is released.
///
/// # Safety
/// `attributes` points to an `OBJECT_ATTRIBUTES` whose name is null or
/// a counted string.
unsafe fn named(
    attributes: *const OBJECT_ATTRIBUTES,
    mode: i8,
) -> Result<(Held, Vec<u16>), NTSTATUS> {
    // SAFETY: per the contract; fault-protected when `UserMode`.
    let oa = unsafe { crate::svc::capture::capture_object_attributes(attributes, mode) }?
        .ok_or(STATUS_INVALID_PARAMETER)?;
    let root = oa.root;
    let path = oa.name.unwrap_or_default();
    if root.is_null() {
        return absolute(&path);
    }
    let root =
        handle::reference_for(root as u64, None, 0, crate::svc::capture::handle_mode(mode))?.0;
    let (body, path) = if root.is(&object::DIRECTORY_TYPE) {
        crate::ob::lookup(Some(root.body()), &path)?
    } else if path.first() == Some(&u16::from(b'\\')) {
        // Relative to an open object: not from the top.
        return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
    } else {
        (root, path)
    };
    Ok((key_object(body)?, path))
}

/// The key the object `body` is, held by the caller's reference. What
/// leads elsewhere in the namespace names no key.
fn key_object(body: ObRef) -> Result<Held, NTSTATUS> {
    if !body.is(&object::KEY_TYPE) {
        return Err(STATUS_OBJECT_TYPE_MISMATCH);
    }
    // SAFETY: a key object, alive while `body` holds its reference; its
    // body is the key's number, written once when it was made.
    let key = KeyId::from_index(unsafe { body.cast::<usize>().read() });
    Ok(Held { body, key })
}

/// The key the absolute name `path` starts at, and the path from
/// there: the name is looked up in the object namespace, where it must
/// lead to a key, the registry's root, with the rest of the path left
/// over.
fn absolute(path: &[u16]) -> Result<(Held, Vec<u16>), NTSTATUS> {
    let (body, rest) = crate::ob::lookup(None, path)?;
    Ok((key_object(body)?, rest))
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
    // The watches made through this object end with it.
    notify::closed(body);
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
    let mut made = None;
    if new {
        stamp_new(&mut hive, key, now).map_err(status)?;
        made = Some(new_key_seen(&hive, key));
    }
    let mut written = Ok(());
    for (name, kind, data) in values {
        let name: Vec<u16> = name.encode_utf16().collect();
        written = hive
            .set_value(key, &name, *kind, data)
            .and_then(|()| hive.set_last_write(key, now))
            .map_err(status);
        if written.is_err() {
            break;
        }
    }
    let set = (!values.is_empty()).then(|| notify::changed(&hive, key, CHANGE_LAST_SET));
    drop(hive);
    for met in [made, set].into_iter().flatten() {
        met.tell();
    }
    written
}

/// The watches met by `key` having just been made: a change of name at
/// the key it was made under. Called with the registry's lock held.
fn new_key_seen(hive: &Hive, key: KeyId) -> notify::Met {
    match hive.parent(key) {
        Ok(parent) => notify::changed(hive, parent, CHANGE_NAME),
        Err(_) => notify::changed(hive, key, 0),
    }
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

/// As [`write`], making every key of `path` that is not there, not
/// only the last: an instance path is several keys deep, and the first
/// device of a kind brings all of them. For the kernel's own use.
pub fn write_path(path: &str, values: &[(&str, u32, &[u8])]) -> Result<(), NTSTATUS> {
    for (at, _) in path.match_indices('\\') {
        write(&path[..at], &[])?;
    }
    write(path, values)
}

/// The names of the subkeys of the key at `path` (from the registry's
/// root), in the order Windows enumerates them; none if there is no
/// such key. For the kernel's own use.
pub fn subkeys(path: &str) -> Vec<String> {
    let path = wide(path);
    let mut hive = HIVE.lock();
    let Ok(key) = hive.root().and_then(|root| hive.open(root, &path)) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    while let Ok(Some(child)) = hive.subkey(key, names.len()) {
        let name = hive.info(child).map_or(&[][..], |info| info.name);
        names.push(String::from_utf16_lossy(name));
    }
    names
}

/// A value: its name, type and data.
pub type Value = (String, u32, Vec<u8>);

/// The values of the key at `path` (from the registry's root), in the
/// order they were first set; none if there is no such key. For the
/// kernel's own use.
pub fn values(path: &str) -> Vec<Value> {
    let path = wide(path);
    let mut hive = HIVE.lock();
    let Ok(key) = hive.root().and_then(|root| hive.open(root, &path)) else {
        return Vec::new();
    };
    let mut values = Vec::new();
    while let Ok(Some((name, kind, data))) = hive.value_at(key, values.len()) {
        values.push((String::from_utf16_lossy(name), kind, data.to_vec()));
    }
    values
}

/// Copy the key at `from`, with its values and everything below it,
/// over the key at `to` (both from the registry's root), making what
/// is not there: values of the same name are replaced, others stay.
/// For the kernel's own use: what installing a device copies from the
/// driver database into the device's key.
pub fn copy_tree(from: &str, to: &str) -> Result<(), NTSTATUS> {
    let found = values(from);
    let list: Vec<(&str, u32, &[u8])> = found
        .iter()
        .map(|(name, kind, data)| (name.as_str(), *kind, &data[..]))
        .collect();
    write_path(to, &list)?;
    for child in subkeys(from) {
        copy_tree(
            &alloc::format!("{from}\\{child}"),
            &alloc::format!("{to}\\{child}"),
        )?;
    }
    Ok(())
}

/// Delete the key at `path` (from the registry's root) and everything
/// below it. A key that is not there is not an error. For the kernel's
/// own use.
pub fn delete_tree(path: &str) -> Result<(), NTSTATUS> {
    for child in subkeys(path) {
        delete_tree(&alloc::format!("{path}\\{child}"))?;
    }
    let wide = wide(path);
    let now = now();
    let mut hive = HIVE.lock();
    let Ok(key) = hive.root().and_then(|root| hive.open(root, &wide)) else {
        return Ok(());
    };
    hive.parent(key)
        .and_then(|parent| {
            hive.delete(key)?;
            hive.set_last_write(parent, now)
        })
        .map_err(status)
}

/// Delete the value `name` of the key at `path` (from the registry's
/// root). Neither a missing key nor a missing value is an error. For
/// the kernel's own use.
pub fn delete_value(path: &str, name: &str) {
    let path = wide(path);
    let name = wide(name);
    let mut hive = HIVE.lock();
    if let Ok(key) = hive.root().and_then(|root| hive.open(root, &path)) {
        let _ = hive.delete_value(key, &name);
    }
}

/// [`ZwDeleteKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwdeletekey):
/// delete an open key that has no subkeys. It is gone by name at once;
/// handles still open to it, this one included, are good only for
/// closing.
pub extern "C" fn NtDeleteKey(key_handle: *mut c_void) -> NTSTATUS {
    // Held to the end of the call: longer than the registry's lock.
    let held = match key_of(key_handle) {
        Ok(held) => held,
        Err(status) => return status,
    };
    let key = held.key();
    let now = now();
    let mut hive = HIVE.lock();
    // The key it was a subkey of has changed with it.
    let deleted = hive.parent(key).and_then(|parent| {
        hive.delete(key)?;
        hive.set_last_write(parent, now)?;
        Ok(parent)
    });
    let met = deleted
        .ok()
        .map(|parent| notify::changed(&hive, parent, CHANGE_NAME));
    drop(hive);
    if let Some(met) = met {
        met.tell();
    }
    match deleted {
        Ok(_) => STATUS_SUCCESS,
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
pub unsafe extern "C" fn NtOpenKey(
    key_handle: *mut *mut c_void,
    desired_access: u32,
    attributes: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    let mut asked = Vec::new();
    // SAFETY: per the contract.
    let found = unsafe { named(attributes, mode) }.and_then(|(start, path)| {
        if crate::kd::trace_registry() {
            asked.clone_from(&path);
        }
        // `start` outlives the lock: a parameter goes after the locals.
        let mut hive = HIVE.lock();
        let key = hive.open(start.key(), &path).map_err(status)?;
        hive.opened(key);
        Ok(key)
    });
    let status = match found.and_then(|key| open(key, desired_access)) {
        Ok(handle) => {
            // SAFETY: per the contract; fault-protected for `UserMode`.
            match unsafe { crate::svc::capture::write(key_handle, handle, mode) } {
                Ok(()) => STATUS_SUCCESS,
                Err(status) => {
                    let _ =
                        handle::close_for(handle as u64, crate::svc::capture::handle_mode(mode));
                    status
                }
            }
        }
        Err(status) => status,
    };
    if crate::kd::trace_registry() {
        kprintln!(
            "cm: open key {}: {:#x}",
            alloc::string::String::from_utf16_lossy(&asked),
            status as u32
        );
    }
    status
}

/// The bytes of the counted string `class`; none if it is null.
/// `None` without memory for them.
///
/// # Safety
/// `class` is null or points to a counted string.
unsafe fn class_of(class: *const UNICODE_STRING, mode: i8) -> Result<Vec<u8>, NTSTATUS> {
    if class.is_null() {
        return Ok(Vec::new());
    }
    // SAFETY: per the contract; fault-protected for `UserMode`.
    let units = unsafe { crate::svc::capture::capture_unicode_string(class, mode) }?;
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(units.len() * 2).is_err() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    for u in units {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    Ok(bytes)
}

/// Open the key `path` below `start`, making it, with `class`, if it
/// is not there: the key, counted as open (`Hive::opened`), and
/// whether it is new. Whoever watches the key it was made under is
/// told.
fn create_below(start: &Held, path: &[u16], class: &[u8]) -> Result<(KeyId, bool), NTSTATUS> {
    let now = now();
    // `start` is the caller's to let go of, after the lock.
    let mut hive = HIVE.lock();
    let (key, new) = hive.create(start.key(), path).map_err(status)?;
    if new {
        let classed = hive.set_class(key, class);
        if let Err(error) = classed.and_then(|()| stamp_new(&mut hive, key, now)) {
            // Without its class it is not the key that was asked
            // for: nothing has seen it yet, and it has no subkeys.
            let _ = hive.delete(key);
            return Err(status(error));
        }
    }
    hive.opened(key);
    let met = new.then(|| new_key_seen(&hive, key));
    drop(hive);
    if let Some(met) = met {
        met.tell();
    }
    Ok((key, new))
}

/// Set the value `name` of `key`, stamp the key, and tell whoever
/// watches it.
fn set_value(key: KeyId, name: &[u16], kind: u32, data: &[u8]) -> NTSTATUS {
    let now = now();
    let mut hive = HIVE.lock();
    let set = hive.set_value(key, name, kind, data);
    let set = set.and_then(|()| hive.set_last_write(key, now));
    let met = set
        .is_ok()
        .then(|| notify::changed(&hive, key, CHANGE_LAST_SET));
    drop(hive);
    if let Some(met) = met {
        met.tell();
    }
    match set {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => status(error),
    }
}

/// Take the value `name` away from `key`, stamp the key, and tell
/// whoever watches it.
fn delete_value_of(key: KeyId, name: &[u16]) -> NTSTATUS {
    let now = now();
    let mut hive = HIVE.lock();
    let deleted = hive.delete_value(key, name);
    let deleted = deleted.and_then(|()| hive.set_last_write(key, now));
    let met = deleted
        .is_ok()
        .then(|| notify::changed(&hive, key, CHANGE_LAST_SET));
    drop(hive);
    if let Some(met) = met {
        met.tell();
    }
    match deleted {
        Ok(()) => STATUS_SUCCESS,
        Err(error) => status(error),
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
pub unsafe extern "C" fn NtCreateKey(
    key_handle: *mut *mut c_void,
    desired_access: u32,
    attributes: *const OBJECT_ATTRIBUTES,
    _title_index: u32,
    class: *const UNICODE_STRING,
    _create_options: u32,
    disposition: *mut u32,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract; captured before taking the registry lock.
    let class = match unsafe { class_of(class, mode) } {
        Ok(c) => c,
        Err(status) => return status,
    };
    // SAFETY: per the contract.
    let made = unsafe { named(attributes, mode) }
        .and_then(|(start, path)| create_below(&start, &path, &class));
    match made.and_then(|(key, new)| Ok((open(key, desired_access)?, new))) {
        Ok((handle, new)) => {
            // SAFETY: per the contract; fault-protected for `UserMode`.
            let write = unsafe {
                crate::svc::capture::write(key_handle, handle, mode).and_then(|()| {
                    if !disposition.is_null() {
                        crate::svc::capture::write(
                            disposition,
                            if new { CREATED } else { OPENED },
                            mode,
                        )
                    } else {
                        Ok(())
                    }
                })
            };
            if let Err(status) = write {
                let _ = handle::close_for(handle as u64, crate::svc::capture::handle_mode(mode));
                return status;
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
pub unsafe extern "C" fn NtSetValueKey(
    key_handle: *mut c_void,
    value_name: *const UNICODE_STRING,
    _title_index: u32,
    kind: u32,
    data: *const u8,
    data_size: u32,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    // Held to the end of the call: longer than the registry's lock.
    let held = match key_of(key_handle) {
        Ok(held) => held,
        Err(status) => return status,
    };
    let key = held.key();
    // SAFETY: per the contract; captured before taking the registry lock.
    let name = match unsafe { crate::svc::capture::capture_unicode_string(value_name, mode) } {
        Ok(n) => n,
        Err(status) => return status,
    };
    // SAFETY: per the contract; captured before taking the registry lock.
    let data = match unsafe { crate::svc::capture::capture_bytes(data, data_size as usize, mode) } {
        Ok(d) => d,
        Err(status) => return status,
    };
    set_value(key, &name, kind, &data)
}

/// [`ZwDeleteValueKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwdeletevaluekey):
/// take a value away from a key. The values after it move up one place
/// in the order they are enumerated in; set again, the value is the
/// key's last.
///
/// # Safety
/// `value_name` is null or a counted string.
pub unsafe extern "C" fn NtDeleteValueKey(
    key_handle: *mut c_void,
    value_name: *const UNICODE_STRING,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    // Held to the end of the call: longer than the registry's lock.
    let held = match key_of(key_handle) {
        Ok(held) => held,
        Err(status) => return status,
    };
    let key = held.key();
    // SAFETY: per the contract; captured before taking the registry lock.
    let name = match unsafe { crate::svc::capture::capture_unicode_string(value_name, mode) } {
        Ok(n) => n,
        Err(status) => return status,
    };
    delete_value_of(key, &name)
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
    let mode = crate::svc::capture::mode();
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
        out.resize(room, 0);
        // SAFETY: per the contract; fault-protected for `UserMode`.
        let copied = unsafe { crate::svc::capture::copy_from_caller(&mut out, information, mode) };
        if let Err(status) = copied {
            return status;
        }
    };
    // SAFETY: per the contract; fault-protected for `UserMode`.
    let wrote_len = unsafe { crate::svc::capture::write(result_length, needed as u32, mode) };
    if let Err(status) = wrote_len {
        return status;
    }
    if fit != Fit::Nothing {
        // SAFETY: per the contract; `out` is no longer than `length`.
        let wrote_buf = unsafe { crate::svc::capture::copy_to_caller(information, &out, mode) };
        if let Err(status) = wrote_buf {
            return status;
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
pub unsafe extern "C" fn NtEnumerateKey(
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
    // Held to the end of the call: longer than the registry's lock.
    let held = match key_of(key_handle) {
        Ok(held) => held,
        Err(status) => return status,
    };
    let key = held.key();
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
pub unsafe extern "C" fn NtQueryKey(
    key_handle: *mut c_void,
    class: u32,
    information: *mut u8,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    if class > KEY_TRUST {
        return STATUS_INVALID_PARAMETER;
    }
    // Held to the end of the call: longer than the registry's lock.
    let held = match key_of(key_handle) {
        Ok(held) => held,
        Err(status) => return status,
    };
    let key = held.key();
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
/// were first set, in the basic, full and partial forms: Windows 10
/// enumerates in no other, the two aligned for 64 bits included
/// (`STATUS_INVALID_PARAMETER`). Past the last,
/// `STATUS_NO_MORE_ENTRIES`, whatever the buffer.
///
/// # Safety
/// `information` is readable and writable for `length` bytes and
/// `result_length` writable for four.
pub unsafe extern "C" fn NtEnumerateValueKey(
    key_handle: *mut c_void,
    index: u32,
    class: u32,
    information: *mut u8,
    length: u32,
    result_length: *mut u32,
) -> NTSTATUS {
    if class > PARTIAL {
        return STATUS_INVALID_PARAMETER;
    }
    // Held to the end of the call: longer than the registry's lock.
    let held = match key_of(key_handle) {
        Ok(held) => held,
        Err(status) => return status,
    };
    let key = held.key();
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
/// has and the two aligned for 64 bits. There are no layered keys, and
/// a value is not described as part of one (`KeyValueLayerInformation`).
/// The name is matched whatever its letter case and reported as it was
/// set.
///
/// # Safety
/// `value_name` is null or a counted string; `information` is readable
/// and writable for `length` bytes and `result_length` writable for
/// four.
pub unsafe extern "C" fn NtQueryValueKey(
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
    // Held to the end of the call: longer than the registry's lock.
    let held = match key_of(key_handle) {
        Ok(held) => held,
        Err(status) => return status,
    };
    let key = held.key();
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract; fault-protected for `UserMode`.
    let name = match unsafe { crate::svc::capture::capture_unicode_string(value_name, mode) } {
        Ok(n) => n,
        Err(status) => return status,
    };
    let format = |out: &mut [u8]| {
        let hive = HIVE.lock();
        let (stored_name, kind, data) = hive.value(key, &name).map_err(status)?;
        Ok(value_information(class, stored_name, kind, data, out))
    };
    // SAFETY: per the contract.
    let status = unsafe { inform(information, length, result_length, format) };
    if crate::kd::trace_registry() {
        kprintln!(
            "cm: query value {}: {:#x}",
            alloc::string::String::from_utf16_lossy(&name),
            status as u32
        );
    }
    status
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
    let verdict = |file: &[u8]| build(&mut Hive::new(), Some(file), &[]).map(|_| ());
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

/// An overlay with a line that cannot be read is refused whole, and an
/// overlay is carried out before the control set is chosen: one that
/// sets `Select\Current` decides what `CurrentControlSet` leads to.
pub fn overlay_test() -> Result<(), &'static str> {
    if overlay(b"key Select\nvalue Current dword\n").is_ok() {
        return Err("an overlay with a value that has no data was not refused");
    }
    let laid = overlay(b"key Select\nvalue Current dword 2\nkey ControlSet002\\NkOverlay\n")?;
    let mut hive = Hive::new();
    let root = build(&mut hive, None, &laid)?;
    let path = wide("Machine\\System\\CurrentControlSet\\NkOverlay");
    match hive.open(root, &path) {
        Ok(_) => Ok(()),
        Err(_) => Err("an overlay's control set is not the current one"),
    }
}

pub use crate::svc::zw::{
    ZwCreateKey, ZwDeleteKey, ZwDeleteValueKey, ZwEnumerateKey, ZwEnumerateValueKey, ZwOpenKey,
    ZwQueryKey, ZwQueryValueKey, ZwSetValueKey,
};
