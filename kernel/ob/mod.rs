//! The object namespace, reduced to what device I/O needs: named device
//! objects and symbolic links to them.
//!
//! Names are compared case-insensitively and `\DosDevices`, `\??` and
//! `\GLOBAL??` are one directory (`nk_rtl::same_object_name`). A name must
//! match an entry exactly: there is no directory tree and no parsing of a
//! path remainder after a device name yet, so `\Device\Foo\bar` does not
//! open `\Device\Foo`.

pub mod handle;
pub mod object;

use crate::ke::{Rank, SpinLock};
use alloc::vec::Vec;
use nk_ntabi::io::DEVICE_OBJECT;
use nk_ntabi::status::*;

/// How many symbolic links a lookup follows before giving up.
const MAX_LINK_DEPTH: usize = 8;

pub enum Target {
    Device(*mut DEVICE_OBJECT),
    SymbolicLink(Vec<u16>),
}

struct Entry {
    name: Vec<u16>,
    target: Target,
}

// SAFETY: the device pointer is only an identity here; the namespace never
// dereferences it.
unsafe impl Send for Entry {}

static NAMESPACE: SpinLock<Vec<Entry>> = SpinLock::new(Rank::Namespace, Vec::new());

/// Add a name. Fails if the name is malformed or already taken.
pub fn insert(name: &[u16], target: Target) -> NTSTATUS {
    if !nk_rtl::is_valid_object_name(name) {
        return STATUS_OBJECT_NAME_INVALID;
    }
    let mut ns = NAMESPACE.lock();
    if ns.iter().any(|e| nk_rtl::same_object_name(&e.name, name)) {
        return STATUS_OBJECT_NAME_COLLISION;
    }
    if ns.try_reserve(1).is_err() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    ns.push(Entry {
        name: name.to_vec(),
        target,
    });
    STATUS_SUCCESS
}

/// Remove the symbolic link called `name`.
pub fn remove_link(name: &[u16]) -> NTSTATUS {
    let mut ns = NAMESPACE.lock();
    let found = ns.iter().position(|e| {
        matches!(e.target, Target::SymbolicLink(_)) && nk_rtl::same_object_name(&e.name, name)
    });
    match found {
        Some(i) => {
            ns.swap_remove(i);
            ns.shrink_to_fit();
            STATUS_SUCCESS
        }
        None => STATUS_OBJECT_NAME_NOT_FOUND,
    }
}

/// Remove every name of `device`.
pub fn remove_device(device: *mut DEVICE_OBJECT) {
    let mut ns = NAMESPACE.lock();
    ns.retain(|e| !matches!(e.target, Target::Device(d) if d == device));
    // An empty table holds no memory, so leak checks see none.
    ns.shrink_to_fit();
}

/// The device `name` refers to, following symbolic links.
pub fn lookup_device(name: &[u16]) -> Option<*mut DEVICE_OBJECT> {
    let ns = NAMESPACE.lock();
    let mut name = name;
    for _ in 0..MAX_LINK_DEPTH {
        match &ns
            .iter()
            .find(|e| nk_rtl::same_object_name(&e.name, name))?
            .target
        {
            Target::Device(d) => return Some(*d),
            Target::SymbolicLink(to) => name = to,
        }
    }
    None
}

/// The device `name` refers to, with a pointer reference taken while
/// the name still led to it: its memory stays until the caller drops
/// the reference (`object::dereference`), whatever becomes of the
/// device meanwhile.
pub fn lookup_device_referenced(name: &[u16]) -> Option<*mut DEVICE_OBJECT> {
    let ns = NAMESPACE.lock();
    let mut name = name;
    for _ in 0..MAX_LINK_DEPTH {
        match &ns
            .iter()
            .find(|e| nk_rtl::same_object_name(&e.name, name))?
            .target
        {
            Target::Device(d) => {
                // SAFETY: a device loses its names, under this lock,
                // before it gives up the reference it was created with;
                // so one that still has a name is alive.
                unsafe { object::reference(d.cast()) };
                return Some(*d);
            }
            Target::SymbolicLink(to) => name = to,
        }
    }
    None
}

/// Number of names in the namespace (for leak checks).
pub fn count() -> usize {
    NAMESPACE.lock().len()
}
