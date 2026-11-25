//! The object namespace, reduced to what device I/O needs: named device
//! objects and symbolic links to them.
//!
//! The table and its rules for names are `nk_ob::Namespace`, tested on
//! the host; here are the lock around it and the references.

pub mod handle;
pub mod object;

use crate::ke::{Rank, SpinLock};
use alloc::vec::Vec;
use nk_ntabi::io::DEVICE_OBJECT;
use nk_ntabi::status::*;
use nk_ob::{NameError, Namespace};

pub enum Target {
    Device(*mut DEVICE_OBJECT),
    SymbolicLink(Vec<u16>),
}

/// A device as the namespace holds it.
#[derive(Clone, Copy, PartialEq)]
struct Device(*mut DEVICE_OBJECT);

// SAFETY: the device pointer is only an identity here; the namespace never
// dereferences it.
unsafe impl Send for Device {}

static NAMESPACE: SpinLock<Namespace<Device>> = SpinLock::new(Rank::Namespace, Namespace::new());

fn status(error: NameError) -> NTSTATUS {
    match error {
        NameError::Invalid => STATUS_OBJECT_NAME_INVALID,
        NameError::Collision => STATUS_OBJECT_NAME_COLLISION,
        NameError::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
        NameError::NotFound => STATUS_OBJECT_NAME_NOT_FOUND,
    }
}

/// Add a name. Fails if the name is malformed or already taken.
pub fn insert(name: &[u16], target: Target) -> NTSTATUS {
    let target = match target {
        Target::Device(device) => nk_ob::Target::Object(Device(device)),
        Target::SymbolicLink(to) => nk_ob::Target::SymbolicLink(to),
    };
    NAMESPACE
        .lock()
        .insert(name, target)
        .map_or_else(status, |()| STATUS_SUCCESS)
}

/// Remove the symbolic link called `name`.
pub fn remove_link(name: &[u16]) -> NTSTATUS {
    NAMESPACE
        .lock()
        .remove_link(name)
        .map_or_else(status, |()| STATUS_SUCCESS)
}

/// Remove every name of `device`.
pub fn remove_device(device: *mut DEVICE_OBJECT) {
    NAMESPACE.lock().remove_object(Device(device));
}

/// The device `name` refers to, following symbolic links.
pub fn lookup_device(name: &[u16]) -> Option<*mut DEVICE_OBJECT> {
    NAMESPACE.lock().lookup(name).map(|Device(d)| d)
}

/// The device `name` refers to, with a pointer reference taken while
/// the name still led to it: its memory stays until the caller drops
/// the reference (`object::dereference`), whatever becomes of the
/// device meanwhile.
pub fn lookup_device_referenced(name: &[u16]) -> Option<*mut DEVICE_OBJECT> {
    let ns = NAMESPACE.lock();
    let Device(device) = ns.lookup(name)?;
    // SAFETY: a device loses its names, under this lock, before it gives
    // up the reference it was created with; so one that still has a name
    // is alive.
    unsafe { object::reference(device.cast()) };
    Some(device)
}

/// Number of names in the namespace (for leak checks).
pub fn count() -> usize {
    NAMESPACE.lock().len()
}
