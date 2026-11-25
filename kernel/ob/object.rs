//! Objects with a header: a reference count, a handle count and a type.
//!
//! What the object manager allocates has an `OBJECT_HEADER` in front of
//! it, laid out as on Windows. A pointer to an object is a pointer to
//! its body; the header is found by stepping back. An object lives until
//! its last reference is dropped: handles hold references, and so does
//! anything that was given a pointer by `ObReferenceObjectByHandle`.
//!
//! Types are NK's own structures. A driver names a type by the value of
//! a variable it imports (`*ExEventObjectType`) and only ever passes it
//! back, so a type's address is its identity and its contents are
//! private.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::mm::pool;
use core::sync::atomic::{AtomicI64, Ordering};
use nk_ntabi::ob::{OBJECT_BODY, OBJECT_HEADER};

/// Pool tag of object-manager allocations.
const TAG: u32 = u32::from_le_bytes(*b"ObNK");

/// A kind of object.
pub struct ObjectType {
    /// Its place in `TYPES`; kept in each object's header.
    index: u8,
}

/// Events (`KEVENT`).
pub static EVENT_TYPE: ObjectType = ObjectType { index: 0 };
/// Threads (`ETHREAD`).
pub static THREAD_TYPE: ObjectType = ObjectType { index: 1 };

static TYPES: [&ObjectType; 2] = [&EVENT_TYPE, &THREAD_TYPE];

/// A variable a driver imports to name a type: it holds the type's
/// address.
#[repr(transparent)]
pub struct TypeVariable(*const ObjectType);

// SAFETY: immutable, and the pointer names a static.
unsafe impl Sync for TypeVariable {}

/// [`ExEventObjectType`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-reference-tracing-with-tags):
/// what a driver passes to `ObReferenceObjectByHandle` to insist on an
/// event.
pub static ExEventObjectType: TypeVariable = TypeVariable(&raw const EVENT_TYPE);

/// [`PsThreadType`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle):
/// what a driver passes to insist on a thread.
pub static PsThreadType: TypeVariable = TypeVariable(&raw const THREAD_TYPE);

impl TypeVariable {
    /// The address drivers import.
    pub const fn address(&'static self) -> *const () {
        core::ptr::from_ref(self).cast()
    }

    /// The value drivers read from it.
    pub fn value(&self) -> *const ObjectType {
        self.0
    }
}

fn header(body: *mut u8) -> *mut OBJECT_HEADER {
    body.wrapping_sub(OBJECT_BODY).cast()
}

/// # Safety
/// `body` is a live object from [`create`].
unsafe fn pointer_count<'a>(body: *mut u8) -> &'a AtomicI64 {
    // SAFETY: per the contract.
    unsafe { AtomicI64::from_ptr(&raw mut (*header(body)).PointerCount) }
}

/// # Safety
/// `body` is a live object from [`create`].
pub unsafe fn handle_count<'a>(body: *mut u8) -> &'a AtomicI64 {
    // SAFETY: per the contract.
    unsafe { AtomicI64::from_ptr(&raw mut (*header(body)).HandleCount) }
}

/// Allocate a zeroed object of `size` bytes and type `ty`, with one
/// reference: the caller's.
pub fn create(ty: &'static ObjectType, size: usize) -> Option<*mut u8> {
    let block = pool::alloc_zeroed(OBJECT_BODY + size, TAG);
    if block.is_null() {
        return None;
    }
    // SAFETY: a fresh, zeroed block large enough for the header, which
    // the pool aligns to 16 bytes.
    unsafe {
        let header = block.cast::<OBJECT_HEADER>();
        (&raw mut (*header).PointerCount).write(1);
        (&raw mut (*header).TypeIndex).write(ty.index);
    }
    Some(block.wrapping_add(OBJECT_BODY))
}

/// The type of an object.
///
/// # Safety
/// `body` is a live object from [`create`].
pub unsafe fn type_of(body: *mut u8) -> &'static ObjectType {
    // SAFETY: per the contract; the index was written by `create`.
    TYPES[usize::from(unsafe { (&raw const (*header(body)).TypeIndex).read() })]
}

/// Take a reference. Returns the new count.
///
/// # Safety
/// `body` is a live object from [`create`] to which the caller already
/// holds a reference, or which it found under a lock that keeps it
/// alive.
pub unsafe fn reference(body: *mut u8) -> i64 {
    // SAFETY: per the contract.
    unsafe { pointer_count(body) }.fetch_add(1, Ordering::AcqRel) + 1
}

/// Drop a reference; the last one frees the object. Returns the new
/// count.
///
/// # Safety
/// `body` is a live object from [`create`] and the caller owns one of
/// its references, which it gives up.
pub unsafe fn dereference(body: *mut u8) -> i64 {
    // SAFETY: per the contract.
    let left = unsafe { pointer_count(body) }.fetch_sub(1, Ordering::AcqRel) - 1;
    if left == 0 {
        let freed = pool::free(header(body).cast());
        debug_assert!(freed.is_ok());
    } else if left < 0 {
        crate::kd::bugcheck(format_args!(
            "0x00000018 REFERENCE_BY_POINTER: an object was dereferenced more often than referenced"
        ));
    }
    left
}

/// [`ObfDereferenceObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obfdereferenceobject):
/// what `ObDereferenceObject` compiles to.
///
/// # Safety
/// `object` is an object the caller holds a reference to.
pub unsafe extern "C" fn ObfDereferenceObject(object: *mut core::ffi::c_void) -> isize {
    // SAFETY: per the contract.
    unsafe { dereference(object.cast()) as isize }
}
