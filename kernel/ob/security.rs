//! The security descriptor an object carries in its header
//! (`OBJECT_HEADER.SecurityDescriptor`).
//!
//! A descriptor is a self-relative copy in a pool block of its own,
//! counted: the object holds one reference, and whoever reads the
//! descriptor takes another for as long as it looks, so replacing an
//! object's descriptor never frees one that is being read. Blocks are
//! not shared between objects with equal descriptors, as Windows'
//! are.
//!
//! The header's field points at the descriptor itself. On Windows it
//! is a fast reference, a pointer whose low four bits are a count; a
//! descriptor here is 16-byte aligned and the bits are zero.
//!
//! The field belongs to the object's own lock, the header's `Lock`
//! word, held with the IRQL at `DISPATCH_LEVEL` and only for as long
//! as it takes to read or swap a pointer and count a reference
//! (`doc/LOCKING.md`).
//!
//! Devices do not use this: a device's descriptor is in
//! `DEVICE_OBJECT.SecurityDescriptor`, where drivers can see it, as on
//! Windows (`io::device`).

use super::object;
use crate::ke::irql;
use crate::mm::pool;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Pool tag of objects' security descriptors.
const TAG: u32 = u32::from_le_bytes(*b"ObSc");

/// What precedes a descriptor in its block: how many refer to it. As
/// large as the pool's alignment, so the descriptor is aligned too.
#[repr(C, align(16))]
struct Counted {
    references: AtomicUsize,
}

/// A counted copy of `descriptor`, with one reference.
fn copy(descriptor: &[u8]) -> Option<*mut u8> {
    let block = pool::alloc(size_of::<Counted>() + descriptor.len(), TAG);
    if block.is_null() {
        return None;
    }
    // SAFETY: a fresh block of that size, which the pool aligns to 16
    // bytes.
    unsafe {
        block.cast::<Counted>().write(Counted {
            references: AtomicUsize::new(1),
        });
        let copy = block.add(size_of::<Counted>());
        copy.copy_from_nonoverlapping(descriptor.as_ptr(), descriptor.len());
        Some(copy)
    }
}

/// # Safety
/// `descriptor` came from [`copy`] and is referenced.
unsafe fn count<'a>(descriptor: *mut u8) -> &'a AtomicUsize {
    // SAFETY: per the contract: the count is in front, in NK's own
    // memory.
    unsafe { &(*descriptor.sub(size_of::<Counted>()).cast::<Counted>()).references }
}

/// Give up a reference to a descriptor; the last one frees it.
///
/// # Safety
/// `descriptor` came from [`reference`] (or was an object's own) and
/// the caller owns one of its references.
pub unsafe fn release(descriptor: *mut u8) {
    // SAFETY: per the contract.
    unsafe {
        if count(descriptor).fetch_sub(1, Ordering::AcqRel) == 1 {
            let freed = pool::free(descriptor.sub(size_of::<Counted>()));
            debug_assert!(freed.is_ok());
        }
    }
}

/// Run `f` on the object's descriptor field with the object's lock
/// held.
///
/// # Safety
/// `body` is a live object the caller holds a reference to; the IRQL
/// is at most `DISPATCH_LEVEL`.
unsafe fn locked<R>(body: *mut u8, f: impl FnOnce(*mut *mut c_void) -> R) -> R {
    let header = object::header(body);
    // SAFETY: per the contract; the lock word and the field are in the
    // header, which lives as long as the object.
    unsafe {
        let lock = AtomicUsize::from_ptr(&raw mut (*header).Lock);
        let old = irql::raise(irql::DISPATCH_LEVEL);
        while lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let result = f(&raw mut (*header).SecurityDescriptor);
        lock.store(0, Ordering::Release);
        irql::lower(old);
        result
    }
}

/// Give an object the security descriptor `descriptor` (self-relative
/// bytes), in place of the one it has. `false` without memory, and
/// nothing changes.
///
/// # Safety
/// `body` is a live object the caller holds a reference to; the IRQL
/// is at most `DISPATCH_LEVEL`.
pub unsafe fn set(body: *mut u8, descriptor: &[u8]) -> bool {
    let Some(new) = copy(descriptor) else {
        return false;
    };
    // SAFETY: per the contract. The old descriptor is released after
    // the lock is dropped: freeing takes the pool's lock.
    unsafe {
        let old = locked(body, |field| field.replace(new.cast()));
        if !old.is_null() {
            release(old.cast());
        }
    }
    true
}

/// The object's security descriptor, with a reference for the caller
/// to [`release`]; null if the object has none.
///
/// # Safety
/// As [`set`].
pub unsafe fn reference(body: *mut u8) -> *mut u8 {
    // SAFETY: per the contract; the object's own reference keeps the
    // descriptor while the lock is held.
    unsafe {
        locked(body, |field| {
            let descriptor = field.read().cast::<u8>();
            if !descriptor.is_null() {
                count(descriptor).fetch_add(1, Ordering::AcqRel);
            }
            descriptor
        })
    }
}

/// The object is going: give up its own reference to its descriptor.
///
/// # Safety
/// `body` is an object nothing refers to any more.
pub(super) unsafe fn object_freed(body: *mut u8) {
    // SAFETY: per the contract: nobody else can reach the field.
    unsafe {
        let descriptor = (&raw const (*object::header(body)).SecurityDescriptor).read();
        if !descriptor.is_null() {
            release(descriptor.cast());
        }
    }
}

// ---- tests --------------------------------------------------------------

/// An object carries a descriptor in its header as a binary would find
/// it; a reader's reference outlives a replacement; the object's going
/// frees what it carried.
pub fn self_test() -> Result<(), &'static str> {
    use nk_ntabi::ob::{OBJECT_BODY, OBJECT_HEADER};
    use nk_se::Parts;
    let relative = |owner: &[u8]| {
        let parts = Parts {
            control: 0,
            owner: Some(owner),
            group: None,
            sacl: None,
            dacl: None,
        };
        let mut bytes = alloc::vec![0u8; parts.relative_length()];
        parts.write_relative(&mut bytes).map(|_| bytes)
    };
    let (Ok(first), Ok(second)) = (
        relative(&nk_se::token::LOCAL_SYSTEM),
        relative(&nk_se::token::ADMINISTRATORS),
    ) else {
        return Err("a descriptor could not be built");
    };
    let before = pool::usage().blocks;
    let body = object::create(&object::EVENT_TYPE, size_of::<nk_ntabi::ke::KEVENT>())
        .ok_or("no memory")?;
    // SAFETY: a live object this test holds the only reference to; the
    // descriptors are read while referenced.
    let verdict = unsafe {
        (|| {
            let field = || {
                let header = body.sub(OBJECT_BODY).cast::<OBJECT_HEADER>();
                (&raw const (*header).SecurityDescriptor)
                    .read()
                    .cast::<u8>()
            };
            let bytes = |at: *mut u8, len: usize| core::slice::from_raw_parts(at, len);
            if !field().is_null() || !reference(body).is_null() {
                return Err("a new object already has a security descriptor");
            }
            if !set(body, &first) {
                return Err("no memory for a descriptor");
            }
            let held = reference(body);
            if held.is_null() || held != field() || held as usize & 0xF != 0 {
                return Err("the header does not point at the descriptor, count bits clear");
            }
            if bytes(held, first.len()) != &first[..] || pool::usage().blocks != before + 2 {
                return Err("the object's descriptor is not a copy in one block of its own");
            }
            // Replaced while a reader holds the old one.
            if !set(body, &second) {
                release(held);
                return Err("no memory for a descriptor");
            }
            let now = reference(body);
            let kept = bytes(held, first.len()) == &first[..] && pool::usage().blocks == before + 3;
            let replaced = now != held && bytes(now, second.len()) == &second[..];
            release(now);
            release(held);
            if !kept {
                return Err("a descriptor was freed while a reader held it");
            }
            if !replaced || pool::usage().blocks != before + 2 {
                return Err("replacing a descriptor did not leave the new one alone");
            }
            Ok(())
        })()
    };
    // SAFETY: the creating reference.
    unsafe { object::dereference(body) };
    verdict?;
    if pool::usage().blocks != before {
        return Err("an object's descriptor outlived the object");
    }
    Ok(())
}
