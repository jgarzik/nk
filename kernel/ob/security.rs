//! The store of security descriptors, and the descriptor an object
//! carries in its header (`OBJECT_HEADER.SecurityDescriptor`).
//!
//! A stored descriptor is a self-relative copy in a pool block of its
//! own, counted, and there is one copy per distinct descriptor: logging
//! the same bytes again gives the same copy with more references
//! (`nk_ob::descriptors`). File systems log the descriptors of their
//! files and hold the copies (`ObLogSecurityDescriptor`), as Windows
//! has them do. An object holds one reference to the copy in its
//! header, and whoever reads it takes another for as long as it looks,
//! so replacing an object's descriptor never frees one that is being
//! read.
//!
//! The store is under its own lock, held only to search a bucket's
//! chain and to link or unlink an entry: blocks are allocated before it
//! is taken and freed after it is dropped.
//!
//! The header's field points at the descriptor itself. On Windows it
//! is a fast reference, a pointer whose low four bits are a count; a
//! descriptor here is 16-byte aligned and the bits are zero.
//!
//! The field belongs to the object's own lock, the header's `Lock`
//! word, held with the IRQL at `DISPATCH_LEVEL` and only for as long
//! as it takes to read or swap a pointer and count a reference. The
//! word is where Windows has it; the hold is ranked and recorded like
//! a spin lock's, innermost of the locks at that level
//! (`doc/LOCKING.md`).
//!
//! Devices do not use this: a device's descriptor is in
//! `DEVICE_OBJECT.SecurityDescriptor`, where drivers can see it, as on
//! Windows (`io::device`).

#![allow(non_snake_case)]

use super::object;
use crate::ke::{Rank, Ranked, SpinLock};
use crate::mm::pool;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};
use nk_ntabi::status::*;
use nk_ob::descriptors::{Entry, Released, Store, hash};

/// Pool tag of stored security descriptors, Windows' own for them.
const TAG: u32 = u32::from_le_bytes(*b"ObSc");

static STORE: SpinLock<Store> = SpinLock::new(Rank::Descriptors, Store::new());

/// Descriptors stored.
pub fn stored() -> usize {
    STORE.lock().len()
}

/// The stored copy of the `length` bytes at `descriptor`, with `bias`
/// references for the caller; `None` without memory. The bytes are
/// read once, into the block that becomes the stored copy if there is
/// none yet: the search runs on that copy, never on the caller's
/// memory.
///
/// # Safety
/// `descriptor` points to `length` readable bytes.
unsafe fn log(descriptor: *const u8, length: usize, bias: usize) -> Option<*mut u8> {
    let block = pool::alloc(size_of::<Entry>() + length, TAG).cast::<Entry>();
    if block.is_null() {
        return None;
    }
    // SAFETY: a fresh block of that size, which the pool aligns to 16
    // bytes; per the contract for the source. The block is this
    // function's alone until the store has it.
    unsafe {
        let copy = Entry::descriptor(block);
        copy.copy_from_nonoverlapping(descriptor, length);
        let bytes = core::slice::from_raw_parts(copy, length);
        block.write(Entry::new(hash(bytes), length, bias as isize));
        let stored = STORE.lock().log(block, bias);
        if stored != block {
            let freed = pool::free(block.cast());
            debug_assert!(freed.is_ok());
        }
        Some(Entry::descriptor(stored))
    }
}

/// A descriptor's count was not what its holder's reference implies.
/// Windows stops here too (a fast fail, bugcheck `0x139`).
fn corrupt() -> ! {
    crate::kd::bugcheck(format_args!(
        "0x00000139 KERNEL_SECURITY_CHECK_FAILURE: a security descriptor's reference count \
         went wrong (parameters 0xe, 0, 0, 0)"
    ))
}

/// Give up `count` references to a stored descriptor; the last one
/// takes it out of the store and frees it.
///
/// # Safety
/// `descriptor` is a stored descriptor and the caller owns `count` of
/// its references.
unsafe fn release_many(descriptor: *mut u8, count: usize) {
    let entry = Entry::of(descriptor);
    // SAFETY: per the contract. The block is freed after the store's
    // lock is dropped: freeing takes the pool's.
    unsafe {
        let released = STORE.lock().release(entry, count);
        match released {
            Released::Kept => {}
            Released::Last => {
                let freed = pool::free(entry.cast());
                debug_assert!(freed.is_ok());
            }
            Released::TooMany => corrupt(),
        }
    }
}

/// Give up a reference to a descriptor; the last one frees it.
///
/// # Safety
/// `descriptor` came from [`reference`] (or was an object's own) and
/// the caller owns one of its references.
pub unsafe fn release(descriptor: *mut u8) {
    // SAFETY: per the contract.
    unsafe { release_many(descriptor, 1) };
}

/// `ObLogSecurityDescriptor` (`ntoskrnl.exe` exports it; the kit's
/// headers do not declare it): the stored copy of a self-relative
/// security descriptor, the same copy for the same bytes, with
/// `ref_bias` references the caller gives up through
/// [`ObDereferenceSecurityDescriptor`]. The descriptor's length is what
/// [`RtlLengthSecurityDescriptor`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtllengthsecuritydescriptor)
/// says. Nothing is written without memory
/// (`STATUS_INSUFFICIENT_RESOURCES`).
///
/// # Safety
/// `input` points to a self-relative security descriptor; `output`
/// points to room for a pointer.
pub unsafe extern "C" fn ObLogSecurityDescriptor(
    input: *const c_void,
    output: *mut *mut c_void,
    ref_bias: u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let length = crate::se::RtlLengthSecurityDescriptor(input) as usize;
        match log(input.cast(), length, ref_bias as usize) {
            Some(stored) => {
                output.write_unaligned(stored.cast());
                STATUS_SUCCESS
            }
            None => STATUS_INSUFFICIENT_RESOURCES,
        }
    }
}

/// `ObReferenceSecurityDescriptor`: `count` more references to a stored
/// descriptor the caller already holds one to.
///
/// # Safety
/// `descriptor` is a stored descriptor the caller holds a reference
/// to.
pub unsafe extern "C" fn ObReferenceSecurityDescriptor(descriptor: *mut c_void, count: u32) {
    // SAFETY: per the contract.
    if !unsafe { Entry::add(Entry::of(descriptor.cast()), count as usize) } {
        corrupt();
    }
}

/// `ObDereferenceSecurityDescriptor`: give up `count` references to a
/// stored descriptor; with the last it leaves the store and is freed.
///
/// # Safety
/// `descriptor` is a stored descriptor and the caller owns `count` of
/// its references.
pub unsafe extern "C" fn ObDereferenceSecurityDescriptor(descriptor: *mut c_void, count: u32) {
    // SAFETY: per the contract.
    unsafe { release_many(descriptor.cast(), count as usize) };
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
        let hold = Ranked::enter(lock.as_ptr().addr(), Rank::ObjectHeader);
        while lock
            .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            core::hint::spin_loop();
        }
        let result = f(&raw mut (*header).SecurityDescriptor);
        lock.store(0, Ordering::Release);
        drop(hold);
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
    // SAFETY: the slice is readable for its length.
    let Some(new) = (unsafe { log(descriptor.as_ptr(), descriptor.len(), 1) }) else {
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
            if !descriptor.is_null() && !Entry::add(Entry::of(descriptor), 1) {
                corrupt();
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

/// The object's descriptor, looked at and let go of again.
///
/// # Safety
/// As [`reference`].
unsafe fn reference_and_release(body: *mut u8) -> *mut u8 {
    // SAFETY: per the contract.
    unsafe {
        let descriptor = reference(body);
        if !descriptor.is_null() {
            release(descriptor);
        }
        descriptor
    }
}

/// A self-relative descriptor that names `owner` and nothing else.
fn owned_by(owner: &[u8]) -> Result<alloc::vec::Vec<u8>, &'static str> {
    let parts = nk_se::Parts {
        control: 0,
        owner: Some(owner),
        group: None,
        sacl: None,
        dacl: None,
    };
    let mut bytes = alloc::vec![0u8; parts.relative_length()];
    parts
        .write_relative(&mut bytes)
        .map(|_| bytes)
        .map_err(|_| "a descriptor could not be built")
}

/// Log a descriptor as a driver does; the stored copy, or null.
fn logged(descriptor: &[u8], bias: u32) -> *mut u8 {
    let mut stored = core::ptr::dangling_mut::<c_void>();
    // SAFETY: a self-relative descriptor and a local for the result.
    let status =
        unsafe { ObLogSecurityDescriptor(descriptor.as_ptr().cast(), &raw mut stored, bias) };
    if status == STATUS_SUCCESS {
        stored.cast()
    } else {
        core::ptr::null_mut()
    }
}

/// The store as a file system uses it: the same bytes, wherever they
/// are, give one stored copy, counted; other bytes another; the copy
/// goes with its last reference and not before. Returns the
/// descriptors logged.
pub fn store_test() -> Result<u32, &'static str> {
    let first = owned_by(&nk_se::token::LOCAL_SYSTEM)?;
    let elsewhere = first.clone();
    let second = owned_by(&nk_se::token::ADMINISTRATORS)?;
    let (blocks, entries) = (pool::usage().blocks, stored());
    let one = logged(&first, 1);
    if one.is_null() {
        return Err("no memory for a descriptor");
    }
    // SAFETY: stored descriptors this test holds references to, read
    // while it does.
    unsafe {
        let bytes = |at: *mut u8, len: usize| core::slice::from_raw_parts(at, len);
        if one == first.as_ptr().cast_mut()
            || bytes(one, first.len()) != &first[..]
            || one as usize & 0xF != 0
        {
            release(one);
            return Err("logging did not give back an aligned copy of the descriptor");
        }
        // Three more references in one go, from other memory.
        let (again, other) = (logged(&elsewhere, 3), logged(&second, 1));
        let same = again == one && other != one && !other.is_null();
        if !same {
            // Each pointer is let go of as often as it was handed out.
            for (stored, count) in [(one, 1), (again, 3), (other, 1)] {
                if !stored.is_null() {
                    ObDereferenceSecurityDescriptor(stored.cast(), count);
                }
            }
            return Err("the same bytes did not give the same stored copy, or other bytes did");
        }
        let counted = (stored() == entries + 2, pool::usage().blocks == blocks + 2);
        // Five references to the first now: two more taken, six given
        // up, and it is still there for the seventh.
        ObReferenceSecurityDescriptor(one.cast(), 2);
        ObDereferenceSecurityDescriptor(one.cast(), 2);
        ObDereferenceSecurityDescriptor(one.cast(), 3);
        let kept = stored() == entries + 2 && bytes(one, first.len()) == &first[..];
        ObDereferenceSecurityDescriptor(one.cast(), 1);
        let gone = stored() == entries + 1;
        // Stored afresh once it has gone.
        let anew = logged(&first, 1);
        let fresh = stored() == entries + 2;
        if !anew.is_null() {
            ObDereferenceSecurityDescriptor(anew.cast(), 1);
        }
        ObDereferenceSecurityDescriptor(other.cast(), 1);
        if counted != (true, true) {
            return Err("two distinct descriptors are not two entries in two blocks");
        }
        if !kept {
            return Err("a descriptor left the store while references remained");
        }
        if !gone || !fresh {
            return Err("a descriptor did not leave the store with its last reference");
        }
    }
    if stored() != entries || pool::usage().blocks != blocks {
        return Err("the store kept a descriptor nothing refers to");
    }
    Ok(4)
}

static LOG_WRONG: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static LOG_BYTES: core::sync::atomic::AtomicPtr<alloc::vec::Vec<u8>> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Threads on every processor log and let go of the same descriptor at
/// once: while any holds it they all hold one copy, and it is gone
/// when the last lets go. Returns the descriptors logged.
pub fn store_smp_test() -> Result<u32, &'static str> {
    use crate::ke::{thread, time};
    const ROUNDS: u32 = 2000;
    fn body(_: usize) {
        // SAFETY: the test keeps the bytes until every thread has
        // ended.
        let bytes = unsafe { &*LOG_BYTES.load(Ordering::Acquire) };
        for _ in 0..ROUNDS {
            let stored = logged(bytes, 2);
            if stored.is_null() {
                LOG_WRONG.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            // SAFETY: a stored descriptor this thread holds two
            // references to, read while it does.
            unsafe {
                if core::slice::from_raw_parts(stored, bytes.len()) != &bytes[..] {
                    LOG_WRONG.fetch_add(1, Ordering::Relaxed);
                }
                ObDereferenceSecurityDescriptor(stored.cast(), 1);
                ObDereferenceSecurityDescriptor(stored.cast(), 1);
            }
        }
    }
    let mut bytes = owned_by(&nk_se::token::LOCAL_SYSTEM)?;
    let (blocks, entries, threads_before) = (pool::usage().blocks, stored(), thread::count());
    LOG_BYTES.store(&raw mut bytes, Ordering::Release);
    LOG_WRONG.store(0, Ordering::Relaxed);
    let processors = crate::ke::smp::online_count();
    let threads = processors.max(2);
    for n in 0..threads {
        thread::create(body, 0, thread::NORMAL_PRIORITY, 1 << (n % processors))?;
    }
    let deadline = time::interrupt_time() + 100_000_000;
    while thread::count() != threads_before && time::interrupt_time() < deadline {
        thread::yield_now();
    }
    if thread::count() != threads_before {
        return Err("the threads did not finish");
    }
    LOG_BYTES.store(core::ptr::null_mut(), Ordering::Release);
    if LOG_WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a logged descriptor was not a copy of what was logged");
    }
    if stored() != entries || pool::usage().blocks != blocks {
        return Err("descriptors logged on several processors were left in the store");
    }
    Ok(threads as u32 * ROUNDS)
}

/// An object carries a descriptor in its header as a binary would find
/// it; a reader's reference outlives a replacement; the object's going
/// frees what it carried; and objects with equal descriptors share one
/// stored copy.
pub fn self_test() -> Result<(), &'static str> {
    use nk_ntabi::ob::{OBJECT_BODY, OBJECT_HEADER};
    let first = owned_by(&nk_se::token::LOCAL_SYSTEM)?;
    let second = owned_by(&nk_se::token::ADMINISTRATORS)?;
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
            // A second object with the same descriptor shares the copy.
            let twin = object::create(&object::EVENT_TYPE, size_of::<nk_ntabi::ke::KEVENT>())
                .ok_or("no memory")?;
            let shared = set(twin, &second) && {
                let theirs = reference(twin);
                let same = theirs == field() && pool::usage().blocks == before + 3;
                release(theirs);
                same
            };
            object::dereference(twin);
            if !shared || reference_and_release(body) != field() {
                return Err("two objects with one descriptor do not share its stored copy");
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
