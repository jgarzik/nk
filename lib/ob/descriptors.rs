//! The store of security descriptors: one counted copy per distinct
//! descriptor, found again by what the descriptor says.
//!
//! A descriptor here is a run of bytes; two are the same descriptor if
//! their bytes are equal. Each stored copy has an [`Entry`] in front of
//! it, in one block the kernel allocates, and the entries hang in
//! buckets by a hash of the bytes. The store owns no memory and is
//! only touched under its owner's lock; the count alone may also be
//! raised without it, by someone who already holds a reference.
//!
//! This is the shape of the store Windows keeps for the descriptors of
//! its objects (`ObLogSecurityDescriptor`); the hash and the entry's
//! fields are NK's own, no binary can see them.

use core::sync::atomic::{AtomicIsize, Ordering};

/// Buckets of the store.
pub const BUCKETS: usize = 256;

/// A hash of a descriptor's bytes (FNV-1a). Equal bytes, equal hash.
pub fn hash(descriptor: &[u8]) -> u64 {
    descriptor.iter().fold(0xCBF2_9CE4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01B3)
    })
}

/// What precedes a stored descriptor in its block. As large and as
/// aligned as a pool block's alignment, so the descriptor after it is
/// 16-byte aligned: the low four bits of a pointer to it are free, as
/// the fast reference in an object's header needs.
#[repr(C, align(16))]
#[derive(Debug)]
pub struct Entry {
    /// The next entry of the bucket. The store's lock.
    next: *mut Entry,
    /// How many refer to the descriptor.
    references: AtomicIsize,
    hash: u64,
    /// The descriptor's length in bytes.
    length: usize,
}

const _: () = assert!(size_of::<Entry>() == 32 && align_of::<Entry>() == 16);

impl Entry {
    /// The entry for a descriptor of `length` bytes that hash to
    /// `hash`, referred to `references` times, in no bucket yet.
    pub const fn new(hash: u64, length: usize, references: isize) -> Self {
        Self {
            next: core::ptr::null_mut(),
            references: AtomicIsize::new(references),
            hash,
            length,
        }
    }

    /// Where the descriptor of `entry` is: right after it.
    pub const fn descriptor(entry: *mut Entry) -> *mut u8 {
        entry.wrapping_add(1).cast()
    }

    /// The entry of a stored `descriptor`.
    pub const fn of(descriptor: *mut u8) -> *mut Entry {
        descriptor.cast::<Entry>().wrapping_sub(1)
    }

    /// Count `count` more references to a descriptor the caller already
    /// holds one to. `false` if it had none: the caller's reference
    /// was no reference, and nothing is to be trusted.
    ///
    /// # Safety
    /// `entry` is an entry whose block is still allocated.
    pub unsafe fn add(entry: *mut Entry, count: usize) -> bool {
        // SAFETY: per the contract; the count is atomic.
        unsafe {
            (*entry)
                .references
                .fetch_add(count as isize, Ordering::AcqRel)
                > 0
        }
    }

    /// The bytes of the entry's descriptor.
    ///
    /// # Safety
    /// `entry` is an entry followed by its descriptor, and the block
    /// stays allocated and unchanged for `'a`.
    unsafe fn bytes<'a>(entry: *mut Entry) -> &'a [u8] {
        // SAFETY: per the contract.
        unsafe { core::slice::from_raw_parts(Self::descriptor(entry), (*entry).length) }
    }
}

/// What giving up references did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Released {
    /// Others still refer to the descriptor.
    Kept,
    /// Those were the last: the entry is out of the store and its block
    /// is the caller's to free.
    Last,
    /// More were given up than were held. Nothing was changed.
    TooMany,
}

/// The buckets.
#[derive(Debug)]
pub struct Store {
    buckets: [*mut Entry; BUCKETS],
}

// SAFETY: the store is pointers; whoever holds the lock around it may
// use it from any processor.
unsafe impl Send for Store {}

impl Store {
    pub const fn new() -> Self {
        Self {
            buckets: [core::ptr::null_mut(); BUCKETS],
        }
    }

    const fn bucket(hash: u64) -> usize {
        (hash % BUCKETS as u64) as usize
    }

    /// The stored descriptor equal to that of `candidate`, with `bias`
    /// more references; or, if there is none, `candidate` itself, now
    /// stored, with the references it was made with. A candidate that
    /// was not stored is the caller's to free.
    ///
    /// # Safety
    /// `candidate` is an entry in no bucket, followed by its descriptor,
    /// in a block that stays allocated until [`Store::release`] says
    /// otherwise; every stored entry is likewise valid.
    pub unsafe fn log(&mut self, candidate: *mut Entry, bias: usize) -> *mut Entry {
        // SAFETY: per the contract.
        unsafe {
            let (hash, bytes) = ((*candidate).hash, Entry::bytes(candidate));
            let head = &mut self.buckets[Self::bucket(hash)];
            let mut entry = *head;
            while !entry.is_null() {
                if (*entry).hash == hash && Entry::bytes(entry) == bytes {
                    (*entry)
                        .references
                        .fetch_add(bias as isize, Ordering::AcqRel);
                    return entry;
                }
                entry = (*entry).next;
            }
            (*candidate).next = *head;
            *head = candidate;
            candidate
        }
    }

    /// Give up `count` references to a stored descriptor.
    ///
    /// # Safety
    /// `entry` is a stored entry; every stored entry is valid.
    pub unsafe fn release(&mut self, entry: *mut Entry, count: usize) -> Released {
        // SAFETY: per the contract.
        unsafe {
            let references = &(*entry).references;
            let held = references.load(Ordering::Acquire);
            let count = count as isize;
            if count > held {
                return Released::TooMany;
            }
            // Raised only by holders, so it cannot rise from nothing:
            // a count that reaches zero here stays there.
            if references.fetch_sub(count, Ordering::AcqRel) != count {
                return Released::Kept;
            }
            let mut link = &raw mut self.buckets[Self::bucket((*entry).hash)];
            while *link != entry {
                link = &raw mut (**link).next;
            }
            *link = (*entry).next;
            Released::Last
        }
    }

    /// Descriptors stored.
    pub fn len(&self) -> usize {
        let mut entries = 0;
        for &head in &self.buckets {
            let mut entry = head;
            while !entry.is_null() {
                entries += 1;
                // SAFETY: stored entries are valid.
                entry = unsafe { (*entry).next };
            }
        }
        entries
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(|head| head.is_null())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    /// An entry and room for a small descriptor, as one block.
    #[repr(C)]
    struct Block {
        entry: Entry,
        bytes: [u8; 16],
    }

    fn block(bytes: &[u8], hash: u64, references: isize) -> *mut Entry {
        let mut room = [0; 16];
        room[..bytes.len()].copy_from_slice(bytes);
        Box::into_raw(Box::new(Block {
            entry: Entry::new(hash, bytes.len(), references),
            bytes: room,
        }))
        .cast()
    }

    fn candidate(bytes: &[u8], references: isize) -> *mut Entry {
        block(bytes, hash(bytes), references)
    }

    fn free(entry: *mut Entry) {
        // SAFETY: a block from `block`, in no store.
        drop(unsafe { Box::from_raw(entry.cast::<Block>()) });
    }

    fn references(entry: *mut Entry) -> isize {
        // SAFETY: the tests' blocks are live.
        unsafe { (*entry).references.load(Ordering::Acquire) }
    }

    #[test]
    fn the_hash_goes_by_the_bytes() {
        assert_eq!(hash(b"owner"), hash(b"owner"));
        assert_ne!(hash(b"owner"), hash(b"ownes"));
        assert_ne!(hash(b""), hash(b"\0"));
    }

    #[test]
    fn a_descriptor_sits_right_after_its_entry() {
        let entry = candidate(b"abc", 1);
        let descriptor = Entry::descriptor(entry);
        assert_eq!(descriptor.addr(), entry.addr() + 32);
        assert_eq!(descriptor.addr() % 16, 0);
        assert_eq!(Entry::of(descriptor), entry);
        free(entry);
    }

    #[test]
    fn equal_bytes_are_stored_once_and_counted() {
        let mut store = Store::new();
        assert!(store.is_empty());
        // SAFETY: the blocks live until freed below, after release.
        unsafe {
            let first = candidate(b"one", 1);
            assert_eq!(store.log(first, 1), first);
            assert_eq!(references(first), 1, "made with its references");
            let again = candidate(b"one", 3);
            assert_eq!(store.log(again, 3), first, "the stored copy comes back");
            assert_eq!(references(first), 4);
            free(again);
            let other = candidate(b"two", 1);
            assert_eq!(store.log(other, 1), other);
            assert_eq!(store.len(), 2);

            assert!(Entry::add(first, 2));
            assert_eq!(references(first), 6);
            assert_eq!(store.release(first, 5), Released::Kept);
            assert_eq!(store.release(first, 2), Released::TooMany);
            assert_eq!(references(first), 1, "too many changes nothing");
            assert_eq!(store.release(first, 1), Released::Last);
            assert_eq!(store.len(), 1);
            // Gone from the store: the same bytes are stored anew.
            let anew = candidate(b"one", 1);
            assert_eq!(store.log(anew, 1), anew);
            free(first);
            assert_eq!(store.release(anew, 1), Released::Last);
            assert_eq!(store.release(other, 1), Released::Last);
            free(anew);
            free(other);
        }
        assert!(store.is_empty());
    }

    #[test]
    fn a_reference_to_nothing_is_reported() {
        let entry = candidate(b"x", 0);
        // SAFETY: a live block.
        assert!(!unsafe { Entry::add(entry, 1) });
        free(entry);
    }

    #[test]
    fn descriptors_that_share_a_bucket_stay_apart() {
        let mut store = Store::new();
        // The same hash, forced: only the bytes tell them apart. And
        // one more with the same bytes but another length.
        let entries: Vec<*mut Entry> = [&b"aa"[..], b"ab", b"ac", b"a"]
            .iter()
            .map(|bytes| block(bytes, 7, 1))
            .collect();
        // SAFETY: the blocks live until freed below.
        unsafe {
            for &entry in &entries {
                assert_eq!(store.log(entry, 1), entry);
            }
            assert_eq!(store.len(), 4);
            let probe = block(b"ab", 7, 1);
            assert_eq!(store.log(probe, 1), entries[1]);
            free(probe);
            assert_eq!(references(entries[1]), 2);
            // Taken out of the middle, the front and the back of the
            // bucket's chain.
            assert_eq!(store.release(entries[1], 2), Released::Last);
            assert_eq!(store.release(entries[3], 1), Released::Last);
            assert_eq!(store.release(entries[0], 1), Released::Last);
            assert_eq!(store.len(), 1);
            assert_eq!(store.release(entries[2], 1), Released::Last);
        }
        assert!(store.is_empty());
        for entry in entries {
            free(entry);
        }
    }
}
