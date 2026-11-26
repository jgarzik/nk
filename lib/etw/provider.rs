//! The table of registered trace providers.
//!
//! A registration is one word, changed only by compare-and-swap, so the
//! table needs no lock and may be asked at any IRQL: a provider writes
//! events from wherever it runs. The word is zero while the slot is
//! free. While it is taken the word is the registration's handle, plus
//! one bit that says the provider's traits have been set.
//!
//! A handle names its slot and carries a number no other registration
//! ever had, so a handle that was unregistered stays invalid when its
//! slot is taken again.

use core::sync::atomic::{AtomicU64, Ordering};

/// Set in a slot's word, never in a handle: the provider's traits have
/// been set.
const TRAITS_SET: u64 = 1 << 63;
/// A handle's low bits: its slot's index, plus one.
const SLOT_BITS: u32 = 16;
const SLOT_MASK: u64 = (1 << SLOT_BITS) - 1;
/// The bits above them, below [`TRAITS_SET`]: which registration it is.
const SERIAL_MASK: u64 = (TRAITS_SET - 1) >> SLOT_BITS;

/// Why a provider's traits were not set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraitsError {
    /// The handle names no registration.
    NotRegistered,
    /// The registration has traits already: they are set once.
    AlreadySet,
}

/// Up to `N` registrations.
pub struct Registrations<const N: usize> {
    slots: [AtomicU64; N],
    /// How many registrations were ever made.
    made: AtomicU64,
}

impl<const N: usize> Registrations<N> {
    /// Every slot index fits a handle.
    const FITS: () = assert!(N as u64 <= SLOT_MASK);

    pub const fn new() -> Self {
        let () = Self::FITS;
        Self {
            slots: [const { AtomicU64::new(0) }; N],
            made: AtomicU64::new(0),
        }
    }

    /// The slot `handle` names and the word that slot holds, if the
    /// handle is that of the registration there.
    fn find(&self, handle: u64) -> Option<(&AtomicU64, u64)> {
        let index = (handle & SLOT_MASK).checked_sub(1)?;
        let slot = self.slots.get(usize::try_from(index).ok()?)?;
        let word = slot.load(Ordering::Acquire);
        (handle != 0 && handle & TRAITS_SET == 0 && word & !TRAITS_SET == handle)
            .then_some((slot, word))
    }

    /// Register a provider: its handle, never zero. `None` if every
    /// slot is taken.
    pub fn register(&self) -> Option<u64> {
        let serial = (self.made.fetch_add(1, Ordering::Relaxed) + 1) & SERIAL_MASK;
        self.slots.iter().enumerate().find_map(|(index, slot)| {
            let handle = serial << SLOT_BITS | (index as u64 + 1);
            slot.compare_exchange(0, handle, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
                .then_some(handle)
        })
    }

    /// Whether `handle` is that of a provider registered now.
    pub fn is_registered(&self, handle: u64) -> bool {
        self.find(handle).is_some()
    }

    /// Whether the provider `handle` names has its traits set; `None`
    /// if the handle names no registration.
    pub fn has_traits(&self, handle: u64) -> Option<bool> {
        self.find(handle).map(|(_, word)| word & TRAITS_SET != 0)
    }

    /// End the registration `handle` names. `false` if it names none:
    /// zero, a handle never given out, or one already unregistered.
    pub fn unregister(&self, handle: u64) -> bool {
        loop {
            let Some((slot, word)) = self.find(handle) else {
                return false;
            };
            // The word changes under a registration only by gaining its
            // traits bit: look again.
            if slot
                .compare_exchange(word, 0, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Note that the provider's traits are set, which happens once per
    /// registration.
    pub fn set_traits(&self, handle: u64) -> Result<(), TraitsError> {
        let (slot, word) = self.find(handle).ok_or(TraitsError::NotRegistered)?;
        if word & TRAITS_SET != 0 {
            return Err(TraitsError::AlreadySet);
        }
        // Whoever else changed the word either set the traits first or
        // ended the registration.
        match slot.compare_exchange(word, word | TRAITS_SET, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => Ok(()),
            Err(now) if now & !TRAITS_SET == handle => Err(TraitsError::AlreadySet),
            Err(_) => Err(TraitsError::NotRegistered),
        }
    }

    /// How many providers are registered now.
    pub fn count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.load(Ordering::Acquire) != 0)
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::sync::Arc;

    #[test]
    fn a_registration_has_a_handle_that_is_not_zero_until_it_is_ended() {
        let table = Registrations::<4>::new();
        let handle = table.register().unwrap();
        assert_ne!(handle, 0);
        assert!(table.is_registered(handle));
        assert_eq!(table.count(), 1);
        assert!(table.unregister(handle));
        assert!(!table.is_registered(handle));
        assert_eq!(table.count(), 0);
    }

    #[test]
    fn a_registration_ends_once() {
        let table = Registrations::<4>::new();
        let handle = table.register().unwrap();
        assert!(table.unregister(handle));
        assert!(!table.unregister(handle));
    }

    #[test]
    fn zero_and_handles_never_given_out_name_nothing() {
        let table = Registrations::<4>::new();
        let handle = table.register().unwrap();
        for stray in [
            0,
            1,
            5,
            SLOT_MASK,
            handle + 1,
            handle ^ (1 << SLOT_BITS),
            handle | TRAITS_SET,
            u64::MAX,
        ] {
            assert!(!table.is_registered(stray), "{stray:#x}");
            assert!(!table.unregister(stray), "{stray:#x}");
            assert_eq!(
                table.set_traits(stray),
                Err(TraitsError::NotRegistered),
                "{stray:#x}"
            );
        }
        assert!(table.is_registered(handle));
    }

    #[test]
    fn a_stale_handle_stays_invalid_when_its_slot_is_taken_again() {
        let table = Registrations::<1>::new();
        let first = table.register().unwrap();
        assert!(table.unregister(first));
        let second = table.register().unwrap();
        assert_ne!(first, second);
        assert!(!table.is_registered(first));
        assert!(!table.unregister(first));
        assert!(table.is_registered(second));
    }

    #[test]
    fn a_full_table_refuses_and_a_freed_slot_is_used_again() {
        let table = Registrations::<3>::new();
        let handles: Vec<u64> = (0..3).map(|_| table.register().unwrap()).collect();
        assert_eq!(handles.iter().collect::<HashSet<_>>().len(), 3);
        assert_eq!(table.register(), None);
        assert!(table.unregister(handles[1]));
        let again = table.register().unwrap();
        assert!(table.is_registered(again));
        assert_eq!(table.count(), 3);
    }

    #[test]
    fn traits_are_set_once_per_registration() {
        let table = Registrations::<2>::new();
        let handle = table.register().unwrap();
        assert_eq!(table.has_traits(handle), Some(false));
        assert_eq!(table.set_traits(handle), Ok(()));
        assert_eq!(table.has_traits(handle), Some(true));
        assert_eq!(table.set_traits(handle), Err(TraitsError::AlreadySet));
        // The registration is the same one, and ends like any other.
        assert!(table.is_registered(handle));
        assert!(table.unregister(handle));
        assert_eq!(table.set_traits(handle), Err(TraitsError::NotRegistered));
        assert_eq!(table.has_traits(handle), None);
        // A new registration in the slot starts without traits.
        let next = table.register().unwrap();
        assert_eq!(table.set_traits(next), Ok(()));
    }

    #[test]
    fn registrations_made_at_once_all_differ_and_all_end() {
        let table = Arc::new(Registrations::<64>::new());
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let table = Arc::clone(&table);
                std::thread::spawn(move || {
                    let mut seen = Vec::new();
                    for _ in 0..2000 {
                        let handle = table.register().expect("eight of 64 slots are in use");
                        assert!(table.is_registered(handle));
                        assert_eq!(table.set_traits(handle), Ok(()));
                        assert!(table.unregister(handle));
                        assert!(!table.is_registered(handle));
                        seen.push(handle);
                    }
                    seen
                })
            })
            .collect();
        let mut all = HashSet::new();
        for thread in threads {
            for handle in thread.join().unwrap() {
                assert!(all.insert(handle), "handle {handle:#x} given out twice");
            }
        }
        assert_eq!(table.count(), 0);
    }
}
