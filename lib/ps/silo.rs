//! Silo context slots: the numbers under which drivers keep their
//! per-silo contexts.
//!
//! A driver allocates a slot once and then keeps one context per silo
//! under it
//! ([`PsAllocSiloContextSlot`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psallocsilocontextslot)).
//! Windows 10 has 288 slots, 32 in every silo's storage and 256 more
//! in a part made when first needed, and hands out the lowest free
//! one; a driver sees the numbers, so NK has the same.

/// Slots in every silo's storage.
pub const DIRECT_SLOTS: u32 = 32;
/// Slots beyond those.
pub const EXTENDED_SLOTS: u32 = 256;
/// Slots there are.
pub const SLOTS: usize = (DIRECT_SLOTS + EXTENDED_SLOTS) as usize;

const WORDS: usize = SLOTS.div_ceil(64);

/// Which slots are allocated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slots {
    taken: [u64; WORDS],
}

impl Slots {
    pub const fn new() -> Self {
        Self { taken: [0; WORDS] }
    }

    /// Whether `slot` is a slot number at all.
    pub const fn exists(slot: u32) -> bool {
        (slot as usize) < SLOTS
    }

    /// Whether `slot` is allocated.
    pub const fn allocated(&self, slot: u32) -> bool {
        Self::exists(slot) && self.taken[slot as usize / 64] & 1 << (slot % 64) != 0
    }

    /// Allocate the lowest free slot; `None` when all are taken.
    pub fn allocate(&mut self) -> Option<u32> {
        let slot = (0..SLOTS as u32).find(|&slot| !self.allocated(slot))?;
        self.taken[slot as usize / 64] |= 1 << (slot % 64);
        Some(slot)
    }

    /// Free `slot`. `false`, and nothing changes, if it is not a slot
    /// or is not allocated.
    pub fn free(&mut self, slot: u32) -> bool {
        if !self.allocated(slot) {
            return false;
        }
        self.taken[slot as usize / 64] &= !(1 << (slot % 64));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lowest_free_slot_is_handed_out() {
        let mut slots = Slots::new();
        assert_eq!(slots.allocate(), Some(0));
        assert_eq!(slots.allocate(), Some(1));
        assert_eq!(slots.allocate(), Some(2));
        assert!(slots.free(1));
        assert!(!slots.allocated(1) && slots.allocated(0) && slots.allocated(2));
        assert_eq!(
            slots.allocate(),
            Some(1),
            "a freed slot is the lowest again"
        );
        assert_eq!(slots.allocate(), Some(3));
    }

    #[test]
    fn a_slot_is_freed_once() {
        let mut slots = Slots::new();
        assert!(!slots.free(0), "never allocated");
        let slot = slots.allocate().unwrap();
        assert!(slots.free(slot));
        assert!(!slots.free(slot), "freed already");
        assert!(!slots.free(SLOTS as u32), "no such slot");
        assert!(!slots.free(0xFFFF));
        assert_eq!(slots, Slots::new());
    }

    #[test]
    fn there_are_two_hundred_and_eighty_eight() {
        let mut slots = Slots::new();
        for expected in 0..SLOTS as u32 {
            assert_eq!(slots.allocate(), Some(expected));
        }
        assert_eq!(slots.allocate(), None);
        assert!(Slots::exists(SLOTS as u32 - 1) && !Slots::exists(SLOTS as u32));
        assert!(slots.allocated(DIRECT_SLOTS) && !slots.allocated(SLOTS as u32));
        // One past the direct slots is the first of the rest.
        assert!(slots.free(DIRECT_SLOTS));
        assert_eq!(slots.allocate(), Some(DIRECT_SLOTS));
    }
}
