//! The object manager's tables, with no objects behind them: the
//! namespace that maps names to objects and symbolic links, and the
//! slots of a handle table.
//!
//! Both hold whatever the kernel puts in them (a pointer, in practice)
//! and never look inside it; the kernel wraps them in a lock and does
//! the reference counting.
//!
//! [`tree`] is the namespace: directories, and a path walk that follows
//! symbolic links and stops at the object whose type parses the rest.
//! [`handles`] is handle slots with granted access and attributes.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod handles;
pub mod header;
pub mod tree;

use alloc::vec::Vec;

/// How many symbolic links a lookup follows before giving up.
pub const MAX_LINK_DEPTH: usize = 8;

/// The slots of a handle table: each open handle has one, and a handle
/// is its slot's index. The lowest free slot is used first, so indices
/// stay small and a closed handle's number is given out again.
#[derive(Debug)]
pub struct Slots<T> {
    slots: Vec<Option<T>>,
}

impl<T> Slots<T> {
    pub const fn new() -> Self {
        Self { slots: Vec::new() }
    }

    /// Put `item` in the lowest free slot and return its index.
    pub fn insert(&mut self, item: T) -> usize {
        let index = match self.slots.iter().position(Option::is_none) {
            Some(free) => free,
            None => {
                self.slots.push(None);
                self.slots.len() - 1
            }
        };
        self.slots[index] = Some(item);
        index
    }

    /// What slot `index` holds, if it is in use.
    pub fn get(&self, index: usize) -> Option<&T> {
        self.slots.get(index)?.as_ref()
    }

    /// Empty slot `index` and return what it held, if it was in use.
    pub fn take(&mut self, index: usize) -> Option<T> {
        self.slots.get_mut(index)?.take()
    }

    /// Slots in use.
    pub fn count(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// The memory the table itself occupies, in bytes. It grows with the
    /// most slots ever in use at once and is kept.
    pub fn storage(&self) -> usize {
        self.slots.capacity() * size_of::<Option<T>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_slots_are_filled_lowest_first() {
        let mut slots = Slots::new();
        assert_eq!(slots.count(), 0);
        assert_eq!(slots.storage(), 0);
        assert_eq!(slots.insert('a'), 0);
        assert_eq!(slots.insert('b'), 1);
        assert_eq!(slots.insert('c'), 2);
        assert_eq!(slots.count(), 3);
        assert_eq!(slots.get(1), Some(&'b'));
        // A freed slot in the middle is the next one used.
        assert_eq!(slots.take(1), Some('b'));
        assert_eq!(slots.take(0), Some('a'));
        assert_eq!(slots.count(), 1);
        assert_eq!(slots.insert('d'), 0);
        assert_eq!(slots.insert('e'), 1);
        assert_eq!(slots.insert('f'), 3);
        assert_eq!(slots.get(0), Some(&'d'));
        assert_eq!(slots.get(2), Some(&'c'));
    }

    #[test]
    fn a_closed_or_unknown_slot_holds_nothing() {
        let mut slots = Slots::new();
        assert_eq!(slots.get(0), None);
        assert_eq!(slots.take(0), None);
        let index = slots.insert(5u8);
        assert_eq!(slots.get(index + 1), None);
        assert_eq!(slots.take(usize::MAX), None);
        assert_eq!(slots.take(index), Some(5));
        // Closed: it is gone, and closing it again does nothing.
        assert_eq!(slots.get(index), None);
        assert_eq!(slots.take(index), None);
        assert_eq!(slots.count(), 0);
    }

    #[test]
    fn the_table_keeps_the_room_of_its_fullest_moment() {
        let mut slots = Slots::new();
        for n in 0..10u64 {
            slots.insert(n);
        }
        let storage = slots.storage();
        assert!(storage >= 10 * size_of::<Option<u64>>());
        for n in 0..10 {
            slots.take(n);
        }
        assert_eq!(slots.count(), 0);
        assert_eq!(slots.storage(), storage);
        // And fills up again without growing.
        for n in 0..10u64 {
            slots.insert(n);
        }
        assert_eq!(slots.storage(), storage);
    }
}
