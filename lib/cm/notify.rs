//! Who is to be told when a key changes
//! ([`ZwNotifyChangeKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwnotifychangekey)).
//!
//! A watch is on one key, for some kinds of change, and may take in the
//! keys below it. It is told once: the change that meets it takes it
//! out. A watch is made through a key handle and ends with it.

extern crate alloc;

use alloc::vec::Vec;

/// `REG_NOTIFY_CHANGE_NAME`: a subkey was made or deleted.
pub const CHANGE_NAME: u32 = 1;
/// `REG_NOTIFY_CHANGE_ATTRIBUTES`.
pub const CHANGE_ATTRIBUTES: u32 = 2;
/// `REG_NOTIFY_CHANGE_LAST_SET`: a value was set or deleted.
pub const CHANGE_LAST_SET: u32 = 4;
/// `REG_NOTIFY_CHANGE_SECURITY`.
pub const CHANGE_SECURITY: u32 = 8;
/// `REG_NOTIFY_THREAD_AGNOSTIC`: the watch does not end with the thread
/// that made it. No watch of NK's does.
pub const THREAD_AGNOSTIC: u32 = 0x1000_0000;
/// `REG_LEGAL_CHANGE_FILTER`.
pub const LEGAL_FILTER: u32 =
    CHANGE_NAME | CHANGE_ATTRIBUTES | CHANGE_LAST_SET | CHANGE_SECURITY | THREAD_AGNOSTIC;

/// Whether `filter` asks for some change and for nothing unknown.
pub fn filter_is_legal(filter: u32) -> bool {
    filter != 0 && filter & !LEGAL_FILTER == 0
}

/// One watch. `what` is whatever is to be done when it is met.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Watch<T> {
    /// The key watched.
    pub key: usize,
    /// What the watch was made through, and ends with: a key object.
    pub owner: usize,
    /// The kinds of change watched for.
    pub filter: u32,
    /// Whether changes to the keys below count too.
    pub subtree: bool,
    pub what: T,
}

/// The watches there are.
pub struct Watches<T> {
    list: Vec<Watch<T>>,
}

impl<T> Watches<T> {
    pub const fn new() -> Self {
        Self { list: Vec::new() }
    }

    /// Add a watch. Given back when there is no memory for it.
    pub fn add(&mut self, watch: Watch<T>) -> Result<(), Watch<T>> {
        if self.list.try_reserve(1).is_err() {
            return Err(watch);
        }
        self.list.push(watch);
        Ok(())
    }

    /// Take out the watches `met` picks. None, and every watch stays,
    /// when there is no memory to hand them over in. The table holds
    /// no memory once it is empty.
    fn take(&mut self, met: impl Fn(&Watch<T>) -> bool) -> Option<Vec<Watch<T>>> {
        let count = self.list.iter().filter(|w| met(w)).count();
        let mut taken = Vec::new();
        taken.try_reserve_exact(count).ok()?;
        let mut i = 0;
        while i < self.list.len() {
            if met(&self.list[i]) {
                taken.push(self.list.remove(i));
            } else {
                i += 1;
            }
        }
        if self.list.is_empty() {
            self.list = Vec::new();
        }
        Some(taken)
    }

    /// The watches a change of the kinds `change` to a key meets, taken
    /// out: each is told once. `chain` is the key that changed, then
    /// the key it is a subkey of, and so on up. A watch on the key
    /// itself is met; one on a key above it only if it takes in its
    /// subtree.
    pub fn changed(&mut self, chain: &[usize], change: u32) -> Option<Vec<Watch<T>>> {
        self.take(|w| {
            w.filter & change != 0
                && chain
                    .iter()
                    .position(|&key| key == w.key)
                    .is_some_and(|depth| depth == 0 || w.subtree)
        })
    }

    /// The watches made through `owner`, taken out: it is closed.
    pub fn closed(&mut self, owner: usize) -> Option<Vec<Watch<T>>> {
        self.take(|w| w.owner == owner)
    }

    /// How many watches there are.
    pub fn count(&self) -> usize {
        self.list.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watch(key: usize, owner: usize, filter: u32, subtree: bool) -> Watch<u32> {
        Watch {
            key,
            owner,
            filter,
            subtree,
            what: owner as u32,
        }
    }

    fn owners(taken: Option<Vec<Watch<u32>>>) -> Vec<u32> {
        let mut owners: Vec<u32> = taken.unwrap().iter().map(|w| w.what).collect();
        owners.sort_unstable();
        owners
    }

    #[test]
    fn filters() {
        assert!(filter_is_legal(CHANGE_LAST_SET));
        assert!(filter_is_legal(LEGAL_FILTER));
        assert!(!filter_is_legal(0));
        assert!(!filter_is_legal(0x10));
        assert!(!filter_is_legal(CHANGE_NAME | 0x100));
    }

    #[test]
    fn a_watch_is_met_once_by_a_change_it_watches_for() {
        let mut watches = Watches::new();
        watches.add(watch(5, 1, CHANGE_LAST_SET, false)).unwrap();
        watches.add(watch(5, 2, CHANGE_NAME, false)).unwrap();
        watches
            .add(watch(5, 3, CHANGE_NAME | CHANGE_LAST_SET, false))
            .unwrap();
        watches.add(watch(6, 4, CHANGE_LAST_SET, false)).unwrap();
        // Key 5, under 2, under 0.
        assert_eq!(owners(watches.changed(&[5, 2, 0], CHANGE_LAST_SET)), [1, 3]);
        assert_eq!(watches.count(), 2);
        // Told once.
        assert_eq!(owners(watches.changed(&[5, 2, 0], CHANGE_LAST_SET)), []);
        assert_eq!(owners(watches.changed(&[5, 2, 0], CHANGE_NAME)), [2]);
        assert_eq!(owners(watches.changed(&[6, 0], CHANGE_LAST_SET)), [4]);
        assert_eq!(watches.count(), 0);
    }

    #[test]
    fn a_watch_above_is_met_only_with_its_subtree() {
        let mut watches = Watches::new();
        watches.add(watch(2, 1, CHANGE_LAST_SET, true)).unwrap();
        watches.add(watch(2, 2, CHANGE_LAST_SET, false)).unwrap();
        watches.add(watch(0, 3, CHANGE_LAST_SET, true)).unwrap();
        watches.add(watch(9, 4, CHANGE_LAST_SET, true)).unwrap();
        assert_eq!(owners(watches.changed(&[5, 2, 0], CHANGE_LAST_SET)), [1, 3]);
        // The watch without its subtree is met by a change to its key.
        assert_eq!(owners(watches.changed(&[2, 0], CHANGE_LAST_SET)), [2]);
        assert_eq!(watches.count(), 1);
    }

    #[test]
    fn closing_ends_the_watches_made_through_it() {
        let mut watches = Watches::new();
        watches.add(watch(5, 1, CHANGE_NAME, false)).unwrap();
        watches.add(watch(6, 1, CHANGE_NAME, false)).unwrap();
        watches.add(watch(5, 2, CHANGE_NAME, false)).unwrap();
        assert_eq!(owners(watches.closed(1)), [1, 1]);
        assert_eq!(owners(watches.closed(1)), []);
        assert_eq!(watches.count(), 1);
        assert_eq!(owners(watches.closed(2)), [2]);
    }
}
