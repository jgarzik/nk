//! The pool's record of its large blocks: an open-addressed table, keyed
//! by a block's address, over slots the caller provides, so the kernel
//! can back it with frames of its own and grow it by moving every entry
//! into a larger slice. Linear probing, deletion by moving the probe run
//! back, never more than three quarters full.

/// One large block: its address (0 is an empty slot), its pages, the
/// size asked for and the caller's tag.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Entry {
    pub addr: usize,
    pub pages: usize,
    pub size: usize,
    pub tag: u32,
}

impl Entry {
    pub const EMPTY: Entry = Entry {
        addr: 0,
        pages: 0,
        size: 0,
        tag: 0,
    };
}

/// The slot `addr` hashes to in a table of `len` slots (a power of two).
fn home(addr: usize, len: usize) -> usize {
    ((addr >> 12).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 7) & (len - 1)
}

/// Whether a table of `len` slots holding `used` entries must grow
/// before another is added.
pub fn full(len: usize, used: usize) -> bool {
    (used + 1) * 4 > len * 3
}

/// The slot holding `addr`, if any.
pub fn find(slots: &[Entry], addr: usize) -> Option<usize> {
    if slots.is_empty() || addr == 0 {
        return None;
    }
    let mask = slots.len() - 1;
    let mut at = home(addr, slots.len());
    loop {
        match slots[at].addr {
            0 => return None,
            a if a == addr => return Some(at),
            _ => at = (at + 1) & mask,
        }
    }
}

/// Add `entry`, whose address is not in the table, which must not be
/// [`full`].
pub fn insert(slots: &mut [Entry], entry: Entry) {
    debug_assert!(entry.addr != 0);
    let mask = slots.len() - 1;
    let mut at = home(entry.addr, slots.len());
    while slots[at].addr != 0 {
        at = (at + 1) & mask;
    }
    slots[at] = entry;
}

/// Take the entry for `addr` out, if there is one.
pub fn remove(slots: &mut [Entry], addr: usize) -> Option<Entry> {
    let mask = slots.len().checked_sub(1)?;
    let mut hole = find(slots, addr)?;
    let taken = slots[hole];
    slots[hole] = Entry::EMPTY;
    // Move back each later entry of the run that may no longer be
    // reachable from its home past the hole.
    let mut at = (hole + 1) & mask;
    while slots[at].addr != 0 {
        let h = home(slots[at].addr, slots.len());
        let reachable = if hole <= at {
            hole < h && h <= at
        } else {
            hole < h || h <= at
        };
        if !reachable {
            slots[hole] = slots[at];
            slots[at] = Entry::EMPTY;
            hole = at;
        }
        at = (at + 1) & mask;
    }
    Some(taken)
}

/// Move every entry of `from` into `to`, which is empty and large enough.
pub fn rehash(from: &[Entry], to: &mut [Entry]) {
    for e in from.iter().filter(|e| e.addr != 0) {
        insert(to, *e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(addr: usize) -> Entry {
        Entry {
            addr,
            pages: 1,
            size: addr & 0xFFF,
            tag: 7,
        }
    }

    #[test]
    fn insert_find_remove_many() {
        let mut slots = std::vec![Entry::EMPTY; 64];
        let addrs: std::vec::Vec<usize> = (1..=40)
            .map(|i| 0xFFFF_8000_0000_0000 + i * 0x3000)
            .collect();
        for (n, &a) in addrs.iter().enumerate() {
            assert!(!full(slots.len(), n));
            insert(&mut slots, e(a));
        }
        for &a in &addrs {
            assert_eq!(slots[find(&slots, a).unwrap()].addr, a);
        }
        // Remove every other one; the rest stay findable.
        for &a in addrs.iter().step_by(2) {
            assert_eq!(remove(&mut slots, a).map(|x| x.addr), Some(a));
        }
        for (i, &a) in addrs.iter().enumerate() {
            assert_eq!(find(&slots, a).is_some(), i % 2 == 1, "{i}");
        }
        assert_eq!(remove(&mut slots, addrs[0]), None);
    }

    #[test]
    fn collisions_survive_deletion() {
        // Addresses that share a home in a small table.
        let mut slots = std::vec![Entry::EMPTY; 8];
        let mut same = std::vec::Vec::new();
        let mut a = 0x1000;
        while same.len() < 4 {
            if home(a, 8) == 3 {
                same.push(a);
            }
            a += 0x1000;
        }
        for &x in &same {
            insert(&mut slots, e(x));
        }
        remove(&mut slots, same[1]);
        for (i, &x) in same.iter().enumerate() {
            assert_eq!(find(&slots, x).is_some(), i != 1);
        }
    }

    #[test]
    fn rehash_keeps_everything() {
        let mut small = std::vec![Entry::EMPTY; 16];
        for i in 1..=12 {
            insert(&mut small, e(i * 0x1000));
        }
        assert!(full(16, 12));
        let mut big = std::vec![Entry::EMPTY; 32];
        rehash(&small, &mut big);
        for i in 1..=12 {
            assert!(find(&big, i * 0x1000).is_some());
        }
    }
}
