//! The Unicode prefix table: the logic of
//! [`RtlInitializeUnicodePrefix`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitializeunicodeprefix),
//! [`RtlInsertUnicodePrefix`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinsertunicodeprefix),
//! [`RtlRemoveUnicodePrefix`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlremoveunicodeprefix),
//! [`RtlFindUnicodePrefix`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlfindunicodeprefix)
//! and
//! [`RtlNextUnicodePrefix`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlnextunicodeprefix).
//!
//! A file system keeps the path names it knows in such a table and asks
//! it which known name is the longest start, on a component boundary,
//! of a name being opened.
//!
//! # What is modelled, and what a driver could see
//!
//! On Windows the table and its entries are the driver's memory
//! (`UNICODE_PREFIX_TABLE`, `UNICODE_PREFIX_TABLE_ENTRY`), and the
//! routines link entries through fields inside them. [`PrefixTable`]
//! instead owns a copy of each name and identifies an entry by a
//! `handle` the caller chooses, which for the kernel is the address of
//! the driver's entry. This needs the allocator, for the names and the
//! list of entries; it needs no `unsafe` and holds no reference into
//! driver memory.
//!
//! The documentation calls both structures opaque, yet `ntifs.h`
//! declares their fields, so a driver could read them:
//!
//! - of the table: `NodeTypeCode`, `NameLength`, `NextPrefixTree`,
//!   `LastNextEntry`;
//! - of an entry: `NodeTypeCode`, `NameLength`, `NextPrefixTree`,
//!   `CaseMatch`, `Links` (splay links), `Prefix` (the pointer to the
//!   caller's name).
//!
//! This module computes none of them: the links describe a tree that
//! does not exist here. A driver that walks them itself, rather than
//! calling `RtlNextUnicodePrefix`, is not served.
//!
//! # INFERRED
//!
//! The documentation gives the outline (longest prefix; where the
//! comparison turns case-insensitive; a name already present is
//! refused). These details are NK's reading, to be checked against
//! Windows:
//!
//! - "already present" means the same units: two names that differ only
//!   in case are both kept (Windows chains them through `CaseMatch`);
//! - an empty name is refused, and so is a handle already in the table;
//! - a name that ends in a backslash is a prefix of whatever follows
//!   it; a boundary is the end of the full name or either side of a
//!   backslash, and a run of backslashes is not collapsed;
//! - when several entries differ only in case and all satisfy the
//!   comparison, the one whose units sort first is found;
//! - when the longest candidate fails the case-sensitive part of the
//!   comparison, shorter ones are still tried;
//! - the order of enumeration: upper-cased units, then the units
//!   themselves (Windows walks its trees, longest names first);
//! - removing or inserting during an enumeration keeps it going with no
//!   entry repeated or skipped.

use crate::upcase::{equal_unicode_string, order_unicode_string};
use alloc::vec::Vec;
use core::cmp::Ordering;

const SEPARATOR: u16 = b'\\' as u16;

struct Entry {
    name: Vec<u16>,
    handle: usize,
}

/// A prefix table. `RtlInitializeUnicodePrefix` is [`PrefixTable::new`].
#[derive(Default)]
pub struct PrefixTable {
    /// Sorted by upper-cased units, then by the units themselves, so
    /// that names differing only in case are neighbours.
    entries: Vec<Entry>,
    /// The entry `next` returns next.
    cursor: usize,
}

fn table_order(a: &[u16], b: &[u16]) -> Ordering {
    order_unicode_string(a, b, true).then_with(|| a.cmp(b))
}

/// Whether the first `end` units of `name` stop on a component boundary.
fn ends_a_component(name: &[u16], end: usize) -> bool {
    end == name.len() || name[end] == SEPARATOR || name[end - 1] == SEPARATOR
}

impl PrefixTable {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            cursor: 0,
        }
    }

    /// `RtlInsertUnicodePrefix`: add `name` under `handle`. False, with
    /// the table unchanged, if the name is already there.
    pub fn insert(&mut self, name: &[u16], handle: usize) -> bool {
        if name.is_empty() || self.entries.iter().any(|e| e.handle == handle) {
            return false;
        }
        let at = self
            .entries
            .partition_point(|e| table_order(&e.name, name) == Ordering::Less);
        if self.entries.get(at).is_some_and(|e| e.name == name) {
            return false;
        }
        self.entries.insert(
            at,
            Entry {
                name: name.to_vec(),
                handle,
            },
        );
        if at < self.cursor {
            self.cursor += 1;
        }
        true
    }

    /// `RtlRemoveUnicodePrefix`: take the entry `handle` out. False if
    /// it is not in the table.
    pub fn remove(&mut self, handle: usize) -> bool {
        let Some(at) = self.entries.iter().position(|e| e.handle == handle) else {
            return false;
        };
        self.entries.remove(at);
        if at < self.cursor {
            self.cursor -= 1;
        }
        true
    }

    /// `RtlFindUnicodePrefix`: the entry whose name is the longest
    /// prefix of `full_name` that stops on a component boundary; the
    /// whole name counts. Units before `case_insensitive_index` must be
    /// the same; from there on, the same when upper-cased.
    ///
    /// The work is bounded by the length of `full_name`, times the
    /// length of the longest name in the table, times the logarithm of
    /// the number of entries, plus the entries that differ only in case.
    pub fn find(&self, full_name: &[u16], case_insensitive_index: usize) -> Option<usize> {
        (1..=full_name.len())
            .rev()
            .filter(|&end| ends_a_component(full_name, end))
            .find_map(|end| self.named(&full_name[..end], case_insensitive_index))
    }

    /// The entry named `name` under the comparison of `find`.
    fn named(&self, name: &[u16], case_insensitive_index: usize) -> Option<usize> {
        let exact = &name[..case_insensitive_index.min(name.len())];
        let start = self
            .entries
            .partition_point(|e| order_unicode_string(&e.name, name, true) == Ordering::Less);
        self.entries[start..]
            .iter()
            .take_while(|e| equal_unicode_string(&e.name, name, true))
            .find(|e| e.name.starts_with(exact))
            .map(|e| e.handle)
    }

    /// `RtlNextUnicodePrefix`: the entries one by one, from the first
    /// if `restart`; None when there are no more.
    pub fn next(&mut self, restart: bool) -> Option<usize> {
        if restart {
            self.cursor = 0;
        }
        let entry = self.entries.get(self.cursor)?;
        self.cursor += 1;
        Some(entry.handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::upcase::upcase_char;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn table(names: &[&str]) -> PrefixTable {
        let mut table = PrefixTable::new();
        for (handle, name) in names.iter().enumerate() {
            assert!(table.insert(&w(name), handle), "{name}");
        }
        table
    }

    #[test]
    fn the_longest_prefix_on_a_component_boundary_is_found() {
        let names = [
            "\\",
            "\\pipe",
            "\\pipe\\spool",
            "\\PIPE\\Spool\\x",
            "\\other",
        ];
        let t = table(&names);
        for (full, index, expected) in [
            ("\\pipe", 0, Some(1)),
            ("\\PIPE", 0, Some(1)),
            ("\\pipe\\spool", 0, Some(2)),
            ("\\pipe\\spool\\y", 0, Some(2)),
            ("\\pipe\\spool\\x", 0, Some(3)),
            ("\\pipe\\spool\\x\\deeper\\still", 0, Some(3)),
            // Not on a boundary: `\pipe` is not a prefix of `\pipeline`.
            ("\\pipeline", 0, Some(0)),
            ("\\pipe\\spoolx", 0, Some(1)),
            ("\\pipe\\", 0, Some(1)),
            ("\\", 0, Some(0)),
            ("\\unknown\\name", 0, Some(0)),
            ("\\other", 0, Some(4)),
            // A name the table's root does not start.
            ("relative", 0, None),
            ("", 0, None),
            // Case-sensitive throughout.
            ("\\PIPE", 5, Some(0)),
            ("\\pipe", 5, Some(1)),
            ("\\pipe", usize::MAX, Some(1)),
            // Case-sensitive for `\p`, then not.
            ("\\pIPE\\SPOOL", 2, Some(2)),
            ("\\PIPE\\spool", 2, Some(0)),
            // The longest candidate fails the case-sensitive part; the
            // next one down does not.
            ("\\pipe\\spool\\x", 3, Some(2)),
            ("\\PIPE\\Spool\\x", 14, Some(3)),
        ] {
            assert_eq!(t.find(&w(full), index), expected, "{full} at {index}");
        }
        assert_eq!(PrefixTable::default().find(&w("\\a"), 0), None);
    }

    #[test]
    fn a_name_ending_in_a_backslash_starts_what_follows_it() {
        let t = table(&["\\a\\", "a"]);
        assert_eq!(t.find(&w("\\a\\b"), 0), Some(0));
        assert_eq!(t.find(&w("\\a\\"), 0), Some(0));
        assert_eq!(t.find(&w("\\a"), 0), None);
        assert_eq!(t.find(&w("a\\b"), 0), Some(1));
        assert_eq!(t.find(&w("ab"), 0), None);
    }

    #[test]
    fn a_name_already_there_is_refused() {
        let mut t = table(&["\\a", "\\b"]);
        assert!(!t.insert(&w("\\a"), 7), "the same name");
        assert!(!t.insert(&w("\\c"), 0), "the same handle");
        assert!(!t.insert(&[], 8), "no name");
        assert_eq!(t.find(&w("\\c"), 0), None);
        // A name that differs in case is another name.
        assert!(t.insert(&w("\\A"), 9));
        assert_eq!(t.find(&w("\\A"), 2), Some(9));
        assert_eq!(t.find(&w("\\a"), 2), Some(0));
        // Either satisfies a case-insensitive search; the one whose
        // units sort first is found.
        assert_eq!(t.find(&w("\\a"), 0), Some(9));
        assert!(t.remove(9));
        assert_eq!(t.find(&w("\\A"), 0), Some(0));
        assert_eq!(t.find(&w("\\A"), 2), None);
        assert!(!t.remove(9), "already gone");
        // A removed name can be inserted again.
        assert!(t.remove(0));
        assert!(t.insert(&w("\\a"), 7));
        assert_eq!(t.find(&w("\\a\\x"), 0), Some(7));
    }

    #[test]
    fn enumeration_visits_every_entry_once() {
        let mut t = table(&["\\b", "\\a\\x", "\\", "\\a", "\\A"]);
        let mut seen = Vec::new();
        let mut restart = true;
        while let Some(handle) = t.next(restart) {
            seen.push(handle);
            restart = false;
        }
        // Upper-cased order, then the units: `\A` before `\a`.
        assert_eq!(seen, [2, 4, 3, 1, 0]);
        assert_eq!(t.next(false), None, "stays at the end");
        assert_eq!(t.next(true), Some(2));
        assert_eq!(PrefixTable::new().next(true), None);
    }

    #[test]
    fn enumeration_survives_removal_and_insertion() {
        let mut t = table(&["\\a", "\\b", "\\c", "\\d"]);
        assert_eq!(t.next(true), Some(0));
        assert_eq!(t.next(false), Some(1));
        // Behind the cursor: nothing is skipped or repeated.
        assert!(t.remove(0));
        assert!(t.insert(&w("\\0"), 10));
        assert_eq!(t.next(false), Some(2));
        // Ahead of it: the new entry is visited, the removed one not.
        assert!(t.insert(&w("\\e"), 11));
        assert!(t.remove(3));
        assert_eq!(t.next(false), Some(11));
        assert_eq!(t.next(false), None);
    }

    /// The table as a plain list, searched the slow way.
    #[derive(Default)]
    struct Model(Vec<(Vec<u16>, usize)>);

    impl Model {
        fn insert(&mut self, name: &[u16], handle: usize) -> bool {
            let taken = self.0.iter().any(|(n, h)| n == name || *h == handle);
            if name.is_empty() || taken {
                return false;
            }
            self.0.push((name.to_vec(), handle));
            true
        }

        fn remove(&mut self, handle: usize) -> bool {
            let before = self.0.len();
            self.0.retain(|(_, h)| *h != handle);
            self.0.len() != before
        }

        fn find(&self, full: &[u16], index: usize) -> Option<usize> {
            let starts = |name: &[u16]| {
                name.len() <= full.len()
                    && name.iter().zip(full).enumerate().all(|(i, (&a, &b))| {
                        a == b || (i >= index && upcase_char(a) == upcase_char(b))
                    })
                    && (name.len() == full.len()
                        || full[name.len()] == SEPARATOR
                        || name.last() == Some(&SEPARATOR))
            };
            self.0
                .iter()
                .filter(|(name, _)| starts(name))
                // The longest; among equals, the units that sort first.
                .max_by(|(a, _), (b, _)| a.len().cmp(&b.len()).then_with(|| b.cmp(a)))
                .map(|(_, handle)| *handle)
        }
    }

    #[test]
    fn random_sequences_agree_with_a_plain_list() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut random = |below: usize| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as usize % below
        };
        let alphabet = w("\\\\aAb");
        let mut finds = 0;
        for _ in 0..200 {
            let (mut t, mut model) = (PrefixTable::new(), Model::default());
            for step in 0..60 {
                let name: Vec<u16> = (0..random(7)).map(|_| alphabet[random(5)]).collect();
                match random(4) {
                    0 => {
                        let handle = random(12);
                        assert_eq!(t.insert(&name, handle), model.insert(&name, handle));
                    }
                    1 => {
                        let handle = random(12);
                        assert_eq!(t.remove(handle), model.remove(handle));
                    }
                    _ => {
                        let index = random(4);
                        let (got, expected) = (t.find(&name, index), model.find(&name, index));
                        assert_eq!(got, expected, "step {step}: {name:?} at {index}");
                        finds += usize::from(got.is_some());
                    }
                }
            }
            // The enumeration is the whole table, each entry once.
            let mut listed: Vec<usize> = core::iter::once(t.next(true))
                .chain(core::iter::repeat_with(|| t.next(false)))
                .map_while(|handle| handle)
                .collect();
            let mut expected: Vec<usize> = model.0.iter().map(|(_, h)| *h).collect();
            listed.sort_unstable();
            expected.sort_unstable();
            assert_eq!(listed, expected);
        }
        assert!(finds > 500, "the sequences must exercise found names");
    }
}
