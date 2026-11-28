//! The tunnel cache (`TUNNEL`), as the pinned kernel keeps it: a short
//! memory of the names and data (a creation time) of files just
//! renamed or deleted in a directory, so a file made with one of those
//! names soon after gets them back.
//!
//! An entry is keyed by its directory and one of its names, the short
//! or the long as the file system says when it adds it, compared
//! without regard to case. Adding replaces the entry with the same key
//! and dates the new one with the system time. Every addition and
//! look-up first prunes: the oldest entries go while they are older than
//! the maximum age (or dated after now, the clock having gone back),
//! and then while there are more than the maximum number. A look-up
//! leaves the entry where it is.

use alloc::vec::Vec;
use nk_rtl::upcase_char;

/// One remembered file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub directory: u64,
    /// Keyed by the short name, else the long.
    pub by_short: bool,
    pub short: Vec<u16>,
    pub long: Vec<u16>,
    pub data: Vec<u8>,
    /// The system time it was added.
    pub time: i64,
}

impl Entry {
    fn key(&self) -> &[u16] {
        if self.by_short {
            &self.short
        } else {
            &self.long
        }
    }
}

/// How long and how many entries a cache keeps (`TunnelMaxAge`, in
/// 100-nanosecond units, and `TunnelMaxEntries`).
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_age: i64,
    pub max_entries: u32,
}

impl Limits {
    /// What `FsRtlInitializeTunnels` makes of the registry's values, in
    /// seconds and entries (Windows' defaults 15 and 256): an age of
    /// zero turns tunnelling off, and the age is kept in 32 bits.
    pub fn from_registry(age_seconds: u32, max_entries: u32) -> Self {
        let max_entries = if age_seconds == 0 { 0 } else { max_entries };
        Limits {
            max_age: i64::from(age_seconds.wrapping_mul(10_000_000)),
            max_entries,
        }
    }

    /// Whether the cache is off: nothing is added or found.
    pub fn off(&self) -> bool {
        self.max_entries == 0
    }
}

fn same_name(a: &[u16], b: &[u16]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(&x, &y)| upcase_char(x) == upcase_char(y))
}

/// One directory's or volume's cache, oldest entry first.
#[derive(Default, Debug)]
pub struct Tunnel {
    entries: Vec<Entry>,
}

impl Tunnel {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// `FsRtlPruneTunnelCache`.
    fn prune(&mut self, now: i64, limits: Limits) {
        let oldest = now - limits.max_age;
        while self
            .entries
            .first()
            .is_some_and(|e| e.time < oldest || e.time > now)
        {
            self.entries.remove(0);
        }
        while self.entries.len() > limits.max_entries as usize {
            self.entries.remove(0);
        }
    }

    /// `FsRtlAddToTunnelCache`. Without memory for the entry nothing is
    /// added, as on Windows.
    pub fn add(&mut self, entry: Entry, now: i64, limits: Limits) {
        if limits.off() {
            return;
        }
        self.entries
            .retain(|e| !(e.directory == entry.directory && same_name(e.key(), entry.key())));
        if self.entries.try_reserve(1).is_ok() {
            self.entries.push(Entry { time: now, ..entry });
        }
        self.prune(now, limits);
    }

    /// `FsRtlFindInTunnelCache`: the entry of `directory` keyed by
    /// `name`.
    pub fn find(
        &mut self,
        directory: u64,
        name: &[u16],
        now: i64,
        limits: Limits,
    ) -> Option<&Entry> {
        if limits.off() {
            return None;
        }
        self.prune(now, limits);
        self.entries
            .iter()
            .find(|e| e.directory == directory && same_name(e.key(), name))
    }

    /// `FsRtlDeleteKeyFromTunnelCache`: forget every entry of
    /// `directory`.
    pub fn delete_key(&mut self, directory: u64, limits: Limits) {
        if !limits.off() {
            self.entries.retain(|e| e.directory != directory);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND: i64 = 10_000_000;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn entry(directory: u64, short: &str, long: &str, by_short: bool) -> Entry {
        Entry {
            directory,
            by_short,
            short: w(short),
            long: w(long),
            data: std::vec![1, 2, 3],
            time: 0,
        }
    }

    fn limits() -> Limits {
        Limits::from_registry(15, 256)
    }

    #[test]
    fn found_by_its_key_without_regard_to_case() {
        let mut t = Tunnel::default();
        t.add(
            entry(7, "LONGFI~1.TXT", "Long File.txt", false),
            0,
            limits(),
        );
        assert!(t.find(7, &w("long FILE.TXT"), SECOND, limits()).is_some());
        assert!(t.find(7, &w("LONGFI~1.TXT"), SECOND, limits()).is_none());
        assert!(t.find(8, &w("Long File.txt"), SECOND, limits()).is_none());
        // Found again: a look-up keeps the entry.
        assert!(t.find(7, &w("Long File.txt"), SECOND, limits()).is_some());
    }

    #[test]
    fn the_same_key_replaces() {
        let mut t = Tunnel::default();
        t.add(entry(1, "A", "x", true), 0, limits());
        let mut again = entry(1, "a", "y", true);
        again.data = std::vec![9];
        t.add(again, SECOND, limits());
        assert_eq!(t.len(), 1);
        assert_eq!(t.find(1, &w("A"), SECOND, limits()).unwrap().data, [9]);
    }

    #[test]
    fn old_entries_go() {
        let mut t = Tunnel::default();
        t.add(entry(1, "A", "a", true), 0, limits());
        assert!(t.find(1, &w("A"), 15 * SECOND, limits()).is_some());
        assert!(t.find(1, &w("A"), 15 * SECOND + 1, limits()).is_none());
        assert!(t.is_empty());
        // An entry from the future goes too.
        t.add(entry(1, "B", "b", true), 10 * SECOND, limits());
        assert!(t.find(1, &w("B"), 5 * SECOND, limits()).is_none());
    }

    #[test]
    fn the_oldest_go_past_the_limit() {
        let few = Limits::from_registry(15, 2);
        let mut t = Tunnel::default();
        for (i, n) in ["A", "B", "C"].iter().enumerate() {
            t.add(entry(1, n, n, true), i as i64, few);
        }
        assert_eq!(t.len(), 2);
        assert!(t.find(1, &w("A"), 3, few).is_none());
        assert!(t.find(1, &w("C"), 3, few).is_some());
    }

    #[test]
    fn delete_key_forgets_a_directory() {
        let mut t = Tunnel::default();
        t.add(entry(1, "A", "a", true), 0, limits());
        t.add(entry(2, "B", "b", true), 0, limits());
        t.delete_key(1, limits());
        assert_eq!(t.len(), 1);
        assert!(t.find(2, &w("B"), 0, limits()).is_some());
    }

    #[test]
    fn age_zero_turns_it_off() {
        let off = Limits::from_registry(0, 256);
        let mut t = Tunnel::default();
        t.add(entry(1, "A", "a", true), 0, off);
        assert!(t.is_empty());
        assert!(t.find(1, &w("A"), 0, off).is_none());
    }
}
