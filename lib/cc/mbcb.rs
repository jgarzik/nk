//! A file's mask buffer control block (MBCB): which of its pages were
//! dirtied by a copy or MDL write, as bitmaps of pages, the way
//! `CcSetDirtyInMask` keeps them, and the runs the lazy writer and a
//! flush take from them (`CcAcquireByteRangeForWrite`).
//!
//! A bitmap range covers [`RANGE_PAGES`] pages and is made when a page
//! in it is first dirtied; one left with no dirty page is dropped. The
//! lazy writer resumes where its last pass stopped (`ResumeWritePage`),
//! going round to the start of the file, so a file written at its end
//! again and again does not starve its beginning.

use alloc::vec::Vec;

/// Pages one bitmap range covers.
pub const RANGE_PAGES: u64 = 4096;
const WORDS: usize = (RANGE_PAGES / 64) as usize;

/// The pool had no memory for a bitmap range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoMemory;

struct Range {
    /// The first page it covers, a multiple of `RANGE_PAGES`.
    base: u64,
    bits: Vec<u64>,
    dirty: u64,
}

/// A run of dirty pages: the first and how many.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub page: u64,
    pub pages: u64,
}

/// The dirty pages of one file.
#[derive(Default)]
pub struct Mbcb {
    /// Sorted by `base`.
    ranges: Vec<Range>,
    dirty_pages: u64,
    resume_page: u64,
    most_recent_page: u64,
}

impl Mbcb {
    pub fn new() -> Self {
        Self::default()
    }

    /// Dirty pages in all.
    pub fn dirty_pages(&self) -> u64 {
        self.dirty_pages
    }

    /// The page the lazy writer starts its next pass at.
    pub fn resume_page(&self) -> u64 {
        self.resume_page
    }

    /// The last page dirtied.
    pub fn most_recent_page(&self) -> u64 {
        self.most_recent_page
    }

    /// The bitmap ranges the pages of `[page, page + pages)` need that
    /// are not made yet: their bases.
    fn missing(&self, page: u64, pages: u64) -> impl Iterator<Item = u64> + '_ {
        let first = page / RANGE_PAGES;
        let last = (page + pages).div_ceil(RANGE_PAGES);
        (first..last)
            .map(|r| r * RANGE_PAGES)
            .filter(|base| self.ranges.binary_search_by_key(base, |r| r.base).is_err())
    }

    /// Mark the pages that bytes `[offset, offset + len)` touch dirty.
    /// Returns how many were clean before.
    pub fn set_dirty(&mut self, offset: u64, len: u64) -> Result<u64, NoMemory> {
        if len == 0 {
            return Ok(0);
        }
        let page = offset / crate::PAGE_SIZE;
        let end = (offset + len).div_ceil(crate::PAGE_SIZE);
        let missing: Vec<u64> = self.missing(page, end - page).collect();
        self.ranges
            .try_reserve(missing.len())
            .map_err(|_| NoMemory)?;
        for base in missing {
            let mut bits = Vec::new();
            bits.try_reserve_exact(WORDS).map_err(|_| NoMemory)?;
            bits.resize(WORDS, 0);
            let at = self.ranges.partition_point(|r| r.base < base);
            self.ranges.insert(
                at,
                Range {
                    base,
                    bits,
                    dirty: 0,
                },
            );
        }
        let mut newly = 0;
        for p in page..end {
            let r = self.range_mut(p).expect("made above");
            let (word, bit) = (((p - r.base) / 64) as usize, (p - r.base) % 64);
            if r.bits[word] & 1 << bit == 0 {
                r.bits[word] |= 1 << bit;
                r.dirty += 1;
                newly += 1;
            }
        }
        self.dirty_pages += newly;
        self.most_recent_page = end - 1;
        Ok(newly)
    }

    fn range_mut(&mut self, page: u64) -> Option<&mut Range> {
        let base = page / RANGE_PAGES * RANGE_PAGES;
        let i = self.ranges.binary_search_by_key(&base, |r| r.base).ok()?;
        Some(&mut self.ranges[i])
    }

    fn is_dirty(&self, page: u64) -> bool {
        let base = page / RANGE_PAGES * RANGE_PAGES;
        self.ranges
            .binary_search_by_key(&base, |r| r.base)
            .is_ok_and(|i| {
                let r = &self.ranges[i];
                r.bits[((page - base) / 64) as usize] & 1 << ((page - base) % 64) != 0
            })
    }

    /// The first dirty page at or after `page` and before `end`.
    fn first_dirty(&self, page: u64, end: u64) -> Option<u64> {
        for r in self
            .ranges
            .iter()
            .filter(|r| r.dirty != 0 && r.base + RANGE_PAGES > page)
        {
            let from = page.max(r.base);
            for p in from..(r.base + RANGE_PAGES).min(end) {
                let (word, bit) = (((p - r.base) / 64) as usize, (p - r.base) % 64);
                if r.bits[word] & 1 << bit != 0 {
                    return Some(p);
                }
            }
            if r.base + RANGE_PAGES >= end {
                break;
            }
        }
        None
    }

    /// Clear pages `[page, page + pages)`, dropping ranges left empty.
    /// Returns how many were dirty.
    fn clear(&mut self, page: u64, pages: u64) -> u64 {
        let mut cleared = 0;
        for p in page..page + pages {
            if let Some(r) = self.range_mut(p) {
                let (word, bit) = (((p - r.base) / 64) as usize, (p - r.base) % 64);
                if r.bits[word] & 1 << bit != 0 {
                    r.bits[word] &= !(1 << bit);
                    r.dirty -= 1;
                    cleared += 1;
                }
            }
        }
        self.ranges.retain(|r| r.dirty != 0);
        self.dirty_pages -= cleared;
        cleared
    }

    /// Take the next run to write: the first dirty page in
    /// `[from, end)` and the dirty pages that follow it, at most
    /// `most`. The pages are clean from now on; a write that fails puts
    /// them back with [`redirty`](Self::redirty).
    pub fn take_run(&mut self, from: u64, end: u64, most: u64) -> Option<Run> {
        let page = self.first_dirty(from, end)?;
        let mut pages = 1;
        while pages < most && page + pages < end && self.is_dirty(page + pages) {
            pages += 1;
        }
        self.clear(page, pages);
        Some(Run { page, pages })
    }

    /// The lazy writer's next run: from the resume page to the end of
    /// the file, then from its start; the resume page moves past it.
    pub fn take_lazy_run(&mut self, most: u64) -> Option<Run> {
        let run = self
            .take_run(self.resume_page, u64::MAX, most)
            .or_else(|| self.take_run(0, u64::MAX, most))?;
        self.resume_page = run.page + run.pages;
        Some(run)
    }

    /// Mark a run dirty again after its write failed.
    pub fn redirty(&mut self, run: Run) -> Result<u64, NoMemory> {
        self.set_dirty(run.page * crate::PAGE_SIZE, run.pages * crate::PAGE_SIZE)
    }

    /// Forget every dirty page at or after `page` (a file cut there).
    /// Returns how many there were.
    pub fn truncate(&mut self, page: u64) -> u64 {
        let mut gone = 0;
        while let Some(run) = self.take_run(page, u64::MAX, u64::MAX) {
            gone += run.pages;
        }
        if self.resume_page > page {
            self.resume_page = 0;
        }
        gone
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PAGE_SIZE;

    #[test]
    fn dirtying_counts_pages_once() {
        let mut m = Mbcb::new();
        assert_eq!(
            m.set_dirty(0x800, 0x1000),
            Ok(2),
            "a write across a page boundary"
        );
        assert_eq!(m.set_dirty(0, 0x2000), Ok(0));
        assert_eq!(m.set_dirty(0x2000, 0), Ok(0));
        assert_eq!(m.dirty_pages(), 2);
        assert_eq!(m.most_recent_page(), 1);
    }

    #[test]
    fn runs_come_in_offset_order_and_are_capped() {
        let mut m = Mbcb::new();
        m.set_dirty(10 * PAGE_SIZE, 5 * PAGE_SIZE).unwrap();
        m.set_dirty(2 * PAGE_SIZE, PAGE_SIZE).unwrap();
        let far = RANGE_PAGES * 3 + 7;
        m.set_dirty(far * PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(m.dirty_pages(), 7);
        assert_eq!(m.take_run(0, u64::MAX, 16), Some(Run { page: 2, pages: 1 }));
        assert_eq!(m.take_run(0, u64::MAX, 3), Some(Run { page: 10, pages: 3 }));
        assert_eq!(m.take_run(0, 12, 16), None, "a range that holds none");
        assert_eq!(
            m.take_run(0, u64::MAX, 16),
            Some(Run { page: 13, pages: 2 })
        );
        assert_eq!(
            m.take_run(0, u64::MAX, 16),
            Some(Run {
                page: far,
                pages: 1
            })
        );
        assert_eq!(m.take_run(0, u64::MAX, 16), None);
        assert_eq!(m.dirty_pages(), 0);
        assert!(m.ranges.is_empty(), "empty ranges are dropped");
    }

    #[test]
    fn a_failed_write_is_dirty_again() {
        let mut m = Mbcb::new();
        m.set_dirty(0, 4 * PAGE_SIZE).unwrap();
        let run = m.take_run(0, u64::MAX, 16).unwrap();
        assert_eq!(m.dirty_pages(), 0);
        assert_eq!(m.redirty(run), Ok(4));
        assert_eq!(m.dirty_pages(), 4);
    }

    #[test]
    fn the_lazy_writer_resumes_and_wraps() {
        let mut m = Mbcb::new();
        m.set_dirty(0, PAGE_SIZE).unwrap();
        m.set_dirty(100 * PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(m.take_lazy_run(16), Some(Run { page: 0, pages: 1 }));
        m.set_dirty(0, PAGE_SIZE).unwrap();
        assert_eq!(
            m.take_lazy_run(16),
            Some(Run {
                page: 100,
                pages: 1
            }),
            "after the resume page first"
        );
        assert_eq!(
            m.take_lazy_run(16),
            Some(Run { page: 0, pages: 1 }),
            "then round to the start"
        );
        assert_eq!(m.take_lazy_run(16), None);
    }

    #[test]
    fn truncation_forgets_the_tail() {
        let mut m = Mbcb::new();
        m.set_dirty(0, 8 * PAGE_SIZE).unwrap();
        m.set_dirty(RANGE_PAGES * PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(m.truncate(4), 5);
        assert_eq!(m.dirty_pages(), 4);
        assert_eq!(m.take_run(0, u64::MAX, 16), Some(Run { page: 0, pages: 4 }));
    }
}
