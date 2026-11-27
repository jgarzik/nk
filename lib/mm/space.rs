//! Handing out a region of virtual address space.
//!
//! Address space comes from a bump pointer, with a small cache of freed
//! ranges reused by exact size. That is enough for a driver loaded and
//! unloaded repeatedly to land on the same addresses, so the cycle needs
//! no new page tables. Every range is followed by a page that is never
//! handed out, so running off the end of one mapping faults.

use crate::PAGE_SIZE;

/// Freed ranges kept for reuse.
pub const FREE_SLOTS: usize = 32;

/// The allocator of one region, `[base, end)`.
#[derive(Debug)]
pub struct Space {
    next: u64,
    end: u64,
    /// `(va, pages)` ranges given back.
    free: [Option<(u64, usize)>; FREE_SLOTS],
}

impl Space {
    /// A region of which nothing is handed out yet.
    pub const fn new(base: u64, end: u64) -> Self {
        Self {
            next: base,
            end,
            free: [None; FREE_SLOTS],
        }
    }

    /// A range of `pages` pages at a multiple of `align` bytes (a power
    /// of two, at least a page): a freed one of that size and alignment
    /// if there is one, else fresh space. `None` when the region cannot
    /// hold it; nothing is used up in that case.
    pub fn take(&mut self, pages: usize, align: u64) -> Option<u64> {
        if let Some(slot) = self
            .free
            .iter_mut()
            .find(|s| s.is_some_and(|(va, n)| n == pages && va % align == 0))
        {
            return slot.take().map(|(va, _)| va);
        }
        let va = self.next.checked_next_multiple_of(align)?;
        // The page after the range stays unmapped.
        let bytes = u64::try_from(pages)
            .ok()?
            .checked_add(1)?
            .checked_mul(PAGE_SIZE)?;
        let end = va.checked_add(bytes)?;
        if end > self.end {
            return None;
        }
        self.next = end;
        Some(va)
    }

    /// Give back a range from `take`. If the reuse cache is full the
    /// range is simply not reused.
    pub fn give_back(&mut self, va: u64, pages: usize) {
        if let Some(slot) = self.free.iter_mut().find(|s| s.is_none()) {
            *slot = Some((va, pages));
        }
    }
}

/// A range of pages: its address and how many.
pub type Range = (u64, usize);

/// The index of the range of `live` (sorted by start, disjoint) that
/// holds all of the `pages` pages at `va`; `None` if none does, or if
/// no pages are named.
pub fn holder(live: &[Range], va: u64, pages: usize) -> Option<usize> {
    let end = va.checked_add(u64::try_from(pages).ok()?.checked_mul(PAGE_SIZE)?)?;
    let at = live
        .partition_point(|&(start, _)| start <= va)
        .checked_sub(1)?;
    let (start, length) = live[at];
    let held_end = start + length as u64 * PAGE_SIZE;
    (pages != 0 && end <= held_end).then_some(at)
}

/// What is left of the live `range` once the `pages` pages at `va`,
/// which it holds, are given back: the part before them and the part
/// after, each if not empty.
pub fn remainder(range: Range, va: u64, pages: usize) -> (Option<Range>, Option<Range>) {
    let (start, length) = range;
    let before = ((va - start) / PAGE_SIZE) as usize;
    let after = length - before - pages;
    let piece = |at: u64, n: usize| (n != 0).then_some((at, n));
    (
        piece(start, before),
        piece(va + pages as u64 * PAGE_SIZE, after),
    )
}

#[cfg(test)]
mod tests {

    const P: u64 = PAGE_SIZE;

    #[test]
    fn a_release_must_lie_wholly_in_one_live_range() {
        let live = [(0x1000 * P, 4), (0x2000 * P, 2)];
        assert_eq!(holder(&live, 0x1000 * P, 4), Some(0));
        assert_eq!(holder(&live, 0x1001 * P, 2), Some(0));
        assert_eq!(holder(&live, 0x2001 * P, 1), Some(1));
        // One page too many, before the first, between, and nothing.
        assert_eq!(holder(&live, 0x1000 * P, 5), None);
        assert_eq!(holder(&live, 0x0FFF * P, 1), None);
        assert_eq!(holder(&live, 0x1800 * P, 1), None);
        assert_eq!(holder(&live, 0x1000 * P, 0), None);
        assert_eq!(holder(&[], 0x1000 * P, 1), None);
        assert_eq!(holder(&live, u64::MAX - P, 4), None);
    }

    #[test]
    fn a_partial_release_leaves_the_pieces_around_it() {
        let range = (0x1000 * P, 6);
        assert_eq!(remainder(range, 0x1000 * P, 6), (None, None));
        assert_eq!(
            remainder(range, 0x1000 * P, 2),
            (None, Some((0x1002 * P, 4)))
        );
        assert_eq!(
            remainder(range, 0x1004 * P, 2),
            (Some((0x1000 * P, 4)), None)
        );
        assert_eq!(
            remainder(range, 0x1002 * P, 1),
            (Some((0x1000 * P, 2)), Some((0x1003 * P, 3)))
        );
    }
    use super::*;

    const BASE: u64 = 0xFFFF_F880_0000_0000;
    const PAGE: u64 = PAGE_SIZE;

    fn space(pages: u64) -> Space {
        Space::new(BASE, BASE + pages * PAGE)
    }

    #[test]
    fn fresh_ranges_are_separated_by_one_page() {
        let mut s = space(100);
        assert_eq!(s.take(2, PAGE), Some(BASE));
        // Two pages and the gap page.
        assert_eq!(s.take(1, PAGE), Some(BASE + 3 * PAGE));
        assert_eq!(s.take(5, PAGE), Some(BASE + 5 * PAGE));
        assert_eq!(s.take(1, PAGE), Some(BASE + 11 * PAGE));
    }

    #[test]
    fn a_range_is_aligned_as_asked_and_space_goes_on_after_it() {
        let mut s = space(1000);
        assert_eq!(s.take(1, PAGE), Some(BASE));
        // The next free byte is two pages in; a 64 KiB alignment skips
        // to the next multiple.
        let aligned = s.take(4, 0x1_0000).unwrap();
        assert_eq!(aligned, BASE + 0x1_0000);
        assert_eq!(s.take(1, PAGE), Some(aligned + 5 * PAGE));
        // Already aligned: nothing is skipped.
        let mut s = space(1000);
        assert_eq!(s.take(4, 0x1_0000), Some(BASE));
    }

    #[test]
    fn a_stack_and_its_guard_are_one_aligned_range() {
        // What `mm::stack` asks for: twice the stack, at a multiple of
        // twice the stack.
        let stack = 0x8000;
        let mut s = space(1000);
        s.take(3, PAGE);
        let low = s.take(16, 2 * stack).unwrap();
        assert_eq!(low % (2 * stack), 0);
        assert!(low >= BASE + 4 * PAGE);
        let second = s.take(16, 2 * stack).unwrap();
        assert_eq!(second % (2 * stack), 0);
        assert!(second >= low + 17 * PAGE, "ranges overlap");
    }

    #[test]
    fn a_freed_range_is_reused_once_by_the_same_size() {
        let mut s = space(100);
        let a = s.take(3, PAGE).unwrap();
        let b = s.take(3, PAGE).unwrap();
        s.give_back(a, 3);
        // Another size does not fit the freed range.
        let other = s.take(2, PAGE).unwrap();
        assert!(other > b);
        let bigger = s.take(4, PAGE).unwrap();
        assert!(bigger > other);
        // The same size gets it back, once.
        assert_eq!(s.take(3, PAGE), Some(a));
        let fresh = s.take(3, PAGE).unwrap();
        assert!(fresh > bigger);
    }

    #[test]
    fn a_freed_range_is_reused_only_at_the_alignment_asked() {
        let mut s = space(1000);
        s.take(1, PAGE);
        // Two pages in: not a multiple of 64 KiB.
        let odd = s.take(4, PAGE).unwrap();
        assert_ne!(odd % 0x1_0000, 0);
        s.give_back(odd, 4);
        let aligned = s.take(4, 0x1_0000).unwrap();
        assert_ne!(aligned, odd);
        assert_eq!(aligned % 0x1_0000, 0);
        // It is still there for a caller that does not care.
        assert_eq!(s.take(4, PAGE), Some(odd));
        // And an aligned freed range does serve an aligned request.
        s.give_back(aligned, 4);
        assert_eq!(s.take(4, 0x1_0000), Some(aligned));
    }

    #[test]
    fn of_two_freed_ranges_each_is_reused() {
        let mut s = space(100);
        let a = s.take(2, PAGE).unwrap();
        let b = s.take(2, PAGE).unwrap();
        s.give_back(b, 2);
        s.give_back(a, 2);
        let mut got = [s.take(2, PAGE).unwrap(), s.take(2, PAGE).unwrap()];
        got.sort_unstable();
        assert_eq!(got, [a, b]);
    }

    #[test]
    fn the_region_ends_where_it_ends() {
        // Room for exactly one page and its gap, twice.
        let mut s = space(4);
        assert_eq!(s.take(1, PAGE), Some(BASE));
        assert_eq!(s.take(1, PAGE), Some(BASE + 2 * PAGE));
        assert_eq!(s.take(1, PAGE), None);
        // One page short of fitting.
        let mut s = space(4);
        assert_eq!(s.take(4, PAGE), None);
        // A failure uses nothing up.
        assert_eq!(s.take(3, PAGE), Some(BASE));
        assert_eq!(s.take(0, PAGE), None);
        // What was freed can still be had when fresh space is gone.
        s.give_back(BASE, 3);
        assert_eq!(s.take(3, PAGE), Some(BASE));
    }

    #[test]
    fn alignment_that_leaves_the_region_fails_and_uses_nothing() {
        let mut s = space(16);
        s.take(1, PAGE);
        assert_eq!(s.take(1, 1 << 30), None);
        assert_eq!(s.take(1, PAGE), Some(BASE + 2 * PAGE));
    }

    #[test]
    fn sizes_that_overflow_are_refused() {
        let mut s = Space::new(BASE, u64::MAX);
        assert_eq!(s.take(usize::MAX, PAGE), None);
        assert_eq!(s.take((u64::MAX / PAGE) as usize, PAGE), None);
        // The range would run past the top of the address space.
        let mut s = Space::new(u64::MAX - 2 * PAGE + 1, u64::MAX);
        assert_eq!(s.take(1, PAGE), None);
        assert_eq!(s.take(2, PAGE), None);
        // Rounding up to the alignment would.
        let mut s = Space::new(u64::MAX - PAGE, u64::MAX);
        assert_eq!(s.take(1, 1 << 40), None);
        assert_eq!(s.take(0, PAGE), None);
    }

    #[test]
    fn a_full_cache_forgets_further_ranges() {
        let mut s = space(10_000);
        let mut held = [0u64; FREE_SLOTS + 1];
        for (i, slot) in held.iter_mut().enumerate() {
            // A different size each, so reuse is unambiguous.
            *slot = s.take(i + 1, PAGE).unwrap();
        }
        for (i, &va) in held.iter().enumerate() {
            s.give_back(va, i + 1);
        }
        // Every range but the last was remembered.
        for (i, &va) in held.iter().enumerate().take(FREE_SLOTS) {
            assert_eq!(s.take(i + 1, PAGE), Some(va));
        }
        let last = s.take(FREE_SLOTS + 1, PAGE).unwrap();
        assert!(last > held[FREE_SLOTS], "a forgotten range came back");
        // With slots free again, ranges are remembered again.
        s.give_back(last, FREE_SLOTS + 1);
        assert_eq!(s.take(FREE_SLOTS + 1, PAGE), Some(last));
    }
}
