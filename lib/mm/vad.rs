//! Virtual Address Descriptor (VAD) tree for a user process address space.
//!
//! Pure, allocation-backed balanced search tree (`BTreeMap`) mapping each
//! reserved/mapped region's page-aligned start VA to its [`Vad`]. Enforces
//! Windows' 64 KiB allocation granularity, reserves the `KUSER_SHARED_DATA`
//! window (`0x7FFE_0000..0x7FFF_0000`) against user allocations, and supports
//! both bottom-up and `MEM_TOP_DOWN` gap searches with optional address bounds.

use crate::PAGE_SIZE;
use alloc::collections::BTreeMap;

/// Windows' virtual memory allocation granularity (64 KiB).
pub const ALLOC_GRANULARITY: u64 = 64 * 1024;
/// Lowest allocatable user virtual address (64 KiB null-guard window).
pub const MIN_USER_VA: u64 = 0x0000_0000_0001_0000;
/// First address beyond the user range (`MmUserProbeAddress`).
pub const USER_PROBE_VA: u64 = 0x0000_7FFF_FFFF_0000;
/// Reserved window for `KUSER_SHARED_DATA` (`0x7FFE_0000..0x7FFF_0000`).
pub const KUSD_WINDOW_START: u64 = 0x0000_0000_7FFE_0000;
pub const KUSD_WINDOW_END: u64 = 0x0000_0000_7FFF_0000;

/// What backs a VAD.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VadKind {
    /// Anonymous private virtual memory (`MEM_PRIVATE`).
    Private,
    /// Section view (`MEM_MAPPED` or `MEM_IMAGE`).
    Mapped {
        /// Kernel section object pointer (`*mut u8` stored as usize so `lib/mm` stays safe).
        section: usize,
        /// Byte offset within the section (page-aligned).
        offset: u64,
        /// True for `SEC_IMAGE` (`MEM_IMAGE`), false for data/pagefile (`MEM_MAPPED`).
        is_image: bool,
        /// True if writes are shared back to the section (false for CoW / read-only).
        share_write: bool,
    },
}

impl VadKind {
    /// Windows `MEMORY_BASIC_INFORMATION.Type` (`MEM_PRIVATE`, `MEM_MAPPED`, `MEM_IMAGE`).
    pub const fn mem_type(self) -> u32 {
        match self {
            Self::Private => crate::protect::MEM_PRIVATE,
            Self::Mapped { is_image: true, .. } => crate::protect::MEM_IMAGE,
            Self::Mapped {
                is_image: false, ..
            } => crate::protect::MEM_MAPPED,
        }
    }
}

/// One contiguous reserved or mapped region in a user process's address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vad {
    /// Inclusive page-aligned start virtual address.
    pub start: u64,
    /// Exclusive page-aligned end virtual address (`start < end`).
    pub end: u64,
    /// Initial Win32 `PAGE_*` protection recorded at reserve/map time.
    pub protect: u32,
    /// Private allocation or section view.
    pub kind: VadKind,
    /// Number of 4 KiB pages currently committed inside this VAD.
    pub committed_pages: u64,
}

impl Vad {
    pub const fn len(&self) -> u64 {
        self.end - self.start
    }

    pub const fn is_empty(&self) -> bool {
        self.start >= self.end
    }

    pub const fn pages(&self) -> u64 {
        self.len() / PAGE_SIZE
    }

    pub const fn contains(&self, va: u64) -> bool {
        va >= self.start && va < self.end
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VadError {
    BadRange,
    Overlap,
}

/// Balanced tree of non-overlapping user [`Vad`]s ordered by start VA.
#[derive(Debug, Default)]
pub struct VadTree {
    nodes: BTreeMap<u64, Vad>,
}

const fn align_up(value: u64, align: u64) -> Option<u64> {
    let rem = value % align;
    if rem == 0 {
        Some(value)
    } else {
        value.checked_add(align - rem)
    }
}

const fn align_down(value: u64, align: u64) -> u64 {
    value - (value % align)
}

const fn overlaps_range(a_start: u64, a_end: u64, b_start: u64, b_end: u64) -> bool {
    a_start < b_end && b_start < a_end
}

impl VadTree {
    pub const fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Find the VAD containing `va`, if any.
    pub fn find_containing(&self, va: u64) -> Option<&Vad> {
        let (_, vad) = self.nodes.range(..=va).next_back()?;
        vad.contains(va).then_some(vad)
    }

    /// Mutable lookup of the VAD containing `va`, if any.
    pub fn find_containing_mut(&mut self, va: u64) -> Option<&mut Vad> {
        let (_, vad) = self.nodes.range_mut(..=va).next_back()?;
        vad.contains(va).then_some(vad)
    }

    /// Find the VAD starting strictly at `base`.
    pub fn get(&self, base: u64) -> Option<&Vad> {
        self.nodes.get(&base)
    }

    /// Find the first VAD whose `start >= va`.
    pub fn find_next(&self, va: u64) -> Option<&Vad> {
        self.nodes.range(va..).next().map(|(_, v)| v)
    }

    /// True if `[start, end)` overlaps any existing VAD or the reserved
    /// `KUSER_SHARED_DATA` window (`0x7FFE_0000..0x7FFF_0000`).
    pub fn overlaps(&self, start: u64, end: u64) -> bool {
        if start >= end {
            return true;
        }
        if overlaps_range(start, end, KUSD_WINDOW_START, KUSD_WINDOW_END) {
            return true;
        }
        if let Some((_, prev)) = self.nodes.range(..=start).next_back()
            && prev.end > start
        {
            return true;
        }
        if let Some((_, next)) = self.nodes.range(start..).next()
            && next.start < end
        {
            return true;
        }
        false
    }

    /// Insert a validated non-overlapping VAD.
    pub fn insert(&mut self, vad: Vad) -> Result<(), VadError> {
        if vad.start < MIN_USER_VA
            || vad.end > USER_PROBE_VA
            || vad.start >= vad.end
            || !vad.start.is_multiple_of(PAGE_SIZE)
            || !vad.end.is_multiple_of(PAGE_SIZE)
        {
            return Err(VadError::BadRange);
        }
        if self.overlaps(vad.start, vad.end) {
            return Err(VadError::Overlap);
        }
        self.nodes.insert(vad.start, vad);
        Ok(())
    }

    /// Remove and return the VAD starting at `start`.
    pub fn remove(&mut self, start: u64) -> Option<Vad> {
        self.nodes.remove(&start)
    }

    /// Find a free aligned gap of `size` bytes (rounded up to `PAGE_SIZE`)
    /// within `[min_va, max_va]`, aligned to `align` (power of two >= `PAGE_SIZE`).
    /// Never overlaps any existing VAD or the `KUSER_SHARED_DATA` window.
    pub fn find_gap(
        &self,
        size: u64,
        align: u64,
        top_down: bool,
        min_va: u64,
        max_va: u64,
    ) -> Option<u64> {
        if size == 0 || !align.is_power_of_two() || align < PAGE_SIZE {
            return None;
        }
        let size = align_up(size, PAGE_SIZE)?;
        let low = min_va.max(MIN_USER_VA);
        let high = max_va.min(USER_PROBE_VA);
        if low >= high || size > high - low {
            return None;
        }

        if !top_down {
            let mut cursor = align_up(low, align)?;
            // Walk occupied intervals in ascending order (injecting KUSD window).
            let mut kusd_pending = true;
            for vad in self.nodes.values() {
                if kusd_pending && KUSD_WINDOW_START <= vad.start {
                    if let Some(found) = try_gap_below(cursor, KUSD_WINDOW_START, size, high) {
                        return Some(found);
                    }
                    if KUSD_WINDOW_END > cursor {
                        cursor = align_up(KUSD_WINDOW_END, align)?;
                    }
                    kusd_pending = false;
                }
                if vad.end <= cursor {
                    continue;
                }
                if let Some(found) = try_gap_below(cursor, vad.start, size, high) {
                    return Some(found);
                }
                if vad.end > cursor {
                    cursor = align_up(vad.end, align)?;
                }
                if cursor >= high {
                    return None;
                }
            }
            if kusd_pending {
                if let Some(found) = try_gap_below(cursor, KUSD_WINDOW_START, size, high) {
                    return Some(found);
                }
                if KUSD_WINDOW_END > cursor {
                    cursor = align_up(KUSD_WINDOW_END, align)?;
                }
            }
            try_gap_below(cursor, high, size, high)
        } else {
            let mut ceiling = high;
            let mut kusd_pending = true;
            for vad in self.nodes.values().rev() {
                if kusd_pending && KUSD_WINDOW_END >= vad.end {
                    if let Some(found) = try_gap_above(KUSD_WINDOW_END, ceiling, size, align, low) {
                        return Some(found);
                    }
                    if KUSD_WINDOW_START < ceiling {
                        ceiling = KUSD_WINDOW_START;
                    }
                    kusd_pending = false;
                }
                if vad.start >= ceiling {
                    continue;
                }
                if let Some(found) = try_gap_above(vad.end, ceiling, size, align, low) {
                    return Some(found);
                }
                if vad.start < ceiling {
                    ceiling = vad.start;
                }
                if ceiling <= low {
                    return None;
                }
            }
            if kusd_pending {
                if let Some(found) = try_gap_above(KUSD_WINDOW_END, ceiling, size, align, low) {
                    return Some(found);
                }
                if KUSD_WINDOW_START < ceiling {
                    ceiling = KUSD_WINDOW_START;
                }
            }
            try_gap_above(low, ceiling, size, align, low)
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &Vad> {
        self.nodes.values()
    }

    /// Remove and return all VADs (used on process address-space teardown).
    pub fn drain_all(&mut self) -> alloc::vec::Vec<Vad> {
        let all: alloc::vec::Vec<Vad> = self.nodes.values().copied().collect();
        self.nodes.clear();
        all
    }
}

fn try_gap_below(cursor: u64, limit: u64, size: u64, max_end: u64) -> Option<u64> {
    let end = cursor.checked_add(size)?;
    (end <= limit && end <= max_end).then_some(cursor)
}

fn try_gap_above(floor: u64, ceiling: u64, size: u64, align: u64, min_start: u64) -> Option<u64> {
    let floor = floor.max(min_start);
    if ceiling < size {
        return None;
    }
    let cand = align_down(ceiling - size, align);
    (cand >= floor && cand + size <= ceiling).then_some(cand)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protect::PAGE_READWRITE;

    fn priv_vad(start: u64, end: u64) -> Vad {
        Vad {
            start,
            end,
            protect: PAGE_READWRITE,
            kind: VadKind::Private,
            committed_pages: 0,
        }
    }

    #[test]
    fn insert_lookup_and_overlap_rejection() {
        let mut tree = VadTree::new();
        tree.insert(priv_vad(0x10_0000, 0x12_0000)).unwrap();
        assert_eq!(tree.find_containing(0x10_0000).unwrap().start, 0x10_0000);
        assert_eq!(tree.find_containing(0x11_FFFF).unwrap().start, 0x10_0000);
        assert!(tree.find_containing(0x12_0000).is_none());
        assert!(tree.find_containing(0x0F_FFFF).is_none());

        // Overlaps rejected.
        assert_eq!(
            tree.insert(priv_vad(0x11_0000, 0x13_0000)),
            Err(VadError::Overlap)
        );
        assert_eq!(
            tree.insert(priv_vad(0x0F_0000, 0x10_1000)),
            Err(VadError::Overlap)
        );
        // KUSER_SHARED_DATA window rejected.
        assert_eq!(
            tree.insert(priv_vad(KUSD_WINDOW_START, KUSD_WINDOW_END)),
            Err(VadError::Overlap)
        );
        assert_eq!(
            tree.insert(priv_vad(
                KUSD_WINDOW_START - PAGE_SIZE,
                KUSD_WINDOW_START + PAGE_SIZE
            )),
            Err(VadError::Overlap)
        );
        // Bad ranges rejected.
        assert_eq!(tree.insert(priv_vad(0, 0x1_0000)), Err(VadError::BadRange));
        assert_eq!(
            tree.insert(priv_vad(0x10_0001, 0x11_0000)),
            Err(VadError::BadRange)
        );
    }

    #[test]
    fn find_gap_bottom_up_and_top_down_skip_kusd() {
        let mut tree = VadTree::new();
        // Bottom-up starts at MIN_USER_VA.
        let a = tree
            .find_gap(
                0x2_0000,
                ALLOC_GRANULARITY,
                false,
                MIN_USER_VA,
                USER_PROBE_VA,
            )
            .unwrap();
        assert_eq!(a, MIN_USER_VA);
        tree.insert(priv_vad(a, a + 0x2_0000)).unwrap();

        let b = tree
            .find_gap(
                0x1_0000,
                ALLOC_GRANULARITY,
                false,
                MIN_USER_VA,
                USER_PROBE_VA,
            )
            .unwrap();
        assert_eq!(b, MIN_USER_VA + 0x2_0000);

        // Gap right around KUSD window must jump over 0x7FFE_0000..0x7FFF_0000.
        let around = tree
            .find_gap(
                0x2_0000,
                ALLOC_GRANULARITY,
                false,
                KUSD_WINDOW_START - 0x1_0000,
                KUSD_WINDOW_END + 0x3_0000,
            )
            .unwrap();
        assert_eq!(around, KUSD_WINDOW_END);

        // Top-down around KUSD window must land below 0x7FFE_0000 when above is too small.
        let td = tree
            .find_gap(
                0x2_0000,
                ALLOC_GRANULARITY,
                true,
                KUSD_WINDOW_START - 0x3_0000,
                KUSD_WINDOW_END + 0x1_0000,
            )
            .unwrap();
        assert_eq!(td, KUSD_WINDOW_START - 0x2_0000);

        // Top-down across full user space lands near USER_PROBE_VA.
        let high = tree
            .find_gap(
                0x1_0000,
                ALLOC_GRANULARITY,
                true,
                MIN_USER_VA,
                USER_PROBE_VA,
            )
            .unwrap();
        assert_eq!(high, USER_PROBE_VA - 0x1_0000);
        tree.insert(priv_vad(high, high + 0x1_0000)).unwrap();

        let high2 = tree
            .find_gap(
                0x1_0000,
                ALLOC_GRANULARITY,
                true,
                MIN_USER_VA,
                USER_PROBE_VA,
            )
            .unwrap();
        assert_eq!(high2, USER_PROBE_VA - 0x2_0000);
    }

    #[test]
    fn find_next_and_remove() {
        let mut tree = VadTree::new();
        tree.insert(priv_vad(0x20_0000, 0x21_0000)).unwrap();
        tree.insert(priv_vad(0x40_0000, 0x42_0000)).unwrap();
        assert_eq!(tree.find_next(0x10_0000).unwrap().start, 0x20_0000);
        assert_eq!(tree.find_next(0x21_0000).unwrap().start, 0x40_0000);
        assert!(tree.find_next(0x41_0000).is_none());
        assert!(tree.remove(0x20_0000).is_some());
        assert_eq!(tree.len(), 1);
    }
}
