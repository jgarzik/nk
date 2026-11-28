//! Physical frame allocator: one bit per 4 KiB frame.
//!
//! First-fit over a bitmap, with contiguous runs for the callers that need
//! them (page tables need one frame; driver images and pool arenas need
//! many). Simple and auditable beats fast here: the allocator is not on
//! any hot path yet.

use crate::PAGE_SIZE;

/// A bitmap over frames `0..nframes`. A set bit means "in use".
pub struct FrameBitmap<'a> {
    bits: &'a mut [u64],
    nframes: u64,
    free: u64,
}

impl<'a> FrameBitmap<'a> {
    /// Words of storage needed to track `nframes` frames.
    pub fn words_for(nframes: u64) -> usize {
        nframes.div_ceil(64) as usize
    }

    /// A bitmap in which every frame starts out in use. Call
    /// [`release`](Self::release) for each range of usable RAM.
    pub fn new(bits: &'a mut [u64], nframes: u64) -> Self {
        let nframes = nframes.min(bits.len() as u64 * 64);
        bits.fill(u64::MAX);
        Self {
            bits,
            nframes,
            free: 0,
        }
    }

    fn used(&self, pfn: u64) -> bool {
        self.bits[(pfn / 64) as usize] & 1 << (pfn % 64) != 0
    }

    fn set(&mut self, pfn: u64, used: bool) {
        let (word, bit) = ((pfn / 64) as usize, 1 << (pfn % 64));
        if used {
            self.bits[word] |= bit;
        } else {
            self.bits[word] &= !bit;
        }
    }

    pub fn free_frames(&self) -> u64 {
        self.free
    }

    /// Whether frame `pfn` is free: false for frames beyond the bitmap.
    pub fn is_free(&self, pfn: u64) -> bool {
        pfn < self.nframes && !self.used(pfn)
    }

    /// Mark `count` frames starting at `pfn` free. Frames beyond the
    /// bitmap, and frames already free, are ignored.
    pub fn release(&mut self, pfn: u64, count: u64) {
        for p in pfn..pfn.saturating_add(count).min(self.nframes) {
            if self.used(p) {
                self.set(p, false);
                self.free += 1;
            }
        }
    }

    /// Mark `count` frames starting at `pfn` in use (for memory someone
    /// else already occupies). Frames already in use are ignored.
    pub fn reserve(&mut self, pfn: u64, count: u64) {
        for p in pfn..pfn.saturating_add(count).min(self.nframes) {
            if !self.used(p) {
                self.set(p, true);
                self.free -= 1;
            }
        }
    }

    /// Allocate `count` contiguous frames. Returns the first frame number.
    pub fn alloc(&mut self, count: u64) -> Option<u64> {
        if count == 0 || count > self.free {
            return None;
        }
        let mut start = 0;
        while start + count <= self.nframes {
            // Skip whole words that are entirely in use.
            if start % 64 == 0 && self.bits[(start / 64) as usize] == u64::MAX {
                start += 64;
                continue;
            }
            match (start..start + count).find(|&p| self.used(p)) {
                Some(busy) => start = busy + 1,
                None => {
                    self.reserve(start, count);
                    return Some(start);
                }
            }
        }
        None
    }

    /// Return frames from [`alloc`](Self::alloc). Returns false, changing
    /// nothing, if any of them is not currently allocated (a double free).
    pub fn dealloc(&mut self, pfn: u64, count: u64) -> bool {
        let end = pfn.saturating_add(count);
        if end > self.nframes || (pfn..end).any(|p| !self.used(p)) {
            return false;
        }
        self.release(pfn, count);
        true
    }

    /// Allocate `count` contiguous frames where `within` allows: the
    /// lowest such run. Returns the first frame number.
    pub fn alloc_within(&mut self, count: u64, within: &Within) -> Option<u64> {
        if count == 0 || count > self.free {
            return None;
        }
        let align = within.align.max(1);
        // The last frame a run may hold.
        let top = within.highest.min(self.nframes.checked_sub(1)?);
        let mut start = within.lowest.checked_next_multiple_of(align)?;
        while start.checked_add(count - 1)? <= top {
            let last = start + count - 1;
            if within.boundary != 0 && start / within.boundary != last / within.boundary {
                // The run would cross a boundary: begin at it instead.
                start =
                    (last / within.boundary * within.boundary).checked_next_multiple_of(align)?;
                continue;
            }
            match (start..=last).find(|&p| self.used(p)) {
                Some(busy) => start = (busy + 1).checked_next_multiple_of(align)?,
                None => {
                    self.reserve(start, count);
                    return Some(start);
                }
            }
        }
        None
    }
}

/// Where a run of frames may lie in physical memory, in frame numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Within {
    /// The lowest frame the run may hold.
    pub lowest: u64,
    /// The highest frame the run may hold.
    pub highest: u64,
    /// The run begins at a multiple of this many frames; 0 and 1 both
    /// mean any frame.
    pub align: u64,
    /// The run does not cross a multiple of this many frames; 0 for no
    /// such boundary. A run longer than the boundary cannot be had.
    pub boundary: u64,
}

impl Within {
    /// Anywhere.
    pub const ANYWHERE: Self = Self {
        lowest: 0,
        highest: u64::MAX,
        align: 1,
        boundary: 0,
    };

    /// The frames whose every byte lies in the physical addresses
    /// `lowest..=highest`, with the run not crossing a multiple of
    /// `boundary` bytes (0 for none) and beginning at a multiple of
    /// `align` bytes. `None` if no whole frame lies in the range, or a
    /// boundary or alignment is not a whole number of frames.
    pub fn bytes(lowest: u64, highest: u64, boundary: u64, align: u64) -> Option<Self> {
        if !boundary.is_multiple_of(PAGE_SIZE) || !align.is_multiple_of(PAGE_SIZE) {
            return None;
        }
        let first = lowest.div_ceil(PAGE_SIZE);
        // The frame holding `highest` counts only if `highest` is its
        // last byte.
        let end = highest
            .checked_add(1)
            .map_or(u64::MAX / PAGE_SIZE + 1, |e| e / PAGE_SIZE);
        if first >= end {
            return None;
        }
        Some(Self {
            lowest: first,
            highest: end - 1,
            align: align / PAGE_SIZE,
            boundary: boundary / PAGE_SIZE,
        })
    }
}

/// Frames below 1 MiB are never allocated: legacy firmware and devices
/// make assumptions about that range that are not worth discovering.
pub const LOW_RESERVED_FRAMES: u64 = 256;

/// Why the frame allocator cannot be set up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LayoutError {
    /// The memory map has no usable memory.
    NoMemory,
    /// No usable region can hold the bitmap and still have a frame left.
    NoRoom,
}

/// How the frame allocator is laid out over a machine's usable memory:
/// how many frames the bitmap tracks, and where the bitmap itself lives.
/// Usable memory is given as `(physical address, pages)` regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    /// Frames tracked: up to the end of the highest usable region.
    pub nframes: u64,
    /// The bitmap's size, in 64-bit words.
    pub words: usize,
    /// Frames the bitmap occupies.
    pub bitmap_frames: u64,
    /// Physical address of the bitmap: the start of the largest usable
    /// region.
    pub home: u64,
}

impl Layout {
    /// Lay the allocator out over `usable`.
    pub fn of(usable: impl Iterator<Item = (u64, u64)>) -> Result<Self, LayoutError> {
        let (mut top, mut largest) = (None::<u64>, (0, 0));
        for (phys, pages) in usable {
            let end = phys / PAGE_SIZE + pages;
            top = Some(top.map_or(end, |t| t.max(end)));
            // Of regions equally large, the last.
            if pages >= largest.1 {
                largest = (phys, pages);
            }
        }
        let nframes = top.ok_or(LayoutError::NoMemory)?;
        let words = FrameBitmap::words_for(nframes);
        let bitmap_frames = (words as u64 * 8).div_ceil(PAGE_SIZE);
        if largest.1 <= bitmap_frames {
            return Err(LayoutError::NoRoom);
        }
        Ok(Self {
            nframes,
            words,
            bitmap_frames,
            home: largest.0,
        })
    }

    /// Build the bitmap in `bits`, the storage at [`Layout::home`]: the
    /// frames of `usable` are free, except those the bitmap occupies and
    /// the low ones nothing may have.
    pub fn build<'a>(
        &self,
        bits: &'a mut [u64],
        usable: impl Iterator<Item = (u64, u64)>,
    ) -> FrameBitmap<'a> {
        let mut frames = FrameBitmap::new(bits, self.nframes);
        for (phys, pages) in usable {
            frames.release(phys / PAGE_SIZE, pages);
        }
        frames.reserve(self.home / PAGE_SIZE, self.bitmap_frames);
        frames.reserve(0, LOW_RESERVED_FRAMES);
        frames
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_free(bits: &mut [u64]) -> FrameBitmap<'_> {
        let frames = bits.len() as u64 * 64;
        let mut f = FrameBitmap::new(bits, frames);
        f.release(0, frames);
        f
    }

    #[test]
    fn a_run_within_a_range_is_the_lowest_that_fits() {
        let mut bits = [0u64; 4];
        let mut f = all_free(&mut bits);
        let range = |lowest, highest| Within {
            lowest,
            highest,
            ..Within::ANYWHERE
        };
        assert_eq!(f.alloc_within(4, &range(100, 200)), Some(100));
        assert_eq!(f.alloc_within(4, &range(100, 200)), Some(104));
        // The highest frame is one the run may hold, and the last it may.
        assert_eq!(f.alloc_within(2, &range(199, 200)), Some(199));
        assert_eq!(f.alloc_within(1, &range(199, 200)), None);
        assert_eq!(f.alloc_within(3, &range(201, 202)), None);
        // Past the end of memory there is nothing.
        assert_eq!(f.alloc_within(1, &range(256, 300)), None);
        assert_eq!(f.alloc_within(2, &range(255, 300)), None);
        assert_eq!(f.alloc_within(1, &range(255, 300)), Some(255));
        // Anywhere: as `alloc`.
        assert_eq!(f.alloc_within(8, &Within::ANYWHERE), Some(0));
        assert_eq!(f.alloc_within(0, &Within::ANYWHERE), None);
        assert_eq!(f.free_frames(), 256 - 4 - 4 - 2 - 1 - 8);
        assert!(f.dealloc(100, 4));
        assert_eq!(f.alloc_within(4, &range(90, 200)), Some(90));
    }

    #[test]
    fn a_run_within_a_range_skips_frames_in_use() {
        let mut bits = [0u64; 2];
        let mut f = all_free(&mut bits);
        f.reserve(10, 1);
        f.reserve(13, 1);
        let from = |lowest| Within {
            lowest,
            ..Within::ANYWHERE
        };
        assert_eq!(f.alloc_within(3, &from(8)), Some(14));
        assert_eq!(f.alloc_within(2, &from(8)), Some(8));
        assert_eq!(f.alloc_within(2, &from(8)), Some(11));
        // More than is free anywhere.
        assert_eq!(f.alloc_within(200, &Within::ANYWHERE), None);
    }

    #[test]
    fn a_run_begins_at_its_alignment() {
        let mut bits = [0u64; 2];
        let mut f = all_free(&mut bits);
        let aligned = |lowest, align| Within {
            lowest,
            align,
            ..Within::ANYWHERE
        };
        assert_eq!(f.alloc_within(1, &aligned(1, 16)), Some(16));
        // 16 is taken: the next multiple.
        assert_eq!(f.alloc_within(3, &aligned(1, 16)), Some(32));
        assert_eq!(f.alloc_within(1, &aligned(33, 4)), Some(36));
        // An alignment of zero is none.
        assert_eq!(f.alloc_within(1, &aligned(5, 0)), Some(5));
        // No aligned run below the top.
        let top = Within {
            lowest: 113,
            highest: 127,
            align: 16,
            boundary: 0,
        };
        assert_eq!(f.alloc_within(1, &top), None);
        assert_eq!(f.alloc_within(1, &aligned(u64::MAX, 16)), None);
    }

    #[test]
    fn a_run_does_not_cross_its_boundary() {
        let mut bits = [0u64; 2];
        let mut f = all_free(&mut bits);
        let bounded = |lowest, boundary| Within {
            lowest,
            boundary,
            ..Within::ANYWHERE
        };
        // 14..18 would cross 16: the run begins at the boundary.
        assert_eq!(f.alloc_within(4, &bounded(14, 16)), Some(16));
        // 12..16 ends at the boundary without crossing it.
        assert_eq!(f.alloc_within(4, &bounded(12, 16)), Some(12));
        // A run as long as the boundary fits exactly between two.
        assert_eq!(f.alloc_within(16, &bounded(20, 16)), Some(32));
        // One longer than the boundary crosses wherever it lies.
        assert_eq!(f.alloc_within(17, &bounded(0, 16)), None);
        // Boundary and alignment together.
        let both = Within {
            lowest: 49,
            highest: u64::MAX,
            align: 2,
            boundary: 8,
        };
        assert_eq!(f.alloc_within(6, &both), Some(50));
        assert_eq!(f.alloc_within(6, &both), Some(56));
        assert_eq!(f.alloc_within(8, &both), Some(64));
    }

    #[test]
    fn a_range_of_addresses_is_the_frames_wholly_inside_it() {
        let w = |lowest, highest, boundary, align| Within::bytes(lowest, highest, boundary, align);
        // Below 4 GiB: frames 0 to 0xFFFFF.
        assert_eq!(
            w(0, 0xFFFF_FFFF, 0, PAGE_SIZE),
            Some(Within {
                lowest: 0,
                highest: 0xF_FFFF,
                align: 1,
                boundary: 0
            })
        );
        // A highest address inside a frame leaves that frame out; a
        // lowest address inside one leaves that one out too.
        assert_eq!(
            w(0x1001, 0x4FFE, 0x1_0000, 0x2000),
            Some(Within {
                lowest: 2,
                highest: 3,
                align: 2,
                boundary: 16
            })
        );
        assert_eq!(
            w(0x1000, 0x1FFF, 0, 0).map(|w| (w.lowest, w.highest)),
            Some((1, 1))
        );
        assert_eq!(w(0x1000, 0x1FFE, 0, 0), None);
        assert_eq!(w(0x2000, 0x1000, 0, 0), None);
        // The top of the address space is a highest address like another.
        assert_eq!(
            w(0, u64::MAX, 0, 0).map(|w| w.highest),
            Some(u64::MAX / PAGE_SIZE)
        );
        // Boundaries and alignments are whole frames.
        assert_eq!(w(0, u64::MAX, 0x1800, 0), None);
        assert_eq!(w(0, u64::MAX, 0, 0x800), None);
    }

    #[test]
    fn a_run_is_refused_when_the_free_frames_are_not_adjacent() {
        let mut bits = [0u64; 2];
        let mut f = FrameBitmap::new(&mut bits, 128);
        // Every other frame of the first sixteen.
        for pfn in (0..16).step_by(2) {
            f.release(pfn, 1);
        }
        assert_eq!(f.free_frames(), 8);
        // Eight frames are free and no two of them touch.
        assert_eq!(f.alloc(2), None);
        assert_eq!(f.alloc(8), None);
        assert_eq!(f.free_frames(), 8, "a refused run takes nothing");
        assert_eq!(f.alloc(1), Some(0));
        // A run that ends with the bitmap is found; one that would have
        // to go past its end is not.
        f.release(126, 2);
        assert_eq!(f.alloc(3), None);
        assert_eq!(f.alloc(2), Some(126));
    }

    const MIB: u64 = 1 << 20;

    #[test]
    fn the_bitmap_tracks_up_to_the_top_of_usable_memory() {
        // 1 MiB at 1 MiB, and 64 MiB at 16 MiB.
        let layout = Layout::of([(MIB, 256), (16 * MIB, 16384)].into_iter()).unwrap();
        assert_eq!(layout.nframes, 80 * MIB / PAGE_SIZE);
        assert_eq!(layout.words, 320);
        // 320 words are 2560 bytes: one frame.
        assert_eq!(layout.bitmap_frames, 1);
        assert_eq!(layout.home, 16 * MIB);
        // The order of the regions does not change the top.
        let reversed = Layout::of([(16 * MIB, 16384), (MIB, 256)].into_iter()).unwrap();
        assert_eq!(reversed, layout);
    }

    #[test]
    fn the_bitmap_grows_a_frame_for_every_128_mib() {
        // 4096 bytes of bitmap track 32768 frames: 128 MiB.
        let frames = 128 * MIB / PAGE_SIZE;
        assert_eq!(
            Layout::of([(0, frames)].into_iter()).unwrap().bitmap_frames,
            1
        );
        let one_more = Layout::of([(0, frames + 1)].into_iter()).unwrap();
        assert_eq!(one_more.bitmap_frames, 2);
        assert_eq!(one_more.words, 513);
        // 4 GiB: 32 frames of bitmap.
        let big = Layout::of([(0, 4096 * MIB / PAGE_SIZE)].into_iter()).unwrap();
        assert_eq!((big.words, big.bitmap_frames), (16384, 32));
    }

    #[test]
    fn the_bitmap_lives_in_the_largest_region_the_last_of_equals() {
        let home = |regions: &[(u64, u64)]| Layout::of(regions.iter().copied()).map(|l| l.home);
        assert_eq!(
            home(&[(MIB, 16), (8 * MIB, 512), (32 * MIB, 64)]),
            Ok(8 * MIB)
        );
        assert_eq!(home(&[(MIB, 512), (8 * MIB, 512)]), Ok(8 * MIB));
        assert_eq!(home(&[(8 * MIB, 512), (MIB, 512)]), Ok(MIB));
    }

    #[test]
    fn a_machine_without_room_for_the_bitmap_is_refused() {
        assert_eq!(Layout::of([].into_iter()), Err(LayoutError::NoMemory));
        // One frame at 4 GiB needs a 32-frame bitmap.
        assert_eq!(
            Layout::of([(4096 * MIB, 1)].into_iter()),
            Err(LayoutError::NoRoom)
        );
        // A region exactly the bitmap's size leaves nothing to allocate.
        assert_eq!(
            Layout::of([(4096 * MIB - 32 * PAGE_SIZE, 32)].into_iter()),
            Err(LayoutError::NoRoom)
        );
        assert!(Layout::of([(4096 * MIB - 33 * PAGE_SIZE, 33)].into_iter()).is_ok());
        // Regions with no pages are no memory to live in.
        assert_eq!(Layout::of([(MIB, 0)].into_iter()), Err(LayoutError::NoRoom));
    }

    #[test]
    fn usable_frames_are_free_but_for_the_bitmap_and_low_memory() {
        // Low memory (160 frames, all below 1 MiB), 1 MiB at 1 MiB, a
        // hole, and 8 MiB at 16 MiB where the bitmap goes.
        let usable = [(0, 160), (MIB, 256), (16 * MIB, 2048)];
        let layout = Layout::of(usable.into_iter()).unwrap();
        assert_eq!((layout.home, layout.bitmap_frames), (16 * MIB, 1));
        let mut bits = vec![0u64; layout.words];
        let mut frames = layout.build(&mut bits, usable.into_iter());
        // Everything usable above 1 MiB, less the bitmap's frame.
        assert_eq!(frames.free_frames(), 256 + 2048 - 1);
        // The first frame handed out is the first above 1 MiB.
        assert_eq!(frames.alloc(1), Some(256));
        // Nothing below 1 MiB, in the hole, or under the bitmap can be
        // had: a run too long for the 1 MiB region starts after the
        // bitmap's frame.
        let bitmap_pfn = 16 * MIB / PAGE_SIZE;
        assert_eq!(frames.alloc(256), Some(bitmap_pfn + 1));
        // Take everything: no frame handed out is one that must not be.
        let mut taken = 0;
        while let Some(pfn) = frames.alloc(1) {
            assert!(pfn >= LOW_RESERVED_FRAMES, "frame {pfn} is below 1 MiB");
            assert_ne!(pfn, bitmap_pfn, "the bitmap's own frame was handed out");
            assert!(
                (256..512).contains(&pfn) || (bitmap_pfn..bitmap_pfn + 2048).contains(&pfn),
                "frame {pfn} is not usable memory"
            );
            taken += 1;
        }
        assert_eq!(taken, 256 + 2048 - 1 - 1 - 256);
    }

    #[test]
    fn a_bitmap_in_low_memory_is_reserved_only_once() {
        // The largest region starts below 1 MiB: its low frames are
        // reserved as the bitmap's and as low memory, and counted once.
        let usable = [(0x8_0000, 1024)];
        let layout = Layout::of(usable.into_iter()).unwrap();
        assert_eq!(layout.home, 0x8_0000);
        let mut bits = vec![0u64; layout.words];
        let mut frames = layout.build(&mut bits, usable.into_iter());
        // The region covers frames 128 to 1151; those below 256 are gone.
        assert_eq!(frames.free_frames(), 1152 - 256);
        assert_eq!(frames.alloc(1), Some(256));
    }

    #[test]
    fn starts_full_then_releases() {
        let mut bits = [0u64; 4];
        let mut f = FrameBitmap::new(&mut bits, 200);
        assert_eq!(f.free_frames(), 0);
        assert_eq!(f.alloc(1), None);
        f.release(10, 50);
        f.release(40, 40); // overlaps: frames 40..60 are not counted twice
        assert_eq!(f.free_frames(), 70);
        f.release(190, 100); // clipped to the bitmap
        assert_eq!(f.free_frames(), 80);
    }

    #[test]
    fn contiguous_first_fit() {
        let mut bits = [0u64; 4];
        let mut f = FrameBitmap::new(&mut bits, 256);
        f.release(8, 4); // a hole too small for 8
        f.release(100, 32);
        assert_eq!(f.alloc(8), Some(100));
        assert_eq!(f.alloc(4), Some(8));
        assert_eq!(f.alloc(1), Some(108));
        assert_eq!(f.alloc(64), None, "no run that long");
        assert_eq!(f.free_frames(), 23);
        assert_eq!(f.alloc(0), None);
    }

    #[test]
    fn run_may_cross_word_boundary() {
        let mut bits = [0u64; 4];
        let mut f = FrameBitmap::new(&mut bits, 256);
        f.release(60, 10);
        assert_eq!(f.alloc(10), Some(60));
        assert!(f.dealloc(60, 10));
        assert_eq!(f.alloc(10), Some(60));
    }

    #[test]
    fn double_free_is_refused() {
        let mut bits = [0u64; 2];
        let mut f = FrameBitmap::new(&mut bits, 128);
        f.release(0, 128);
        let p = f.alloc(4).unwrap();
        assert!(f.dealloc(p, 4));
        assert!(!f.dealloc(p, 4), "second free");
        assert!(!f.dealloc(126, 4), "runs off the end");
        assert_eq!(f.free_frames(), 128);
    }

    #[test]
    fn reserve_carves_out_used_memory() {
        let mut bits = [0u64; 2];
        let mut f = FrameBitmap::new(&mut bits, 128);
        f.release(0, 128);
        f.reserve(0, 16);
        f.reserve(8, 16); // overlap counted once
        assert_eq!(f.free_frames(), 104);
        assert_eq!(f.alloc(1), Some(24));
    }

    #[test]
    fn storage_smaller_than_requested_is_clipped() {
        let mut bits = [0u64; 1];
        let mut f = FrameBitmap::new(&mut bits, 1000);
        f.release(0, 1000);
        assert_eq!(f.free_frames(), 64);
        assert_eq!(FrameBitmap::words_for(65), 2);
    }
}
