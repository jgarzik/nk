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
