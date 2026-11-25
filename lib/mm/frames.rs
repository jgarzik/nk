//! Physical frame allocator: one bit per 4 KiB frame.
//!
//! First-fit over a bitmap, with contiguous runs for the callers that need
//! them (page tables need one frame; driver images and pool arenas need
//! many). Simple and auditable beats fast here: the allocator is not on
//! any hot path yet.

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

#[cfg(test)]
mod tests {
    use super::*;

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
