//! A small-block allocator over one contiguous arena: the arithmetic
//! behind the executive pool.
//!
//! Blocks carry a 16-byte header and sit back to back, so the arena can be
//! walked from either end of a block (boundary tags). Free neighbours are
//! merged on free. Allocation is first-fit by walking the arena, which is
//! slow for a big heap and fine for boot-time driver bring-up.
//!
//! Built to catch driver bugs rather than hide them:
//! - every block ends in at least 8 guard bytes, checked on free, so a
//!   write past the end of an allocation is reported;
//! - a free of an address that is not a live block is reported, not
//!   obeyed;
//! - `tag` and requested size are kept per block for leak reports.
//!
//! The arena is a byte slice and offsets are returned, so this is safe
//! code and the host tests can drive it.

/// Allocation granularity and payload alignment.
pub const ALIGN: usize = 16;
const HEADER: usize = 16;
const GUARD: usize = 8;
const GUARD_BYTE: u8 = 0xC5;
/// Small allocations stay within a single 4 KiB page, matching Windows'
/// executive pool (which drivers such as KMDF rely on: a small block's
/// payload is never page-aligned, nor is `payload + 16`).
const PAGE_SIZE: usize = 4096;
/// Top bit of the `req` header field: the block is allocated.
const USED: u32 = 1 << 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeapError {
    /// The offset is not the payload of a live allocation.
    NotAllocated,
    /// Bytes past the end of the allocation were overwritten.
    Overrun { tag: u32, size: usize },
    /// Block headers are inconsistent: the arena is corrupt.
    Corrupt,
}

/// Counts of live allocations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Usage {
    pub blocks: usize,
    pub bytes: usize,
}

/// Header fields, all `u32`: block size and previous block's size in
/// `ALIGN` units, the caller's tag, and the requested size with `USED`.
struct Block {
    units: u32,
    prev_units: u32,
    tag: u32,
    req: u32,
}

pub struct Arena<'a> {
    mem: &'a mut [u8],
    usage: Usage,
}

impl<'a> Arena<'a> {
    /// Take over `mem` as one free block. Its length is rounded down to a
    /// multiple of `ALIGN`; an arena too small to hold a block is useless
    /// but harmless.
    pub fn new(mem: &'a mut [u8]) -> Self {
        let len = mem.len() & !(ALIGN - 1);
        let mut a = Self {
            mem: &mut mem[..len],
            usage: Usage::default(),
        };
        if len >= HEADER {
            let whole = Block {
                units: (len / ALIGN) as u32,
                prev_units: 0,
                tag: 0,
                req: 0,
            };
            a.put(0, &whole);
        }
        a
    }

    pub fn len(&self) -> usize {
        self.mem.len()
    }

    pub fn is_empty(&self) -> bool {
        self.mem.is_empty()
    }

    pub fn usage(&self) -> Usage {
        self.usage
    }

    /// The header at `off`: one slice of `HEADER` bytes, bounds-checked
    /// once, read as four little-endian words.
    fn get(&self, off: usize) -> Block {
        let h: &[u8; HEADER] = self.mem[off..off + HEADER]
            .try_into()
            .expect("a header's bytes");
        let word =
            |i: usize| u32::from_le_bytes([h[4 * i], h[4 * i + 1], h[4 * i + 2], h[4 * i + 3]]);
        Block {
            units: word(0),
            prev_units: word(1),
            tag: word(2),
            req: word(3),
        }
    }

    /// Write `b` as the header at `off`, in one slice of `HEADER` bytes.
    fn put(&mut self, off: usize, b: &Block) {
        let h: &mut [u8; HEADER] = (&mut self.mem[off..off + HEADER])
            .try_into()
            .expect("a header's bytes");
        for (i, v) in [b.units, b.prev_units, b.tag, b.req]
            .into_iter()
            .enumerate()
        {
            h[4 * i..4 * i + 4].copy_from_slice(&v.to_le_bytes());
        }
    }

    /// A block header is plausible: nonzero size, inside the arena.
    fn sane(&self, off: usize, b: &Block) -> bool {
        b.units != 0 && off + b.units as usize * ALIGN <= self.mem.len()
    }

    /// Allocate `size` bytes labelled `tag`. Returns the payload offset,
    /// which is a multiple of `ALIGN` plus `HEADER`.
    pub fn alloc(&mut self, size: usize, tag: u32) -> Option<usize> {
        if size >= USED as usize {
            return None;
        }
        let need = (HEADER + size + GUARD).next_multiple_of(ALIGN);
        let stay_in_page = need <= PAGE_SIZE;
        let mut off = 0;
        while off + HEADER <= self.mem.len() {
            let b = self.get(off);
            if !self.sane(off, &b) {
                return None; // corrupt arena: refuse rather than guess
            }
            let total = b.units as usize * ALIGN;
            if b.req & USED == 0 && total >= need {
                let skip = if stay_in_page {
                    let page_rem = PAGE_SIZE - (off & (PAGE_SIZE - 1));
                    if need <= page_rem { 0 } else { page_rem }
                } else {
                    0
                };
                if total >= skip + need {
                    let mut prev_units = b.prev_units;
                    if skip > 0 {
                        let prefix = Block {
                            units: (skip / ALIGN) as u32,
                            prev_units,
                            tag: 0,
                            req: 0,
                        };
                        self.put(off, &prefix);
                        prev_units = prefix.units;
                        off += skip;
                    }
                    let rem = total - skip;
                    // Split unless the remainder could not hold a block.
                    let take = if rem - need >= HEADER + GUARD {
                        need
                    } else {
                        rem
                    };
                    if take < rem {
                        let rest = Block {
                            units: ((rem - take) / ALIGN) as u32,
                            prev_units: (take / ALIGN) as u32,
                            tag: 0,
                            req: 0,
                        };
                        self.put(off + take, &rest);
                        if off + rem < self.mem.len() {
                            let mut next = self.get(off + rem);
                            next.prev_units = rest.units;
                            self.put(off + rem, &next);
                        }
                    } else if skip > 0 && off + rem < self.mem.len() {
                        let mut next = self.get(off + rem);
                        next.prev_units = (take / ALIGN) as u32;
                        self.put(off + rem, &next);
                    }
                    self.put(
                        off,
                        &Block {
                            units: (take / ALIGN) as u32,
                            prev_units,
                            tag,
                            req: size as u32 | USED,
                        },
                    );
                    self.mem[off + HEADER + size..off + take].fill(GUARD_BYTE);
                    self.usage.blocks += 1;
                    self.usage.bytes += size;
                    return Some(off + HEADER);
                }
            }
            off += total;
        }
        None
    }

    /// Validate that `payload` is a live block; return its header offset.
    fn live(&self, payload: usize) -> Result<(usize, Block), HeapError> {
        if payload < HEADER || !payload.is_multiple_of(ALIGN) || payload > self.mem.len() {
            return Err(HeapError::NotAllocated);
        }
        let off = payload - HEADER;
        let b = self.get(off);
        if b.req & USED == 0 || !self.sane(off, &b) {
            return Err(HeapError::NotAllocated);
        }
        let total = b.units as usize * ALIGN;
        let size = (b.req & !USED) as usize;
        if HEADER + size + GUARD > total {
            return Err(HeapError::NotAllocated);
        }
        // The neighbours must agree about this block, or it is not one.
        if off + total < self.mem.len() && self.get(off + total).prev_units != b.units {
            return Err(HeapError::NotAllocated);
        }
        if off > 0 {
            let prev = b.prev_units as usize * ALIGN;
            if prev == 0 || prev > off || self.get(off - prev).units != b.prev_units {
                return Err(HeapError::NotAllocated);
            }
        } else if b.prev_units != 0 {
            return Err(HeapError::NotAllocated);
        }
        Ok((off, b))
    }

    /// Size and tag of the live allocation at `payload`.
    pub fn info(&self, payload: usize) -> Result<(usize, u32), HeapError> {
        self.live(payload)
            .map(|(_, b)| ((b.req & !USED) as usize, b.tag))
    }

    /// Free the allocation at `payload`. On `Overrun` the block is still
    /// freed; the error reports the damage. Returns the size and tag.
    pub fn free(&mut self, payload: usize) -> Result<(usize, u32), HeapError> {
        let (mut off, b) = self.live(payload)?;
        let size = (b.req & !USED) as usize;
        let mut total = b.units as usize * ALIGN;
        let intact = self.mem[off + HEADER + size..off + total]
            .iter()
            .all(|&g| g == GUARD_BYTE);
        self.usage.blocks -= 1;
        self.usage.bytes -= size;

        let mut prev_units = b.prev_units;
        // Merge with a free successor, then a free predecessor.
        if off + total < self.mem.len() {
            let next = self.get(off + total);
            if next.req & USED == 0 {
                total += next.units as usize * ALIGN;
            }
        }
        if off > 0 {
            let prev_off = off - b.prev_units as usize * ALIGN;
            let prev = self.get(prev_off);
            if prev.req & USED == 0 {
                total += off - prev_off;
                off = prev_off;
                prev_units = prev.prev_units;
            }
        }
        self.put(
            off,
            &Block {
                units: (total / ALIGN) as u32,
                prev_units,
                tag: 0,
                req: 0,
            },
        );
        if off + total < self.mem.len() {
            let mut next = self.get(off + total);
            next.prev_units = (total / ALIGN) as u32;
            self.put(off + total, &next);
        }
        if intact {
            Ok((size, b.tag))
        } else {
            Err(HeapError::Overrun { tag: b.tag, size })
        }
    }

    /// Walk the whole arena, checking every header and guard, and call
    /// `each(tag, size)` for every live allocation.
    pub fn walk(&self, mut each: impl FnMut(u32, usize)) -> Result<(), HeapError> {
        let (mut off, mut prev_units, mut seen) = (0, 0, Usage::default());
        while off < self.mem.len() {
            let b = self.get(off);
            if !self.sane(off, &b) || b.prev_units != prev_units {
                return Err(HeapError::Corrupt);
            }
            let total = b.units as usize * ALIGN;
            if b.req & USED != 0 {
                let size = (b.req & !USED) as usize;
                if HEADER + size + GUARD > total {
                    return Err(HeapError::Corrupt);
                }
                if self.mem[off + HEADER + size..off + total]
                    .iter()
                    .any(|&g| g != GUARD_BYTE)
                {
                    return Err(HeapError::Overrun { tag: b.tag, size });
                }
                seen.blocks += 1;
                seen.bytes += size;
                each(b.tag, size);
            }
            prev_units = b.units;
            off += total;
        }
        if seen == self.usage {
            Ok(())
        } else {
            Err(HeapError::Corrupt)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: u32 = u32::from_le_bytes(*b"Test");

    fn payload<'m>(a: &'m mut Arena<'_>, off: usize, len: usize) -> &'m mut [u8] {
        &mut a.mem[off..off + len]
    }

    #[test]
    fn alloc_is_aligned_and_accounted() {
        let mut mem = vec![0u8; 4096];
        let mut a = Arena::new(&mut mem);
        let p = a.alloc(100, TAG).unwrap();
        let q = a.alloc(1, TAG).unwrap();
        assert_eq!((p % ALIGN, q % ALIGN), (0, 0));
        assert!(q >= p + 100 + GUARD);
        assert_eq!(
            a.usage(),
            Usage {
                blocks: 2,
                bytes: 101
            }
        );
        assert_eq!(a.info(p), Ok((100, TAG)));
        payload(&mut a, p, 100).fill(0xFF);
        assert_eq!(
            a.walk(|_, _| {}),
            Ok(()),
            "writing the whole payload is legal"
        );
        assert_eq!(a.free(p), Ok((100, TAG)));
        assert_eq!(a.free(q), Ok((1, TAG)));
        assert_eq!(a.usage(), Usage::default());
    }

    #[test]
    fn zero_size_allocations_are_distinct() {
        let mut mem = vec![0u8; 256];
        let mut a = Arena::new(&mut mem);
        let (p, q) = (a.alloc(0, TAG).unwrap(), a.alloc(0, TAG).unwrap());
        assert_ne!(p, q);
        assert_eq!(a.free(p), Ok((0, TAG)));
        assert_eq!(a.free(q), Ok((0, TAG)));
    }

    #[test]
    fn free_merges_neighbours_so_the_arena_is_whole_again() {
        let mut mem = vec![0u8; 1024];
        let mut a = Arena::new(&mut mem);
        let big = 1024 - HEADER - GUARD;
        let blocks: Vec<usize> = (0..6).map(|_| a.alloc(100, TAG).unwrap()).collect();
        assert_eq!(a.alloc(big, TAG), None);
        // Free in an order that exercises merge-with-next, merge-with-prev and both.
        for i in [1, 3, 2, 5, 0, 4] {
            assert!(a.free(blocks[i]).is_ok());
            assert_eq!(a.walk(|_, _| {}), Ok(()));
        }
        assert!(
            a.alloc(big, TAG).is_some(),
            "all free space merged back into one block"
        );
    }

    #[test]
    fn overrun_is_detected_on_free_and_on_walk() {
        let mut mem = vec![0u8; 1024];
        let mut a = Arena::new(&mut mem);
        let p = a.alloc(24, TAG).unwrap();
        a.mem[p + 24] = 0; // one byte past the end
        assert_eq!(
            a.walk(|_, _| {}),
            Err(HeapError::Overrun { tag: TAG, size: 24 })
        );
        assert_eq!(a.free(p), Err(HeapError::Overrun { tag: TAG, size: 24 }));
        assert_eq!(a.usage(), Usage::default(), "the block is released even so");
    }

    #[test]
    fn bad_frees_are_refused() {
        let mut mem = vec![0u8; 1024];
        let mut a = Arena::new(&mut mem);
        let p = a.alloc(64, TAG).unwrap();
        for bad in [0, 8, p + 16, p + 1, 4096, usize::MAX & !15] {
            assert_eq!(a.free(bad), Err(HeapError::NotAllocated), "offset {bad:#x}");
        }
        assert!(a.free(p).is_ok());
        assert_eq!(a.free(p), Err(HeapError::NotAllocated), "double free");
        assert_eq!(a.usage(), Usage::default());
    }

    #[test]
    fn forged_header_inside_a_payload_is_not_a_block() {
        let mut mem = vec![0u8; 1024];
        let mut a = Arena::new(&mut mem);
        let p = a.alloc(128, TAG).unwrap();
        // Write something shaped like a used header into the payload.
        let fake = p + 32;
        a.mem[fake..fake + 4].copy_from_slice(&3u32.to_le_bytes());
        a.mem[fake + 12..fake + 16].copy_from_slice(&(8 | USED).to_le_bytes());
        assert_eq!(a.free(fake + HEADER), Err(HeapError::NotAllocated));
        assert!(a.free(p).is_ok());
    }

    /// Header fields, by position.
    const UNITS: usize = 0;
    const PREV_UNITS: usize = 1;
    const REQ: usize = 3;

    /// Overwrite one header field of the block whose payload is at
    /// `payload`, as an overrun of the block before it would.
    fn smash(a: &mut Arena<'_>, payload: usize, field: usize, value: u32) {
        let at = payload - HEADER + 4 * field;
        a.mem[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    #[test]
    fn a_block_whose_header_was_overwritten_is_refused_not_freed() {
        // Three 64-byte blocks of six units each; the middle one's
        // header is damaged in each way that leaves the `USED` bit set.
        let corrupt = HeapError::Corrupt;
        let cases = [
            // It claims more bytes than it has room for.
            (REQ, USED | 4000, corrupt),
            // It is smaller than what it claims to hold.
            (UNITS, 3, corrupt),
            // It has no size, or runs off the arena.
            (UNITS, 0, corrupt),
            (UNITS, 60_000, corrupt),
            // It swallows the next block, whose header then lies where
            // guard bytes should, and whose successor disagrees.
            (UNITS, 12, HeapError::Overrun { tag: TAG, size: 64 }),
            // It denies having a predecessor, puts it before the start
            // of the arena, or puts it where no block begins.
            (PREV_UNITS, 0, corrupt),
            (PREV_UNITS, 1000, corrupt),
            (PREV_UNITS, 2, corrupt),
        ];
        for (field, value, walk) in cases {
            let mut mem = vec![0u8; 1024];
            let mut a = Arena::new(&mut mem);
            let blocks: Vec<usize> = (0..3).map(|_| a.alloc(64, TAG).unwrap()).collect();
            assert_eq!(a.walk(|_, _| {}), Ok(()));
            smash(&mut a, blocks[1], field, value);
            let case = format!("field {field} = {value:#x}");
            assert_eq!(a.info(blocks[1]), Err(HeapError::NotAllocated), "{case}");
            assert_eq!(a.free(blocks[1]), Err(HeapError::NotAllocated), "{case}");
            // Nothing was released on the damaged header's word.
            assert_eq!(
                a.usage(),
                Usage {
                    blocks: 3,
                    bytes: 192
                },
                "{case}"
            );
            assert_eq!(a.walk(|_, _| {}), Err(walk), "{case}");
        }
    }

    #[test]
    fn the_first_block_has_no_predecessor() {
        let mut mem = vec![0u8; 1024];
        let mut a = Arena::new(&mut mem);
        let p = a.alloc(64, TAG).unwrap();
        smash(&mut a, p, PREV_UNITS, 6);
        assert_eq!(a.free(p), Err(HeapError::NotAllocated));
        assert_eq!(a.walk(|_, _| {}), Err(HeapError::Corrupt));
    }

    #[test]
    fn a_corrupt_arena_refuses_to_allocate() {
        // A block of no size would be walked for ever; one that runs off
        // the arena would be read past its end.
        for units in [0, 60_000] {
            let mut mem = vec![0u8; 1024];
            let mut a = Arena::new(&mut mem);
            a.alloc(64, TAG).unwrap();
            let q = a.alloc(64, TAG).unwrap();
            smash(&mut a, q, UNITS, units);
            // There is room after the damaged block, but no way to it.
            assert_eq!(a.alloc(8, TAG), None, "units {units}");
            assert_eq!(a.usage().blocks, 2);
        }
    }

    #[test]
    fn the_walk_notices_an_allocation_that_went_missing() {
        let mut mem = vec![0u8; 1024];
        let mut a = Arena::new(&mut mem);
        a.alloc(64, 1).unwrap();
        let q = a.alloc(64, 2).unwrap();
        // The header chain stays consistent; only the `USED` bit goes.
        smash(&mut a, q, REQ, 64);
        let mut seen = Vec::new();
        assert_eq!(
            a.walk(|tag, size| seen.push((tag, size))),
            Err(HeapError::Corrupt),
            "one block fewer than were allocated"
        );
        assert_eq!(seen, [(1, 64)]);
        assert_eq!(a.free(q), Err(HeapError::NotAllocated));
    }

    #[test]
    fn walk_reports_tags() {
        let mut mem = vec![0u8; 1024];
        let mut a = Arena::new(&mut mem);
        a.alloc(10, 1).unwrap();
        let q = a.alloc(20, 2).unwrap();
        a.alloc(30, 3).unwrap();
        a.free(q).unwrap();
        let mut seen = Vec::new();
        a.walk(|tag, size| seen.push((tag, size))).unwrap();
        assert_eq!(seen, [(1, 10), (3, 30)]);
    }

    #[test]
    fn exhaustion_and_tiny_arenas() {
        let mut mem = vec![0u8; 64];
        let mut a = Arena::new(&mut mem);
        assert_eq!(a.alloc(64, TAG), None);
        let p = a.alloc(40, TAG).unwrap();
        assert_eq!(a.alloc(1, TAG), None);
        assert!(a.free(p).is_ok());
        let mut tiny = [0u8; 8];
        let mut t = Arena::new(&mut tiny);
        assert_eq!(t.alloc(0, TAG), None);
        assert!(t.is_empty());
        assert_eq!(t.walk(|_, _| {}), Ok(()));
    }

    /// Random alloc/free against a model, checking contents and the walk.
    #[test]
    fn stress_against_model() {
        let mut mem = vec![0u8; 16 * 1024];
        let mut a = Arena::new(&mut mem);
        let mut live: Vec<(usize, usize, u8)> = Vec::new();
        let mut seed = 0x1234_5678_9ABC_DEF0u64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        for step in 0..4000u32 {
            if rnd() % 3 != 0 || live.is_empty() {
                let size = (rnd() % 300) as usize;
                if let Some(p) = a.alloc(size, step) {
                    let fill = step as u8;
                    payload(&mut a, p, size).fill(fill);
                    live.push((p, size, fill));
                }
            } else {
                let (p, size, fill) = live.swap_remove((rnd() % live.len() as u64) as usize);
                assert!(
                    payload(&mut a, p, size).iter().all(|&b| b == fill),
                    "payload intact"
                );
                assert_eq!(a.free(p).map(|r| r.0), Ok(size));
            }
            if step % 97 == 0 {
                assert_eq!(a.walk(|_, _| {}), Ok(()));
            }
        }
        assert_eq!(a.usage().blocks, live.len());
        for (p, _, _) in live {
            assert!(a.free(p).is_ok());
        }
        assert_eq!(a.usage(), Usage::default());
        assert!(a.alloc(16 * 1024 - HEADER - GUARD, 0).is_some());
    }

    /// Windows small-pool invariant: allocations smaller than a page never
    /// cross a 4 KiB page boundary and never land at a page-aligned offset or
    /// 16 bytes before a page boundary (which KMDF `FxPoolFree` relies on).
    #[test]
    fn small_allocations_stay_within_one_page() {
        const PAGE: usize = 4096;
        let mut mem = vec![0u8; 4 * PAGE];
        let mut a = Arena::new(&mut mem);
        let mut live = Vec::new();
        // Fill near the end of page 0 so the next small allocation would cross
        // the 0x1000 page boundary (or land at 0xFF0 where ptr + 0x10 == 0x1000).
        for size in [
            4000usize, 32, 48, 64, 16, 24, 100, 3900, 128, 4031, 16, 16, 16,
        ] {
            let p = a.alloc(size, TAG).expect("allocation fits in 4-page arena");
            assert_ne!(
                p & (PAGE - 1),
                0,
                "small block {p:#x} must not be page-aligned"
            );
            assert!(
                (p & (PAGE - 1)) + size <= PAGE,
                "small block {p:#x}..{:#x} crossed a 4 KiB page boundary",
                p + size
            );
            if size >= 16 {
                assert_ne!(
                    (p + 16) & (PAGE - 1),
                    0,
                    "small block {p:#x} + 0x10 must not be page-aligned (KMDF FxPoolFree)"
                );
            }
            live.push(p);
        }
        assert_eq!(a.walk(|_, _| {}), Ok(()));
        for p in live {
            assert!(a.free(p).is_ok());
        }
        assert_eq!(a.usage(), Usage::default());
        assert_eq!(a.walk(|_, _| {}), Ok(()));
    }
}
