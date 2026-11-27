//! Read-ahead: what a file object's last reads say about the next one.
//!
//! A private cache map keeps the last two reads (`FileOffset1`,
//! `BeyondLastByte1`, `FileOffset2`, `BeyondLastByte2`). The pattern is
//! `CcDetermineReadPattern`'s, read from the pinned kernel:
//!
//! - a file object opened for sequential access only is sequential, one
//!   opened for random access has no pattern;
//! - a read that starts roughly where the last ended, the last having
//!   started roughly where the one before ended, is sequential twice
//!   over;
//! - a read as far from the last as the last was from the one before is
//!   strided;
//! - anything else has no pattern.
//!
//! "Roughly" is `CcAreOffsetsRoughlyEqual`: the same high 32 bits and
//! low halves at most 512 bytes apart.
//!
//! What is read ahead follows the pattern: for a sequential read, the
//! read's length rounded up to the read-ahead granularity, from the page
//! where it ended (twice that for a file object opened for sequential
//! access only); for a strided one, the read's length at the next
//! stride. Windows' pipelined read-ahead and its growth
//! (`CcScheduleReadAheadEx` with `CcSetReadAheadGranularityEx`) are
//! NK's to leave out: no file system of the set asks for them.

/// `FO_SEQUENTIAL_ONLY`.
pub const FO_SEQUENTIAL_ONLY: u32 = 0x20;
/// `FO_RANDOM_ACCESS`.
pub const FO_RANDOM_ACCESS: u32 = 0x10_0000;

/// A private cache map's read history.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct History {
    pub offset1: u64,
    pub beyond1: u64,
    pub offset2: u64,
    pub beyond2: u64,
}

impl History {
    /// The history after a read of `len` bytes at `offset`, as
    /// `CcCopyReadEx` rotates it.
    pub fn after(self, offset: u64, len: u64) -> Self {
        Self {
            offset1: self.offset2,
            beyond1: self.beyond2,
            offset2: offset,
            beyond2: offset + len,
        }
    }
}

/// The access pattern, numbered as `CcDetermineReadPattern` returns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pattern {
    None = 0,
    /// The file object is opened for sequential access only.
    SequentialOnly = 1,
    Sequential = 2,
    Strided = 3,
}

/// `CcAreOffsetsRoughlyEqual`.
pub fn roughly_equal(a: u64, b: u64) -> bool {
    a >> 32 == b >> 32 && (a as u32).abs_diff(b as u32) <= 0x200
}

/// The pattern of a read at `offset`, after `h`, by a file object whose
/// `Flags` are `fo_flags`.
pub fn pattern(h: &History, offset: u64, fo_flags: u32) -> Pattern {
    if fo_flags & FO_SEQUENTIAL_ONLY != 0 {
        return Pattern::SequentialOnly;
    }
    if fo_flags & FO_RANDOM_ACCESS != 0 {
        return Pattern::None;
    }
    if roughly_equal(offset, h.beyond2) && roughly_equal(h.beyond1, h.offset2) {
        return Pattern::Sequential;
    }
    if offset.wrapping_sub(h.offset2) == h.offset2.wrapping_sub(h.offset1) {
        return Pattern::Strided;
    }
    Pattern::None
}

/// What to read ahead after a read of `len` bytes at `offset` with
/// pattern `p`, `h` being the history before the read, with read-ahead
/// granularity mask `mask` (granularity minus one): the offset and
/// length, or nothing.
pub fn plan(h: &History, p: Pattern, offset: u64, len: u64, mask: u64) -> Option<(u64, u64)> {
    let size = (len + mask) & !mask;
    let page = |at: u64| at & !(crate::PAGE_SIZE - 1);
    match p {
        Pattern::None => None,
        Pattern::Sequential => Some((page(offset + len), size)),
        Pattern::SequentialOnly => Some((page(offset + len), 2 * size)),
        Pattern::Strided => Some((page((2 * offset).checked_sub(h.offset2)?), size)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roughly_is_half_a_kilobyte() {
        assert!(roughly_equal(0x1000, 0x1200));
        assert!(roughly_equal(0x1200, 0x1000));
        assert!(!roughly_equal(0x1000, 0x1201));
        assert!(
            !roughly_equal(0x1_0000_0000, 0xFFFF_FF00),
            "the high halves differ"
        );
    }

    #[test]
    fn patterns() {
        let seq = History::default().after(0, 0x1000).after(0x1000, 0x1000);
        assert_eq!(pattern(&seq, 0x2000, 0), Pattern::Sequential);
        assert_eq!(
            pattern(&seq, 0x2100, 0),
            Pattern::Sequential,
            "roughly where it ended"
        );
        assert_eq!(pattern(&seq, 0x2000, FO_RANDOM_ACCESS), Pattern::None);
        assert_eq!(
            pattern(&seq, 0x9000, FO_SEQUENTIAL_ONLY),
            Pattern::SequentialOnly
        );
        let stride = History::default().after(0, 0x200).after(0x10000, 0x200);
        assert_eq!(pattern(&stride, 0x20000, 0), Pattern::Strided);
        assert_eq!(pattern(&stride, 0x30000, 0), Pattern::None);
    }

    #[test]
    fn plans() {
        let none = History::default();
        assert_eq!(
            plan(&none, Pattern::Sequential, 0x1000, 0x1800, 0xFFFF),
            Some((0x2000, 0x10000))
        );
        assert_eq!(
            plan(&none, Pattern::SequentialOnly, 0, 0x1000, 0xFFFF),
            Some((0x1000, 0x20000))
        );
        assert_eq!(plan(&none, Pattern::None, 0, 0x1000, 0xFFFF), None);
        let h = History::default().after(0, 0x200).after(0x10000, 0x200);
        assert_eq!(
            plan(&h, Pattern::Strided, 0x20000, 0x200, 0xFFF),
            Some((0x30000, 0x1000))
        );
    }
}
