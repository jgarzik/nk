//! How much dirty data the cache may hold, and how much of it a lazy
//! writer's pass writes, as the pinned kernel computes them
//! (`CcInitializePartition`, `CcCalculatePagesToWrite`).

/// A pass writes every dirty page while there are at most this many
/// (`CcMaxLazyWritePages`).
pub const MAX_LAZY_WRITE_PAGES: u64 = 0x100;
/// Below this many available pages, memory is short and a pass writes
/// more (`CcCalculatePagesToWrite`'s test of the partition's available
/// pages).
pub const LOW_AVAILABLE_PAGES: u64 = 0x1000;

/// The dirty-page threshold and target for `physical_pages` of memory:
/// an eighth of it, and three quarters of that.
pub fn thresholds(physical_pages: u64) -> (u64, u64) {
    let threshold = physical_pages >> 3;
    (threshold, threshold / 2 + threshold / 4)
}

/// What a pass looks at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scan {
    /// Dirty pages in the cache.
    pub dirty: u64,
    /// Pages writers are throttled for (the third statistic Windows
    /// reads, added to the dirty ones against the threshold).
    pub pending: u64,
    pub threshold: u64,
    pub target: u64,
    /// Memory is short.
    pub low_memory: bool,
    /// The pass writes everything: a flush of the whole cache, as at
    /// shutdown, or a teardown waiting for it.
    pub everything: bool,
}

/// `CcCalculatePagesToWrite`: an eighth of the dirty pages once there
/// are more than [`MAX_LAZY_WRITE_PAGES`], else all of them; plus what
/// would be left above the target, counting what passes the threshold,
/// three times that when memory is short; never more than are dirty.
pub fn pages_to_write(s: &Scan) -> u64 {
    if s.everything {
        return s.dirty;
    }
    let mut write = if s.dirty > MAX_LAZY_WRITE_PAGES {
        s.dirty / 8
    } else {
        s.dirty
    };
    let over_threshold = (s.pending + s.dirty).saturating_sub(s.threshold);
    let left = s.dirty - write + over_threshold;
    if left > s.target {
        write += left - s.target;
        if s.low_memory {
            write += 2 * (left - s.target);
        }
    }
    write.min(s.dirty)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(dirty: u64) -> Scan {
        let (threshold, target) = thresholds(0x40000); // 1 GiB
        Scan {
            dirty,
            pending: 0,
            threshold,
            target,
            low_memory: false,
            everything: false,
        }
    }

    #[test]
    fn thresholds_of_memory() {
        assert_eq!(thresholds(0x40000), (0x8000, 0x6000));
    }

    #[test]
    fn few_dirty_pages_are_all_written() {
        assert_eq!(pages_to_write(&scan(0)), 0);
        assert_eq!(pages_to_write(&scan(256)), 256);
    }

    #[test]
    fn many_dirty_pages_an_eighth_at_a_time() {
        assert_eq!(pages_to_write(&scan(257)), 32);
        assert_eq!(pages_to_write(&scan(0x4000)), 0x800);
    }

    #[test]
    fn above_the_target_more_is_written() {
        // 0x7000 dirty: an eighth is 0xE00, leaving 0x6200, 0x200 over
        // the target.
        assert_eq!(pages_to_write(&scan(0x7000)), 0xE00 + 0x200);
        // Past the threshold, the excess counts too.
        assert_eq!(
            pages_to_write(&scan(0x9000)),
            0x1200 + (0x9000 - 0x1200 + 0x1000 - 0x6000)
        );
        let short = Scan {
            low_memory: true,
            ..scan(0x7000)
        };
        assert_eq!(pages_to_write(&short), 0xE00 + 3 * 0x200);
        let pending = Scan {
            pending: 0x2000,
            ..scan(0x7000)
        };
        assert_eq!(pages_to_write(&pending), 0xE00 + (0x6200 + 0x1000 - 0x6000));
    }

    #[test]
    fn never_more_than_dirty_and_everything_when_asked() {
        let short = Scan {
            low_memory: true,
            pending: 0x100000,
            ..scan(0x300)
        };
        assert_eq!(pages_to_write(&short), 0x300);
        assert_eq!(
            pages_to_write(&Scan {
                everything: true,
                ..scan(0x4000)
            }),
            0x4000
        );
    }
}
