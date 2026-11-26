//! [Run-down protection](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/run-down-protection)
//! (`EX_RUNDOWN_REF`): one word of the driver's memory that counts the
//! threads using an object and lets its owner wait for them to finish.
//!
//! The word, as Windows keeps it: bit 0 says the object is being run
//! down, after which nobody new gets in; until then the rest counts the
//! holders, two to a holder. A thread that runs the object down while
//! it has holders puts in the word the address of a block of its own,
//! with bit 0 set, in which the holders left are counted and on which
//! it sleeps; each release then counts down in that block and the last
//! one wakes the sleeper.
//!
//! The cache-aware kind is an array of such words, one a processor,
//! each on a cache line of its own, behind a header
//! (`EX_RUNDOWN_REF_CACHE_AWARE`). A thread takes and gives back on the
//! word of the processor it is running on at that moment, which need
//! not be the same one: a word's count may go below zero, and only the
//! sum over the words means anything. Read from the kernel NK follows
//! (10.0.19041): how much memory the kind takes and how a caller's
//! buffer is laid out.

/// Bit 0 of the word: the object is being run down.
pub const ACTIVE: usize = 1;
/// What one holder adds to the word.
pub const HOLD: usize = 2;

/// `ExAcquireRundownProtection`: the word with one more holder; `None`
/// if the object is being run down, when the routine returns `FALSE`.
pub fn acquire(word: usize) -> Option<usize> {
    (word & ACTIVE == 0).then(|| word.wrapping_add(HOLD))
}

/// What a release does to a word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Release {
    /// Store this: one holder fewer.
    Store(usize),
    /// The object is being run down: count one holder off in the block
    /// at this address, and wake its owner if that was the last.
    CountDown(usize),
    /// The object has been run down and nobody waits: there is no hold
    /// to give back.
    NotHeld,
}

/// `ExReleaseRundownProtection`.
pub fn release(word: usize) -> Release {
    if word & ACTIVE == 0 {
        Release::Store(word.wrapping_sub(HOLD))
    } else if word == ACTIVE {
        Release::NotHeld
    } else {
        Release::CountDown(word & !ACTIVE)
    }
}

/// The holders a word counts, when it is not being run down. A word of
/// the cache-aware kind may count fewer than none.
pub fn holders(word: usize) -> isize {
    (word as isize) >> 1
}

/// The word of an object being run down by the owner of the block at
/// `block`, whose address is even.
pub fn waited_for(block: usize) -> usize {
    block | ACTIVE
}

/// Bytes of the header of the cache-aware kind
/// (`EX_RUNDOWN_REF_CACHE_AWARE`).
pub const CACHE_AWARE_HEADER: usize = 0x18;

/// `ExSizeOfRundownProtectionCacheAware`: the bytes a caller sets aside
/// for the cache-aware kind on a system of `processors` processors
/// whose cache lines are `line` bytes: the header and a line for each
/// processor, and one more so that the lines can start on a boundary.
/// One processor needs no line to itself.
pub fn cache_aware_size(processors: u32, line: u32) -> usize {
    let words = if processors <= 1 {
        size_of::<usize>()
    } else {
        line as usize * (processors as usize + 1)
    };
    CACHE_AWARE_HEADER + words
}

/// How the words of the cache-aware kind lie.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Words {
    /// Where the first word is.
    pub first: usize,
    /// Bytes from one word to the next.
    pub stride: u32,
    /// How many words.
    pub number: u32,
}

/// `ExInitializeRundownProtectionCacheAware`: where the words lie in a
/// caller's buffer of `size` bytes at `buffer`, which is as
/// [`cache_aware_size`] said.
pub fn cache_aware_words(buffer: usize, size: usize, line: u32) -> Words {
    let first = buffer + CACHE_AWARE_HEADER;
    let room = size - CACHE_AWARE_HEADER;
    if room == size_of::<usize>() {
        return Words {
            first,
            stride: size_of::<usize>() as u32,
            number: 1,
        };
    }
    Words {
        first: first.next_multiple_of(line as usize),
        stride: line,
        number: (room / line as usize - 1) as u32,
    }
}

/// The index of the word a thread on processor `processor` uses.
pub fn word_of(processor: u32, number: u32) -> u32 {
    processor % number
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn holders_come_and_go_two_to_the_word() {
        assert_eq!(acquire(0), Some(2));
        assert_eq!(acquire(2), Some(4));
        assert_eq!(release(4), Release::Store(2));
        assert_eq!(release(2), Release::Store(0));
        assert_eq!(holders(0), 0);
        assert_eq!(holders(2), 1);
        assert_eq!(holders(6), 3);
    }

    #[test]
    fn nobody_gets_in_once_run_down_has_begun() {
        assert_eq!(acquire(ACTIVE), None);
        assert_eq!(acquire(waited_for(0x1000)), None);
        assert_eq!(release(ACTIVE), Release::NotHeld);
        assert_eq!(release(waited_for(0x1000)), Release::CountDown(0x1000));
        assert_eq!(
            release(waited_for(0xFFFF_8000_1234_5670)),
            Release::CountDown(0xFFFF_8000_1234_5670)
        );
    }

    #[test]
    fn a_processors_word_may_count_below_none() {
        // Taken on one processor, given back on another.
        let (taken, given) = (acquire(0).unwrap(), release(0));
        assert_eq!(given, Release::Store(usize::MAX - 1));
        let Release::Store(given) = given else {
            unreachable!()
        };
        assert_eq!(holders(given), -1);
        assert_eq!(holders(taken) + holders(given), 0);
        // And it still lets holders in.
        assert_eq!(acquire(given), Some(0));
    }

    #[test]
    fn the_cache_aware_kind_takes_a_line_a_processor_and_one_to_spare() {
        assert_eq!(cache_aware_size(1, 64), 0x18 + 8);
        assert_eq!(cache_aware_size(0, 64), 0x18 + 8);
        assert_eq!(cache_aware_size(2, 64), 0x18 + 3 * 64);
        assert_eq!(cache_aware_size(8, 64), 0x18 + 9 * 64);
        assert_eq!(cache_aware_size(4, 128), 0x18 + 5 * 128);
    }

    #[test]
    fn a_callers_buffer_holds_the_words_on_cache_lines() {
        // One processor: the word follows the header.
        let one = cache_aware_words(0x1000, cache_aware_size(1, 64), 64);
        assert_eq!(
            one,
            Words {
                first: 0x1018,
                stride: 8,
                number: 1
            }
        );
        for (buffer, processors) in [(0x1000, 2), (0x1008, 4), (0x1028, 4), (0x1FE8, 64)] {
            let size = cache_aware_size(processors, 64);
            let words = cache_aware_words(buffer, size, 64);
            assert_eq!((words.stride, words.number), (64, processors));
            assert_eq!(words.first % 64, 0);
            assert!(words.first >= buffer + CACHE_AWARE_HEADER);
            // The last word ends inside the buffer.
            let end = words.first + (words.number as usize - 1) * 64 + size_of::<usize>();
            assert!(end <= buffer + size, "{buffer:#x} {processors}");
        }
    }

    #[test]
    fn a_processor_uses_its_own_word() {
        assert_eq!(word_of(0, 4), 0);
        assert_eq!(word_of(3, 4), 3);
        assert_eq!(word_of(5, 4), 1);
        assert_eq!(word_of(7, 1), 0);
    }
}
