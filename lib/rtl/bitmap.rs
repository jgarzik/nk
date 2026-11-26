//! Bitmaps: the rules of the
//! [`RTL_BITMAP`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitializebitmap)
//! routines. Bit `n` is bit `n % 32` of the `n / 32`th `ULONG` of the
//! buffer, which on a little-endian machine is bit `n % 8` of byte
//! `n / 8`.
//!
//! # How a bitmap is given
//!
//! The buffer is the caller's memory, and in the kernel a driver's, so
//! it is reached through [`Bits`], a byte or a word at a time, and never
//! as a slice. The routines that change a run of bits write the bytes
//! that hold the run and no others, as Windows does: a caller may guard
//! two parts of one bitmap with two locks.
//!
//! # Where Microsoft's documentation stops
//!
//! Read from the kernel NK follows (10.0.19041):
//!
//! - `RtlFindSetBits` starts at the hint itself, not at its byte; a hint
//!   at or past the size is zero; a search that fails above the hint
//!   goes on from bit zero, among the runs that end before
//!   `hint + count`; and a search for no bits answers the hint with its
//!   low three bits cleared.
//! - `RtlAreBitsClear` is false for a run of no bits and for one that
//!   does not lie within the bitmap.
//! - `RtlFindNextForwardRunClear` and `RtlFindLastBackwardRunClear`
//!   store the index they were given when it is at or past the size.
//!   With no clear bit to find, the first stores the size and the second
//!   stores zero. All of them return a length of zero then.
//! - `RtlCopyBitMap` copies as many bits as the source has and the
//!   target has room for after the target bit.
//! - `RtlInterlockedSetClearRun` takes a run only if every bit of it is
//!   clear, and gives back the part it took when it meets a set bit.
//!
//! INFERRED: of several clear runs of the greatest length,
//! `RtlFindLongestRunClear` answers the first.

/// A bitmap's buffer, where it lies.
pub trait Bits {
    /// Byte `index` of the buffer.
    fn byte(&self, index: usize) -> u8;

    fn set_byte(&mut self, index: usize, value: u8);

    /// The `index`th `ULONG` of the buffer.
    fn word(&self, index: usize) -> u32 {
        let at = index * 4;
        u32::from_le_bytes([
            self.byte(at),
            self.byte(at + 1),
            self.byte(at + 2),
            self.byte(at + 3),
        ])
    }
}

impl Bits for [u8] {
    fn byte(&self, index: usize) -> u8 {
        self[index]
    }

    fn set_byte(&mut self, index: usize, value: u8) {
        self[index] = value;
    }
}

/// How many bytes the whole-bitmap routines write for a bitmap of `size`
/// bits: its `ULONG`s, the last one whole.
pub fn bytes(size: u32) -> usize {
    (size as usize).div_ceil(32) * 4
}

/// `RtlSetAllBits`, `RtlClearAllBits`: every `ULONG` of the bitmap, the
/// bits past the size in the last one included.
pub fn fill<B: Bits + ?Sized>(bits: &mut B, size: u32, value: bool) {
    for at in 0..bytes(size) {
        bits.set_byte(at, if value { 0xFF } else { 0 });
    }
}

/// `RtlTestBit`. The index is not held to the bitmap's size.
pub fn test<B: Bits + ?Sized>(bits: &B, index: u32) -> bool {
    bits.byte((index / 8) as usize) >> (index % 8) & 1 != 0
}

/// `RtlSetBits`, `RtlClearBits`, and with a count of one `RtlSetBit` and
/// `RtlClearBit`: make `count` bits from `start` equal `value`. The run
/// is not held to the bitmap's size.
pub fn set_run<B: Bits + ?Sized>(bits: &mut B, start: u32, count: u32, value: bool) {
    let (mut at, end) = (u64::from(start), u64::from(start) + u64::from(count));
    while at < end {
        // The part of the run in this byte.
        let low = (at % 8) as u32;
        let width = (8 - low).min((end - at) as u32);
        let mask = (((1u32 << width) - 1) << low) as u8;
        let index = (at / 8) as usize;
        let byte = if mask == 0xFF { 0 } else { bits.byte(index) };
        bits.set_byte(index, if value { byte | mask } else { byte & !mask });
        at += u64::from(width);
    }
}

/// The first index in `from..end` whose bit is `value`, or `end`.
fn next<B: Bits + ?Sized>(bits: &B, from: u64, end: u64, value: bool) -> u64 {
    let mut at = from;
    while at < end {
        let word = bits.word((at / 32) as usize);
        let matching = (if value { word } else { !word }) >> (at % 32);
        if matching != 0 {
            return (at + u64::from(matching.trailing_zeros())).min(end);
        }
        at = (at / 32 + 1) * 32;
    }
    end
}

/// The last index at or below `from` whose bit is `value`.
fn previous<B: Bits + ?Sized>(bits: &B, from: u32, value: bool) -> Option<u32> {
    let mut at = from;
    loop {
        let word = bits.word((at / 32) as usize);
        let matching = (if value { word } else { !word }) << (31 - at % 32);
        if matching != 0 {
            return Some(at - matching.leading_zeros());
        }
        // The last bit of the word before, if there is one.
        at = (at / 32 * 32).checked_sub(1)?;
    }
}

/// `RtlAreBitsClear`.
pub fn are_clear<B: Bits + ?Sized>(bits: &B, size: u32, start: u32, length: u32) -> bool {
    if start >= size || length == 0 || size - start < length {
        return false;
    }
    let end = u64::from(start) + u64::from(length);
    next(bits, u64::from(start), end, true) == end
}

/// The first run of `count` set bits that lies in `from..end`.
fn set_run_in<B: Bits + ?Sized>(bits: &B, from: u64, end: u64, count: u32) -> Option<u32> {
    let count = u64::from(count);
    let mut at = from;
    loop {
        let start = next(bits, at, end, true);
        if end - start < count {
            return None;
        }
        at = next(bits, start, start + count, false);
        if at - start == count {
            return Some(start as u32);
        }
    }
}

/// `RtlFindSetBits`: where a run of `count` set bits starts, `None` for
/// the routine's 0xFFFFFFFF.
pub fn find_set<B: Bits + ?Sized>(bits: &B, size: u32, count: u32, hint: u32) -> Option<u32> {
    let hint = if hint < size { hint } else { 0 };
    if count == 0 {
        return Some(hint & !7);
    }
    let size_wide = u64::from(size);
    set_run_in(bits, u64::from(hint), size_wide, count).or_else(|| {
        if hint == 0 {
            return None;
        }
        // Windows adds the two as 32-bit numbers.
        let end = u64::from(hint.wrapping_add(count)).min(size_wide);
        set_run_in(bits, 0, end, count)
    })
}

/// `RtlFindNextForwardRunClear`: the start and length of the first clear
/// run at or after `from`.
pub fn next_clear_run<B: Bits + ?Sized>(bits: &B, size: u32, from: u32) -> (u32, u32) {
    if from >= size {
        return (from, 0);
    }
    let size = u64::from(size);
    let start = next(bits, u64::from(from), size, false);
    let end = next(bits, start, size, true);
    (start as u32, (end - start) as u32)
}

/// `RtlFindLastBackwardRunClear`: the start and length of the clear run
/// that ends at the last clear bit at or before `from`.
pub fn last_clear_run<B: Bits + ?Sized>(bits: &B, size: u32, from: u32) -> (u32, u32) {
    if from >= size {
        return (from, 0);
    }
    let Some(last) = previous(bits, from, false) else {
        return (0, 0);
    };
    let start = previous(bits, last, true).map_or(0, |set| set + 1);
    (start, last - start + 1)
}

/// `RtlFindLongestRunClear`: the start and length of the longest clear
/// run, `(0, 0)` if no bit is clear.
pub fn longest_clear_run<B: Bits + ?Sized>(bits: &B, size: u32) -> (u32, u32) {
    let mut longest = (0, 0);
    let mut from = 0;
    while from < size {
        let (start, length) = next_clear_run(bits, size, from);
        if length > longest.1 {
            longest = (start, length);
        }
        if length == 0 {
            break;
        }
        // The run is within the bitmap, so the sum is at most its size.
        from = start + length;
    }
    longest
}

/// `RtlNumberOfSetBits`, from which `RtlNumberOfClearBits` follows: the
/// set bits below `size`.
pub fn count_set<B: Bits + ?Sized>(bits: &B, size: u32) -> u32 {
    let whole = (size / 32) as usize;
    let mut count: u32 = (0..whole).map(|at| bits.word(at).count_ones()).sum();
    if size % 32 != 0 {
        count += (bits.word(whole) & ((1 << (size % 32)) - 1)).count_ones();
    }
    count
}

/// How many bits `RtlCopyBitMap` copies from a bitmap of `source` bits
/// to bit `target` of one of `destination` bits. Windows subtracts as
/// 32-bit numbers: a target past the destination's end does not stop
/// the copy.
pub fn copy_count(source: u32, destination: u32, target: u32) -> u32 {
    source.min(destination.wrapping_sub(target))
}

/// The `width` (at most 8) bits at `at`.
fn extract<B: Bits + ?Sized>(bits: &B, at: u64, width: u32) -> u8 {
    let (index, low) = ((at / 8) as usize, (at % 8) as u32);
    let mut value = u32::from(bits.byte(index)) >> low;
    if low + width > 8 {
        value |= u32::from(bits.byte(index + 1)) << (8 - low);
    }
    (value & ((1 << width) - 1)) as u8
}

/// `RtlCopyBitMap`: copy `count` bits from the start of `source` to
/// `target` in `destination`, a byte of the destination at a time.
/// `backward` copies the last bits first, which is the order to use
/// when the two are one buffer and the bits move up.
pub fn copy<S: Bits + ?Sized, D: Bits + ?Sized>(
    source: &S,
    destination: &mut D,
    target: u32,
    count: u32,
    backward: bool,
) {
    let (first, end) = (u64::from(target), u64::from(target) + u64::from(count));
    // The part of the run in one byte of the destination.
    let mut piece = |from: u64, to: u64| {
        let (index, low, width) = ((from / 8) as usize, (from % 8) as u32, (to - from) as u32);
        let mask = (((1u32 << width) - 1) << low) as u8;
        let value = extract(source, from - first, width) << low;
        let byte = if mask == 0xFF {
            0
        } else {
            destination.byte(index)
        };
        destination.set_byte(index, byte & !mask | value);
    };
    if backward {
        let mut to = end;
        while to > first {
            let from = ((to - 1) / 8 * 8).max(first);
            piece(from, to);
            to = from;
        }
    } else {
        let mut from = first;
        while from < end {
            let to = ((from / 8 + 1) * 8).min(end);
            piece(from, to);
            from = to;
        }
    }
}

/// `RtlFindLeastSignificantBit`: the index of the lowest set bit, -1 for
/// zero.
pub fn least_significant(value: u64) -> i8 {
    if value == 0 {
        -1
    } else {
        value.trailing_zeros() as i8
    }
}

/// `RtlFindMostSignificantBit`: the index of the highest set bit, -1 for
/// zero.
pub fn most_significant(value: u64) -> i8 {
    if value == 0 {
        -1
    } else {
        63 - value.leading_zeros() as i8
    }
}

/// The parts of a run of `count` bits from `start`, `ULONG` by `ULONG`:
/// the index of each and the run's bits in it. The interlocked routines
/// change one `ULONG` at a time.
pub fn words(start: u32, count: u32) -> impl Iterator<Item = (usize, u32)> {
    let end = u64::from(start) + u64::from(count);
    let mut at = u64::from(start);
    core::iter::from_fn(move || {
        if at >= end {
            return None;
        }
        let low = (at % 32) as u32;
        let width = u64::from(32 - low).min(end - at) as u32;
        let mask = (u32::MAX >> (32 - width)) << low;
        let index = (at / 32) as usize;
        at += u64::from(width);
        Some((index, mask))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bitmap of `size` bits and the same bits one by one.
    struct Model {
        size: u32,
        bytes: Vec<u8>,
        bits: Vec<bool>,
    }

    /// A sequence of numbers that is the same on every run.
    struct Random(u64);

    impl Random {
        fn next(&mut self) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as u32
        }
    }

    impl Model {
        /// Runs of set and clear bits of random lengths.
        fn random(size: u32, random: &mut Random) -> Self {
            let mut model = Self {
                size,
                // Room past the last `ULONG`, which must stay untouched.
                bytes: vec![0; bytes(size) + 4],
                bits: vec![false; size as usize],
            };
            let (mut at, mut value) = (0, random.next() % 2 == 0);
            while at < size {
                let length = (random.next() % 70 + 1).min(size - at);
                set_run(&mut model.bytes[..], at, length, value);
                for bit in at..at + length {
                    model.bits[bit as usize] = value;
                }
                at += length;
                value = !value;
            }
            // Bits past the size are set: no routine may count them.
            let whole = bytes(size) as u32 * 8;
            set_run(&mut model.bytes[..], size, whole - size, true);
            model
        }

        fn run_from(&self, from: u32, value: bool) -> u32 {
            self.bits[from as usize..]
                .iter()
                .take_while(|&&bit| bit == value)
                .count() as u32
        }
    }

    fn of(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    #[test]
    fn a_bit_is_in_the_ulong_and_the_byte_of_its_index() {
        let mut map = of(&[0, 0]);
        set_run(&mut map[..], 33, 1, true);
        assert_eq!(map, of(&[0, 2]));
        assert_eq!(map[4], 2);
        assert!(test(&map[..], 33));
        assert!(!test(&map[..], 32));
        assert!(!test(&map[..], 34));
        assert_eq!(map[..].word(1), 2);
    }

    #[test]
    fn filling_writes_whole_ulongs_and_nothing_after() {
        let mut map = [0x55u8; 12];
        fill(&mut map[..], 33, true);
        assert_eq!(map[..8], [0xFF; 8]);
        assert_eq!(map[8..], [0x55; 4]);
        fill(&mut map[..], 32, false);
        assert_eq!(map[..4], [0; 4]);
        assert_eq!(map[4..8], [0xFF; 4]);
        fill(&mut map[..], 0, false);
        assert_eq!(map[4..8], [0xFF; 4]);
        assert_eq!((bytes(0), bytes(1), bytes(32), bytes(33)), (0, 4, 4, 8));
    }

    #[test]
    fn a_run_changes_its_bits_and_only_the_bytes_that_hold_them() {
        /// Fails the test if a byte outside the run's is read or
        /// written.
        struct Fenced {
            bytes: Vec<u8>,
            low: usize,
            high: usize,
        }
        impl Bits for Fenced {
            fn byte(&self, index: usize) -> u8 {
                assert!((self.low..=self.high).contains(&index));
                self.bytes[index]
            }
            fn set_byte(&mut self, index: usize, value: u8) {
                assert!((self.low..=self.high).contains(&index));
                self.bytes[index] = value;
            }
        }
        for start in 0..40u32 {
            for count in 0..40u32 {
                for value in [false, true] {
                    let before = if value { 0 } else { 0xFF };
                    let mut map = Fenced {
                        bytes: vec![before; 12],
                        low: (start / 8) as usize,
                        high: ((start + count).max(1) - 1) as usize / 8,
                    };
                    if count == 0 {
                        // Nothing at all is touched.
                        map.low = usize::MAX;
                    }
                    set_run(&mut map, start, count, value);
                    for bit in 0..96 {
                        let inside = (start..start + count).contains(&bit);
                        assert_eq!(test(&map.bytes[..], bit), inside == value);
                    }
                }
            }
        }
    }

    #[test]
    fn bits_are_clear_only_for_a_real_run_inside_the_bitmap() {
        let map = of(&[0x0000_0100, 0, 0x8000_0000]);
        let clear = |start, length| are_clear(&map[..], 95, start, length);
        assert!(clear(0, 8));
        assert!(!clear(0, 9));
        assert!(clear(9, 86));
        assert!(clear(9, 1));
        assert!(!clear(8, 1));
        // No bits, a start at the end, a run past the end.
        assert!(!clear(0, 0));
        assert!(!clear(95, 1));
        assert!(!clear(9, 87));
        assert!(!clear(9, u32::MAX));
        assert!(!clear(u32::MAX, 2));
        // Bit 95 is past the size: it is not looked at.
        assert!(clear(94, 1));
    }

    #[test]
    fn find_set_starts_at_the_hint_and_wraps_to_what_ends_before_it() {
        // Set: 4..8, 16..19, 40..50.
        let mut map = of(&[0, 0, 0]);
        for (start, count) in [(4, 4), (16, 3), (40, 10)] {
            set_run(&mut map[..], start, count, true);
        }
        let find = |count, hint| find_set(&map[..], 80, count, hint);
        assert_eq!(find(1, 0), Some(4));
        assert_eq!(find(4, 0), Some(4));
        assert_eq!(find(5, 0), Some(40));
        assert_eq!(find(10, 0), Some(40));
        assert_eq!(find(11, 0), None);
        // The hint is a bit, not a byte: a run may start in mid-byte.
        assert_eq!(find(2, 5), Some(5));
        assert_eq!(find(3, 5), Some(5));
        assert_eq!(find(4, 5), Some(40));
        assert_eq!(find(3, 17), Some(40));
        assert_eq!(find(2, 17), Some(17));
        // Nothing above the hint: from zero, runs that end before
        // `hint + count`.
        assert_eq!(find(4, 47), Some(4));
        assert_eq!(find(3, 48), Some(4));
        assert_eq!(find(10, 41), Some(40));
        assert_eq!(find(10, 45), Some(40));
        assert_eq!(find(1, 60), Some(4));
        assert_eq!(find(11, 45), None);
        // A hint at or past the size is zero.
        assert_eq!(find(3, 80), Some(4));
        assert_eq!(find(3, u32::MAX), Some(4));
        // No bits: the hint's byte.
        assert_eq!(find(0, 0), Some(0));
        assert_eq!(find(0, 13), Some(8));
        assert_eq!(find(0, 79), Some(72));
        assert_eq!(find(0, 80), Some(0));
        assert_eq!(find(81, 0), None);
        assert_eq!(find(u32::MAX, 5), None);
        assert_eq!(find_set(&map[..], 0, 1, 0), None);
        assert_eq!(find_set(&map[..], 0, 0, 0), Some(0));
        // A run cut by the size does not count.
        assert_eq!(find_set(&map[..], 45, 6, 0), None);
        assert_eq!(find_set(&map[..], 45, 5, 0), Some(40));
    }

    #[test]
    fn find_set_agrees_with_a_search_bit_by_bit() {
        let mut random = Random(1);
        for size in [1, 7, 31, 32, 33, 64, 65, 200, 257] {
            for _ in 0..40 {
                let model = Model::random(size, &mut random);
                for _ in 0..60 {
                    let count = random.next() % 40 + 1;
                    let hint = random.next() % (size + 2);
                    let start = if hint < size { hint } else { 0 };
                    let fits = |from: u32, end: u32| {
                        (from..end).find(|&at| {
                            end - at >= count && model.run_from(at, true) >= count.min(end - at)
                        })
                    };
                    let expected = fits(start, size).or_else(|| {
                        (start != 0)
                            .then(|| fits(0, (start + count).min(size)))
                            .flatten()
                    });
                    assert_eq!(
                        find_set(&model.bytes[..], size, count, hint),
                        expected,
                        "size {size} count {count} hint {hint}"
                    );
                }
            }
        }
    }

    #[test]
    fn clear_runs_agree_with_a_search_bit_by_bit() {
        let mut random = Random(2);
        for size in [1, 5, 31, 32, 33, 63, 64, 65, 130, 300] {
            for _ in 0..40 {
                let model = Model::random(size, &mut random);
                let map = &model.bytes[..];
                let mut longest = (0, 0);
                for from in 0..size {
                    // Forward.
                    let start = (from..size)
                        .find(|&at| !model.bits[at as usize])
                        .unwrap_or(size);
                    let length = if start < size {
                        model.run_from(start, false)
                    } else {
                        0
                    };
                    assert_eq!(next_clear_run(map, size, from), (start, length));
                    if length > longest.1 {
                        longest = (start, length);
                    }
                    // Backward.
                    let expected = match (0..=from).rev().find(|&at| !model.bits[at as usize]) {
                        None => (0, 0),
                        Some(last) => {
                            let start = (0..=last)
                                .rev()
                                .find(|&at| model.bits[at as usize])
                                .map_or(0, |set| set + 1);
                            (start, last - start + 1)
                        }
                    };
                    assert_eq!(last_clear_run(map, size, from), expected);
                }
                assert_eq!(longest_clear_run(map, size), longest);
                let set = model.bits.iter().filter(|&&bit| bit).count() as u32;
                assert_eq!(count_set(map, size), set);
            }
        }
    }

    #[test]
    fn a_run_search_from_outside_the_bitmap_answers_the_index_given() {
        let map = of(&[0, 0]);
        assert_eq!(next_clear_run(&map[..], 40, 40), (40, 0));
        assert_eq!(next_clear_run(&map[..], 40, 99), (99, 0));
        assert_eq!(last_clear_run(&map[..], 40, 40), (40, 0));
        assert_eq!(last_clear_run(&map[..], 40, u32::MAX), (u32::MAX, 0));
        assert_eq!(next_clear_run(&map[..], 0, 0), (0, 0));
        assert_eq!(longest_clear_run(&map[..], 0), (0, 0));
        assert_eq!(longest_clear_run(&map[..], 40), (0, 40));
        assert_eq!(count_set(&map[..], 0), 0);
    }

    #[test]
    fn a_bitmap_with_no_clear_bit_has_no_clear_run() {
        let map = of(&[u32::MAX, u32::MAX]);
        assert_eq!(next_clear_run(&map[..], 40, 3), (40, 0));
        assert_eq!(last_clear_run(&map[..], 40, 39), (0, 0));
        assert_eq!(longest_clear_run(&map[..], 40), (0, 0));
        assert_eq!(count_set(&map[..], 40), 40);
        assert_eq!(count_set(&map[..], 64), 64);
    }

    #[test]
    fn the_longest_run_is_the_first_of_its_length() {
        // Clear: 2..5, 10..13, 20..22.
        let mut map = of(&[u32::MAX]);
        for start in [2, 10] {
            set_run(&mut map[..], start, 3, false);
        }
        set_run(&mut map[..], 20, 2, false);
        assert_eq!(longest_clear_run(&map[..], 32), (2, 3));
        set_run(&mut map[..], 13, 1, false);
        assert_eq!(longest_clear_run(&map[..], 32), (10, 4));
    }

    #[test]
    fn copying_moves_the_bits_that_fit() {
        assert_eq!(copy_count(10, 40, 0), 10);
        assert_eq!(copy_count(10, 40, 35), 5);
        assert_eq!(copy_count(10, 40, 40), 0);
        // Past the end the subtraction wraps.
        assert_eq!(copy_count(10, 40, 41), 10);
        let mut random = Random(3);
        for _ in 0..300 {
            let size = random.next() % 90 + 1;
            let source = Model::random(size, &mut random);
            let target = random.next() % 50;
            let count = random.next() % (size + 1);
            for backward in [false, true] {
                let before = Model::random(160, &mut random);
                let mut after = before.bytes.clone();
                copy(&source.bytes[..], &mut after[..], target, count, backward);
                for bit in 0..before.size {
                    let expected = if (target..target + count).contains(&bit) {
                        source.bits[(bit - target) as usize]
                    } else {
                        before.bits[bit as usize]
                    };
                    assert_eq!(test(&after[..], bit), expected);
                }
            }
        }
    }

    #[test]
    fn copying_within_one_buffer_keeps_the_bits_in_the_right_order() {
        /// A bitmap that is its own source: reads see earlier writes.
        struct Shared<'a>(&'a core::cell::RefCell<Vec<u8>>);
        impl Bits for Shared<'_> {
            fn byte(&self, index: usize) -> u8 {
                self.0.borrow()[index]
            }
            fn set_byte(&mut self, index: usize, value: u8) {
                self.0.borrow_mut()[index] = value;
            }
        }
        let mut random = Random(4);
        for _ in 0..200 {
            let model = Model::random(120, &mut random);
            let target = random.next() % 40 + 1;
            let count = random.next() % 80;
            let bytes = core::cell::RefCell::new(model.bytes.clone());
            // The bits move up, so the last go first.
            copy(&Shared(&bytes), &mut Shared(&bytes), target, count, true);
            let bytes = bytes.into_inner();
            for bit in target..target + count {
                assert_eq!(test(&bytes[..], bit), model.bits[(bit - target) as usize]);
            }
        }
    }

    #[test]
    fn the_lowest_and_highest_set_bits() {
        assert_eq!(least_significant(0), -1);
        assert_eq!(most_significant(0), -1);
        assert_eq!(least_significant(1), 0);
        assert_eq!(most_significant(1), 0);
        assert_eq!(least_significant(0x8000_0000_0000_0000), 63);
        assert_eq!(most_significant(0x8000_0000_0000_0000), 63);
        assert_eq!(least_significant(0x0000_0100_0001_0000), 16);
        assert_eq!(most_significant(0x0000_0100_0001_0000), 40);
        assert_eq!(most_significant(u64::MAX), 63);
    }

    #[test]
    fn a_run_is_split_at_ulong_boundaries() {
        let parts = |start, count| words(start, count).collect::<Vec<_>>();
        assert_eq!(parts(0, 0), []);
        assert_eq!(parts(5, 0), []);
        assert_eq!(parts(0, 1), [(0, 1)]);
        assert_eq!(parts(31, 1), [(0, 0x8000_0000)]);
        assert_eq!(parts(0, 32), [(0, u32::MAX)]);
        assert_eq!(parts(4, 8), [(0, 0xFF0)]);
        assert_eq!(parts(28, 8), [(0, 0xF000_0000), (1, 0xF)]);
        assert_eq!(
            parts(40, 70),
            [(1, 0xFFFF_FF00), (2, u32::MAX), (3, 0x3FFF)]
        );
        assert_eq!(
            parts(u32::MAX, 2),
            [(0x7FF_FFFF, 0x8000_0000), (0x800_0000, 1)]
        );
        // Every bit of the run once, and no other.
        for start in 0..70 {
            for count in 0..70 {
                let mut map = [0u8; 20];
                for (index, mask) in words(start, count) {
                    for bit in 0..32 {
                        if mask >> bit & 1 != 0 {
                            let at = index as u32 * 32 + bit;
                            assert!(!test(&map[..], at));
                            set_run(&mut map[..], at, 1, true);
                        }
                    }
                }
                for bit in 0..160 {
                    assert_eq!(test(&map[..], bit), (start..start + count).contains(&bit));
                }
            }
        }
    }
}
