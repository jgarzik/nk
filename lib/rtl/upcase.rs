//! Upper-casing of UTF-16 units and the counted-string comparisons built
//! on it: the logic of
//! [`RtlUpcaseUnicodeChar`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodechar),
//! [`RtlUpcaseUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodestring),
//! [`RtlPrefixUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlprefixunicodestring),
//! [`RtlEqualUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlequalunicodestring)
//! and
//! [`RtlCompareUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcompareunicodestring).
//!
//! # The table
//!
//! [`RUNS`] is Windows' own table: what `RtlUpcaseUnicodeChar` answers
//! for each of the 65536 units on Windows 10 (10.0.19045), recorded
//! there by the conformance driver `nkc-rtl`, which returns the table
//! whole. 973 units have an upper case other than themselves. The runs
//! were generated from the recording by sorting the mapped units and
//! merging neighbours that share a distance to their upper case and
//! lie 1 or 2 apart. A unit with no entry, a surrogate among them, is
//! its own upper case.
//!
//! Every mapping is the simple upper-case mapping of the Unicode
//! Character Database, but the table is older than the database and
//! leaves alone some two hundred units the database maps: the
//! compatibility characters (the micro sign `00B5`, dotless i `0131`,
//! long s `017F`, final sigma `03C2`), the title-case digraphs
//! (`01C5`), the combining iota `0345`, and the letters of newer
//! Unicode versions (Georgian `10D0-10FF`, Cherokee `AB70-ABBF`,
//! `0525-052F` and others).

use core::cmp::Ordering;

/// One run of the table: the units `first`, `first + step`, ... up to
/// `last` have the upper case `unit + delta`, modulo 2^16.
type Run = (u16, u16, u16, u16);

/// The runs, ascending and disjoint.
const RUNS: [Run; 134] = [
    (0x0061, 0x007A, 1, 0xFFE0),
    (0x00E0, 0x00F6, 1, 0xFFE0),
    (0x00F8, 0x00FE, 1, 0xFFE0),
    (0x00FF, 0x00FF, 1, 0x0079),
    (0x0101, 0x012F, 2, 0xFFFF),
    (0x0133, 0x0137, 2, 0xFFFF),
    (0x013A, 0x0148, 2, 0xFFFF),
    (0x014B, 0x0177, 2, 0xFFFF),
    (0x017A, 0x017E, 2, 0xFFFF),
    (0x0180, 0x0180, 1, 0x00C3),
    (0x0183, 0x0185, 2, 0xFFFF),
    (0x0188, 0x0188, 1, 0xFFFF),
    (0x018C, 0x018C, 1, 0xFFFF),
    (0x0192, 0x0192, 1, 0xFFFF),
    (0x0195, 0x0195, 1, 0x0061),
    (0x0199, 0x0199, 1, 0xFFFF),
    (0x019A, 0x019A, 1, 0x00A3),
    (0x019E, 0x019E, 1, 0x0082),
    (0x01A1, 0x01A5, 2, 0xFFFF),
    (0x01A8, 0x01A8, 1, 0xFFFF),
    (0x01AD, 0x01AD, 1, 0xFFFF),
    (0x01B0, 0x01B0, 1, 0xFFFF),
    (0x01B4, 0x01B6, 2, 0xFFFF),
    (0x01B9, 0x01B9, 1, 0xFFFF),
    (0x01BD, 0x01BD, 1, 0xFFFF),
    (0x01BF, 0x01BF, 1, 0x0038),
    (0x01C6, 0x01C6, 1, 0xFFFE),
    (0x01C9, 0x01C9, 1, 0xFFFE),
    (0x01CC, 0x01CC, 1, 0xFFFE),
    (0x01CE, 0x01DC, 2, 0xFFFF),
    (0x01DD, 0x01DD, 1, 0xFFB1),
    (0x01DF, 0x01EF, 2, 0xFFFF),
    (0x01F3, 0x01F3, 1, 0xFFFE),
    (0x01F5, 0x01F5, 1, 0xFFFF),
    (0x01F9, 0x021F, 2, 0xFFFF),
    (0x0223, 0x0233, 2, 0xFFFF),
    (0x023C, 0x023C, 1, 0xFFFF),
    (0x0242, 0x0242, 1, 0xFFFF),
    (0x0247, 0x024F, 2, 0xFFFF),
    (0x0250, 0x0250, 1, 0x2A1F),
    (0x0251, 0x0251, 1, 0x2A1C),
    (0x0253, 0x0253, 1, 0xFF2E),
    (0x0254, 0x0254, 1, 0xFF32),
    (0x0256, 0x0257, 1, 0xFF33),
    (0x0259, 0x0259, 1, 0xFF36),
    (0x025B, 0x025B, 1, 0xFF35),
    (0x0260, 0x0260, 1, 0xFF33),
    (0x0263, 0x0263, 1, 0xFF31),
    (0x0268, 0x0268, 1, 0xFF2F),
    (0x0269, 0x0269, 1, 0xFF2D),
    (0x026B, 0x026B, 1, 0x29F7),
    (0x026F, 0x026F, 1, 0xFF2D),
    (0x0271, 0x0271, 1, 0x29FD),
    (0x0272, 0x0272, 1, 0xFF2B),
    (0x0275, 0x0275, 1, 0xFF2A),
    (0x027D, 0x027D, 1, 0x29E7),
    (0x0280, 0x0280, 1, 0xFF26),
    (0x0283, 0x0283, 1, 0xFF26),
    (0x0288, 0x0288, 1, 0xFF26),
    (0x0289, 0x0289, 1, 0xFFBB),
    (0x028A, 0x028B, 1, 0xFF27),
    (0x028C, 0x028C, 1, 0xFFB9),
    (0x0292, 0x0292, 1, 0xFF25),
    (0x0371, 0x0373, 2, 0xFFFF),
    (0x0377, 0x0377, 1, 0xFFFF),
    (0x037B, 0x037D, 1, 0x0082),
    (0x03AC, 0x03AC, 1, 0xFFDA),
    (0x03AD, 0x03AF, 1, 0xFFDB),
    (0x03B1, 0x03C1, 1, 0xFFE0),
    (0x03C3, 0x03CB, 1, 0xFFE0),
    (0x03CC, 0x03CC, 1, 0xFFC0),
    (0x03CD, 0x03CE, 1, 0xFFC1),
    (0x03D7, 0x03D7, 1, 0xFFF8),
    (0x03D9, 0x03EF, 2, 0xFFFF),
    (0x03F2, 0x03F2, 1, 0x0007),
    (0x03F8, 0x03F8, 1, 0xFFFF),
    (0x03FB, 0x03FB, 1, 0xFFFF),
    (0x0430, 0x044F, 1, 0xFFE0),
    (0x0450, 0x045F, 1, 0xFFB0),
    (0x0461, 0x0481, 2, 0xFFFF),
    (0x048B, 0x04BF, 2, 0xFFFF),
    (0x04C2, 0x04CE, 2, 0xFFFF),
    (0x04CF, 0x04CF, 1, 0xFFF1),
    (0x04D1, 0x0523, 2, 0xFFFF),
    (0x0561, 0x0586, 1, 0xFFD0),
    (0x1D79, 0x1D79, 1, 0x8A04),
    (0x1D7D, 0x1D7D, 1, 0x0EE6),
    (0x1E01, 0x1E95, 2, 0xFFFF),
    (0x1EA1, 0x1EFF, 2, 0xFFFF),
    (0x1F00, 0x1F07, 1, 0x0008),
    (0x1F10, 0x1F15, 1, 0x0008),
    (0x1F20, 0x1F27, 1, 0x0008),
    (0x1F30, 0x1F37, 1, 0x0008),
    (0x1F40, 0x1F45, 1, 0x0008),
    (0x1F51, 0x1F57, 2, 0x0008),
    (0x1F60, 0x1F67, 1, 0x0008),
    (0x1F70, 0x1F71, 1, 0x004A),
    (0x1F72, 0x1F75, 1, 0x0056),
    (0x1F76, 0x1F77, 1, 0x0064),
    (0x1F78, 0x1F79, 1, 0x0080),
    (0x1F7A, 0x1F7B, 1, 0x0070),
    (0x1F7C, 0x1F7D, 1, 0x007E),
    (0x1F80, 0x1F87, 1, 0x0008),
    (0x1F90, 0x1F97, 1, 0x0008),
    (0x1FA0, 0x1FA7, 1, 0x0008),
    (0x1FB0, 0x1FB1, 1, 0x0008),
    (0x1FB3, 0x1FB3, 1, 0x0009),
    (0x1FC3, 0x1FC3, 1, 0x0009),
    (0x1FD0, 0x1FD1, 1, 0x0008),
    (0x1FE0, 0x1FE1, 1, 0x0008),
    (0x1FE5, 0x1FE5, 1, 0x0007),
    (0x1FF3, 0x1FF3, 1, 0x0009),
    (0x214E, 0x214E, 1, 0xFFE4),
    (0x2170, 0x217F, 1, 0xFFF0),
    (0x2184, 0x2184, 1, 0xFFFF),
    (0x24D0, 0x24E9, 1, 0xFFE6),
    (0x2C30, 0x2C5E, 1, 0xFFD0),
    (0x2C61, 0x2C61, 1, 0xFFFF),
    (0x2C65, 0x2C65, 1, 0xD5D5),
    (0x2C66, 0x2C66, 1, 0xD5D8),
    (0x2C68, 0x2C6C, 2, 0xFFFF),
    (0x2C73, 0x2C73, 1, 0xFFFF),
    (0x2C76, 0x2C76, 1, 0xFFFF),
    (0x2C81, 0x2CE3, 2, 0xFFFF),
    (0x2D00, 0x2D25, 1, 0xE3A0),
    (0xA641, 0xA65F, 2, 0xFFFF),
    (0xA663, 0xA66D, 2, 0xFFFF),
    (0xA681, 0xA697, 2, 0xFFFF),
    (0xA723, 0xA72F, 2, 0xFFFF),
    (0xA733, 0xA76F, 2, 0xFFFF),
    (0xA77A, 0xA77C, 2, 0xFFFF),
    (0xA77F, 0xA787, 2, 0xFFFF),
    (0xA78C, 0xA78C, 1, 0xFFFF),
    (0xFF41, 0xFF5A, 1, 0xFFE0),
];

/// The upper case of one UTF-16 unit, as `RtlUpcaseUnicodeChar` gives
/// it: one unit for one unit.
pub fn upcase_char(c: u16) -> u16 {
    let at = RUNS.partition_point(|run| run.1 < c);
    match RUNS.get(at) {
        Some(&(first, _, step, delta)) if c >= first && (c - first) % step == 0 => {
            c.wrapping_add(delta)
        }
        _ => c,
    }
}

/// The `Length` `RtlUpcaseUnicodeString` stores in a destination it does
/// not allocate: the source's, every unit of which is upper-cased. None
/// if the destination's `MaximumLength` is too small, which is
/// `STATUS_BUFFER_OVERFLOW`. No terminator is written.
pub fn upcase_string_length(source_length: u16, destination_maximum: u16) -> Option<u16> {
    (source_length <= destination_maximum).then_some(source_length)
}

fn fold(c: u16, ignore_case: bool) -> u16 {
    if ignore_case { upcase_char(c) } else { c }
}

/// `RtlCompareUnicodeString`: negative, zero or positive as `a` sorts
/// before, with or after `b`. The units are compared in order, upper
/// case against upper case if `ignore_case`; if one string is the start
/// of the other, the shorter sorts first.
///
/// The value is the difference of the first two units that differ, or
/// of the lengths in bytes.
pub fn compare_unicode_string(a: &[u16], b: &[u16], ignore_case: bool) -> i32 {
    for (&x, &y) in a.iter().zip(b) {
        let (x, y) = (fold(x, ignore_case), fold(y, ignore_case));
        if x != y {
            return i32::from(x) - i32::from(y);
        }
    }
    // A counted string is under 2^16 bytes long.
    (a.len() as i32 - b.len() as i32) * 2
}

/// The same comparison as an [`Ordering`].
pub fn order_unicode_string(a: &[u16], b: &[u16], ignore_case: bool) -> Ordering {
    compare_unicode_string(a, b, ignore_case).cmp(&0)
}

/// `RtlEqualUnicodeString`.
pub fn equal_unicode_string(a: &[u16], b: &[u16], ignore_case: bool) -> bool {
    a.len() == b.len() && prefix_unicode_string(a, b, ignore_case)
}

/// `RtlPrefixUnicodeString`: whether `string` starts with `prefix`. A
/// string is a prefix of itself, and the empty string of every string.
pub fn prefix_unicode_string(prefix: &[u16], string: &[u16], ignore_case: bool) -> bool {
    prefix_units(prefix.iter().copied(), string.iter().copied(), ignore_case)
}

/// The same for strings given as their units in order, which are read
/// no further than the first two that differ.
pub fn prefix_units(
    prefix: impl ExactSizeIterator<Item = u16>,
    string: impl ExactSizeIterator<Item = u16>,
    ignore_case: bool,
) -> bool {
    prefix.len() <= string.len()
        && prefix
            .zip(string)
            .all(|(x, y)| fold(x, ignore_case) == fold(y, ignore_case))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    /// The upper case of a unit by a second route: the standard
    /// library's full upper-casing, kept where it is a single unit.
    fn by_the_standard_library(c: u16) -> u16 {
        let Some(ch) = char::from_u32(u32::from(c)) else {
            return c;
        };
        let mut upper = ch.to_uppercase();
        match (upper.next(), upper.next()) {
            (Some(u), None) => u16::try_from(u32::from(u)).unwrap_or(c),
            _ => c,
        }
    }

    /// Units whose simple upper case is one unit although their full
    /// upper case, which is what the standard library gives, is two.
    const IOTA_SUBSCRIPT: [(u16, u16); 6] = [
        (0x1F80, 0x1F87),
        (0x1F90, 0x1F97),
        (0x1FA0, 0x1FA7),
        (0x1FB3, 0x1FB3),
        (0x1FC3, 0x1FC3),
        (0x1FF3, 0x1FF3),
    ];

    #[test]
    fn every_mapping_is_one_the_standard_library_has() {
        let mut left_alone = 0;
        for c in 0..=u16::MAX {
            let (ours, theirs) = (upcase_char(c), by_the_standard_library(c));
            if IOTA_SUBSCRIPT.iter().any(|&(a, b)| (a..=b).contains(&c)) {
                // The three single ones are nine further on, the runs eight.
                let delta = if c >= 0x1FB3 { 9 } else { 8 };
                assert_eq!(ours, c + delta, "{c:04X}");
                assert_eq!(theirs, c, "{c:04X}");
            } else if ours != theirs {
                // Only ever a unit Windows leaves alone.
                assert_eq!(ours, c, "{c:04X}: the table maps it to {ours:04X}");
                left_alone += 1;
            }
        }
        // A newer standard library may map more, never fewer.
        assert!(left_alone >= 217, "{left_alone}");
    }

    /// The table in two numbers, as the conformance driver `nkc-rtl`
    /// logs them on Windows: how many units have an upper case other
    /// than themselves, and a hash (FNV-1a over units) of all 65536
    /// upper cases.
    #[test]
    fn the_table_is_the_one_recorded_on_windows() {
        let mut mapped = 0;
        let mut previous_last = 0;
        for &(first, last, step, delta) in &RUNS {
            assert!(first > previous_last && first <= last, "{first:04X}");
            assert!(step == 1 || step == 2, "{first:04X}");
            assert_eq!((last - first) % step, 0, "{first:04X}");
            assert_ne!(delta, 0, "{first:04X}");
            mapped += usize::from((last - first) / step) + 1;
            previous_last = last;
        }
        assert_eq!(mapped, 973);
        let changed = (0..=u16::MAX).filter(|&c| upcase_char(c) != c).count();
        let hash = (0..=u16::MAX).fold(2_166_136_261u32, |hash, c| {
            (hash ^ u32::from(upcase_char(c))).wrapping_mul(16_777_619)
        });
        assert_eq!((changed, hash), (973, 0x5215_A76D));
    }

    #[test]
    fn single_units() {
        for (lower, upper) in [
            (0x0061, 0x0041), // a
            (0x007A, 0x005A), // z
            (0x0041, 0x0041), // A
            (0x0060, 0x0060), // before a
            (0x007B, 0x007B), // after z
            (0x0000, 0x0000),
            (0x00E9, 0x00C9), // e acute
            (0x00F7, 0x00F7), // division sign
            (0x00DF, 0x00DF), // sharp s: its upper case is two units
            (0x00FF, 0x0178), // y diaeresis
            (0x0101, 0x0100), // a run of every other unit
            (0x0100, 0x0100),
            (0x0102, 0x0102),
            (0x0103, 0x0102),
            (0x03B1, 0x0391), // alpha
            (0x0451, 0x0401), // io
            (0x2D00, 0x10A0), // Georgian: a distance that wraps
            (0x2C65, 0x023A), // a with stroke, from far above
            // Units Unicode maps and Windows leaves alone.
            (0x00B5, 0x00B5), // micro sign
            (0x0131, 0x0131), // dotless i
            (0x017F, 0x017F), // long s
            (0x01C5, 0x01C5), // a title-case digraph
            (0x01C6, 0x01C4), // its lower case is mapped
            (0x03C2, 0x03C2), // final sigma
            (0x10D0, 0x10D0), // Georgian
            (0xAB70, 0xAB70), // Cherokee
            (0xFF41, 0xFF21), // fullwidth a
            (0xFF5A, 0xFF3A), // the last mapping
            (0xFF5B, 0xFF5B),
            (0xD800, 0xD800), // surrogates
            (0xDFFF, 0xDFFF),
            (0xFFFF, 0xFFFF),
        ] {
            assert_eq!(upcase_char(lower), upper, "{lower:04X}");
        }
    }

    #[test]
    fn upcased_string_length() {
        assert_eq!(upcase_string_length(0, 0), Some(0));
        assert_eq!(upcase_string_length(10, 10), Some(10), "no terminator");
        assert_eq!(upcase_string_length(10, 12), Some(10));
        assert_eq!(upcase_string_length(10, 8), None);
        assert_eq!(upcase_string_length(0xFFFE, 0xFFFE), Some(0xFFFE));
    }

    #[test]
    fn comparison() {
        // a, b, case-sensitive sign, case-insensitive sign.
        for (a, b, exact, folded) in [
            ("", "", 0, 0),
            ("", "a", -1, -1),
            ("a", "", 1, 1),
            ("abc", "abc", 0, 0),
            ("abc", "ABC", 1, 0),
            ("ABC", "abc", -1, 0),
            ("abc", "abd", -1, -1),
            ("abc", "ab", 1, 1),
            ("ab", "abc", -1, -1),
            // Compared as upper case: `_` (5F) sorts after `Z` (5A)
            // but before `a` (61).
            ("a", "_", 1, -1),
            ("_", "a", -1, 1),
            ("\u{E9}t\u{E9}", "\u{C9}T\u{C9}", 1, 0),
            ("\u{3B1}", "\u{391}", 1, 0),
            ("abc", "abcd", -1, -1),
            ("b", "abcd", 1, 1),
        ] {
            let (a, b) = (w(a), w(b));
            for (ignore_case, sign) in [(false, exact), (true, folded)] {
                let got = compare_unicode_string(&a, &b, ignore_case);
                assert_eq!(got.signum(), sign, "{a:?} {b:?} {ignore_case}");
                assert_eq!(
                    order_unicode_string(&a, &b, ignore_case),
                    sign.cmp(&0),
                    "{a:?} {b:?}"
                );
                assert_eq!(
                    equal_unicode_string(&a, &b, ignore_case),
                    sign == 0,
                    "{a:?} {b:?} {ignore_case}"
                );
            }
        }
    }

    #[test]
    fn the_value_of_a_comparison() {
        assert_eq!(compare_unicode_string(&w("b"), &w("e"), false), -3);
        assert_eq!(compare_unicode_string(&w("b"), &w("E"), true), -3);
        assert_eq!(compare_unicode_string(&w("abcd"), &w("ab"), false), 4);
        assert_eq!(compare_unicode_string(&w("ab"), &w("abcde"), true), -6);
        assert_eq!(
            compare_unicode_string(&[0xFFFF], &[0], false),
            0xFFFF,
            "units are unsigned"
        );
    }

    #[test]
    fn prefixes() {
        for (prefix, string, exact, folded) in [
            ("", "", true, true),
            ("", "abc", true, true),
            ("abc", "abc", true, true),
            ("ab", "abc", true, true),
            ("AB", "abc", false, true),
            ("abc", "ab", false, false),
            ("b", "abc", false, false),
            ("\\Device\\", "\\DEVICE\\NamedPipe", false, true),
            ("a", "", false, false),
            ("ac", "abc", false, false),
            // By the system's table, not ASCII alone.
            ("\u{C9}", "\u{E9}x", false, true),
        ] {
            let (prefix, string) = (w(prefix), w(string));
            assert_eq!(
                prefix_unicode_string(&prefix, &string, false),
                exact,
                "{prefix:?} {string:?}"
            );
            assert_eq!(
                prefix_unicode_string(&prefix, &string, true),
                folded,
                "{prefix:?} {string:?}"
            );
        }
    }
}
