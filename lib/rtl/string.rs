//! Text forms of GUIDs, SIDs and integers, and the length rules of the
//! counted-string routines that copy and append.
//!
//! The text is produced into arrays the caller owns; how many bytes of
//! a driver's `UNICODE_STRING` to write, what `Length` to store and
//! whether a terminator follows is returned as numbers ([`Stored`]), so
//! that the kernel does the writing.
//!
//! # INFERRED
//!
//! Stated by Microsoft's pages: the lengths `RtlCopyUnicodeString`
//! copies, `STATUS_BUFFER_TOO_SMALL` from the append routines, and the
//! parsing rules and examples of `RtlUnicodeStringToInteger`. NK's
//! reading, to be checked against Windows:
//!
//! - a terminator is written by the copy and append routines exactly
//!   when two bytes remain after the new `Length`;
//! - `RtlStringFromGUID` prints lower-case digits;
//! - `RtlConvertSidToUnicodeString` prints an identifier authority of
//!   2^32 or more as `0x` and twelve lower-case digits, a smaller one
//!   in decimal, and the revision in decimal;
//! - `RtlIntegerToUnicodeString` prints upper-case digits, no prefix,
//!   and treats the value as unsigned in every base;
//! - `RtlUnicodeStringToInteger`: white space is any unit up to U+0020;
//!   the prefix letters `x`, `o`, `b` are recognized in lower case only
//!   and only when the base is 0; a value too large wraps modulo 2^32;
//!   a base other than 0, 2, 8, 10 or 16 is `STATUS_INVALID_PARAMETER`.

/// Append `value` in `radix` to `out` at `*at`, with at least
/// `min_digits` digits.
fn push_number(
    out: &mut [u16],
    at: &mut usize,
    value: u64,
    radix: u64,
    min_digits: usize,
    upper: bool,
) {
    let mut digits = [0u8; 64];
    let mut n = 0;
    let mut rest = value;
    while rest != 0 || n < min_digits.max(1) {
        let d = (rest % radix) as u8;
        digits[n] = match d {
            0..=9 => b'0' + d,
            _ if upper => b'A' + d - 10,
            _ => b'a' + d - 10,
        };
        n += 1;
        rest /= radix;
    }
    for &d in digits[..n].iter().rev() {
        out[*at] = u16::from(d);
        *at += 1;
    }
}

fn push_text(out: &mut [u16], at: &mut usize, text: &str) {
    for b in text.bytes() {
        out[*at] = u16::from(b);
        *at += 1;
    }
}

/// Characters in the text form of a GUID.
pub const GUID_TEXT_LENGTH: usize = 38;

/// The text
/// [`RtlStringFromGUID`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlstringfromguid)
/// produces: `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`. The routine
/// allocates the string, terminator included.
pub fn guid_text(data1: u32, data2: u16, data3: u16, data4: &[u8; 8]) -> [u16; GUID_TEXT_LENGTH] {
    let mut out = [0u16; GUID_TEXT_LENGTH];
    let mut at = 0;
    push_text(&mut out, &mut at, "{");
    push_number(&mut out, &mut at, u64::from(data1), 16, 8, false);
    for group in [data2, data3] {
        push_text(&mut out, &mut at, "-");
        push_number(&mut out, &mut at, u64::from(group), 16, 4, false);
    }
    for (i, &byte) in data4.iter().enumerate() {
        if i == 0 || i == 2 {
            push_text(&mut out, &mut at, "-");
        }
        push_number(&mut out, &mut at, u64::from(byte), 16, 2, false);
    }
    push_text(&mut out, &mut at, "}");
    out
}

/// Sub-authorities a SID can have (`SID_MAX_SUB_AUTHORITIES`).
pub const SID_MAX_SUB_AUTHORITIES: usize = 15;

/// Characters in the longest text form of a SID: `S-`, a revision of
/// three digits, `-0x` and twelve digits, and fifteen sub-authorities
/// of a hyphen and ten digits.
pub const SID_TEXT_MAX: usize = 2 + 3 + 1 + 14 + SID_MAX_SUB_AUTHORITIES * 11;

/// The text
/// [`RtlConvertSidToUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlconvertsidtounicodestring)
/// produces, such as `S-1-5-18`, written to `out`; its length in
/// characters. None if there are more sub-authorities than a SID can
/// have (`STATUS_INVALID_SID`).
///
/// `authority` is the `IdentifierAuthority`, most significant byte
/// first: a number of 48 bits, printed in decimal if it fits in 32 and
/// else in hexadecimal after `0x`, without leading zeros, as Windows
/// 10 prints it.
pub fn sid_text(
    revision: u8,
    authority: &[u8; 6],
    sub_authorities: &[u32],
    out: &mut [u16; SID_TEXT_MAX],
) -> Option<usize> {
    if sub_authorities.len() > SID_MAX_SUB_AUTHORITIES {
        return None;
    }
    let mut at = 0;
    push_text(out, &mut at, "S-");
    push_number(out, &mut at, u64::from(revision), 10, 1, false);
    push_text(out, &mut at, "-");
    let value = authority.iter().fold(0u64, |v, &b| v << 8 | u64::from(b));
    if value > u64::from(u32::MAX) {
        push_text(out, &mut at, "0x");
        push_number(out, &mut at, value, 16, 1, false);
    } else {
        push_number(out, &mut at, value, 10, 1, false);
    }
    for &sub in sub_authorities {
        push_text(out, &mut at, "-");
        push_number(out, &mut at, u64::from(sub), 10, 1, false);
    }
    Some(at)
}

/// Characters in the longest text of a 32-bit integer: base 2.
pub const INTEGER_TEXT_MAX: usize = 32;

/// The digits
/// [`RtlIntegerToUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlintegertounicodestring)
/// produces for `value` in `base` (0 means 10), written to `out`; their
/// number. None if the base is not 0, 2, 8, 10 or 16
/// (`STATUS_INVALID_PARAMETER`).
pub fn integer_text(value: u32, base: u32, out: &mut [u16; INTEGER_TEXT_MAX]) -> Option<usize> {
    let radix = match base {
        0 => 10,
        2 | 8 | 10 | 16 => u64::from(base),
        _ => return None,
    };
    let mut at = 0;
    push_number(out, &mut at, u64::from(value), radix, 1, true);
    Some(at)
}

/// [`RtlUnicodeStringToInteger`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtointeger):
/// the number `string` starts with, after white space and a sign. With
/// a `base` of 0 a prefix of `0x`, `0o` or `0b` chooses 16, 8 or 2, and
/// no prefix 10. The digits end at the first unit that is not one;
/// none at all is the value 0.
///
/// None (`STATUS_INVALID_PARAMETER`) if the string is empty or the base
/// is not one of 0, 2, 8, 10, 16.
pub fn unicode_string_to_integer(string: &[u16], base: u32) -> Option<u32> {
    if string.is_empty() || !matches!(base, 0 | 2 | 8 | 10 | 16) {
        return None;
    }
    let is = |c: Option<&u16>, ch: u8| c == Some(&u16::from(ch));
    let mut rest = string;
    while rest.first().is_some_and(|&c| c <= 0x20) {
        rest = &rest[1..];
    }
    let negative = is(rest.first(), b'-');
    if negative || is(rest.first(), b'+') {
        rest = &rest[1..];
    }
    let mut radix = base;
    if base == 0 {
        radix = 10;
        if is(rest.first(), b'0') {
            let prefixed = [(b'x', 16), (b'o', 8), (b'b', 2)]
                .into_iter()
                .find(|&(letter, _)| is(rest.get(1), letter));
            if let Some((_, chosen)) = prefixed {
                radix = chosen;
                rest = &rest[2..];
            }
        }
    }
    let mut value = 0u32;
    for &c in rest {
        let Some(digit) = char::from_u32(u32::from(c)).and_then(|c| c.to_digit(radix)) else {
            break;
        };
        value = value.wrapping_mul(radix).wrapping_add(digit);
    }
    Some(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}

/// What a copying routine does to its destination string.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Stored {
    /// Bytes of the source to copy.
    pub bytes: u16,
    /// The destination's new `Length`.
    pub length: u16,
    /// Whether a terminator is written after the new `Length`. It is
    /// not counted in it.
    pub terminated: bool,
}

fn stored(bytes: u16, length: u16, maximum: u16) -> Stored {
    Stored {
        bytes,
        length,
        terminated: u32::from(length) + 2 <= u32::from(maximum),
    }
}

/// [`RtlCopyUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopyunicodestring):
/// as much of the source as the destination's `MaximumLength` holds; it
/// truncates and reports nothing. A null source is a length of zero.
pub fn copy_unicode_string(source_length: u16, destination_maximum: u16) -> Stored {
    let bytes = source_length.min(destination_maximum);
    stored(bytes, bytes, destination_maximum)
}

/// [`RtlAppendUnicodeStringToString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlappendunicodestringtostring)
/// and
/// [`RtlAppendUnicodeToString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlappendunicodetostring):
/// the whole source after the destination's present contents, or
/// nothing. None, with the destination untouched, if it does not fit
/// (`STATUS_BUFFER_TOO_SMALL`).
///
/// `source_length` is in bytes; for `RtlAppendUnicodeToString` it is
/// the length of the NUL-terminated source, zero for a null one.
pub fn append_unicode_string(
    destination_length: u16,
    destination_maximum: u16,
    source_length: usize,
) -> Option<Stored> {
    let room = destination_maximum.checked_sub(destination_length)?;
    let bytes = u16::try_from(source_length).ok().filter(|&b| b <= room)?;
    Some(stored(
        bytes,
        destination_length + bytes,
        destination_maximum,
    ))
}

/// [`RtlCompareMemory`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcomparememory):
/// how many bytes, from the start, the two blocks have in common. Each
/// block is given as its bytes in order, the routine's `Length` of
/// them; none is read after the first that differs.
pub fn compare_memory(a: impl Iterator<Item = u8>, b: impl Iterator<Item = u8>) -> usize {
    a.zip(b).take_while(|(x, y)| x == y).count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn text(units: &[u16]) -> String {
        String::from_utf16(units).unwrap()
    }

    /// The GUID a text form names.
    fn parse_guid(s: &str) -> (u32, u16, u16, [u8; 8]) {
        let hex = |range: core::ops::Range<usize>| u64::from_str_radix(&s[range], 16).unwrap();
        assert_eq!(s.len(), GUID_TEXT_LENGTH);
        for (at, c) in [
            (0, '{'),
            (9, '-'),
            (14, '-'),
            (19, '-'),
            (24, '-'),
            (37, '}'),
        ] {
            assert_eq!(s[at..].chars().next(), Some(c), "{s}");
        }
        let mut data4 = [0u8; 8];
        for (i, at) in [20, 22, 25, 27, 29, 31, 33, 35].into_iter().enumerate() {
            data4[i] = hex(at..at + 2) as u8;
        }
        (
            hex(1..9) as u32,
            hex(10..14) as u16,
            hex(15..19) as u16,
            data4,
        )
    }

    #[test]
    fn guids() {
        let cases = [
            (
                (
                    0x4D36_E96C,
                    0xE325,
                    0x11CE,
                    [0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18],
                ),
                "{4d36e96c-e325-11ce-bfc1-08002be10318}",
            ),
            ((0, 0, 0, [0; 8]), "{00000000-0000-0000-0000-000000000000}"),
            (
                (u32::MAX, u16::MAX, u16::MAX, [0xFF; 8]),
                "{ffffffff-ffff-ffff-ffff-ffffffffffff}",
            ),
            (
                (
                    0x1,
                    0x2,
                    0x3,
                    [0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B],
                ),
                "{00000001-0002-0003-0405-060708090a0b}",
            ),
        ];
        for ((d1, d2, d3, d4), expected) in cases {
            let got = text(&guid_text(d1, d2, d3, &d4));
            assert_eq!(got, expected);
            assert_eq!(parse_guid(&got), (d1, d2, d3, d4));
        }
    }

    /// The SID a text form names.
    fn parse_sid(s: &str) -> (u8, [u8; 6], Vec<u32>) {
        let mut parts = s.split('-');
        assert_eq!(parts.next(), Some("S"));
        let revision = parts.next().unwrap().parse().unwrap();
        let authority = parts.next().unwrap();
        let value = match authority.strip_prefix("0x") {
            Some(hex) => u64::from_str_radix(hex, 16).unwrap(),
            None => authority.parse().unwrap(),
        };
        let mut bytes = [0u8; 6];
        bytes.copy_from_slice(&value.to_be_bytes()[2..]);
        (revision, bytes, parts.map(|p| p.parse().unwrap()).collect())
    }

    #[test]
    fn sids() {
        let cases: [(u8, [u8; 6], &[u32], &str); 8] = [
            (1, [0, 0, 0, 0, 0, 5], &[18], "S-1-5-18"),
            (1, [0, 0, 0, 0, 0, 1], &[0], "S-1-1-0"),
            (1, [0, 0, 0, 0, 0, 5], &[], "S-1-5"),
            (
                1,
                [0, 0, 0, 0, 0, 5],
                &[21, 3_623_811_015, 3_361_044_348, 30_300_820, 500],
                "S-1-5-21-3623811015-3361044348-30300820-500",
            ),
            // The largest authority printed in decimal, and the smallest
            // in hexadecimal.
            (1, [0, 0, 0xFF, 0xFF, 0xFF, 0xFF], &[1], "S-1-4294967295-1"),
            (1, [0, 1, 0, 0, 0, 0], &[1], "S-1-0x100000000-1"),
            (
                1,
                [0x01, 0x02, 0x03, 0xAB, 0xCD, 0xEF],
                &[u32::MAX],
                "S-1-0x10203abcdef-4294967295",
            ),
            (255, [0; 6], &[0, 0], "S-255-0-0-0"),
        ];
        for (revision, authority, subs, expected) in cases {
            let mut out = [0u16; SID_TEXT_MAX];
            let len = sid_text(revision, &authority, subs, &mut out).unwrap();
            let got = text(&out[..len]);
            assert_eq!(got, expected);
            assert_eq!(parse_sid(&got), (revision, authority, subs.to_vec()));
        }
    }

    #[test]
    fn the_longest_sid_fills_its_buffer_and_one_too_long_is_refused() {
        let mut out = [0u16; SID_TEXT_MAX];
        let len = sid_text(255, &[0xFF; 6], &[u32::MAX; 15], &mut out);
        assert_eq!(len, Some(SID_TEXT_MAX));
        assert_eq!(parse_sid(&text(&out)), (255, [0xFF; 6], vec![u32::MAX; 15]));
        assert_eq!(sid_text(1, &[0; 6], &[0; 16], &mut out), None);
    }

    #[test]
    fn integers_to_text() {
        for (value, base, expected) in [
            (0, 10, Some("0")),
            (0, 2, Some("0")),
            (123, 0, Some("123")),
            (123, 10, Some("123")),
            (255, 16, Some("FF")),
            (0xDEAD_BEEF, 16, Some("DEADBEEF")),
            (8, 8, Some("10")),
            (5, 2, Some("101")),
            (u32::MAX, 10, Some("4294967295")),
            (u32::MAX, 8, Some("37777777777")),
            (u32::MAX, 2, Some("11111111111111111111111111111111")),
            (1, 1, None),
            (1, 3, None),
            (1, 36, None),
        ] {
            let mut out = [0u16; INTEGER_TEXT_MAX];
            let got = integer_text(value, base, &mut out).map(|len| text(&out[..len]));
            assert_eq!(got.as_deref(), expected, "{value} in base {base}");
        }
    }

    #[test]
    fn text_to_integers() {
        let minus = |n: u32| n.wrapping_neg();
        for (string, base, expected) in [
            // The examples of Microsoft's page.
            ("123", 10, Some(123)),
            ("-345", 10, Some(minus(345))),
            ("xyz", 10, Some(0)),
            ("+678abc", 10, Some(678)),
            ("+678abc", 16, Some(6_785_724)),
            ("007", 10, Some(7)),
            ("789", 8, Some(7)),
            ("FGH", 16, Some(15)),
            (" ", 10, Some(0)),
            ("", 10, None),
            // Prefixes, when the base is left to the string.
            ("0x1F", 0, Some(31)),
            ("0o17", 0, Some(15)),
            ("0b101", 0, Some(5)),
            ("42", 0, Some(42)),
            ("-0x10", 0, Some(minus(16))),
            ("0", 0, Some(0)),
            ("0x", 0, Some(0)),
            ("0X1F", 0, Some(0)),
            ("017", 0, Some(17)),
            // A stated base takes no prefix: the digits end at the `x`.
            ("0x1F", 16, Some(0)),
            ("1f", 16, Some(31)),
            ("102", 2, Some(2)),
            // White space and signs.
            (" \t\r\n 12", 10, Some(12)),
            ("+12", 10, Some(12)),
            ("- 12", 10, Some(0)),
            ("+-12", 10, Some(0)),
            ("12 34", 10, Some(12)),
            ("-", 10, Some(0)),
            ("\u{A0}12", 10, Some(0)),
            // Digits are ASCII.
            ("\u{FF11}", 10, Some(0)),
            // Too large wraps.
            ("4294967295", 10, Some(u32::MAX)),
            ("4294967296", 10, Some(0)),
            ("-4294967295", 10, Some(1)),
            ("1FFFFFFFF", 16, Some(u32::MAX)),
            // Bases there are none of.
            ("12", 1, None),
            ("12", 7, None),
            ("12", 36, None),
        ] {
            assert_eq!(
                unicode_string_to_integer(&w(string), base),
                expected,
                "{string:?} in base {base}"
            );
        }
    }

    #[test]
    fn integers_survive_the_round_trip() {
        let values = [0, 1, 9, 10, 255, 256, 0x7FFF_FFFF, 0x8000_0000, u32::MAX];
        for value in values {
            for base in [2, 8, 10, 16] {
                let mut out = [0u16; INTEGER_TEXT_MAX];
                let len = integer_text(value, base, &mut out).unwrap();
                assert_eq!(
                    unicode_string_to_integer(&out[..len], base),
                    Some(value),
                    "{value} in base {base}"
                );
            }
        }
    }

    #[test]
    fn copying_truncates_and_terminates_if_there_is_room() {
        let s = |bytes, length, terminated| Stored {
            bytes,
            length,
            terminated,
        };
        for (source, maximum, expected) in [
            (0, 0, s(0, 0, false)),
            (0, 2, s(0, 0, true)),
            (10, 12, s(10, 10, true)),
            (10, 11, s(10, 10, false)),
            (10, 10, s(10, 10, false)),
            (10, 6, s(6, 6, false)),
            (10, 0, s(0, 0, false)),
            (0xFFFE, 0xFFFF, s(0xFFFE, 0xFFFE, false)),
            (0xFFFC, 0xFFFE, s(0xFFFC, 0xFFFC, true)),
        ] {
            assert_eq!(
                copy_unicode_string(source, maximum),
                expected,
                "{source} into {maximum}"
            );
        }
    }

    #[test]
    fn appending_is_all_or_nothing() {
        let s = |bytes, length, terminated| {
            Some(Stored {
                bytes,
                length,
                terminated,
            })
        };
        for (length, maximum, source, expected) in [
            (0, 0, 0, s(0, 0, false)),
            (4, 10, 0, s(0, 4, true)),
            (4, 10, 4, s(4, 8, true)),
            (4, 10, 6, s(6, 10, false)),
            (4, 10, 8, None),
            (4, 9, 4, s(4, 8, false)),
            (10, 10, 2, None),
            (10, 10, 0, s(0, 10, false)),
            // A destination already past its own maximum.
            (12, 10, 0, None),
            (0, 0xFFFF, 0xFFFE, s(0xFFFE, 0xFFFE, false)),
            (0, 0xFFFF, 0x1_0000, None),
            (0, 0xFFFF, usize::MAX, None),
            (0xFFFC, 0xFFFE, 2, s(2, 0xFFFE, false)),
        ] {
            assert_eq!(
                append_unicode_string(length, maximum, source),
                expected,
                "{source} after {length} of {maximum}"
            );
        }
    }

    #[test]
    fn memory_comparison_counts_the_common_start() {
        for (a, b, expected) in [
            (&b""[..], &b""[..], 0),
            (b"abc", b"abc", 3),
            (b"abc", b"abd", 2),
            (b"abc", b"xbc", 0),
            (b"abc", b"ab", 2),
            (b"\0\0", b"\0\x01", 1),
        ] {
            assert_eq!(
                compare_memory(a.iter().copied(), b.iter().copied()),
                expected,
                "{a:?} {b:?}"
            );
        }
        // Nothing is read after the first difference.
        let poisoned = |bytes: &'static [u8]| {
            bytes
                .iter()
                .copied()
                .chain(core::iter::from_fn(|| panic!("read past the difference")))
        };
        assert_eq!(compare_memory(poisoned(b"abc"), poisoned(b"abd")), 2);
    }
}
