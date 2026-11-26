//! Text forms of GUIDs and SIDs, and how much two blocks of memory have
//! in common.
//!
//! The text is produced into arrays the caller owns, so that the kernel
//! does the writing into a driver's memory.
//!
//! # INFERRED
//!
//! NK's reading, to be checked against Windows:
//!
//! - `RtlStringFromGUID` prints lower-case digits;
//! - `RtlConvertSidToUnicodeString` prints an identifier authority of
//!   2^32 or more as `0x` and twelve lower-case digits, a smaller one
//!   in decimal, and the revision in decimal.

/// Append `value` in `radix` to `out` at `*at`, with at least
/// `min_digits` digits, the letters among them lower-case.
fn push_number(out: &mut [u16], at: &mut usize, value: u64, radix: u64, min_digits: usize) {
    let mut digits = [0u8; 64];
    let mut n = 0;
    let mut rest = value;
    while rest != 0 || n < min_digits.max(1) {
        let d = (rest % radix) as u8;
        digits[n] = match d {
            0..=9 => b'0' + d,
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
    push_number(&mut out, &mut at, u64::from(data1), 16, 8);
    for group in [data2, data3] {
        push_text(&mut out, &mut at, "-");
        push_number(&mut out, &mut at, u64::from(group), 16, 4);
    }
    for (i, &byte) in data4.iter().enumerate() {
        if i == 0 || i == 2 {
            push_text(&mut out, &mut at, "-");
        }
        push_number(&mut out, &mut at, u64::from(byte), 16, 2);
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
    push_number(out, &mut at, u64::from(revision), 10, 1);
    push_text(out, &mut at, "-");
    let value = authority.iter().fold(0u64, |v, &b| v << 8 | u64::from(b));
    if value > u64::from(u32::MAX) {
        push_text(out, &mut at, "0x");
        push_number(out, &mut at, value, 16, 1);
    } else {
        push_number(out, &mut at, value, 10, 1);
    }
    for &sub in sub_authorities {
        push_text(out, &mut at, "-");
        push_number(out, &mut at, u64::from(sub), 10, 1);
    }
    Some(at)
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
