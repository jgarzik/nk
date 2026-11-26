//! Numbers, GUIDs, times and checksums to and from their other forms:
//! the rules of
//! [`RtlUnicodeStringToInteger`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtointeger),
//! [`RtlIntegerToUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlintegertounicodestring),
//! [`RtlGUIDFromString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlguidfromstring),
//! [`RtlTimeToTimeFields`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimetotimefields)
//! and `RtlComputeCrc32`.
//!
//! # Where Microsoft's documentation stops
//!
//! Read from the kernel NK follows (10.0.19041), for
//! `RtlUnicodeStringToInteger`: an empty string, or one of an odd
//! number of bytes, is `STATUS_INVALID_PARAMETER` and stores zero; the
//! prefixes that choose a base are lower-case `0x`, `0o` and `0b` and
//! no others; a NUL ends the number; too large a number wraps; and a
//! string with no digit in it is zero and a success.
//!
//! # INFERRED
//!
//! - `RtlGUIDFromString` wants the braces, the hyphens and exactly the
//!   digits of each field, in either case, and does not look at what
//!   follows the closing brace.
//! - `RtlComputeCrc32` inverts the partial sum on the way in and the
//!   result on the way out, so that sums chain and the sum of
//!   `123456789` from zero is 0xCBF43926.
//! - `RtlTimeToTimeFields` reads the time as unsigned.

/// `RtlUnicodeStringToInteger`: the number in a counted string of
/// `length` bytes whose units are `units`. `None` is
/// `STATUS_INVALID_PARAMETER`, with which the routine stores zero.
pub fn unicode_to_integer(
    length: u16,
    mut units: impl Iterator<Item = u16>,
    base: u32,
) -> Option<u32> {
    if length == 0 || length % 2 != 0 {
        return None;
    }
    let is = |c: u16, ch: u8| c == u16::from(ch);
    // The end of the string reads as a NUL, which ends the number.
    let mut c = loop {
        match units.next() {
            None => break 0,
            Some(c) if c <= 0x20 => {}
            Some(c) => break c,
        }
    };
    let negative = is(c, b'-');
    if negative || is(c, b'+') {
        c = units.next().unwrap_or(0);
    }
    let base = match base {
        0 => {
            let mut base = 10;
            if is(c, b'0') {
                c = units.next().unwrap_or(0);
                let prefixed = [(b'x', 16), (b'o', 8), (b'b', 2)]
                    .into_iter()
                    .find(|&(letter, _)| is(c, letter));
                if let Some((_, named)) = prefixed {
                    base = named;
                    c = units.next().unwrap_or(0);
                }
            }
            base
        }
        2 | 8 | 10 | 16 => base,
        _ => return None,
    };
    let mut value = 0u32;
    while let Some(digit) = char::from_u32(u32::from(c))
        .and_then(|c| c.to_digit(16))
        .filter(|&digit| digit < base)
    {
        value = value.wrapping_mul(base).wrapping_add(digit);
        match units.next() {
            Some(next) => c = next,
            None => break,
        }
    }
    Some(if negative {
        value.wrapping_neg()
    } else {
        value
    })
}

/// The longest text [`integer_text`] produces: 32 binary digits.
pub const INTEGER_TEXT_MAX: usize = 32;

/// `RtlIntegerToUnicodeString`, `RtlIntegerToChar`: the digits of
/// `value` in `base` (zero means ten), letters upper-case, and how many
/// there are. `None`, for a base other than 2, 8, 10 or 16, is
/// `STATUS_INVALID_PARAMETER`.
pub fn integer_text(value: u32, base: u32) -> Option<([u8; INTEGER_TEXT_MAX], usize)> {
    let base = match base {
        0 => 10,
        2 | 8 | 10 | 16 => base,
        _ => return None,
    };
    let mut reversed = [0u8; INTEGER_TEXT_MAX];
    let (mut count, mut rest) = (0, value);
    loop {
        let digit = (rest % base) as u8;
        reversed[count] = match digit {
            0..=9 => b'0' + digit,
            _ => b'A' + digit - 10,
        };
        count += 1;
        rest /= base;
        if rest == 0 {
            break;
        }
    }
    let mut text = [0u8; INTEGER_TEXT_MAX];
    for (to, from) in text.iter_mut().zip(reversed[..count].iter().rev()) {
        *to = *from;
    }
    Some((text, count))
}

/// `RtlGUIDFromString`: the GUID that `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`
/// names, as its four fields. `None` is `STATUS_INVALID_PARAMETER`.
pub fn guid_from_text(mut units: impl Iterator<Item = u16>) -> Option<(u32, u16, u16, [u8; 8])> {
    fn literal(units: &mut impl Iterator<Item = u16>, c: u8) -> Option<()> {
        (units.next()? == u16::from(c)).then_some(())
    }
    fn hex(units: &mut impl Iterator<Item = u16>, digits: usize) -> Option<u32> {
        let mut value = 0;
        for _ in 0..digits {
            let digit = char::from_u32(u32::from(units.next()?))?.to_digit(16)?;
            value = value << 4 | digit;
        }
        Some(value)
    }
    let units = &mut units;
    literal(units, b'{')?;
    let data1 = hex(units, 8)?;
    literal(units, b'-')?;
    let data2 = hex(units, 4)? as u16;
    literal(units, b'-')?;
    let data3 = hex(units, 4)? as u16;
    literal(units, b'-')?;
    let mut data4 = [0u8; 8];
    for (at, byte) in data4.iter_mut().enumerate() {
        if at == 2 {
            literal(units, b'-')?;
        }
        *byte = hex(units, 2)? as u8;
    }
    literal(units, b'}')?;
    Some((data1, data2, data3, data4))
}

/// `RtlTimeToTimeFields`: the fields of a time counted in 100 ns since
/// the start of 1601, in the order of `TIME_FIELDS`: year, month (from
/// 1), day (from 1), hour, minute, second, milliseconds, weekday (0 is
/// Sunday).
pub fn time_fields(time: u64) -> [i16; 8] {
    const PER_MILLISECOND: u64 = 10_000;
    const MILLISECONDS_PER_DAY: u64 = 86_400_000;
    /// Days from 0000-03-01 of the Gregorian calendar to 1601-01-01.
    const DAYS_TO_1601: u64 = 584_694;
    let milliseconds = time / PER_MILLISECOND;
    let (days, in_day) = (
        milliseconds / MILLISECONDS_PER_DAY,
        milliseconds % MILLISECONDS_PER_DAY,
    );
    // The first day of 1601 was a Monday.
    let weekday = (days + 1) % 7;
    // The date, counting years from March so that a leap day is a
    // year's last: whole 400-year eras, then the year and the day in
    // the era.
    let shifted = days + DAYS_TO_1601;
    let (era, day_of_era) = (shifted / 146_097, shifted % 146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_from_march = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_from_march + 2) / 5 + 1;
    let month = if month_from_march < 10 {
        month_from_march + 3
    } else {
        month_from_march - 9
    };
    let year = era * 400 + year_of_era + u64::from(month <= 2);
    [
        year as i16,
        month as i16,
        day as i16,
        (in_day / 3_600_000) as i16,
        (in_day / 60_000 % 60) as i16,
        (in_day / 1_000 % 60) as i16,
        (in_day % 1_000) as i16,
        weekday as i16,
    ]
}

/// `RtlComputeCrc32`: the CRC-32 (the reflected polynomial 0xEDB88320)
/// of `bytes`, carried on from `partial`, the sum of what came before
/// them.
pub fn crc32(partial: u32, bytes: impl Iterator<Item = u8>) -> u32 {
    let mut crc = !partial;
    for byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = crc >> 1 ^ if crc & 1 != 0 { 0xEDB8_8320 } else { 0 };
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn integer(text: &str, base: u32) -> Option<u32> {
        let units: Vec<u16> = text.encode_utf16().collect();
        unicode_to_integer((units.len() * 2) as u16, units.into_iter(), base)
    }

    #[test]
    fn a_number_is_read_in_the_base_given() {
        assert_eq!(integer("123", 10), Some(123));
        assert_eq!(integer("ff", 16), Some(255));
        assert_eq!(integer("Ff", 16), Some(255));
        assert_eq!(integer("777", 8), Some(511));
        assert_eq!(integer("101", 2), Some(5));
        assert_eq!(integer("4294967295", 10), Some(u32::MAX));
        // A digit the base lacks ends the number.
        assert_eq!(integer("129", 8), Some(10));
        assert_eq!(integer("12a", 10), Some(12));
        assert_eq!(integer("12 3", 10), Some(12));
        assert_eq!(integer("102", 2), Some(2));
        assert_eq!(integer("fg", 16), Some(15));
        // With a base given, a prefix is not a prefix.
        assert_eq!(integer("0x10", 16), Some(0));
        assert_eq!(integer("0x10", 10), Some(0));
    }

    #[test]
    fn base_zero_reads_the_prefix() {
        assert_eq!(integer("123", 0), Some(123));
        assert_eq!(integer("0x1F", 0), Some(31));
        assert_eq!(integer("0o17", 0), Some(15));
        assert_eq!(integer("0b101", 0), Some(5));
        // Lower-case letters only; a bare zero in front is decimal.
        assert_eq!(integer("0X1F", 0), Some(0));
        assert_eq!(integer("0O17", 0), Some(0));
        assert_eq!(integer("0B11", 0), Some(0));
        assert_eq!(integer("017", 0), Some(17));
        assert_eq!(integer("0", 0), Some(0));
        assert_eq!(integer("0x", 0), Some(0));
        assert_eq!(integer("00x10", 0), Some(0));
        assert_eq!(integer("-0x10", 0), Some(16u32.wrapping_neg()));
    }

    #[test]
    fn space_and_a_sign_may_come_first() {
        assert_eq!(integer("  \t\r\n42", 10), Some(42));
        assert_eq!(integer("\u{1}7", 10), Some(7));
        assert_eq!(integer("+42", 10), Some(42));
        assert_eq!(integer("-42", 10), Some(42u32.wrapping_neg()));
        assert_eq!(integer(" -1", 10), Some(u32::MAX));
        // One sign, and no space after it.
        assert_eq!(integer("--1", 10), Some(0));
        assert_eq!(integer("+-1", 10), Some(0));
        assert_eq!(integer("- 1", 10), Some(0));
        // Nothing to read is zero, and a success.
        assert_eq!(integer("   ", 10), Some(0));
        assert_eq!(integer("-", 10), Some(0));
        assert_eq!(integer("x", 10), Some(0));
        // A NUL ends the number.
        assert_eq!(integer("12\u{0}34", 10), Some(12));
    }

    #[test]
    fn a_number_too_large_wraps() {
        assert_eq!(integer("4294967296", 10), Some(0));
        assert_eq!(integer("4294967301", 10), Some(5));
        assert_eq!(integer("123456789ab", 16), Some(0x4567_89AB));
        assert_eq!(integer("-4294967295", 10), Some(1));
    }

    #[test]
    fn a_bad_base_or_string_is_refused() {
        for base in [1, 3, 7, 9, 11, 15, 17, 36, u32::MAX] {
            assert_eq!(integer("1", base), None);
        }
        assert_eq!(integer("", 10), None);
        assert_eq!(unicode_to_integer(0, [0x31].into_iter(), 10), None);
        // An odd count of bytes.
        assert_eq!(unicode_to_integer(3, [0x31].into_iter(), 10), None);
        assert_eq!(unicode_to_integer(1, core::iter::empty(), 10), None);
    }

    fn digits(value: u32, base: u32) -> Option<String> {
        integer_text(value, base)
            .map(|(text, count)| String::from_utf8(text[..count].to_vec()).unwrap())
    }

    #[test]
    fn an_integer_prints_in_four_bases() {
        assert_eq!(digits(0, 10).unwrap(), "0");
        assert_eq!(digits(0, 2).unwrap(), "0");
        assert_eq!(digits(1234567890, 10).unwrap(), "1234567890");
        assert_eq!(digits(1234567890, 0).unwrap(), "1234567890");
        assert_eq!(digits(u32::MAX, 10).unwrap(), "4294967295");
        assert_eq!(digits(0xDEAD_BEEF, 16).unwrap(), "DEADBEEF");
        assert_eq!(digits(0o1234567, 8).unwrap(), "1234567");
        assert_eq!(digits(u32::MAX, 8).unwrap(), "37777777777");
        assert_eq!(digits(u32::MAX, 2).unwrap(), "1".repeat(32));
        assert_eq!(digits(5, 2).unwrap(), "101");
        for base in [1, 3, 4, 7, 9, 12, 32, 36] {
            assert_eq!(digits(1, base), None);
        }
        // What is printed reads back.
        for value in [0, 1, 9, 10, 255, 256, 65535, 0x8000_0000, u32::MAX] {
            for base in [2, 8, 10, 16] {
                assert_eq!(integer(&digits(value, base).unwrap(), base), Some(value));
            }
        }
    }

    fn guid(text: &str) -> Option<(u32, u16, u16, [u8; 8])> {
        guid_from_text(text.encode_utf16())
    }

    #[test]
    fn a_guid_is_read_from_its_text() {
        let expected = (
            0x0123_4567,
            0x89AB,
            0xCDEF,
            [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
        );
        assert_eq!(
            guid("{01234567-89ab-cdef-0123-456789abcdef}"),
            Some(expected)
        );
        assert_eq!(
            guid("{01234567-89AB-CDEF-0123-456789ABCDEF}"),
            Some(expected)
        );
        assert_eq!(
            guid("{00000000-0000-0000-0000-000000000000}"),
            Some((0, 0, 0, [0; 8]))
        );
        assert_eq!(
            guid("{ffffffff-ffff-ffff-ffff-ffffffffffff}"),
            Some((u32::MAX, u16::MAX, u16::MAX, [0xFF; 8]))
        );
        // What follows the closing brace is not looked at.
        assert_eq!(
            guid("{01234567-89ab-cdef-0123-456789abcdef}\\rest"),
            Some(expected)
        );
        // What `guid_text` prints reads back.
        let text = crate::string::guid_text(expected.0, expected.1, expected.2, &expected.3);
        assert_eq!(guid_from_text(text.into_iter()), Some(expected));
    }

    #[test]
    fn a_malformed_guid_is_refused() {
        for text in [
            "",
            "{",
            "01234567-89ab-cdef-0123-456789abcdef",
            "{01234567-89ab-cdef-0123-456789abcdef",
            "{01234567-89ab-cdef-0123-456789abcde}",
            "{01234567-89ab-cdef-0123-456789abcdeff}",
            "{0123456-89ab-cdef-0123-456789abcdef}",
            "{01234567 89ab-cdef-0123-456789abcdef}",
            "{01234567-89ab-cdef-0123456789abcdef}",
            "{01234567-89ab-cdef-01-23456789abcdef}",
            "{0123456g-89ab-cdef-0123-456789abcdef}",
            "(01234567-89ab-cdef-0123-456789abcdef)",
            " {01234567-89ab-cdef-0123-456789abcdef}",
            "{01234567-89ab-cdef-0123-456789abcd\u{ff46}f}",
        ] {
            assert_eq!(guid(text), None, "{text}");
        }
    }

    /// 100 ns units from the start of 1601 to a date and time, by
    /// counting the days of every year and month before it.
    fn time_of(year: u64, month: u64, day: u64, in_day: u64) -> (u64, u64) {
        let leap = |year: u64| year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        let mut days: u64 = (1601..year).map(|y| if leap(y) { 366 } else { 365 }).sum();
        for m in 1..month {
            days += match m {
                4 | 6 | 9 | 11 => 30,
                2 if leap(year) => 29,
                2 => 28,
                _ => 31,
            };
        }
        days += day - 1;
        (days * 864_000_000_000 + in_day, days)
    }

    #[test]
    fn a_time_splits_into_its_fields() {
        assert_eq!(time_fields(0), [1601, 1, 1, 0, 0, 0, 0, 1]);
        assert_eq!(time_fields(9_999), [1601, 1, 1, 0, 0, 0, 0, 1]);
        assert_eq!(time_fields(10_000), [1601, 1, 1, 0, 0, 0, 1, 1]);
        assert_eq!(
            time_fields(864_000_000_000 - 1),
            [1601, 1, 1, 23, 59, 59, 999, 1]
        );
        assert_eq!(time_fields(864_000_000_000), [1601, 1, 2, 0, 0, 0, 0, 2]);
        // The start of 1970, a Thursday: the well-known 116444736000000000.
        assert_eq!(
            time_fields(116_444_736_000_000_000),
            [1970, 1, 1, 0, 0, 0, 0, 4]
        );
        // 2000-02-29 12:34:56.789, a Tuesday.
        let in_day = ((12 * 60 + 34) * 60 + 56) * 10_000_000 + 789 * 10_000;
        assert_eq!(
            time_fields(time_of(2000, 2, 29, in_day).0),
            [2000, 2, 29, 12, 34, 56, 789, 2]
        );
        // 2026-11-26, a Thursday.
        assert_eq!(
            time_fields(time_of(2026, 11, 26, 0).0),
            [2026, 11, 26, 0, 0, 0, 0, 4]
        );
    }

    #[test]
    fn every_month_end_of_four_centuries_is_the_right_date() {
        let leap = |year: u64| year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
        for year in (1601..2101).chain([2400, 9999, 30827]) {
            for month in 1..=12 {
                let last = match month {
                    4 | 6 | 9 | 11 => 30,
                    2 if leap(year) => 29,
                    2 => 28,
                    _ => 31,
                };
                for day in [1, last] {
                    let (time, days) = time_of(year, month, day, 0);
                    let fields = time_fields(time);
                    assert_eq!(
                        fields[..3],
                        [year as i16, month as i16, day as i16],
                        "{year}-{month}-{day}"
                    );
                    assert_eq!(fields[7], ((days + 1) % 7) as i16);
                }
            }
        }
    }

    #[test]
    fn the_checksum_is_crc_32_and_chains() {
        assert_eq!(crc32(0, core::iter::empty()), 0);
        assert_eq!(crc32(0, b"123456789".iter().copied()), 0xCBF4_3926);
        assert_eq!(crc32(0, [0u8].into_iter()), 0xD202_EF8D);
        assert_eq!(
            crc32(
                0,
                b"The quick brown fox jumps over the lazy dog"
                    .iter()
                    .copied()
            ),
            0x414F_A339
        );
        // A sum carried on is the sum of the whole.
        let first = crc32(0, b"1234".iter().copied());
        assert_eq!(crc32(first, b"56789".iter().copied()), 0xCBF4_3926);
        assert_eq!(crc32(0x1234_5678, core::iter::empty()), 0x1234_5678);
    }
}
