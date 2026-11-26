//! Conversion between the 8-bit code pages and UTF-16: the content and
//! size rules of
//! [`RtlMultiByteToUnicodeN`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlmultibytetounicoden),
//! [`RtlUnicodeToMultiByteN`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodetomultibyten),
//! [`RtlAnsiStringToUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlansistringtounicodestring)
//! and
//! [`RtlUnicodeStringToAnsiString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtoansistring).
//!
//! # The tables
//!
//! Bytes below 0x80 are ASCII in both pages. The upper halves are
//! transcribed from the mapping files Microsoft gave the Unicode
//! Consortium:
//!
//! - [`ANSI_1252`] is `MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1252.TXT`; the
//!   five bytes it leaves undefined (81, 8D, 8F, 90, 9D) map to the
//!   control characters of the same value, as
//!   `MAPPINGS/VENDORS/MICSFT/WindowsBestFit/bestfit1252.txt` has them;
//! - [`OEM_437`] is `MAPPINGS/VENDORS/MICSFT/PC/CP437.TXT`.
//!
//! All under <https://www.unicode.org/Public/>.
//!
//! # INFERRED
//!
//! - That the pinned Windows, installed with the English (United
//!   States) system locale, has 1252 as its ANSI page and 437 as its
//!   OEM page.
//! - A UTF-16 unit the page has no byte for becomes `?`. Windows first
//!   tries a "best fit" (the second half of `bestfit1252.txt`: a
//!   fullwidth or accented letter to its plain form, say); that table
//!   is not here.
//! - `RtlUnicodeStringToAnsiString` into a buffer that is too small
//!   stores what fits, terminated, and returns `STATUS_BUFFER_OVERFLOW`;
//!   `RtlAnsiStringToUnicodeString` in the same position stores nothing.
//!   Both need room for the terminator. Microsoft's pages say only that
//!   the routines fail.

/// An 8-bit code page whose lower half is ASCII.
pub struct CodePage {
    /// The UTF-16 units of bytes 0x80 to 0xFF.
    high: [u16; 128],
}

/// Windows code page 1252, "ANSI Latin 1".
#[rustfmt::skip]
pub static ANSI_1252: CodePage = CodePage {
    high: [
        0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
        0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
        0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
        0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
        0x00A0, 0x00A1, 0x00A2, 0x00A3, 0x00A4, 0x00A5, 0x00A6, 0x00A7,
        0x00A8, 0x00A9, 0x00AA, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x00AF,
        0x00B0, 0x00B1, 0x00B2, 0x00B3, 0x00B4, 0x00B5, 0x00B6, 0x00B7,
        0x00B8, 0x00B9, 0x00BA, 0x00BB, 0x00BC, 0x00BD, 0x00BE, 0x00BF,
        0x00C0, 0x00C1, 0x00C2, 0x00C3, 0x00C4, 0x00C5, 0x00C6, 0x00C7,
        0x00C8, 0x00C9, 0x00CA, 0x00CB, 0x00CC, 0x00CD, 0x00CE, 0x00CF,
        0x00D0, 0x00D1, 0x00D2, 0x00D3, 0x00D4, 0x00D5, 0x00D6, 0x00D7,
        0x00D8, 0x00D9, 0x00DA, 0x00DB, 0x00DC, 0x00DD, 0x00DE, 0x00DF,
        0x00E0, 0x00E1, 0x00E2, 0x00E3, 0x00E4, 0x00E5, 0x00E6, 0x00E7,
        0x00E8, 0x00E9, 0x00EA, 0x00EB, 0x00EC, 0x00ED, 0x00EE, 0x00EF,
        0x00F0, 0x00F1, 0x00F2, 0x00F3, 0x00F4, 0x00F5, 0x00F6, 0x00F7,
        0x00F8, 0x00F9, 0x00FA, 0x00FB, 0x00FC, 0x00FD, 0x00FE, 0x00FF,
    ],
};

/// Code page 437, the original IBM PC's.
#[rustfmt::skip]
pub static OEM_437: CodePage = CodePage {
    high: [
        0x00C7, 0x00FC, 0x00E9, 0x00E2, 0x00E4, 0x00E0, 0x00E5, 0x00E7,
        0x00EA, 0x00EB, 0x00E8, 0x00EF, 0x00EE, 0x00EC, 0x00C4, 0x00C5,
        0x00C9, 0x00E6, 0x00C6, 0x00F4, 0x00F6, 0x00F2, 0x00FB, 0x00F9,
        0x00FF, 0x00D6, 0x00DC, 0x00A2, 0x00A3, 0x00A5, 0x20A7, 0x0192,
        0x00E1, 0x00ED, 0x00F3, 0x00FA, 0x00F1, 0x00D1, 0x00AA, 0x00BA,
        0x00BF, 0x2310, 0x00AC, 0x00BD, 0x00BC, 0x00A1, 0x00AB, 0x00BB,
        0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
        0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
        0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F,
        0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
        0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B,
        0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
        0x03B1, 0x00DF, 0x0393, 0x03C0, 0x03A3, 0x03C3, 0x00B5, 0x03C4,
        0x03A6, 0x0398, 0x03A9, 0x03B4, 0x221E, 0x03C6, 0x03B5, 0x2229,
        0x2261, 0x00B1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00F7, 0x2248,
        0x00B0, 0x2219, 0x00B7, 0x221A, 0x207F, 0x00B2, 0x25A0, 0x00A0,
    ],
};

impl CodePage {
    /// The UTF-16 unit of `byte`.
    pub fn to_unicode(&self, byte: u8) -> u16 {
        match byte.checked_sub(0x80) {
            Some(high) => self.high[usize::from(high)],
            None => u16::from(byte),
        }
    }

    /// The byte of `unit`; `?` if the page has none.
    pub fn from_unicode(&self, unit: u16) -> u8 {
        if unit < 0x80 {
            return unit as u8;
        }
        match self.high.iter().position(|&u| u == unit) {
            Some(high) => 0x80 + high as u8,
            None => b'?',
        }
    }
}

/// How many characters `RtlMultiByteToUnicodeN` converts: as many as
/// the source has, or as fit. An odd last byte of room is no room;
/// `BytesInUnicodeString` is twice the count, and no terminator is
/// written. Windows reports no truncation: the status is
/// `STATUS_SUCCESS` either way, and the count alone tells.
pub fn multibyte_to_unicode_chars(max_bytes_in_unicode: u32, bytes_in_multibyte: u32) -> u32 {
    bytes_in_multibyte.min(max_bytes_in_unicode / 2)
}

/// How many characters `RtlUnicodeToMultiByteN` converts: as many as
/// the source has, or as fit; and whether that is all of them. If it
/// is not the status is `STATUS_BUFFER_OVERFLOW`. An odd last byte of
/// the source is not a character; `BytesInMultiByteString` is the
/// count, and no terminator is written.
pub fn unicode_to_multibyte_chars(
    max_bytes_in_multibyte: u32,
    bytes_in_unicode: u32,
) -> (u32, bool) {
    let chars = bytes_in_unicode / 2;
    (
        chars.min(max_bytes_in_multibyte),
        chars <= max_bytes_in_multibyte,
    )
}

/// `RtlAnsiStringToUnicodeString`: the `Length` of the result and the
/// `MaximumLength` it needs, terminator included, for a source of
/// `ansi_length` bytes. The routine allocates that much, or fails with
/// `STATUS_BUFFER_OVERFLOW` if the caller's buffer is smaller. None if
/// the result cannot be a counted string
/// (`STATUS_INVALID_PARAMETER_2`).
pub fn ansi_to_unicode_lengths(ansi_length: u16) -> Option<(u16, u16)> {
    let needed = u16::try_from((u32::from(ansi_length) + 1) * 2).ok()?;
    Some((needed - 2, needed))
}

/// `RtlUnicodeStringToAnsiString`: the `Length` of the result and the
/// `MaximumLength` it needs, terminator included, for a source of
/// `unicode_length` bytes. The routine allocates that much, or stores
/// as [`unicode_to_ansi_stored`] says.
pub fn unicode_to_ansi_lengths(unicode_length: u16) -> (u16, u16) {
    let chars = unicode_length / 2;
    (chars, chars + 1)
}

/// `RtlUnicodeStringToAnsiString` into the caller's buffer of
/// `destination_maximum` bytes: the `Length` stored, a terminator after
/// it, and whether that is the whole string. If it is not, or if
/// nothing can be stored (None), the status is
/// `STATUS_BUFFER_OVERFLOW`.
pub fn unicode_to_ansi_stored(
    unicode_length: u16,
    destination_maximum: u16,
) -> Option<(u16, bool)> {
    let (length, needed) = unicode_to_ansi_lengths(unicode_length);
    if needed <= destination_maximum {
        Some((length, true))
    } else {
        Some((destination_maximum.checked_sub(1)?, false))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_is_itself_in_both_pages() {
        for page in [&ANSI_1252, &OEM_437] {
            for byte in 0..0x80u8 {
                assert_eq!(page.to_unicode(byte), u16::from(byte));
                assert_eq!(page.from_unicode(u16::from(byte)), byte);
            }
        }
    }

    #[test]
    fn every_byte_survives_the_round_trip() {
        for page in [&ANSI_1252, &OEM_437] {
            for byte in 0..=u8::MAX {
                assert_eq!(page.from_unicode(page.to_unicode(byte)), byte, "{byte:02X}");
            }
        }
    }

    /// The upper halves a second time, as the characters themselves in
    /// byte order, written out from the pages' character charts rather
    /// than from the mapping files.
    const CHART_1252: &str = "€\u{81}‚ƒ„…†‡ˆ‰Š‹Œ\u{8D}Ž\u{8F}\u{90}‘’“”•–—˜™š›œ\u{9D}žŸ\
        \u{A0}¡¢£¤¥¦§¨©ª«¬\u{AD}®¯°±²³´µ¶·¸¹º»¼½¾¿\
        ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß\
        àáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ";
    const CHART_437: &str = "ÇüéâäàåçêëèïîìÄÅÉæÆôöòûùÿÖÜ¢£¥₧ƒ\
        áíóúñÑªº¿⌐¬½¼¡«»░▒▓│┤╡╢╖╕╣║╗╝╜╛┐\
        └┴┬├─┼╞╟╚╔╩╦╠═╬╧╨╤╥╙╘╒╓╫╪┘┌█▄▌▐▀\
        αßΓπΣσµτΦΘΩδ∞φε∩≡±≥≤⌠⌡÷≈°∙·√ⁿ²■\u{A0}";

    #[test]
    fn the_tables_agree_with_the_character_charts() {
        for (page, chart) in [(&ANSI_1252, CHART_1252), (&OEM_437, CHART_437)] {
            let chart: Vec<u16> = chart.encode_utf16().collect();
            assert_eq!(chart.len(), 128);
            for (byte, &unit) in (0x80..=0xFFu8).zip(&chart) {
                assert_eq!(page.to_unicode(byte), unit, "{byte:02X}");
            }
        }
    }

    #[test]
    fn known_characters() {
        // (byte, unit in 1252, unit in 437)
        for (byte, ansi, oem) in [
            (0x80, 0x20AC, 0x00C7), // euro sign; C cedilla
            (0x81, 0x0081, 0x00FC), // undefined in 1252; u diaeresis
            (0x8D, 0x008D, 0x00EC),
            (0x8F, 0x008F, 0x00C5),
            (0x90, 0x0090, 0x00C9),
            (0x9D, 0x009D, 0x00A5), // undefined in 1252; yen sign
            (0x99, 0x2122, 0x00D6), // trade mark; O diaeresis
            (0x9F, 0x0178, 0x0192),
            (0xA0, 0x00A0, 0x00E1), // no-break space; a acute
            (0xB0, 0x00B0, 0x2591), // degree; light shade
            (0xC4, 0x00C4, 0x2500), // A diaeresis; box horizontal
            (0xDB, 0x00DB, 0x2588), // U circumflex; full block
            (0xE1, 0x00E1, 0x00DF), // a acute; sharp s
            (0xE9, 0x00E9, 0x0398), // e acute; theta
            (0xFE, 0x00FE, 0x25A0), // thorn; black square
            (0xFF, 0x00FF, 0x00A0), // y diaeresis; no-break space
        ] {
            assert_eq!(ANSI_1252.to_unicode(byte), ansi, "{byte:02X}");
            assert_eq!(OEM_437.to_unicode(byte), oem, "{byte:02X}");
        }
    }

    #[test]
    fn latin_1_is_itself_in_1252_from_a0_up() {
        for byte in 0xA0..=0xFFu8 {
            assert_eq!(ANSI_1252.to_unicode(byte), u16::from(byte));
        }
    }

    #[test]
    fn a_unit_the_page_lacks_is_a_question_mark() {
        // The euro sign is in 1252 and not in 437; theta the reverse.
        assert_eq!(ANSI_1252.from_unicode(0x20AC), 0x80);
        assert_eq!(OEM_437.from_unicode(0x20AC), b'?');
        assert_eq!(OEM_437.from_unicode(0x0398), 0xE9);
        assert_eq!(ANSI_1252.from_unicode(0x0398), b'?');
        // C1 controls: only the five 1252 leaves undefined.
        assert_eq!(ANSI_1252.from_unicode(0x0081), 0x81);
        assert_eq!(ANSI_1252.from_unicode(0x0080), b'?');
        for page in [&ANSI_1252, &OEM_437] {
            assert_eq!(page.from_unicode(0xFF21), b'?', "no best fit");
            assert_eq!(page.from_unicode(0xD800), b'?');
            assert_eq!(page.from_unicode(0xFFFF), b'?');
        }
    }

    #[test]
    fn multibyte_to_unicode_truncates() {
        for (max_bytes, source, chars) in [
            (0, 0, 0),
            (10, 5, 5),
            (10, 3, 3),
            (10, 8, 5),
            (11, 8, 5),
            (4, 3, 2),
            (5, 3, 2),
            (1, 8, 0),
            (0, 8, 0),
            (u32::MAX, u32::MAX, u32::MAX / 2),
        ] {
            assert_eq!(
                multibyte_to_unicode_chars(max_bytes, source),
                chars,
                "{source} into {max_bytes}"
            );
        }
        for (max_bytes, source, chars, all) in [
            (0, 0, 0, true),
            (4, 2, 1, true),
            (4, 8, 4, true),
            (4, 9, 4, true),
            (4, 10, 4, false),
            (0, 2, 0, false),
            (u32::MAX, u32::MAX, u32::MAX / 2, true),
        ] {
            assert_eq!(
                unicode_to_multibyte_chars(max_bytes, source),
                (chars, all),
                "{source} into {max_bytes}"
            );
        }
    }

    #[test]
    fn ansi_to_unicode_sizes() {
        assert_eq!(ansi_to_unicode_lengths(0), Some((0, 2)));
        assert_eq!(ansi_to_unicode_lengths(5), Some((10, 12)));
        assert_eq!(ansi_to_unicode_lengths(0x7FFE), Some((0xFFFC, 0xFFFE)));
        assert_eq!(ansi_to_unicode_lengths(0x7FFF), None);
        assert_eq!(ansi_to_unicode_lengths(0xFFFF), None);
    }

    #[test]
    fn unicode_to_ansi_sizes() {
        assert_eq!(unicode_to_ansi_lengths(0), (0, 1));
        assert_eq!(unicode_to_ansi_lengths(10), (5, 6));
        assert_eq!(unicode_to_ansi_lengths(11), (5, 6), "an odd length");
        assert_eq!(unicode_to_ansi_lengths(0xFFFE), (0x7FFF, 0x8000));
        for (unicode, maximum, expected) in [
            (10, 6, Some((5, true))),
            (10, 100, Some((5, true))),
            (10, 5, Some((4, false))),
            (10, 1, Some((0, false))),
            (10, 0, None),
            (0, 1, Some((0, true))),
            (0, 0, None),
        ] {
            assert_eq!(
                unicode_to_ansi_stored(unicode, maximum),
                expected,
                "{unicode} into {maximum}"
            );
        }
    }
}
