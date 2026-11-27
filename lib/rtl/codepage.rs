//! Conversion between the 8-bit ANSI and OEM code pages and UTF-16: the content
//! and size rules of
//! [`RtlMultiByteToUnicodeN`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlmultibytetounicoden),
//! [`RtlUnicodeToMultiByteN`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodetomultibyten)
//! and
//! [`RtlUnicodeStringToAnsiString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtoansistring).
//!
//! # The table
//!
//! Bytes below 0x80 are ASCII. The upper half is transcribed from the
//! mapping file Microsoft gave the Unicode Consortium: [`ANSI_1252`] is
//! `MAPPINGS/VENDORS/MICSFT/WINDOWS/CP1252.TXT`; the five bytes it
//! leaves undefined (81, 8D, 8F, 90, 9D) map to the control characters
//! of the same value, as
//! `MAPPINGS/VENDORS/MICSFT/WindowsBestFit/bestfit1252.txt` has them.
//! Both under <https://www.unicode.org/Public/>.
//!
//! [`BEST_FIT_1252`] is Windows' own: for a unit 1252 has no byte for,
//! the byte `RtlUnicodeToMultiByteN` gives on Windows 10 (10.0.19045)
//! where that is not `?`: an accented or fullwidth letter becomes its
//! plain form, a dash a hyphen. 452 units, recorded there by the
//! conformance driver `nkc-rtl`, which returns the byte of every unit
//! (`oracle/nkc-rtl-tables.txt`). The same recording has Windows' unit
//! for each of the 256 bytes, which are those of [`ANSI_1252`]. Tests
//! here compare both directions, every byte and every unit.
//!
//! # INFERRED
//!
//! - That the pinned Windows, installed with the English (United
//!   States) system locale, has 1252 as its ANSI page.
//! - `RtlUnicodeStringToAnsiString` into a buffer that is too small
//!   stores what fits, terminated, and returns `STATUS_BUFFER_OVERFLOW`.
//!   It needs room for the terminator. Microsoft's page says only that
//!   the routine fails.

/// An 8-bit code page whose lower half is ASCII.
pub struct CodePage {
    /// The UTF-16 units of bytes 0x80 to 0xFF.
    high: [u16; 128],
    /// The byte to use for a unit the page has no byte for, ascending
    /// by unit.
    best_fit: &'static [(u16, u8)],
}

/// Windows' best fit for code page 1252: a unit and its byte.
#[rustfmt::skip]
static BEST_FIT_1252: [(u16, u8); 452] = [
    (0x0100, 0x41), (0x0101, 0x61), (0x0102, 0x41), (0x0103, 0x61), (0x0104, 0x41), (0x0105, 0x61),
    (0x0106, 0x43), (0x0107, 0x63), (0x0108, 0x43), (0x0109, 0x63), (0x010A, 0x43), (0x010B, 0x63),
    (0x010C, 0x43), (0x010D, 0x63), (0x010E, 0x44), (0x010F, 0x64), (0x0110, 0xD0), (0x0111, 0x64),
    (0x0112, 0x45), (0x0113, 0x65), (0x0114, 0x45), (0x0115, 0x65), (0x0116, 0x45), (0x0117, 0x65),
    (0x0118, 0x45), (0x0119, 0x65), (0x011A, 0x45), (0x011B, 0x65), (0x011C, 0x47), (0x011D, 0x67),
    (0x011E, 0x47), (0x011F, 0x67), (0x0120, 0x47), (0x0121, 0x67), (0x0122, 0x47), (0x0123, 0x67),
    (0x0124, 0x48), (0x0125, 0x68), (0x0126, 0x48), (0x0127, 0x68), (0x0128, 0x49), (0x0129, 0x69),
    (0x012A, 0x49), (0x012B, 0x69), (0x012C, 0x49), (0x012D, 0x69), (0x012E, 0x49), (0x012F, 0x69),
    (0x0130, 0x49), (0x0131, 0x69), (0x0134, 0x4A), (0x0135, 0x6A), (0x0136, 0x4B), (0x0137, 0x6B),
    (0x0139, 0x4C), (0x013A, 0x6C), (0x013B, 0x4C), (0x013C, 0x6C), (0x013D, 0x4C), (0x013E, 0x6C),
    (0x0141, 0x4C), (0x0142, 0x6C), (0x0143, 0x4E), (0x0144, 0x6E), (0x0145, 0x4E), (0x0146, 0x6E),
    (0x0147, 0x4E), (0x0148, 0x6E), (0x014C, 0x4F), (0x014D, 0x6F), (0x014E, 0x4F), (0x014F, 0x6F),
    (0x0150, 0x4F), (0x0151, 0x6F), (0x0154, 0x52), (0x0155, 0x72), (0x0156, 0x52), (0x0157, 0x72),
    (0x0158, 0x52), (0x0159, 0x72), (0x015A, 0x53), (0x015B, 0x73), (0x015C, 0x53), (0x015D, 0x73),
    (0x015E, 0x53), (0x015F, 0x73), (0x0162, 0x54), (0x0163, 0x74), (0x0164, 0x54), (0x0165, 0x74),
    (0x0166, 0x54), (0x0167, 0x74), (0x0168, 0x55), (0x0169, 0x75), (0x016A, 0x55), (0x016B, 0x75),
    (0x016C, 0x55), (0x016D, 0x75), (0x016E, 0x55), (0x016F, 0x75), (0x0170, 0x55), (0x0171, 0x75),
    (0x0172, 0x55), (0x0173, 0x75), (0x0174, 0x57), (0x0175, 0x77), (0x0176, 0x59), (0x0177, 0x79),
    (0x0179, 0x5A), (0x017A, 0x7A), (0x017B, 0x5A), (0x017C, 0x7A), (0x0180, 0x62), (0x0189, 0xD0),
    (0x0191, 0x83), (0x0197, 0x49), (0x019A, 0x6C), (0x019F, 0x4F), (0x01A0, 0x4F), (0x01A1, 0x6F),
    (0x01AB, 0x74), (0x01AE, 0x54), (0x01AF, 0x55), (0x01B0, 0x75), (0x01B6, 0x7A), (0x01C0, 0x7C),
    (0x01C3, 0x21), (0x01CD, 0x41), (0x01CE, 0x61), (0x01CF, 0x49), (0x01D0, 0x69), (0x01D1, 0x4F),
    (0x01D2, 0x6F), (0x01D3, 0x55), (0x01D4, 0x75), (0x01D5, 0x55), (0x01D6, 0x75), (0x01D7, 0x55),
    (0x01D8, 0x75), (0x01D9, 0x55), (0x01DA, 0x75), (0x01DB, 0x55), (0x01DC, 0x75), (0x01DE, 0x41),
    (0x01DF, 0x61), (0x01E4, 0x47), (0x01E5, 0x67), (0x01E6, 0x47), (0x01E7, 0x67), (0x01E8, 0x4B),
    (0x01E9, 0x6B), (0x01EA, 0x4F), (0x01EB, 0x6F), (0x01EC, 0x4F), (0x01ED, 0x6F), (0x01F0, 0x6A),
    (0x0261, 0x67), (0x02B9, 0x27), (0x02BA, 0x22), (0x02BC, 0x27), (0x02C4, 0x5E), (0x02C8, 0x27),
    (0x02C9, 0xAF), (0x02CA, 0xB4), (0x02CB, 0x60), (0x02CD, 0x5F), (0x02DA, 0xB0), (0x0300, 0x60),
    (0x0301, 0xB4), (0x0302, 0x5E), (0x0303, 0x7E), (0x0304, 0xAF), (0x0305, 0xAF), (0x0308, 0xA8),
    (0x030A, 0xB0), (0x030E, 0x22), (0x0327, 0xB8), (0x0331, 0x5F), (0x0332, 0x5F), (0x037E, 0x3B),
    (0x0393, 0x47), (0x0398, 0x54), (0x03A3, 0x53), (0x03A6, 0x46), (0x03A9, 0x4F), (0x03B1, 0x61),
    (0x03B2, 0xDF), (0x03B4, 0x64), (0x03B5, 0x65), (0x03BC, 0xB5), (0x03C0, 0x70), (0x03C3, 0x73),
    (0x03C4, 0x74), (0x03C6, 0x66), (0x04BB, 0x68), (0x0589, 0x3A), (0x066A, 0x25), (0x2000, 0x20),
    (0x2001, 0x20), (0x2002, 0x20), (0x2003, 0x20), (0x2004, 0x20), (0x2005, 0x20), (0x2006, 0x20),
    (0x2007, 0xA0), (0x2008, 0x20), (0x2009, 0x20), (0x200A, 0x20), (0x2010, 0x2D), (0x2011, 0x2D),
    (0x2012, 0x2D), (0x2015, 0x2D), (0x2017, 0x3D), (0x201B, 0x27), (0x201F, 0x22), (0x2024, 0xB7),
    (0x202F, 0xA0), (0x2032, 0x27), (0x2033, 0x22), (0x2035, 0x60), (0x2036, 0x22), (0x2044, 0x2F),
    (0x2070, 0xB0), (0x2074, 0x34), (0x2075, 0x35), (0x2076, 0x36), (0x2077, 0x37), (0x2078, 0x38),
    (0x207F, 0x6E), (0x2080, 0x30), (0x2081, 0x31), (0x2082, 0x32), (0x2083, 0x33), (0x2084, 0x34),
    (0x2085, 0x35), (0x2086, 0x36), (0x2087, 0x37), (0x2088, 0x38), (0x2089, 0x39), (0x20A1, 0xA2),
    (0x20A4, 0xA3), (0x20A7, 0x50), (0x2102, 0x43), (0x2107, 0x45), (0x210A, 0x67), (0x210B, 0x48),
    (0x210C, 0x48), (0x210D, 0x48), (0x210E, 0x68), (0x2110, 0x49), (0x2111, 0x49), (0x2112, 0x4C),
    (0x2113, 0x6C), (0x2115, 0x4E), (0x2118, 0x50), (0x2119, 0x50), (0x211A, 0x51), (0x211B, 0x52),
    (0x211C, 0x52), (0x211D, 0x52), (0x2124, 0x5A), (0x2128, 0x5A), (0x212A, 0x4B), (0x212B, 0xC5),
    (0x212C, 0x42), (0x212D, 0x43), (0x212E, 0x65), (0x212F, 0x65), (0x2130, 0x45), (0x2131, 0x46),
    (0x2133, 0x4D), (0x2134, 0x6F), (0x2205, 0xD8), (0x2212, 0x2D), (0x2213, 0xB1), (0x2215, 0x2F),
    (0x2216, 0x5C), (0x2217, 0x2A), (0x2218, 0xB0), (0x2219, 0xB7), (0x221A, 0x76), (0x221E, 0x38),
    (0x2223, 0x7C), (0x2229, 0x6E), (0x2236, 0x3A), (0x223C, 0x7E), (0x2248, 0x98), (0x2261, 0x3D),
    (0x2264, 0x3D), (0x2265, 0x3D), (0x226A, 0xAB), (0x226B, 0xBB), (0x22C5, 0xB7), (0x2302, 0xA6),
    (0x2303, 0x5E), (0x2310, 0xAC), (0x2320, 0x28), (0x2321, 0x29), (0x2329, 0x3C), (0x232A, 0x3E),
    (0x2500, 0x2D), (0x2502, 0xA6), (0x250C, 0x2B), (0x2510, 0x2B), (0x2514, 0x2B), (0x2518, 0x2B),
    (0x251C, 0x2B), (0x2524, 0xA6), (0x252C, 0x2D), (0x2534, 0x2D), (0x253C, 0x2B), (0x2550, 0x2D),
    (0x2551, 0xA6), (0x2552, 0x2B), (0x2553, 0x2B), (0x2554, 0x2B), (0x2555, 0x2B), (0x2556, 0x2B),
    (0x2557, 0x2B), (0x2558, 0x2B), (0x2559, 0x2B), (0x255A, 0x2B), (0x255B, 0x2B), (0x255C, 0x2B),
    (0x255D, 0x2B), (0x255E, 0xA6), (0x255F, 0xA6), (0x2560, 0xA6), (0x2561, 0xA6), (0x2562, 0xA6),
    (0x2563, 0xA6), (0x2564, 0x2D), (0x2565, 0x2D), (0x2566, 0x2D), (0x2567, 0x2D), (0x2568, 0x2D),
    (0x2569, 0x2D), (0x256A, 0x2B), (0x256B, 0x2B), (0x256C, 0x2B), (0x2580, 0xAF), (0x2584, 0x5F),
    (0x2588, 0xA6), (0x258C, 0xA6), (0x2590, 0xA6), (0x2591, 0xA6), (0x2592, 0xA6), (0x2593, 0xA6),
    (0x25A0, 0xA6), (0x263C, 0xA4), (0x2758, 0x7C), (0x3000, 0x20), (0x3008, 0x3C), (0x3009, 0x3E),
    (0x300A, 0xAB), (0x300B, 0xBB), (0x301A, 0x5B), (0x301B, 0x5D), (0x30FB, 0xB7), (0xFF01, 0x21),
    (0xFF02, 0x22), (0xFF03, 0x23), (0xFF04, 0x24), (0xFF05, 0x25), (0xFF06, 0x26), (0xFF07, 0x27),
    (0xFF08, 0x28), (0xFF09, 0x29), (0xFF0A, 0x2A), (0xFF0B, 0x2B), (0xFF0C, 0x2C), (0xFF0D, 0x2D),
    (0xFF0E, 0x2E), (0xFF0F, 0x2F), (0xFF10, 0x30), (0xFF11, 0x31), (0xFF12, 0x32), (0xFF13, 0x33),
    (0xFF14, 0x34), (0xFF15, 0x35), (0xFF16, 0x36), (0xFF17, 0x37), (0xFF18, 0x38), (0xFF19, 0x39),
    (0xFF1A, 0x3A), (0xFF1B, 0x3B), (0xFF1C, 0x3C), (0xFF1D, 0x3D), (0xFF1E, 0x3E), (0xFF20, 0x40),
    (0xFF21, 0x41), (0xFF22, 0x42), (0xFF23, 0x43), (0xFF24, 0x44), (0xFF25, 0x45), (0xFF26, 0x46),
    (0xFF27, 0x47), (0xFF28, 0x48), (0xFF29, 0x49), (0xFF2A, 0x4A), (0xFF2B, 0x4B), (0xFF2C, 0x4C),
    (0xFF2D, 0x4D), (0xFF2E, 0x4E), (0xFF2F, 0x4F), (0xFF30, 0x50), (0xFF31, 0x51), (0xFF32, 0x52),
    (0xFF33, 0x53), (0xFF34, 0x54), (0xFF35, 0x55), (0xFF36, 0x56), (0xFF37, 0x57), (0xFF38, 0x58),
    (0xFF39, 0x59), (0xFF3A, 0x5A), (0xFF3B, 0x5B), (0xFF3C, 0x5C), (0xFF3D, 0x5D), (0xFF3E, 0x5E),
    (0xFF3F, 0x5F), (0xFF40, 0x60), (0xFF41, 0x61), (0xFF42, 0x62), (0xFF43, 0x63), (0xFF44, 0x64),
    (0xFF45, 0x65), (0xFF46, 0x66), (0xFF47, 0x67), (0xFF48, 0x68), (0xFF49, 0x69), (0xFF4A, 0x6A),
    (0xFF4B, 0x6B), (0xFF4C, 0x6C), (0xFF4D, 0x6D), (0xFF4E, 0x6E), (0xFF4F, 0x6F), (0xFF50, 0x70),
    (0xFF51, 0x71), (0xFF52, 0x72), (0xFF53, 0x73), (0xFF54, 0x74), (0xFF55, 0x75), (0xFF56, 0x76),
    (0xFF57, 0x77), (0xFF58, 0x78), (0xFF59, 0x79), (0xFF5A, 0x7A), (0xFF5B, 0x7B), (0xFF5C, 0x7C),
    (0xFF5D, 0x7D), (0xFF5E, 0x7E),
];

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
    best_fit: &BEST_FIT_1252,
};

/// Windows code page 437, the OEM page of the English (United States)
/// system locale, which FAT keeps short names in. Transcribed from
/// `MAPPINGS/VENDORS/MICSFT/PC/CP437.TXT` under
/// <https://www.unicode.org/Public/>, which maps every byte.
///
/// # INFERRED
///
/// Windows best-fits some units 437 has no byte for (its `c_437.nls`
/// carries the table); no published file or recording of Windows gives
/// those, so every unit outside the page becomes `?`.
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
    best_fit: &[],
};

impl CodePage {
    /// The UTF-16 unit of `byte`.
    pub fn to_unicode(&self, byte: u8) -> u16 {
        match byte.checked_sub(0x80) {
            Some(high) => self.high[usize::from(high)],
            None => u16::from(byte),
        }
    }

    /// The byte of `unit`: its own in the page, else its best fit, else
    /// `?`.
    pub fn from_unicode(&self, unit: u16) -> u8 {
        if unit < 0x80 {
            return unit as u8;
        }
        if let Some(high) = self.high.iter().position(|&u| u == unit) {
            return 0x80 + high as u8;
        }
        match self.best_fit.binary_search_by_key(&unit, |&(unit, _)| unit) {
            Ok(at) => self.best_fit[at].1,
            Err(_) => b'?',
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

impl CodePage {
    /// `RtlUpperChar`: the upper case of a byte, which is the byte of
    /// the upper case of its unit.
    pub fn upper(&self, byte: u8) -> u8 {
        self.from_unicode(crate::upcase_char(self.to_unicode(byte)))
    }
}

/// `RtlxAnsiStringToUnicodeSize`: the bytes an ANSI string of `length`
/// bytes takes in UTF-16, terminator included. A page of single bytes
/// makes one unit of each.
pub fn ansi_to_unicode_size(length: u16) -> u32 {
    (u32::from(length) + 1) * 2
}

/// `RtlAnsiStringToUnicodeString`: the `Length` of the result and the
/// `MaximumLength` it needs, terminator included, for a source of
/// `length` bytes. `None`, for a source whose result a counted string
/// cannot hold, is `STATUS_INVALID_PARAMETER_2`. The routine stores the
/// `Length` first; then it allocates the `MaximumLength`, or else
/// requires it of the caller's buffer and fails with
/// `STATUS_BUFFER_OVERFLOW`, converting nothing, if it is not there.
pub fn ansi_to_unicode_lengths(length: u16) -> Option<(u16, u16)> {
    let size = ansi_to_unicode_size(length);
    (size <= 0xFFFE).then_some(((size - 2) as u16, size as u16))
}

/// `RtlCompareString`: negative, zero or positive as `a` sorts before,
/// with or after `b`: the difference of the first two bytes that
/// differ, upper case against upper case if `ignore_case`, or of the
/// lengths.
pub fn compare_string(
    page: &CodePage,
    a: impl ExactSizeIterator<Item = u8>,
    b: impl ExactSizeIterator<Item = u8>,
    ignore_case: bool,
) -> i32 {
    let lengths = a.len() as i32 - b.len() as i32;
    let fold = |byte: u8| if ignore_case { page.upper(byte) } else { byte };
    for (x, y) in a.zip(b) {
        let (x, y) = (fold(x), fold(y));
        if x != y {
            return i32::from(x) - i32::from(y);
        }
    }
    lengths
}

#[cfg(test)]
mod tests {
    #[test]
    fn oem_437_maps_every_byte_both_ways() {
        for byte in 0..=255u8 {
            assert_eq!(OEM_437.from_unicode(OEM_437.to_unicode(byte)), byte);
        }
        assert_eq!(OEM_437.to_unicode(0x41), 0x41);
        assert_eq!(OEM_437.to_unicode(0x80), 0x00C7);
        assert_eq!(OEM_437.to_unicode(0xE1), 0x00DF);
        assert_eq!(OEM_437.to_unicode(0xFF), 0x00A0);
        // A unit 437 lacks, and one it has that 1252 puts elsewhere.
        assert_eq!(OEM_437.from_unicode(0x20AC), b'?');
        assert_eq!(OEM_437.from_unicode(0x00E9), 0x82);
    }

    use super::*;

    #[test]
    fn ascii_is_itself() {
        let page = &ANSI_1252;
        for byte in 0..0x80u8 {
            assert_eq!(page.to_unicode(byte), u16::from(byte));
            assert_eq!(page.from_unicode(u16::from(byte)), byte);
        }
    }

    #[test]
    fn every_byte_survives_the_round_trip() {
        let page = &ANSI_1252;
        for byte in 0..=u8::MAX {
            assert_eq!(page.from_unicode(page.to_unicode(byte)), byte, "{byte:02X}");
        }
    }

    /// The upper half a second time, as the characters themselves in
    /// byte order, written out from the page's character chart rather
    /// than from the mapping file.
    const CHART_1252: &str = "€\u{81}‚ƒ„…†‡ˆ‰Š‹Œ\u{8D}Ž\u{8F}\u{90}‘’“”•–—˜™š›œ\u{9D}žŸ\
        \u{A0}¡¢£¤¥¦§¨©ª«¬\u{AD}®¯°±²³´µ¶·¸¹º»¼½¾¿\
        ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞß\
        àáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ";

    #[test]
    fn the_table_agrees_with_the_character_chart() {
        let chart: Vec<u16> = CHART_1252.encode_utf16().collect();
        assert_eq!(chart.len(), 128);
        for (byte, &unit) in (0x80..=0xFFu8).zip(&chart) {
            assert_eq!(ANSI_1252.to_unicode(byte), unit, "{byte:02X}");
        }
    }

    #[test]
    fn known_characters() {
        for (byte, unit) in [
            (0x80, 0x20AC), // euro sign
            (0x81, 0x0081), // undefined in 1252
            (0x8D, 0x008D),
            (0x8F, 0x008F),
            (0x90, 0x0090),
            (0x9D, 0x009D), // undefined in 1252
            (0x99, 0x2122), // trade mark
            (0x9F, 0x0178),
            (0xA0, 0x00A0), // no-break space
            (0xB0, 0x00B0), // degree
            (0xC4, 0x00C4), // A diaeresis
            (0xDB, 0x00DB), // U circumflex
            (0xE1, 0x00E1), // a acute
            (0xE9, 0x00E9), // e acute
            (0xFE, 0x00FE), // thorn
            (0xFF, 0x00FF), // y diaeresis
        ] {
            assert_eq!(ANSI_1252.to_unicode(byte), unit, "{byte:02X}");
        }
    }

    #[test]
    fn latin_1_is_itself_in_1252_from_a0_up() {
        for byte in 0xA0..=0xFFu8 {
            assert_eq!(ANSI_1252.to_unicode(byte), u16::from(byte));
        }
    }

    #[test]
    fn a_unit_the_page_lacks_is_its_best_fit_or_a_question_mark() {
        // The euro sign is in 1252; theta is not, and 1252 makes do
        // with a `T`.
        assert_eq!(ANSI_1252.from_unicode(0x20AC), 0x80);
        assert_eq!(ANSI_1252.from_unicode(0x0398), b'T');
        // C1 controls: only the five 1252 leaves undefined.
        assert_eq!(ANSI_1252.from_unicode(0x0081), 0x81);
        assert_eq!(ANSI_1252.from_unicode(0x0080), b'?');
        for (unit, byte) in [
            (0x0100, b'A'), // A macron: the first best fit
            (0x0141, b'L'), // L stroke
            (0x0110, 0xD0), // D stroke: eth
            (0x2013, 0x96), // en dash: its own byte
            (0x2010, b'-'), // hyphen
            (0x2248, 0x98), // almost equal: the small tilde
            (0xFF21, b'A'), // fullwidth A
            (0xFF5E, b'~'), // the last best fit
            (0xFF5F, b'?'),
            (0x4E00, b'?'), // a Han character
            (0xD800, b'?'),
            (0xFFFF, b'?'),
        ] {
            assert_eq!(ANSI_1252.from_unicode(unit), byte, "{unit:04X}");
        }
    }

    #[test]
    fn the_ansi_page_is_the_one_recorded_on_windows() {
        let to_unicode = crate::recorded::to_unicode();
        assert_eq!(to_unicode.len(), 256);
        for (byte, &unit) in (0..=u8::MAX).zip(&to_unicode) {
            assert_eq!(ANSI_1252.to_unicode(byte), unit, "{byte:02X}");
        }
        let to_ansi = crate::recorded::to_ansi();
        assert_eq!(to_ansi.len(), 0x1_0000);
        for (unit, &byte) in (0..=u16::MAX).zip(&to_ansi) {
            assert_eq!(ANSI_1252.from_unicode(unit), byte, "{unit:04X}");
        }
    }

    /// The best fits are ascending, for the search; none is for a unit
    /// the page has a byte for, and none is `?`. The whole of what
    /// 1252 makes of the 65536 units, in a hash (FNV-1a over the
    /// bytes), is what Windows 10 makes of them.
    #[test]
    fn the_best_fit_is_the_one_recorded_on_windows() {
        for pair in BEST_FIT_1252.windows(2) {
            assert!(pair[0].0 < pair[1].0, "{:04X}", pair[1].0);
        }
        for &(unit, byte) in &BEST_FIT_1252 {
            assert!(
                unit >= 0x80 && !ANSI_1252.high.contains(&unit),
                "{unit:04X}"
            );
            assert_ne!(byte, b'?', "{unit:04X}");
        }
        let hash = (0..=u16::MAX).fold(2_166_136_261u32, |hash, unit| {
            (hash ^ u32::from(ANSI_1252.from_unicode(unit))).wrapping_mul(16_777_619)
        });
        assert_eq!(hash, 0xCE2B1F5D);
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
    fn upper_case_of_a_byte_goes_through_its_unit() {
        let page = &ANSI_1252;
        for byte in 0..0x80u8 {
            assert_eq!(page.upper(byte), byte.to_ascii_uppercase());
        }
        assert_eq!(page.upper(0xE9), 0xC9); // e acute
        assert_eq!(page.upper(0xFF), 0x9F); // y diaeresis: its capital is in the page
        assert_eq!(page.upper(0x9A), 0x8A); // s caron
        assert_eq!(page.upper(0xDF), 0xDF); // sharp s has no single capital
        assert_eq!(page.upper(0xF7), 0xF7); // the division sign
        assert_eq!(page.upper(0xC9), 0xC9);
    }

    #[test]
    fn ansi_to_unicode_sizes() {
        assert_eq!(ansi_to_unicode_size(0), 2);
        assert_eq!(ansi_to_unicode_size(5), 12);
        assert_eq!(ansi_to_unicode_size(0xFFFF), 0x2_0000);
        assert_eq!(ansi_to_unicode_lengths(0), Some((0, 2)));
        assert_eq!(ansi_to_unicode_lengths(5), Some((10, 12)));
        assert_eq!(ansi_to_unicode_lengths(0x7FFE), Some((0xFFFC, 0xFFFE)));
        assert_eq!(ansi_to_unicode_lengths(0x7FFF), None);
        assert_eq!(ansi_to_unicode_lengths(0xFFFF), None);
    }

    #[test]
    fn byte_strings_compare_by_byte_then_length() {
        let compare = |a: &[u8], b: &[u8], ignore_case| {
            compare_string(
                &ANSI_1252,
                a.iter().copied(),
                b.iter().copied(),
                ignore_case,
            )
        };
        assert_eq!(compare(b"abc", b"abc", false), 0);
        assert_eq!(compare(b"abc", b"abd", false), -1);
        assert_eq!(compare(b"abd", b"abc", true), 1);
        assert_eq!(compare(b"abc", b"ABC", false), 0x20);
        assert_eq!(compare(b"abc", b"ABC", true), 0);
        assert_eq!(compare(b"abc", b"ab", false), 1);
        assert_eq!(compare(b"ab", b"abcd", true), -2);
        assert_eq!(compare(b"", b"", true), 0);
        assert_eq!(compare(b"", b"a", false), -1);
        // Bytes are unsigned, and upper case is the page's.
        assert_eq!(compare(b"\xE9", b"a", false), 0xE9 - 0x61);
        assert_eq!(compare(b"\xE9", b"\xC9", true), 0);
        assert_eq!(compare(b"\xE9", b"\xC9", false), 0x20);
        // Upper case, not lower: `_` sorts after `A`.
        assert_eq!(compare(b"_", b"a", true), 0x5F - 0x41);
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
