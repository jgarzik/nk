//! Windows NLS binary table builders (`C_1252.NLS`, `C_437.NLS`, `l_intl.nls`).
//!
//! Layout verified against `ntdll!RtlInitCodePageTable`, `ntdll!RtlInitNlsTables`,
//! and `ntdll!RtlUpcaseUnicodeChar` in Windows 10 19041.1949:
//!
//! - **Code-page table (`C_1252.NLS`, `C_437.NLS`)**, array of `u16` words:
//!   - `w[0]`: header size in words (`13`).
//!   - `w[1]`: code page number (`1252` or `437`).
//!   - `w[2]`: `MaximumCharacterSize` (`1` for SBCS).
//!   - `w[3..=6]`: `DefaultChar`, `UniDefaultChar`, `TransDefaultChar`, `TransUniDefaultChar` (`0x003F`).
//!   - `w[7..13]`: `LeadByte[12]` (all zero for SBCS).
//!   - `w[13]`: word distance from `w[13]` to the WideCharTable header word (`259` for SBCS without OEM glyphs).
//!   - `w[14..270]`: 256-entry `MultiByteTable` (`u16` Unicode code point per SBCS byte).
//!   - `w[270]`: OEM glyph-table flag (`0` = absent).
//!   - `w[271]`: DBCS range count (`0`).
//!   - `w[272]`: WideCharTable flag (`0` = 65536-byte SBCS lookup array follows).
//!   - `bytes[546..546 + 65536]`: `WideCharTable[u16]` -> SBCS byte (`0x3F` if unmapped).
//!
//! - **Unicode case table (`l_intl.nls`)**, array of `u16` words:
//!   - `w[0]`: version (`1`).
//!   - `w[1]`: word length of `UpperCaseTable` (so `LowerCaseTable` starts at `&w[2 + w[1]]`).
//!   - `w[2 .. 2 + upper_len]`: 3-level uppercase delta table.
//!   - `w[2 + upper_len ..]`: 3-level lowercase delta table.
//!   - Lookup of `c: u16`: `p1 = t[c >> 8]`, `p2 = t[p1 + ((c >> 4) & 0xF)]`,
//!     `delta = t[p2 + (c & 0xF)]`, result = `c.wrapping_add(delta)`.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

/// Header length of a Windows SBCS `.NLS` code-page file in 16-bit words.
const CP_HEADER_WORDS: u16 = 13;
/// Word offset from `w[13]` (`mb_table_size`) to `w[272]` (before `WideCharTable` at `w[273]`).
const SBCS_MB_TABLE_WORDS: u16 = 259;
/// Default substitution character (`'?'`).
const DEFAULT_CHAR: u16 = 0x003F;

/// Unicode Consortium Windows-1252 mappings for bytes `0x80..=0xFF`.
/// Undefined positions (`0x81`, `0x8D`, `0x8F`, `0x90`, `0x9D`) map to C1 control
/// code points of the same numeric value, matching Windows' `C_1252.NLS`.
#[rustfmt::skip]
const CP1252_HIGH: [u16; 128] = [
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
];

/// Unicode Consortium IBM/OEM Code Page 437 mappings for bytes `0x80..=0xFF`.
#[rustfmt::skip]
const CP437_HIGH: [u16; 128] = [
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
];

/// Build a single-byte Windows `.NLS` code-page file from its code-page ID
/// and the 128 Unicode mappings for bytes `0x80..=0xFF`.
pub fn build_sbcs(code_page: u16, high: &[u16; 128]) -> Vec<u8> {
    let mut words = Vec::with_capacity(273);
    // Header (13 words).
    words.push(CP_HEADER_WORDS);
    words.push(code_page);
    words.push(1); // MaximumCharacterSize
    words.push(DEFAULT_CHAR);
    words.push(DEFAULT_CHAR);
    words.push(DEFAULT_CHAR);
    words.push(DEFAULT_CHAR);
    words.extend_from_slice(&[0u16; 6]); // LeadByte[12]
    // MultiByte section.
    words.push(SBCS_MB_TABLE_WORDS);
    for b in 0..128u16 {
        words.push(b);
    }
    words.extend_from_slice(high);
    words.push(0); // OEM glyph table flag: absent
    words.push(0); // DBCS range count: 0
    words.push(0); // WideCharTable flag: SBCS byte array
    debug_assert_eq!(words.len(), 273);

    let mut out = Vec::with_capacity(words.len() * 2 + 65536);
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    let mut wc = vec![DEFAULT_CHAR as u8; 65536];
    for b in 0..128u8 {
        wc[usize::from(b)] = b;
    }
    for (idx, &cp) in high.iter().enumerate() {
        wc[usize::from(cp)] = (idx + 128) as u8;
    }
    out.extend_from_slice(&wc);
    out
}

/// Build `C_1252.NLS` (Windows ANSI Latin-1).
pub fn c_1252() -> Vec<u8> {
    build_sbcs(1252, &CP1252_HIGH)
}

/// Build `C_437.NLS` (OEM United States).
pub fn c_437() -> Vec<u8> {
    build_sbcs(437, &CP437_HIGH)
}

/// Build one 3-level Windows case-folding delta table (`UpperCaseTable` or
/// `LowerCaseTable`) over the BMP (`0x0000..=0xFFFF`).
fn build_case_half(map_char: fn(u16) -> u16) -> Vec<u16> {
    // Words 0..256: level-1 index by `c >> 8`.
    // Words 256..272: shared all-zero level-2 block (each entry points to 272).
    // Words 272..288: shared all-zero level-3 block (each delta is 0).
    let mut table = vec![0u16; 288];
    for slot in &mut table[256..272] {
        *slot = 272;
    }
    for page in 0..256usize {
        let l2 = [272u16; 16];
        let mut page_has_mapping = false;
        let mut pending_l3: [(usize, [u16; 16]); 16] = [(0, [0; 16]); 16];
        let mut pending_count = 0usize;
        for row in 0..16usize {
            let mut deltas = [0u16; 16];
            let mut row_has_mapping = false;
            for (col, slot) in deltas.iter_mut().enumerate() {
                let c = ((page << 8) | (row << 4) | col) as u16;
                let mapped = map_char(c);
                let delta = mapped.wrapping_sub(c);
                if delta != 0 {
                    *slot = delta;
                    row_has_mapping = true;
                }
            }
            if row_has_mapping {
                page_has_mapping = true;
                pending_l3[pending_count] = (row, deltas);
                pending_count += 1;
            }
        }
        if !page_has_mapping {
            table[page] = 256;
            continue;
        }
        let l2_off = table.len() as u16;
        table.extend_from_slice(&l2);
        for &(row, deltas) in &pending_l3[..pending_count] {
            let l3_off = table.len() as u16;
            table[usize::from(l2_off) + row] = l3_off;
            table.extend_from_slice(&deltas);
        }
        table[page] = l2_off;
    }
    table
}

fn single_bmp_upper(c: u16) -> u16 {
    let Some(ch) = char::from_u32(u32::from(c)) else {
        return c;
    };
    let mut it = ch.to_uppercase();
    let Some(first) = it.next() else {
        return c;
    };
    if it.next().is_some() {
        return c;
    }
    u16::try_from(u32::from(first)).unwrap_or(c)
}

fn single_bmp_lower(c: u16) -> u16 {
    let Some(ch) = char::from_u32(u32::from(c)) else {
        return c;
    };
    let mut it = ch.to_lowercase();
    let Some(first) = it.next() else {
        return c;
    };
    if it.next().is_some() {
        return c;
    }
    u16::try_from(u32::from(first)).unwrap_or(c)
}

/// Build `l_intl.nls` (BMP 1-to-1 uppercase and lowercase folding tables).
pub fn l_intl() -> Vec<u8> {
    let upper = build_case_half(single_bmp_upper);
    let lower = build_case_half(single_bmp_lower);
    let mut out = Vec::with_capacity((2 + upper.len() + lower.len()) * 2);
    out.extend_from_slice(&1u16.to_le_bytes()); // version
    out.extend_from_slice(&(upper.len() as u16).to_le_bytes());
    for w in upper {
        out.extend_from_slice(&w.to_le_bytes());
    }
    for w in lower {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

/// Look up `c` in a Windows 3-level case table (`UpperCaseTable` or
/// `LowerCaseTable`, starting at its first `u16` word).
pub fn fold_char(table_bytes: &[u8], c: u16) -> u16 {
    let read_u16 = |word_idx: usize| -> u16 {
        let at = word_idx * 2;
        u16::from_le_bytes([table_bytes[at], table_bytes[at + 1]])
    };
    let p1 = usize::from(read_u16(usize::from(c >> 8)));
    let p2 = usize::from(read_u16(p1 + usize::from((c >> 4) & 0xF)));
    let delta = read_u16(p2 + usize::from(c & 0xF));
    c.wrapping_add(delta)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn word(bytes: &[u8], index: usize) -> u16 {
        u16::from_le_bytes([bytes[index * 2], bytes[index * 2 + 1]])
    }

    /// Reproduce `ntdll!RtlInitCodePageTable`'s exact pointer arithmetic.
    fn parse_sbcs(data: &[u8]) -> (u16, usize, usize) {
        let hdr_words = usize::from(word(data, 0));
        let cp = word(data, 1);
        let mb_size = usize::from(word(data, hdr_words));
        let mb_table_off = (hdr_words + 1) * 2;
        let glyph_flag = word(data, hdr_words + 1 + 256);
        assert_eq!(glyph_flag, 0);
        let dbcs_count = word(data, hdr_words + 1 + 256 + 1);
        assert_eq!(dbcs_count, 0);
        let wc_table_off = (hdr_words + mb_size + 1) * 2;
        (cp, mb_table_off, wc_table_off)
    }

    #[test]
    fn code_page_1252_and_437_round_trip() {
        for (expected_cp, data, sample_byte, sample_uni) in [
            (1252u16, c_1252(), 0x80u8, 0x20ACu16), // Euro sign
            (1252u16, c_1252(), 0xE9u8, 0x00E9u16), // Latin small e with acute
            (437u16, c_437(), 0xB3u8, 0x2502u16),   // Box drawings light vertical
            (437u16, c_437(), 0xE0u8, 0x03B1u16),   // Greek small letter alpha
        ] {
            let (cp, mb_off, wc_off) = parse_sbcs(&data);
            assert_eq!(cp, expected_cp);
            assert_eq!(data.len(), wc_off + 65536);
            let got_uni = word(&data[mb_off..], usize::from(sample_byte));
            assert_eq!(got_uni, sample_uni);
            assert_eq!(data[wc_off + usize::from(sample_uni)], sample_byte);
            // Every ASCII byte round-trips identically.
            for b in 0..128u8 {
                assert_eq!(word(&data[mb_off..], usize::from(b)), u16::from(b));
                assert_eq!(data[wc_off + usize::from(b)], b);
            }
            // Unmapped Unicode code point falls back to '?'.
            assert_eq!(data[wc_off + 0x4E2D], b'?');
        }
    }

    #[test]
    fn case_table_matches_ntdll_layout_and_folds_bmp() {
        let data = l_intl();
        assert_eq!(word(&data, 0), 1);
        let upper_words = usize::from(word(&data, 1));
        // `RtlInitNlsTables`: UpperCaseTable = base + 4, LowerCaseTable = base + (w[1] + 2) * 2.
        let upper = &data[4..];
        let lower = &data[(upper_words + 2) * 2..];
        for (lo, hi) in [
            ('a', 'A'),
            ('z', 'Z'),
            ('\u{00E9}', '\u{00C9}'), // é / É
            ('\u{03B1}', '\u{0391}'), // α / Α
            ('\u{0436}', '\u{0416}'), // ж / Ж
        ] {
            assert_eq!(fold_char(upper, lo as u16), hi as u16);
            assert_eq!(fold_char(upper, hi as u16), hi as u16);
            assert_eq!(fold_char(lower, hi as u16), lo as u16);
            assert_eq!(fold_char(lower, lo as u16), lo as u16);
        }
        // Digits and CJK are unchanged.
        for c in ['0', '9', '/', '\\', '\u{4E2D}'] {
            assert_eq!(fold_char(upper, c as u16), c as u16);
            assert_eq!(fold_char(lower, c as u16), c as u16);
        }
    }
}
