//! Short names for long ones:
//! [`RtlGenerate8dot3Name`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlgenerate8dot3name),
//! as the pinned kernel makes them. The names land on disk, so they are
//! Windows' to the character.
//!
//! The first call reads the long name into the context: a base of up to
//! six characters from before the last dot, and an extension of a dot
//! and up to three characters from after it. Each character is upper
//! case, a space, control or (unless extended characters are allowed)
//! non-ASCII character is left out, as are dots in the base, and a
//! character FAT forbids becomes `_`. A base of two characters or fewer
//! gets the long name's checksum, four hexadecimal digits, lowest first.
//!
//! Every call then gives the next name: base, `~`, a number from 1. After
//! `~4` the base becomes its first two characters and the checksum, and
//! the number starts again from 1; when a number is all nines the base
//! loses a character, so the next, longer number still fits, and a base
//! that would lose its last character is
//! `STATUS_FILE_SYSTEM_LIMITATION`. An extension of more than three
//! characters ends in `~` instead of its third when the kernel keeps
//! "safe" extensions (registry `Win95TruncatedExtensions` absent or 0).
//!
//! The OEM page has no double-byte characters (`codepage::OEM_437`), so
//! Windows' double-byte handling never applies.

use crate::codepage::OEM_437;
use crate::upcase_char;
use nk_ntabi::rtl::GENERATE_NAME_CONTEXT;

/// Characters FAT forbids in a short name, among the ASCII ones: the
/// pinned kernel's `RtlFatIllegalTable`, a bit per character.
const FAT_ILLEGAL: [u32; 4] = [0xFFFF_FFFF, 0xFC00_9C04, 0x3800_0000, 0x1000_0000];

/// The longest base before a number is added.
const BASE: u8 = 6;

/// The longest short name: eight characters, a dot and three.
pub const MAX_SHORT: usize = 12;

/// The checksum of a long name (`RtlComputeLfnChecksum`).
pub fn checksum(name: &[u16]) -> u16 {
    let hash = name
        .iter()
        .fold(0u16, |h, &c| h.wrapping_mul(37).wrapping_add(c));
    let x = i32::from(hash).wrapping_mul(0x12B9_B0A5).wrapping_abs();
    (x.wrapping_sub(x / 1_000_000_007 * 1_000_000_007)) as u16
}

/// The hexadecimal digit of the low four bits of `value`.
fn hex(value: u16) -> u16 {
    let nibble = value & 0xF;
    nibble
        + if nibble > 9 {
            u16::from(b'7')
        } else {
            u16::from(b'0')
        }
}

/// `RtlIsValidOemCharacter` for a single-byte OEM page: the upper case
/// of `c` if the page has it, else none.
fn valid_oem(c: u16) -> Option<u16> {
    let upper = upcase_char(OEM_437.to_unicode(OEM_437.from_unicode(c)));
    (OEM_437.from_unicode(upper) != b'?').then_some(upper)
}

/// The next character of `name` from `*at` for a short name, `*at`
/// moved past it, or `None` at the end (`GetNextWchar`).
fn next(name: &[u16], at: &mut usize, skip_dots: bool, extended: bool) -> Option<u16> {
    loop {
        let mut c = *name.get(*at)?;
        *at += 1;
        if c <= 0x20 {
            continue;
        }
        if c >= 0x7F {
            match extended.then(|| valid_oem(c)).flatten() {
                Some(upper) => c = upper,
                None => continue,
            }
        }
        if c == u16::from(b'.') && skip_dots {
            continue;
        }
        if c < 0x80 && FAT_ILLEGAL[usize::from(c >> 5)] & 1 << (c & 0x1F) != 0 {
            c = u16::from(b'_');
        }
        if (u16::from(b'a')..=u16::from(b'z')).contains(&c) {
            c -= 0x20;
        }
        return Some(c);
    }
}

/// Put the long name's checksum into the base from position `from`.
fn insert_checksum(ctx: &mut GENERATE_NAME_CONTEXT, name: &[u16], from: usize) {
    let mut sum = checksum(name);
    ctx.Checksum = sum;
    for slot in &mut ctx.NameBuffer[from..from + 4] {
        *slot = hex(sum);
        sum >>= 4;
    }
    ctx.ChecksumInserted = 1;
}

/// The first call's reading of the long name into the context.
fn read(ctx: &mut GENERATE_NAME_CONTEXT, name: &[u16], extended: bool, safe_extensions: bool) {
    let dot = u16::from(b'.');
    // Where the extension starts: just past the last dot, unless the
    // name ends there. Leading dots are not the last dot.
    let mut ext = None;
    let mut at = 0;
    let mut skip = name.first() == Some(&dot);
    while let Some(c) = next(name, &mut at, skip, extended) {
        skip = false;
        if c == dot {
            ext = Some(at);
        }
    }
    let ext = ext.filter(|&e| e != name.len());
    let stop = ext.unwrap_or(usize::MAX);
    ctx.NameLength = 0;
    let mut at = 0;
    while let Some(c) = next(name, &mut at, true, extended) {
        if at >= stop || ctx.NameLength >= BASE {
            break;
        }
        ctx.NameBuffer[usize::from(ctx.NameLength)] = c;
        ctx.NameLength += 1;
    }
    if ctx.NameLength <= 2 {
        insert_checksum(ctx, name, usize::from(ctx.NameLength));
        ctx.NameLength += 4;
    }
    ctx.ExtensionLength = 0;
    if let Some(mut at) = ext {
        ctx.ExtensionBuffer[0] = dot;
        ctx.ExtensionLength = 1;
        while let Some(c) = next(name, &mut at, true, extended) {
            if ctx.ExtensionLength >= 4 {
                if safe_extensions {
                    ctx.ExtensionBuffer[3] = u16::from(b'~');
                }
                break;
            }
            ctx.ExtensionBuffer[ctx.ExtensionLength as usize] = c;
            ctx.ExtensionLength += 1;
        }
    }
}

/// The next short name of `name` into `out`; its length in characters,
/// or `Err` with that length when the base is used up
/// (`STATUS_FILE_SYSTEM_LIMITATION`; the name given is still written).
pub fn generate(
    name: &[u16],
    extended: bool,
    safe_extensions: bool,
    ctx: &mut GENERATE_NAME_CONTEXT,
    out: &mut [u16; MAX_SHORT],
) -> Result<usize, usize> {
    if ctx.NameLength == 0 {
        read(ctx, name, extended, safe_extensions);
    }
    ctx.LastIndexValue = ctx.LastIndexValue.wrapping_add(1);
    if ctx.LastIndexValue > 4 && ctx.ChecksumInserted == 0 {
        insert_checksum(ctx, name, 2);
        ctx.NameLength = BASE;
        ctx.LastIndexValue = 1;
    }
    // `~` and the number's digits, most significant first.
    let mut tail = [0u16; 8];
    let mut start = tail.len();
    let mut value = ctx.LastIndexValue;
    let mut nines = true;
    loop {
        let digit = u16::from(b'0') + (value % 10) as u16;
        start -= 1;
        tail[start] = digit;
        nines &= digit == u16::from(b'9');
        value /= 10;
        if value == 0 || start == 1 {
            break;
        }
    }
    start -= 1;
    tail[start] = u16::from(b'~');
    let base = &ctx.NameBuffer[..usize::from(ctx.NameLength)];
    let extension = &ctx.ExtensionBuffer[..ctx.ExtensionLength as usize];
    let mut length = 0;
    for &c in base.iter().chain(&tail[start..]).chain(extension) {
        if let Some(slot) = out.get_mut(length) {
            *slot = c;
            length += 1;
        }
    }
    if nines {
        ctx.NameLength -= 1;
        if ctx.NameLength == 0 {
            return Err(length);
        }
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> std::vec::Vec<u16> {
        s.encode_utf16().collect()
    }

    fn names(long: &str, count: usize, safe: bool) -> std::vec::Vec<std::string::String> {
        let name = w(long);
        let mut ctx = GENERATE_NAME_CONTEXT::default();
        (0..count)
            .map(|_| {
                let mut out = [0; MAX_SHORT];
                let n = generate(&name, true, safe, &mut ctx, &mut out).unwrap();
                std::string::String::from_utf16(&out[..n]).unwrap()
            })
            .collect()
    }

    #[test]
    fn the_first_four_are_numbered() {
        assert_eq!(
            names("Long File Name.txt", 4, true),
            [
                "LONGFI~1.TXT",
                "LONGFI~2.TXT",
                "LONGFI~3.TXT",
                "LONGFI~4.TXT"
            ]
        );
    }

    #[test]
    fn the_fifth_carries_the_checksum() {
        let sum = checksum(&w("Long File Name.txt"));
        let digits: std::string::String = (0..4)
            .map(|i| char::from_u32(u32::from(hex(sum >> (4 * i)))).unwrap())
            .collect();
        let five = names("Long File Name.txt", 5, true);
        assert_eq!(five[4], std::format!("LO{digits}~1.TXT"));
    }

    #[test]
    fn a_short_base_carries_the_checksum_at_once() {
        let n = names("ab.document", 1, false);
        assert!(
            n[0].starts_with("AB") && n[0].ends_with("~1.DOC"),
            "{}",
            n[0]
        );
        assert_eq!(n[0].len(), 12);
    }

    #[test]
    fn safe_extensions_end_in_a_tilde() {
        assert_eq!(names("index.html", 1, true), ["INDEX~1.HT~"]);
        assert_eq!(names("index.html", 1, false), ["INDEX~1.HTM"]);
    }

    #[test]
    fn illegal_characters_become_underscores_and_spaces_go() {
        assert_eq!(names("a+b c[d].txt", 1, true), ["A_BC_D~1.TXT"]);
    }

    #[test]
    fn dots_before_the_last_are_dropped_and_leading_dots_skipped() {
        assert_eq!(names("my.long.name.c", 1, true), ["MYLONG~1.C"]);
        assert_eq!(names("...hidden", 1, true), ["HIDDEN~1"]);
        assert_eq!(names("trailing.", 1, true), ["TRAILI~1"]);
    }

    #[test]
    fn all_nines_shortens_the_base() {
        let name = w("Long File Name.txt");
        let mut ctx = GENERATE_NAME_CONTEXT::default();
        let mut last = std::string::String::new();
        for _ in 0..14 {
            let mut out = [0; MAX_SHORT];
            let n = generate(&name, true, true, &mut ctx, &mut out).unwrap();
            last = std::string::String::from_utf16(&out[..n]).unwrap();
        }
        // ~1..~4, then the checksum form ~1..~9, then ~10 on a base of 5.
        assert_eq!(last.len(), 12);
        assert!(last.contains("~10."), "{last}");
        assert_eq!(&last[..2], "LO");
    }

    #[test]
    fn extended_characters_are_kept_when_allowed() {
        // é is in 437; its upper case É is too.
        assert_eq!(names("café.txt", 1, true), ["CAFÉ~1.TXT"]);
        // € is not in 437: left out.
        assert_eq!(names("price€list.txt", 1, true), ["PRICEL~1.TXT"]);
    }
}
