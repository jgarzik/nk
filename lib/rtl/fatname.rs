//! Names as the file-system runtime library takes them apart and judges
//! them, as the pinned kernel does: `FsRtlDissectName`,
//! `FsRtlDoesNameContainWildCards` and its byte-string form, and
//! `FsRtlIsFatDbcsLegal` for a single-byte OEM page.

use crate::legal::{FAT_LEGAL, LEGAL_ANSI_CHARACTERS, WILD_CHARACTER};
use core::ops::Range;

const BACKSLASH: u16 = b'\\' as u16;

/// `FsRtlDissectName`: the first component of `path`, after one leading
/// backslash, and the rest after the backslash that ends it, if there
/// is one; as ranges of units.
pub fn dissect(path: &[u16]) -> Option<(Range<usize>, Option<Range<usize>>)> {
    if path.is_empty() {
        return None;
    }
    let skip = usize::from(path[0] == BACKSLASH);
    let end = (skip..path.len())
        .find(|&i| path[i] == BACKSLASH)
        .unwrap_or(path.len());
    let rest = (end < path.len()).then(|| end + 1..path.len());
    Some((skip..end, rest))
}

/// Whether the table calls `c`, below 0x80, a wildcard.
fn wild(c: u8) -> bool {
    c < 0x80 && LEGAL_ANSI_CHARACTERS[usize::from(c)] & WILD_CHARACTER != 0
}

/// `FsRtlDoesNameContainWildCards`: whether the last component of
/// `name` holds a wildcard (`*`, `?` and the DOS ones `"`, `<`, `>`).
pub fn contains_wildcards(name: &[u16]) -> bool {
    name.iter()
        .rev()
        .take_while(|&&c| c != BACKSLASH)
        .any(|&c| c < 0x40 && wild(c as u8))
}

/// `FsRtlDoesDbcsContainWildCards` for a single-byte page: whether any
/// byte is a wildcard.
pub fn bytes_contain_wildcards(name: &[u8]) -> bool {
    name.iter().any(|&c| wild(c))
}

/// `FsRtlIsFatDbcsLegal` for a single-byte page, with neither a path nor
/// a leading backslash permitted: whether `name` may be a FAT short
/// name (with wildcards, if `wildcards`, a pattern for one).
pub fn is_fat_legal(name: &[u8], wildcards: bool) -> bool {
    let n = name.len();
    if n == 0 {
        return false;
    }
    let is_dot = |c: u8| c == b'.' || c == b'"';
    if wildcards && (n == 1 && is_dot(name[0]) || n == 2 && is_dot(name[0]) && name[1] == name[0]) {
        return true;
    }
    if name[0] == b'\\' {
        return false;
    }
    let mask = if wildcards {
        FAT_LEGAL | WILD_CHARACTER
    } else {
        FAT_LEGAL
    };
    if wildcards && bytes_contain_wildcards(name) {
        return name
            .iter()
            .all(|&c| c >= 0x80 || LEGAL_ANSI_CHARACTERS[usize::from(c)] & mask != 0);
    }
    if n > 12 {
        return false;
    }
    let mut dot = false;
    for (i, &c) in name.iter().enumerate() {
        if c < 0x80 && LEGAL_ANSI_CHARACTERS[usize::from(c)] & mask == 0 {
            return false;
        }
        if is_dot(c) {
            if i == 0 || dot || n - i - 1 > 3 || name[i - 1] == b' ' {
                return false;
            }
            dot = true;
        }
        if i >= 8 && !dot {
            return false;
        }
    }
    !matches!(name[n - 1], b' ' | b'"' | b'.')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> std::vec::Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn dissect_takes_the_first_component() {
        assert_eq!(dissect(&w("")), None);
        assert_eq!(dissect(&w("\\a\\b\\c")), Some((1..2, Some(3..6))));
        assert_eq!(dissect(&w("abc")), Some((0..3, None)));
        assert_eq!(dissect(&w("\\")), Some((1..1, None)));
        assert_eq!(dissect(&w("a\\")), Some((0..1, Some(2..2))));
    }

    #[test]
    fn wildcards_only_in_the_last_component() {
        assert!(contains_wildcards(&w("dir\\*.txt")));
        assert!(contains_wildcards(&w("a<b")));
        assert!(!contains_wildcards(&w("d*r\\file.txt")));
        assert!(!contains_wildcards(&w("plain")));
        assert!(bytes_contain_wildcards(b"A?B"));
        assert!(!bytes_contain_wildcards(b"AB.C"));
    }

    #[test]
    fn fat_short_names() {
        for good in [
            &b"A"[..],
            b"ABCDEFGH",
            b"ABCDEFGH.TXT",
            b"A.B",
            b"NAME~1.TXT",
            &[0x82, b'A'],
        ] {
            assert!(is_fat_legal(good, false), "{good:?}");
        }
        for bad in [
            &b""[..],
            b"ABCDEFGHI",
            b"A.TXTX",
            b".A",
            b"A.B.C",
            b"A .B",
            b"A.",
            b"A ",
            b"A+B",
            b"A*",
            b"\\A",
            b"ABCDEFGHIJKLM",
        ] {
            assert!(!is_fat_legal(bad, false), "{bad:?}");
        }
    }

    #[test]
    fn fat_patterns() {
        assert!(is_fat_legal(b".", true));
        assert!(is_fat_legal(b"..", true));
        assert!(is_fat_legal(b"*.*", true));
        assert!(is_fat_legal(b"VERYLONGNAME*", true));
        assert!(!is_fat_legal(b"A+*", true));
        assert!(!is_fat_legal(b".", false));
    }
}
