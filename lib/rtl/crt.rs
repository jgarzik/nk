//! C runtime string functions that drivers import from the kernel:
//! [`_stricmp`, `_wcsicmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/stricmp-wcsicmp-mbsicmp-stricmp-l-wcsicmp-l-mbsicmp-l),
//! [`strncmp`, `wcsncmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncmp-wcsncmp-mbsncmp-mbsncmp-l),
//! [`wcscmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcmp-wcscmp-mbscmp),
//! [`strrchr`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strrchr-wcsrchr-mbsrchr-mbsrchr-l),
//! [`wcsstr`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strstr-wcsstr-mbsstr-mbsstr-l)
//! and
//! [`strnlen`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnlen-strnlen-s).
//!
//! A string is given as a slice and ends at its first NUL, or at the
//! end of the slice if it has none. Where C returns a pointer, these
//! return the index into the slice.
//!
//! # Return values
//!
//! C promises only the sign of a comparison. These return the
//! difference of the first two characters that differ, taken as
//! unsigned, except [`wcscmp`], which returns -1, 0 or 1.
//!
//! INFERRED: that this is what the kernel's own functions return.
//! Microsoft's C sources return the difference from `strncmp`,
//! `wcsncmp`, `_stricmp` and `_wcsicmp` and -1/0/1 from `wcscmp`; the
//! x64 assembly `strncmp` is believed to return -1/0/1.
//!
//! The case-insensitive ones fold `A` to `Z` only, as the C locale
//! does: they do not use the system's upper-case table.

/// The characters of a string, then its terminator for ever.
fn characters<T: Copy + Into<u16>>(string: &[T]) -> impl Iterator<Item = u16> + '_ {
    string
        .iter()
        .map(|&c| c.into())
        .take_while(|&c| c != 0)
        .chain(core::iter::repeat(0))
}

fn lower(c: u16) -> u16 {
    match c {
        0x41..=0x5A => c + 0x20,
        _ => c,
    }
}

fn same(c: u16) -> u16 {
    c
}

/// Compare at most `count` characters, each through `fold`.
fn compare<T: Copy + Into<u16>>(a: &[T], b: &[T], count: usize, fold: fn(u16) -> u16) -> i32 {
    for (x, y) in characters(a).zip(characters(b)).take(count) {
        let (x, y) = (fold(x), fold(y));
        if x != y {
            return i32::from(x) - i32::from(y);
        }
        if x == 0 {
            break;
        }
    }
    0
}

/// `_stricmp`.
pub fn stricmp(a: &[u8], b: &[u8]) -> i32 {
    compare(a, b, usize::MAX, lower)
}

/// `_wcsicmp`.
pub fn wcsicmp(a: &[u16], b: &[u16]) -> i32 {
    compare(a, b, usize::MAX, lower)
}

/// `strncmp`: at most `count` characters.
pub fn strncmp(a: &[u8], b: &[u8], count: usize) -> i32 {
    compare(a, b, count, same)
}

/// `wcsncmp`: at most `count` characters.
pub fn wcsncmp(a: &[u16], b: &[u16], count: usize) -> i32 {
    compare(a, b, count, same)
}

/// `wcscmp`: -1, 0 or 1.
pub fn wcscmp(a: &[u16], b: &[u16]) -> i32 {
    compare(a, b, usize::MAX, same).signum()
}

/// `strnlen`: the length of the string, or `max` if no terminator is
/// found in its first `max` characters.
pub fn strnlen(string: &[u8], max: usize) -> usize {
    characters(string).take(max).take_while(|&c| c != 0).count()
}

/// `strrchr`: where `c` last occurs in the string. The terminator is
/// part of the string, so a `c` of zero finds it.
pub fn strrchr(string: &[u8], c: u8) -> Option<usize> {
    let length = strnlen(string, usize::MAX);
    if c == 0 {
        return Some(length);
    }
    string[..length].iter().rposition(|&x| x == c)
}

/// `wcsstr`: where `needle` first occurs in `haystack`. An empty needle
/// is found at the start.
pub fn wcsstr(haystack: &[u16], needle: &[u16]) -> Option<usize> {
    let length = |s: &[u16]| s.iter().position(|&c| c == 0).unwrap_or(s.len());
    let (haystack, needle) = (&haystack[..length(haystack)], &needle[..length(needle)]);
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    #[test]
    fn case_insensitive_comparison_folds_ascii_only() {
        for (a, b, expected) in [
            ("", "", 0),
            ("abc", "ABC", 0),
            ("abc", "abd", -1),
            ("ABD", "abc", 1),
            ("abc", "ab", i32::from(b'c')),
            ("ab", "abc", -i32::from(b'c')),
            ("abc\0x", "ABC\0y", 0),
            ("abc\0", "abc", 0),
            // Folded to lower case: `_` (5F) is below `a` (61), though
            // above `A` (41).
            ("_", "A", 0x5F - 0x61),
            ("[", "a", 0x5B - 0x61),
            ("@", "`", 0x40 - 0x60),
        ] {
            assert_eq!(stricmp(a.as_bytes(), b.as_bytes()), expected, "{a:?} {b:?}");
            assert_eq!(wcsicmp(&w(a), &w(b)), expected, "{a:?} {b:?}");
        }
        // Not the system table: e acute and E acute differ...
        assert_eq!(wcsicmp(&[0xE9], &[0xC9]), 0x20);
        assert_eq!(stricmp(&[0xE9], &[0xC9]), 0x20);
        assert_eq!(wcsicmp(&w("\u{3B1}"), &w("\u{391}")), 0x20);
        // ...and bytes are unsigned.
        assert_eq!(stricmp(&[0xFF], b"a"), 0xFF - 0x61);
        assert_eq!(wcsicmp(&[0xFFFF], &[1]), 0xFFFE);
    }

    #[test]
    fn counted_comparison() {
        for (a, b, count, expected) in [
            ("abc", "abc", 3, 0),
            ("abc", "abd", 3, -1),
            ("abc", "abd", 2, 0),
            ("abc", "abd", 0, 0),
            ("abc", "ABC", 3, 0x20),
            ("abc", "ab", 3, i32::from(b'c')),
            ("abc", "ab", 2, 0),
            ("ab", "abc", usize::MAX, -i32::from(b'c')),
            // Nothing after the terminator is compared.
            ("ab\0x", "ab\0y", 10, 0),
            ("", "", 5, 0),
        ] {
            assert_eq!(
                strncmp(a.as_bytes(), b.as_bytes(), count),
                expected,
                "{a:?} {b:?} {count}"
            );
            assert_eq!(
                wcsncmp(&w(a), &w(b), count),
                expected,
                "{a:?} {b:?} {count}"
            );
        }
        assert_eq!(strncmp(&[0x80], &[0x7F], 1), 1, "bytes are unsigned");
        assert_eq!(wcsncmp(&[0x8000], &[0x7FFF], 1), 1);
    }

    #[test]
    fn wide_comparison_is_minus_one_zero_or_one() {
        for (a, b, expected) in [
            ("", "", 0),
            ("abc", "abc", 0),
            ("abc", "abz", -1),
            ("abz", "abc", 1),
            ("abc", "ab", 1),
            ("ab", "abc", -1),
            ("abc", "ABC", 1),
            ("a\0b", "a\0c", 0),
        ] {
            assert_eq!(wcscmp(&w(a), &w(b)), expected, "{a:?} {b:?}");
        }
        assert_eq!(wcscmp(&[0xFFFF], &[1]), 1);
    }

    #[test]
    fn bounded_length() {
        for (string, max, expected) in [
            (&b"hello\0"[..], 10, 5),
            (b"hello\0", 5, 5),
            (b"hello\0", 3, 3),
            (b"hello\0", 0, 0),
            (b"\0", 10, 0),
            (b"", 10, 0),
            (b"he\0lo", 10, 2),
            // No terminator in the slice: its end is one.
            (b"hello", 10, 5),
        ] {
            assert_eq!(strnlen(string, max), expected, "{string:?} {max}");
        }
    }

    #[test]
    fn last_occurrence() {
        for (string, c, expected) in [
            (&b"a/b/c\0"[..], b'/', Some(3)),
            (b"a/b/c\0", b'a', Some(0)),
            (b"a/b/c\0", b'c', Some(4)),
            (b"a/b/c\0", b'x', None),
            (b"a/b/c\0", 0, Some(5)),
            (b"a/b\0/c", b'/', Some(1)),
            (b"a\0b", b'b', None),
            (b"\0", b'a', None),
            (b"\0", 0, Some(0)),
            (b"", 0, Some(0)),
        ] {
            assert_eq!(strrchr(string, c), expected, "{string:?} {c}");
        }
    }

    #[test]
    fn substring() {
        for (haystack, needle, expected) in [
            ("hello world", "world", Some(6)),
            ("hello world", "hello", Some(0)),
            ("hello world", "o", Some(4)),
            ("hello world", "", Some(0)),
            ("", "", Some(0)),
            ("", "a", None),
            ("abc", "abcd", None),
            ("abc", "ABC", None),
            ("aab", "ab", Some(1)),
            // Neither string goes past its terminator.
            ("ab\0cd", "cd", None),
            ("abcd", "cd\0x", Some(2)),
            ("abcd", "\0x", Some(0)),
        ] {
            assert_eq!(
                wcsstr(&w(haystack), &w(needle)),
                expected,
                "{haystack:?} {needle:?}"
            );
        }
    }
}
