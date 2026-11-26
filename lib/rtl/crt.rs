//! C runtime string functions that drivers import from the kernel:
//! [`_stricmp`, `_wcsicmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/stricmp-wcsicmp-mbsicmp-stricmp-l-wcsicmp-l-mbsicmp-l),
//! [`strncmp`, `wcsncmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncmp-wcsncmp-mbsncmp-mbsncmp-l),
//! [`wcscmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcmp-wcscmp-mbscmp),
//! [`strrchr`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strrchr-wcsrchr-mbsrchr-mbsrchr-l),
//! [`wcsstr`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strstr-wcsstr-mbsstr-mbsstr-l)
//! and
//! [`strnlen`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnlen-strnlen-s).
//!
//! # How a string is given
//!
//! A C string is memory the caller owns, as long as its terminator
//! says, and the kernel may form no slice over a driver's memory. So a
//! string is given as an iterator over its characters, the terminator
//! not among them ([`of`] makes one from a slice), or to [`wcsstr`] as
//! a function from an index to the character there. Either is asked
//! only for what the result needs: no character after the one that
//! decides a comparison, none past a count, and none past a terminator.
//! Where C returns a pointer, these return the index.
//!
//! # Return values
//!
//! C promises only the sign of a comparison. `_stricmp`, `_wcsicmp`
//! and `wcsncmp` return the difference of the first two characters
//! that differ, taken as unsigned; [`strncmp`] and [`wcscmp`] return
//! -1, 0 or 1.
//!
//! INFERRED: that this is what the kernel's own functions return.
//! Microsoft's C sources return the difference from `wcsncmp`,
//! `_stricmp` and `_wcsicmp` and -1/0/1 from `wcscmp`; `strncmp` on
//! x86-64 is assembly that is believed to return -1/0/1, and arm64 is
//! held to transcripts recorded on x86-64.
//!
//! The case-insensitive ones fold `A` to `Z` only, as the C locale
//! does: they do not use the system's upper-case table.

/// The characters of the string in `string`: up to its first NUL, or
/// all of the slice if it has none.
pub fn of<T: Copy + Into<u16>>(string: &[T]) -> impl Iterator<Item = u16> + '_ {
    string.iter().map(|&c| c.into()).take_while(|&c| c != 0)
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
fn compare(
    a: impl Iterator<Item = u16>,
    b: impl Iterator<Item = u16>,
    count: usize,
    fold: fn(u16) -> u16,
) -> i32 {
    // After its characters a string has its terminator, for ever.
    let (a, b) = (
        a.chain(core::iter::repeat(0)),
        b.chain(core::iter::repeat(0)),
    );
    for (x, y) in a.zip(b).take(count) {
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
pub fn stricmp(a: impl Iterator<Item = u16>, b: impl Iterator<Item = u16>) -> i32 {
    compare(a, b, usize::MAX, lower)
}

/// `_wcsicmp`.
pub fn wcsicmp(a: impl Iterator<Item = u16>, b: impl Iterator<Item = u16>) -> i32 {
    compare(a, b, usize::MAX, lower)
}

/// `strncmp`: at most `count` characters; -1, 0 or 1.
pub fn strncmp(a: impl Iterator<Item = u16>, b: impl Iterator<Item = u16>, count: usize) -> i32 {
    compare(a, b, count, same).signum()
}

/// `wcsncmp`: at most `count` characters.
pub fn wcsncmp(a: impl Iterator<Item = u16>, b: impl Iterator<Item = u16>, count: usize) -> i32 {
    compare(a, b, count, same)
}

/// `wcscmp`: -1, 0 or 1.
pub fn wcscmp(a: impl Iterator<Item = u16>, b: impl Iterator<Item = u16>) -> i32 {
    compare(a, b, usize::MAX, same).signum()
}

/// `strnlen`: the length of the string, or `max` if no terminator is
/// found in its first `max` characters.
pub fn strnlen(string: impl Iterator<Item = u16>, max: usize) -> usize {
    string.take(max).count()
}

/// `strrchr`: where `c` last occurs in the string. The terminator is
/// part of the string, so a `c` of zero finds it.
pub fn strrchr(string: impl Iterator<Item = u16>, c: u8) -> Option<usize> {
    let (mut last, mut length) = (None, 0);
    for (at, x) in string.enumerate() {
        if x == u16::from(c) {
            last = Some(at);
        }
        length = at + 1;
    }
    if c == 0 { Some(length) } else { last }
}

/// `wcsstr`: where `needle` first occurs in `haystack`. An empty needle
/// is found at the start. Each string is a function from an index to
/// the character there, the terminator's included.
pub fn wcsstr(haystack: impl Fn(usize) -> u16, needle: impl Fn(usize) -> u16) -> Option<usize> {
    let mut start = 0;
    loop {
        let mut at = 0;
        loop {
            let wanted = needle(at);
            if wanted == 0 {
                return Some(start);
            }
            let found = haystack(start + at);
            if found == 0 {
                // The haystack ends inside the needle: it is too short
                // from here on.
                return None;
            }
            if found != wanted {
                break;
            }
            at += 1;
        }
        start += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    /// A slice as `wcsstr` takes a string: past its end is a terminator.
    fn at(string: &[u16]) -> impl Fn(usize) -> u16 + '_ {
        |i| string.get(i).copied().unwrap_or(0)
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
            assert_eq!(
                stricmp(of(a.as_bytes()), of(b.as_bytes())),
                expected,
                "{a:?} {b:?}"
            );
            assert_eq!(wcsicmp(of(&w(a)), of(&w(b))), expected, "{a:?} {b:?}");
        }
        // Not the system table: e acute and E acute differ...
        assert_eq!(wcsicmp(of(&[0xE9u16]), of(&[0xC9u16])), 0x20);
        assert_eq!(stricmp(of(&[0xE9u8]), of(&[0xC9u8])), 0x20);
        assert_eq!(wcsicmp(of(&w("\u{3B1}")), of(&w("\u{391}"))), 0x20);
        // ...and bytes are unsigned.
        assert_eq!(stricmp(of(&[0xFFu8]), of(b"a")), 0xFF - 0x61);
        assert_eq!(wcsicmp(of(&[0xFFFFu16]), of(&[1u16])), 0xFFFE);
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
            ("ab", "abc", 5, -i32::from(b'c')),
            ("ab", "abc", usize::MAX, -i32::from(b'c')),
            ("abc", "abc", 100, 0),
            // Nothing after the terminator is compared.
            ("ab\0x", "ab\0y", 10, 0),
            ("", "", 5, 0),
        ] {
            // The narrow one gives the sign alone.
            assert_eq!(
                strncmp(of(a.as_bytes()), of(b.as_bytes()), count),
                expected.signum(),
                "{a:?} {b:?} {count}"
            );
            assert_eq!(
                wcsncmp(of(&w(a)), of(&w(b)), count),
                expected,
                "{a:?} {b:?} {count}"
            );
        }
        assert_eq!(strncmp(of(&[0x80u8]), of(b"a"), 1), 1, "bytes are unsigned");
        assert_eq!(wcsncmp(of(&[0x8000u16]), of(&[0x7FFFu16]), 1), 1);
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
            assert_eq!(wcscmp(of(&w(a)), of(&w(b))), expected, "{a:?} {b:?}");
        }
        assert_eq!(wcscmp(of(&[0xFFFFu16]), of(&[1u16])), 1);
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
            assert_eq!(strnlen(of(string), max), expected, "{string:?} {max}");
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
            assert_eq!(strrchr(of(string), c), expected, "{string:?} {c}");
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
            ("aaab", "aab", Some(1)),
            ("aaab", "aaabb", None),
            ("hello world", "o w", Some(4)),
            // Neither string goes past its terminator.
            ("ab\0cd", "cd", None),
            ("abcd", "cd\0x", Some(2)),
            ("abcd", "\0x", Some(0)),
        ] {
            let (haystack, needle) = (w(haystack), w(needle));
            assert_eq!(
                wcsstr(at(&haystack), at(&needle)),
                expected,
                "{haystack:?} {needle:?}"
            );
        }
    }

    /// A string in memory that ends right after its terminator: asking
    /// for anything further is the overrun a real one would be.
    fn guarded(string: &[u16]) -> impl Iterator<Item = u16> + '_ {
        let mut next = 0;
        core::iter::from_fn(move || {
            let c = *string.get(next).expect("read past the terminator");
            next += 1;
            (c != 0).then_some(c)
        })
    }

    #[test]
    fn nothing_is_read_that_the_result_does_not_need() {
        let (abc, abd, ab) = (w("abc\0"), w("abd\0"), w("ab\0"));
        assert_eq!(wcsicmp(guarded(&abc), guarded(&ab)), i32::from(b'c'));
        assert_eq!(wcsicmp(guarded(&ab), guarded(&abc)), -i32::from(b'c'));
        assert_eq!(wcscmp(guarded(&abc), guarded(&abc)), 0);
        assert_eq!(strrchr(guarded(&abc), 0), Some(3));
        assert_eq!(strnlen(guarded(&abc), 10), 3);
        // A count ends the comparison before the memory does: neither
        // string has a terminator here.
        let unterminated = |s: &'static str| {
            s.encode_utf16()
                .chain(core::iter::from_fn(|| panic!("read past the count")))
        };
        assert_eq!(strncmp(unterminated("ab"), unterminated("ab"), 2), 0);
        assert_eq!(wcsncmp(guarded(&abc), guarded(&abd), 2), 0);
        assert_eq!(strnlen(unterminated("ab"), 2), 2);
        // The first difference ends it too.
        assert_eq!(stricmp(unterminated("ax"), unterminated("b")), -1);
        // A search stops at either terminator.
        let strict = |s: &'static [u16]| move |i: usize| s[i];
        const HAY: &[u16] = &[0x61, 0x62, 0];
        const LONG: &[u16] = &[0x61, 0x62, 0x63, 0];
        const END: &[u16] = &[0x62, 0];
        assert_eq!(wcsstr(strict(HAY), strict(LONG)), None);
        assert_eq!(wcsstr(strict(HAY), strict(END)), Some(1));
        assert_eq!(wcsstr(strict(LONG), strict(HAY)), Some(0));
    }
}
