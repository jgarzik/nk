//! C runtime string functions that drivers import from the kernel:
//! [`_stricmp`, `_wcsicmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/stricmp-wcsicmp-mbsicmp-stricmp-l-wcsicmp-l-mbsicmp-l),
//! [`strncmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncmp-wcsncmp-mbsncmp-mbsncmp-l),
//! [`strrchr`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strrchr-wcsrchr-mbsrchr-mbsrchr-l)
//! and
//! [`wcsstr`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strstr-wcsstr-mbsstr-mbsstr-l).
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
//! C promises only the sign of a comparison. `_stricmp` and `_wcsicmp`
//! return the difference of the first two characters that differ,
//! taken as unsigned; [`strncmp`] returns -1, 0 or 1.
//!
//! INFERRED: that this is what the kernel's own functions return.
//! Microsoft's C sources return the difference from `_stricmp` and
//! `_wcsicmp`; `strncmp` on x86-64 is assembly that is believed to
//! return -1/0/1, and arm64 is held to transcripts recorded on x86-64.
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

/// `strrchr`: where `c` last occurs in the string. The terminator is
/// part of the string, so a `c` of zero finds it.
pub fn strrchr(string: impl Iterator<Item = u16>, c: u16) -> Option<usize> {
    let (mut last, mut length) = (None, 0);
    for (at, x) in string.enumerate() {
        if x == c {
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

/// [`_strnicmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnicmp-wcsnicmp-mbsnicmp-strnicmp-l-wcsnicmp-l-mbsnicmp-l):
/// `_stricmp` over at most `count` characters.
pub fn strnicmp(a: impl Iterator<Item = u16>, b: impl Iterator<Item = u16>, count: usize) -> i32 {
    compare(a, b, count, lower)
}

/// [`strchr`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strchr-wcschr-mbschr-mbschr-l):
/// where `c` first occurs in the string. The terminator is part of the
/// string, so a `c` of zero finds it.
pub fn strchr(string: impl Iterator<Item = u16>, c: u8) -> Option<usize> {
    let mut length = 0;
    for x in string {
        if x == u16::from(c) {
            return Some(length);
        }
        length += 1;
    }
    (c == 0).then_some(length)
}

/// [`strnlen`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnlen-strnlen-s):
/// the length of the string, or `max` if it has no terminator within
/// `max` characters.
pub fn strnlen(string: impl Iterator<Item = u16>, max: usize) -> usize {
    string.take(max).count()
}

/// [`isspace`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isspace-iswspace-isspace-l-iswspace-l)
/// in the C locale: the space flag of Microsoft's character table (8)
/// for a tab, a line feed, a vertical tab, a form feed, a carriage
/// return or a space, and zero for anything else.
pub fn isspace(c: i32) -> i32 {
    if matches!(c, 9..=13 | 32) { 8 } else { 0 }
}

/// `_strupr` in the C locale: the upper case of one character, `a` to
/// `z` only.
pub fn upper(c: u8) -> u8 {
    c.to_ascii_uppercase()
}

/// [`rand`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/rand):
/// the seed after `seed` and the number it gives, 0 to 32767.
/// Microsoft's generator, which starts from a seed of 1.
pub fn rand(seed: u32) -> (u32, i32) {
    let seed = seed.wrapping_mul(214_013).wrapping_add(2_531_011);
    (seed, (seed >> 16 & 0x7FFF) as i32)
}

/// [`_strtoui64`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtoui64-wcstoui64-strtoui64-l-wcstoui64-l):
/// the number at the start of a string, and the index of the character
/// after it (what `endptr` is set to). The string is a function from an
/// index to the character there, asked for nothing past the first
/// character that is not part of the number.
///
/// White space, then a sign, then the digits. A base of zero reads the
/// prefix: `0x` or `0X` is 16, another `0` is 8, anything else 10; base
/// 16 allows the prefix. A base that is neither zero nor 2 to 36, or a
/// string with no digits, gives zero and the index zero. A number that
/// does not fit gives the largest there is; a minus sign negates one
/// that fits.
///
/// INFERRED: a `0x` with no digit after it is "no digits" (index zero),
/// as in the C runtime the kernel was built with, where newer runtimes
/// stop after the `0`.
pub fn strtoui64(string: impl Fn(usize) -> u8, base: i32) -> (u64, usize) {
    if base != 0 && !(2..=36).contains(&base) {
        return (0, 0);
    }
    let mut at = 0;
    while isspace(i32::from(string(at))) != 0 {
        at += 1;
    }
    let negative = string(at) == b'-';
    if negative || string(at) == b'+' {
        at += 1;
    }
    let prefixed = string(at) == b'0' && string(at + 1).eq_ignore_ascii_case(&b'x');
    let base = match base {
        0 if prefixed => 16,
        0 if string(at) == b'0' => 8,
        0 => 10,
        _ => base as u32,
    };
    if base == 16 && prefixed {
        at += 2;
    }
    let (mut value, mut any, mut overflow) = (0u64, false, false);
    while let Some(digit) = char::from(string(at)).to_digit(base) {
        match value
            .checked_mul(u64::from(base))
            .and_then(|value| value.checked_add(u64::from(digit)))
        {
            Some(next) => value = next,
            None => overflow = true,
        }
        any = true;
        at += 1;
    }
    if !any {
        return (0, 0);
    }
    if overflow {
        (u64::MAX, at)
    } else if negative {
        (value.wrapping_neg(), at)
    } else {
        (value, at)
    }
}

/// `_TRUNCATE`: the count that tells `strncpy_s` to copy what fits.
pub const TRUNCATE: usize = usize::MAX;
/// `EINVAL`.
pub const EINVAL: i32 = 22;
/// `ERANGE`.
pub const ERANGE: i32 = 34;
/// `STRUNCATE`.
pub const STRUNCATE: i32 = 80;

/// [`strncpy_s`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncpy-s-strncpy-s-l-wcsncpy-s-wcsncpy-s-l-mbsncpy-s-mbsncpy-s-l):
/// copy at most `count` characters of `source` and a terminator into a
/// buffer of `size` characters, and return the error number.
///
/// `destination` is `None` for a null buffer and otherwise writes a
/// character at an index; `source` is `None` for a null string and
/// otherwise reads the character at an index, and is asked for nothing
/// past its terminator or the count.
///
/// The kernel's C runtime has no handler to call for a bad argument: the
/// function empties the destination, if it has one, and returns the
/// error.
pub fn strncpy_s<T: Copy + Default + PartialEq>(
    destination: Option<impl FnMut(usize, T)>,
    size: usize,
    source: Option<impl Fn(usize) -> T>,
    count: usize,
) -> i32 {
    let zero = T::default();
    let null = destination.is_none();
    let Some(mut write) = destination.filter(|_| size != 0) else {
        // Nothing asked of no buffer is no error.
        return if null && count == 0 && size == 0 {
            0
        } else {
            EINVAL
        };
    };
    if count == 0 {
        write(0, zero);
        return 0;
    }
    let Some(source) = source else {
        write(0, zero);
        return EINVAL;
    };
    let mut at = 0;
    loop {
        if at == size {
            // No room for the terminator.
            return if count == TRUNCATE {
                write(size - 1, zero);
                STRUNCATE
            } else {
                write(0, zero);
                ERANGE
            };
        }
        if at == count {
            write(at, zero);
            return 0;
        }
        let c = source(at);
        write(at, c);
        if c == zero {
            return 0;
        }
        at += 1;
    }
}

/// [`strcpy_s`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcpy-s-wcscpy-s-mbscpy-s)
/// and `wcscpy_s`: all of `source` and a terminator into a buffer of
/// `size` characters, as [`strncpy_s`] with no count: a source that does
/// not fit empties the buffer and is `ERANGE`.
pub fn strcpy_s<T: Copy + Default + PartialEq>(
    destination: Option<impl FnMut(usize, T)>,
    size: usize,
    source: Option<impl Fn(usize) -> T>,
) -> i32 {
    strncpy_s(destination, size, source, TRUNCATE - 1)
}

/// One step of
/// [`strtok_s`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtok-s-strtok-s-l-wcstok-s-wcstok-s-l-mbstok-s-mbstok-s-l)
/// over the string that starts where the last step left off.
pub struct Token {
    /// Where the token starts; `None` if only delimiters were left.
    pub start: Option<usize>,
    /// Where the token ends: a delimiter, to be overwritten with a
    /// terminator, or the string's own terminator.
    pub end: usize,
    /// Where the next step starts: after the delimiter, or at the
    /// string's terminator.
    pub next: usize,
}

/// `strtok_s`: the next token of `string`, which is a function from an
/// index to the character there; `delimiters` are the characters that
/// separate tokens.
pub fn strtok(string: impl Fn(usize) -> u8, delimiters: impl Iterator<Item = u8>) -> Token {
    let mut separates = [false; 256];
    for c in delimiters {
        separates[usize::from(c)] = true;
    }
    // The terminator separates nothing: it ends the string.
    separates[0] = false;
    let mut at = 0;
    while separates[usize::from(string(at))] {
        at += 1;
    }
    if string(at) == 0 {
        return Token {
            start: None,
            end: at,
            next: at,
        };
    }
    let start = at;
    while string(at) != 0 && !separates[usize::from(string(at))] {
        at += 1;
    }
    Token {
        start: Some(start),
        end: at,
        next: if string(at) == 0 { at } else { at + 1 },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A byte string as the index-taking functions take one: reading
    /// past its end is the overrun a real one would be.
    fn bytes(string: &[u8]) -> impl Fn(usize) -> u8 + '_ {
        |i| string[i]
    }

    #[test]
    fn counted_case_insensitive_comparison() {
        for (a, b, count, expected) in [
            ("abc", "ABC", 3, 0),
            ("abc", "ABD", 3, -1),
            ("abc", "ABD", 2, 0),
            ("abc", "abd", 0, 0),
            ("abc", "ab", 3, i32::from(b'c')),
            ("ab", "abc", 9, -i32::from(b'c')),
            ("ab\0x", "AB\0y", 9, 0),
            ("[", "a", 1, 0x5B - 0x61),
        ] {
            assert_eq!(
                strnicmp(of(a.as_bytes()), of(b.as_bytes()), count),
                expected,
                "{a:?} {b:?} {count}"
            );
        }
        assert_eq!(strnicmp(of(&[0xE9u8]), of(&[0xC9u8]), 1), 0x20);
    }

    #[test]
    fn first_occurrence_and_bounded_length() {
        for (string, c, expected) in [
            (&b"a/b/c\0"[..], b'/', Some(1)),
            (b"a/b/c\0", b'a', Some(0)),
            (b"a/b/c\0", b'c', Some(4)),
            (b"a/b/c\0", b'x', None),
            (b"a/b/c\0", 0, Some(5)),
            (b"a\0b", b'b', None),
            (b"\0", 0, Some(0)),
        ] {
            assert_eq!(strchr(of(string), c), expected, "{string:?} {c}");
        }
        assert_eq!(strnlen(of(b"abc\0"), 10), 3);
        assert_eq!(strnlen(of(b"abc\0"), 3), 3);
        assert_eq!(strnlen(of(b"abc\0"), 2), 2);
        assert_eq!(strnlen(of(b"abc\0"), 0), 0);
        assert_eq!(strnlen(of(b"\0"), 5), 0);
        // Nothing past the count is read.
        let unterminated = b"ab"
            .iter()
            .map(|&c| u16::from(c))
            .chain(core::iter::from_fn(|| panic!("read past the count")));
        assert_eq!(strnlen(unterminated, 2), 2);
    }

    #[test]
    fn white_space_and_upper_case_are_the_c_locales() {
        for c in -1..=255 {
            let space = [9, 10, 11, 12, 13, 32].contains(&c);
            assert_eq!(isspace(c), if space { 8 } else { 0 }, "{c}");
        }
        for c in 0..=u8::MAX {
            let expected = if c.is_ascii_lowercase() { c - 0x20 } else { c };
            assert_eq!(upper(c), expected);
        }
    }

    #[test]
    fn rand_is_microsofts_sequence() {
        let mut seed = 1;
        let mut values = [0; 5];
        for value in &mut values {
            (seed, *value) = rand(seed);
        }
        assert_eq!(values, [41, 18467, 6334, 26500, 19169]);
        for _ in 0..10_000 {
            let value;
            (seed, value) = rand(seed);
            assert!((0..=0x7FFF).contains(&value));
        }
    }

    #[test]
    fn an_unsigned_number_is_read_from_a_string() {
        for (string, base, expected) in [
            (&b"123\0"[..], 10, (123, 3)),
            (b"123abc\0", 10, (123, 3)),
            (b"  \t\n42 \0", 10, (42, 6)),
            (b"+42\0", 10, (42, 3)),
            (b"-1\0", 10, (u64::MAX, 2)),
            (b"-42\0", 10, (42u64.wrapping_neg(), 3)),
            (b"ff\0", 16, (255, 2)),
            (b"0xff\0", 16, (255, 4)),
            (b"0XFF\0", 16, (255, 4)),
            (b"0xff\0", 0, (255, 4)),
            (b"077\0", 0, (63, 3)),
            (b"078\0", 0, (7, 2)),
            (b"99\0", 0, (99, 2)),
            (b"0\0", 0, (0, 1)),
            (b"zz\0", 36, (35 * 36 + 35, 2)),
            (b"Zz\0", 36, (35 * 36 + 35, 2)),
            (b"102\0", 2, (2, 2)),
            (b"18446744073709551615\0", 10, (u64::MAX, 20)),
            // Too large: the largest number, and all the digits read.
            (b"18446744073709551616\0", 10, (u64::MAX, 20)),
            (b"-18446744073709551616\0", 10, (u64::MAX, 21)),
            (b"ffffffffffffffffff\0", 16, (u64::MAX, 18)),
            // No digits.
            (b"\0", 10, (0, 0)),
            (b"abc\0", 10, (0, 0)),
            (b"  -\0", 10, (0, 0)),
            (b"- 1\0", 10, (0, 0)),
            (b"0x\0", 16, (0, 0)),
            (b"0xg\0", 0, (0, 0)),
            // A prefix is one only in base 16.
            (b"0x10\0", 10, (0, 1)),
            (b"0x10\0", 8, (0, 1)),
            // A bad base.
            (b"10\0", 1, (0, 0)),
            (b"10\0", 37, (0, 0)),
            (b"10\0", -1, (0, 0)),
        ] {
            assert_eq!(
                strtoui64(bytes(string), base),
                expected,
                "{:?} base {base}",
                core::str::from_utf8(string)
            );
        }
    }

    /// `strncpy_s` into a buffer of `size` filled with `#`.
    fn copy(size: usize, source: Option<&[u8]>, count: usize) -> (i32, Vec<u8>) {
        let mut buffer = vec![b'#'; size];
        let result = strncpy_s(
            Some(|at: usize, c: u8| buffer[at] = c),
            size,
            source.map(bytes),
            count,
        );
        (result, buffer)
    }

    #[test]
    fn a_bounded_copy_fits_or_says_why_not() {
        assert_eq!(copy(8, Some(b"abc\0"), 10), (0, b"abc\0####".to_vec()));
        assert_eq!(copy(8, Some(b"abc\0"), 3), (0, b"abc\0####".to_vec()));
        // A count stops the copy, and a terminator follows.
        assert_eq!(copy(8, Some(b"abcdef"), 2), (0, b"ab\0#####".to_vec()));
        assert_eq!(copy(4, Some(b"abc\0"), 9), (0, b"abc\0".to_vec()));
        assert_eq!(copy(4, Some(b"abcd"), 3), (0, b"abc\0".to_vec()));
        // No room for the terminator: an empty string and ERANGE.
        assert_eq!(copy(4, Some(b"abcd\0"), 9), (ERANGE, b"\0bcd".to_vec()));
        assert_eq!(copy(4, Some(b"abcd"), 4), (ERANGE, b"\0bcd".to_vec()));
        assert_eq!(copy(1, Some(b"a"), 1), (ERANGE, b"\0".to_vec()));
        // Unless told to truncate.
        assert_eq!(
            copy(4, Some(b"abcdef\0"), TRUNCATE),
            (STRUNCATE, b"abc\0".to_vec())
        );
        assert_eq!(copy(4, Some(b"abc\0"), TRUNCATE), (0, b"abc\0".to_vec()));
        assert_eq!(copy(1, Some(b"a"), TRUNCATE), (STRUNCATE, b"\0".to_vec()));
        // Nothing to copy: an empty string, whatever the source.
        assert_eq!(copy(4, Some(b""), 0), (0, b"\0###".to_vec()));
        assert_eq!(copy(4, None, 0), (0, b"\0###".to_vec()));
        assert_eq!(copy(4, None, 3), (EINVAL, b"\0###".to_vec()));
        // No buffer.
        let none = None::<fn(usize, u8)>;
        assert_eq!(strncpy_s(none, 0, Some(bytes(b"")), 0), 0);
        assert_eq!(strncpy_s(none, 0, Some(bytes(b"")), 1), EINVAL);
        assert_eq!(strncpy_s(none, 4, Some(bytes(b"")), 0), EINVAL);
        assert_eq!(strncpy_s(none, 4, Some(bytes(b"")), 1), EINVAL);
        let unused = |_: usize, _: u8| panic!("wrote to a buffer of no size");
        assert_eq!(strncpy_s(Some(unused), 0, Some(bytes(b"")), 0), EINVAL);
        assert_eq!(strncpy_s(Some(unused), 0, Some(bytes(b"a")), 1), EINVAL);
    }

    /// Every token of `string`, as a caller of `strtok_s` gets them.
    fn tokens(string: &[u8], delimiters: &[u8]) -> Vec<String> {
        let mut string = string.to_vec();
        let (mut from, mut found) = (0, Vec::new());
        loop {
            let token = strtok(bytes(&string[from..]), delimiters.iter().copied());
            let Some(start) = token.start else {
                assert_eq!(string[from + token.next], 0);
                return found;
            };
            string[from + token.end] = 0;
            found.push(String::from_utf8(string[from + start..from + token.end].to_vec()).unwrap());
            from += token.next;
        }
    }

    #[test]
    fn a_string_splits_into_tokens() {
        assert_eq!(tokens(b"a b c\0", b" "), ["a", "b", "c"]);
        assert_eq!(tokens(b"  a,,b ;c  \0", b" ,;"), ["a", "b", "c"]);
        assert_eq!(tokens(b"abc\0", b" "), ["abc"]);
        assert_eq!(tokens(b"abc\0", b""), ["abc"]);
        assert_eq!(tokens(b"\0", b" "), [""; 0]);
        assert_eq!(tokens(b"   \0", b" "), [""; 0]);
        assert_eq!(tokens(b"a\xFFb\0", b"\xFF"), ["a", "b"]);
        // The last token ends at the terminator, where the next step
        // starts and finds nothing.
        let token = strtok(bytes(b"ab\0"), b" ".iter().copied());
        assert_eq!((token.start, token.end, token.next), (Some(0), 2, 2));
        let token = strtok(bytes(b"ab cd\0"), b" ".iter().copied());
        assert_eq!((token.start, token.end, token.next), (Some(0), 2, 3));
    }

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
            ("abc", "ABC", 3, 1),
            ("abc", "ab", 3, 1),
            ("abc", "ab", 2, 0),
            ("ab", "abc", 5, -1),
            ("ab", "abc", usize::MAX, -1),
            ("abc", "abc", 100, 0),
            // Nothing after the terminator is compared.
            ("ab\0x", "ab\0y", 10, 0),
            ("", "", 5, 0),
        ] {
            // The sign alone.
            assert_eq!(
                strncmp(of(a.as_bytes()), of(b.as_bytes()), count),
                expected,
                "{a:?} {b:?} {count}"
            );
        }
        assert_eq!(strncmp(of(&[0x80u8]), of(b"a"), 1), 1, "bytes are unsigned");
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
            assert_eq!(
                strrchr(of(string), u16::from(c)),
                expected,
                "{string:?} {c}"
            );
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
        assert_eq!(wcsicmp(guarded(&abc), guarded(&abc)), 0);
        assert_eq!(strrchr(guarded(&abc), 0), Some(3));
        // A count ends the comparison before the memory does: neither
        // string has a terminator here.
        let unterminated = |s: &'static str| {
            s.encode_utf16()
                .chain(core::iter::from_fn(|| panic!("read past the count")))
        };
        assert_eq!(strncmp(unterminated("ab"), unterminated("ab"), 2), 0);
        assert_eq!(strncmp(guarded(&abc), guarded(&abd), 2), 0);
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

    #[test]
    fn strcpy_s_copies_all_or_empties() {
        let mut buf = [0xFFu16; 4];
        let src: std::vec::Vec<u16> = "abc\0".encode_utf16().collect();
        let long: std::vec::Vec<u16> = "abcd\0".encode_utf16().collect();
        let r = strcpy_s(
            Some(|i: usize, c: u16| buf[i] = c),
            4,
            Some(|i: usize| src[i]),
        );
        assert_eq!(r, 0);
        assert_eq!(buf, [97, 98, 99, 0]);
        let r = strcpy_s(
            Some(|i: usize, c: u16| buf[i] = c),
            4,
            Some(|i: usize| long[i]),
        );
        assert_eq!(r, ERANGE);
        assert_eq!(buf[0], 0);
        let r = strcpy_s(
            Some(|i: usize, c: u16| buf[i] = c),
            4,
            None::<fn(usize) -> u16>,
        );
        assert_eq!(r, EINVAL);
        assert_eq!(
            strcpy_s(None::<fn(usize, u16)>, 4, Some(|i: usize| src[i])),
            EINVAL
        );
    }
}
