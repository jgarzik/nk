//! Tests of the runtime library through the routines drivers call: the
//! same calls as the conformance driver `nkc-rtl` makes, and the values
//! its source predicts of Windows.

use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::ffi::CStr;
use nk_bootinfo::BootInfo;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::rtl::ANSI_STRING;

pub static GROUP: Group = Group {
    names: &["rtl.crt", "rtl.vsnwprintf"],
    run,
    manual: false,
};

/// A wide, NUL-terminated copy of `text`.
fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

fn narrow(text: &'static CStr) -> *const u8 {
    text.as_ptr().cast()
}

/// Where in the string at `base` a returned pointer is; `None` for
/// null.
fn at<T>(found: *mut T, base: *const T) -> Option<usize> {
    (!found.is_null()).then(|| (found as usize - base as usize) / size_of::<T>())
}

/// The C runtime's comparisons and searches.
fn crt() -> Result<(), &'static str> {
    use crate::rtl::crt::{_stricmp, _wcsicmp, strncmp, strrchr, wcsstr};
    // SAFETY: every string is a NUL-terminated constant or local.
    unsafe {
        // Letters A to Z are made small, so `[` sorts before `a`; bytes
        // above 0x7F are no letters and compare as unsigned.
        let compared = [
            _stricmp(narrow(c"abc"), narrow(c"ABC")),
            _stricmp(narrow(c"abc"), narrow(c"abd")),
            _stricmp(narrow(c"B"), narrow(c"a")),
            _stricmp(narrow(c"a"), narrow(c"B")),
            _stricmp(narrow(c"["), narrow(c"a")),
            _stricmp(narrow(c"abc"), narrow(c"ab")),
            _stricmp(narrow(c"ab"), narrow(c"abc")),
            _stricmp(narrow(c""), narrow(c"")),
            _stricmp(narrow(c"\xE9"), narrow(c"\xC9")),
            _stricmp(narrow(c"\xE9"), narrow(c"a")),
        ];
        if compared != [0, -1, 1, -1, -6, 99, -99, 0, 32, 136] {
            return Err("_stricmp compared wrongly");
        }
        let w = |text: &str| wide(text);
        let compared = [
            _wcsicmp(w("abc").as_ptr(), w("ABC").as_ptr()),
            _wcsicmp(w("abc").as_ptr(), w("abd").as_ptr()),
            _wcsicmp(w("[").as_ptr(), w("a").as_ptr()),
            _wcsicmp(w("abc").as_ptr(), w("ab").as_ptr()),
            _wcsicmp(w("ab").as_ptr(), w("abc").as_ptr()),
            _wcsicmp(w("\u{E9}").as_ptr(), w("\u{C9}").as_ptr()),
            _wcsicmp(w("\u{430}").as_ptr(), w("\u{410}").as_ptr()),
            _wcsicmp([0xFFFF, 0].as_ptr(), w("a").as_ptr()),
        ];
        if compared != [0, -1, -6, 99, -99, 32, 32, 65438] {
            return Err("_wcsicmp compared wrongly");
        }
        let compared = [
            strncmp(narrow(c"abc"), narrow(c"abd"), 2),
            strncmp(narrow(c"abc"), narrow(c"abd"), 3),
            strncmp(narrow(c"abc"), narrow(c"abd"), 0),
            strncmp(narrow(c"ab"), narrow(c"abc"), 5),
            strncmp(narrow(c"ab"), narrow(c"abc"), 2),
            strncmp(narrow(c"abc"), narrow(c"abc"), 100),
            strncmp(narrow(c"\x80"), narrow(c"a"), 1),
            strncmp(narrow(c"b"), narrow(c"a"), 1),
        ];
        if compared != [0, -1, 0, -1, 0, 0, 1, 1] {
            return Err("strncmp compared wrongly");
        }
        // A count ends the comparison where the memory ends: these two
        // have no terminator.
        let (one, two) = (*b"abcd", *b"abcd");
        if strncmp(one.as_ptr(), two.as_ptr(), 4) != 0 {
            return Err("strncmp of two unterminated strings is not 0");
        }
        let path = narrow(c"a/b/c");
        let found = [
            at(strrchr(path, i32::from(b'/')), path),
            at(strrchr(path, i32::from(b'x')), path),
            at(strrchr(path, 0), path),
            at(strrchr(path, i32::from(b'a')), path),
            at(strrchr(path.add(5), i32::from(b'a')), path),
            // Only the character's low byte counts.
            at(strrchr(path, i32::from(b'/') + 0x100), path),
        ];
        if found != [Some(3), None, Some(5), Some(0), None, Some(3)] {
            return Err("strrchr found the wrong place");
        }
        let (hello, aaab) = (wide("hello world"), wide("aaab"));
        let found = [
            at(wcsstr(hello.as_ptr(), w("o w").as_ptr()), hello.as_ptr()),
            at(wcsstr(hello.as_ptr(), w("").as_ptr()), hello.as_ptr()),
            at(wcsstr(hello.as_ptr(), w("xyz").as_ptr()), hello.as_ptr()),
            at(wcsstr(hello.as_ptr(), w("HELLO").as_ptr()), hello.as_ptr()),
            at(wcsstr(aaab.as_ptr(), w("aaabb").as_ptr()), aaab.as_ptr()),
            at(wcsstr(aaab.as_ptr(), w("aab").as_ptr()), aaab.as_ptr()),
            at(wcsstr(hello.as_ptr(), w("world").as_ptr()), hello.as_ptr()),
        ];
        if found != [Some(4), Some(0), None, None, None, Some(1), Some(6)] {
            return Err("wcsstr found the wrong place");
        }
    }
    Ok(())
}

/// Characters of room the formatting tests print into.
const TEXT: usize = 64;

/// `_vsnwprintf` into a buffer filled with 0xEEEE, with room for
/// `count` characters, the way a driver's variadic wrapper calls it: a
/// `va_list` is the address of the arguments, eight bytes each.
fn print(count: usize, format: &str, arguments: &[u64]) -> (i32, [u16; TEXT + 1]) {
    let mut text = [0xEEEEu16; TEXT + 1];
    let format = wide(format);
    // SAFETY: the buffer has room for `count` characters (at most
    // `TEXT`), the format is NUL-terminated, and each caller passes the
    // arguments its format names.
    let result = unsafe {
        crate::rtl::print::_vsnwprintf(
            text.as_mut_ptr(),
            count,
            format.as_ptr(),
            arguments.as_ptr(),
        )
    };
    (result, text)
}

/// Whether `print` gave `expected` and its terminator, and returned its
/// length.
fn printed(format: &str, arguments: &[u64], expected: &str) -> bool {
    let (result, text) = print(TEXT, format, arguments);
    let expected = wide(expected);
    result == expected.len() as i32 - 1
        && text[..expected.len()] == expected[..]
        && text[expected.len()] == 0xEEEE
}

/// Formatted output from a `va_list`.
fn vsnwprintf() -> Result<(), &'static str> {
    let (wide_text, ws, abcdef) = (wide("wide"), wide("ws"), wide("abcdef"));
    let address = |text: &[u16]| text.as_ptr() as u64;
    let c = |text: &'static CStr| text.as_ptr() as u64;
    if !printed(
        "%s|%S|%ws|%hs",
        &[address(&wide_text), c(c"narrow"), address(&ws), c(c"hs")],
        "wide|narrow|ws|hs",
    ) {
        return Err("strings of either width were not formatted right");
    }
    // Counted strings give as many characters as their length says and
    // need no terminator.
    let mut unicode_text = wide("unicode");
    let mut ansi_text = *b"ansi";
    let unicode = UNICODE_STRING {
        Length: 6,
        MaximumLength: 16,
        Buffer: unicode_text.as_mut_ptr(),
    };
    let ansi = ANSI_STRING {
        Length: 4,
        MaximumLength: 4,
        Buffer: ansi_text.as_mut_ptr(),
    };
    let empty = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: core::ptr::null_mut(),
    };
    if !printed(
        "%wZ|%Z",
        &[&raw const unicode as u64, &raw const ansi as u64],
        "uni|ansi",
    ) {
        return Err("counted strings were not formatted right");
    }
    if !printed(
        "%s|%wZ|%wZ",
        &[0, 0, &raw const empty as u64],
        "(null)|(null)|(null)",
    ) {
        return Err("a null string was not shown as (null)");
    }
    // Integers of every size, as a caller's 64-bit argument slots hold
    // them: a 32-bit argument's upper half is whatever was there.
    let junk = 0xAAAA_AAAA_0000_0000u64;
    let minus = |n: i32| junk | u64::from(n as u32);
    if !printed(
        "%d|%i|%u|%x|%X|%o|%x",
        &[
            minus(-5),
            junk | 7,
            junk | 4_000_000_000,
            junk | 0xBEEF,
            junk | 0xBEEF,
            junk | 8,
            minus(-1),
        ],
        "-5|7|4000000000|beef|BEEF|10|ffffffff",
    ) || !printed(
        "%I64d|%I64u|%I64x|%p",
        &[u64::MAX, u64::MAX, 0x0123_4567_89AB_CDEF, 0x1234_ABCD],
        "-1|18446744073709551615|123456789abcdef|000000001234ABCD",
    ) || !printed(
        "%ld|%lu|%lx|%hd|%hu",
        &[
            minus(-100_000),
            junk | 3_000_000_000,
            junk | 0xDEAD_BEEF,
            minus(-2),
            junk | 0x1_FFFF,
        ],
        "-100000|3000000000|deadbeef|-2|65535",
    ) {
        return Err("integers were not formatted right");
    }
    if !printed(
        "%5d|%-5d|%05d|%+d|% d|%.5d|%8.3d|%.0d|%#x",
        &[42, 42, 42, 42, 42, 42, 42, 0, 0xAB],
        "   42|42   |00042|+42| 42|00042|     042||0xab",
    ) || !printed(
        "%.3s|%10s|%.*s|%*d|%c|%C",
        &[
            address(&abcdef),
            address(&ws),
            2,
            address(&abcdef),
            4,
            7,
            0x77,
            0x6E,
        ],
        "abc|        ws|ab|   7|w|n",
    ) {
        return Err("width, precision or flags were not honoured");
    }
    // "abcdef" into room for 7, 6, 4 and 0 characters: with its
    // terminator; without one; cut off; and nothing at all. The
    // character after a full buffer is never written.
    let argument = [address(&abcdef)];
    let (seven, six, four, none) = (
        print(7, "%s", &argument),
        print(6, "%s", &argument),
        print(4, "%s", &argument),
        print(0, "%s", &argument),
    );
    if seven.0 != 6 || seven.1[..8] != [0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0, 0xEEEE] {
        return Err("text that fits with its terminator was not written with it");
    }
    if six.0 != 6 || six.1[..7] != [0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0xEEEE] {
        return Err("text that fills the buffer was terminated past it");
    }
    if four.0 != -1 || four.1[..5] != [0x61, 0x62, 0x63, 0x64, 0xEEEE] {
        return Err("text too long was not cut off at the buffer's end with -1");
    }
    if none.0 != -1 || none.1[0] != 0xEEEE {
        return Err("a buffer with no room was written to");
    }
    let (empty_format, cut) = (print(TEXT, "", &[]), print(2, "%d", &[12345]));
    if empty_format.0 != 0 || empty_format.1[..2] != [0, 0xEEEE] {
        return Err("an empty format did not give an empty string");
    }
    if cut.0 != -1 || cut.1[..3] != [0x31, 0x32, 0xEEEE] {
        return Err("a number too long was not cut off");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("rtl.crt", crt);
    r.check("rtl.vsnwprintf", vsnwprintf);
}
