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
    names: &[
        "rtl.crt",
        "rtl.vsnwprintf",
        "rtl.compare",
        "rtl.upcase",
        "rtl.multibyte",
        "rtl.ansi-string",
        "rtl.guid",
    ],
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

/// A counted string over `text`, which has no terminator.
fn counted(text: &mut [u16]) -> UNICODE_STRING {
    UNICODE_STRING {
        Length: (text.len() * 2) as u16,
        MaximumLength: (text.len() * 2) as u16,
        Buffer: text.as_mut_ptr(),
    }
}

/// `RtlCompareMemory` and `RtlPrefixUnicodeString`.
fn compare() -> Result<(), &'static str> {
    use crate::rtl::string::{RtlCompareMemory, RtlPrefixUnicodeString};
    let (one, two) = ([1u8, 2, 3, 4, 5, 6, 7, 8], [1u8, 2, 3, 9, 5, 6, 7, 8]);
    let (a, b) = (
        one.as_ptr().cast(),
        two.as_ptr().cast::<core::ffi::c_void>(),
    );
    // SAFETY: both blocks are eight bytes; no call reads more.
    let common = unsafe {
        [
            RtlCompareMemory(a, a, 8),
            RtlCompareMemory(a, b, 8),
            RtlCompareMemory(a, b, 0),
            RtlCompareMemory(a, b.byte_add(3), 5),
        ]
    };
    if common != [8, 3, 0, 0] {
        return Err("RtlCompareMemory did not count the bytes two blocks share");
    }
    let prefix = |prefix: &str, string: &str, ignore_case: u8| {
        let (mut prefix, mut string): (Vec<u16>, Vec<u16>) = (
            prefix.encode_utf16().collect(),
            string.encode_utf16().collect(),
        );
        let (prefix, string) = (counted(&mut prefix), counted(&mut string));
        // SAFETY: both name locals that outlive the call.
        unsafe { RtlPrefixUnicodeString(&raw const prefix, &raw const string, ignore_case) }
    };
    let starts = [
        prefix("ab", "abc", 0),
        prefix("AB", "abc", 0),
        prefix("AB", "abc", 1),
        prefix("abc", "ab", 1),
        prefix("", "abc", 0),
        prefix("abc", "abc", 0),
        prefix("ac", "abc", 1),
        // Capital E with acute starts small e with acute, "x": the
        // system's table, not ASCII alone.
        prefix("\u{C9}", "\u{E9}x", 1),
        prefix("\u{C9}", "\u{E9}x", 0),
    ];
    if starts != [1, 0, 1, 0, 1, 1, 0, 1, 0] {
        return Err("RtlPrefixUnicodeString did not say which strings start which");
    }
    Ok(())
}

/// `RtlUpcaseUnicodeChar` and `RtlUpcaseUnicodeString`.
fn upcase() -> Result<(), &'static str> {
    use crate::rtl::print::RtlFreeUnicodeString;
    use crate::rtl::string::{RtlUpcaseUnicodeChar, RtlUpcaseUnicodeString};
    let capitals = [0x61, 0x7A, 0x7B, 0xE9, 0xF7, 0xFF, 0x3B1, 0xFF41, 0xFFFF]
        .map(|c| RtlUpcaseUnicodeChar(c));
    if capitals != [0x41, 0x5A, 0x7B, 0xC9, 0xF7, 0x178, 0x391, 0xFF21, 0xFFFF] {
        return Err("RtlUpcaseUnicodeChar gave the wrong capital");
    }
    let mut mixed: Vec<u16> = "abc \u{E9}\u{FF}z".encode_utf16().collect();
    let capital: Vec<u16> = "ABC \u{C9}\u{178}Z".encode_utf16().collect();
    let source = counted(&mut mixed);
    // SAFETY: every string names a local that outlives the calls, with
    // the room its `MaximumLength` says.
    unsafe {
        // Into a string the routine allocates: the text and no room
        // for a terminator.
        let mut made = UNICODE_STRING {
            Length: 0xEEEE,
            MaximumLength: 0xEEEE,
            Buffer: core::ptr::null_mut(),
        };
        if RtlUpcaseUnicodeString(&raw mut made, &raw const source, 1) != 0 {
            return Err("RtlUpcaseUnicodeString could not allocate a string");
        }
        let right = (made.Length, made.MaximumLength) == (14, 14)
            && (0..7).all(|at| made.Buffer.add(at).read() == capital[at]);
        RtlFreeUnicodeString(&raw mut made);
        if !right {
            return Err("the string RtlUpcaseUnicodeString allocated is wrong");
        }
        // Into the caller's buffer: too small is refused and the length
        // left alone; large enough keeps its room.
        let mut room = [0xEEEEu16; 16];
        let mut given = UNICODE_STRING {
            Length: 0,
            MaximumLength: 12,
            Buffer: room.as_mut_ptr(),
        };
        let status = RtlUpcaseUnicodeString(&raw mut given, &raw const source, 0);
        if status as u32 != 0x8000_0005 || given.Length != 0 || room[0] != 0xEEEE {
            return Err("a buffer too small for the capitals was not refused untouched");
        }
        given.MaximumLength = 32;
        let status = RtlUpcaseUnicodeString(&raw mut given, &raw const source, 0);
        if status != 0
            || (given.Length, given.MaximumLength) != (14, 32)
            || room[..7] != capital[..]
            || room[7] != 0xEEEE
        {
            return Err("the capitals were not written to the caller's buffer");
        }
        // In place.
        room[0] = 0x61;
        room[1] = 0x62;
        given.Length = 4;
        let same = &raw mut given;
        if RtlUpcaseUnicodeString(same, same, 0) != 0 || room[..3] != [0x41, 0x42, 0x43] {
            return Err("a string was not made capital in place");
        }
    }
    Ok(())
}

/// `RtlMultiByteToUnicodeN` and `RtlUnicodeToMultiByteN`: the ANSI code
/// page, Windows-1252.
fn multibyte() -> Result<(), &'static str> {
    use crate::rtl::string::{RtlMultiByteToUnicodeN, RtlUnicodeToMultiByteN};
    let mut room = [0xEEEEu16; 16];
    let to_wide = |room: &mut [u16; 16], max_bytes: u32, bytes: u32| {
        let mut converted = 0xEEEE_EEEEu32;
        // SAFETY: the room is 32 bytes and the source three; no call
        // names more.
        let status = unsafe {
            RtlMultiByteToUnicodeN(
                room.as_mut_ptr(),
                max_bytes,
                &raw mut converted,
                b"abc".as_ptr(),
                bytes,
            )
        };
        (status as u32, converted)
    };
    if to_wide(&mut room, 32, 3) != (0, 6) || room[..4] != [0x61, 0x62, 0x63, 0xEEEE] {
        return Err("three bytes did not become three characters and no terminator");
    }
    room = [0xEEEE; 16];
    // Room for two characters; then five bytes, whose odd one is none.
    if to_wide(&mut room, 4, 3) != (0x8000_0005, 4)
        || room[..3] != [0x61, 0x62, 0xEEEE]
        || to_wide(&mut room, 5, 3) != (0x8000_0005, 4)
        || room[2] != 0xEEEE
    {
        return Err("bytes that do not fit were not cut off with a warning");
    }
    // SAFETY: as above; the count may be left out.
    let status = unsafe {
        RtlMultiByteToUnicodeN(
            room.as_mut_ptr(),
            32,
            core::ptr::null_mut(),
            b"abc".as_ptr(),
            3,
        )
    };
    if to_wide(&mut room, 32, 0) != (0, 0) || status != 0 {
        return Err("no bytes, or no place for the count, was not accepted");
    }
    // Every byte alone, and back: 0x80 is the euro sign, 0xE9 itself.
    let mut sum = 0u32;
    for byte in 0..=255u8 {
        let (mut unit, mut back, mut converted) = (0xFFFFu16, 0u8, 0u32);
        // SAFETY: one byte into room for one character, and back.
        let status = unsafe {
            RtlMultiByteToUnicodeN(&raw mut unit, 2, &raw mut converted, &raw const byte, 1)
                | RtlUnicodeToMultiByteN(&raw mut back, 1, &raw mut converted, &raw const unit, 2)
        };
        if status != 0 || converted != 1 || back != byte {
            return Err("a byte did not survive the ANSI code page and back");
        }
        if !(0x80..0xA0).contains(&byte) && unit != u16::from(byte) {
            return Err("an ASCII or Latin-1 byte is not itself in the ANSI code page");
        }
        sum = sum.wrapping_add(u32::from(unit));
    }
    let (euro, han, mut narrow) = (0x20ACu16, [0x61u16, 0x4E00, 0x62], [0xEEu8; 4]);
    let mut converted = 0u32;
    // SAFETY: locals of the sizes named.
    let status = unsafe {
        RtlUnicodeToMultiByteN(
            narrow.as_mut_ptr(),
            1,
            core::ptr::null_mut(),
            &raw const euro,
            2,
        )
    };
    if status != 0 || narrow[0] != 0x80 {
        return Err("the euro sign is not byte 0x80");
    }
    // SAFETY: three characters into room for two bytes.
    let status = unsafe {
        RtlUnicodeToMultiByteN(narrow.as_mut_ptr(), 2, &raw mut converted, han.as_ptr(), 6)
    };
    if status as u32 != 0x8000_0005 || converted != 2 || narrow != [0x61, b'?', 0xEE, 0xEE] {
        return Err("a character the code page lacks is not `?`, or too many were written");
    }
    // The sum of what all 256 bytes become tells one code page from
    // another: this is Windows-1252's.
    if sum != 173_354 {
        return Err("the ANSI code page is not Windows-1252");
    }
    Ok(())
}

/// `RtlUnicodeStringToAnsiString` and `RtlFreeAnsiString`.
fn ansi_string() -> Result<(), &'static str> {
    use crate::mm::pool;
    use crate::rtl::string::{RtlFreeAnsiString, RtlUnicodeStringToAnsiString};
    let (mut abc, mut han, mut nothing) = ([0x61u16, 0x62, 0x63], [0x61u16, 0x4E00, 0x62], []);
    let (abc, han, nothing) = (counted(&mut abc), counted(&mut han), counted(&mut nothing));
    let blocks = pool::usage().blocks;
    // SAFETY: every string names a local that outlives the calls, with
    // the room its `MaximumLength` says.
    unsafe {
        let mut made = ANSI_STRING {
            Length: 0xEEEE,
            MaximumLength: 0xEEEE,
            Buffer: core::ptr::null_mut(),
        };
        if RtlUnicodeStringToAnsiString(&raw mut made, &raw const abc, 1) != 0 {
            return Err("RtlUnicodeStringToAnsiString could not allocate a string");
        }
        let right = (made.Length, made.MaximumLength) == (3, 4)
            && [0, 1, 2, 3].map(|at| made.Buffer.add(at).read()) == *b"abc\0";
        RtlFreeAnsiString(&raw mut made);
        if !right {
            return Err("the string RtlUnicodeStringToAnsiString allocated is wrong");
        }
        if !made.Buffer.is_null() || (made.Length, made.MaximumLength) != (0, 0) {
            return Err("RtlFreeAnsiString did not empty the string");
        }
        // The empty string takes one byte, its terminator.
        let status = RtlUnicodeStringToAnsiString(&raw mut made, &raw const nothing, 1);
        let right =
            status == 0 && (made.Length, made.MaximumLength) == (0, 1) && made.Buffer.read() == 0;
        RtlFreeAnsiString(&raw mut made);
        if !right || pool::usage().blocks != blocks {
            return Err("an empty string was not converted to a terminator alone, or leaked");
        }
        // Into the caller's buffer: three bytes hold "ab" and a
        // terminator, with a warning; eight hold it all.
        let mut room = [0xEEu8; 8];
        let mut given = ANSI_STRING {
            Length: 0,
            MaximumLength: 3,
            Buffer: room.as_mut_ptr(),
        };
        let status = RtlUnicodeStringToAnsiString(&raw mut given, &raw const abc, 0);
        if status as u32 != 0x8000_0005
            || (given.Length, given.MaximumLength) != (2, 3)
            || room[..4] != [0x61, 0x62, 0, 0xEE]
        {
            return Err("a string too long was not cut off, terminated, with a warning");
        }
        given.MaximumLength = 8;
        let status = RtlUnicodeStringToAnsiString(&raw mut given, &raw const abc, 0);
        if status != 0
            || (given.Length, given.MaximumLength) != (3, 8)
            || room[..5] != [0x61, 0x62, 0x63, 0, 0xEE]
        {
            return Err("a string that fits was not converted into the caller's buffer");
        }
        let status = RtlUnicodeStringToAnsiString(&raw mut given, &raw const han, 0);
        if status != 0 || given.Length != 3 || room[..4] != [0x61, b'?', 0x62, 0] {
            return Err("a character the code page lacks did not become `?`");
        }
        given.MaximumLength = 0;
        room[0] = 0xEE;
        let status = RtlUnicodeStringToAnsiString(&raw mut given, &raw const abc, 0);
        if status as u32 != 0x8000_0005 || room[0] != 0xEE {
            return Err("a buffer of no bytes was written to");
        }
    }
    Ok(())
}

/// `RtlStringFromGUID`.
fn guid() -> Result<(), &'static str> {
    use crate::rtl::print::RtlFreeUnicodeString;
    let guid = nk_ntabi::rtl::GUID {
        Data1: 0x1234_5678,
        Data2: 0x9ABC,
        Data3: 0xDEF0,
        Data4: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xAA, 0xFF],
    };
    let expected = wide("{12345678-9abc-def0-1122-33445566aaff}");
    let mut text = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: core::ptr::null_mut(),
    };
    // SAFETY: both name locals; the string made is read within its
    // `MaximumLength` and freed.
    unsafe {
        if crate::rtl::string::RtlStringFromGUID(&raw const guid, &raw mut text) != 0 {
            return Err("RtlStringFromGUID could not allocate a string");
        }
        let right = (text.Length, text.MaximumLength) == (76, 78)
            && (0..39).all(|at| text.Buffer.add(at).read() == expected[at]);
        RtlFreeUnicodeString(&raw mut text);
        if !right {
            return Err("a GUID's text is not 38 characters of lower-case digits, terminated");
        }
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("rtl.crt", crt);
    r.check("rtl.vsnwprintf", vsnwprintf);
    r.check("rtl.compare", compare);
    r.check("rtl.upcase", upcase);
    r.check("rtl.multibyte", multibyte);
    r.check("rtl.ansi-string", ansi_string);
    r.check("rtl.guid", guid);
}
