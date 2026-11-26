//! Tests of the runtime library through the routines drivers call: the
//! same calls as the conformance driver `nkc-rtl` makes, and the values
//! its source predicts of Windows.

use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::ffi::CStr;
use nk_bootinfo::BootInfo;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::rtl::{ANSI_STRING, UNICODE_PREFIX_TABLE, UNICODE_PREFIX_TABLE_ENTRY};

pub static GROUP: Group = Group {
    names: &[
        "rtl.crt",
        "rtl.vsnwprintf",
        "rtl.compare",
        "rtl.upcase",
        "rtl.multibyte",
        "rtl.ansi-string",
        "rtl.guid",
        "rtl.sid",
        "rtl.sid-text",
        "rtl.app-container",
        "rtl.acl",
        "rtl.owner-group",
        "rtl.prefix-table",
        "rtl.wildcards",
        "rtl.legal-characters",
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
    // By Windows' table, which leaves the micro sign and the dotless i
    // as they are.
    let capitals = [
        0x61, 0x7A, 0x7B, 0xB5, 0xE9, 0xF7, 0xFF, 0x131, 0x3B1, 0xFF41, 0xFFFF,
    ]
    .map(|c| RtlUpcaseUnicodeChar(c));
    let expected = [
        0x41, 0x5A, 0x7B, 0xB5, 0xC9, 0xF7, 0x178, 0x131, 0x391, 0xFF21, 0xFFFF,
    ];
    if capitals != expected {
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

/// Room for the largest SID, aligned as one is.
#[repr(C, align(4))]
struct SidRoom([u8; nk_se::SID_MAX_SIZE]);

impl SidRoom {
    /// S-1-`authority`-`subs`, built the way a driver builds one.
    fn new(authority: u8, subs: &[u32]) -> Self {
        use crate::se::sid::{RtlInitializeSid, RtlSubAuthoritySid};
        let mut room = Self([0xEE; nk_se::SID_MAX_SIZE]);
        let value = [0, 0, 0, 0, 0, authority];
        // SAFETY: the room holds the largest SID; no caller passes more
        // than fifteen sub-authorities.
        unsafe {
            RtlInitializeSid(room.0.as_mut_ptr(), value.as_ptr(), subs.len() as u8);
            for (index, &sub) in subs.iter().enumerate() {
                RtlSubAuthoritySid(room.0.as_ptr(), index as u32).write(sub);
            }
        }
        room
    }

    fn at(&self) -> *const u8 {
        self.0.as_ptr()
    }
}

/// SIDs built, measured, compared, judged and copied.
fn sid() -> Result<(), &'static str> {
    use crate::se::sid::*;
    use crate::se::{RtlLengthSid, SeExports};
    // SAFETY: every SID is in room for the largest one, or is one of
    // the kernel's own.
    unsafe {
        let mut room = SidRoom([0xEE; nk_se::SID_MAX_SIZE]);
        let nt = [0u8, 0, 0, 0, 0, 5];
        let one = room.0.as_mut_ptr();
        if RtlLengthRequiredSid(2) != 16 || RtlInitializeSid(one, nt.as_ptr(), 2) != 0 {
            return Err("a SID of two sub-authorities was not measured or initialised");
        }
        let places = [
            *RtlSubAuthorityCountSid(one) as usize,
            RtlSubAuthoritySid(one, 0) as usize - one as usize,
            RtlSubAuthoritySid(one, 1) as usize - one as usize,
        ];
        if places != [2, 8, 12] || room.0[16] != 0xEE {
            return Err("a SID's count or sub-authorities are not where Windows has them");
        }
        *RtlSubAuthoritySid(one, 0) = 32;
        *RtlSubAuthoritySid(one, 1) = 544;
        let table = SeExports.table();
        if RtlLengthSid(one) != 16
            || RtlValidSid(one) != 1
            || RtlEqualSid(one, (*table).SeAliasAdminsSid) != 1
            || RtlEqualSid(one, (*table).SeLocalSystemSid) != 0
        {
            return Err("a SID built by hand is not the administrators' SID");
        }
        let equal = [
            RtlEqualSid(one, SidRoom::new(5, &[32, 545]).at()),
            RtlEqualSid(one, SidRoom::new(5, &[32]).at()),
            RtlEqualSid(one, SidRoom::new(1, &[32, 544]).at()),
            RtlEqualSid(one, one),
        ];
        if equal != [0, 0, 0, 1] {
            return Err("RtlEqualSid called different SIDs equal, or a SID unlike itself");
        }
        let fifteen = SidRoom::new(5, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let (mut sixteen, mut revised) = (SidRoom::new(5, &[1]), SidRoom::new(5, &[32, 544]));
        sixteen.0[1] = 16;
        revised.0[0] = 2;
        let valid = [
            RtlValidSid(fifteen.at()),
            RtlValidSid(sixteen.at()),
            RtlValidSid(revised.at()),
            RtlValidSid(SidRoom::new(5, &[]).at()),
            RtlValidSid(core::ptr::null()),
        ];
        if valid != [1, 0, 0, 1, 0] {
            return Err("RtlValidSid judged a SID wrongly");
        }
        let mut copy = SidRoom([0xEE; nk_se::SID_MAX_SIZE]);
        if RtlCopySid(16, copy.0.as_mut_ptr(), one) != 0
            || RtlEqualSid(copy.at(), one) != 1
            || copy.0[16] != 0xEE
        {
            return Err("RtlCopySid did not copy a SID, or wrote past it");
        }
        copy.0[0] = 0xEE;
        if RtlCopySid(15, copy.0.as_mut_ptr(), one) as u32 != 0xC000_0023 || copy.0[0] != 0xEE {
            return Err("RtlCopySid wrote a SID into less room than it needs");
        }
    }
    Ok(())
}

/// `RtlConvertSidToUnicodeString`.
fn sid_text() -> Result<(), &'static str> {
    use crate::rtl::print::RtlFreeUnicodeString;
    use crate::se::sid::RtlConvertSidToUnicodeString;
    /// The status, and whether the allocated string is `expected` with
    /// room for its terminator.
    fn text(sid: &SidRoom, expected: &str) -> (u32, bool) {
        let mut made = UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: core::ptr::null_mut(),
        };
        let expected = wide(expected);
        // SAFETY: the SID is in room for the largest one; the string
        // made is read within its `MaximumLength` and freed.
        unsafe {
            let status = RtlConvertSidToUnicodeString(&raw mut made, sid.at(), 1) as u32;
            if status != 0 {
                return (status, made.Buffer.is_null());
            }
            let bytes = expected.len() * 2;
            let right = (usize::from(made.Length), usize::from(made.MaximumLength))
                == (bytes - 2, bytes)
                && (0..expected.len()).all(|at| made.Buffer.add(at).read() == expected[at]);
            RtlFreeUnicodeString(&raw mut made);
            (status, right)
        }
    }
    let mut wide_authority = SidRoom::new(5, &[18]);
    wide_authority.0[2] = 1;
    let mut revised = SidRoom::new(5, &[18]);
    revised.0[0] = 2;
    if text(&SidRoom::new(5, &[32, 544]), "S-1-5-32-544") != (0, true)
        || text(&SidRoom::new(5, &[18]), "S-1-5-18") != (0, true)
        || text(
            &SidRoom::new(5, &[u32::MAX, 0x8000_0000]),
            "S-1-5-4294967295-2147483648",
        ) != (0, true)
    {
        return Err("a SID's text is wrong");
    }
    if text(&wide_authority, "S-1-0x010000000005-18") != (0, true) {
        return Err("an authority beyond 32 bits is not printed in hexadecimal");
    }
    if text(&revised, "") != (0xC000_0078, true) {
        return Err("a SID of another revision was printed");
    }
    // Into the caller's buffer: twelve characters need room for
    // thirteen.
    let admins = SidRoom::new(5, &[32, 544]);
    let mut room = [0xEEEEu16; 16];
    let mut given = UNICODE_STRING {
        Length: 0,
        MaximumLength: 16,
        Buffer: room.as_mut_ptr(),
    };
    // SAFETY: the buffer has the sixteen units the last call is told of.
    unsafe {
        let status = RtlConvertSidToUnicodeString(&raw mut given, admins.at(), 0);
        if status as u32 != 0x8000_0005 || given.Length != 0 || room[0] != 0xEEEE {
            return Err("text that does not fit the caller's buffer was not refused");
        }
        given.MaximumLength = 24;
        let status = RtlConvertSidToUnicodeString(&raw mut given, admins.at(), 0);
        if status as u32 != 0x8000_0005 {
            return Err("text without room for its terminator was not refused");
        }
        given.MaximumLength = 26;
        let status = RtlConvertSidToUnicodeString(&raw mut given, admins.at(), 0);
        if status != 0
            || (given.Length, given.MaximumLength) != (24, 26)
            || room[..14] != [wide("S-1-5-32-544"), alloc::vec![0xEEEE]].concat()[..]
        {
            return Err("a SID's text was not written to the caller's buffer");
        }
    }
    Ok(())
}

/// `RtlGetAppContainerSidType` and `RtlGetAppContainerParent`.
fn app_container() -> Result<(), &'static str> {
    use crate::mm::pool;
    use crate::se::sid::{RtlEqualSid, RtlGetAppContainerParent, RtlGetAppContainerSidType};
    const PACKAGE: [u32; 12] = [2, 11, 22, 33, 44, 55, 66, 77, 1001, 1002, 1003, 1004];
    /// The first routine's status and the type it stored; the second's
    /// status and whether it gave the SID's first eight sub-authorities.
    fn asked(sid: &SidRoom) -> (u32, u32, u32, bool) {
        let mut kind = 0xEEEE_EEEEu32;
        let mut parent: *const u8 = core::ptr::null();
        // SAFETY: the SID is in room for the largest one; a parent
        // returned is a pool block, compared and freed.
        unsafe {
            let first = RtlGetAppContainerSidType(sid.at(), &raw mut kind) as u32;
            let second = RtlGetAppContainerParent(sid.at(), &raw mut parent) as u32;
            let mut right = false;
            if !parent.is_null() {
                right = RtlEqualSid(parent, SidRoom::new(15, &PACKAGE[..8]).at()) == 1;
                pool::ExFreePoolWithTag(parent.cast_mut().cast(), 0);
            }
            (first, kind, second, right)
        }
    }
    const NOT_APPCONTAINER: u32 = 0xC000_0200;
    const INVALID_PARAMETER: u32 = 0xC000_000D;
    if asked(&SidRoom::new(5, &[18])) != (NOT_APPCONTAINER, 0, NOT_APPCONTAINER, false)
        || asked(&SidRoom::new(15, &[3, 1])) != (NOT_APPCONTAINER, 0, NOT_APPCONTAINER, false)
    {
        return Err("a SID that is no app container's was taken for one");
    }
    if asked(&SidRoom::new(15, &PACKAGE[..8])) != (0, 2, INVALID_PARAMETER, false) {
        return Err("a package's SID is not a parent, or was given a parent");
    }
    if asked(&SidRoom::new(15, &PACKAGE)) != (0, 1, 0, true) {
        return Err("a child's SID did not give its parent");
    }
    if asked(&SidRoom::new(15, &PACKAGE[..2])) != (0, 3, INVALID_PARAMETER, false)
        || asked(&SidRoom::new(15, &PACKAGE[..9])) != (0, 3, INVALID_PARAMETER, false)
    {
        return Err("a package SID of the wrong length is not of the invalid type");
    }
    Ok(())
}

/// `RtlCreateAcl`.
fn acl() -> Result<(), &'static str> {
    use crate::se::sid::RtlCreateAcl;
    let mut room = [0xEEEE_EEEEu32; 32];
    let acl = room.as_mut_ptr().cast::<core::ffi::c_void>();
    let create = |length: u32, revision: u32| {
        // SAFETY: the room is 128 bytes; a length beyond it is refused
        // before anything is written.
        let status = unsafe { RtlCreateAcl(acl, length, revision) } as u32;
        // SAFETY: the room is initialised and aligned.
        (status, unsafe { acl.cast::<[u32; 3]>().read() })
    };
    // Revision, a zero byte, the size; no entries, a zero word; and
    // nothing after the header.
    if create(64, 2) != (0, [0x0040_0002, 0, 0xEEEE_EEEE])
        || create(64, 4) != (0, [0x0040_0004, 0, 0xEEEE_EEEE])
        // A size is brought down to a multiple of four.
        || create(67, 3) != (0, [0x0040_0003, 0, 0xEEEE_EEEE])
    {
        return Err("RtlCreateAcl did not write an empty list's header");
    }
    let untouched = [0x0040_0003, 0, 0xEEEE_EEEE];
    if create(64, 1) != (0xC000_000D, untouched)
        || create(64, 5) != (0xC000_000D, untouched)
        || create(4, 2) != (0xC000_0023, untouched)
        || create(0x1_0000, 2) != (0xC000_000D, untouched)
    {
        return Err("RtlCreateAcl took a revision or a size an access list cannot have");
    }
    Ok(())
}

/// Owner and group of a descriptor, and `RtlValidSecurityDescriptor`.
fn owner_group() -> Result<(), &'static str> {
    use crate::se::sid::RtlCreateAcl;
    use crate::se::*;
    use nk_ntabi::se::SECURITY_DESCRIPTOR;
    let admins = SidRoom::new(5, &[32, 544]);
    let mut revised = SidRoom::new(5, &[32, 544]);
    revised.0[0] = 2;
    let sid = admins.at().cast_mut().cast::<core::ffi::c_void>();
    let mut log = Vec::new();
    // SAFETY: every pointer names a local that outlives the calls.
    unsafe {
        let mut sd = core::mem::zeroed::<SECURITY_DESCRIPTOR>();
        let at = &raw mut sd;
        let control = |at: *mut SECURITY_DESCRIPTOR| u32::from((&raw const (*at).Control).read());
        RtlCreateSecurityDescriptor(at, 1);
        log.push(RtlSetOwnerSecurityDescriptor(at, sid, 0) as u32);
        log.push(u32::from((&raw const (*at).Owner).read() == sid));
        log.push(control(at) & 1);
        log.push(RtlSetOwnerSecurityDescriptor(at, sid, 1) as u32);
        log.push(control(at) & 1);
        let (mut got, mut defaulted) = (core::ptr::null_mut(), 0xEEu8);
        log.push(RtlGetOwnerSecurityDescriptor(at.cast(), &raw mut got, &raw mut defaulted) as u32);
        log.push(u32::from(got == sid));
        log.push(u32::from(defaulted));
        log.push(RtlSetGroupSecurityDescriptor(at, sid, 1) as u32);
        log.push(u32::from((&raw const (*at).Group).read() == sid));
        log.push(control(at) & 2);
        log.push(RtlSetOwnerSecurityDescriptor(at, core::ptr::null_mut(), 0) as u32);
        log.push(u32::from((&raw const (*at).Owner).read().is_null()));
        log.push(control(at) & 1);
        if log != [0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 2, 0, 1, 0] {
            return Err("owner or group was not set, cleared or marked defaulted");
        }
        log.clear();
        // Valid with a group and no owner; with an owner and an access
        // list; not with an owner of revision 2, nor at revision 2, nor
        // with a damaged list; valid again in self-relative form.
        let mut list = [0u32; 16];
        let dacl = list.as_mut_ptr().cast::<core::ffi::c_void>();
        RtlCreateAcl(dacl, 64, 2);
        log.push(u32::from(RtlValidSecurityDescriptor(at.cast())));
        RtlSetOwnerSecurityDescriptor(at, sid, 0);
        RtlSetDaclSecurityDescriptor(at, 1, dacl, 0);
        log.push(u32::from(RtlValidSecurityDescriptor(at.cast())));
        RtlSetOwnerSecurityDescriptor(at, revised.at().cast_mut().cast(), 0);
        log.push(u32::from(RtlValidSecurityDescriptor(at.cast())));
        RtlSetOwnerSecurityDescriptor(at, sid, 0);
        (&raw mut (*at).Revision).write(2);
        log.push(u32::from(RtlValidSecurityDescriptor(at.cast())));
        (&raw mut (*at).Revision).write(1);
        // One entry claimed, none there.
        dacl.cast::<u32>().add(1).write(1);
        log.push(u32::from(RtlValidSecurityDescriptor(at.cast())));
        dacl.cast::<u32>().add(1).write(0);
        let mut relative = [0u8; 128];
        let mut length = 128u32;
        log.push(
            RtlAbsoluteToSelfRelativeSD(at.cast(), relative.as_mut_ptr(), &raw mut length) as u32,
        );
        log.push(u32::from(RtlValidSecurityDescriptor(
            relative.as_ptr().cast(),
        )));
        if log != [1, 1, 0, 0, 0, 0, 1] {
            return Err("RtlValidSecurityDescriptor judged a descriptor wrongly");
        }
        log.clear();
        // Neither can be set in a self-relative descriptor, nor in one
        // of another revision; and nothing is written.
        let block = relative.as_mut_ptr().cast::<SECURITY_DESCRIPTOR>();
        let before = relative;
        log.push(RtlSetOwnerSecurityDescriptor(block, sid, 0) as u32);
        log.push(RtlSetGroupSecurityDescriptor(block, sid, 0) as u32);
        (&raw mut (*at).Revision).write(2);
        (&raw mut (*at).Group).write(core::ptr::null_mut());
        log.push(RtlSetOwnerSecurityDescriptor(at, sid, 0) as u32);
        log.push(RtlSetGroupSecurityDescriptor(at, sid, 0) as u32);
        if log != [0xC000_0079, 0xC000_0079, 0xC000_0058, 0xC000_0058]
            || relative != before
            || !(&raw const (*at).Group).read().is_null()
        {
            return Err("owner or group was set where a descriptor has no pointer for it");
        }
    }
    Ok(())
}

/// A prefix table as a driver keeps one: the table, five entries and
/// their names in one block of pool, every byte 0xEE before the
/// routines see it.
#[repr(C)]
struct Prefixes {
    table: UNICODE_PREFIX_TABLE,
    entries: [UNICODE_PREFIX_TABLE_ENTRY; 5],
    names: [UNICODE_STRING; 5],
    text: [[u16; 8]; 5],
}

/// The prefix table over driver-style memory: the calls of `nkc-rtl`.
fn prefix_table() -> Result<(), &'static str> {
    use crate::mm::pool;
    use crate::rtl::RtlInitUnicodeString;
    use crate::rtl::prefix::*;
    let block = pool::alloc(size_of::<Prefixes>(), u32::from_le_bytes(*b"Test")).cast::<Prefixes>();
    if block.is_null() {
        return Err("no memory for a prefix table");
    }
    // SAFETY: the block is the test's own, large enough for a
    // `Prefixes`, and reached through raw pointers alone, as a driver's
    // is; every name is NUL-terminated within its eight units.
    let result = unsafe {
        block.cast::<u8>().write_bytes(0xEE, size_of::<Prefixes>());
        let table = &raw mut (*block).table;
        let entries = (&raw mut (*block).entries).cast::<UNICODE_PREFIX_TABLE_ENTRY>();
        let names = (&raw mut (*block).names).cast::<UNICODE_STRING>();
        let texts = (&raw mut (*block).text).cast::<[u16; 8]>();
        let entry = move |number: usize| entries.add(number - 1);
        // Put `name` in the table as entry `number` (1 to 5).
        let insert = move |number: usize, name: &str| {
            let text = texts.add(number - 1).cast::<u16>();
            for (at, unit) in name.encode_utf16().chain([0]).enumerate() {
                text.add(at).write(unit);
            }
            let counted = names.add(number - 1);
            RtlInitUnicodeString(counted, text);
            RtlInsertUnicodePrefix(table, counted, entry(number))
        };
        // The number of the entry found for `name`; 0 for none.
        let find = move |name: &str, index: u32| {
            let mut text: Vec<u16> = name.encode_utf16().collect();
            let full = counted(&mut text);
            let found = RtlFindUnicodePrefix(table, &raw const full, index);
            if found.is_null() {
                0
            } else {
                found.offset_from(entries) + 1
            }
        };
        let finds = move |wanted: &[(&str, u32, isize)]| {
            wanted
                .iter()
                .all(|&(name, index, number)| find(name, index) == number)
        };
        'calls: {
            RtlInitializeUnicodePrefix(table);
            if (&raw const (*table).NodeTypeCode).read() != 0x800 || find("\\a", 0) != 0 {
                break 'calls Err("an initialised table is not an empty table");
            }
            let inserted = [
                insert(1, "\\a"),
                insert(2, "\\a\\b"),
                insert(3, "\\a\\b\\c"),
                insert(4, "\\x"),
                insert(5, "\\a"),
            ];
            if inserted != [1, 1, 1, 1, 0] {
                break 'calls Err("four names did not go in, or one went in twice");
            }
            // An entry is what `ntifs.h` says: the count of its name's
            // components, and the caller's name pointed to, not copied.
            let third = entry(3);
            if (&raw const (*third).NameLength).read() != 4
                || (&raw const (*third).Prefix).read() != names.add(2)
            {
                break 'calls Err("an entry does not hold its name's length and the name");
            }
            if !finds(&[
                ("\\a\\b\\c\\d", 0, 3),
                ("\\a\\b\\c", 0, 3),
                ("\\a\\b", 0, 2),
                ("\\a\\bc", 0, 1),
                ("\\a", 0, 1),
                ("\\ab", 0, 0),
                ("\\y", 0, 0),
                ("\\x\\a\\b", 0, 4),
                ("a\\b", 0, 0),
                ("\\a\\b\\", 0, 2),
            ]) {
                break 'calls Err("the longest prefix on a component boundary was not found");
            }
            if !finds(&[
                ("\\A\\B\\X", 0, 2),
                ("\\A\\B\\X", 100, 0),
                ("\\a\\B\\X", 100, 1),
                ("\\a\\B", 3, 2),
                ("\\a\\B", 6, 1),
            ]) {
                break 'calls Err("case was not regarded up to the index and disregarded after");
            }
            RtlRemoveUnicodePrefix(table, entry(2));
            let after_one = [find("\\a\\b\\c\\d", 0), find("\\a\\b", 0)];
            RtlRemoveUnicodePrefix(table, entry(3));
            if after_one != [3, 1] || find("\\a\\b\\c\\d", 0) != 1 {
                break 'calls Err("a removed name was found, or took others with it");
            }
            if insert(3, "\\") != 1
                || !finds(&[
                    ("\\zzz", 0, 3),
                    ("\\x\\y", 0, 4),
                    ("\\a\\q", 0, 1),
                    ("zzz", 0, 0),
                ])
            {
                break 'calls Err("the name `\\` does not start every name with nothing longer");
            }
            // A name that differs in case is another name; each is
            // found by its own spelling, and the one first in without
            // regard to case.
            if insert(2, "\\X") != 1
                || !finds(&[
                    ("\\X", 100, 2),
                    ("\\x", 100, 4),
                    ("\\x", 0, 4),
                    ("\\X", 0, 4),
                ])
            {
                break 'calls Err("names that differ in case were not kept apart");
            }
            RtlRemoveUnicodePrefix(table, entry(4));
            if !finds(&[("\\x\\y", 100, 3), ("\\x\\y", 0, 2)]) {
                break 'calls Err("removing one of two names alike but for case lost the other");
            }
            for number in 1..=3 {
                RtlRemoveUnicodePrefix(table, entry(number));
            }
            if !finds(&[("\\a", 0, 0), ("\\", 0, 0)])
                || (&raw const (*table).NextPrefixTree).read() != table.cast()
            {
                break 'calls Err("a table with every name removed is not empty");
            }
            Ok(())
        }
    };
    // SAFETY: the block came from the pool and nothing points to it.
    unsafe { pool::ExFreePoolWithTag(block.cast(), 0) };
    result
}

/// `FsRtlIsNameInExpression`, with the system's table of capitals and
/// with the caller's.
fn wildcards() -> Result<(), &'static str> {
    use crate::mm::pool;
    use crate::rtl::name::FsRtlIsNameInExpression;
    use crate::rtl::string::RtlUpcaseUnicodeChar;
    let matches = |expression: &str, name: &str, ignore_case: u8, table: *const u16| {
        let (mut expression, mut name): (Vec<u16>, Vec<u16>) = (
            expression.encode_utf16().collect(),
            name.encode_utf16().collect(),
        );
        let (expression, name) = (counted(&mut expression), counted(&mut name));
        // SAFETY: both name locals; the table is null or the 65536
        // units allocated below.
        unsafe {
            FsRtlIsNameInExpression(&raw const expression, &raw const name, ignore_case, table)
        }
    };
    // `<` is DOS_STAR, `>` DOS_QM and `"` DOS_DOT.
    let none = core::ptr::null();
    for (expression, name, ignore_case, expected) in [
        ("*", "anything", 0, 1),
        ("*", "", 0, 0),
        ("", "", 0, 1),
        ("abc", "ABC", 0, 0),
        ("ABC", "abc", 1, 1),
        // The expression is not made capital.
        ("abc", "ABC", 1, 0),
        ("*.txt", "file.txt", 0, 1),
        ("*.txt", "file.txt.bak", 0, 0),
        ("*.TXT", "file.txt", 1, 1),
        ("a*b*c", "aXbYc", 0, 1),
        ("*a*a*a*a", "aaa", 0, 0),
        ("*.*", "file", 0, 0),
        ("a?c", "a.c", 0, 1),
        ("a?", "a", 0, 0),
        ("<.txt", "a.b.txt", 0, 1),
        ("<.b", "a.b.c", 0, 0),
        ("<\"*", "file", 0, 1),
        ("a>", "a", 0, 1),
        ("a>c", "ac", 0, 0),
        (">>>>>>>>\">>>", "abc.de", 0, 1),
        (">>>>>>>>\">>>", "abc.defg", 0, 0),
        ("a\"", "a.", 0, 1),
        ("a\"b", "ab", 0, 0),
        ("<.TXT", "File.Txt", 1, 1),
        // The system's table: e acute, and alpha.
        ("\u{C9}*", "\u{E9}x", 1, 1),
        ("\u{C9}*", "\u{E9}x", 0, 0),
        ("\u{391}?", "\u{3B1}\u{3B2}", 1, 1),
    ] {
        if matches(expression, name, ignore_case, none) != expected {
            return Err("a name was matched against a wildcard expression wrongly");
        }
    }
    // The caller's own table of capitals: one that leaves every
    // character as it is, one that says what the system's says, and
    // one that makes every character `X`.
    let table = pool::alloc(0x1_0000 * 2, u32::from_le_bytes(*b"Test")).cast::<u16>();
    if table.is_null() {
        return Err("no memory for a table of capitals");
    }
    let fill = |capital: &dyn Fn(u16) -> u16| {
        for c in 0..=u16::MAX {
            // SAFETY: the block holds 65536 units.
            unsafe { table.add(usize::from(c)).write(capital(c)) };
        }
    };
    fill(&|c| c);
    let same = [
        matches("ABC", "abc", 1, table),
        matches("abc", "abc", 1, table),
    ];
    fill(&|c| RtlUpcaseUnicodeChar(c));
    let system = [
        matches("ABC", "abc", 1, table),
        matches("*.TXT", "file.txt", 1, table),
        // With case regarded a table is not used.
        matches("ABC", "abc", 0, table),
    ];
    fill(&|_| 0x58);
    let all_x = matches("X?X", "abc", 1, table);
    // SAFETY: the block came from the pool and nothing points to it.
    unsafe { pool::ExFreePoolWithTag(table.cast(), 0) };
    if same != [0, 1] || system != [1, 1, 0] || all_x != 1 {
        return Err("the caller's table of capitals was not used for the name");
    }
    Ok(())
}

/// `FsRtlLegalAnsiCharacterArray`, read the way the header's macros
/// read it: the import is the address of a pointer to the table.
fn legal_characters() -> Result<(), &'static str> {
    let import = crate::export::resolve(b"ntoskrnl.exe", b"FsRtlLegalAnsiCharacterArray")
        .ok_or("FsRtlLegalAnsiCharacterArray is not exported")?
        as *const *const u8;
    // `FsRtlTestAnsiCharacter`: any of the flags, or the wildcard flag
    // if wildcards are let through.
    let test = |c: u8, wild_ok: bool, flags: u8| {
        // SAFETY: the export is a pointer to a table of 128 bytes, and
        // every character asked about is below 0x80.
        let entry = unsafe { (*import).add(usize::from(c)).read() };
        entry & (flags | if wild_ok { 8 } else { 0 }) != 0
    };
    let (fat, hpfs, ntfs, stream) = (1, 2, 4, 4 | 16);
    if !test(b'a', false, fat) || !test(b'~', false, fat) || !test(b' ', false, fat) {
        return Err("a letter is not legal in a FAT name");
    }
    if test(b'+', false, fat) || !test(b'+', false, hpfs) || test(b':', false, hpfs) {
        return Err("FAT's and HPFS's own exclusions are not in the table");
    }
    if !test(b':', false, ntfs) || test(b'\\', true, fat | hpfs | ntfs) || test(0x1F, true, ntfs) {
        return Err("a backslash or a control character is legal in a file's name");
    }
    if test(b'*', false, ntfs) || !test(b'*', true, ntfs) || !test(b'<', true, fat) {
        return Err("a wildcard is not legal exactly when wildcards are let through");
    }
    if !test(b'|', false, stream) || !test(1, false, stream) || test(b'/', false, stream) {
        return Err("a stream's name does not take what a file's refuses");
    }
    let wild = (0..128).filter(|&c| test(c, false, 8)).count();
    if wild != 5 {
        return Err("there are not five wildcard characters");
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
    r.check("rtl.sid", sid);
    r.check("rtl.sid-text", sid_text);
    r.check("rtl.app-container", app_container);
    r.check("rtl.acl", acl);
    r.check("rtl.owner-group", owner_group);
    r.check("rtl.prefix-table", prefix_table);
    r.check("rtl.wildcards", wildcards);
    r.check("rtl.legal-characters", legal_characters);
}
