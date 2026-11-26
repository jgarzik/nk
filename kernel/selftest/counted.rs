//! Counted strings, conversions and the C runtime's string functions
//! through the routines drivers call. The rules themselves are tested
//! on the host (`nk_rtl::counted`, `nk_rtl::convert`, `nk_rtl::crt`).

use crate::rtl::counted::*;
use crate::rtl::crt::{
    _strnicmp, _strtoui64, _strupr, isspace, rand, strchr, strncpy_s, strnlen, strstr, strtok_s,
};
use crate::rtl::print::{_vsnprintf, RtlFreeUnicodeString};
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::ffi::CStr;
use nk_bootinfo::BootInfo;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::rtl::{GUID, STRING, TIME_FIELDS};
use nk_ntabi::status::*;

static GROUP: Group = Group {
    names: &["rtl.counted", "rtl.crt-strings"],
    run,
    manual: false,
};

const EMPTY: UNICODE_STRING = UNICODE_STRING {
    Length: 0,
    MaximumLength: 0,
    Buffer: core::ptr::null_mut(),
};

/// A counted string over `units`, all of it text.
fn counted_over(units: &mut [u16]) -> UNICODE_STRING {
    UNICODE_STRING {
        Length: (units.len() * 2) as u16,
        MaximumLength: (units.len() * 2) as u16,
        Buffer: units.as_mut_ptr(),
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// The text of a counted string.
///
/// # Safety
/// `string` is a counted string whose buffer holds `Length` bytes.
unsafe fn text(string: &UNICODE_STRING) -> Vec<u16> {
    // SAFETY: per the contract.
    (0..usize::from(string.Length) / 2)
        .map(|at| unsafe { string.Buffer.add(at).read() })
        .collect()
}

fn counted() -> Result<(), &'static str> {
    // SAFETY: every string is a local or a constant, with the buffer its
    // header says.
    unsafe {
        let mut narrow = STRING {
            Length: 9,
            MaximumLength: 9,
            Buffer: core::ptr::null_mut(),
        };
        RtlInitString(&raw mut narrow, c"caf\xE9".as_ptr().cast());
        if (narrow.Length, narrow.MaximumLength) != (4, 5) {
            return Err("RtlInitString did not count the string");
        }
        RtlInitAnsiString(&raw mut narrow, core::ptr::null());
        if (narrow.Length, narrow.MaximumLength) != (0, 0) || !narrow.Buffer.is_null() {
            return Err("RtlInitAnsiString of no string is not empty");
        }
        RtlInitAnsiString(&raw mut narrow, c"caf\xE9".as_ptr().cast());
        if RtlxAnsiStringToUnicodeSize(&raw const narrow) != 10 {
            return Err("RtlxAnsiStringToUnicodeSize is not the text and a terminator");
        }

        // Conversion, into a buffer allocated for it and into too small
        // a one.
        let mut converted = EMPTY;
        if RtlAnsiStringToUnicodeString(&raw mut converted, &raw const narrow, 1) != STATUS_SUCCESS
            || text(&converted) != wide("caf\u{E9}")
            || converted.MaximumLength != 10
            || converted.Buffer.add(4).read() != 0
        {
            return Err("RtlAnsiStringToUnicodeString did not allocate the converted text");
        }
        RtlFreeUnicodeString(&raw mut converted);
        let mut room = [0xFFFFu16; 5];
        let mut small = counted_over(&mut room[..4]);
        if RtlAnsiStringToUnicodeString(&raw mut small, &raw const narrow, 0)
            != STATUS_BUFFER_OVERFLOW
            || small.Length != 8
            || room != [0xFFFF; 5]
        {
            return Err("RtlAnsiStringToUnicodeString wrote text that does not fit");
        }
        let mut cursor = narrow.Buffer.add(3);
        if RtlAnsiCharToUnicodeChar(&raw mut cursor) != 0xE9 || cursor != narrow.Buffer.add(4) {
            return Err("RtlAnsiCharToUnicodeChar did not convert a byte and step past it");
        }

        // Append and copy.
        let mut buffer = [0xFFFFu16; 8];
        let mut target = UNICODE_STRING {
            Length: 0,
            MaximumLength: 14,
            Buffer: buffer.as_mut_ptr(),
        };
        let (mut ab, mut cdef) = (wide("ab"), wide("cdef"));
        let (ab, cdef) = (counted_over(&mut ab), counted_over(&mut cdef));
        RtlCopyUnicodeString(&raw mut target, &raw const ab);
        if RtlAppendUnicodeStringToString(&raw mut target, &raw const cdef) != STATUS_SUCCESS
            || text(&target) != wide("abcdef")
            || buffer[6] != 0
            || buffer[7] != 0xFFFF
        {
            return Err("copy then append did not make the two strings one");
        }
        if RtlAppendUnicodeStringToString(&raw mut target, &raw const ab) != STATUS_BUFFER_TOO_SMALL
            || target.Length != 12
        {
            return Err("RtlAppendUnicodeStringToString appended what does not fit");
        }
        RtlCopyUnicodeString(&raw mut target, core::ptr::null());
        if target.Length != 0 {
            return Err("RtlCopyUnicodeString of no string did not empty the destination");
        }

        // Duplicate.
        let mut copy = EMPTY;
        if RtlDuplicateUnicodeString(1, &raw const cdef, &raw mut copy) != STATUS_SUCCESS
            || text(&copy) != wide("cdef")
            || copy.MaximumLength != 10
            || copy.Buffer == cdef.Buffer
            || copy.Buffer.add(4).read() != 0
        {
            return Err("RtlDuplicateUnicodeString did not copy and terminate the string");
        }
        RtlFreeUnicodeString(&raw mut copy);
        if RtlDuplicateUnicodeString(2, &raw const cdef, &raw mut copy) != STATUS_INVALID_PARAMETER
            || RtlDuplicateUnicodeString(0, &raw const cdef, core::ptr::null_mut())
                != STATUS_INVALID_PARAMETER
        {
            return Err("RtlDuplicateUnicodeString took flags or a destination it refuses");
        }
        if RtlDuplicateUnicodeString(0, core::ptr::null(), &raw mut copy) != STATUS_SUCCESS
            || !copy.Buffer.is_null()
        {
            return Err("RtlDuplicateUnicodeString allocated for an empty string");
        }

        // Comparison.
        let (mut upper, mut lower) = (wide("CAF\u{C9}"), wide("caf\u{E9}"));
        let (upper, lower) = (counted_over(&mut upper), counted_over(&mut lower));
        if RtlCompareUnicodeString(&raw const upper, &raw const lower, 1) != 0
            || RtlCompareUnicodeString(&raw const upper, &raw const lower, 0) != -0x20
            || RtlCompareUnicodeString(&raw const ab, &raw const lower, 1) >= 0
            || RtlEqualUnicodeString(&raw const upper, &raw const lower, 1) != 1
            || RtlEqualUnicodeString(&raw const upper, &raw const lower, 0) != 0
            || RtlEqualUnicodeString(&raw const ab, &raw const cdef, 1) != 0
        {
            return Err("the counted-string comparisons misjudged case or order");
        }
        let mut shout = STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: core::ptr::null_mut(),
        };
        RtlInitString(&raw mut shout, c"CAF\xC9!".as_ptr().cast());
        if RtlCompareString(&raw const narrow, &raw const shout, 1) != -1
            || RtlCompareString(&raw const narrow, &raw const shout, 0) != 0x20
        {
            return Err("RtlCompareString misjudged case or length");
        }

        // Numbers.
        let mut digits = [0u16; 12];
        let mut number = UNICODE_STRING {
            Length: 0,
            MaximumLength: 24,
            Buffer: digits.as_mut_ptr(),
        };
        let mut value = 7u32;
        if RtlIntegerToUnicodeString(0xBEEF, 16, &raw mut number) != STATUS_SUCCESS
            || text(&number) != wide("BEEF")
            || RtlUnicodeStringToInteger(&raw const number, 16, &raw mut value) != STATUS_SUCCESS
            || value != 0xBEEF
        {
            return Err("an integer did not survive the trip to text and back");
        }
        if RtlIntegerToUnicodeString(1, 7, &raw mut number) != STATUS_INVALID_PARAMETER
            || RtlUnicodeStringToInteger(&raw const number, 7, &raw mut value)
                != STATUS_INVALID_PARAMETER
            || value != 0
        {
            return Err("a base of seven was taken");
        }
        let mut prefixed = wide(" -0x10z");
        let prefixed = counted_over(&mut prefixed);
        if RtlUnicodeStringToInteger(&raw const prefixed, 0, &raw mut value) != STATUS_SUCCESS
            || value != 16u32.wrapping_neg()
        {
            return Err("RtlUnicodeStringToInteger did not read space, a sign and a prefix");
        }

        // A GUID from the text RtlStringFromGUID makes of it.
        let guid = GUID {
            Data1: 0x0123_4567,
            Data2: 0x89AB,
            Data3: 0xCDEF,
            Data4: [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF],
        };
        let mut printed = EMPTY;
        let mut parsed = GUID {
            Data1: 0,
            Data2: 0,
            Data3: 0,
            Data4: [0; 8],
        };
        if crate::rtl::string::RtlStringFromGUID(&raw const guid, &raw mut printed)
            != STATUS_SUCCESS
        {
            return Err("RtlStringFromGUID failed");
        }
        let status = RtlGUIDFromString(&raw const printed, &raw mut parsed);
        RtlFreeUnicodeString(&raw mut printed);
        if status != STATUS_SUCCESS
            || (parsed.Data1, parsed.Data2, parsed.Data3, parsed.Data4)
                != (guid.Data1, guid.Data2, guid.Data3, guid.Data4)
        {
            return Err("RtlGUIDFromString did not read back a GUID's text");
        }
        if RtlGUIDFromString(&raw const cdef, &raw mut parsed) != STATUS_INVALID_PARAMETER {
            return Err("RtlGUIDFromString took text that is no GUID");
        }

        // The start of 1970, a Thursday.
        let time = 116_444_736_000_000_000i64 + 12_345_678;
        let mut fields = core::mem::zeroed::<TIME_FIELDS>();
        RtlTimeToTimeFields(&raw const time, &raw mut fields);
        let expected = TIME_FIELDS {
            Year: 1970,
            Month: 1,
            Day: 1,
            Hour: 0,
            Minute: 0,
            Second: 1,
            Milliseconds: 234,
            Weekday: 4,
        };
        if fields != expected {
            return Err("RtlTimeToTimeFields split a time wrongly");
        }

        let check = b"123456789";
        let first = RtlComputeCrc32(0, check.as_ptr(), 4);
        if RtlComputeCrc32(first, check.as_ptr().add(4), 5) != 0xCBF4_3926 {
            return Err("RtlComputeCrc32 is not CRC-32, or does not chain");
        }
    }
    Ok(())
}

fn narrow(text: &'static CStr) -> *const u8 {
    text.as_ptr().cast()
}

fn crt_strings() -> Result<(), &'static str> {
    // SAFETY: every string is a NUL-terminated constant or local, and
    // every buffer as large as the call is told.
    unsafe {
        if _strnicmp(narrow(c"abcX"), narrow(c"ABCy"), 3) != 0
            || _strnicmp(narrow(c"abcX"), narrow(c"ABCy"), 4) != -1
        {
            return Err("_strnicmp compared wrongly");
        }
        let path = narrow(c"a/b/c");
        if strchr(path, i32::from(b'/')) != path.add(1).cast_mut()
            || strchr(path, 0) != path.add(5).cast_mut()
            || !strchr(path, i32::from(b'x')).is_null()
            || strstr(path, narrow(c"b/")) != path.add(2).cast_mut()
            || !strstr(path, narrow(c"cc")).is_null()
            || strnlen(path, 3) != 3
            || strnlen(path, 30) != 5
        {
            return Err("strchr, strstr or strnlen answered wrongly");
        }
        if isspace(i32::from(b'\t')) == 0 || isspace(i32::from(b'a')) != 0 {
            return Err("isspace misjudged a character");
        }
        let mut end = core::ptr::null_mut();
        let number = narrow(c" 0x1fz");
        if _strtoui64(number, &raw mut end, 0) != 31 || end != number.add(5).cast_mut() {
            return Err("_strtoui64 did not read a prefixed number and stop after it");
        }
        if _strtoui64(narrow(c"99999999999999999999"), core::ptr::null_mut(), 10) != u64::MAX {
            return Err("_strtoui64 did not clamp a number too large");
        }

        let mut buffer = *b"mixed Case-9\0###";
        let text = buffer.as_mut_ptr();
        if _strupr(text) != text || buffer[..13] != *b"MIXED CASE-9\0" {
            return Err("_strupr did not make the letters upper case");
        }
        let mut context = core::ptr::null_mut();
        let first = strtok_s(text, narrow(c" -"), &raw mut context);
        let second = strtok_s(core::ptr::null_mut(), narrow(c" -"), &raw mut context);
        let third = strtok_s(core::ptr::null_mut(), narrow(c" -"), &raw mut context);
        let fourth = strtok_s(core::ptr::null_mut(), narrow(c" -"), &raw mut context);
        if (first, second, third) != (text, text.add(6), text.add(11))
            || !fourth.is_null()
            || buffer[..13] != *b"MIXED\0CASE\x009\0"
        {
            return Err("strtok_s did not split the string into its tokens");
        }

        let mut small = [b'#'; 4];
        let to = small.as_mut_ptr();
        if strncpy_s(to, 4, narrow(c"abc"), 3) != 0
            || small != *b"abc\0"
            || strncpy_s(to, 4, narrow(c"abcd"), 4) != 34
            || small[0] != 0
            || strncpy_s(to, 4, narrow(c"abcdef"), usize::MAX) != 80
            || small != *b"abc\0"
            || strncpy_s(core::ptr::null_mut(), 4, narrow(c"a"), 1) != 22
        {
            return Err("strncpy_s did not copy, or did not refuse, as Microsoft's does");
        }

        // `%s`, `%d`, `%x` and a wide string, from a `va_list`.
        let wide_text = [u16::from(b'w'), 0xE9, 0];
        let arguments = [
            narrow(c"str") as u64,
            u64::from((-5i32) as u32),
            0xBEEF,
            wide_text.as_ptr() as u64,
        ];
        let mut line = [b'#'; 24];
        let written = _vsnprintf(
            line.as_mut_ptr(),
            line.len(),
            narrow(c"%s %d %04x %ws"),
            arguments.as_ptr(),
        );
        if written != 14 || line[..15] != *b"str -5 beef w\xE9\0" {
            return Err("_vsnprintf did not format into the buffer");
        }
        if _vsnprintf(line.as_mut_ptr(), 3, narrow(c"%s"), arguments.as_ptr()) != 3
            || _vsnprintf(line.as_mut_ptr(), 2, narrow(c"%s"), arguments.as_ptr()) != -1
            || line[..3] != *b"str"
        {
            return Err("_vsnprintf did not report text that does not fit");
        }
    }
    // Microsoft's generator: its numbers are 15 bits wide, and two in a
    // row are not the same. The seed is the system's, so other callers
    // may have drawn from it.
    let (a, b) = (rand(), rand());
    if !(0..=0x7FFF).contains(&a) || !(0..=0x7FFF).contains(&b) || a == b {
        return Err("rand is not Microsoft's generator");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("rtl.counted", counted);
    r.check("rtl.crt-strings", crt_strings);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
