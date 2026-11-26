//! Counted strings: comparison, upper case, conversion between the ANSI
//! code page and UTF-16, and text forms. The rules are `nk_rtl`; here a
//! driver's strings are read and written in place, one unit at a time.
//!
//! The ANSI code page is Windows-1252 and the upper-case table is
//! `nk_rtl::upcase` (`doc/DESIGN.md`, "Strings").

#![allow(non_snake_case)]

use crate::mm::pool;
use core::ffi::c_void;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::rtl::{ANSI_STRING, GUID};
use nk_ntabi::status::*;
use nk_rtl::codepage::{self, ANSI_1252};

/// Pool tag of strings these routines allocate.
const TAG: u32 = u32::from_le_bytes(*b"Strg");

/// A buffer of `bytes` bytes for a string, from the pool; null without
/// memory. An empty string still gets a block, which the routines that
/// free strings give back.
pub(crate) fn buffer(bytes: usize) -> *mut u8 {
    pool::alloc(bytes.max(1), TAG)
}

/// A driver's wide string, where it lies.
#[derive(Clone, Copy)]
pub(crate) struct Wide {
    buffer: *const u16,
    /// In units.
    length: usize,
}

impl Wide {
    /// # Safety
    /// `string` points to a counted string whose buffer holds `Length`
    /// bytes, and stays so while the result is used.
    pub(crate) unsafe fn of(string: *const UNICODE_STRING) -> Self {
        // SAFETY: per the contract. Drivers may pack strings, so read
        // unaligned.
        unsafe {
            Self {
                buffer: (&raw const (*string).Buffer).read_unaligned(),
                length: usize::from((&raw const (*string).Length).read_unaligned()) / 2,
            }
        }
    }

    pub(crate) fn len(self) -> usize {
        self.length
    }

    pub(crate) fn unit(self, at: usize) -> u16 {
        debug_assert!(at < self.length);
        // SAFETY: `of`'s contract: the buffer holds `length` units.
        unsafe { self.buffer.add(at).read_unaligned() }
    }

    /// The units in order, each read when it is asked for.
    pub(crate) fn units(self) -> impl ExactSizeIterator<Item = u16> {
        (0..self.length).map(move |at| self.unit(at))
    }
}

/// [`RtlCompareMemory`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcomparememory):
/// how many bytes, from the start, two blocks have in common.
///
/// # Safety
/// Both blocks are readable for `length` bytes.
pub unsafe extern "C" fn RtlCompareMemory(
    a: *const c_void,
    b: *const c_void,
    length: usize,
) -> usize {
    let bytes = |block: *const c_void| {
        // SAFETY: per the contract: `at` is below `length`.
        (0..length).map(move |at| unsafe { block.cast::<u8>().add(at).read() })
    };
    nk_rtl::string::compare_memory(bytes(a), bytes(b))
}

/// [`RtlPrefixUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlprefixunicodestring):
/// whether `string` starts with `prefix`.
///
/// # Safety
/// Both point to counted strings.
pub unsafe extern "C" fn RtlPrefixUnicodeString(
    prefix: *const UNICODE_STRING,
    string: *const UNICODE_STRING,
    ignore_case: u8,
) -> u8 {
    // SAFETY: per the contract.
    let (prefix, string) = unsafe { (Wide::of(prefix), Wide::of(string)) };
    u8::from(nk_rtl::upcase::prefix_units(
        prefix.units(),
        string.units(),
        ignore_case != 0,
    ))
}

/// [`RtlUpcaseUnicodeChar`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodechar).
pub extern "C" fn RtlUpcaseUnicodeChar(character: u16) -> u16 {
    nk_rtl::upcase_char(character)
}

/// [`RtlUpcaseUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodestring):
/// the source in upper case, in the destination's buffer or in one
/// allocated for it (which has room for the text and no terminator).
/// The two may be one string.
///
/// # Safety
/// `source` points to a counted string; `destination` is writable and,
/// unless a buffer is to be allocated, its buffer has `MaximumLength`
/// bytes.
pub unsafe extern "C" fn RtlUpcaseUnicodeString(
    destination: *mut UNICODE_STRING,
    source: *const UNICODE_STRING,
    allocate: u8,
) -> NTSTATUS {
    // SAFETY: per the contract. Each unit is read before the unit of
    // the same place is written, so the strings may share a buffer.
    unsafe {
        let from = Wide::of(source);
        let length = (from.len() * 2) as u16;
        let to = if allocate != 0 {
            let to = buffer(usize::from(length)).cast::<u16>();
            if to.is_null() {
                return STATUS_NO_MEMORY;
            }
            (&raw mut (*destination).MaximumLength).write_unaligned(length);
            (&raw mut (*destination).Buffer).write_unaligned(to);
            to
        } else {
            let maximum = (&raw const (*destination).MaximumLength).read_unaligned();
            if nk_rtl::upcase::upcase_string_length(length, maximum).is_none() {
                return STATUS_BUFFER_OVERFLOW;
            }
            (&raw const (*destination).Buffer).read_unaligned()
        };
        for at in 0..from.len() {
            to.add(at)
                .write_unaligned(nk_rtl::upcase_char(from.unit(at)));
        }
        (&raw mut (*destination).Length).write_unaligned(length);
    }
    STATUS_SUCCESS
}

/// [`RtlMultiByteToUnicodeN`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlmultibytetounicoden):
/// ANSI bytes to UTF-16, as many as fit; no terminator.
///
/// # Safety
/// `unicode` is writable for `max_bytes` bytes, `multibyte` readable for
/// `bytes`, and `converted` is null or writable.
pub unsafe extern "C" fn RtlMultiByteToUnicodeN(
    unicode: *mut u16,
    max_bytes: u32,
    converted: *mut u32,
    multibyte: *const u8,
    bytes: u32,
) -> NTSTATUS {
    let (chars, all) = codepage::multibyte_to_unicode_chars(max_bytes, bytes);
    // SAFETY: per the contract; `chars` fit both blocks.
    unsafe {
        for at in 0..chars as usize {
            unicode
                .add(at)
                .write_unaligned(ANSI_1252.to_unicode(multibyte.add(at).read()));
        }
        if !converted.is_null() {
            converted.write_unaligned(chars * 2);
        }
    }
    if all {
        STATUS_SUCCESS
    } else {
        STATUS_BUFFER_OVERFLOW
    }
}

/// [`RtlUnicodeToMultiByteN`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodetomultibyten):
/// UTF-16 to ANSI bytes, as many as fit; no terminator. A character the
/// code page lacks becomes `?`.
///
/// # Safety
/// `multibyte` is writable for `max_bytes` bytes, `unicode` readable for
/// `bytes`, and `converted` is null or writable.
pub unsafe extern "C" fn RtlUnicodeToMultiByteN(
    multibyte: *mut u8,
    max_bytes: u32,
    converted: *mut u32,
    unicode: *const u16,
    bytes: u32,
) -> NTSTATUS {
    let (chars, all) = codepage::unicode_to_multibyte_chars(max_bytes, bytes);
    // SAFETY: per the contract; `chars` fit both blocks.
    unsafe {
        for at in 0..chars as usize {
            multibyte
                .add(at)
                .write(ANSI_1252.from_unicode(unicode.add(at).read_unaligned()));
        }
        if !converted.is_null() {
            converted.write_unaligned(chars);
        }
    }
    if all {
        STATUS_SUCCESS
    } else {
        STATUS_BUFFER_OVERFLOW
    }
}

/// [`RtlUnicodeStringToAnsiString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtoansistring):
/// the source in the ANSI code page, terminated, in the destination's
/// buffer or in one allocated for it. A buffer too small gets what
/// fits, terminated, and `STATUS_BUFFER_OVERFLOW`.
///
/// # Safety
/// `source` points to a counted string; `destination` is writable and,
/// unless a buffer is to be allocated, its buffer has `MaximumLength`
/// bytes.
pub unsafe extern "C" fn RtlUnicodeStringToAnsiString(
    destination: *mut ANSI_STRING,
    source: *const UNICODE_STRING,
    allocate: u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let from = Wide::of(source);
        let (whole, needed) = codepage::unicode_to_ansi_lengths((from.len() * 2) as u16);
        let (to, length, all) = if allocate != 0 {
            let to = buffer(usize::from(needed));
            if to.is_null() {
                return STATUS_NO_MEMORY;
            }
            (&raw mut (*destination).MaximumLength).write_unaligned(needed);
            (&raw mut (*destination).Buffer).write_unaligned(to);
            (to, whole, true)
        } else {
            let maximum = (&raw const (*destination).MaximumLength).read_unaligned();
            let Some((length, all)) =
                codepage::unicode_to_ansi_stored((from.len() * 2) as u16, maximum)
            else {
                return STATUS_BUFFER_OVERFLOW;
            };
            (
                (&raw const (*destination).Buffer).read_unaligned(),
                length,
                all,
            )
        };
        for at in 0..usize::from(length) {
            to.add(at).write(ANSI_1252.from_unicode(from.unit(at)));
        }
        to.add(usize::from(length)).write(0);
        (&raw mut (*destination).Length).write_unaligned(length);
        if all {
            STATUS_SUCCESS
        } else {
            STATUS_BUFFER_OVERFLOW
        }
    }
}

/// [`RtlFreeAnsiString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfreeansistring):
/// free a string's buffer, which a conversion routine allocated, and
/// empty the string.
///
/// # Safety
/// `string` is a counted string whose buffer is null or from the pool.
pub unsafe extern "C" fn RtlFreeAnsiString(string: *mut ANSI_STRING) {
    // SAFETY: per the contract.
    unsafe {
        let buffer = (&raw const (*string).Buffer).read_unaligned();
        if !buffer.is_null() {
            pool::ExFreePoolWithTag(buffer.cast::<c_void>(), 0);
        }
        string.write_unaligned(ANSI_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: core::ptr::null_mut(),
        });
    }
}

/// Give `string` a pool buffer holding `text`, which is a GUID's or a
/// SID's and so far shorter than a counted string can be, and a
/// terminator.
///
/// # Safety
/// `string` is writable.
pub(crate) unsafe fn allocated(string: *mut UNICODE_STRING, text: &[u16]) -> NTSTATUS {
    let (length, maximum) = nk_rtl::init_unicode_lengths(text.len());
    let to = buffer(usize::from(maximum)).cast::<u16>();
    if to.is_null() {
        return STATUS_NO_MEMORY;
    }
    // SAFETY: the block is fresh and `maximum` bytes long; the string is
    // writable per the contract.
    unsafe {
        for (at, &unit) in text.iter().chain(&[0]).enumerate() {
            to.add(at).write(unit);
        }
        string.write_unaligned(UNICODE_STRING {
            Length: length,
            MaximumLength: maximum,
            Buffer: to,
        });
    }
    STATUS_SUCCESS
}

/// [`RtlStringFromGUID`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlstringfromguid):
/// the text form of a GUID, braces and lower-case digits, in a buffer
/// the caller frees with `RtlFreeUnicodeString`.
///
/// # Safety
/// `guid` points to a GUID and `string` is writable.
pub unsafe extern "C" fn RtlStringFromGUID(
    guid: *const GUID,
    string: *mut UNICODE_STRING,
) -> NTSTATUS {
    // SAFETY: per the contract. The GUID is copied out whole: it has no
    // invalid values.
    unsafe {
        let guid = guid.read_unaligned();
        let text = nk_rtl::string::guid_text(guid.Data1, guid.Data2, guid.Data3, &guid.Data4);
        allocated(string, &text)
    }
}
