//! Counted strings a driver initialises, fills, compares and converts:
//! the routines beside those of `string`. The length rules are
//! `nk_rtl::counted`, the conversions `nk_rtl::convert` and
//! `nk_rtl::codepage`; here the characters are moved, in the driver's
//! memory.

#![allow(non_snake_case)]

use super::string::{Wide, buffer};
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::rtl::{ANSI_STRING, GUID, STRING, TIME_FIELDS};
use nk_ntabi::status::*;
use nk_rtl::codepage::{self, ANSI_1252, CodePage};
use nk_rtl::counted::{self, DuplicateError, Header};
use nk_rtl::{convert, upcase};

/// A driver's byte string, where it lies.
#[derive(Clone, Copy)]
pub(crate) struct Narrow {
    buffer: *const u8,
    length: usize,
}

impl Narrow {
    /// # Safety
    /// `string` points to a counted string whose buffer holds `Length`
    /// bytes, and stays so while the result is used.
    pub(crate) unsafe fn of(string: *const STRING) -> Self {
        // SAFETY: per the contract. Drivers may pack strings, so read
        // unaligned.
        unsafe {
            Self {
                buffer: (&raw const (*string).Buffer).read_unaligned(),
                length: usize::from((&raw const (*string).Length).read_unaligned()),
            }
        }
    }

    /// The bytes in order, each read when it is asked for.
    pub(crate) fn bytes(self) -> impl ExactSizeIterator<Item = u8> {
        // SAFETY: `of`'s contract: the buffer holds `length` bytes.
        (0..self.length).map(move |at| unsafe { self.buffer.add(at).read() })
    }
}

/// [`RtlInitString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitstring):
/// point `destination` at the NUL-terminated string `source` without
/// copying it.
///
/// # Safety
/// `destination` is writable; `source` is null or NUL-terminated.
pub unsafe extern "C" fn RtlInitString(destination: *mut STRING, source: *const u8) {
    let (length, maximum) = if source.is_null() {
        (0, 0)
    } else {
        let mut chars = 0;
        // SAFETY: the caller guarantees a terminator, and every byte
        // before it is readable.
        while chars < counted::INIT_STRING_SCAN && unsafe { source.add(chars).read() } != 0 {
            chars += 1;
        }
        counted::init_string_lengths(chars)
    };
    // SAFETY: the caller guarantees `destination` is writable.
    unsafe {
        destination.write_unaligned(STRING {
            Length: length,
            MaximumLength: maximum,
            Buffer: source.cast_mut(),
        });
    }
}

/// [`RtlInitAnsiString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitansistring):
/// [`RtlInitString`] under its other name.
///
/// # Safety
/// As for [`RtlInitString`].
pub unsafe extern "C" fn RtlInitAnsiString(destination: *mut ANSI_STRING, source: *const u8) {
    // SAFETY: per the contract.
    unsafe { RtlInitString(destination, source) }
}

/// `RtlxAnsiStringToUnicodeSize`, which the WDK's
/// [`RtlAnsiStringToUnicodeSize`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlansistringtounicodesize)
/// calls: the bytes the string takes in UTF-16, terminator included.
///
/// # Safety
/// `string` points to a counted string.
pub unsafe extern "C" fn RtlxAnsiStringToUnicodeSize(string: *const ANSI_STRING) -> u32 {
    // SAFETY: per the contract.
    codepage::ansi_to_unicode_size(unsafe { (&raw const (*string).Length).read_unaligned() })
}

/// `RtlAnsiCharToUnicodeChar` (`ntifs.h`): the UTF-16 unit of the
/// character `*source` points to, and `*source` moved past it. Every
/// character of the ANSI page is one byte.
///
/// # Safety
/// `source` points to a pointer to a readable byte.
pub unsafe extern "C" fn RtlAnsiCharToUnicodeChar(source: *mut *mut u8) -> u16 {
    // SAFETY: per the contract.
    unsafe {
        let at = source.read_unaligned();
        source.write_unaligned(at.add(1));
        ANSI_1252.to_unicode(at.read())
    }
}

/// Fill `destination` with `bytes` of `page` as UTF-16 and a
/// terminator, in its own buffer or in one allocated for it: the body
/// of `RtlAnsiStringToUnicodeString` and `RtlOemStringToUnicodeString`.
///
/// # Safety
/// `destination` is writable and, unless a buffer is to be allocated,
/// its buffer has `MaximumLength` bytes.
pub(crate) unsafe fn from_narrow(
    destination: *mut UNICODE_STRING,
    bytes: impl ExactSizeIterator<Item = u8>,
    allocate: bool,
    page: &CodePage,
) -> NTSTATUS {
    let Some((length, needed)) = codepage::ansi_to_unicode_lengths(bytes.len() as u16) else {
        return STATUS_INVALID_PARAMETER_2;
    };
    // SAFETY: per the contract; the buffer, the caller's or the fresh
    // one, has `needed` bytes.
    unsafe {
        // Windows stores the length before it knows the text fits.
        (&raw mut (*destination).Length).write_unaligned(length);
        let to = if allocate {
            (&raw mut (*destination).MaximumLength).write_unaligned(needed);
            let to = buffer(usize::from(needed)).cast::<u16>();
            (&raw mut (*destination).Buffer).write_unaligned(to);
            if to.is_null() {
                return STATUS_NO_MEMORY;
            }
            to
        } else {
            if needed > (&raw const (*destination).MaximumLength).read_unaligned() {
                return STATUS_BUFFER_OVERFLOW;
            }
            (&raw const (*destination).Buffer).read_unaligned()
        };
        let mut at = 0;
        for byte in bytes {
            to.add(at).write_unaligned(page.to_unicode(byte));
            at += 1;
        }
        to.add(at).write_unaligned(0);
    }
    STATUS_SUCCESS
}

/// [`RtlAnsiStringToUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlansistringtounicodestring):
/// the source as UTF-16, terminated, in the destination's buffer or in
/// one allocated for it, which `RtlFreeUnicodeString` frees. A buffer
/// without room for the text and its terminator gets nothing but the
/// `Length` the text would have, and `STATUS_BUFFER_OVERFLOW`.
///
/// # Safety
/// `source` points to a counted string; `destination` is writable and,
/// unless a buffer is to be allocated, its buffer has `MaximumLength`
/// bytes.
pub unsafe extern "C" fn RtlAnsiStringToUnicodeString(
    destination: *mut UNICODE_STRING,
    source: *const ANSI_STRING,
    allocate: u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        from_narrow(
            destination,
            Narrow::of(source).bytes(),
            allocate != 0,
            &ANSI_1252,
        )
    }
}

/// [`RtlIntegerToUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlintegertounicodestring):
/// the digits of `value` in the caller's buffer, as
/// [`RtlAnsiStringToUnicodeString`] stores them.
///
/// # Safety
/// `string` is a counted string whose buffer has `MaximumLength` bytes.
pub unsafe extern "C" fn RtlIntegerToUnicodeString(
    value: u32,
    base: u32,
    string: *mut UNICODE_STRING,
) -> NTSTATUS {
    let Some((text, count)) = convert::integer_text(value, base) else {
        return STATUS_INVALID_PARAMETER;
    };
    // SAFETY: per the contract.
    unsafe { from_narrow(string, text[..count].iter().copied(), false, &ANSI_1252) }
}

/// [`RtlUnicodeStringToInteger`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlunicodestringtointeger).
/// What the page leaves open is stated in `nk_rtl::convert`.
///
/// # Safety
/// `string` points to a counted string and `value` is writable.
pub unsafe extern "C" fn RtlUnicodeStringToInteger(
    string: *const UNICODE_STRING,
    base: u32,
    value: *mut u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let length = (&raw const (*string).Length).read_unaligned();
        let number = convert::unicode_to_integer(length, Wide::of(string).units(), base);
        value.write_unaligned(number.unwrap_or(0));
        match number {
            Some(_) => STATUS_SUCCESS,
            None => STATUS_INVALID_PARAMETER,
        }
    }
}

/// [`RtlAppendUnicodeStringToString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlappendunicodestringtostring).
///
/// # Safety
/// Both point to counted strings, and the destination's buffer has
/// `MaximumLength` bytes.
pub unsafe extern "C" fn RtlAppendUnicodeStringToString(
    destination: *mut UNICODE_STRING,
    source: *const UNICODE_STRING,
) -> NTSTATUS {
    // SAFETY: per the contract; the rule says the text fits.
    unsafe {
        let from = (&raw const (*source).Length).read_unaligned();
        let length = (&raw const (*destination).Length).read_unaligned();
        let maximum = (&raw const (*destination).MaximumLength).read_unaligned();
        let Some((total, terminate)) = counted::append(length, maximum, from) else {
            return STATUS_BUFFER_TOO_SMALL;
        };
        if from != 0 {
            // The end of the text, at a whole unit as Windows takes it.
            let to = (&raw const (*destination).Buffer)
                .read_unaligned()
                .add(usize::from(length) / 2)
                .cast::<u8>();
            let text = (&raw const (*source).Buffer).read_unaligned().cast::<u8>();
            // The two may overlap.
            core::ptr::copy(text, to, usize::from(from));
            (&raw mut (*destination).Length).write_unaligned(total);
            if terminate {
                to.cast::<u16>()
                    .add(usize::from(from) / 2)
                    .write_unaligned(0);
            }
        }
    }
    STATUS_SUCCESS
}

/// [`RtlCopyUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopyunicodestring):
/// as much of the source as the destination's buffer holds; no source
/// empties the destination.
///
/// # Safety
/// `destination` is a counted string whose buffer has `MaximumLength`
/// bytes; `source` is null or points to a counted string.
pub unsafe extern "C" fn RtlCopyUnicodeString(
    destination: *mut UNICODE_STRING,
    source: *const UNICODE_STRING,
) {
    // SAFETY: per the contract; the rule keeps to the buffer.
    unsafe {
        if source.is_null() {
            (&raw mut (*destination).Length).write_unaligned(0);
            return;
        }
        let maximum = (&raw const (*destination).MaximumLength).read_unaligned();
        let (length, terminate) =
            counted::copy((&raw const (*source).Length).read_unaligned(), maximum);
        let to = (&raw const (*destination).Buffer).read_unaligned();
        (&raw mut (*destination).Length).write_unaligned(length);
        core::ptr::copy(
            (&raw const (*source).Buffer).read_unaligned().cast::<u8>(),
            to.cast::<u8>(),
            usize::from(length),
        );
        if terminate {
            to.add(usize::from(length) / 2).write_unaligned(0);
        }
    }
}

/// [`RtlDuplicateUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlduplicateunicodestring):
/// a copy of the source in a buffer from the pool, which
/// `RtlFreeUnicodeString` frees.
///
/// # Safety
/// `source` is null or points to a counted string; `destination` is
/// null or writable.
pub unsafe extern "C" fn RtlDuplicateUnicodeString(
    flags: u32,
    source: *const UNICODE_STRING,
    destination: *mut UNICODE_STRING,
) -> NTSTATUS {
    if destination.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract.
    unsafe {
        let header = (!source.is_null()).then(|| Header {
            length: (&raw const (*source).Length).read_unaligned(),
            maximum: (&raw const (*source).MaximumLength).read_unaligned(),
            buffer_is_null: (&raw const (*source).Buffer).read_unaligned().is_null(),
        });
        let (length, maximum) = match counted::duplicate(flags, header) {
            Ok(lengths) => lengths,
            Err(DuplicateError::InvalidParameter) => return STATUS_INVALID_PARAMETER,
            Err(DuplicateError::NameTooLong) => return STATUS_NAME_TOO_LONG,
        };
        let mut to = core::ptr::null_mut();
        if maximum != 0 {
            to = buffer(usize::from(maximum)).cast::<u16>();
            if to.is_null() {
                return STATUS_NO_MEMORY;
            }
            if length != 0 {
                let from = Wide::of(source);
                for at in 0..from.len() {
                    to.add(at).write(from.unit(at));
                }
            }
            if maximum > length {
                to.add(usize::from(length) / 2).write(0);
            }
        }
        destination.write_unaligned(UNICODE_STRING {
            Length: length,
            MaximumLength: maximum,
            Buffer: to,
        });
    }
    STATUS_SUCCESS
}

/// [`RtlCompareString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcomparestring).
///
/// # Safety
/// Both point to counted strings.
pub unsafe extern "C" fn RtlCompareString(
    a: *const STRING,
    b: *const STRING,
    ignore_case: u8,
) -> i32 {
    // SAFETY: per the contract.
    let (a, b) = unsafe { (Narrow::of(a), Narrow::of(b)) };
    codepage::compare_string(&ANSI_1252, a.bytes(), b.bytes(), ignore_case != 0)
}

/// [`RtlCompareUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcompareunicodestring).
///
/// # Safety
/// Both point to counted strings.
pub unsafe extern "C" fn RtlCompareUnicodeString(
    a: *const UNICODE_STRING,
    b: *const UNICODE_STRING,
    ignore_case: u8,
) -> i32 {
    // SAFETY: per the contract.
    let (a, b) = unsafe { (Wide::of(a), Wide::of(b)) };
    upcase::compare_units(a.units(), b.units(), ignore_case != 0)
}

/// [`RtlEqualUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlequalunicodestring).
///
/// # Safety
/// Both point to counted strings.
pub unsafe extern "C" fn RtlEqualUnicodeString(
    a: *const UNICODE_STRING,
    b: *const UNICODE_STRING,
    ignore_case: u8,
) -> u8 {
    // SAFETY: per the contract.
    let (a, b) = unsafe { (Wide::of(a), Wide::of(b)) };
    u8::from(upcase::equal_units(a.units(), b.units(), ignore_case != 0))
}

/// [`RtlGUIDFromString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlguidfromstring).
/// A string that is not a GUID's leaves `guid` as it was.
///
/// # Safety
/// `string` points to a counted string and `guid` is writable.
pub unsafe extern "C" fn RtlGUIDFromString(
    string: *const UNICODE_STRING,
    guid: *mut GUID,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let Some((data1, data2, data3, data4)) = convert::guid_from_text(Wide::of(string).units())
        else {
            return STATUS_INVALID_PARAMETER;
        };
        guid.write_unaligned(GUID {
            Data1: data1,
            Data2: data2,
            Data3: data3,
            Data4: data4,
        });
    }
    STATUS_SUCCESS
}

/// [`RtlTimeToTimeFields`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimetotimefields).
///
/// # Safety
/// `time` is readable and `fields` writable.
pub unsafe extern "C" fn RtlTimeToTimeFields(time: *const i64, fields: *mut TIME_FIELDS) {
    // SAFETY: per the contract.
    unsafe {
        let [
            year,
            month,
            day,
            hour,
            minute,
            second,
            milliseconds,
            weekday,
        ] = convert::time_fields(time.read_unaligned() as u64);
        fields.write_unaligned(TIME_FIELDS {
            Year: year,
            Month: month,
            Day: day,
            Hour: hour,
            Minute: minute,
            Second: second,
            Milliseconds: milliseconds,
            Weekday: weekday,
        });
    }
}

/// [`RtlTimeFieldsToTime`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltimefieldstotime):
/// the time the fields name; false, the time left alone, for fields
/// Windows refuses (`nk_rtl::convert::fields_time`). The weekday is not
/// looked at. NK keeps no leap seconds, as Windows without them.
///
/// # Safety
/// `fields` is readable and `time` writable.
pub unsafe extern "C" fn RtlTimeFieldsToTime(fields: *const TIME_FIELDS, time: *mut i64) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let f = fields.read_unaligned();
        match convert::fields_time([
            f.Year,
            f.Month,
            f.Day,
            f.Hour,
            f.Minute,
            f.Second,
            f.Milliseconds,
            f.Weekday,
        ]) {
            Some(t) => {
                time.write_unaligned(t as i64);
                1
            }
            None => 0,
        }
    }
}

/// `RtlComputeCrc32` (exported, not documented): the CRC-32 of a block,
/// carried on from the sum of what came before it.
///
/// # Safety
/// `buffer` is readable for `length` bytes.
pub unsafe extern "C" fn RtlComputeCrc32(partial: u32, buffer: *const u8, length: u32) -> u32 {
    // SAFETY: per the contract: `at` is below `length`.
    let bytes = (0..length as usize).map(|at| unsafe { buffer.add(at).read() });
    convert::crc32(partial, bytes)
}
