//! Strings in the OEM code page (437, `nk_rtl::codepage::OEM_437`), in
//! which FAT keeps short names: conversion to and from UTF-16, as the
//! pinned kernel does it.
//!
//! The counted forms carry no terminator. Converting to OEM reports
//! `STATUS_UNMAPPABLE_CHARACTER` when a character of the source had no
//! byte and became the page's default character, `?`, as Windows'
//! check after the conversion does: a file system takes that to mean
//! the name cannot be a short name.

#![allow(non_snake_case)]

use super::counted::{Narrow, from_narrow};
use super::string::{Wide, buffer};
use crate::mm::pool;
use core::ffi::c_void;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::rtl::STRING;
use nk_ntabi::status::*;
use nk_rtl::codepage::{self, OEM_437};

/// The OEM page's default character, which a unit it lacks becomes.
const DEFAULT: u8 = b'?';

/// [`RtlOemToUnicodeN`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtloemtounicoden):
/// OEM bytes to UTF-16, as many as fit; no terminator. As
/// `RtlMultiByteToUnicodeN`: bytes that do not fit are left out with
/// `STATUS_SUCCESS`, and the count stored tells.
///
/// # Safety
/// `unicode` is writable for `max_bytes` bytes, `oem` readable for
/// `bytes`, and `converted` is null or writable.
pub unsafe extern "C" fn RtlOemToUnicodeN(
    unicode: *mut u16,
    max_bytes: u32,
    converted: *mut u32,
    oem: *const u8,
    bytes: u32,
) -> NTSTATUS {
    let chars = codepage::multibyte_to_unicode_chars(max_bytes, bytes);
    // SAFETY: per the contract; `chars` fit both blocks.
    unsafe {
        for at in 0..chars as usize {
            unicode
                .add(at)
                .write_unaligned(OEM_437.to_unicode(oem.add(at).read()));
        }
        if !converted.is_null() {
            converted.write_unaligned(chars * 2);
        }
    }
    STATUS_SUCCESS
}

/// `RtlxOemStringToUnicodeSize`, which the WDK's
/// `RtlOemStringToUnicodeSize` calls: the bytes the string takes in
/// UTF-16, terminator included.
///
/// # Safety
/// `string` points to a counted string.
pub unsafe extern "C" fn RtlxOemStringToUnicodeSize(string: *const STRING) -> u32 {
    // SAFETY: per the contract.
    codepage::ansi_to_unicode_size(unsafe { (&raw const (*string).Length).read_unaligned() })
}

/// [`RtlOemStringToUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtloemstringtounicodestring):
/// as `RtlAnsiStringToUnicodeString`, from the OEM page.
///
/// # Safety
/// `source` points to a counted string; `destination` is writable and,
/// unless a buffer is to be allocated, its buffer has `MaximumLength`
/// bytes.
pub unsafe extern "C" fn RtlOemStringToUnicodeString(
    destination: *mut UNICODE_STRING,
    source: *const STRING,
    allocate: u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        from_narrow(
            destination,
            Narrow::of(source).bytes(),
            allocate != 0,
            &OEM_437,
        )
    }
}

/// Where a counted conversion writes: the destination's own buffer, or
/// one allocated for it, `length` bytes; `Length` is stored first, as
/// Windows stores it before it knows the text fits. An empty result
/// leaves the destination empty with no buffer, the caller's included.
///
/// # Safety
/// `destination` is a writable counted string (of either width: the
/// header is the same) whose buffer, unless one is to be allocated,
/// has `MaximumLength` bytes.
unsafe fn counted_target(
    destination: *mut STRING,
    length: u32,
    allocate: bool,
) -> Result<Option<*mut u8>, NTSTATUS> {
    // SAFETY: per the contract.
    unsafe {
        if length == 0 {
            destination.write_unaligned(STRING {
                Length: 0,
                MaximumLength: 0,
                Buffer: core::ptr::null_mut(),
            });
            return Ok(None);
        }
        let Ok(length) = u16::try_from(length) else {
            return Err(STATUS_INVALID_PARAMETER_2);
        };
        (&raw mut (*destination).Length).write_unaligned(length);
        if allocate {
            (&raw mut (*destination).MaximumLength).write_unaligned(length);
            let to = buffer(usize::from(length));
            (&raw mut (*destination).Buffer).write_unaligned(to);
            if to.is_null() {
                return Err(STATUS_NO_MEMORY);
            }
            return Ok(Some(to));
        }
        if length > (&raw const (*destination).MaximumLength).read_unaligned() {
            return Err(STATUS_BUFFER_OVERFLOW);
        }
        Ok(Some((&raw const (*destination).Buffer).read_unaligned()))
    }
}

/// [`RtlOemStringToCountedUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtloemstringtocountedunicodestring):
/// the source as UTF-16, with no terminator, in the destination's
/// buffer or one allocated for it.
///
/// # Safety
/// As [`RtlOemStringToUnicodeString`].
pub unsafe extern "C" fn RtlOemStringToCountedUnicodeString(
    destination: *mut UNICODE_STRING,
    source: *const STRING,
    allocate: u8,
) -> NTSTATUS {
    // SAFETY: per the contract; the target holds the source's length in
    // units.
    unsafe {
        let from = Narrow::of(source);
        let to = match counted_target(
            destination.cast(),
            from.bytes().len() as u32 * 2,
            allocate != 0,
        ) {
            Ok(Some(to)) => to.cast::<u16>(),
            Ok(None) => return STATUS_SUCCESS,
            Err(status) => return status,
        };
        for (at, byte) in from.bytes().enumerate() {
            to.add(at).write_unaligned(OEM_437.to_unicode(byte));
        }
    }
    STATUS_SUCCESS
}

/// The body of the two conversions to counted OEM strings: each unit,
/// upper-cased first if asked, to its byte. A unit that became the
/// default character without being it makes the status
/// `STATUS_UNMAPPABLE_CHARACTER`; a buffer allocated for a conversion
/// that fails is freed.
///
/// # Safety
/// As [`RtlUnicodeStringToCountedOemString`].
unsafe fn to_counted_oem(
    destination: *mut STRING,
    source: *const UNICODE_STRING,
    allocate: bool,
    upper: bool,
) -> NTSTATUS {
    // SAFETY: per the contract; the target holds one byte per unit.
    unsafe {
        let from = Wide::of(source);
        let to = match counted_target(destination, from.len() as u32, allocate) {
            Ok(Some(to)) => to,
            Ok(None) => return STATUS_SUCCESS,
            Err(status) => return status,
        };
        let mut status = STATUS_SUCCESS;
        for (at, unit) in from.units().enumerate() {
            let byte = OEM_437.from_unicode(if upper {
                nk_rtl::upcase_char(unit)
            } else {
                unit
            });
            to.add(at).write(byte);
            if byte == DEFAULT && unit != u16::from(DEFAULT) {
                status = STATUS_UNMAPPABLE_CHARACTER;
            }
        }
        if status != STATUS_SUCCESS && allocate {
            pool::ExFreePoolWithTag(to.cast::<c_void>(), 0);
            (&raw mut (*destination).Buffer).write_unaligned(core::ptr::null_mut());
        }
        status
    }
}

/// [`RtlUnicodeStringToCountedOemString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlunicodestringtocountedoemstring):
/// the source in the OEM page, with no terminator, in the destination's
/// buffer or one allocated for it.
///
/// # Safety
/// `source` points to a counted string; `destination` is writable and,
/// unless a buffer is to be allocated, its buffer has `MaximumLength`
/// bytes.
pub unsafe extern "C" fn RtlUnicodeStringToCountedOemString(
    destination: *mut STRING,
    source: *const UNICODE_STRING,
    allocate: u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { to_counted_oem(destination, source, allocate != 0, false) }
}

/// [`RtlUpcaseUnicodeStringToCountedOemString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlupcaseunicodestringtocountedoemstring):
/// as [`RtlUnicodeStringToCountedOemString`], each unit upper-cased
/// first.
///
/// # Safety
/// As [`RtlUnicodeStringToCountedOemString`].
pub unsafe extern "C" fn RtlUpcaseUnicodeStringToCountedOemString(
    destination: *mut STRING,
    source: *const UNICODE_STRING,
    allocate: u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { to_counted_oem(destination, source, allocate != 0, true) }
}

/// [`RtlFreeOemString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlfreeoemstring):
/// free a string's buffer, which a conversion routine allocated, and
/// empty the string.
///
/// # Safety
/// `string` is a counted string whose buffer is null or from the pool.
pub unsafe extern "C" fn RtlFreeOemString(string: *mut STRING) {
    // SAFETY: per the contract; an OEM string is an ANSI string.
    unsafe { super::string::RtlFreeAnsiString(string.cast()) }
}
