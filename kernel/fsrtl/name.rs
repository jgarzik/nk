//! File names, taken apart and judged as the pinned kernel does: the
//! exports over `nk_rtl::fatname` and `nk_rtl::wildcard`.

#![allow(non_snake_case)]

use crate::kd;
use crate::rtl::counted::Narrow;
use crate::rtl::string::Wide;
use alloc::vec::Vec;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::rtl::STRING;
use nk_rtl::fatname;

/// [`FsRtlDissectName`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtldissectname):
/// the first component of `path` and the rest, each pointing into the
/// path's buffer; both empty, with no buffer, for an empty path.
///
/// # Safety
/// `path` is a counted string; the outputs are writable.
pub unsafe extern "C" fn FsRtlDissectName(
    path: UNICODE_STRING,
    first: *mut UNICODE_STRING,
    remaining: *mut UNICODE_STRING,
) {
    let empty = UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: core::ptr::null_mut(),
    };
    // SAFETY: per the contract; the parts point into the path's buffer.
    unsafe {
        first.write_unaligned(empty);
        remaining.write_unaligned(empty);
        let units: Vec<u16> = Wide::of(&raw const path).units().collect();
        let Some((head, rest)) = fatname::dissect(&units) else {
            return;
        };
        let part = |range: core::ops::Range<usize>| {
            let bytes = (range.len() * 2) as u16;
            UNICODE_STRING {
                Length: bytes,
                MaximumLength: bytes,
                Buffer: path.Buffer.add(range.start),
            }
        };
        first.write_unaligned(part(head));
        if let Some(rest) = rest {
            remaining.write_unaligned(part(rest));
        }
    }
}

/// [`FsRtlAreNamesEqual`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlarenamesequal):
/// whether two names are the same, without regard to case if asked, by
/// the caller's upper-case table or the system's. Windows upper-cases
/// copies when it has no table, and raises if it cannot allocate them;
/// NK compares a unit at a time and needs nothing.
///
/// # Safety
/// The names are counted strings; `table` is null or 65536 units.
pub unsafe extern "C" fn FsRtlAreNamesEqual(
    a: *const UNICODE_STRING,
    b: *const UNICODE_STRING,
    ignore_case: u8,
    table: *const u16,
) -> u8 {
    // SAFETY: per the contract.
    let (a, b) = unsafe { (Wide::of(a), Wide::of(b)) };
    let fold = |c: u16| {
        if ignore_case == 0 {
            c
        } else if table.is_null() {
            nk_rtl::upcase_char(c)
        } else {
            // SAFETY: per the contract: a unit for every value.
            unsafe { table.add(usize::from(c)).read_unaligned() }
        }
    };
    u8::from(a.len() == b.len() && a.units().zip(b.units()).all(|(x, y)| fold(x) == fold(y)))
}

/// [`FsRtlDoesNameContainWildCards`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtldoesnamecontainwildcards):
/// whether the last component of `name` holds a wildcard.
///
/// # Safety
/// `name` is a counted string.
pub unsafe extern "C" fn FsRtlDoesNameContainWildCards(name: *const UNICODE_STRING) -> u8 {
    // SAFETY: per the contract.
    let units: Vec<u16> = unsafe { Wide::of(name) }.units().collect();
    u8::from(fatname::contains_wildcards(&units))
}

/// [`FsRtlIsFatDbcsLegal`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlisfatdbcslegal):
/// whether an OEM name may be a FAT short name, or with wildcards a
/// pattern for one. The branches Windows takes for a path or a leading
/// backslash when the caller permits them were not read from the pinned
/// kernel and no binary NK runs asks for them: asking stops the system,
/// naming the routine.
///
/// # Safety
/// `name` is a counted string.
pub unsafe extern "C" fn FsRtlIsFatDbcsLegal(
    name: STRING,
    wildcards: u8,
    path: u8,
    leading_backslash: u8,
) -> u8 {
    // SAFETY: per the contract.
    let bytes: Vec<u8> = unsafe { Narrow::of(&raw const name) }.bytes().collect();
    if path != 0 || (leading_backslash != 0 && bytes.first() == Some(&b'\\')) {
        kd::bugcheck(format_args!(
            "FsRtlIsFatDbcsLegal: NK does not implement path names or leading backslashes \
             (path {path}, leading backslash {leading_backslash})"
        ));
    }
    u8::from(fatname::is_fat_legal(&bytes, wildcards != 0))
}

/// [`FsRtlIsDbcsInExpression`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlisdbcsinexpression):
/// whether an OEM name matches an OEM wildcard expression, byte for byte
/// (the OEM page has no double-byte characters): the matcher of
/// `FsRtlIsNameInExpression`.
///
/// # Safety
/// Both are counted strings.
pub unsafe extern "C" fn FsRtlIsDbcsInExpression(
    expression: *const STRING,
    name: *const STRING,
) -> u8 {
    // SAFETY: per the contract.
    let (expression, name): (Vec<u8>, Vec<u8>) = unsafe {
        (
            Narrow::of(expression).bytes().collect(),
            Narrow::of(name).bytes().collect(),
        )
    };
    u8::from(
        nk_rtl::wildcard::is_name_in_expression(&expression[..], &name[..], |c| c) == Some(true),
    )
}
