//! The C runtime's string functions, as the kernel exports them. The
//! comparisons and searches are `nk_rtl::crt`, which reads a string one
//! character at a time and no further than its answer needs: here each
//! character comes straight from the caller's memory.

#![allow(non_snake_case)]

use super::print::characters;
use nk_rtl::crt;

/// [`_stricmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/stricmp-wcsicmp-mbsicmp-stricmp-l-wcsicmp-l-mbsicmp-l):
/// compare two strings, the letters `A` to `Z` without regard to case.
///
/// # Safety
/// Both strings are NUL-terminated.
pub unsafe extern "C" fn _stricmp(a: *const u8, b: *const u8) -> i32 {
    // SAFETY: per the contract.
    unsafe { crt::stricmp(characters(a), characters(b)) }
}

/// `_wcsicmp`: [`_stricmp`] for wide strings.
///
/// # Safety
/// Both strings are NUL-terminated.
pub unsafe extern "C" fn _wcsicmp(a: *const u16, b: *const u16) -> i32 {
    // SAFETY: per the contract.
    unsafe { crt::wcsicmp(characters(a), characters(b)) }
}

/// [`strncmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncmp-wcsncmp-mbsncmp-mbsncmp-l):
/// compare at most `count` characters.
///
/// # Safety
/// Each string is NUL-terminated or at least `count` characters long.
pub unsafe extern "C" fn strncmp(a: *const u8, b: *const u8, count: usize) -> i32 {
    // SAFETY: per the contract; neither string is read past `count`.
    unsafe { crt::strncmp(characters(a), characters(b), count) }
}

/// [`strrchr`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strrchr-wcsrchr-mbsrchr-mbsrchr-l):
/// the last `character` in `string`, or null. Only the low byte of
/// `character` counts, and the terminator is part of the string.
///
/// # Safety
/// `string` is NUL-terminated.
pub unsafe extern "C" fn strrchr(string: *const u8, character: i32) -> *mut u8 {
    // SAFETY: per the contract.
    match crt::strrchr(unsafe { characters(string) }, character as u8) {
        Some(at) => string.wrapping_add(at).cast_mut(),
        None => core::ptr::null_mut(),
    }
}

/// [`wcsstr`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strstr-wcsstr-mbsstr-mbsstr-l):
/// the first place `needle` occurs in `haystack`, or null. An empty
/// needle is found at the start.
///
/// # Safety
/// Both strings are NUL-terminated.
pub unsafe extern "C" fn wcsstr(haystack: *const u16, needle: *const u16) -> *mut u16 {
    // SAFETY: per the contract: the search asks for no character past a
    // terminator.
    let unit = |string: *const u16| move |at: usize| unsafe { string.add(at).read_unaligned() };
    match crt::wcsstr(unit(haystack), unit(needle)) {
        Some(at) => haystack.wrapping_add(at).cast_mut(),
        None => core::ptr::null_mut(),
    }
}
