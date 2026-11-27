//! The C runtime's string functions, as the kernel exports them. The
//! comparisons and searches are `nk_rtl::crt`, which reads a string one
//! character at a time and no further than its answer needs: here each
//! character comes straight from the caller's memory.

#![allow(non_snake_case)]

use super::print::characters;
use core::sync::atomic::{AtomicU32, Ordering};
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

/// [`wcsncmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncmp-wcsncmp-mbsncmp-mbsncmp-l):
/// [`strncmp`] for wide strings.
///
/// # Safety
/// Each string is NUL-terminated or at least `count` characters long.
pub unsafe extern "C" fn wcsncmp(a: *const u16, b: *const u16, count: usize) -> i32 {
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

/// The character at each index of a NUL-terminated string.
///
/// # Safety
/// `string` is NUL-terminated, and the result is asked for nothing past
/// the terminator.
unsafe fn at(string: *const u8) -> impl Fn(usize) -> u8 {
    // SAFETY: per the contract.
    move |index| unsafe { string.add(index).read() }
}

/// [`_strnicmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnicmp-wcsnicmp-mbsnicmp-strnicmp-l-wcsnicmp-l-mbsnicmp-l):
/// [`_stricmp`] over at most `count` characters.
///
/// # Safety
/// Each string is NUL-terminated or at least `count` characters long.
pub unsafe extern "C" fn _strnicmp(a: *const u8, b: *const u8, count: usize) -> i32 {
    // SAFETY: per the contract; neither string is read past `count`.
    unsafe { crt::strnicmp(characters(a), characters(b), count) }
}

/// [`strchr`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strchr-wcschr-mbschr-mbschr-l):
/// the first `character` in `string`, or null. Only the low byte of
/// `character` counts, and the terminator is part of the string.
///
/// # Safety
/// `string` is NUL-terminated.
pub unsafe extern "C" fn strchr(string: *const u8, character: i32) -> *mut u8 {
    // SAFETY: per the contract.
    match crt::strchr(unsafe { characters(string) }, character as u8) {
        Some(at) => string.wrapping_add(at).cast_mut(),
        None => core::ptr::null_mut(),
    }
}

/// [`strstr`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strstr-wcsstr-mbsstr-mbsstr-l):
/// [`wcsstr`] for byte strings.
///
/// # Safety
/// Both strings are NUL-terminated.
pub unsafe extern "C" fn strstr(haystack: *const u8, needle: *const u8) -> *mut u8 {
    // SAFETY: per the contract: the search asks for no character past a
    // terminator.
    let unit = |string: *const u8| move |at: usize| u16::from(unsafe { string.add(at).read() });
    match crt::wcsstr(unit(haystack), unit(needle)) {
        Some(at) => haystack.wrapping_add(at).cast_mut(),
        None => core::ptr::null_mut(),
    }
}

/// [`strnlen`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnlen-strnlen-s).
///
/// # Safety
/// `string` is NUL-terminated or at least `max` characters long.
pub unsafe extern "C" fn strnlen(string: *const u8, max: usize) -> usize {
    // SAFETY: per the contract; the string is not read past `max`.
    crt::strnlen(unsafe { characters(string) }, max)
}

/// [`isspace`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/isspace-iswspace-isspace-l-iswspace-l),
/// in the C locale.
pub extern "C" fn isspace(character: i32) -> i32 {
    crt::isspace(character)
}

/// [`_strupr`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strupr-strupr-l-mbsupr-mbsupr-l-wcsupr-l-wcsupr):
/// make `a` to `z` upper case, in place.
///
/// # Safety
/// `string` is NUL-terminated and writable.
pub unsafe extern "C" fn _strupr(string: *mut u8) -> *mut u8 {
    let mut at = string;
    // SAFETY: per the contract, up to the terminator.
    unsafe {
        while at.read() != 0 {
            at.write(crt::upper(at.read()));
            at = at.add(1);
        }
    }
    string
}

/// The seed of [`rand`]: one for the whole system, as the kernel's C
/// runtime has no thread to keep one for.
static SEED: AtomicU32 = AtomicU32::new(1);

/// [`rand`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/rand).
pub extern "C" fn rand() -> i32 {
    let before = SEED
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |seed| {
            Some(crt::rand(seed).0)
        })
        .unwrap_or_else(|seed| seed);
    crt::rand(before).1
}

/// [`_strtoui64`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtoui64-wcstoui64-strtoui64-l-wcstoui64-l).
/// The details are stated at `nk_rtl::crt::strtoui64`.
///
/// # Safety
/// `string` is NUL-terminated; `end` is null or writable.
pub unsafe extern "C" fn _strtoui64(string: *const u8, end: *mut *mut u8, base: i32) -> u64 {
    // SAFETY: per the contract.
    unsafe {
        let (value, after) = crt::strtoui64(at(string), base);
        if !end.is_null() {
            end.write_unaligned(string.add(after).cast_mut());
        }
        value
    }
}

/// [`strncpy_s`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strncpy-s-strncpy-s-l-wcsncpy-s-wcsncpy-s-l-mbsncpy-s-mbsncpy-s-l).
/// A bad argument is answered with its error number: the kernel's C
/// runtime has no invalid-parameter handler to stop in.
///
/// # Safety
/// `destination` is null or writable for `size` characters; `source` is
/// null, NUL-terminated or at least `count` characters long.
pub unsafe extern "C" fn strncpy_s(
    destination: *mut u8,
    size: usize,
    source: *const u8,
    count: usize,
) -> i32 {
    // SAFETY: per the contract: the rule writes below `size`.
    let write = (!destination.is_null())
        .then_some(move |index: usize, c: u8| unsafe { destination.add(index).write(c) });
    // SAFETY: per the contract.
    let read = (!source.is_null()).then(|| unsafe { at(source) });
    crt::strncpy_s(write, size, read, count)
}

/// [`strtok_s`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtok-s-strtok-s-l-wcstok-s-wcstok-s-l-mbstok-s-mbstok-s-l).
///
/// # Safety
/// `string` is null or NUL-terminated and writable; `delimiters` is
/// NUL-terminated; `context` is writable and, when `string` is null,
/// holds what an earlier call left there.
pub unsafe extern "C" fn strtok_s(
    string: *mut u8,
    delimiters: *const u8,
    context: *mut *mut u8,
) -> *mut u8 {
    // SAFETY: per the contract.
    unsafe {
        let string = if string.is_null() {
            context.read_unaligned()
        } else {
            string
        };
        let delimiters = characters(delimiters).map(|c| c as u8);
        let token = crt::strtok(at(string), delimiters);
        if token.next != token.end {
            string.add(token.end).write(0);
        }
        context.write_unaligned(string.add(token.next));
        match token.start {
            Some(start) => string.add(start),
            None => core::ptr::null_mut(),
        }
    }
}
