//! Formatted output for drivers: `DbgPrint`, `_snwprintf`.
//!
//! The functions drivers call take a variable number of arguments. Each
//! is entered through an assembly stub (`arch::variadic`) that passes
//! the arguments here as an array; `nk_rtl::format` does the formatting.

#![allow(non_snake_case)]

use core::ffi::c_void;
use nk_rtl::format::{Arguments, format, snprintf_result};

unsafe extern "C" {
    /// [`DbgPrint`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprint).
    pub fn nk_variadic_DbgPrint(format: *const u8, ...) -> u32;
    /// [`_snwprintf`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/snprintf-snprintf-snprintf-l-snwprintf-snwprintf-l).
    pub fn nk_variadic__snwprintf(buffer: *mut u16, count: usize, format: *const u16, ...) -> i32;
}

/// The arguments of a variadic call, as the entry stub laid them out.
struct Passed(*const u64);

impl Arguments for Passed {
    fn next(&mut self) -> u64 {
        // SAFETY: the caller passed at least as many arguments as its
        // format asks for; that is the C contract, and all there is.
        unsafe {
            let value = self.0.read();
            self.0 = self.0.add(1);
            value
        }
    }

    fn narrow(&mut self, address: u64, limit: usize, out: &mut dyn FnMut(u16)) {
        let text = address as *const u8;
        for i in 0..limit {
            // SAFETY: the driver passed a string: NUL-terminated, or at
            // least `limit` characters long.
            match unsafe { text.add(i).read() } {
                0 => break,
                c => out(u16::from(c)),
            }
        }
    }

    fn wide(&mut self, address: u64, limit: usize, out: &mut dyn FnMut(u16)) {
        let text = address as *const u16;
        for i in 0..limit {
            // SAFETY: as in `narrow`.
            match unsafe { text.add(i).read_unaligned() } {
                0 => break,
                c => out(c),
            }
        }
    }

    fn counted(&mut self, address: u64, wide: bool) -> (u64, usize) {
        // `ANSI_STRING` and `UNICODE_STRING` share a shape: length in
        // bytes, capacity, buffer.
        // SAFETY: the driver passed a counted string.
        unsafe {
            let bytes = usize::from((address as *const u16).read_unaligned());
            let buffer = ((address + 8) as *const u64).read_unaligned();
            (buffer, if wide { bytes / 2 } else { bytes })
        }
    }
}

/// The characters of a NUL-terminated string, read as they are asked
/// for.
///
/// # Safety
/// `text` points to a NUL-terminated string of `T`.
unsafe fn characters<T: Copy + Into<u16> + PartialEq + Default>(
    text: *const T,
) -> impl Iterator<Item = u16> {
    (0..)
        // SAFETY: per the contract, up to the terminator.
        .map(move |i| unsafe { text.add(i).read_unaligned() })
        .take_while(|&c| c != T::default())
        .map(Into::into)
}

/// `DbgPrint`, entered from its stub: `args[0]` is the format.
///
/// # Safety
/// `args` is the argument array of a `DbgPrint` call.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_dbg_print(args: *const u64) -> u32 {
    // What Windows hands a debugger, NK puts on the console, a line's
    // worth at a time so that it does not mingle with other output.
    let mut line = [0u8; 256];
    let mut len = 0;
    // SAFETY: per the contract.
    unsafe {
        let mut passed = Passed(args.add(1));
        format(
            &mut characters(args.read() as *const u8),
            false,
            &mut passed,
            &mut |c| {
                if len < line.len() {
                    // Console output is ASCII; anything else shows as `?`.
                    line[len] = u8::try_from(c).ok().filter(u8::is_ascii).unwrap_or(b'?');
                    len += 1;
                }
            },
        );
    }
    let text = core::str::from_utf8(&line[..len]).unwrap_or("?");
    crate::kd::print(format_args!("DbgPrint: {}\n", text.trim_end_matches('\n')));
    0
}

/// `_snwprintf`, entered from its stub: buffer, count, format, then the
/// format's arguments.
///
/// # Safety
/// `args` is the argument array of an `_snwprintf` call.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_snwprintf(args: *const u64) -> i32 {
    // SAFETY: per the contract; the buffer has room for `count`
    // characters.
    unsafe {
        let buffer = args.read() as *mut u16;
        let count = args.add(1).read() as usize;
        let mut passed = Passed(args.add(3));
        let mut produced = 0;
        format(
            &mut characters(args.add(2).read() as *const u16),
            true,
            &mut passed,
            &mut |c| {
                if produced < count {
                    buffer.add(produced).write_unaligned(c);
                }
                produced += 1;
            },
        );
        // A terminator only if there is room for one.
        if produced < count {
            buffer.add(produced).write_unaligned(0);
        }
        snprintf_result(produced, count)
    }
}

/// [`wcschr`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strchr-wcschr-mbschr-mbschr-l):
/// the first `character` in `string`, or null. The terminator counts as
/// part of the string.
///
/// # Safety
/// `string` is NUL-terminated.
pub unsafe extern "C" fn wcschr(string: *const u16, character: u16) -> *mut u16 {
    let mut at = string;
    loop {
        // SAFETY: per the contract, up to the terminator.
        let c = unsafe { at.read_unaligned() };
        if c == character {
            return at.cast_mut();
        }
        if c == 0 {
            return core::ptr::null_mut();
        }
        at = at.wrapping_add(1);
    }
}

/// [`_wcsnicmp`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strnicmp-wcsnicmp-mbsnicmp-strnicmp-l-wcsnicmp-l-mbsnicmp-l):
/// compare at most `count` characters, ASCII letters without regard to
/// case.
///
/// # Safety
/// Both strings are NUL-terminated or at least `count` long.
pub unsafe extern "C" fn _wcsnicmp(a: *const u16, b: *const u16, count: usize) -> i32 {
    let lower = |c: u16| match c {
        0x41..=0x5A => c + 0x20,
        _ => c,
    };
    for i in 0..count {
        // SAFETY: per the contract.
        let (x, y) = unsafe {
            (
                lower(a.add(i).read_unaligned()),
                lower(b.add(i).read_unaligned()),
            )
        };
        if x != y {
            return i32::from(x) - i32::from(y);
        }
        if x == 0 {
            break;
        }
    }
    0
}

/// [`RtlFreeUnicodeString`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfreeunicodestring):
/// free a string's buffer, which came from the pool, and empty the
/// string.
///
/// # Safety
/// `string` is a counted string whose buffer is null or from the pool.
pub unsafe extern "C" fn RtlFreeUnicodeString(string: *mut nk_ntabi::io::UNICODE_STRING) {
    // SAFETY: per the contract.
    unsafe {
        let buffer = (&raw const (*string).Buffer).read_unaligned();
        if !buffer.is_null() {
            crate::mm::pool::ExFreePoolWithTag(buffer.cast::<c_void>(), 0);
        }
        string.write_unaligned(nk_ntabi::io::UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: core::ptr::null_mut(),
        });
    }
}
