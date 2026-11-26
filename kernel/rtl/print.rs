//! Formatted output for drivers: `DbgPrint` and its filtered forms,
//! `_snwprintf`, `_vsnwprintf`.
//!
//! `DbgPrint` and `_snwprintf` take a variable number of arguments. Each
//! is entered through an assembly stub (`arch::variadic`) that passes
//! the arguments here as an array; `nk_rtl::format` does the formatting.
//! A `va_list` is the address of such an array (`doc/ABI.md`), so
//! `_vsnwprintf` is an ordinary function and `_snwprintf` is a call of
//! it.

#![allow(non_snake_case)]

use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};
use nk_ntabi::status::{NTSTATUS, STATUS_SUCCESS};
use nk_rtl::dbgfilter;
use nk_rtl::format::{Arguments, format, snprintf_result};

unsafe extern "C" {
    /// [`DbgPrint`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprint).
    pub fn nk_variadic_DbgPrint(format: *const u8, ...) -> u32;
    /// [`DbgPrintEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprintex).
    pub fn nk_variadic_DbgPrintEx(component: u32, level: u32, format: *const u8, ...) -> u32;
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
        let string = address as *const nk_ntabi::rtl::STRING;
        // SAFETY: the driver passed a counted string.
        unsafe {
            let bytes = usize::from((&raw const (*string).Length).read_unaligned());
            let buffer = (&raw const (*string).Buffer).read_unaligned() as u64;
            (buffer, if wide { bytes / 2 } else { bytes })
        }
    }
}

/// The characters of a NUL-terminated string, read as they are asked
/// for.
///
/// # Safety
/// `text` points to a NUL-terminated string of `T`.
pub(crate) unsafe fn characters<T: Copy + Into<u16> + PartialEq + Default>(
    text: *const T,
) -> impl Iterator<Item = u16> {
    (0..)
        // SAFETY: per the contract, up to the terminator.
        .map(move |i| unsafe { text.add(i).read_unaligned() })
        .take_while(|&c| c != T::default())
        .map(Into::into)
}

/// Put a debug message on the console: `prefix`, if there is one, then
/// `format_string` with its arguments.
///
/// # Safety
/// `prefix` is null or NUL-terminated; `format_string` is
/// NUL-terminated; `arguments` holds what the format names.
unsafe fn debug_message(prefix: *const u8, format_string: *const u8, arguments: *const u64) {
    // What Windows hands a debugger, NK puts on the console, a line's
    // worth at a time so that it does not mingle with other output.
    let mut line = [0u8; 256];
    let mut len = 0;
    let mut put = |c: u16| {
        if len < line.len() {
            // Console output is ASCII; anything else shows as `?`.
            line[len] = u8::try_from(c).ok().filter(u8::is_ascii).unwrap_or(b'?');
            len += 1;
        }
    };
    // SAFETY: per the contract.
    unsafe {
        if !prefix.is_null() {
            characters(prefix).for_each(&mut put);
        }
        let mut passed = Passed(arguments);
        format(&mut characters(format_string), false, &mut passed, &mut put);
    }
    let text = core::str::from_utf8(&line[..len]).unwrap_or("?");
    crate::kd::print(format_args!("DbgPrint: {}\n", text.trim_end_matches('\n')));
}

/// `DbgPrint`, entered from its stub: `args[0]` is the format.
///
/// # Safety
/// `args` is the argument array of a `DbgPrint` call.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_dbg_print(args: *const u64) -> u32 {
    // SAFETY: per the contract.
    unsafe { debug_message(core::ptr::null(), args.read() as *const u8, args.add(1)) };
    0
}

/// The filter masks of the components (`nk_rtl::dbgfilter`), and the
/// one that applies to all of them.
static COMPONENT_MASKS: [AtomicU32; dbgfilter::COMPONENTS] =
    [const { AtomicU32::new(0) }; dbgfilter::COMPONENTS];
static WIN2000_MASK: AtomicU32 = AtomicU32::new(dbgfilter::WIN2000_AT_BOOT);

/// Whether a message of `component` at `level` is let through.
pub fn debug_filter_passes(component: u32, level: u32) -> bool {
    let (decides, wanted) = dbgfilter::message(component, level);
    dbgfilter::passes(
        wanted,
        COMPONENT_MASKS[decides].load(Ordering::Relaxed),
        WIN2000_MASK.load(Ordering::Relaxed),
    )
}

/// `DbgPrintEx`, entered from its stub: component, level, format, then
/// the format's arguments. A message the filter stops is dropped; one
/// it lets through goes where `DbgPrint`'s go.
///
/// # Safety
/// `args` is the argument array of a `DbgPrintEx` call.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_dbg_print_ex(args: *const u64) -> u32 {
    // SAFETY: per the contract: three named arguments, then the
    // format's.
    unsafe {
        if debug_filter_passes(args.read() as u32, args.add(1).read() as u32) {
            debug_message(
                core::ptr::null(),
                args.add(2).read() as *const u8,
                args.add(3),
            );
        }
    }
    0
}

/// [`vDbgPrintExWithPrefix`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-vdbgprintexwithprefix):
/// `DbgPrintEx` with a prefix before the message and the format's
/// arguments in a `va_list`.
///
/// # Safety
/// `prefix` and `format_string` are NUL-terminated; `arguments` is a
/// `va_list` of at least the arguments the format names.
pub unsafe extern "C" fn vDbgPrintExWithPrefix(
    prefix: *const u8,
    component: u32,
    level: u32,
    format_string: *const u8,
    arguments: *const u64,
) -> u32 {
    if debug_filter_passes(component, level) {
        // SAFETY: per the contract.
        unsafe { debug_message(prefix, format_string, arguments) };
    }
    0
}

/// [`DbgSetDebugFilterState`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgsetdebugfilterstate):
/// turn `level` on or off in a component's filter mask. A component
/// number of -1 names the mask that applies to every component; any
/// other number past the table names the default component's.
pub extern "C" fn DbgSetDebugFilterState(component: u32, level: u32, state: u8) -> NTSTATUS {
    let mask = match dbgfilter::slot(component) {
        dbgfilter::Slot::Component(index) => &COMPONENT_MASKS[index],
        dbgfilter::Slot::Win2000 => &WIN2000_MASK,
    };
    if state != 0 {
        mask.fetch_or(dbgfilter::mask(level), Ordering::Relaxed);
    } else {
        mask.fetch_and(!dbgfilter::mask(level), Ordering::Relaxed);
    }
    STATUS_SUCCESS
}

/// [`DbgPrompt`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-dbgprompt):
/// ask whoever is at the debugger for a line. The request is a
/// breakpoint the debugger answers. With no debugger Windows' stub
/// passes over print and command requests but not this one, which is
/// then an exception, `0x80000003`, like any breakpoint
/// (`doc/DESIGN.md`, "Breakpoints and the debugger"); NK's debugger
/// that always says go has nobody to type, and the response is empty.
pub extern "C" fn DbgPrompt(_prompt: *const u8, _response: *mut u8, _length: u32) -> u32 {
    crate::arch::driver_breakpoint();
    0
}

/// `DbgCommandString` (undocumented): hand the debugger a command to
/// run. With no debugger Windows' stub passes over the request, and
/// nothing is done.
pub extern "C" fn DbgCommandString(_name: *const u8, _command: *const u8) {}

/// `_snwprintf`, entered from its stub: buffer, count, format, then the
/// format's arguments.
///
/// # Safety
/// `args` is the argument array of an `_snwprintf` call.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_snwprintf(args: *const u64) -> i32 {
    // SAFETY: per the contract. What follows the three named arguments
    // is what `va_start` would point a `va_list` at.
    unsafe {
        _vsnwprintf(
            args.read() as *mut u16,
            args.add(1).read() as usize,
            args.add(2).read() as *const u16,
            args.add(3),
        )
    }
}

/// [`_vsnwprintf`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/vsnprintf-vsnprintf-vsnprintf-l-vsnwprintf-vsnwprintf-l):
/// format into `buffer`, which has room for `count` characters, taking
/// the format's arguments from a `va_list`. Returns the number of
/// characters written, or -1 when they do not all fit: then the buffer
/// is full. A terminator is written only if there is room for one after
/// the text; nothing is written past `count` characters.
///
/// # Safety
/// `buffer` is writable for `count` characters, `format` is
/// NUL-terminated, and `arguments` is a `va_list` of at least the
/// arguments the format names.
pub unsafe extern "C" fn _vsnwprintf(
    buffer: *mut u16,
    count: usize,
    format_string: *const u16,
    arguments: *const u64,
) -> i32 {
    // SAFETY: per the contract.
    unsafe {
        let mut passed = Passed(arguments);
        let mut produced = 0;
        format(
            &mut characters(format_string),
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

/// [`_vsnprintf`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/vsnprintf-vsnprintf-vsnprintf-l-vsnwprintf-vsnwprintf-l):
/// [`_vsnwprintf`] into a buffer of bytes, from a format of bytes. A
/// wide character or string among the arguments is written in the ANSI
/// code page.
///
/// # Safety
/// `buffer` is writable for `count` characters, `format` is
/// NUL-terminated, and `arguments` is a `va_list` of at least the
/// arguments the format names.
pub unsafe extern "C" fn _vsnprintf(
    buffer: *mut u8,
    count: usize,
    format_string: *const u8,
    arguments: *const u64,
) -> i32 {
    // SAFETY: per the contract.
    unsafe {
        let mut passed = Passed(arguments);
        let mut produced = 0;
        format(
            &mut characters(format_string),
            false,
            &mut passed,
            &mut |c| {
                if produced < count {
                    buffer
                        .add(produced)
                        .write(nk_rtl::codepage::ANSI_1252.from_unicode(c));
                }
                produced += 1;
            },
        );
        // A terminator only if there is room for one.
        if produced < count {
            buffer.add(produced).write(0);
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
