//! Runtime-library exports. The logic is in `lib/rtl`.

#![allow(non_snake_case)]

use nk_ntabi::io::UNICODE_STRING;

/// Copy a driver's counted string out of its memory.
///
/// # Safety
/// `us` must be null or point to a `UNICODE_STRING` whose buffer holds
/// `Length` bytes.
pub unsafe fn copy_unicode(us: *const UNICODE_STRING) -> alloc::vec::Vec<u16> {
    let mut out = alloc::vec::Vec::new();
    if us.is_null() {
        return out;
    }
    // SAFETY: per the contract, the header is readable and the buffer
    // holds `Length / 2` units. Drivers may pack strings, so read unaligned.
    unsafe {
        let (buf, len) = ((*us).Buffer, usize::from((*us).Length) / 2);
        if !buf.is_null() {
            out.extend((0..len).map(|i| buf.add(i).read_unaligned()));
        }
    }
    out
}

/// `RtlInitUnicodeString`: point `destination` at the NUL-terminated
/// string `source` without copying it.
///
/// # Safety
/// `destination` must be writable; `source` must be null or NUL terminated.
pub unsafe extern "C" fn RtlInitUnicodeString(
    destination: *mut UNICODE_STRING,
    source: *const u16,
) {
    let mut chars = 0;
    if !source.is_null() {
        // The scan stops at the longest length the function can report.
        while chars < nk_rtl::MAX_INIT_LENGTH / 2 {
            // SAFETY: the caller guarantees a terminator, and every unit
            // before it is readable.
            if unsafe { source.add(chars).read_unaligned() } == 0 {
                break;
            }
            chars += 1;
        }
    }
    let (length, maximum) = if source.is_null() {
        (0, 0)
    } else {
        nk_rtl::init_unicode_lengths(chars)
    };
    // SAFETY: the caller guarantees `destination` is writable.
    unsafe {
        destination.write_unaligned(UNICODE_STRING {
            Length: length,
            MaximumLength: maximum,
            Buffer: source.cast_mut(),
        });
    }
}
