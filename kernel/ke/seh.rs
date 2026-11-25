//! Structured exception handling: not implemented.
//!
//! Drivers built with `__try`/`__except` import the language handler and
//! call routines that report bad arguments by raising an exception. NK can
//! neither raise nor unwind yet. The exports below exist so such drivers
//! load, and they are honest about it: anything that would need SEH stops
//! the machine with a message naming what was needed.

#![allow(non_snake_case)]

use crate::kd;
use core::ffi::c_void;

/// `MmUserProbeAddress`: the first address beyond user space.
const USER_PROBE_ADDRESS: usize = 0x7FFF_FFFF_0000;
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;
const STATUS_ACCESS_VIOLATION: u32 = 0xC000_0005;

fn raise(routine: &str, status: u32, address: usize) -> ! {
    kd::bugcheck(format_args!(
        "{routine}: Windows would raise exception {status:#x} for address {address:#x}; SEH is not implemented"
    ))
}

/// `__C_specific_handler`: the C language exception handler. Reached only
/// while an exception is being dispatched, which NK never does.
///
/// # Safety
/// Never returns; callable with any arguments.
pub unsafe extern "C" fn __C_specific_handler(
    _record: *mut c_void,
    _frame: *mut c_void,
    _context: *mut c_void,
    _dispatcher: *mut c_void,
) -> i32 {
    kd::bugcheck(format_args!(
        "__C_specific_handler called: SEH is not implemented"
    ))
}

/// `ProbeForRead`: check that a buffer lies in user space and is aligned.
///
/// The checks are the Windows ones. A buffer that passes returns
/// normally; one that fails must raise, which NK turns into a bugcheck.
/// (A buffer that passes still cannot be read: there is no user memory.)
///
/// # Safety
/// Callable with any arguments; the address is only compared.
pub unsafe extern "C" fn ProbeForRead(address: *const c_void, length: usize, alignment: u32) {
    let address = address as usize;
    if length == 0 {
        return;
    }
    if alignment > 1 && address & (alignment as usize - 1) != 0 {
        raise("ProbeForRead", STATUS_DATATYPE_MISALIGNMENT, address);
    }
    match address.checked_add(length) {
        Some(end) if end <= USER_PROBE_ADDRESS => {}
        _ => raise("ProbeForRead", STATUS_ACCESS_VIOLATION, address),
    }
}
