//! `HalDispatchTable.HalQuerySystemInformation`: what drivers ask the
//! HAL about the machine, by information class
//! ([`HAL_QUERY_INFORMATION_CLASS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ne-ntddk-_hal_query_information_class)).
//!
//! The classes Microsoft's drivers reach are answered as the pinned
//! kernel's HAL answers them on a machine like NK's; any other class
//! stops the system naming it.

#![allow(non_snake_case)]

use super::dispatch::{HalDispatchTable, public_slot};
use core::ffi::c_void;
use nk_ntabi::status::{NTSTATUS, STATUS_UNSUCCESSFUL};

/// `HalQueryDebuggerInformation`: the devices the kernel debugger uses.
const DEBUGGER_INFORMATION: u32 = 33;

/// The routine in the slot.
///
/// # Safety
/// `buffer` points to `size` writable bytes; `returned` is null or
/// points to a writable `ULONG`.
pub unsafe extern "C" fn HalQuerySystemInformation(
    class: u32,
    size: u32,
    _buffer: *mut c_void,
    returned: *mut u32,
) -> NTSTATUS {
    let give = |length: u32| {
        if !returned.is_null() {
            // SAFETY: the caller's.
            unsafe { returned.write_unaligned(length) };
        }
    };
    give(0);
    match class {
        // Windows' HAL says the answer is four bytes long, and fails
        // when its list of debugging devices is empty. NK's always is:
        // it speaks no Windows debugger protocol.
        DEBUGGER_INFORMATION => {
            give(4);
            STATUS_UNSUCCESSFUL
        }
        _ => crate::kd::bugcheck(format_args!(
            "HalQuerySystemInformation: NK does not implement information class {class} \
             (buffer of {size:#x} bytes)"
        )),
    }
}

/// Put the routine in its slot.
pub fn init() {
    HalDispatchTable.provide(
        public_slot("HalQuerySystemInformation"),
        HalQuerySystemInformation as *const (),
    );
}

/// For the self-tests.
pub fn test() -> Result<(), &'static str> {
    let mut returned = 77u32;
    // SAFETY: no buffer, of no length; a local for the length.
    let status = unsafe {
        HalQuerySystemInformation(
            DEBUGGER_INFORMATION,
            0,
            core::ptr::null_mut(),
            &raw mut returned,
        )
    };
    if status != STATUS_UNSUCCESSFUL || returned != 4 {
        return Err("debugging devices were not reported as none, four bytes long");
    }
    if HalDispatchTable.routine(public_slot("HalQuerySystemInformation"))
        != HalQuerySystemInformation as *mut ()
    {
        return Err("the routine is not in its slot");
    }
    Ok(())
}
