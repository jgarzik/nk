//! Power: what Microsoft's drivers ask of the power manager on a
//! machine that is on and stays on.

#![allow(non_snake_case)]

use core::ffi::c_void;
use nk_ntabi::status::{NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_SUCCESS};

/// `POWER_INFORMATION_LEVEL` `PlatformInformation`: a
/// `POWER_PLATFORM_INFORMATION`, one `BOOLEAN`, whether the platform
/// has an always-on, always-connected low-power idle state.
const PLATFORM_INFORMATION: i32 = 66;

/// [`ZwPowerInformation`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwpowerinformation):
/// read or set power information of one level.
///
/// `PlatformInformation` is answered: NK has no low-power idle state,
/// so the platform is not always on, always connected. Any other level
/// stops the system naming it.
///
/// # Safety
/// `output` points to `output_length` writable bytes.
pub unsafe extern "C" fn ZwPowerInformation(
    level: i32,
    _input: *mut c_void,
    _input_length: u32,
    output: *mut c_void,
    output_length: u32,
) -> NTSTATUS {
    match level {
        PLATFORM_INFORMATION => {
            if output.is_null() || output_length < 1 {
                return STATUS_BUFFER_TOO_SMALL;
            }
            // SAFETY: the caller's buffer, of at least a byte.
            unsafe { output.cast::<u8>().write(0) };
            STATUS_SUCCESS
        }
        _ => crate::kd::bugcheck(format_args!(
            "ZwPowerInformation: NK does not implement information level {level}"
        )),
    }
}

/// For the self-tests.
pub fn test() -> Result<(), &'static str> {
    let mut platform = 0xFFu8;
    // SAFETY: a local of the size given.
    let status = unsafe {
        ZwPowerInformation(
            PLATFORM_INFORMATION,
            core::ptr::null_mut(),
            0,
            (&raw mut platform).cast(),
            1,
        )
    };
    if status != STATUS_SUCCESS || platform != 0 {
        return Err("the platform was not reported as one without low-power idle");
    }
    // SAFETY: no buffer, and a length that says so.
    let status = unsafe {
        ZwPowerInformation(
            PLATFORM_INFORMATION,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            0,
        )
    };
    if status != STATUS_BUFFER_TOO_SMALL {
        return Err("a buffer too small for the answer was not refused");
    }
    Ok(())
}
