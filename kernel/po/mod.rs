//! Power: what Microsoft's drivers ask of the power manager on a
//! machine that is on and stays on.

#![allow(non_snake_case)]

use core::ffi::c_void;
use nk_ntabi::status::{
    NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS,
};

/// `POWER_INFORMATION_LEVEL` `PlatformInformation`: a
/// `POWER_PLATFORM_INFORMATION`, one `BOOLEAN`, whether the platform
/// has an always-on, always-connected low-power idle state.
const PLATFORM_INFORMATION: i32 = 66;

/// `POWER_INFORMATION_LEVEL` `PowerInformationInternal`: requests of
/// Windows' own components, told apart by the number the input starts
/// with.
const INTERNAL: i32 = 87;

/// The internal request for the sleep study helper's table of routines,
/// through which `pci.sys` and others report what keeps the machine
/// from sleeping.
const INTERNAL_SLEEP_STUDY_ROUTINES: u32 = 0x3F;

/// [`ZwPowerInformation`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwpowerinformation):
/// read or set power information of one level.
///
/// `PlatformInformation` is answered: NK has no low-power idle state,
/// so the platform is not always on, always connected.
///
/// The internal request for the sleep study helper's routines fails
/// with `STATUS_NOT_SUPPORTED`. Windows always has the helper and
/// answers with its table; NK has no sleep study, and the callers have
/// a path for a request that fails, on which they report nothing.
///
/// Any other level, or internal request, stops the system naming it.
///
/// # Safety
/// `output` points to `output_length` writable bytes.
pub unsafe extern "C" fn ZwPowerInformation(
    level: i32,
    input: *mut c_void,
    input_length: u32,
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
        INTERNAL => {
            if input.is_null() || input_length < 4 {
                return STATUS_INVALID_PARAMETER;
            }
            // SAFETY: the caller's buffer, of at least four bytes.
            match unsafe { input.cast::<u32>().read_unaligned() } {
                INTERNAL_SLEEP_STUDY_ROUTINES => STATUS_NOT_SUPPORTED,
                request => crate::kd::bugcheck(format_args!(
                    "ZwPowerInformation: NK does not implement internal request {request:#x}"
                )),
            }
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
    let mut request = [INTERNAL_SLEEP_STUDY_ROUTINES, 0];
    let mut routines = 0usize;
    // SAFETY: locals of the sizes given.
    let status = unsafe {
        ZwPowerInformation(
            INTERNAL,
            request.as_mut_ptr().cast(),
            8,
            (&raw mut routines).cast(),
            8,
        )
    };
    if status != STATUS_NOT_SUPPORTED || routines != 0 {
        return Err("the sleep study helper's routines were not refused");
    }
    // SAFETY: an internal request with no input.
    let status =
        unsafe { ZwPowerInformation(INTERNAL, core::ptr::null_mut(), 0, core::ptr::null_mut(), 0) };
    if status != STATUS_INVALID_PARAMETER {
        return Err("an internal request that names no request was not refused");
    }
    Ok(())
}
