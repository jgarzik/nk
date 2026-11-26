//! Power: what Microsoft's drivers ask of the power manager on a
//! machine that is on and stays on.
//!
//! The system is in S0 and every device in D0, always (`doc/DESIGN.md`,
//! "Power"). [`request`] makes the power requests a driver asks for,
//! [`setting`] keeps the registrations for power settings and for
//! coalescing, [`absent`] answers for what a machine that never
//! sleeps, hibernates or overheats does not have. The rules are
//! `nk_po`'s.

#![allow(non_snake_case)]

pub mod absent;
pub mod request;
pub mod setting;

use crate::ke::spinlock::{Rank, SpinLock};
use crate::mm::pool;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_ntabi::io::DEVICE_OBJECT;
use nk_ntabi::status::{
    NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS,
};
use nk_po::request::Turns;
use nk_po::setting::Registrations;

/// Pool tag of a device's power block.
const TAG_DOPE: u32 = u32::from_le_bytes(*b"Dope");

/// What the power manager keeps about a device, in the block
/// `DEVOBJ_EXTENSION.Dope` points to, which is where Windows keeps its
/// own (a `DEVICE_OBJECT_POWER_EXTENSION`, private to the kernel: no
/// driver reads it). Made when first needed, freed with the device
/// object. Read and written under [`POWER`].
struct Dope {
    /// The queries and sets of the device's power state asked for:
    /// the address of the request sent, and of those that wait. Kept
    /// in the block of the device at the bottom of the stack.
    turns: Turns<usize>,
    /// The flags `PoDirectedDripsSetDeviceFlags` has been given.
    drips_flags: u32,
}

/// The power manager's records.
struct Power {
    /// The address of every request made for a driver that has not
    /// completed (`request::Request`).
    requests: Vec<usize>,
    /// Who is registered for which power setting.
    settings: Registrations,
    /// Whether a worker is making, or is queued to make, the calls
    /// owed to those registered.
    telling: bool,
    /// The coalescing callbacks registered.
    coalescing: Vec<setting::Coalescing>,
    /// How many coalescing registrations have been made.
    coalescing_made: usize,
}

static POWER: SpinLock<Power> = SpinLock::new(
    Rank::Power,
    Power {
        requests: Vec::new(),
        settings: Registrations::new(),
        telling: false,
        coalescing: Vec::new(),
        coalescing_made: 0,
    },
);

/// The power block of `device`, made if it has none; null if there is
/// no memory for one.
///
/// # Safety
/// `device` is a live device object. The caller holds [`POWER`], which
/// `_power` witnesses.
unsafe fn dope(_power: &mut Power, device: *mut DEVICE_OBJECT) -> *mut Dope {
    // SAFETY: per the contract; the extension is the device's own, and
    // its `Dope` word is the power manager's, under the lock held.
    unsafe {
        let slot = &raw mut (*(*device).DeviceObjectExtension).Dope;
        let mut block = slot.read().cast::<Dope>();
        if block.is_null() {
            block = pool::alloc(size_of::<Dope>(), TAG_DOPE).cast::<Dope>();
            if !block.is_null() {
                block.write(Dope {
                    turns: Turns::new(),
                    drips_flags: 0,
                });
                slot.write(block.cast());
            }
        }
        block
    }
}

/// A device object's memory is going: free its power block. Windows
/// frees its own as the device is deleted (`PoRunDownDeviceObject`).
///
/// # Safety
/// `device` is a device object nothing refers to any more.
pub unsafe fn run_down(device: *mut DEVICE_OBJECT) {
    let block = {
        let _power = POWER.lock();
        // SAFETY: per the contract; the word is read and cleared under
        // the lock that owns it.
        unsafe {
            let extension = (*device).DeviceObjectExtension;
            if extension.is_null() {
                return;
            }
            (&raw mut (*extension).Dope)
                .replace(core::ptr::null_mut())
                .cast::<Dope>()
        }
    };
    if !block.is_null() {
        // SAFETY: the block `dope` made, which nothing else points to
        // now.
        unsafe {
            block.drop_in_place();
            let _ = pool::free(block.cast());
        }
    }
}

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
