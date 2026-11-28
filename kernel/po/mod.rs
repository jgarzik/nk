//! Power: what Microsoft's drivers ask of the power manager on a
//! machine that is on and stays on.
//!
//! The system is in S0 and every device in D0, always (`doc/design/power.md`). [`request`] makes the power requests a driver asks for,
//! [`setting`] keeps the registrations for power settings and for
//! coalescing, [`fx`] is the runtime power framework, [`action`] takes
//! a request to shut the system down, [`absent`]
//! answers for what a machine that never sleeps or hibernates does not
//! have. The rules are `nk_po`'s.

#![allow(non_snake_case)]

pub mod absent;
pub mod action;
pub mod fx;
pub mod request;
pub mod setting;

use crate::ke::spinlock::{Rank, SpinLock};
use crate::mm::pool;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_ntabi::io::DEVICE_OBJECT;
use nk_ntabi::status::{
    NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER,
    STATUS_NOT_SUPPORTED, STATUS_OBJECT_NAME_COLLISION, STATUS_SUCCESS,
};
use nk_po::logging::{Logged, Reasons};
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
    /// Whether the Plug and Play manager has begun to start the device
    /// (`fx::prepare_device`), and the registration its drivers made
    /// with the runtime power framework since, if any: the address of
    /// an `fx::Fx`. Kept in the block of the device at the bottom of
    /// the stack.
    fx_prepared: bool,
    fx: usize,
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
    /// The address of every device registered with the runtime power
    /// framework (`fx::Fx`).
    fx: Vec<usize>,
    /// Those whose drivers are owed callbacks from a worker, oldest
    /// first, and whether a worker is making them or queued to.
    fx_work: Vec<usize>,
    fx_working: bool,
    /// Why sleep states cannot be entered, as logged.
    sleep_disabled: Reasons,
}

static POWER: SpinLock<Power> = SpinLock::new(
    Rank::Power,
    Power {
        requests: Vec::new(),
        settings: Registrations::new(),
        telling: false,
        coalescing: Vec::new(),
        coalescing_made: 0,
        fx: Vec::new(),
        fx_work: Vec::new(),
        fx_working: false,
        sleep_disabled: Reasons::new(),
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
                    fx_prepared: false,
                    fx: 0,
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

/// `POWER_INFORMATION_LEVEL` `SystemPowerLoggingEntry`: the input is
/// a reason code and the sleep states it rules out, two `ULONG`s, to be
/// logged.
const SYSTEM_POWER_LOGGING_ENTRY: i32 = 24;

/// `POWER_INFORMATION_LEVEL` `PlatformInformation`: a
/// `POWER_PLATFORM_INFORMATION`, one `BOOLEAN`, whether the platform
/// has an always-on, always-connected low-power idle state.
const PLATFORM_INFORMATION: i32 = 66;

/// `POWER_INFORMATION_LEVEL` `FirmwareTableInformationRegistered`: the
/// firmware's tables can be read now, so what the power manager takes
/// from them is to be read again.
const FIRMWARE_TABLE_INFORMATION_REGISTERED: i32 = 69;

/// `POWER_INFORMATION_LEVEL` `PowerInformationInternal`: requests of
/// Windows' own components, told apart by the number the input starts
/// with.
const INTERNAL: i32 = 87;

/// `POWER_INFORMATION_LEVEL` `QueryPotentialDripsConstraint`: whether
/// a device would keep the platform out of its low-power idle state.
const QUERY_POTENTIAL_DRIPS_CONSTRAINT: i32 = 91;

/// The internal requests that set and clear a device's flags for the
/// platform's low-power idle state: the request number, padded to a
/// pointer, the device object, the flags.
const INTERNAL_DRIPS_SET_DEVICE_FLAGS: u32 = 0x3A;
const INTERNAL_DRIPS_CLEAR_DEVICE_FLAGS: u32 = 0x3B;
/// The bytes of input those two need.
const INTERNAL_DRIPS_INPUT: u32 = 0x18;

/// The internal request for the sleep study helper's table of routines,
/// through which `pci.sys` and others report what keeps the machine
/// from sleeping.
const INTERNAL_SLEEP_STUDY_ROUTINES: u32 = 0x3F;

/// [`ZwPowerInformation`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwpowerinformation):
/// read or set power information of one level.
///
/// `SystemPowerLoggingEntry` records the reason and the states it
/// rules out; a reason logged before is refused with
/// `STATUS_OBJECT_NAME_COLLISION`. NK never sleeps, so nothing reads
/// the record but the self-tests.
///
/// `PlatformInformation` is answered: NK has no low-power idle state,
/// so the platform is not always on, always connected.
///
/// `FirmwareTableInformationRegistered` succeeds with nothing to do:
/// what Windows reads again from the firmware's tables is whether the
/// platform has the low-power idle state, which it then turns off
/// when it runs as Windows PE; NK's platform never has it.
///
/// `QueryPotentialDripsConstraint` fails with `STATUS_NOT_SUPPORTED`,
/// Windows' answer on a platform without the low-power idle state,
/// given before it looks at the buffers.
///
/// The internal requests that set and clear a device's flags for that
/// state go to `PoDirectedDripsSetDeviceFlags` and its counterpart.
///
/// The internal request for the sleep study helper's routines fails
/// with `STATUS_NOT_SUPPORTED`. Windows always has the helper and
/// answers with its table; NK has no sleep study, and the callers have
/// a path for a request that fails, on which they report nothing.
///
/// Any other level, or internal request, stops the system naming it.
///
/// # Safety
/// `input` points to `input_length` readable bytes and `output` to
/// `output_length` writable bytes; a device object an internal request
/// names is null or live.
pub unsafe extern "C" fn NtPowerInformation(
    level: i32,
    input: *mut c_void,
    input_length: u32,
    output: *mut c_void,
    output_length: u32,
) -> NTSTATUS {
    // As the pinned kernel: a null buffer has no length.
    let input_length = if input.is_null() { 0 } else { input_length };
    let output_length = if output.is_null() { 0 } else { output_length };
    match level {
        SYSTEM_POWER_LOGGING_ENTRY => {
            if input_length == 0 || output_length != 0 {
                return STATUS_INVALID_PARAMETER;
            }
            if input_length < 8 {
                return STATUS_BUFFER_TOO_SMALL;
            }
            // SAFETY: the caller's buffer, of at least eight bytes.
            let (reason, states) = unsafe {
                let words = input.cast::<u32>();
                (words.read_unaligned(), words.add(1).read_unaligned())
            };
            match POWER.lock().sleep_disabled.log(reason, states) {
                Logged::Recorded => STATUS_SUCCESS,
                Logged::Already => STATUS_OBJECT_NAME_COLLISION,
                Logged::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
            }
        }
        PLATFORM_INFORMATION => {
            if output_length < 1 {
                return STATUS_BUFFER_TOO_SMALL;
            }
            // SAFETY: the caller's buffer, of at least a byte.
            unsafe { output.cast::<u8>().write(0) };
            STATUS_SUCCESS
        }
        FIRMWARE_TABLE_INFORMATION_REGISTERED => {
            if input_length != 0 || output_length != 0 {
                return STATUS_INVALID_PARAMETER;
            }
            STATUS_SUCCESS
        }
        QUERY_POTENTIAL_DRIPS_CONSTRAINT => STATUS_NOT_SUPPORTED,
        INTERNAL => {
            if input_length < 8 {
                return STATUS_INVALID_PARAMETER;
            }
            // SAFETY: the caller's buffer, of at least eight bytes.
            let request = unsafe { input.cast::<u32>().read_unaligned() };
            match request {
                INTERNAL_DRIPS_SET_DEVICE_FLAGS | INTERNAL_DRIPS_CLEAR_DEVICE_FLAGS => {
                    if input_length < INTERNAL_DRIPS_INPUT {
                        return STATUS_INVALID_PARAMETER;
                    }
                    // SAFETY: the buffer holds the three fields; the
                    // device is the caller's, null or live.
                    unsafe {
                        let device = input
                            .cast::<u8>()
                            .add(8)
                            .cast::<*mut DEVICE_OBJECT>()
                            .read_unaligned();
                        let flags = input.cast::<u8>().add(16).cast::<u32>().read_unaligned();
                        if request == INTERNAL_DRIPS_SET_DEVICE_FLAGS {
                            request::PoDirectedDripsSetDeviceFlags(device, flags)
                        } else {
                            request::drips_clear_device_flags(device, flags)
                        }
                    }
                }
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

    // A reason no driver logs, ruling out S1 and S4.
    const REASON: u32 = 0x4E4B_0001;
    let mut entry = [REASON, 0x9];
    let null = core::ptr::null_mut::<c_void>();
    let mut log = |length: u32, output: *mut c_void, output_length: u32| {
        // SAFETY: a local of at least the length given.
        unsafe {
            ZwPowerInformation(
                SYSTEM_POWER_LOGGING_ENTRY,
                entry.as_mut_ptr().cast(),
                length,
                output,
                output_length,
            )
        }
    };
    if log(0, null, 0) != STATUS_INVALID_PARAMETER
        || log(8, (&raw mut platform).cast(), 1) != STATUS_INVALID_PARAMETER
        || log(4, null, 0) != STATUS_BUFFER_TOO_SMALL
    {
        return Err("a malformed logging entry was not refused as Windows refuses it");
    }
    let first = log(8, null, 0);
    let recorded = POWER.lock().sleep_disabled.states(REASON);
    let second = log(8, null, 0);
    POWER.lock().sleep_disabled.forget(REASON);
    if first != STATUS_SUCCESS || recorded != Some(0x9) {
        return Err("a reason sleep is disabled was not recorded");
    }
    if second != STATUS_OBJECT_NAME_COLLISION {
        return Err("a reason was logged twice");
    }

    let mut simple = |level: i32, length: u32| {
        // SAFETY: a local of at least the length given, and no output.
        unsafe { ZwPowerInformation(level, entry.as_mut_ptr().cast(), length, null, 0) }
    };
    if simple(FIRMWARE_TABLE_INFORMATION_REGISTERED, 0) != STATUS_SUCCESS
        || simple(FIRMWARE_TABLE_INFORMATION_REGISTERED, 8) != STATUS_INVALID_PARAMETER
    {
        return Err(
            "the notice that firmware tables can be read was not taken as Windows takes it",
        );
    }
    if simple(QUERY_POTENTIAL_DRIPS_CONSTRAINT, 8) != STATUS_NOT_SUPPORTED {
        return Err("a low-power idle constraint was answered for a platform without the state");
    }
    Ok(())
}

/// For the self-tests: the internal request to set (else clear) a
/// device's flags for the low-power idle state, made as `storport.sys`
/// makes it, with `length` bytes of input.
///
/// # Safety
/// `device` is null or a live device object.
pub unsafe fn test_drips(
    set: bool,
    device: *mut DEVICE_OBJECT,
    flags: u32,
    length: u32,
) -> NTSTATUS {
    let request = if set {
        INTERNAL_DRIPS_SET_DEVICE_FLAGS
    } else {
        INTERNAL_DRIPS_CLEAR_DEVICE_FLAGS
    };
    let mut input = [u64::from(request), device as u64, u64::from(flags)];
    // SAFETY: a local of three pointers; the device per the contract.
    unsafe {
        ZwPowerInformation(
            INTERNAL,
            input.as_mut_ptr().cast(),
            length,
            core::ptr::null_mut(),
            0,
        )
    }
}

pub use crate::svc::zw::ZwPowerInformation;
