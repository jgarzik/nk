//! `ZwInitiatePowerAction`: a driver asks for the system's power state
//! to change.

use nk_ntabi::status::{NTSTATUS, STATUS_INVALID_PARAMETER};
use nk_po::action::{Outcome, outcome};

/// `ZwInitiatePowerAction` (exported; documented for user mode as
/// `NtInitiatePowerAction`): ask for `action`, a `POWER_ACTION`.
/// `acpi.sys` asks for a shutdown when the power button is pressed and
/// when a thermal zone passes its critical temperature.
///
/// A request the pinned kernel refuses outright is refused the same
/// way (`nk_po::action`). A shutdown that ends with the power off
/// powers the machine off now, through the path the kernel itself ends
/// a run by: the devices registered for it are sent their shutdown
/// requests, and the power goes off. NK has no user mode to ask and no
/// file system to flush. It does not return.
///
/// Partial: any other action (sleep, hibernation, a restart, none)
/// goes to Windows' policy manager, which NK lacks, and stops the
/// system naming the action.
pub extern "C" fn ZwInitiatePowerAction(
    action: i32,
    lightest_state: i32,
    flags: u32,
    _asynchronous: u8,
) -> NTSTATUS {
    match outcome(action, lightest_state, flags) {
        Outcome::Invalid => STATUS_INVALID_PARAMETER,
        Outcome::PowerOff => {
            kprintln!("po: a driver asked for a shutdown (flags {flags:#x}): powering off");
            crate::io::shutdown::shutdown_system();
            crate::hal::power_off_or_halt()
        }
        Outcome::NotImplemented => crate::kd::bugcheck(format_args!(
            "ZwInitiatePowerAction: NK does not implement power action {action} (lightest \
             system state {lightest_state}, flags {flags:#x})"
        )),
    }
}

/// For the self-tests.
pub fn test() -> Result<(), &'static str> {
    // What `acpi.sys` passes, but for one value out of range each.
    for (action, state, flags) in [
        (8, 4, 0x4100_0004),
        (6, 8, 0x4100_0004),
        (6, 4, 0x5100_0004),
        (6, 4, 0x4100_0044),
        (2, 5, 0),
    ] {
        if ZwInitiatePowerAction(action, state, flags, 0) != STATUS_INVALID_PARAMETER {
            return Err("a power action Windows refuses outright was not refused");
        }
    }
    Ok(())
}
