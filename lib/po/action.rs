//! A request to change the system's power state
//! (`ZwInitiatePowerAction`): what is refused outright, and what NK
//! does with the rest.
//!
//! The checks are those the pinned kernel's `NtInitiatePowerAction`
//! makes of a caller in kernel mode before it hands the request to its
//! policy manager. NK has no policy manager: a request to shut down
//! powers the machine off, which is where Windows' ends too.

use nk_ntabi::pnp::{
    POWER_ACTION_SHUTDOWN, POWER_ACTION_SHUTDOWN_OFF, POWER_ACTION_SLEEP, POWER_SYSTEM_HIBERNATE,
    POWER_SYSTEM_MAXIMUM,
};

/// The last `POWER_ACTION`: `PowerActionWarmEject`.
const LAST_ACTION: i32 = 7;
/// The flags the pinned kernel refuses: bit 28, and those it does not
/// define.
const REFUSED_FLAGS: u32 = 1 << 28 | 0x0CFF_FFC0;

/// What becomes of a request.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    /// `STATUS_INVALID_PARAMETER`.
    Invalid,
    /// The machine is powered off.
    PowerOff,
    /// A request Windows' policy manager would take up and NK does not
    /// implement: any action but a shutdown that ends with the power
    /// off.
    NotImplemented,
}

/// What becomes of a request for `action` (a `POWER_ACTION`) with the
/// lightest system state `lightest` and `flags`. The action and the
/// state are compared as the signed values the pinned kernel compares.
pub const fn outcome(action: i32, lightest: i32, flags: u32) -> Outcome {
    if lightest > POWER_SYSTEM_MAXIMUM as i32
        || action > LAST_ACTION
        || flags & REFUSED_FLAGS != 0
        || (action == POWER_ACTION_SLEEP as i32 && lightest >= POWER_SYSTEM_HIBERNATE as i32)
    {
        return Outcome::Invalid;
    }
    if action == POWER_ACTION_SHUTDOWN as i32 || action == POWER_ACTION_SHUTDOWN_OFF as i32 {
        Outcome::PowerOff
    } else {
        Outcome::NotImplemented
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nk_ntabi::pnp::*;

    const S3: i32 = POWER_SYSTEM_SLEEPING3 as i32;

    #[test]
    fn a_shutdown_powers_the_machine_off() {
        // As `acpi.sys` asks, for the power button and for a critical
        // temperature.
        let off = POWER_ACTION_SHUTDOWN_OFF as i32;
        assert_eq!(outcome(off, S3, 0x4100_0004), Outcome::PowerOff);
        assert_eq!(outcome(off, S3, 0x0200_0003), Outcome::PowerOff);
        assert_eq!(
            outcome(POWER_ACTION_SHUTDOWN as i32, S3, 0),
            Outcome::PowerOff
        );
    }

    #[test]
    fn values_out_of_range_are_refused() {
        let off = POWER_ACTION_SHUTDOWN_OFF as i32;
        assert_eq!(outcome(8, S3, 0), Outcome::Invalid);
        assert_eq!(outcome(off, 8, 0), Outcome::Invalid);
        assert_eq!(outcome(off, 7, 0), Outcome::PowerOff);
        assert_eq!(outcome(off, S3, 1 << 28), Outcome::Invalid);
        assert_eq!(outcome(off, S3, 0x40), Outcome::Invalid);
        assert_eq!(outcome(off, S3, 0x0400_0000), Outcome::Invalid);
        assert_eq!(outcome(off, S3, 0xE300_003F), Outcome::PowerOff);
    }

    #[test]
    fn a_sleep_no_lighter_than_hibernation_is_refused() {
        let sleep = POWER_ACTION_SLEEP as i32;
        assert_eq!(outcome(sleep, 5, 0), Outcome::Invalid);
        assert_eq!(outcome(sleep, 6, 0), Outcome::Invalid);
        assert_eq!(outcome(sleep, S3, 0), Outcome::NotImplemented);
    }

    #[test]
    fn the_other_actions_are_the_policy_managers() {
        for action in [
            POWER_ACTION_NONE,
            POWER_ACTION_RESERVED,
            POWER_ACTION_HIBERNATE,
            POWER_ACTION_SHUTDOWN_RESET,
            POWER_ACTION_WARM_EJECT,
        ] {
            assert_eq!(outcome(action as i32, S3, 0), Outcome::NotImplemented);
        }
        // Signed, as the pinned kernel compares.
        assert_eq!(outcome(-1, -1, 0), Outcome::NotImplemented);
    }
}
