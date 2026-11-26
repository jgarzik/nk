//! The power state a device object records: `DEVOBJ_EXTENSION.PowerFlags`.
//!
//! The pinned kernel's `PoSetPowerState` keeps the system power state a
//! driver reports for its device in bits 0 to 3 of that word and the
//! device power state in bits 4 to 7, and returns what was there. It
//! tells nobody.

use nk_ntabi::pnp::{POWER_STATE_TYPE_DEVICE, POWER_STATE_TYPE_SYSTEM};

/// The bits of `PowerFlags` that hold the system power state.
const SYSTEM_MASK: u32 = 0x0F;
/// The bits that hold the device power state, and where they start.
const DEVICE_MASK: u32 = 0xF0;
const DEVICE_SHIFT: u32 = 4;

/// Record `state`, of the kind `kind` (a `POWER_STATE_TYPE`), in
/// `flags`. Returns the new flags and the state of that kind recorded
/// before.
///
/// A kind that is neither the system's nor the device's records
/// nothing, and the state before is reported as zero: what the pinned
/// kernel does.
pub const fn record(flags: u32, kind: u32, state: u32) -> (u32, u32) {
    match kind {
        POWER_STATE_TYPE_SYSTEM => (
            flags & !SYSTEM_MASK | state & SYSTEM_MASK,
            flags & SYSTEM_MASK,
        ),
        POWER_STATE_TYPE_DEVICE => (
            flags & !DEVICE_MASK | (state << DEVICE_SHIFT) & DEVICE_MASK,
            (flags & DEVICE_MASK) >> DEVICE_SHIFT,
        ),
        _ => (flags, 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nk_ntabi::pnp::{POWER_DEVICE_D0, POWER_DEVICE_D3, POWER_SYSTEM_WORKING};

    #[test]
    fn a_device_state_goes_in_the_second_nibble() {
        let (flags, before) = record(0, POWER_STATE_TYPE_DEVICE, POWER_DEVICE_D0);
        assert_eq!((flags, before), (0x10, 0));
        let (flags, before) = record(flags, POWER_STATE_TYPE_DEVICE, POWER_DEVICE_D3);
        assert_eq!((flags, before), (0x40, POWER_DEVICE_D0));
    }

    #[test]
    fn a_system_state_goes_in_the_first_nibble() {
        let (flags, before) = record(0x40, POWER_STATE_TYPE_SYSTEM, POWER_SYSTEM_WORKING);
        assert_eq!((flags, before), (0x41, 0));
        let (flags, before) = record(flags, POWER_STATE_TYPE_SYSTEM, POWER_SYSTEM_WORKING);
        assert_eq!((flags, before), (0x41, POWER_SYSTEM_WORKING));
    }

    #[test]
    fn the_other_bits_of_the_word_stay() {
        let (flags, _) = record(0xFFFF_FF00, POWER_STATE_TYPE_DEVICE, POWER_DEVICE_D0);
        assert_eq!(flags, 0xFFFF_FF10);
        let (flags, _) = record(flags, POWER_STATE_TYPE_SYSTEM, 0x1F);
        assert_eq!(flags, 0xFFFF_FF1F);
    }

    #[test]
    fn a_kind_windows_does_not_define_records_nothing() {
        assert_eq!(record(0x41, 2, POWER_DEVICE_D3), (0x41, 0));
    }
}
