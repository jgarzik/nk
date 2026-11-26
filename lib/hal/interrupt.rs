//! Device interrupts, the part both architectures share: how a line
//! signals, and which processor an interrupt is sent to.

/// When a line asks for service: Windows' `KINTERRUPT_MODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trigger {
    /// While the line is held active (`LevelSensitive`, 0).
    Level,
    /// Once per transition to active (`Latched`, 1).
    Edge,
}

impl Trigger {
    /// The `KINTERRUPT_MODE` value.
    pub const fn mode(self) -> u32 {
        match self {
            Trigger::Level => 0,
            Trigger::Edge => 1,
        }
    }

    /// The trigger a `KINTERRUPT_MODE` value names.
    pub const fn from_mode(mode: u32) -> Option<Self> {
        match mode {
            0 => Some(Trigger::Level),
            1 => Some(Trigger::Edge),
            _ => None,
        }
    }
}

/// Which state of a line is the active one: Windows'
/// `KINTERRUPT_POLARITY`, of which NK routes two.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Polarity {
    /// `InterruptActiveHigh`, `InterruptRisingEdge` (1).
    High,
    /// `InterruptActiveLow`, `InterruptFallingEdge` (2).
    Low,
}

impl Polarity {
    /// The `KINTERRUPT_POLARITY` value.
    pub const fn value(self) -> u32 {
        match self {
            Polarity::High => 1,
            Polarity::Low => 2,
        }
    }
}

/// A device's interrupt line as firmware names it: an input of the
/// machine's interrupt controllers and how the device signals on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Line {
    /// Global system interrupt: an I/O APIC input on x86-64, a GIC
    /// interrupt id on arm64.
    pub gsi: u32,
    pub trigger: Trigger,
    pub polarity: Polarity,
}

impl Polarity {
    /// The polarity a `KINTERRUPT_POLARITY` value names, of the two NK
    /// routes.
    pub const fn from_value(value: u32) -> Option<Self> {
        match value {
            1 => Some(Polarity::High),
            2 => Some(Polarity::Low),
            _ => None,
        }
    }
}

impl Line {
    /// The line an `INTERRUPT_VECTOR_DATA` names: its global system
    /// interrupt, `KINTERRUPT_POLARITY` and `KINTERRUPT_MODE`. `None`
    /// for a polarity or mode NK does not route.
    pub const fn from_vector_data(gsi: u32, polarity: u32, mode: u32) -> Option<Self> {
        match (Trigger::from_mode(mode), Polarity::from_value(polarity)) {
            (Some(trigger), Some(polarity)) => Some(Line {
                gsi,
                trigger,
                polarity,
            }),
            _ => None,
        }
    }
}

/// The processor an interrupt is sent to: one of those `allowed` (a
/// bit per processor) names, chosen by `seed` so that different
/// interrupts go to different processors. `None` if none is allowed.
pub const fn target(allowed: u64, seed: u32) -> Option<u8> {
    if allowed == 0 {
        return None;
    }
    let mut skip = seed % allowed.count_ones();
    let mut rest = allowed;
    loop {
        let bit = rest.trailing_zeros();
        if skip == 0 {
            return Some(bit as u8);
        }
        skip -= 1;
        rest &= rest - 1;
    }
}

/// `HalGetMessageRoutingInfo`'s destination mode in which a message
/// names its target by the processor's own identifier. The others are
/// the local APIC's logical modes, which NK does not use.
pub const DESTINATION_PHYSICAL: u32 = 1;

/// Whether `HalGetMessageRoutingInfo` can route a message of `kind` to
/// the processors `mask` of `group` in destination mode `mode`, where
/// the processors `online` run. As the pinned kernel decides it for a
/// machine whose processors are addressed physically: the kind is one
/// it knows (0 or 1), the mode is physical, and the target is one
/// running processor or all of them.
pub const fn message_routable(kind: u32, mask: u64, group: u16, mode: u32, online: u64) -> bool {
    kind <= 1
        && mode == DESTINATION_PHYSICAL
        && group == 0
        && mask & online != 0
        && (mask.is_power_of_two() || mask == online)
}

/// What Windows' HAL answers `acpi.sys` for the version register of
/// the I/O APIC whose inputs start at a global system interrupt
/// (`HalpInterruptGetApicVersion`): not the register, but one made up
/// from the number of lines the HAL knows the controller to have:
/// version 0x11, the last input's number in the third byte and the
/// count in the fourth. With no controller there (`lines` is `None`)
/// the fourth byte alone, 0xF0.
pub const fn apic_version(lines: Option<u32>) -> u32 {
    match lines {
        Some(lines) => 0x11 | (lines.wrapping_sub(1) & 0xFF) << 16 | (lines & 0xFF) << 24,
        None => 0xF000_0000,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_data_names_a_line() {
        assert_eq!(
            Line::from_vector_data(9, 2, 0),
            Some(Line {
                gsi: 9,
                trigger: Trigger::Level,
                polarity: Polarity::Low
            })
        );
        assert_eq!(
            Line::from_vector_data(1, 1, 1),
            Some(Line {
                gsi: 1,
                trigger: Trigger::Edge,
                polarity: Polarity::High
            })
        );
        // Unknown polarity, both edges, and a mode that is neither.
        assert_eq!(Line::from_vector_data(9, 0, 0), None);
        assert_eq!(Line::from_vector_data(9, 3, 1), None);
        assert_eq!(Line::from_vector_data(9, 1, 2), None);
    }

    #[test]
    fn an_apic_version_is_made_from_the_line_count() {
        assert_eq!(apic_version(Some(24)), 0x1817_0011);
        assert_eq!(apic_version(Some(1)), 0x0100_0011);
        assert_eq!(apic_version(None), 0xF000_0000);
    }

    #[test]
    fn a_message_goes_to_one_running_processor_or_to_all() {
        let online = 0b1111;
        for kind in [0, 1] {
            assert!(message_routable(kind, 0b0100, 0, 1, online));
            assert!(message_routable(kind, online, 0, 1, online));
            assert!(message_routable(kind, 1, 0, 1, 1));
            // Several, but not all.
            assert!(!message_routable(kind, 0b0110, 0, 1, online));
            assert!(!message_routable(kind, 0b1_1111, 0, 1, online));
            // None, or one that does not run.
            assert!(!message_routable(kind, 0, 0, 1, online));
            assert!(!message_routable(kind, 0b1_0000, 0, 1, online));
            // Another group.
            assert!(!message_routable(kind, 0b0100, 1, 1, online));
            assert!(!message_routable(kind, online, 1, 1, online));
            // The logical modes, and no mode at all.
            for mode in [0, 2, 3, 4, u32::MAX] {
                assert!(!message_routable(kind, 0b0100, 0, mode, online));
                assert!(!message_routable(kind, online, 0, mode, online));
            }
        }
        for kind in [2, 3, u32::MAX] {
            assert!(!message_routable(kind, 0b0100, 0, 1, online));
        }
    }

    #[test]
    fn the_values_are_windows_own() {
        assert_eq!(Trigger::Level.mode(), 0);
        assert_eq!(Trigger::Edge.mode(), 1);
        assert_eq!(Trigger::from_mode(0), Some(Trigger::Level));
        assert_eq!(Trigger::from_mode(1), Some(Trigger::Edge));
        assert_eq!(Trigger::from_mode(2), None);
        assert_eq!(Polarity::High.value(), 1);
        assert_eq!(Polarity::Low.value(), 2);
    }

    #[test]
    fn a_target_is_an_allowed_processor() {
        assert_eq!(target(0, 5), None);
        assert_eq!(target(1, 0), Some(0));
        assert_eq!(target(1, 77), Some(0));
        assert_eq!(target(0b1111, 0), Some(0));
        assert_eq!(target(0b1111, 1), Some(1));
        assert_eq!(target(0b1111, 6), Some(2));
        assert_eq!(target(0b1010_0100, 0), Some(2));
        assert_eq!(target(0b1010_0100, 1), Some(5));
        assert_eq!(target(0b1010_0100, 2), Some(7));
        assert_eq!(target(0b1010_0100, 3), Some(2));
        assert_eq!(target(1 << 63, 9), Some(63));
        assert_eq!(target(u64::MAX, 63), Some(63));
        for seed in 0..200 {
            let cpu = target(0x8000_0000_0000_F0F1, seed).unwrap();
            assert!(0x8000_0000_0000_F0F1u64 & 1 << cpu != 0);
        }
    }
}
