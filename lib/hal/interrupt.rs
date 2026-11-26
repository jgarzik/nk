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

#[cfg(test)]
mod tests {
    use super::*;

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
