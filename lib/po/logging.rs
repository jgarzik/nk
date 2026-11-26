//! Why a sleep state cannot be entered: the reasons drivers and the
//! kernel log (`ZwPowerInformation`, `SystemPowerLoggingEntry`).
//!
//! The pinned kernel keeps one entry for each reason code
//! (`PopLogSleepDisabled`): the code and the sleep states it rules
//! out. A reason logged a second time is refused, whatever states it
//! names, and the first entry stays.

use alloc::vec::Vec;

/// What became of a reason handed to [`Reasons::log`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Logged {
    /// It is recorded.
    Recorded,
    /// The reason was logged before: Windows answers
    /// `STATUS_OBJECT_NAME_COLLISION`.
    Already,
    /// No memory for the entry.
    NoMemory,
}

/// The reasons logged, oldest first.
pub struct Reasons {
    entries: Vec<(u32, u32)>,
}

impl Reasons {
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Record that `reason` rules out the sleep states in `states`.
    pub fn log(&mut self, reason: u32, states: u32) -> Logged {
        if self.states(reason).is_some() {
            return Logged::Already;
        }
        if self.entries.try_reserve(1).is_err() {
            return Logged::NoMemory;
        }
        self.entries.push((reason, states));
        Logged::Recorded
    }

    /// The states `reason` was logged as ruling out, if it was logged.
    pub fn states(&self, reason: u32) -> Option<u32> {
        self.entries
            .iter()
            .find(|entry| entry.0 == reason)
            .map(|entry| entry.1)
    }

    /// Drop the entry for `reason`, and the memory of a list left
    /// empty.
    pub fn forget(&mut self, reason: u32) {
        self.entries.retain(|entry| entry.0 != reason);
        if self.entries.is_empty() {
            self.entries = Vec::new();
        }
    }
}

impl Default for Reasons {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reason_is_recorded_once() {
        let mut reasons = Reasons::new();
        assert_eq!(reasons.states(3), None);
        assert_eq!(reasons.log(3, 0x1), Logged::Recorded);
        assert_eq!(reasons.log(3, 0x6), Logged::Already);
        assert_eq!(reasons.states(3), Some(0x1));
    }

    #[test]
    fn reasons_are_kept_apart() {
        let mut reasons = Reasons::new();
        assert_eq!(reasons.log(3, 0x1), Logged::Recorded);
        assert_eq!(reasons.log(4, 0x8), Logged::Recorded);
        assert_eq!(reasons.states(3), Some(0x1));
        assert_eq!(reasons.states(4), Some(0x8));
    }

    #[test]
    fn a_forgotten_reason_can_be_logged_again() {
        let mut reasons = Reasons::new();
        assert_eq!(reasons.log(3, 0x1), Logged::Recorded);
        assert_eq!(reasons.log(4, 0x8), Logged::Recorded);
        reasons.forget(3);
        assert_eq!(reasons.states(3), None);
        assert_eq!(reasons.states(4), Some(0x8));
        assert_eq!(reasons.log(3, 0x2), Logged::Recorded);
    }
}
