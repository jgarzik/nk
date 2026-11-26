//! The power requests a driver asks for (`PoRequestPowerIrp`): which
//! are accepted, and the order in which those for one device are sent.
//!
//! The pinned kernel sends one query or set of a device's power state
//! at a time to a device's stack: a second waits until the first has
//! completed, and they are sent in the order they were asked for
//! (`PopQueueQuerySetIrp`, `PopDequeueQuerySetIrp`). A wait-wake
//! request is not held back by them, nor they by it.

use alloc::collections::VecDeque;
use nk_ntabi::pnp::{IRP_MN_QUERY_POWER, IRP_MN_SET_POWER, IRP_MN_WAIT_WAKE};

/// What a driver may ask for, by minor function.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// `IRP_MN_WAIT_WAKE`: sent at once.
    WaitWake,
    /// `IRP_MN_QUERY_POWER` or `IRP_MN_SET_POWER` of the device's
    /// state: sent in turn.
    InTurn,
}

/// The kind of request `minor` asks for; `None` for a minor function
/// `PoRequestPowerIrp` refuses (`STATUS_INVALID_PARAMETER_2`).
pub const fn kind(minor: u8) -> Option<Kind> {
    match minor {
        IRP_MN_WAIT_WAKE => Some(Kind::WaitWake),
        IRP_MN_SET_POWER | IRP_MN_QUERY_POWER => Some(Kind::InTurn),
        _ => None,
    }
}

/// One device's requests that are sent in turn. `T` names a request.
#[derive(Debug)]
pub struct Turns<T> {
    /// Whether one has been sent and has not completed.
    sent: bool,
    /// Those that wait, oldest first.
    waiting: VecDeque<T>,
}

impl<T> Turns<T> {
    pub const fn new() -> Self {
        Self {
            sent: false,
            waiting: VecDeque::new(),
        }
    }

    /// A request has been asked for. It is handed back if it is to be
    /// sent now; else it waits. `Err` gives it back when there is no
    /// memory to make it wait.
    pub fn asked(&mut self, request: T) -> Result<Option<T>, T> {
        if !self.sent {
            self.sent = true;
            return Ok(Some(request));
        }
        if self.waiting.try_reserve(1).is_err() {
            return Err(request);
        }
        self.waiting.push_back(request);
        Ok(None)
    }

    /// The request that was sent has completed. Returns the one to
    /// send next, if one waits.
    pub fn completed(&mut self) -> Option<T> {
        let next = self.waiting.pop_front();
        self.sent = next.is_some();
        if self.waiting.is_empty() {
            // An empty queue holds no memory.
            self.waiting = VecDeque::new();
        }
        next
    }

    /// Whether nothing is sent and nothing waits.
    pub fn is_idle(&self) -> bool {
        !self.sent && self.waiting.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_wait_wake_query_and_set_are_accepted() {
        assert_eq!(kind(0), Some(Kind::WaitWake));
        assert_eq!(kind(1), None); // IRP_MN_POWER_SEQUENCE
        assert_eq!(kind(2), Some(Kind::InTurn));
        assert_eq!(kind(3), Some(Kind::InTurn));
        for minor in 4..=255 {
            assert_eq!(kind(minor), None);
        }
    }

    #[test]
    fn the_first_request_is_sent_at_once() {
        let mut turns = Turns::new();
        assert!(turns.is_idle());
        assert_eq!(turns.asked(1), Ok(Some(1)));
        assert!(!turns.is_idle());
        assert_eq!(turns.completed(), None);
        assert!(turns.is_idle());
    }

    #[test]
    fn later_requests_wait_and_go_in_the_order_asked() {
        let mut turns = Turns::new();
        assert_eq!(turns.asked(1), Ok(Some(1)));
        assert_eq!(turns.asked(2), Ok(None));
        assert_eq!(turns.asked(3), Ok(None));
        assert_eq!(turns.completed(), Some(2));
        // One asked for while another is out waits behind those
        // already waiting.
        assert_eq!(turns.asked(4), Ok(None));
        assert_eq!(turns.completed(), Some(3));
        assert_eq!(turns.completed(), Some(4));
        assert!(!turns.is_idle());
        assert_eq!(turns.completed(), None);
        assert!(turns.is_idle());
        assert_eq!(turns.asked(5), Ok(Some(5)));
    }
}
