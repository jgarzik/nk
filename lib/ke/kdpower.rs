//! The routines the kernel debugger is to call around a power
//! transition (`KdRegisterPowerHandler`): which are registered.

extern crate alloc;

use alloc::vec::Vec;

/// One registered routine: `VOID Handler(Context, ...)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Handler {
    pub routine: usize,
    pub context: usize,
}

/// The registered routines, each under the number its registration was
/// given. Numbers are not used again.
pub struct Handlers {
    last: usize,
    registered: Vec<(usize, Handler)>,
}

impl Handlers {
    pub const fn new() -> Self {
        Self {
            last: 0,
            registered: Vec::new(),
        }
    }

    /// Register a routine, for a number that is never zero. None when
    /// there is no memory.
    pub fn register(&mut self, handler: Handler) -> Option<usize> {
        self.registered.try_reserve(1).ok()?;
        self.last += 1;
        self.registered.push((self.last, handler));
        Some(self.last)
    }

    /// Take back the registration numbered `number`: what it was, or
    /// none if there is no such registration. The table holds no memory
    /// once it is empty.
    pub fn deregister(&mut self, number: usize) -> Option<Handler> {
        let at = self.registered.iter().position(|(n, _)| *n == number)?;
        let (_, handler) = self.registered.remove(at);
        if self.registered.is_empty() {
            self.registered = Vec::new();
        }
        Some(handler)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_registration_is_taken_back_once() {
        let mut handlers = Handlers::new();
        let one = Handler {
            routine: 0x100,
            context: 1,
        };
        let two = Handler {
            routine: 0x200,
            context: 2,
        };
        let first = handlers.register(one).unwrap();
        let second = handlers.register(two).unwrap();
        assert_ne!(first, 0);
        assert_ne!(first, second);
        assert_eq!(handlers.deregister(first), Some(one));
        assert_eq!(handlers.deregister(first), None);
        assert_eq!(handlers.deregister(0), None);
        assert_eq!(handlers.deregister(second), Some(two));
        // Numbers are not used again.
        let third = handlers.register(one).unwrap();
        assert!(third != first && third != second);
    }
}
