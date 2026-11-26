//! The errata manager's database, and its verdicts.
//!
//! Windows' errata manager matches the machine against rules. Its
//! database is read from an errata file at boot: the kinds of entry
//! (facts about the machine) and the callbacks (tests over entries)
//! that exist, each named by a GUID, and the rules built from them. A
//! provider (a driver) then registers the entry types it supplies and
//! the callbacks it implements; a client asks for the state of a rule.
//!
//! NK reads no errata file. Its database declares no rule, and its
//! entry types and callbacks are the ones providers register: a
//! registration is checked as the pinned kernel's `EmpProviderRegister`
//! checks one whose GUIDs the database knows, and a client's question
//! (`EmClientQueryRuleState`, `EmClientRuleEvaluate`) is answered as
//! Windows answers for a rule its database lacks.

extern crate alloc;

use alloc::vec::Vec;
use nk_ntabi::ex::GUID;
use nk_ntabi::status::{
    NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND,
    STATUS_OBJECT_NAME_COLLISION,
};

/// `EM_RULE_STATE` `STATE_UNKNOWN`: what a client is told of a rule
/// that could not be decided.
pub const STATE_UNKNOWN: u32 = 1;

/// An entry type a provider registers: its GUID, none if the provider
/// gave no GUID, and the routine that supplies the entry when a rule
/// first needs it, 0 for none.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Entry {
    pub guid: Option<GUID>,
    pub lazy_callback: usize,
    pub lazy_context: usize,
}

/// A callback a provider registers: its GUID, none if the provider
/// gave no GUID, the routine (0 for none) and its context.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Callback {
    pub guid: Option<GUID>,
    pub function: usize,
    pub context: usize,
}

struct Registered<T> {
    provider: u64,
    guid: GUID,
    what: T,
}

/// What providers have registered.
pub struct Database {
    last_provider: u64,
    entries: Vec<Registered<(usize, usize)>>,
    callbacks: Vec<Registered<(usize, usize)>>,
}

impl Database {
    pub const fn new() -> Self {
        Self {
            last_provider: 0,
            entries: Vec::new(),
            callbacks: Vec::new(),
        }
    }

    /// Register a provider of `entries` and `callbacks`, all or none,
    /// for a number that names the registration.
    ///
    /// | Refusal | Status |
    /// | --- | --- |
    /// | an entry type or a callback without a GUID, a callback without a routine | `STATUS_INVALID_PARAMETER` |
    /// | a callback another routine is registered for | `STATUS_OBJECT_NAME_COLLISION` |
    /// | no memory | `STATUS_INSUFFICIENT_RESOURCES` |
    pub fn register(&mut self, entries: &[Entry], callbacks: &[Callback]) -> Result<u64, NTSTATUS> {
        // Entries first, then callbacks, each in order: the first thing
        // wrong decides the status.
        if entries.iter().any(|e| e.guid.is_none()) {
            return Err(STATUS_INVALID_PARAMETER);
        }
        for (i, callback) in callbacks.iter().enumerate() {
            let Some(guid) = callback.guid.filter(|_| callback.function != 0) else {
                return Err(STATUS_INVALID_PARAMETER);
            };
            // A callback has one routine: registering the same one
            // again is accepted, another is a collision.
            let other = |function: usize| function != callback.function;
            let registered = self.callbacks.iter().map(|c| (c.guid, c.what.0));
            let earlier = callbacks[..i]
                .iter()
                .map(|c| (c.guid.unwrap_or(guid), c.function));
            if registered
                .chain(earlier)
                .any(|(g, f)| g == guid && other(f))
            {
                return Err(STATUS_OBJECT_NAME_COLLISION);
            }
        }
        if self.entries.try_reserve(entries.len()).is_err()
            || self.callbacks.try_reserve(callbacks.len()).is_err()
        {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        self.last_provider += 1;
        let provider = self.last_provider;
        for entry in entries {
            if let Some(guid) = entry.guid {
                self.entries.push(Registered {
                    provider,
                    guid,
                    what: (entry.lazy_callback, entry.lazy_context),
                });
            }
        }
        for callback in callbacks {
            if let Some(guid) = callback.guid {
                self.callbacks.push(Registered {
                    provider,
                    guid,
                    what: (callback.function, callback.context),
                });
            }
        }
        Ok(provider)
    }

    /// Take back what the registration numbered `provider` registered.
    /// The database holds no memory once it is empty.
    pub fn deregister(&mut self, provider: u64) {
        self.entries.retain(|e| e.provider != provider);
        self.callbacks.retain(|c| c.provider != provider);
        if self.entries.is_empty() {
            self.entries = Vec::new();
        }
        if self.callbacks.is_empty() {
            self.callbacks = Vec::new();
        }
    }

    /// The routine and context registered for the callback `guid`.
    pub fn callback(&self, guid: &GUID) -> Option<(usize, usize)> {
        self.callbacks
            .iter()
            .find(|c| c.guid == *guid)
            .map(|c| c.what)
    }

    /// How many providers supply entries of the type `guid`.
    pub fn suppliers(&self, guid: &GUID) -> usize {
        self.entries.iter().filter(|e| e.guid == *guid).count()
    }
}

/// The status of a client's question about a rule, asked with every
/// argument it needs (`complete`) or not: the database has no rule.
pub fn rule(complete: bool) -> NTSTATUS {
    if complete {
        STATUS_NOT_FOUND
    } else {
        STATUS_INVALID_PARAMETER
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guid(n: u32) -> GUID {
        GUID {
            Data1: n,
            Data2: 2,
            Data3: 3,
            Data4: [4; 8],
        }
    }

    fn entry(n: u32) -> Entry {
        Entry {
            guid: Some(guid(n)),
            lazy_callback: 0,
            lazy_context: 0,
        }
    }

    fn callback(n: u32, function: usize) -> Callback {
        Callback {
            guid: Some(guid(n)),
            function,
            context: 7,
        }
    }

    #[test]
    fn a_provider_registers_and_takes_back() {
        let mut db = Database::new();
        let first = db
            .register(&[entry(1), entry(2)], &[callback(10, 0x100)])
            .unwrap();
        let second = db.register(&[entry(1)], &[]).unwrap();
        assert_ne!(first, second);
        assert_eq!(db.suppliers(&guid(1)), 2);
        assert_eq!(db.suppliers(&guid(2)), 1);
        assert_eq!(db.suppliers(&guid(3)), 0);
        assert_eq!(db.callback(&guid(10)), Some((0x100, 7)));
        assert_eq!(db.callback(&guid(11)), None);
        db.deregister(first);
        assert_eq!(db.suppliers(&guid(1)), 1);
        assert_eq!(db.callback(&guid(10)), None);
        db.deregister(second);
        assert_eq!(db.suppliers(&guid(1)), 0);
        // Taking back what is not registered does nothing.
        db.deregister(first);
        // A provider of nothing registers too.
        assert!(db.register(&[], &[]).is_ok());
    }

    #[test]
    fn a_registration_without_its_parts_is_invalid() {
        let mut db = Database::new();
        let nameless = Entry {
            guid: None,
            ..entry(1)
        };
        assert_eq!(
            db.register(&[entry(1), nameless], &[]),
            Err(STATUS_INVALID_PARAMETER)
        );
        let nameless = Callback {
            guid: None,
            ..callback(1, 0x100)
        };
        assert_eq!(db.register(&[], &[nameless]), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(
            db.register(&[entry(1)], &[callback(1, 0)]),
            Err(STATUS_INVALID_PARAMETER)
        );
        // Nothing of a refused registration stays.
        assert_eq!(db.suppliers(&guid(1)), 0);
    }

    #[test]
    fn a_callback_has_one_routine() {
        let mut db = Database::new();
        let first = db.register(&[], &[callback(1, 0x100)]).unwrap();
        // The same routine again is accepted; another collides, and
        // registers nothing.
        let again = db.register(&[], &[callback(1, 0x100)]).unwrap();
        assert_eq!(
            db.register(&[entry(5)], &[callback(2, 0x300), callback(1, 0x200)]),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert_eq!(db.callback(&guid(2)), None);
        assert_eq!(db.suppliers(&guid(5)), 0);
        // Within one registration too.
        assert_eq!(
            db.register(&[], &[callback(3, 0x100), callback(3, 0x200)]),
            Err(STATUS_OBJECT_NAME_COLLISION)
        );
        assert!(
            db.register(&[], &[callback(3, 0x100), callback(3, 0x100)])
                .is_ok()
        );
        db.deregister(first);
        // Still registered by the second.
        assert_eq!(db.callback(&guid(1)), Some((0x100, 7)));
        db.deregister(again);
        assert!(db.register(&[], &[callback(1, 0x200)]).is_ok());
    }

    #[test]
    fn no_rule_is_found() {
        assert_eq!(rule(true), STATUS_NOT_FOUND);
        assert_eq!(rule(false), STATUS_INVALID_PARAMETER);
    }
}
