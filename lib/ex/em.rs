//! The errata manager's verdicts over a database that holds nothing.
//!
//! Windows' errata manager matches the machine against rules read from
//! an errata file at boot. A provider (a driver) registers the kinds of
//! entry it supplies and the callbacks it implements, each named by a
//! GUID the database must already hold; a client asks for the state of
//! a rule by its GUID. NK reads no errata file: its database has no
//! entry type, no callback and no rule. These are the answers the
//! pinned kernel's routines (`EmpProviderRegister`,
//! `EmClientQueryRuleState`, `EmClientRuleEvaluate`) give then.

use nk_ntabi::em::{EM_CALLBACK_REGISTRATION, EM_ENTRY_REGISTRATION};
use nk_ntabi::status::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND};

/// `EM_RULE_STATE` `STATE_UNKNOWN`: what a client is told of a rule
/// that could not be decided.
pub const STATE_UNKNOWN: u32 = 1;

/// What a provider asks to register, as far as the verdict needs it.
pub struct Registration {
    /// The provider named no driver object.
    pub no_driver: bool,
    /// The provider gave nowhere to put its handle.
    pub no_handle: bool,
    pub entry_count: u32,
    /// The first of the entries; none when the array is null.
    pub first_entry: Option<EM_ENTRY_REGISTRATION>,
    pub callback_count: u32,
    /// The first of the callbacks; none when the array is null.
    pub first_callback: Option<EM_CALLBACK_REGISTRATION>,
}

/// Whether a provider may register. With nothing in the database, only
/// one that registers nothing: the first entry or callback it names is
/// not found.
pub fn register(r: &Registration) -> Result<(), NTSTATUS> {
    if r.no_driver
        || r.no_handle
        || (r.entry_count != 0 && r.first_entry.is_none())
        || (r.callback_count != 0 && r.first_callback.is_none())
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if let (true, Some(entry)) = (r.entry_count != 0, &r.first_entry) {
        return Err(if entry.EntryGuid.is_null() {
            STATUS_INVALID_PARAMETER
        } else {
            STATUS_NOT_FOUND
        });
    }
    if let (true, Some(callback)) = (r.callback_count != 0, &r.first_callback) {
        return Err(
            if callback.CallbackFunction.is_null() || callback.CallbackGuid.is_null() {
                STATUS_INVALID_PARAMETER
            } else {
                STATUS_NOT_FOUND
            },
        );
    }
    Ok(())
}

/// The status of a client's question about a rule, asked with every
/// argument it needs (`complete`) or not: no rule is found.
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
    use core::ffi::c_void;

    fn entry(guid: usize) -> Option<EM_ENTRY_REGISTRATION> {
        Some(EM_ENTRY_REGISTRATION {
            EntryGuid: guid as *const _,
            LazyEntryCallback: core::ptr::null_mut(),
            LazyCallbackContext: core::ptr::null_mut(),
        })
    }

    fn callback(guid: usize, function: usize) -> Option<EM_CALLBACK_REGISTRATION> {
        Some(EM_CALLBACK_REGISTRATION {
            CallbackGuid: guid as *const _,
            CallbackFunction: function as *mut c_void,
            Context: core::ptr::null_mut(),
        })
    }

    fn nothing() -> Registration {
        Registration {
            no_driver: false,
            no_handle: false,
            entry_count: 0,
            first_entry: None,
            callback_count: 0,
            first_callback: None,
        }
    }

    #[test]
    fn a_provider_of_nothing_registers() {
        assert_eq!(register(&nothing()), Ok(()));
        // Arrays given with counts of zero are not looked at.
        let r = Registration {
            first_entry: entry(0),
            first_callback: callback(0, 0),
            ..nothing()
        };
        assert_eq!(register(&r), Ok(()));
    }

    #[test]
    fn missing_arguments_are_invalid() {
        for r in [
            Registration {
                no_driver: true,
                ..nothing()
            },
            Registration {
                no_handle: true,
                ..nothing()
            },
            Registration {
                entry_count: 1,
                ..nothing()
            },
            Registration {
                callback_count: 1,
                ..nothing()
            },
            Registration {
                entry_count: 1,
                first_entry: entry(0),
                ..nothing()
            },
            Registration {
                callback_count: 1,
                first_callback: callback(0x10, 0),
                ..nothing()
            },
            Registration {
                callback_count: 1,
                first_callback: callback(0, 0x20),
                ..nothing()
            },
        ] {
            assert_eq!(register(&r), Err(STATUS_INVALID_PARAMETER));
        }
    }

    #[test]
    fn what_a_provider_names_is_not_found() {
        let r = Registration {
            entry_count: 3,
            first_entry: entry(0x10),
            callback_count: 3,
            first_callback: callback(0, 0),
            ..nothing()
        };
        // The entries are looked up first.
        assert_eq!(register(&r), Err(STATUS_NOT_FOUND));
        let r = Registration {
            callback_count: 1,
            first_callback: callback(0x10, 0x20),
            ..nothing()
        };
        assert_eq!(register(&r), Err(STATUS_NOT_FOUND));
    }

    #[test]
    fn no_rule_is_found() {
        assert_eq!(rule(true), STATUS_NOT_FOUND);
        assert_eq!(rule(false), STATUS_INVALID_PARAMETER);
    }
}
