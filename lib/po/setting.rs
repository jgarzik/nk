//! Power settings: which have a value, and who is told of them
//! (`PoRegisterPowerSettingCallback`).
//!
//! A power setting is a GUID and a value. On Windows a driver registers
//! a callback for a setting and is called, from a thread of the power
//! manager's, with the value the setting has, and again whenever it
//! changes; a setting that has never been given a value has nothing to
//! tell, and the registration waits until it has
//! (`PoRegisterPowerSettingCallback`, `PopDispatchPowerSettingCallbacks`
//! in the pinned kernel).
//!
//! The pinned kernel itself gives two settings a value as it starts
//! (`PoInitSystem`): the power source, which is AC on a machine with no
//! battery, and the state of the console's display, which is on. Every
//! other setting is given its value by something NK does not have: the
//! power scheme, applied by user mode's power service; the platform's
//! idle driver (`pdc.sys`); a session. On NK those never have a value,
//! and a registration for one is kept and never called. NK's settings
//! do not change, so no registration is called twice.

extern crate alloc;

use alloc::vec::Vec;
use nk_ntabi::ex::GUID;

/// `GUID_ACDC_POWER_SOURCE`: where the machine's power comes from, a
/// `SYSTEM_POWER_CONDITION`.
pub const GUID_ACDC_POWER_SOURCE: GUID = GUID {
    Data1: 0x5D3E_9A59,
    Data2: 0xE9D5,
    Data3: 0x4B00,
    Data4: [0xA6, 0xBD, 0xFF, 0x34, 0xFF, 0x51, 0x65, 0x48],
};

/// `GUID_CONSOLE_DISPLAY_STATE`: whether the console's display is off
/// (0), on (1) or dimmed (2).
pub const GUID_CONSOLE_DISPLAY_STATE: GUID = GUID {
    Data1: 0x6FE6_9556,
    Data2: 0x704A,
    Data3: 0x47A0,
    Data4: [0x8F, 0x24, 0xC2, 0x8D, 0x93, 0x6F, 0xDA, 0x47],
};

/// `GUID_SESSION_DISPLAY_STATUS` and `GUID_SESSION_USER_PRESENCE`: the
/// settings that belong to a session. The pinned kernel refuses a
/// driver's registration for either (`PopStateIsSessionSpecific`).
const SESSION_SPECIFIC: [GUID; 2] = [
    GUID {
        Data1: 0x2B84_C20E,
        Data2: 0xAD23,
        Data3: 0x4DDF,
        Data4: [0x93, 0xDB, 0x05, 0xFF, 0xBD, 0x7E, 0xFC, 0xA5],
    },
    GUID {
        Data1: 0x3C0F_4548,
        Data2: 0xC03F,
        Data3: 0x4C4D,
        Data4: [0xB9, 0xF2, 0x23, 0x7E, 0xDE, 0x68, 0x63, 0x76],
    },
];

/// `PoAc`: the power source is AC.
const POWER_CONDITION_AC: u32 = 0;
/// `PowerMonitorOn`: the display is on.
const MONITOR_ON: u32 = 1;

/// The value `setting` has on NK, as the bytes a callback is handed;
/// `None` for a setting that has no value.
pub fn value(setting: &GUID) -> Option<[u8; 4]> {
    if *setting == GUID_ACDC_POWER_SOURCE {
        Some(POWER_CONDITION_AC.to_le_bytes())
    } else if *setting == GUID_CONSOLE_DISPLAY_STATE {
        Some(MONITOR_ON.to_le_bytes())
    } else {
        None
    }
}

/// Why a registration is refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refused {
    /// The setting belongs to a session: `STATUS_INVALID_PARAMETER`.
    SessionSpecific,
    /// `STATUS_INSUFFICIENT_RESOURCES`.
    NoMemory,
}

/// What became of a request to unregister.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Unregistered {
    /// The registration is gone.
    Gone,
    /// The registration's callback is running in the thread that asks:
    /// the registration goes when the callback returns.
    WhenItReturns,
    /// The registration's callback is running in another thread: the
    /// caller waits until it is woken, by whoever is told of it when
    /// the callback returns ([`Registrations::returned`]); the
    /// registration is gone then.
    Wait,
    /// No such registration, or one that is already going:
    /// `STATUS_INVALID_PARAMETER`.
    Invalid,
}

/// A callback to make: a registration's routine and context, and the
/// setting's value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Call {
    pub handle: usize,
    pub setting: GUID,
    pub value: [u8; 4],
    pub callback: usize,
    pub context: usize,
}

struct Registration {
    handle: usize,
    setting: GUID,
    callback: usize,
    context: usize,
    /// Whether the setting has a value the callback has not been told.
    owed: bool,
    /// The thread the callback is running in, if it is running.
    calling: Option<usize>,
    /// Whether the registration goes when its callback returns.
    leaving: bool,
    /// What wakes the thread that waits for the callback to return to
    /// take the registration away, if one waits.
    awaited: Option<usize>,
}

/// Every registration there is.
pub struct Registrations {
    list: Vec<Registration>,
    /// How many have been made: a handle is never used twice.
    made: usize,
}

impl Registrations {
    pub const fn new() -> Self {
        Self {
            list: Vec::new(),
            made: 0,
        }
    }

    /// Register `callback`, to be called with `context`, for `setting`.
    /// Returns the registration's handle, and whether a call is owed
    /// now: whether the setting has a value.
    pub fn register(
        &mut self,
        setting: GUID,
        callback: usize,
        context: usize,
    ) -> Result<(usize, bool), Refused> {
        if SESSION_SPECIFIC.contains(&setting) {
            return Err(Refused::SessionSpecific);
        }
        if self.list.try_reserve(1).is_err() {
            return Err(Refused::NoMemory);
        }
        self.made += 1;
        // Never null, never an address of anything.
        let handle = self.made << 4;
        let owed = value(&setting).is_some();
        self.list.push(Registration {
            handle,
            setting,
            callback,
            context,
            owed,
            calling: None,
            leaving: false,
            awaited: None,
        });
        Ok((handle, owed))
    }

    /// The next callback to make, oldest registration first, to be made
    /// in `thread`; `None` when none is owed. [`Self::returned`]
    /// follows the call.
    pub fn next_call(&mut self, thread: usize) -> Option<Call> {
        let registration = self
            .list
            .iter_mut()
            .find(|r| r.owed && r.calling.is_none())?;
        let value = value(&registration.setting)?;
        registration.owed = false;
        registration.calling = Some(thread);
        Some(Call {
            handle: registration.handle,
            setting: registration.setting,
            value,
            callback: registration.callback,
            context: registration.context,
        })
    }

    /// The callback of `handle` has returned. A registration that was
    /// unregistered while its callback ran goes now; if a thread waits
    /// for that, what wakes it is returned.
    pub fn returned(&mut self, handle: usize) -> Option<usize> {
        let at = self.list.iter().position(|r| r.handle == handle)?;
        let registration = &mut self.list[at];
        registration.calling = None;
        let waiter = registration.awaited;
        if registration.leaving || waiter.is_some() {
            self.remove(at);
        }
        waiter
    }

    /// Unregister `handle`, on behalf of `thread`, which `waiter` wakes
    /// if it has to wait.
    pub fn unregister(&mut self, handle: usize, thread: usize, waiter: usize) -> Unregistered {
        let Some(at) = self.list.iter().position(|r| r.handle == handle) else {
            return Unregistered::Invalid;
        };
        let registration = &mut self.list[at];
        if registration.leaving || registration.awaited.is_some() {
            return Unregistered::Invalid;
        }
        match registration.calling {
            None => {
                self.remove(at);
                Unregistered::Gone
            }
            Some(caller) if caller == thread => {
                registration.leaving = true;
                Unregistered::WhenItReturns
            }
            Some(_) => {
                registration.awaited = Some(waiter);
                Unregistered::Wait
            }
        }
    }

    /// Take the registration at `at` off the list. An empty list holds
    /// no memory.
    fn remove(&mut self, at: usize) {
        self.list.remove(at);
        if self.list.is_empty() {
            self.list = Vec::new();
        }
    }

    /// How many registrations there are.
    pub fn len(&self) -> usize {
        self.list.len()
    }

    /// Whether there is no registration.
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A setting of the power scheme's: `GUID_DISK_IDLE_TIMEOUT`.
    const SCHEME: GUID = GUID {
        Data1: 0x58E3_9BA8,
        Data2: 0xB8E6,
        Data3: 0x4EF6,
        Data4: [0x90, 0xD0, 0x89, 0xAE, 0x32, 0xB2, 0x58, 0xD6],
    };

    #[test]
    fn the_power_source_is_ac_and_the_display_is_on() {
        assert_eq!(value(&GUID_ACDC_POWER_SOURCE), Some([0, 0, 0, 0]));
        assert_eq!(value(&GUID_CONSOLE_DISPLAY_STATE), Some([1, 0, 0, 0]));
        assert_eq!(value(&SCHEME), None);
    }

    #[test]
    fn a_setting_with_a_value_is_told_once() {
        let mut all = Registrations::new();
        let (handle, owed) = all.register(GUID_ACDC_POWER_SOURCE, 0x100, 0x200).unwrap();
        assert!(owed && handle != 0);
        let call = all.next_call(7).unwrap();
        assert_eq!(
            call,
            Call {
                handle,
                setting: GUID_ACDC_POWER_SOURCE,
                value: [0; 4],
                callback: 0x100,
                context: 0x200,
            }
        );
        // Not again while it runs, nor after.
        assert_eq!(all.next_call(7), None);
        assert_eq!(all.returned(handle), None);
        assert_eq!(all.next_call(7), None);
        assert_eq!(all.len(), 1);
        assert_eq!(all.unregister(handle, 9, 0x90), Unregistered::Gone);
        assert!(all.is_empty());
    }

    #[test]
    fn a_setting_without_a_value_is_registered_and_never_told() {
        let mut all = Registrations::new();
        let (handle, owed) = all.register(SCHEME, 1, 2).unwrap();
        assert!(!owed);
        assert_eq!(all.next_call(7), None);
        assert_eq!(all.unregister(handle, 7, 0x70), Unregistered::Gone);
    }

    #[test]
    fn a_session_setting_is_refused() {
        let mut all = Registrations::new();
        for setting in SESSION_SPECIFIC {
            assert_eq!(all.register(setting, 1, 2), Err(Refused::SessionSpecific));
        }
        assert!(all.is_empty());
    }

    #[test]
    fn calls_are_made_oldest_registration_first() {
        let mut all = Registrations::new();
        let (first, _) = all.register(GUID_CONSOLE_DISPLAY_STATE, 1, 0).unwrap();
        let (_, _) = all.register(SCHEME, 2, 0).unwrap();
        let (third, _) = all.register(GUID_ACDC_POWER_SOURCE, 3, 0).unwrap();
        assert_ne!(first, third);
        assert_eq!(all.next_call(7).map(|c| c.callback), Some(1));
        // The first is still running: the worker goes on to the next.
        assert_eq!(all.next_call(8).map(|c| c.callback), Some(3));
        assert_eq!(all.next_call(9), None);
    }

    #[test]
    fn unregistering_from_inside_the_callback_takes_effect_when_it_returns() {
        let mut all = Registrations::new();
        let (handle, _) = all.register(GUID_ACDC_POWER_SOURCE, 1, 0).unwrap();
        all.next_call(7).unwrap();
        assert_eq!(all.unregister(handle, 7, 0x70), Unregistered::WhenItReturns);
        assert_eq!(all.len(), 1);
        // Already going: a second request is refused.
        assert_eq!(all.unregister(handle, 7, 0x70), Unregistered::Invalid);
        assert_eq!(all.unregister(handle, 8, 0x80), Unregistered::Invalid);
        assert_eq!(all.returned(handle), None);
        assert!(all.is_empty());
        assert_eq!(all.unregister(handle, 7, 0x70), Unregistered::Invalid);
    }

    #[test]
    fn unregistering_from_another_thread_waits_for_the_callback() {
        let mut all = Registrations::new();
        let (handle, _) = all.register(GUID_ACDC_POWER_SOURCE, 1, 0).unwrap();
        all.next_call(7).unwrap();
        let (other, _) = all.register(GUID_CONSOLE_DISPLAY_STATE, 2, 0).unwrap();
        all.next_call(6).unwrap();
        assert_eq!(all.unregister(handle, 8, 0x80), Unregistered::Wait);
        // A third thread is refused while the second waits.
        assert_eq!(all.unregister(handle, 9, 0x90), Unregistered::Invalid);
        // Another registration's callback returns: nobody is woken.
        assert_eq!(all.returned(other), None);
        assert_eq!(all.len(), 2);
        // Its own returns: the registration goes and the waiter wakes.
        assert_eq!(all.returned(handle), Some(0x80));
        assert_eq!(all.len(), 1);
        assert_eq!(all.unregister(handle, 8, 0x80), Unregistered::Invalid);
    }

    #[test]
    fn a_handle_is_never_used_twice_and_an_unknown_one_is_refused() {
        let mut all = Registrations::new();
        let (first, _) = all.register(SCHEME, 1, 0).unwrap();
        assert_eq!(all.unregister(first, 7, 0x70), Unregistered::Gone);
        let (second, _) = all.register(SCHEME, 1, 0).unwrap();
        assert_ne!(first, second);
        assert_eq!(all.unregister(first, 7, 0x70), Unregistered::Invalid);
        assert_eq!(all.unregister(0, 7, 0x70), Unregistered::Invalid);
        assert_eq!(all.unregister(second, 7, 0x70), Unregistered::Gone);
    }
}
