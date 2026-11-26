//! The runtime power framework (PoFx) for devices whose components are
//! never put in a low-power state.
//!
//! A driver registers a device as a set of components
//! ([`PoFxRegisterDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxregisterdevice))
//! and then tells the framework when it is using each
//! (`PoFxActivateComponent`) and when it has stopped
//! (`PoFxIdleComponent`). The framework counts, and tells the driver
//! when a component passes between its two conditions, active and
//! idle:
//!
//! - A component whose count leaves zero becomes active, and the driver
//!   is told so (`ComponentActiveConditionCallback`).
//! - A component whose count reaches zero is to become idle: the driver
//!   is told (`ComponentIdleConditionCallback`) and answers, then or
//!   later, with `PoFxCompleteIdleCondition`; only then is the
//!   component idle.
//!
//! One transition of a component is under way at a time, and the next
//! starts when it has finished, so the driver sees them in order.
//! [`Component`] is that rule. On Windows an idle component may then be
//! moved to a low-power state (`ComponentIdleStateCallback`) and the
//! whole device powered down when all are idle; NK does neither: a
//! component stays in F0 and a device in D0.
//!
//! [`registration`] is what the pinned kernel checks of the components a
//! driver describes (`PopFxRegisterDeviceWorker`).

/// `PO_FX_FLAG_BLOCKING`: the call returns when the transition it
/// starts has finished.
pub const FLAG_BLOCKING: u32 = 1;
/// `PO_FX_FLAG_ASYNC_ONLY`: the driver's callbacks are made from
/// another thread.
pub const FLAG_ASYNC_ONLY: u32 = 2;

/// Which of its two conditions a component is in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Condition {
    Active,
    Idle,
}

/// What the driver is to be told next about a component.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tell {
    /// `ComponentActiveConditionCallback`; [`Component::told_active`]
    /// when it has returned.
    Active,
    /// `ComponentIdleConditionCallback`; the transition finishes when
    /// the callback has returned ([`Component::told_idle`]) and the
    /// driver has completed it ([`Component::idle_completed`]).
    Idle,
}

/// The transition of a component that is under way.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Moving {
    /// The driver is being told the component is active.
    ToActive,
    /// The component is becoming idle: whether the driver's callback
    /// has returned, and whether the driver has completed the
    /// transition.
    ToIdle { returned: bool, completed: bool },
}

/// One component of a device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Component {
    /// How many activations are outstanding.
    count: u32,
    condition: Condition,
    moving: Option<Moving>,
}

/// `PoFxIdleComponent` for a component that has no activation
/// outstanding, which stops Windows (`INTERNAL_POWER_ERROR`, 0x608).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NotActivated;

/// `PoFxCompleteIdleCondition` for a component whose idle transition
/// is not waiting for it, which stops Windows (`INTERNAL_POWER_ERROR`,
/// 0x613).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NotIdling;

impl Component {
    /// A component as registration leaves it: active, with the one
    /// activation that `PoFxStartDevicePowerManagement` gives up.
    pub const fn new() -> Self {
        Self {
            count: 1,
            condition: Condition::Active,
            moving: None,
        }
    }

    /// `PoFxActivateComponent`: one more activation.
    pub fn activate(&mut self) {
        self.count += 1;
    }

    /// `PoFxIdleComponent`: one activation fewer.
    pub fn idle(&mut self) -> Result<(), NotActivated> {
        if self.count == 0 {
            return Err(NotActivated);
        }
        self.count -= 1;
        Ok(())
    }

    /// What the driver is to be told now, if anything: asked after
    /// every change, by whoever made it. `Some` starts a transition,
    /// and nothing more is to be told until it has finished.
    pub fn owed(&mut self) -> Option<Tell> {
        if self.moving.is_some() {
            return None;
        }
        match (self.condition, self.count) {
            (Condition::Active, 0) => {
                self.moving = Some(Moving::ToIdle {
                    returned: false,
                    completed: false,
                });
                Some(Tell::Idle)
            }
            (Condition::Idle, count) if count > 0 => {
                self.condition = Condition::Active;
                self.moving = Some(Moving::ToActive);
                Some(Tell::Active)
            }
            _ => None,
        }
    }

    /// The driver's active-condition callback has returned.
    pub fn told_active(&mut self) {
        if self.moving == Some(Moving::ToActive) {
            self.moving = None;
        }
    }

    /// The driver's idle-condition callback has returned.
    pub fn told_idle(&mut self) {
        if let Some(Moving::ToIdle { completed, .. }) = self.moving {
            self.become_idle(true, completed);
        }
    }

    /// `PoFxCompleteIdleCondition`.
    pub fn idle_completed(&mut self) -> Result<(), NotIdling> {
        match self.moving {
            Some(Moving::ToIdle {
                returned,
                completed: false,
            }) => {
                self.become_idle(returned, true);
                Ok(())
            }
            _ => Err(NotIdling),
        }
    }

    fn become_idle(&mut self, returned: bool, completed: bool) {
        if returned && completed {
            self.condition = Condition::Idle;
            self.moving = None;
        } else {
            self.moving = Some(Moving::ToIdle {
                returned,
                completed,
            });
        }
    }

    /// The condition the component is in, if no transition is under
    /// way.
    pub fn settled(&self) -> Option<Condition> {
        match self.moving {
            None => Some(self.condition),
            Some(_) => None,
        }
    }

    /// Whether the component is where its count says it should be, with
    /// no transition under way: what a blocking call waits for.
    pub fn at_rest(&self) -> bool {
        match self.settled() {
            Some(Condition::Active) => self.count > 0,
            Some(Condition::Idle) => self.count == 0,
            None => false,
        }
    }

    /// How many activations are outstanding.
    pub fn count(&self) -> u32 {
        self.count
    }
}

/// What a driver says of one component when it registers a device.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Described<'a> {
    /// `IdleStateCount`: how many F-states the component has, F0
    /// included.
    pub idle_states: u32,
    /// `DeepestWakeableIdleState`.
    pub deepest_wakeable: u32,
    /// `Providers`: the components this one depends on, by index.
    pub providers: &'a [u32],
}

/// Whether the pinned kernel accepts a device described as
/// `components`, the driver having given the three component callbacks
/// (active condition, idle condition, idle state) or not;
/// `STATUS_INVALID_PARAMETER` otherwise.
///
/// A device has at least one component. A component has at least one
/// F-state; one with more needs the three callbacks and a deepest
/// wakeable state that is one of its states. A provider is a component
/// of the device, and a component has fewer providers than the device
/// has components. The counts, added up, fit in 32 bits.
pub fn registration(components: &[Described<'_>], three_callbacks: bool) -> bool {
    let Ok(count) = u32::try_from(components.len()) else {
        return false;
    };
    if count == 0 {
        return false;
    }
    let (mut states, mut providers) = (0u32, 0u32);
    for component in components {
        if component.idle_states == 0 {
            return false;
        }
        if component.idle_states > 1
            && (!three_callbacks || component.deepest_wakeable >= component.idle_states)
        {
            return false;
        }
        let Some(sum) = states.checked_add(component.idle_states) else {
            return false;
        };
        states = sum;
        let Ok(named) = u32::try_from(component.providers.len()) else {
            return false;
        };
        if named != 0 {
            if named >= count {
                return false;
            }
            let Some(sum) = providers.checked_add(named) else {
                return false;
            };
            providers = sum;
            if component
                .providers
                .iter()
                .any(|&provider| provider >= count)
            {
                return false;
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A component after `PoFxStartDevicePowerManagement` with no
    /// activation of the driver's: idle, the driver told and having
    /// completed.
    fn idle() -> Component {
        let mut component = Component::new();
        component.idle().unwrap();
        assert_eq!(component.owed(), Some(Tell::Idle));
        component.told_idle();
        component.idle_completed().unwrap();
        assert_eq!(component.settled(), Some(Condition::Idle));
        component
    }

    #[test]
    fn a_registered_component_is_active_with_one_activation() {
        let mut component = Component::new();
        assert_eq!(component.count(), 1);
        assert_eq!(component.settled(), Some(Condition::Active));
        assert!(component.at_rest());
        assert_eq!(component.owed(), None);
    }

    #[test]
    fn starting_power_management_with_the_driver_active_tells_nothing() {
        let mut component = Component::new();
        component.activate();
        // `PoFxStartDevicePowerManagement` gives up registration's.
        component.idle().unwrap();
        assert_eq!(component.owed(), None);
        assert_eq!(component.settled(), Some(Condition::Active));
    }

    #[test]
    fn the_last_idle_tells_the_driver_and_waits_for_it_to_complete() {
        let mut component = Component::new();
        component.idle().unwrap();
        assert_eq!(component.owed(), Some(Tell::Idle));
        // Under way: nothing more to tell, and not at rest.
        assert_eq!(component.owed(), None);
        assert_eq!(component.settled(), None);
        component.told_idle();
        assert_eq!(component.settled(), None);
        component.idle_completed().unwrap();
        assert_eq!(component.settled(), Some(Condition::Idle));
        assert!(component.at_rest());
        assert_eq!(component.owed(), None);
    }

    #[test]
    fn the_driver_may_complete_from_inside_its_callback() {
        let mut component = Component::new();
        component.idle().unwrap();
        assert_eq!(component.owed(), Some(Tell::Idle));
        component.idle_completed().unwrap();
        assert_eq!(component.settled(), None);
        component.told_idle();
        assert_eq!(component.settled(), Some(Condition::Idle));
    }

    #[test]
    fn the_first_activation_of_an_idle_component_tells_the_driver() {
        let mut component = idle();
        component.activate();
        assert!(!component.at_rest());
        assert_eq!(component.owed(), Some(Tell::Active));
        assert_eq!(component.owed(), None);
        assert!(!component.at_rest());
        // A second activation meanwhile tells nothing more.
        component.activate();
        assert_eq!(component.owed(), None);
        component.told_active();
        assert!(component.at_rest());
        assert_eq!(component.owed(), None);
        // Nor does giving one of the two up.
        component.idle().unwrap();
        assert_eq!(component.owed(), None);
        component.idle().unwrap();
        assert_eq!(component.owed(), Some(Tell::Idle));
    }

    #[test]
    fn an_activation_during_the_idle_transition_waits_for_it() {
        let mut component = Component::new();
        component.idle().unwrap();
        assert_eq!(component.owed(), Some(Tell::Idle));
        component.activate();
        assert_eq!(component.owed(), None);
        component.told_idle();
        assert_eq!(component.owed(), None);
        component.idle_completed().unwrap();
        // Idle for a moment, then told active.
        assert_eq!(component.settled(), Some(Condition::Idle));
        assert!(!component.at_rest());
        assert_eq!(component.owed(), Some(Tell::Active));
        component.told_active();
        assert!(component.at_rest());
    }

    #[test]
    fn an_idle_during_the_active_callback_waits_for_it() {
        let mut component = idle();
        component.activate();
        assert_eq!(component.owed(), Some(Tell::Active));
        component.idle().unwrap();
        assert_eq!(component.owed(), None);
        component.told_active();
        assert_eq!(component.owed(), Some(Tell::Idle));
    }

    #[test]
    fn an_activation_given_up_before_anything_was_told_tells_nothing() {
        let mut component = idle();
        component.activate();
        component.idle().unwrap();
        assert_eq!(component.owed(), None);
        assert!(component.at_rest());
    }

    #[test]
    fn idling_a_component_with_no_activation_is_an_error() {
        let mut component = idle();
        assert_eq!(component.idle(), Err(NotActivated));
        assert_eq!(component.count(), 0);
    }

    #[test]
    fn completing_an_idle_transition_that_is_not_waiting_is_an_error() {
        let mut component = Component::new();
        assert_eq!(component.idle_completed(), Err(NotIdling));
        component.idle().unwrap();
        assert_eq!(component.idle_completed(), Err(NotIdling));
        assert_eq!(component.owed(), Some(Tell::Idle));
        assert_eq!(component.idle_completed(), Ok(()));
        // Twice.
        assert_eq!(component.idle_completed(), Err(NotIdling));
        component.told_idle();
        assert_eq!(component.idle_completed(), Err(NotIdling));
    }

    fn one(idle_states: u32, deepest_wakeable: u32) -> Described<'static> {
        Described {
            idle_states,
            deepest_wakeable,
            providers: &[],
        }
    }

    #[test]
    fn a_device_needs_a_component_and_a_component_a_state() {
        assert!(!registration(&[], true));
        assert!(!registration(&[one(0, 0)], true));
        assert!(registration(&[one(1, 0)], false));
        assert!(registration(&[one(1, 0), one(1, 0)], true));
    }

    #[test]
    fn low_power_states_need_the_callbacks_and_a_wakeable_state_of_theirs() {
        assert!(registration(&[one(3, 2)], true));
        assert!(!registration(&[one(3, 2)], false));
        assert!(!registration(&[one(3, 3)], true));
        // With one state the deepest wakeable one is not looked at.
        assert!(registration(&[one(1, 7)], false));
    }

    #[test]
    fn providers_are_components_of_the_device_and_fewer_than_it_has() {
        let with = |providers: &'static [u32]| Described {
            idle_states: 1,
            deepest_wakeable: 0,
            providers,
        };
        assert!(registration(&[with(&[1]), one(1, 0)], false));
        assert!(!registration(&[with(&[2]), one(1, 0)], false));
        assert!(!registration(&[with(&[0, 1]), one(1, 0)], false));
        assert!(!registration(&[with(&[0])], false));
    }

    #[test]
    fn the_states_of_a_device_fit_in_32_bits() {
        assert!(!registration(&[one(u32::MAX, 0), one(1, 0)], true));
        assert!(registration(&[one(u32::MAX, 0)], true));
    }
}
