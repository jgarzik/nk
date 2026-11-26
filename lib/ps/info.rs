//! Thread information: which classes
//! [`ZwSetInformationThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwsetinformationthread)
//! knows, and the arithmetic of priorities set through it.
//!
//! The facts are those of Windows 10 (19041 line), read from what the
//! routine does, class by class; Microsoft documents only some of the
//! classes
//! ([`THREADINFOCLASS`](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationthread)).

/// `ThreadPriority`: the thread's priority, a `KPRIORITY` (32 bits).
pub const THREAD_PRIORITY: u32 = 2;
/// `ThreadBasePriority`: the thread's base priority as a difference
/// from its process's, a `LONG`.
pub const THREAD_BASE_PRIORITY: u32 = 3;
/// `ThreadImpersonationToken`: a handle to the token the thread is to
/// impersonate, or null to stop.
pub const THREAD_IMPERSONATION_TOKEN: u32 = 5;

/// The highest class the routine looks at.
const LAST_CLASS: u32 = 0x32;

/// Classes below [`LAST_CLASS`] that can be queried but not set, or
/// that no longer mean anything.
const NEVER_SET: [u32; 18] = [
    0x0, 0x1, 0x6, 0x8, 0xB, 0xC, 0x10, 0x14, 0x15, 0x17, 0x1A, 0x1B, 0x1C, 0x23, 0x25, 0x28, 0x29,
    0x2D,
];

/// Whether Windows sets anything for information class `class`. A
/// class that it does not is `STATUS_INVALID_INFO_CLASS` before the
/// handle or the buffer is looked at.
pub const fn can_be_set(class: u32) -> bool {
    if class > LAST_CLASS {
        return false;
    }
    let mut i = 0;
    while i < NEVER_SET.len() {
        if NEVER_SET[i] == class {
            return false;
        }
        i += 1;
    }
    true
}

/// Whether `priority` is one `ThreadPriority` sets: 1 to 31. Checked
/// before the handle is looked at; one that is not is
/// `STATUS_INVALID_PARAMETER`.
pub const fn priority_allowed(priority: i32) -> bool {
    priority >= 1 && priority <= 31
}

/// Whether `increment` is a step `ThreadBasePriority` takes for a
/// thread of a process that is not in the real-time class: -2 to 2
/// (`THREAD_PRIORITY_LOWEST` to `THREAD_PRIORITY_HIGHEST`), and 16 and
/// -16, which stand for time-critical and idle. Checked after the
/// handle; a step that is not allowed is `STATUS_INVALID_PARAMETER`.
pub const fn base_increment_allowed(increment: i32) -> bool {
    matches!(increment, -16 | -2..=2 | 16)
}

/// A thread's priorities after its base priority is set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BaseChange {
    /// The new base priority.
    pub base: u8,
    /// The new priority.
    pub priority: u8,
    /// The new saturation: 1 after a time-critical step, -1 after an
    /// idle one, else 0.
    pub saturation: i8,
    /// The step the thread was at before: what the change returns.
    pub was: i32,
}

/// What `KeSetBasePriorityThread` makes of a thread at `priority` with
/// base priority `base` and saturation `saturation`, in a process whose
/// base priority is `process_base`, when its base is set to
/// `increment` away from the process's.
///
/// The new base is the process's plus the step, kept within 1 to 15.
/// A saturating step (16 or more either way) puts the thread at its new
/// base. Any other step moves the thread's priority by as much as its
/// base moved, counting from its base if it had sunk below, and keeps
/// it within 1 to 15: a priority set apart from the base
/// (`KeSetPriorityThread`) keeps its distance.
///
/// For a process whose base priority is below 16, which is every
/// process outside the real-time class.
pub const fn set_base_priority(
    process_base: u8,
    base: u8,
    priority: u8,
    saturation: i8,
    increment: i32,
) -> BaseChange {
    debug_assert!(process_base < 16);
    let was = if saturation != 0 {
        saturation as i32 * 16
    } else {
        base as i32 - process_base as i32
    };
    let new_saturation = if increment >= 16 {
        1
    } else if increment <= -16 {
        -1
    } else {
        0
    };
    let new_base = clamp(process_base as i32 + increment);
    let new_priority = if new_saturation != 0 {
        new_base
    } else {
        let from = if priority >= 16 || priority > base {
            priority
        } else {
            base
        };
        clamp(from as i32 + new_base as i32 - base as i32)
    };
    BaseChange {
        base: new_base,
        priority: new_priority,
        saturation: new_saturation,
        was,
    }
}

/// `value` kept within the priorities of a thread that is not
/// real-time.
const fn clamp(value: i32) -> u8 {
    if value >= 16 {
        15
    } else if value <= 0 {
        1
    } else {
        value as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_that_set_something() {
        for class in [THREAD_PRIORITY, THREAD_BASE_PRIORITY, 4, 7, 9, 0x32] {
            assert!(can_be_set(class), "class {class:#x}");
        }
        // The impersonation token is set by this routine too.
        assert!(can_be_set(THREAD_IMPERSONATION_TOKEN));
        for class in [0, 1, 6, 0x2D, 0x33, 0x7FFF, u32::MAX] {
            assert!(!can_be_set(class), "class {class:#x}");
        }
        assert_eq!(
            (0..=LAST_CLASS).filter(|&class| !can_be_set(class)).count(),
            NEVER_SET.len()
        );
    }

    #[test]
    fn priorities_and_steps_that_are_accepted() {
        assert!(!priority_allowed(0));
        assert!(priority_allowed(1) && priority_allowed(16) && priority_allowed(31));
        assert!(!priority_allowed(32) && !priority_allowed(-1));
        for step in [-16, -2, -1, 0, 1, 2, 16] {
            assert!(base_increment_allowed(step), "step {step}");
        }
        for step in [-17, -15, -3, 3, 15, 17, i32::MIN, i32::MAX] {
            assert!(!base_increment_allowed(step), "step {step}");
        }
    }

    fn change(base: u8, priority: u8, saturation: i8, increment: i32) -> (u8, u8, i8, i32) {
        let c = set_base_priority(8, base, priority, saturation, increment);
        (c.base, c.priority, c.saturation, c.was)
    }

    #[test]
    fn a_thread_at_its_base_follows_it() {
        assert_eq!(change(8, 8, 0, 1), (9, 9, 0, 0));
        assert_eq!(change(9, 9, 0, 0), (8, 8, 0, 1));
        assert_eq!(change(8, 8, 0, -2), (6, 6, 0, 0));
        assert_eq!(change(6, 6, 0, 2), (10, 10, 0, -2));
    }

    #[test]
    fn a_priority_set_apart_keeps_its_distance() {
        // Set to 9 over a base of 8, then the base goes up one: 10.
        assert_eq!(change(8, 9, 0, 1), (9, 10, 0, 0));
        // Set to 8 under a base of 9: counted from the base, 9, and
        // down one with it.
        assert_eq!(change(9, 8, 0, 0), (8, 8, 0, 1));
        // Kept within 1 to 15.
        assert_eq!(change(8, 15, 0, 2), (10, 15, 0, 0));
        assert_eq!(change(10, 1, 0, -2), (6, 6, 0, 2));
        // A thread taken into the real-time range comes back out.
        assert_eq!(change(8, 20, 0, 1), (9, 15, 0, 0));
    }

    #[test]
    fn saturating_steps_pin_the_thread() {
        assert_eq!(change(8, 9, 0, 16), (15, 15, 1, 0));
        assert_eq!(change(8, 9, 0, -16), (1, 1, -1, 0));
        // What it was at, while saturated: the saturating step.
        assert_eq!(change(15, 15, 1, 0), (8, 8, 0, 16));
        assert_eq!(change(1, 1, -1, 2), (10, 10, 0, -16));
    }

    #[test]
    fn the_base_stays_within_one_to_fifteen() {
        let high = set_base_priority(15, 15, 15, 0, 2);
        assert_eq!((high.base, high.priority), (15, 15));
        let low = set_base_priority(1, 1, 1, 0, -2);
        assert_eq!((low.base, low.priority), (1, 1));
    }
}
