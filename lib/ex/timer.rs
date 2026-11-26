//! Executive timers (`EX_TIMER`): what the arguments of `ExAllocateTimer`
//! and `ExSetTimer` mean.
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/exxxxtimer-routines-and-ex-timer-objects>
//!
//! An executive timer is a kernel timer the kernel allocates, with a
//! callback; setting, expiring and waiting are the kernel timer's. What
//! is decided here is which attribute bits make which timer, and what a
//! period in 100 ns units is to a kernel timer, which counts in
//! milliseconds.

/// `EX_TIMER_HIGH_RESOLUTION`, from `wdm.h`.
pub const HIGH_RESOLUTION: u32 = 4;
/// `EX_TIMER_NO_WAKE`.
pub const NO_WAKE: u32 = 8;
/// `EX_TIMER_NOTIFICATION`.
pub const NOTIFICATION: u32 = 1 << 31;

/// What kind of timer the attributes ask for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Kind {
    /// Stays signalled until set again; otherwise satisfying one wait
    /// resets it.
    pub notification: bool,
    /// Asked to expire closer to its time than the clock tick allows.
    pub high_resolution: bool,
}

/// Attributes `ExAllocateTimer` does not accept.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BadAttributes {
    /// High resolution and no-wake together: Windows stops the system.
    Conflict,
    /// A bit Windows does not define.
    Unknown,
}

/// The timer `ExAllocateTimer`'s attributes ask for.
pub const fn kind(attributes: u32) -> Result<Kind, BadAttributes> {
    if attributes & !(HIGH_RESOLUTION | NO_WAKE | NOTIFICATION) != 0 {
        return Err(BadAttributes::Unknown);
    }
    if attributes & HIGH_RESOLUTION != 0 && attributes & NO_WAKE != 0 {
        return Err(BadAttributes::Conflict);
    }
    Ok(Kind {
        notification: attributes & NOTIFICATION != 0,
        high_resolution: attributes & HIGH_RESOLUTION != 0,
    })
}

/// The most `ExSetTimer`'s period may be: `MAXLONG`, in 100 ns units.
pub const MAXIMUM_PERIOD: i64 = i32::MAX as i64;

/// A period `ExSetTimer` does not accept: negative, or over
/// [`MAXIMUM_PERIOD`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BadPeriod;

/// `ExSetTimer`'s period, in 100 ns units, as the milliseconds a kernel
/// timer repeats in; zero for a timer that fires once. A period that is
/// not a whole number of milliseconds is rounded up, so that the timer
/// never comes round early.
pub const fn period_ms(period: i64) -> Result<i32, BadPeriod> {
    if period < 0 || period > MAXIMUM_PERIOD {
        return Err(BadPeriod);
    }
    Ok(((period + 9_999) / 10_000) as i32)
}

/// Whether a timer of this kind may be set for `due_time`: a
/// high-resolution timer takes only a time relative to now, which is a
/// negative one.
pub const fn due_time_allowed(kind: Kind, due_time: i64) -> bool {
    !kind.high_resolution || due_time < 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_attribute_bits_are_the_headers() {
        assert_eq!(
            (HIGH_RESOLUTION, NO_WAKE, NOTIFICATION),
            (4, 8, 0x8000_0000)
        );
    }

    #[test]
    fn attributes_choose_the_kind_of_timer() {
        let plain = Kind {
            notification: false,
            high_resolution: false,
        };
        assert_eq!(kind(0), Ok(plain));
        assert_eq!(kind(NO_WAKE), Ok(plain));
        assert_eq!(
            kind(NOTIFICATION),
            Ok(Kind {
                notification: true,
                ..plain
            })
        );
        assert_eq!(
            kind(HIGH_RESOLUTION),
            Ok(Kind {
                high_resolution: true,
                ..plain
            })
        );
        // The notification bit goes with either of the others.
        for other in [HIGH_RESOLUTION, NO_WAKE] {
            assert!(kind(NOTIFICATION | other).unwrap().notification);
        }
    }

    #[test]
    fn bad_attributes_are_refused() {
        assert_eq!(
            kind(HIGH_RESOLUTION | NO_WAKE),
            Err(BadAttributes::Conflict)
        );
        assert_eq!(
            kind(HIGH_RESOLUTION | NO_WAKE | NOTIFICATION),
            Err(BadAttributes::Conflict)
        );
        for bit in [1, 2, 16, 1 << 30] {
            assert_eq!(kind(bit), Err(BadAttributes::Unknown), "{bit:#x}");
            assert_eq!(kind(bit | NOTIFICATION), Err(BadAttributes::Unknown));
        }
        // An unknown bit is noticed before a conflict.
        assert_eq!(
            kind(1 | HIGH_RESOLUTION | NO_WAKE),
            Err(BadAttributes::Unknown)
        );
    }

    #[test]
    fn a_period_becomes_whole_milliseconds_never_fewer() {
        assert_eq!(period_ms(0), Ok(0));
        assert_eq!(period_ms(1), Ok(1));
        assert_eq!(period_ms(9_999), Ok(1));
        assert_eq!(period_ms(10_000), Ok(1));
        assert_eq!(period_ms(10_001), Ok(2));
        assert_eq!(period_ms(100_000), Ok(10));
        assert_eq!(period_ms(156_250), Ok(16));
        assert_eq!(period_ms(MAXIMUM_PERIOD), Ok(214_749));
        for period in [0, 1, 5_000, 10_000, 123_456, MAXIMUM_PERIOD] {
            let ms = i64::from(period_ms(period).unwrap());
            assert!(ms * 10_000 >= period && (ms - 1) * 10_000 < period.max(1));
        }
    }

    #[test]
    fn a_period_out_of_range_is_refused() {
        for period in [-1, i64::MIN, MAXIMUM_PERIOD + 1, i64::MAX] {
            assert_eq!(period_ms(period), Err(BadPeriod), "{period}");
        }
    }

    #[test]
    fn a_high_resolution_timer_takes_only_relative_times() {
        let high = kind(HIGH_RESOLUTION).unwrap();
        let plain = kind(0).unwrap();
        assert!(due_time_allowed(high, -1));
        assert!(due_time_allowed(high, i64::MIN));
        assert!(!due_time_allowed(high, 0));
        assert!(!due_time_allowed(high, 132_000_000_000_000_000));
        for due_time in [-1, 0, 1, i64::MAX] {
            assert!(due_time_allowed(plain, due_time));
        }
    }
}
