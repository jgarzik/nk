//! The arithmetic of waits and of the objects waited on: when a time
//! limit or a timer falls due, what a semaphore's count may become, and
//! which lists of objects one wait may name.
//!
//! Times are in 100 ns units. Drivers give a due time as an `i64`:
//! negative is that long from now, anything else is a system time (since
//! 1601). Timer tables keep interrupt time (since boot).

/// The most objects one wait may name, as on Windows.
pub const MAXIMUM_WAIT_OBJECTS: usize = 64;

/// How many of a thread's built-in wait blocks are for objects.
pub const THREAD_WAIT_OBJECTS: usize = 3;

/// Whether one wait may name `count` objects: at most
/// [`MAXIMUM_WAIT_OBJECTS`], and more than a thread's own blocks hold
/// only if the caller brought wait blocks (`caller_blocks`).
pub const fn count_allowed(count: usize, caller_blocks: bool) -> bool {
    count <= MAXIMUM_WAIT_OBJECTS && (count <= THREAD_WAIT_OBJECTS || caller_blocks)
}

/// Whether a list names something twice. A wait for all of its objects
/// may not: one object can never be taken twice at once.
pub fn repeated<T: PartialEq>(items: &[T]) -> bool {
    (1..items.len()).any(|i| items[..i].contains(&items[i]))
}

/// A wait's time limit as a system time, given the limit the caller
/// passed and the system time now. Zero stays zero: do not wait at all.
/// The limit is fixed once, however often the wait has to look again.
pub const fn deadline(timeout: i64, system_time: u64) -> i64 {
    match timeout {
        0 => 0,
        relative if relative < 0 => (system_time + relative.unsigned_abs()) as i64,
        absolute => absolute,
    }
}

/// When a timer set with `due_time` falls due, in interrupt time, given
/// the interrupt time `now` and the system time at boot. A system time
/// before boot comes out as zero: already due.
pub const fn timer_due(due_time: i64, now: u64, boot_time: u64) -> u64 {
    if due_time < 0 {
        now.saturating_add(due_time.unsigned_abs())
    } else {
        (due_time as u64).saturating_sub(boot_time)
    }
}

/// A timer's period as stored: the milliseconds a driver passed, with
/// anything negative meaning none.
pub const fn period_ms(period: i32) -> u32 {
    if period < 0 { 0 } else { period as u32 }
}

/// When a periodic timer that was due at `due` falls due next: one
/// period later, but always after `now`. A timer whose expiry ran late
/// by more than a period fires once more, not once per period missed.
pub const fn next_period(due: u64, period_ms: u32, now: u64) -> u64 {
    let next = due + period_ms as u64 * 10_000;
    if next > now { next } else { now + 1 }
}

/// A semaphore's count after a release of `adjustment`, or `None` if the
/// release is not one Windows allows: it must raise the count, and not
/// past `limit`.
pub const fn semaphore_release(count: i32, adjustment: i32, limit: i32) -> Option<i32> {
    match count.checked_add(adjustment) {
        Some(raised) if raised > count && raised <= limit => Some(raised),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2024-01-01 as a system time: where a real clock stands.
    const NOW: u64 = 133_485_408_000_000_000;

    #[test]
    fn a_wait_names_at_most_64_objects_and_three_without_blocks() {
        for count in 0..=THREAD_WAIT_OBJECTS {
            assert!(count_allowed(count, false));
            assert!(count_allowed(count, true));
        }
        assert!(!count_allowed(4, false));
        assert!(count_allowed(4, true));
        assert!(count_allowed(64, true));
        assert!(!count_allowed(64, false));
        assert!(!count_allowed(65, true));
        assert!(!count_allowed(65, false));
        assert!(!count_allowed(usize::MAX, true));
    }

    #[test]
    fn a_repeated_object_is_found_wherever_it_is() {
        assert!(!repeated::<u32>(&[]));
        assert!(!repeated(&[1]));
        assert!(!repeated(&[1, 2, 3, 4]));
        assert!(repeated(&[1, 1]));
        assert!(repeated(&[1, 2, 2, 3]));
        assert!(repeated(&[1, 2, 3, 1]));
        assert!(repeated(&[5, 1, 2, 3, 4, 3]));
        let (a, b) = (1u8, 1u8);
        // Pointers compare by address, as the kernel's objects do.
        assert!(!repeated(&[&raw const a, &raw const b]));
        assert!(repeated(&[&raw const a, &raw const b, &raw const a]));
    }

    #[test]
    fn no_time_limit_at_all_stays_zero() {
        assert_eq!(deadline(0, NOW), 0);
        assert_eq!(deadline(0, 0), 0);
    }

    #[test]
    fn a_relative_limit_is_counted_from_now() {
        assert_eq!(deadline(-1, NOW), NOW as i64 + 1);
        assert_eq!(deadline(-10_000_000, NOW), NOW as i64 + 10_000_000);
        // Never mistaken for "do not wait", even with a clock at zero.
        assert_eq!(deadline(-1, 0), 1);
        // A year from now is still a positive system time.
        let year = 365 * 24 * 3600 * 10_000_000i64;
        assert_eq!(deadline(-year, NOW), NOW as i64 + year);
    }

    #[test]
    fn an_absolute_limit_is_kept_as_it_is() {
        assert_eq!(deadline(1, NOW), 1);
        assert_eq!(deadline(NOW as i64 + 5, NOW), NOW as i64 + 5);
        // In the past: it stays in the past, and the timer fires at once.
        assert_eq!(deadline(NOW as i64 - 5, NOW), NOW as i64 - 5);
        assert_eq!(deadline(i64::MAX, NOW), i64::MAX);
    }

    #[test]
    fn a_relative_timer_is_due_that_long_after_now() {
        assert_eq!(timer_due(-1, 1000, NOW), 1001);
        assert_eq!(timer_due(-156_250, 0, NOW), 156_250);
        // The boot time plays no part.
        assert_eq!(timer_due(-500, 1000, 0), 1500);
        // The farthest future there is, not a wrapped-round past.
        assert_eq!(timer_due(i64::MIN, u64::MAX - 5, NOW), u64::MAX);
        assert_eq!(timer_due(i64::MIN, 7, NOW), (1 << 63) + 7);
    }

    #[test]
    fn an_absolute_timer_is_due_at_that_system_time() {
        // Boot was at NOW; one second later in system time is one second
        // of interrupt time.
        assert_eq!(timer_due(NOW as i64 + 10_000_000, 123, NOW), 10_000_000);
        // The interrupt time now plays no part.
        assert_eq!(
            timer_due(NOW as i64 + 10_000_000, 99_999_999, NOW),
            10_000_000
        );
        // Before boot, or the zero a careless driver passes: due already.
        assert_eq!(timer_due(NOW as i64 - 1, 123, NOW), 0);
        assert_eq!(timer_due(0, 123, NOW), 0);
        assert_eq!(timer_due(NOW as i64, 123, NOW), 0);
        assert_eq!(timer_due(i64::MAX, 0, 0), i64::MAX as u64);
    }

    #[test]
    fn a_period_is_never_negative() {
        assert_eq!(period_ms(0), 0);
        assert_eq!(period_ms(1), 1);
        assert_eq!(period_ms(i32::MAX), i32::MAX as u32);
        assert_eq!(period_ms(-1), 0);
        assert_eq!(period_ms(i32::MIN), 0);
    }

    #[test]
    fn a_periodic_timer_keeps_its_rhythm_when_expiry_is_on_time() {
        // Due at 1 s, 10 ms period, expiry ran 2 ms late: the next is
        // counted from when it was due, not from when it was seen.
        let due = 10_000_000;
        assert_eq!(next_period(due, 10, due + 20_000), due + 100_000);
        assert_eq!(next_period(due, 10, due), due + 100_000);
        // A millisecond is 10,000 units.
        assert_eq!(next_period(0, 1, 0), 10_000);
    }

    #[test]
    fn a_periodic_timer_that_fell_behind_fires_once_not_in_a_burst() {
        let due = 10_000_000;
        // Seen five periods late: next is just after now.
        let now = due + 500_000;
        assert_eq!(next_period(due, 10, now), now + 1);
        // The boundary: a next time equal to now is already past.
        assert_eq!(next_period(due, 10, due + 100_000), due + 100_001);
        assert_eq!(next_period(due, 10, due + 99_999), due + 100_000);
        // A period of nothing still moves forward.
        assert_eq!(next_period(due, 0, due), due + 1);
    }

    #[test]
    fn a_semaphore_release_raises_the_count_up_to_the_limit() {
        assert_eq!(semaphore_release(0, 1, 1), Some(1));
        assert_eq!(semaphore_release(0, 5, 10), Some(5));
        assert_eq!(semaphore_release(3, 7, 10), Some(10));
        assert_eq!(semaphore_release(0, i32::MAX, i32::MAX), Some(i32::MAX));
    }

    #[test]
    fn a_semaphore_release_past_the_limit_is_refused() {
        assert_eq!(semaphore_release(1, 1, 1), None);
        assert_eq!(semaphore_release(3, 8, 10), None);
        assert_eq!(semaphore_release(10, 1, 10), None);
        // Past what the count can hold at all.
        assert_eq!(semaphore_release(i32::MAX, 1, i32::MAX), None);
        assert_eq!(semaphore_release(1, i32::MAX, i32::MAX), None);
    }

    #[test]
    fn a_semaphore_release_that_does_not_raise_the_count_is_refused() {
        assert_eq!(semaphore_release(5, 0, 10), None);
        assert_eq!(semaphore_release(5, -1, 10), None);
        assert_eq!(semaphore_release(0, i32::MIN, 10), None);
        assert_eq!(semaphore_release(-5, i32::MIN, 10), None);
    }
}
