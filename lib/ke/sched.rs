//! The dispatcher's decisions: who a thread gives way to, where it goes
//! back on the ready queue, and which processor a thread is made ready
//! on. The kernel supplies the facts (the thread's priority, which
//! processors are idle) and acts on the answers.

/// Why the running thread is calling the dispatcher.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Leaving {
    /// It can go on running; others at its priority or above go first.
    Yield,
    /// It has finished.
    Exit,
    /// It was interrupted: a thread of higher priority goes first, and
    /// if its quantum is spent so do its equals.
    Preempt,
    /// It waits for something, and runs again when made ready.
    Wait,
}

impl Leaving {
    /// The lowest priority a ready thread must have to take the
    /// processor from this one. `idle` says the thread is the
    /// processor's idle thread, `spent` that its quantum is used up, and
    /// `priority` is its own.
    ///
    /// The idle thread gives way to anything, as does a thread that
    /// cannot go on; a thread that yields or has had its quantum, to its
    /// equals and betters; one that was merely interrupted, to its
    /// betters only. The answer can be one more than the highest
    /// priority: nothing qualifies then.
    pub const fn floor(self, idle: bool, spent: bool, priority: u8) -> u8 {
        match self {
            Leaving::Exit | Leaving::Wait => 0,
            _ if idle => 0,
            Leaving::Preempt if !spent => priority + 1,
            _ => priority,
        }
    }

    /// Whether the thread's next run starts a fresh quantum: its last
    /// one is spent, or it gave the processor up of its own accord.
    pub const fn new_turn(self, spent: bool) -> bool {
        spent || matches!(self, Leaving::Yield | Leaving::Wait)
    }

    /// Whether the thread stops being runnable: when no ready thread
    /// takes over, the processor's idle thread must.
    pub const fn stops(self) -> bool {
        matches!(self, Leaving::Exit | Leaving::Wait)
    }

    /// Where a thread that stays runnable goes on its priority's queue:
    /// at the front (`true`) when it was pushed aside before its turn
    /// was over, so that it is next among its equals; otherwise at the
    /// back.
    pub const fn requeue_in_front(self, spent: bool) -> bool {
        matches!(self, Leaving::Preempt) && !spent
    }
}

/// The processors of a mask, lowest first.
fn processors(mask: u64) -> impl Iterator<Item = usize> {
    (0..64).filter(move |n| mask & 1 << n != 0)
}

/// The ideal processor of a new thread: threads are spread in turn over
/// the processors `allowed`, `turn` being a count of threads made so
/// far. `None` if no processor is allowed.
pub fn ideal_processor(allowed: u64, turn: u32) -> Option<usize> {
    let turn = turn.checked_rem(allowed.count_ones())?;
    processors(allowed).nth(turn as usize)
}

/// The processor a thread should be made ready on: its ideal processor
/// if that one is idle, else the lowest idle processor its affinity
/// (`allowed`) admits, else its ideal processor all the same.
pub fn place(allowed: u64, ideal: usize, idling: impl Fn(usize) -> bool) -> usize {
    if idling(ideal) {
        return ideal;
    }
    processors(allowed).find(|&n| idling(n)).unwrap_or(ideal)
}

/// The processor to wake so that it looks for work to take: the lowest
/// idle one among `allowed`, other than `me`.
pub fn idle_to_wake(allowed: u64, me: usize, idling: impl Fn(usize) -> bool) -> Option<usize> {
    processors(allowed).find(|&n| n != me && idling(n))
}

/// The order in which processor `me`, with nothing to run, looks at the
/// others' queues: each of the other `processors` once, starting with
/// the one after itself.
pub fn steal_order(me: usize, processors: usize) -> impl Iterator<Item = usize> {
    (1..processors).map(move |step| (me + step) % processors)
}

#[cfg(test)]
mod tests {
    use super::Leaving::{Exit, Preempt, Wait, Yield};
    use super::*;
    use crate::{ListEntry, ReadyQueues};

    #[test]
    fn a_thread_that_stops_gives_way_to_anything() {
        for leaving in [Exit, Wait] {
            for idle in [false, true] {
                for spent in [false, true] {
                    assert_eq!(leaving.floor(idle, spent, 31), 0);
                    assert_eq!(leaving.floor(idle, spent, 8), 0);
                }
            }
            assert!(leaving.stops());
        }
        assert!(!Yield.stops());
        assert!(!Preempt.stops());
    }

    #[test]
    fn the_idle_thread_gives_way_to_anything() {
        for leaving in [Yield, Preempt, Exit, Wait] {
            for spent in [false, true] {
                assert_eq!(leaving.floor(true, spent, 0), 0);
                // Whatever priority it is recorded with.
                assert_eq!(leaving.floor(true, spent, 15), 0);
            }
        }
    }

    #[test]
    fn a_yield_gives_way_to_equals_and_an_interruption_only_to_betters() {
        assert_eq!(Yield.floor(false, false, 8), 8);
        assert_eq!(Yield.floor(false, true, 8), 8);
        // Interrupted with quantum left: only a higher priority.
        assert_eq!(Preempt.floor(false, false, 8), 9);
        // Interrupted with the quantum spent: its equals too.
        assert_eq!(Preempt.floor(false, true, 8), 8);
        assert_eq!(Preempt.floor(false, false, 0), 1);
    }

    #[test]
    fn nothing_preempts_the_highest_priority_before_its_quantum_ends() {
        let floor = Preempt.floor(false, false, 31);
        assert_eq!(floor, 32);
        // The ready queues take that as "nobody": even a thread at 31.
        let mut queues = ReadyQueues::new();
        let mut link = ListEntry {
            next: core::ptr::null_mut(),
            prev: core::ptr::null_mut(),
        };
        // SAFETY: the link is a local that outlives the queue's use.
        unsafe {
            queues.insert(&raw mut link, 31, false);
            assert_eq!(queues.take(floor), None);
            assert_eq!(
                queues.take(Preempt.floor(false, true, 31)),
                Some((&raw mut link, 31))
            );
        }
    }

    #[test]
    fn a_new_turn_begins_when_the_quantum_is_spent_or_given_up() {
        assert!(Yield.new_turn(false));
        assert!(Wait.new_turn(false));
        assert!(!Preempt.new_turn(false));
        assert!(!Exit.new_turn(false));
        for leaving in [Yield, Exit, Preempt, Wait] {
            assert!(leaving.new_turn(true));
        }
    }

    #[test]
    fn only_a_thread_preempted_mid_turn_keeps_its_place() {
        assert!(Preempt.requeue_in_front(false));
        assert!(!Preempt.requeue_in_front(true));
        assert!(!Yield.requeue_in_front(false));
        assert!(!Yield.requeue_in_front(true));
        // A thread that keeps its place is also one that keeps its
        // quantum, and gave way only to a better.
        assert!(!Preempt.new_turn(false));
        assert_eq!(Preempt.floor(false, false, 8), 9);
    }

    #[test]
    fn ideal_processors_go_round_the_allowed_ones() {
        // Processors 1, 4 and 63.
        let allowed = 1 << 1 | 1 << 4 | 1 << 63;
        let turns: Vec<_> = (0..7).map(|t| ideal_processor(allowed, t)).collect();
        assert_eq!(
            turns,
            [1, 4, 63, 1, 4, 63, 1].map(Some),
            "each allowed processor in turn, and round again"
        );
        assert_eq!(ideal_processor(1 << 5, 0), Some(5));
        assert_eq!(ideal_processor(1 << 5, u32::MAX), Some(5));
        assert_eq!(ideal_processor(u64::MAX, 63), Some(63));
        assert_eq!(ideal_processor(u64::MAX, 64), Some(0));
        // The count may wrap; the turn is still an allowed processor.
        assert_eq!(ideal_processor(0b1011, u32::MAX), Some(0));
        assert_eq!(ideal_processor(0, 0), None);
        assert_eq!(ideal_processor(0, 7), None);
    }

    #[test]
    fn a_thread_goes_to_its_ideal_processor_when_that_is_idle() {
        let all_idle = |_| true;
        assert_eq!(place(0b1111, 2, all_idle), 2);
        // Even when a lower one is idle too.
        assert_eq!(place(0b1111, 3, |n| n == 0 || n == 3), 3);
    }

    #[test]
    fn a_thread_goes_to_an_idle_processor_it_is_allowed_on() {
        // Ideal 2 is busy; 1 and 3 are idle; the lowest allowed wins.
        assert_eq!(place(0b1111, 2, |n| n == 1 || n == 3), 1);
        // 1 is idle but not allowed.
        assert_eq!(place(0b1100, 2, |n| n == 1 || n == 3), 3);
        // Only processors outside the affinity are idle: stay put.
        assert_eq!(place(0b0100, 2, |n| n != 2), 2);
        // The highest processor is reachable.
        assert_eq!(place(1 << 63 | 1, 0, |n| n == 63), 63);
    }

    #[test]
    fn a_thread_goes_to_its_ideal_processor_when_nobody_is_idle() {
        assert_eq!(place(0b1111, 2, |_| false), 2);
        assert_eq!(place(u64::MAX, 63, |_| false), 63);
    }

    #[test]
    fn the_idle_processor_woken_is_allowed_idle_and_not_the_caller() {
        let idle = |n| n == 0 || n == 2 || n == 3;
        // Not the caller, though it is the lowest idle one.
        assert_eq!(idle_to_wake(0b1111, 0, idle), Some(2));
        assert_eq!(idle_to_wake(0b1111, 1, idle), Some(0));
        // Not one outside the affinity.
        assert_eq!(idle_to_wake(0b1010, 1, idle), Some(3));
        // Nobody else is idle, or allowed.
        assert_eq!(idle_to_wake(0b1111, 0, |n| n == 0), None);
        assert_eq!(idle_to_wake(0b0001, 0, |_| true), None);
        assert_eq!(idle_to_wake(0, 0, |_| true), None);
        assert_eq!(idle_to_wake(1 << 63, 0, |_| true), Some(63));
    }

    #[test]
    fn stealing_looks_at_every_other_processor_once() {
        assert_eq!(steal_order(0, 4).collect::<Vec<_>>(), [1, 2, 3]);
        assert_eq!(steal_order(2, 4).collect::<Vec<_>>(), [3, 0, 1]);
        assert_eq!(steal_order(3, 4).collect::<Vec<_>>(), [0, 1, 2]);
        assert_eq!(steal_order(1, 2).collect::<Vec<_>>(), [0]);
        // Alone, there is nobody to take from.
        assert_eq!(steal_order(0, 1).count(), 0);
        assert_eq!(steal_order(0, 0).count(), 0);
        for processors in 1..=64 {
            for me in 0..processors {
                let mut seen = 0u64;
                for other in steal_order(me, processors) {
                    assert!(other < processors && other != me);
                    assert_eq!(seen & 1 << other, 0, "looked at {other} twice");
                    seen |= 1 << other;
                }
                assert_eq!(seen.count_ones() as usize, processors - 1);
            }
        }
    }
}
