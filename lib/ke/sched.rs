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
    /// Its affinity no longer allows this processor: anything else runs
    /// here, and it is made ready on a processor it may run on.
    Move,
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
            Leaving::Exit | Leaving::Wait | Leaving::Move => 0,
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

    /// Whether the thread stops being runnable.
    pub const fn stops(self) -> bool {
        matches!(self, Leaving::Exit | Leaving::Wait)
    }

    /// Whether the thread cannot go on here: when no ready thread takes
    /// over, the processor's idle thread must.
    pub const fn vacates(self) -> bool {
        self.stops() || matches!(self, Leaving::Move)
    }

    /// Why a thread that called the dispatcher for `self` is leaving,
    /// given whether its affinity still `allows` the processor it is
    /// on. A thread that can go on, on a processor it may not run on,
    /// moves; the idle thread is its processor's and never does.
    pub const fn or_move(self, idle: bool, allows: bool) -> Leaving {
        if idle || allows || self.stops() {
            self
        } else {
            Leaving::Move
        }
    }

    /// Where a thread that stays runnable goes on its priority's queue:
    /// at the front (`true`) when it was pushed aside before its turn
    /// was over, so that it is next among its equals; otherwise at the
    /// back.
    pub const fn requeue_in_front(self, spent: bool) -> bool {
        matches!(self, Leaving::Preempt) && !spent
    }
}

/// The priority
/// [`KeSetPriorityThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesetprioritythread)
/// gives a thread whose base priority is `base` when asked for `new`,
/// or `None` if it leaves the thread as it is. As Windows 10 decides
/// it: priority 0 is the zero-page thread's, so a thread with a base
/// gets 1 instead; and a thread with a real-time base (16 and up) is
/// not taken below 16.
pub const fn priority_to_set(base: u8, new: u8) -> Option<u8> {
    let new = if new == 0 && base != 0 { 1 } else { new };
    if base >= 16 && new < 16 {
        None
    } else {
        Some(new)
    }
}

/// The affinity
/// [`KeSetSystemGroupAffinityThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesetsystemgroupaffinitythread)
/// gives the calling thread for a `GROUP_AFFINITY` of `mask`, `group`
/// and `reserved`, where the processors `online` run: those of the
/// mask that run. `None` if the routine leaves the affinity as it is:
/// a group other than 0, a reserved field not zero, or no running
/// processor in the mask.
pub fn system_affinity(mask: u64, group: u16, reserved: [u16; 3], online: u64) -> Option<u64> {
    (group == 0 && reserved == [0; 3] && mask & online != 0).then_some(mask & online)
}

/// What
/// [`KeRevertToUserGroupAffinityThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereverttousergroupaffinitythread)
/// does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Revert {
    /// Nothing.
    Nothing,
    /// The thread goes back to its own affinity and ideal processor,
    /// and is no longer in system affinity.
    ToUser,
    /// The thread stays in system affinity, with this one.
    To(u64),
}

/// What `KeRevertToUserGroupAffinityThread` does for a thread that is
/// (`active`) or is not in system affinity, given the `GROUP_AFFINITY`
/// its caller got from `KeSetSystemGroupAffinityThread`. As the pinned
/// kernel decides it: a mask of zero goes back to the thread's own
/// affinity, whatever the group; any other must be one
/// [`system_affinity`] takes.
pub fn revert_affinity(
    active: bool,
    mask: u64,
    group: u16,
    reserved: [u16; 3],
    online: u64,
) -> Revert {
    if !active || reserved != [0; 3] {
        Revert::Nothing
    } else if mask == 0 {
        Revert::ToUser
    } else {
        system_affinity(mask, group, reserved, online).map_or(Revert::Nothing, Revert::To)
    }
}

/// The ideal processor of a thread whose affinity becomes `affinity`
/// (not empty): the one it has, `ideal`, if the affinity allows it,
/// else the highest processor of the affinity, as on Windows.
pub fn ideal_within(affinity: u64, ideal: usize) -> usize {
    if ideal < 64 && affinity & 1 << ideal != 0 {
        ideal
    } else {
        63 - affinity.leading_zeros() as usize
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
    fn what_a_thread_is_set_to() {
        assert_eq!(priority_to_set(8, 9), Some(9));
        assert_eq!(priority_to_set(8, 31), Some(31));
        assert_eq!(
            priority_to_set(8, 0),
            Some(1),
            "0 is not for a thread with a base"
        );
        assert_eq!(priority_to_set(0, 0), Some(0));
        assert_eq!(
            priority_to_set(16, 15),
            None,
            "a real-time base stays real-time"
        );
        assert_eq!(priority_to_set(16, 0), None);
        assert_eq!(priority_to_set(16, 16), Some(16));
        assert_eq!(priority_to_set(24, 31), Some(31));
    }

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
    fn a_thread_its_processor_no_longer_allows_moves() {
        use super::Leaving::Move;
        for spent in [false, true] {
            // Anything runs in its place, the idle thread failing all.
            assert_eq!(Move.floor(false, spent, 31), 0);
        }
        assert!(Move.vacates() && !Move.stops());
        assert!(Exit.vacates() && Wait.vacates());
        assert!(!Yield.vacates() && !Preempt.vacates());
        // It keeps its turn as an interrupted thread does.
        assert!(!Move.new_turn(false) && Move.new_turn(true));
        assert!(!Move.requeue_in_front(false));
        for leaving in [Yield, Preempt] {
            assert_eq!(leaving.or_move(false, false), Move);
            assert_eq!(leaving.or_move(false, true), leaving);
            // The idle thread is its processor's.
            assert_eq!(leaving.or_move(true, false), leaving);
        }
        // A thread that stops is placed by its affinity when it is
        // next made ready.
        for leaving in [Exit, Wait] {
            assert_eq!(leaving.or_move(false, false), leaving);
        }
    }

    #[test]
    fn a_system_affinity_is_the_running_processors_of_group_0_named() {
        let none = [0; 3];
        assert_eq!(system_affinity(0b0110, 0, none, 0b1111), Some(0b0110));
        assert_eq!(system_affinity(0b1110, 0, none, 0b0011), Some(0b0010));
        assert_eq!(system_affinity(u64::MAX, 0, none, 1), Some(1));
        assert_eq!(system_affinity(0b1100, 0, none, 0b0011), None);
        assert_eq!(system_affinity(0, 0, none, 0b0011), None);
        assert_eq!(system_affinity(1, 1, none, 0b0011), None);
        for reserved in [[1, 0, 0], [0, 1, 0], [0, 0, 1]] {
            assert_eq!(system_affinity(1, 0, reserved, 0b0011), None);
        }
    }

    #[test]
    fn reverting_goes_back_to_the_threads_own_affinity_or_to_the_one_given() {
        let none = [0; 3];
        assert_eq!(revert_affinity(true, 0, 0, none, 0b11), Revert::ToUser);
        // The group of an empty mask is not looked at.
        assert_eq!(revert_affinity(true, 0, 7, none, 0b11), Revert::ToUser);
        assert_eq!(
            revert_affinity(true, 0b110, 0, none, 0b11),
            Revert::To(0b10)
        );
        assert_eq!(revert_affinity(true, 0b100, 0, none, 0b11), Revert::Nothing);
        assert_eq!(revert_affinity(true, 0b1, 1, none, 0b11), Revert::Nothing);
        assert_eq!(
            revert_affinity(true, 0, 0, [0, 0, 1], 0b11),
            Revert::Nothing
        );
        // Not in system affinity: nothing to go back from.
        assert_eq!(revert_affinity(false, 0, 0, none, 0b11), Revert::Nothing);
        assert_eq!(revert_affinity(false, 0b1, 0, none, 0b11), Revert::Nothing);
    }

    #[test]
    fn the_ideal_processor_stays_if_allowed_and_is_else_the_highest_allowed() {
        assert_eq!(ideal_within(0b1010, 1), 1);
        assert_eq!(ideal_within(0b1010, 3), 3);
        assert_eq!(ideal_within(0b1010, 0), 3);
        assert_eq!(ideal_within(0b0010, 2), 1);
        assert_eq!(ideal_within(1, 63), 0);
        assert_eq!(ideal_within(1 << 63, 0), 63);
        assert_eq!(ideal_within(u64::MAX, 63), 63);
        assert_eq!(ideal_within(1, 64), 0);
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
