//! The push lock (`EX_PUSH_LOCK`): a reader/writer lock in one word of
//! the driver's memory, free when the word is zero. Drivers initialise it
//! by zeroing it and never look inside; `FltAcquirePushLockExclusive` and
//! its siblings document the semantics:
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltacquirepushlockexclusive>
//!
//! # The word
//!
//! The bits are where Windows' public symbols put them: [`LOCKED`],
//! [`WAITING`], [`WAKING`], [`MULTIPLE_SHARED`], and the count of shared
//! holders from bit [`SHARE_SHIFT`] up. One exclusive holder is `LOCKED`
//! with a share count of zero; `n` shared holders are `LOCKED` with a
//! share count of `n`.
//!
//! The waiter linkage is NK's own. Windows chains wait blocks through
//! the word once `WAITING` is set, and moves the share count into the
//! chain. NK keeps the share count in the word always and keeps the
//! waiters in a queue of the kernel's, found by the lock's address and
//! guarded by a lock of its own (the queue lock). So NK never sets
//! `MULTIPLE_SHARED`, which describes Windows' chain.
//!
//! # The protocol
//!
//! Every function here maps the word as read to the word to store with a
//! compare-and-swap, and says what to do once the swap succeeded
//! ([`update`] is that loop).
//!
//! - **Acquire.** Try the transition. [`Acquire::Wait`] off the queue
//!   lock stores nothing: take the queue lock and try again there. A
//!   second `Wait` is stored (it sets `WAITING`), the thread joins the
//!   tail of the queue, drops the queue lock and sleeps. Woken, it starts
//!   over.
//! - **Release.** [`Release::Wake`] hands the releaser the duty to wake
//!   (`WAKING` is now set, so nobody else takes it): under the queue lock
//!   it removes the waiters [`wake`] names, stores [`end_wake`], and
//!   readies them after dropping the queue lock.
//!
//! `WAITING` is set exactly while the queue is not empty, both changing
//! only under the queue lock; a releaser that finds it clear has nobody
//! to wake.
//!
//! # Fairness
//!
//! Once anyone waits, a new shared acquirer does not join the shared
//! holders: it queues. So a stream of readers cannot starve a writer.
//! This is Windows' rule as its public behaviour shows it (ReactOS
//! implements the same one). Otherwise the lock is unfair, as on
//! Windows: a waiter is woken to try again, not handed the lock, and a
//! thread that arrives first may take it.
//!
//! When the lock comes free the oldest waiter is woken alone if it wants
//! exclusive access; if it wants shared access every waiter is woken,
//! and the exclusive ones among them queue again.

use core::sync::atomic::{AtomicU64, Ordering};

/// Held, by one exclusive holder or by the shared holders counted above.
pub const LOCKED: u64 = 1 << 0;
/// Threads wait in the kernel's queue for this lock.
pub const WAITING: u64 = 1 << 1;
/// A releaser is on its way to wake waiters.
pub const WAKING: u64 = 1 << 2;
/// Windows' mark for several shared holders with waiters. Never set.
pub const MULTIPLE_SHARED: u64 = 1 << 3;
/// The count of shared holders starts at this bit.
pub const SHARE_SHIFT: u32 = 4;

const ONE_SHARE: u64 = 1 << SHARE_SHIFT;

/// How many threads hold the lock shared.
pub const fn shared(word: u64) -> u64 {
    word >> SHARE_SHIFT
}

/// The kind of access wanted or held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Access {
    Exclusive,
    Shared,
}

/// What an acquirer does after its transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acquire {
    /// The lock is the caller's once the word is stored.
    Acquired,
    /// The lock cannot be had now. See the protocol: the word given with
    /// this is stored only under the queue lock.
    Wait,
}

/// Take the lock exclusively: possible only when nobody holds it.
pub const fn acquire_exclusive(word: u64) -> (u64, Acquire) {
    if word & LOCKED == 0 {
        (word | LOCKED, Acquire::Acquired)
    } else {
        (word | WAITING, Acquire::Wait)
    }
}

/// Take the lock shared: when nobody holds it, or when it is held shared
/// and nobody waits.
pub const fn acquire_shared(word: u64) -> (u64, Acquire) {
    if word & LOCKED == 0 {
        (word | LOCKED | ONE_SHARE, Acquire::Acquired)
    } else if shared(word) > 0 && word & WAITING == 0 {
        (word + ONE_SHARE, Acquire::Acquired)
    } else {
        (word | WAITING, Acquire::Wait)
    }
}

/// Take the lock exclusively if nobody holds it; never waits.
pub const fn try_acquire_exclusive(word: u64) -> Option<u64> {
    match acquire_exclusive(word) {
        (new, Acquire::Acquired) => Some(new),
        (_, Acquire::Wait) => None,
    }
}

/// Turn the caller's shared hold into an exclusive one. Only when it is
/// the sole holder and nobody waits: the one word Windows converts from.
pub const fn try_convert_shared_to_exclusive(word: u64) -> Option<u64> {
    if word == LOCKED | ONE_SHARE {
        Some(LOCKED)
    } else {
        None
    }
}

/// What a releaser does after its transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Release {
    /// Nothing more.
    Done,
    /// The lock came free with threads waiting: wake them (see the
    /// protocol).
    Wake,
}

/// A release of access the word says nobody holds: a driver bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotHeld;

/// The lock has just come free: does this releaser wake the waiters?
const fn freed(word: u64) -> (u64, Release) {
    if word & (WAITING | WAKING) == WAITING {
        (word | WAKING, Release::Wake)
    } else {
        (word, Release::Done)
    }
}

/// Give up an exclusive hold.
pub const fn release_exclusive(word: u64) -> Result<(u64, Release), NotHeld> {
    if word & LOCKED == 0 || shared(word) != 0 {
        return Err(NotHeld);
    }
    Ok(freed(word & !LOCKED))
}

/// Give up one shared hold. The lock comes free with the last.
pub const fn release_shared(word: u64) -> Result<(u64, Release), NotHeld> {
    if shared(word) == 0 {
        return Err(NotHeld);
    }
    let word = word - ONE_SHARE;
    if shared(word) > 0 {
        Ok((word, Release::Done))
    } else {
        Ok(freed(word & !LOCKED))
    }
}

/// Give up the caller's hold, whichever kind the word shows
/// (`ExReleasePushLockEx`).
pub const fn release(word: u64) -> Result<(u64, Release), NotHeld> {
    if shared(word) > 0 {
        release_shared(word)
    } else {
        release_exclusive(word)
    }
}

/// Whom a releaser with the duty to wake takes off the queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wake {
    /// The oldest waiter only.
    Oldest,
    /// Every waiter.
    All,
}

/// Whom to wake, given what the oldest waiter wants.
pub const fn wake(oldest: Access) -> Wake {
    match oldest {
        Access::Exclusive => Wake::Oldest,
        Access::Shared => Wake::All,
    }
}

/// The word once the waiters to wake are off the queue: the duty is
/// done, and `WAITING` stays only if the queue still holds somebody.
pub const fn end_wake(word: u64, waiters_left: bool) -> u64 {
    if waiters_left {
        word & !WAKING
    } else {
        word & !(WAKING | WAITING)
    }
}

/// Apply a transition to a lock word: read, compute, compare-and-swap,
/// again if the word moved meanwhile. Returns what the transition said
/// about the word that was finally replaced.
pub fn update<T>(lock: &AtomicU64, step: impl Fn(u64) -> (u64, T)) -> T {
    let mut old = lock.load(Ordering::Relaxed);
    loop {
        let (new, then) = step(old);
        match lock.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return then,
            Err(now) => old = now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::explore;

    const X: u64 = LOCKED;
    const S1: u64 = LOCKED | ONE_SHARE;
    const S2: u64 = LOCKED | (2 * ONE_SHARE);

    #[test]
    fn the_bits_are_where_the_symbols_put_them() {
        assert_eq!(
            (LOCKED, WAITING, WAKING, MULTIPLE_SHARED, SHARE_SHIFT),
            (1, 2, 4, 8, 4)
        );
        assert_eq!(shared(0x35), 3);
    }

    #[test]
    fn exclusive_needs_the_lock_free() {
        assert_eq!(acquire_exclusive(0), (X, Acquire::Acquired));
        // Free with waiters still queued: an arrival may take it.
        assert_eq!(acquire_exclusive(WAITING), (X | WAITING, Acquire::Acquired));
        assert_eq!(acquire_exclusive(X), (X | WAITING, Acquire::Wait));
        assert_eq!(acquire_exclusive(S2), (S2 | WAITING, Acquire::Wait));
        assert_eq!(try_acquire_exclusive(0), Some(X));
        assert_eq!(try_acquire_exclusive(X), None);
        assert_eq!(try_acquire_exclusive(S1), None);
    }

    #[test]
    fn shared_joins_holders_only_while_nobody_waits() {
        assert_eq!(acquire_shared(0), (S1, Acquire::Acquired));
        assert_eq!(acquire_shared(S1), (S2, Acquire::Acquired));
        assert_eq!(acquire_shared(X), (X | WAITING, Acquire::Wait));
        assert_eq!(acquire_shared(S1 | WAITING), (S1 | WAITING, Acquire::Wait));
        // Free, though others still queue: taken.
        assert_eq!(acquire_shared(WAITING), (S1 | WAITING, Acquire::Acquired));
    }

    #[test]
    fn conversion_needs_a_sole_holder_and_no_waiters() {
        assert_eq!(try_convert_shared_to_exclusive(S1), Some(X));
        for word in [0, X, S2, S1 | WAITING, S1 | WAITING | WAKING] {
            assert_eq!(try_convert_shared_to_exclusive(word), None, "{word:#x}");
        }
    }

    #[test]
    fn release_frees_the_lock_and_says_whether_to_wake() {
        assert_eq!(release_exclusive(X), Ok((0, Release::Done)));
        assert_eq!(
            release_exclusive(X | WAITING),
            Ok((WAITING | WAKING, Release::Wake))
        );
        // Somebody is already waking: one waker at a time.
        assert_eq!(
            release_exclusive(X | WAITING | WAKING),
            Ok((WAITING | WAKING, Release::Done))
        );
        assert_eq!(release_shared(S2), Ok((S1, Release::Done)));
        assert_eq!(
            release_shared(S2 | WAITING),
            Ok((S1 | WAITING, Release::Done))
        );
        assert_eq!(release_shared(S1), Ok((0, Release::Done)));
        assert_eq!(
            release_shared(S1 | WAITING),
            Ok((WAITING | WAKING, Release::Wake))
        );
        assert_eq!(release(X), release_exclusive(X));
        assert_eq!(release(S2), release_shared(S2));
    }

    #[test]
    fn releasing_what_is_not_held_is_refused() {
        for word in [0, WAITING, S1, S2 | WAITING] {
            assert_eq!(release_exclusive(word), Err(NotHeld), "{word:#x}");
        }
        for word in [0, WAITING, X, X | WAITING] {
            assert_eq!(release_shared(word), Err(NotHeld), "{word:#x}");
        }
        assert_eq!(release(0), Err(NotHeld));
        assert_eq!(release(WAITING | WAKING), Err(NotHeld));
    }

    #[test]
    fn waking_takes_one_writer_or_everybody() {
        assert_eq!(wake(Access::Exclusive), Wake::Oldest);
        assert_eq!(wake(Access::Shared), Wake::All);
        assert_eq!(end_wake(WAITING | WAKING, true), WAITING);
        assert_eq!(end_wake(WAITING | WAKING, false), 0);
        assert_eq!(end_wake(X | WAITING | WAKING, false), X);
        assert_eq!(end_wake(S2 | WAITING | WAKING, true), S2 | WAITING);
    }

    #[test]
    fn update_retries_until_its_swap_lands() {
        let lock = AtomicU64::new(0);
        assert_eq!(update(&lock, acquire_shared), Acquire::Acquired);
        assert_eq!(update(&lock, acquire_shared), Acquire::Acquired);
        assert_eq!(lock.load(Ordering::Relaxed), S2);
        assert_eq!(update(&lock, |w| release_shared(w).unwrap()), Release::Done);

        // Many threads counting themselves in and out lose no update.
        let lock = std::sync::Arc::new(AtomicU64::new(0));
        let threads: Vec<_> = (0..4)
            .map(|_| {
                let lock = lock.clone();
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        update(&lock, |w| (w + ONE_SHARE, ()));
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(shared(lock.load(Ordering::Relaxed)), 40_000);
    }

    // The model: a few threads, each running a script against one lock
    // and one queue.
    //
    // Each step below changes the word once. A step taken under the
    // queue lock also changes the queue; only steps under that lock look
    // at the queue, so the two changes are one as far as anybody can
    // tell, and the model may take the step whole.

    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    enum Op {
        Acquire(Access),
        TryExclusive,
        /// Shared to exclusive, if the thread holds shared.
        Convert,
        /// Give up what the thread holds, if anything, by the routine
        /// for that kind.
        Release,
        /// The same through `release`, which reads the kind off the word.
        ReleaseAny,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    enum Phase {
        /// About to start the next operation of its script.
        Ready,
        /// Refused off the queue lock; about to try again under it.
        Slow,
        /// In the queue until a waker takes it out.
        Asleep,
        /// Released with the duty to wake.
        Waking,
    }

    #[derive(Clone, PartialEq, Eq, Hash, Debug)]
    struct Thread {
        script: &'static [Op],
        at: usize,
        phase: Phase,
        holds: Option<Access>,
    }

    #[derive(Clone, PartialEq, Eq, Hash, Debug)]
    struct World {
        word: u64,
        queue: Vec<(usize, Access)>,
        threads: Vec<Thread>,
        /// A deliberately broken waiter, to show the checker can fail:
        /// it queues without setting `WAITING`.
        forgets_waiting: bool,
    }

    impl World {
        fn new(scripts: &[&'static [Op]]) -> Self {
            World {
                word: 0,
                queue: Vec::new(),
                threads: scripts
                    .iter()
                    .map(|&script| Thread {
                        script,
                        at: 0,
                        phase: Phase::Ready,
                        holds: None,
                    })
                    .collect(),
                forgets_waiting: false,
            }
        }

        fn finished(&self) -> bool {
            self.threads.iter().all(|t| t.at == t.script.len())
        }

        fn steps(&self) -> Vec<World> {
            (0..self.threads.len())
                .filter(|&i| {
                    let t = &self.threads[i];
                    t.at < t.script.len() && t.phase != Phase::Asleep
                })
                .map(|i| {
                    let mut next = self.clone();
                    next.step(i);
                    next.check();
                    next
                })
                .collect()
        }

        fn took(&mut self, i: usize, new: u64, access: Access) {
            let others = self.threads.iter().any(|t| t.holds.is_some());
            if access == Access::Shared && others {
                // The fairness rule: nobody joins shared holders while
                // anyone waits.
                assert!(self.queue.is_empty(), "joined past a waiter: {self:?}");
            }
            self.word = new;
            let t = &mut self.threads[i];
            t.holds = Some(access);
            t.phase = Phase::Ready;
            t.at += 1;
        }

        fn step(&mut self, i: usize) {
            let op = self.threads[i].script[self.threads[i].at];
            match (self.threads[i].phase, op) {
                (Phase::Ready, Op::Acquire(access)) => match acquire(access, self.word) {
                    (new, Acquire::Acquired) => self.took(i, new, access),
                    (_, Acquire::Wait) => self.threads[i].phase = Phase::Slow,
                },
                (Phase::Slow, Op::Acquire(access)) => match acquire(access, self.word) {
                    (new, Acquire::Acquired) => self.took(i, new, access),
                    (new, Acquire::Wait) => {
                        if !self.forgets_waiting {
                            self.word = new;
                        }
                        self.queue.push((i, access));
                        self.threads[i].phase = Phase::Asleep;
                    }
                },
                (Phase::Ready, Op::TryExclusive) => match try_acquire_exclusive(self.word) {
                    Some(new) => self.took(i, new, Access::Exclusive),
                    None => self.threads[i].at += 1,
                },
                (Phase::Ready, Op::Convert) => {
                    if self.threads[i].holds == Some(Access::Shared)
                        && let Some(new) = try_convert_shared_to_exclusive(self.word)
                    {
                        self.word = new;
                        self.threads[i].holds = Some(Access::Exclusive);
                    }
                    self.threads[i].at += 1;
                }
                (Phase::Ready, Op::Release | Op::ReleaseAny) => {
                    let Some(held) = self.threads[i].holds.take() else {
                        self.threads[i].at += 1;
                        return;
                    };
                    let (new, then) = match (op, held) {
                        (Op::ReleaseAny, _) => release(self.word),
                        (_, Access::Exclusive) => release_exclusive(self.word),
                        (_, Access::Shared) => release_shared(self.word),
                    }
                    .unwrap();
                    self.word = new;
                    match then {
                        Release::Done => self.threads[i].at += 1,
                        Release::Wake => self.threads[i].phase = Phase::Waking,
                    }
                }
                (Phase::Waking, _) => {
                    let count = match wake(self.queue[0].1) {
                        Wake::Oldest => 1,
                        Wake::All => self.queue.len(),
                    };
                    for (woken, _) in self.queue.drain(..count) {
                        self.threads[woken].phase = Phase::Ready;
                    }
                    self.word = end_wake(self.word, !self.queue.is_empty());
                    self.threads[i].phase = Phase::Ready;
                    self.threads[i].at += 1;
                }
                (phase, op) => unreachable!("{phase:?} {op:?}"),
            }
        }

        /// What must hold between any two steps.
        fn check(&self) {
            let holding = |access| {
                self.threads
                    .iter()
                    .filter(|t| t.holds == Some(access))
                    .count() as u64
            };
            let (writers, readers) = (holding(Access::Exclusive), holding(Access::Shared));
            // Mutual exclusion: one writer alone, or readers.
            assert!(writers <= 1 && (writers == 0 || readers == 0), "{self:?}");
            // The word tells the truth about the holders.
            assert_eq!(self.word & LOCKED != 0, writers + readers > 0, "{self:?}");
            assert_eq!(shared(self.word), readers, "{self:?}");
            assert_eq!(self.word & MULTIPLE_SHARED, 0);
            if self.forgets_waiting {
                return;
            }
            assert_eq!(self.word & WAITING != 0, !self.queue.is_empty(), "{self:?}");
            let wakers = self
                .threads
                .iter()
                .filter(|t| t.phase == Phase::Waking)
                .count();
            assert_eq!(usize::from(self.word & WAKING != 0), wakers, "{self:?}");
        }
    }

    fn acquire(access: Access, word: u64) -> (u64, Acquire) {
        match access {
            Access::Exclusive => acquire_exclusive(word),
            Access::Shared => acquire_shared(word),
        }
    }

    const SCRIPTS: &[&[Op]] = &[
        &[Op::Acquire(Access::Exclusive), Op::Release],
        &[Op::Acquire(Access::Shared), Op::Release],
        &[Op::Acquire(Access::Exclusive), Op::ReleaseAny],
        &[Op::Acquire(Access::Shared), Op::ReleaseAny],
        &[Op::TryExclusive, Op::Release],
        &[Op::Acquire(Access::Shared), Op::Convert, Op::Release],
        &[
            Op::Acquire(Access::Shared),
            Op::Release,
            Op::Acquire(Access::Exclusive),
            Op::Release,
        ],
        &[
            Op::Acquire(Access::Exclusive),
            Op::Release,
            Op::Acquire(Access::Shared),
            Op::Release,
        ],
    ];

    /// Run every interleaving of these scripts; every one must end with
    /// all scripts run out and the lock free.
    fn run(scripts: &[&'static [Op]]) -> usize {
        let (states, ends) = explore(World::new(scripts), World::steps, World::finished);
        // Every path ends in the one state where all is done: the lock
        // is free, nobody waits, nobody was left asleep.
        assert_eq!(ends, 1, "{scripts:?}");
        states
    }

    #[test]
    fn every_interleaving_of_three_threads_excludes_and_wakes() {
        let mut states = 0;
        for a in SCRIPTS {
            for b in SCRIPTS {
                for c in SCRIPTS {
                    states += run(&[a, b, c]);
                }
            }
        }
        // The check is not vacuous: it walked a real state space.
        assert!(states > 50_000, "{states}");
    }

    #[test]
    fn every_finished_world_is_free() {
        let scripts = [SCRIPTS[0], SCRIPTS[1], SCRIPTS[5]];
        let world = World::new(&scripts);
        explore(
            world,
            |w| {
                let next = w.steps();
                if next.is_empty() {
                    assert_eq!((w.word, w.queue.len()), (0, 0));
                }
                next
            },
            World::finished,
        );
    }

    #[test]
    fn a_writer_waiting_behind_readers_stops_new_readers() {
        // Reader 0 holds. Writer 1 queues. Reader 2 must queue behind
        // it, and get in only after the writer is woken.
        let scripts: [&'static [Op]; 3] = [SCRIPTS[1], SCRIPTS[0], SCRIPTS[1]];
        let mut w = World::new(&scripts);
        w.step(0);
        w.step(1);
        w.step(1);
        assert_eq!(w.threads[1].phase, Phase::Asleep);
        w.step(2);
        w.step(2);
        assert_eq!(w.threads[2].phase, Phase::Asleep);
        assert_eq!(w.word, S1 | WAITING);
        // The reader leaves: the writer, oldest, is woken alone.
        w.step(0);
        w.step(0);
        assert_eq!(w.threads[1].phase, Phase::Ready);
        assert_eq!(w.threads[2].phase, Phase::Asleep);
        assert_eq!(w.word, WAITING);
        w.step(1);
        assert_eq!(w.threads[1].holds, Some(Access::Exclusive));
        // The writer leaves: the reader is woken and gets in.
        w.step(1);
        w.step(1);
        w.step(2);
        assert_eq!(w.threads[2].holds, Some(Access::Shared));
        assert_eq!(w.word, S1);
    }

    #[test]
    #[should_panic(expected = "stuck with work left")]
    fn the_model_catches_a_lost_wake_up() {
        let scripts = [SCRIPTS[0], SCRIPTS[0]];
        let mut world = World::new(&scripts);
        world.forgets_waiting = true;
        explore(world, World::steps, World::finished);
    }
}
