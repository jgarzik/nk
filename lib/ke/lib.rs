//! Kernel-core logic with no hardware behind it, so the host can test it:
//! the rules for IRQL changes and lock nesting, and the spin lock itself.
//!
//! The kernel wraps these with the per-processor state and the IRQL
//! register; see `kernel/ke`. `doc/LOCKING.md` states the rules.

#![cfg_attr(not(test), no_std)]

pub mod sched;

use core::sync::atomic::{AtomicU32, Ordering};

/// A rule broken. Each is a kernel bug; the kernel stops on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// Raising the IRQL to a level below the current one.
    RaiseBelow { current: u8, new: u8 },
    /// Lowering the IRQL to a level above the current one.
    LowerAbove { current: u8, new: u8 },
    /// Taking a lock this processor already holds.
    Recursive,
    /// Taking a lock whose rank is not above every lock already held.
    Order { held: u8, wanted: u8 },
    /// Releasing a lock this processor does not hold.
    NotHeld,
    /// Releasing a lock while one taken after it is still held.
    NotInnermost,
    /// More locks nested than the kernel ever means to.
    TooDeep,
}

/// May the IRQL go from `current` up to `new`?
pub fn check_raise(current: u8, new: u8) -> Result<(), Violation> {
    if new < current {
        return Err(Violation::RaiseBelow { current, new });
    }
    Ok(())
}

/// May the IRQL go from `current` down to `new`?
pub fn check_lower(current: u8, new: u8) -> Result<(), Violation> {
    if new > current {
        return Err(Violation::LowerAbove { current, new });
    }
    Ok(())
}

/// Most locks one processor may hold at once.
pub const MAX_HELD: usize = 8;

/// The locks one processor holds, innermost last. Locks are taken in
/// strictly rising rank and released in the reverse order.
#[derive(Debug)]
pub struct Held {
    /// `(identity, rank)` of each lock; the identity is its address.
    locks: [(usize, u8); MAX_HELD],
    depth: usize,
}

impl Held {
    pub const fn new() -> Self {
        Self {
            locks: [(0, 0); MAX_HELD],
            depth: 0,
        }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Record that the lock `id` of rank `rank` is about to be taken.
    pub fn acquire(&mut self, id: usize, rank: u8) -> Result<(), Violation> {
        let held = &self.locks[..self.depth];
        if held.iter().any(|&(other, _)| other == id) {
            return Err(Violation::Recursive);
        }
        if let Some(&(_, top)) = held.last()
            && rank <= top
        {
            return Err(Violation::Order {
                held: top,
                wanted: rank,
            });
        }
        if self.depth == MAX_HELD {
            return Err(Violation::TooDeep);
        }
        self.locks[self.depth] = (id, rank);
        self.depth += 1;
        Ok(())
    }

    /// Record that the lock `id` is being released.
    pub fn release(&mut self, id: usize) -> Result<(), Violation> {
        match self.locks[..self.depth]
            .iter()
            .rposition(|&(other, _)| other == id)
        {
            None => Err(Violation::NotHeld),
            Some(i) if i + 1 != self.depth => Err(Violation::NotInnermost),
            Some(_) => {
                self.depth -= 1;
                Ok(())
            }
        }
    }
}

/// A fair spin lock: waiters are served in the order they arrived.
///
/// Only the mutual exclusion is here. Raising the IRQL around it and
/// checking the nesting rules is the caller's part.
#[derive(Debug)]
pub struct TicketLock {
    /// The next ticket to hand out.
    next: AtomicU32,
    /// The ticket being served; the lock is free when it equals `next`.
    serving: AtomicU32,
}

impl TicketLock {
    pub const fn new() -> Self {
        Self {
            next: AtomicU32::new(0),
            serving: AtomicU32::new(0),
        }
    }

    /// Take the lock, spinning until this caller's turn.
    pub fn lock(&self) {
        let ticket = self.next.fetch_add(1, Ordering::Relaxed);
        while self.serving.load(Ordering::Acquire) != ticket {
            core::hint::spin_loop();
        }
    }

    /// Take the lock if it is free.
    pub fn try_lock(&self) -> bool {
        let serving = self.serving.load(Ordering::Relaxed);
        self.next
            .compare_exchange(
                serving,
                serving.wrapping_add(1),
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
    }

    /// Release the lock. Only its holder may call this.
    pub fn unlock(&self) {
        // Only the holder writes `serving`, so a plain add would do; the
        // atomic one costs nothing here.
        self.serving.fetch_add(1, Ordering::Release);
    }

    /// Take the lock whoever holds it. For the path that stops the
    /// system, where the holder will never run again.
    pub fn force(&self) {
        let serving = self.serving.load(Ordering::Relaxed);
        self.next.store(serving.wrapping_add(1), Ordering::Relaxed);
    }

    pub fn is_locked(&self) -> bool {
        self.next.load(Ordering::Relaxed) != self.serving.load(Ordering::Relaxed)
    }
}

/// A link in a singly linked list: Windows' `SINGLE_LIST_ENTRY`. It lives
/// inside the structure being queued, which a driver owns.
#[repr(C)]
#[derive(Debug)]
pub struct Link {
    pub next: *mut Link,
}

/// A first-in, first-out queue threaded through [`Link`]s embedded in the
/// queued structures. The queue owns no memory and is only ever touched
/// under its owner's lock.
#[derive(Debug)]
pub struct Fifo {
    head: *mut Link,
    tail: *mut Link,
}

// SAFETY: the queue is a pair of pointers; whoever holds the lock around
// it may use it from any processor.
unsafe impl Send for Fifo {}

impl Fifo {
    pub const fn new() -> Self {
        Self {
            head: core::ptr::null_mut(),
            tail: core::ptr::null_mut(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.head.is_null()
    }

    /// Add `link` at the back.
    ///
    /// # Safety
    /// `link` points to a writable `Link` that is in no queue and stays
    /// valid until it is popped or removed.
    pub unsafe fn push(&mut self, link: *mut Link) {
        // SAFETY: per the contract; `tail`, when set, is a link still in
        // the queue and so still valid.
        unsafe {
            (&raw mut (*link).next).write(core::ptr::null_mut());
            if self.tail.is_null() {
                self.head = link;
            } else {
                (&raw mut (*self.tail).next).write(link);
            }
        }
        self.tail = link;
    }

    /// Take the link at the front; null if the queue is empty.
    ///
    /// # Safety
    /// Every link in the queue is still valid.
    pub unsafe fn pop(&mut self) -> *mut Link {
        let link = self.head;
        if !link.is_null() {
            // SAFETY: per the contract.
            self.head = unsafe { (&raw const (*link).next).read() };
            if self.head.is_null() {
                self.tail = core::ptr::null_mut();
            }
        }
        link
    }

    /// Take `link` out, wherever it is. `false` if it is not in the
    /// queue.
    ///
    /// # Safety
    /// Every link in the queue is still valid.
    pub unsafe fn remove(&mut self, link: *mut Link) -> bool {
        let (mut before, mut at) = (core::ptr::null_mut::<Link>(), self.head);
        while !at.is_null() {
            // SAFETY: per the contract, `at` and `before` are valid.
            unsafe {
                let next = (&raw const (*at).next).read();
                if at == link {
                    if before.is_null() {
                        self.head = next;
                    } else {
                        (&raw mut (*before).next).write(next);
                    }
                    if self.tail == at {
                        self.tail = before;
                    }
                    return true;
                }
                (before, at) = (at, next);
            }
        }
        false
    }
}

/// A link in a doubly linked list: Windows' `LIST_ENTRY`, embedded in the
/// structure being listed. [`TimerBuckets`] ends its lists with null
/// rather than making them circular.
#[repr(C)]
#[derive(Debug)]
pub struct ListEntry {
    pub next: *mut ListEntry,
    pub prev: *mut ListEntry,
}

/// Where a thread stands with respect to waiting. One word, changed only
/// by compare-and-swap, decides every race between a thread going to
/// sleep and whatever would wake it:
///
/// - the thread `begin`s before any waker can find it;
/// - when it is ready to give up its processor it `commit`s, which fails
///   if a waker got there first, and then it does not sleep at all;
/// - a waker `claim`s the thread with the status the wait is to return.
///   Exactly one claim succeeds per wait, and it says whether the thread
///   had committed (it sleeps, or is about to: make it ready) or had not
///   (it will see the claim when it tries to commit: leave it alone).
#[derive(Debug)]
#[repr(transparent)]
pub struct WaitRegister(AtomicU32);

/// What a successful claim found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claimed {
    /// The thread had not yet given up its processor and now will not.
    /// It must not be made ready: it never stopped running.
    BeforeSleep,
    /// The thread is asleep or committed to it. The claimer must make it
    /// ready.
    Asleep,
}

impl WaitRegister {
    const IDLE: u32 = 0;
    const IN_PROGRESS: u32 = 1;
    const COMMITTED: u32 = 2;
    const WOKEN: u32 = 3;

    pub const fn new() -> Self {
        Self(AtomicU32::new(Self::IDLE))
    }

    /// The thread is about to become findable by wakers.
    pub fn begin(&self) {
        self.0.store(Self::IN_PROGRESS, Ordering::Release);
    }

    /// The thread gives up its processor. `false` if it was claimed
    /// first: it must go on running.
    pub fn commit(&self) -> bool {
        self.0
            .compare_exchange(
                Self::IN_PROGRESS,
                Self::COMMITTED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// End this thread's wait with `status`, if nothing else has. `None`
    /// if another waker won, or the thread is not waiting.
    pub fn claim(&self, status: u32) -> Option<Claimed> {
        debug_assert!(status < 1 << 30);
        let woken = Self::WOKEN | status << 2;
        for (from, found) in [
            (Self::IN_PROGRESS, Claimed::BeforeSleep),
            (Self::COMMITTED, Claimed::Asleep),
        ] {
            // The thread moves only forward, from in-progress to
            // committed, so trying in that order misses neither.
            if self
                .0
                .compare_exchange(from, woken, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(found);
            }
        }
        None
    }

    /// The status the wait was ended with, once it has been.
    pub fn status(&self) -> Option<u32> {
        let word = self.0.load(Ordering::Acquire);
        (word & 3 == Self::WOKEN).then_some(word >> 2)
    }

    /// The wait is over and cleaned up: wakers will find nothing.
    pub fn finish(&self) {
        self.0.store(Self::IDLE, Ordering::Release);
    }
}

/// Thread priorities run from 0 to 31, as on Windows.
pub const PRIORITIES: usize = 32;

/// One processor's threads that are ready to run: a queue per priority,
/// and a summary word with a bit for each queue that is not empty. The
/// links are inside the threads; the queues own no memory and are only
/// touched under their owner's lock.
#[derive(Debug)]
pub struct ReadyQueues {
    /// `(first, last)` of each priority's queue; null when empty.
    queues: [(*mut ListEntry, *mut ListEntry); PRIORITIES],
    summary: u32,
}

// SAFETY: the queues are pointers; whoever holds the lock around them
// may use them from any processor.
unsafe impl Send for ReadyQueues {}

impl ReadyQueues {
    pub const fn new() -> Self {
        Self {
            queues: [(core::ptr::null_mut(), core::ptr::null_mut()); PRIORITIES],
            summary: 0,
        }
    }

    /// The highest priority with a thread ready, if any is.
    pub fn highest(&self) -> Option<u8> {
        (self.summary != 0).then(|| 31 - self.summary.leading_zeros() as u8)
    }

    /// Queue `entry` at `priority`: at the back, behind threads already
    /// waiting their turn, or at the front when `front` (a thread that
    /// was preempted before its turn was over).
    ///
    /// # Safety
    /// `entry` is a writable link in no queue, valid until removed or
    /// taken; every queued link is valid. `priority` is below 32.
    pub unsafe fn insert(&mut self, entry: *mut ListEntry, priority: u8, front: bool) {
        let (head, tail) = self.queues[usize::from(priority)];
        // SAFETY: per the contract.
        unsafe {
            if front {
                entry.write(ListEntry {
                    next: head,
                    prev: core::ptr::null_mut(),
                });
                if head.is_null() {
                    self.queues[usize::from(priority)] = (entry, entry);
                } else {
                    (&raw mut (*head).prev).write(entry);
                    self.queues[usize::from(priority)].0 = entry;
                }
            } else {
                entry.write(ListEntry {
                    next: core::ptr::null_mut(),
                    prev: tail,
                });
                if tail.is_null() {
                    self.queues[usize::from(priority)] = (entry, entry);
                } else {
                    (&raw mut (*tail).next).write(entry);
                    self.queues[usize::from(priority)].1 = entry;
                }
            }
        }
        self.summary |= 1 << priority;
    }

    /// Take `entry`, queued at `priority`, out of its queue.
    ///
    /// # Safety
    /// As `insert`, except that `entry` is in the queue of `priority`.
    pub unsafe fn remove(&mut self, entry: *mut ListEntry, priority: u8) {
        let queue = &mut self.queues[usize::from(priority)];
        // SAFETY: per the contract.
        unsafe {
            let ListEntry { next, prev } = entry.read();
            if prev.is_null() {
                queue.0 = next;
            } else {
                (&raw mut (*prev).next).write(next);
            }
            if next.is_null() {
                queue.1 = prev;
            } else {
                (&raw mut (*next).prev).write(prev);
            }
        }
        if queue.0.is_null() {
            self.summary &= !(1 << priority);
        }
    }

    /// Take the first thread of the highest non-empty queue, if its
    /// priority is at least `floor`. Returns it with its priority.
    ///
    /// # Safety
    /// Every queued link is valid.
    pub unsafe fn take(&mut self, floor: u8) -> Option<(*mut ListEntry, u8)> {
        let priority = self.highest().filter(|&p| p >= floor)?;
        let entry = self.queues[usize::from(priority)].0;
        // SAFETY: per the contract; the summary bit says the queue is
        // not empty.
        unsafe { self.remove(entry, priority) };
        Some((entry, priority))
    }
}

/// How many clock ticks a thread runs before threads of its own priority
/// get a turn: two, as on Windows client systems.
pub const QUANTUM_TICKS: u8 = 2;

/// How many buckets a timer table has, as on Windows.
pub const TIMER_BUCKETS: usize = 256;

/// The bucket for a timer due at `due` (interrupt time, 100 ns units):
/// the clock tick it falls in, modulo the table size. Timers whose ticks
/// are a multiple of the table size apart share a bucket.
pub const fn timer_hand(due: u64) -> usize {
    (ticks_in(due) % TIMER_BUCKETS as u64) as usize
}

/// One processor's pending timers: a bucket per clock tick, each a list
/// in order of due time, earliest first. The table owns no memory; the
/// links are inside the timers. Touched only under its owner's lock.
///
/// Every method takes `due_of`, which reads a listed timer's due time
/// given its link, and those that change a bucket return the earliest
/// due time left in it (`u64::MAX` when empty), which the owner
/// publishes for the clock tick to read without the lock.
#[derive(Debug)]
pub struct TimerBuckets {
    heads: [*mut ListEntry; TIMER_BUCKETS],
}

// SAFETY: the table is an array of pointers; whoever holds the lock
// around it may use it from any processor.
unsafe impl Send for TimerBuckets {}

impl TimerBuckets {
    pub const fn new() -> Self {
        Self {
            heads: [core::ptr::null_mut(); TIMER_BUCKETS],
        }
    }

    /// The earliest due time in bucket `hand`.
    ///
    /// # Safety
    /// Every listed link is valid, and `due_of` may be called on it.
    unsafe fn earliest(&self, hand: usize, due_of: &impl Fn(*mut ListEntry) -> u64) -> u64 {
        match self.heads[hand] {
            head if head.is_null() => u64::MAX,
            head => due_of(head),
        }
    }

    /// List `entry`, whose due time is `due`. Among equal due times the
    /// earlier arrival stays ahead.
    ///
    /// # Safety
    /// `entry` is a writable link in no list, valid until removed or
    /// popped; every listed link is valid, and `due_of` may be called on
    /// any of them.
    pub unsafe fn insert(
        &mut self,
        entry: *mut ListEntry,
        due: u64,
        due_of: impl Fn(*mut ListEntry) -> u64,
    ) -> u64 {
        let hand = timer_hand(due);
        let (mut before, mut at) = (core::ptr::null_mut::<ListEntry>(), self.heads[hand]);
        // SAFETY: per the contract.
        unsafe {
            while !at.is_null() && due_of(at) <= due {
                (before, at) = (at, (&raw const (*at).next).read());
            }
            entry.write(ListEntry {
                next: at,
                prev: before,
            });
            if before.is_null() {
                self.heads[hand] = entry;
            } else {
                (&raw mut (*before).next).write(entry);
            }
            if !at.is_null() {
                (&raw mut (*at).prev).write(entry);
            }
            self.earliest(hand, &due_of)
        }
    }

    /// Unlist `entry`, which is listed with due time `due`.
    ///
    /// # Safety
    /// As `insert`, except that `entry` is in this table.
    pub unsafe fn remove(
        &mut self,
        entry: *mut ListEntry,
        due: u64,
        due_of: impl Fn(*mut ListEntry) -> u64,
    ) -> u64 {
        let hand = timer_hand(due);
        // SAFETY: per the contract.
        unsafe {
            let ListEntry { next, prev } = entry.read();
            if prev.is_null() {
                self.heads[hand] = next;
            } else {
                (&raw mut (*prev).next).write(next);
            }
            if !next.is_null() {
                (&raw mut (*next).prev).write(prev);
            }
            self.earliest(hand, &due_of)
        }
    }

    /// Unlist and return the first timer of bucket `hand` if it is due at
    /// `now`, with the earliest due time then left in the bucket. A timer
    /// is never returned before its time.
    ///
    /// # Safety
    /// As `insert`, without an `entry`.
    pub unsafe fn pop_due(
        &mut self,
        hand: usize,
        now: u64,
        due_of: impl Fn(*mut ListEntry) -> u64,
    ) -> Option<(*mut ListEntry, u64)> {
        let head = self.heads[hand];
        // SAFETY: per the contract.
        unsafe {
            if head.is_null() || due_of(head) > now {
                return None;
            }
            let next = (&raw const (*head).next).read();
            self.heads[hand] = next;
            if !next.is_null() {
                (&raw mut (*next).prev).write(core::ptr::null_mut());
            }
            Some((head, self.earliest(hand, &due_of)))
        }
    }
}

/// The buckets the clock must look at, given that it last looked during
/// tick `checked` and it is now tick `now`: every tick from `checked` to
/// `now`, both included (a timer set after the last look may be due
/// within that same tick), but each bucket once.
pub fn hands_to_check(checked: u64, now: u64) -> impl Iterator<Item = usize> {
    let span = now.saturating_sub(checked).min(TIMER_BUCKETS as u64 - 1);
    (now - span..=now).map(|tick| (tick % TIMER_BUCKETS as u64) as usize)
}

/// How long one deferred procedure call may run before the system stops
/// (`DPC_WATCHDOG_VIOLATION`), in clock ticks: 20 s, as on Windows 10.
pub const DPC_TIME_LIMIT_TICKS: u64 = 1280;

/// The clock tick, in 100 ns units: 15.625 ms, Windows' default, which is
/// what `KeQueryTimeIncrement` reports.
pub const TIME_INCREMENT: u64 = 156_250;

/// A count of a counter running at `frequency` ticks per second, in the
/// 100 ns units Windows measures time in. Exact for any count: the
/// product is taken in 128 bits.
pub const fn counter_to_time(count: u64, frequency: u64) -> u64 {
    (count as u128 * 10_000_000 / frequency as u128) as u64
}

/// Counter ticks in `micros` microseconds, rounded up: a wait must never
/// come out short.
pub const fn micros_to_counter(micros: u64, frequency: u64) -> u64 {
    (micros as u128 * frequency as u128).div_ceil(1_000_000) as u64
}

/// How many clock ticks fit in `time` (100 ns units since boot).
pub const fn ticks_in(time: u64) -> u64 {
    time / TIME_INCREMENT
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::UnsafeCell;
    use std::sync::Arc;

    /// A stand-in for a timer: its due time beside its link.
    #[repr(C)]
    struct FakeTimer {
        link: ListEntry,
        due: u64,
    }

    fn due_of(link: *mut ListEntry) -> u64 {
        // SAFETY: the link is the first field of a live `FakeTimer`.
        unsafe { (*link.cast::<FakeTimer>()).due }
    }

    fn timers(dues: &[u64]) -> Vec<FakeTimer> {
        dues.iter()
            .map(|&due| FakeTimer {
                link: ListEntry {
                    next: core::ptr::dangling_mut(),
                    prev: core::ptr::dangling_mut(),
                },
                due,
            })
            .collect()
    }

    /// One wait, seen from outside: the register, and what the model's
    /// actors did around it.
    struct WaitModel {
        register: WaitRegister,
        /// The waiter is off its processor.
        asleep: bool,
        /// Times the waiter was made ready, and whether any of them came
        /// while it was still on its processor (the bug the register
        /// exists to prevent).
        readied: u32,
        readied_while_running: bool,
        /// Claims that succeeded.
        won: u32,
        /// The waiter went on without sleeping.
        went_on: bool,
        woke: bool,
    }

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Step {
        Begin,
        /// Commit; on success the waiter is committed but still on its
        /// processor until `SwitchOut`.
        Commit,
        SwitchOut,
        /// A waker claims, with its own status, and readies the thread
        /// if told to.
        Wake(u32),
    }

    impl WaitModel {
        fn apply(&mut self, step: Step, committed: &mut bool) {
            match step {
                Step::Begin => self.register.begin(),
                Step::Commit => {
                    *committed = self.register.commit();
                    self.went_on = !*committed;
                }
                Step::SwitchOut => {
                    if *committed {
                        self.asleep = true;
                        // Whoever readied it before now did so while it
                        // was committed: that is allowed (`swap_busy`
                        // makes the processor that takes it wait).
                        if self.readied > 0 {
                            self.woke = true;
                        }
                    }
                }
                Step::Wake(status) => match self.register.claim(status) {
                    Some(Claimed::Asleep) => {
                        self.won += 1;
                        self.readied += 1;
                        if !*committed {
                            self.readied_while_running = true;
                        }
                        if self.asleep {
                            self.woke = true;
                        }
                    }
                    Some(Claimed::BeforeSleep) => self.won += 1,
                    None => {}
                },
            }
        }
    }

    /// Every way of interleaving the actors' steps, each actor's own
    /// steps staying in order.
    fn interleavings(
        actors: &[&[Step]],
        prefix: &mut Vec<Step>,
        at: &mut Vec<usize>,
        out: &mut Vec<Vec<Step>>,
    ) {
        let mut done = true;
        for a in 0..actors.len() {
            if at[a] < actors[a].len() {
                done = false;
                prefix.push(actors[a][at[a]]);
                at[a] += 1;
                interleavings(actors, prefix, at, out);
                at[a] -= 1;
                prefix.pop();
            }
        }
        if done {
            out.push(prefix.clone());
        }
    }

    #[test]
    fn a_wait_is_ended_exactly_once_in_every_interleaving() {
        let waiter = [Step::Begin, Step::Commit, Step::SwitchOut];
        let (first, second, third) = ([Step::Wake(7)], [Step::Wake(8)], [Step::Wake(9)]);
        for wakers in 0..=3 {
            let mut actors: Vec<&[Step]> = vec![&waiter];
            actors.extend(
                [&first[..], &second[..], &third[..]]
                    .into_iter()
                    .take(wakers),
            );
            let mut orders = Vec::new();
            interleavings(
                &actors,
                &mut Vec::new(),
                &mut vec![0; actors.len()],
                &mut orders,
            );
            // 3 steps and n single steps: (3 + n)! / 3! orders.
            assert_eq!(orders.len(), [1, 4, 20, 120][wakers]);
            for order in orders {
                let mut m = WaitModel {
                    register: WaitRegister::new(),
                    asleep: false,
                    readied: 0,
                    readied_while_running: false,
                    won: 0,
                    went_on: false,
                    woke: false,
                };
                let mut committed = false;
                for &step in &order {
                    m.apply(step, &mut committed);
                }
                let begun_at = order.iter().position(|&s| s == Step::Begin).unwrap();
                let wakes_after_begin = order[begun_at..]
                    .iter()
                    .filter(|s| matches!(s, Step::Wake(_)))
                    .count();
                let context = format!("{order:?}");
                // A wake before the wait began finds nothing; any wake
                // after it ends the wait, and exactly one does.
                assert_eq!(m.won, u32::from(wakes_after_begin > 0), "{context}");
                assert!(!m.readied_while_running, "{context}");
                assert!(m.readied <= 1, "{context}");
                if m.went_on {
                    // Claimed before it slept: never readied, and it
                    // knows why it did not sleep.
                    assert_eq!((m.readied, m.asleep), (0, false), "{context}");
                    assert!(matches!(m.register.status(), Some(7..=9)), "{context}");
                } else if wakes_after_begin > 0 {
                    // It slept, and was woken: no wake was lost.
                    assert!(m.asleep && m.woke && m.readied == 1, "{context}");
                    assert!(matches!(m.register.status(), Some(7..=9)), "{context}");
                } else {
                    // It sleeps, and nothing has tried to wake it.
                    assert!(m.asleep && m.register.status().is_none(), "{context}");
                }
                // The status is the winner's, whole.
                m.register.finish();
                assert_eq!(m.register.status(), None);
                assert_eq!(m.register.claim(1), None, "finished: nothing to claim");
            }
        }
    }

    #[test]
    fn a_wait_register_carries_any_status() {
        let r = WaitRegister::new();
        assert_eq!((r.claim(5), r.status()), (None, None));
        assert!(!r.commit(), "nothing to commit before a wait begins");
        r.begin();
        assert_eq!(r.status(), None);
        assert_eq!(r.claim(0x102), Some(Claimed::BeforeSleep));
        assert_eq!(r.status(), Some(0x102));
        assert!(!r.commit());
        r.finish();
        r.begin();
        assert!(r.commit());
        assert_eq!(r.claim(0), Some(Claimed::Asleep));
        assert_eq!(r.status(), Some(0));
        assert_eq!(r.claim(0xC0), None);
    }

    fn entries(n: usize) -> Vec<ListEntry> {
        (0..n)
            .map(|_| ListEntry {
                next: core::ptr::dangling_mut(),
                prev: core::ptr::dangling_mut(),
            })
            .collect()
    }

    #[test]
    fn ready_queues_serve_the_highest_priority_in_turn() {
        let mut nodes = entries(6);
        let p: Vec<*mut ListEntry> = nodes.iter_mut().map(core::ptr::from_mut).collect();
        let mut ready = ReadyQueues::new();
        // SAFETY: the nodes outlive the queues' use of them.
        unsafe {
            assert_eq!((ready.highest(), ready.take(0)), (None, None));
            ready.insert(p[0], 8, false);
            ready.insert(p[1], 8, false);
            ready.insert(p[2], 31, false);
            ready.insert(p[3], 0, false);
            ready.insert(p[4], 8, true);
            assert_eq!(ready.highest(), Some(31));
            assert_eq!(ready.take(0), Some((p[2], 31)));
            // At the front goes first; the rest in order of arrival.
            assert_eq!(ready.take(0), Some((p[4], 8)));
            assert_eq!(ready.take(0), Some((p[0], 8)));
            // Nothing at or above the floor: left alone.
            assert_eq!(ready.take(9), None);
            assert_eq!(ready.take(8), Some((p[1], 8)));
            assert_eq!(ready.highest(), Some(0));
            assert_eq!(ready.take(1), None);
            assert_eq!(ready.take(0), Some((p[3], 0)));
            assert_eq!((ready.highest(), ready.take(0)), (None, None));
            // To the front of an empty queue, then behind it.
            ready.insert(p[5], 4, true);
            ready.insert(p[0], 4, false);
            assert_eq!(ready.take(0), Some((p[5], 4)));
            assert_eq!(ready.take(0), Some((p[0], 4)));
        }
    }

    #[test]
    fn ready_queues_give_up_a_thread_from_any_place() {
        for victim in 0..3 {
            let mut nodes = entries(4);
            let p: Vec<*mut ListEntry> = nodes.iter_mut().map(core::ptr::from_mut).collect();
            let mut ready = ReadyQueues::new();
            // SAFETY: as above.
            unsafe {
                for &entry in &p[..3] {
                    ready.insert(entry, 12, false);
                }
                ready.insert(p[3], 3, false);
                ready.remove(p[victim], 12);
                assert_eq!(ready.highest(), Some(12));
                for i in (0..3).filter(|&i| i != victim) {
                    assert_eq!(ready.take(0), Some((p[i], 12)));
                }
                // The queue emptied by taking: its summary bit is gone.
                assert_eq!(ready.highest(), Some(3));
                ready.remove(p[3], 3);
                assert_eq!(ready.highest(), None);
                // Emptied by removal, a queue is whole again.
                ready.insert(p[victim], 12, true);
                ready.insert(p[3], 12, false);
                assert_eq!(ready.take(0), Some((p[victim], 12)));
                assert_eq!(ready.take(0), Some((p[3], 12)));
            }
        }
    }

    const T: u64 = TIME_INCREMENT;
    /// One turn of the table.
    const TURN: u64 = TIMER_BUCKETS as u64 * T;

    #[test]
    fn timer_hands() {
        assert_eq!(timer_hand(0), 0);
        assert_eq!(timer_hand(T - 1), 0);
        assert_eq!(timer_hand(T), 1);
        assert_eq!(timer_hand(255 * T), 255);
        assert_eq!(timer_hand(TURN), 0);
        assert_eq!(timer_hand(TURN + 3 * T + 5), 3);
    }

    #[test]
    fn timers_come_out_in_due_order_and_never_early() {
        // All in bucket 5: two in the same tick, one a turn later, one
        // equal to another.
        let dues = [5 * T + 900, 5 * T + 100, TURN + 5 * T, 5 * T + 100];
        let mut nodes = timers(&dues);
        let p: Vec<*mut ListEntry> = nodes.iter_mut().map(|n| &raw mut n.link).collect();
        let mut table = TimerBuckets::new();
        // SAFETY: the nodes outlive the table's use of them.
        unsafe {
            assert_eq!(table.insert(p[0], dues[0], due_of), 5 * T + 900);
            assert_eq!(table.insert(p[1], dues[1], due_of), 5 * T + 100);
            assert_eq!(table.insert(p[2], dues[2], due_of), 5 * T + 100);
            assert_eq!(table.insert(p[3], dues[3], due_of), 5 * T + 100);
            // Not yet due, and nothing in other buckets.
            assert_eq!(table.pop_due(5, 5 * T + 99, due_of), None);
            assert_eq!(table.pop_due(6, u64::MAX, due_of), None);
            // Equal due times: first come, first served.
            assert_eq!(
                table.pop_due(5, 5 * T + 100, due_of),
                Some((p[1], 5 * T + 100))
            );
            assert_eq!(
                table.pop_due(5, 5 * T + 100, due_of),
                Some((p[3], 5 * T + 900))
            );
            assert_eq!(table.pop_due(5, 5 * T + 100, due_of), None);
            assert_eq!(table.pop_due(5, 6 * T, due_of), Some((p[0], TURN + 5 * T)));
            // The one a turn later shares the bucket but is not due.
            assert_eq!(table.pop_due(5, 6 * T, due_of), None);
            assert_eq!(
                table.pop_due(5, TURN + 5 * T, due_of),
                Some((p[2], u64::MAX))
            );
            assert_eq!(table.pop_due(5, u64::MAX, due_of), None);
        }
    }

    #[test]
    fn timers_can_be_removed_from_any_position() {
        let dues = [7 * T + 1, 7 * T + 2, 7 * T + 3];
        for victim in 0..3 {
            let mut nodes = timers(&dues);
            let p: Vec<*mut ListEntry> = nodes.iter_mut().map(|n| &raw mut n.link).collect();
            let mut table = TimerBuckets::new();
            // SAFETY: as above.
            unsafe {
                // Inserted out of order.
                for i in [2, 0, 1] {
                    table.insert(p[i], dues[i], due_of);
                }
                let left: Vec<usize> = (0..3).filter(|&i| i != victim).collect();
                assert_eq!(table.remove(p[victim], dues[victim], due_of), dues[left[0]]);
                assert_eq!(
                    table.pop_due(7, u64::MAX, due_of),
                    Some((p[left[0]], dues[left[1]]))
                );
                // Removing the last one empties the bucket.
                assert_eq!(table.remove(p[left[1]], dues[left[1]], due_of), u64::MAX);
                assert_eq!(table.pop_due(7, u64::MAX, due_of), None);
                // And the bucket is usable again.
                assert_eq!(table.insert(p[victim], dues[victim], due_of), dues[victim]);
            }
        }
    }

    #[test]
    fn the_clock_checks_each_bucket_it_must_and_once() {
        let hands = |checked, now| hands_to_check(checked, now).collect::<Vec<_>>();
        // The tick last looked at is looked at again.
        assert_eq!(hands(10, 10), [10]);
        assert_eq!(hands(10, 11), [10, 11]);
        assert_eq!(hands(10, 13), [10, 11, 12, 13]);
        // Across the end of the table.
        assert_eq!(hands(254, 257), [254, 255, 0, 1]);
        // A long gap: every bucket, each once, ending at now's.
        let all = hands(0, 1000);
        assert_eq!(all.len(), TIMER_BUCKETS);
        assert_eq!(all.last(), Some(&(1000 % TIMER_BUCKETS)));
        let mut sorted = all.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), TIMER_BUCKETS);
        // Exactly a turn apart is already "every bucket".
        assert_eq!(hands(0, 255).len(), 256);
        assert_eq!(hands(0, 256).len(), 256);
        // The clock never runs backwards, but a stale `checked` must not
        // underflow.
        assert_eq!(hands(11, 10), [10]);
    }

    fn links(n: usize) -> Vec<Link> {
        (0..n)
            .map(|_| Link {
                // Stale on purpose: push must not trust it.
                next: core::ptr::dangling_mut(),
            })
            .collect()
    }

    #[test]
    fn fifo_serves_in_order() {
        let mut nodes = links(3);
        let p: Vec<*mut Link> = nodes.iter_mut().map(core::ptr::from_mut).collect();
        let mut q = Fifo::new();
        // SAFETY: the nodes outlive the queue's use of them.
        unsafe {
            assert!(q.is_empty() && q.pop().is_null());
            for &link in &p {
                q.push(link);
            }
            assert!(!q.is_empty());
            assert_eq!([q.pop(), q.pop(), q.pop()], [p[0], p[1], p[2]]);
            assert!(q.is_empty() && q.pop().is_null());
            // Empty again: usable again.
            q.push(p[1]);
            q.push(p[0]);
            assert_eq!(
                [q.pop(), q.pop(), q.pop()],
                [p[1], p[0], core::ptr::null_mut()]
            );
        }
    }

    #[test]
    fn fifo_removes_from_any_position() {
        for victim in 0..3 {
            let mut nodes = links(4);
            let p: Vec<*mut Link> = nodes.iter_mut().map(core::ptr::from_mut).collect();
            let mut q = Fifo::new();
            // SAFETY: as above.
            unsafe {
                for &link in &p[..3] {
                    q.push(link);
                }
                assert!(!q.remove(p[3]), "not in the queue");
                assert!(q.remove(p[victim]));
                assert!(!q.remove(p[victim]), "already out");
                // The tail is still right: a push lands at the back.
                q.push(p[3]);
                let mut left: Vec<*mut Link> = p[..3].to_vec();
                left.remove(victim);
                left.push(p[3]);
                let got: Vec<*mut Link> = (0..3).map(|_| q.pop()).collect();
                assert_eq!(got, left);
                assert!(q.is_empty());
            }
        }
        // The only one.
        let mut nodes = links(1);
        let only: *mut Link = &raw mut nodes[0];
        let mut q = Fifo::new();
        // SAFETY: as above.
        unsafe {
            q.push(only);
            assert!(q.remove(only) && q.is_empty());
            q.push(only);
            assert_eq!(q.pop(), only);
        }
    }

    #[test]
    fn irql_moves_one_way_per_call() {
        assert_eq!(check_raise(0, 2), Ok(()));
        assert_eq!(check_raise(2, 2), Ok(()));
        assert_eq!(
            check_raise(2, 1),
            Err(Violation::RaiseBelow { current: 2, new: 1 })
        );
        assert_eq!(check_lower(2, 0), Ok(()));
        assert_eq!(check_lower(2, 2), Ok(()));
        assert_eq!(
            check_lower(0, 2),
            Err(Violation::LowerAbove { current: 0, new: 2 })
        );
    }

    #[test]
    fn locks_nest_in_rising_rank_and_unwind_in_reverse() {
        let mut held = Held::new();
        assert_eq!(held.acquire(0x1000, 10), Ok(()));
        assert_eq!(held.acquire(0x2000, 20), Ok(()));
        assert_eq!(held.acquire(0x3000, 30), Ok(()));
        assert_eq!(held.depth(), 3);
        assert_eq!(held.release(0x3000), Ok(()));
        assert_eq!(held.release(0x2000), Ok(()));
        assert_eq!(held.release(0x1000), Ok(()));
        assert_eq!(held.depth(), 0);
    }

    #[test]
    fn nesting_violations() {
        let mut held = Held::new();
        held.acquire(0x1000, 20).unwrap();
        assert_eq!(held.acquire(0x1000, 20), Err(Violation::Recursive));
        assert_eq!(
            held.acquire(0x1000, 99),
            Err(Violation::Recursive),
            "whatever the rank"
        );
        assert_eq!(
            held.acquire(0x2000, 10),
            Err(Violation::Order {
                held: 20,
                wanted: 10
            })
        );
        assert_eq!(
            held.acquire(0x2000, 20),
            Err(Violation::Order {
                held: 20,
                wanted: 20
            }),
            "two locks of one rank never nest"
        );
        assert_eq!(held.depth(), 1, "a refused lock is not recorded");

        held.acquire(0x2000, 30).unwrap();
        assert_eq!(held.release(0x1000), Err(Violation::NotInnermost));
        assert_eq!(held.release(0x9000), Err(Violation::NotHeld));
        assert_eq!(held.depth(), 2, "a refused release changes nothing");
        held.release(0x2000).unwrap();
        held.release(0x1000).unwrap();
        assert_eq!(held.release(0x1000), Err(Violation::NotHeld));
    }

    #[test]
    fn nesting_has_a_limit() {
        let mut held = Held::new();
        for i in 0..MAX_HELD {
            held.acquire(0x1000 + i, i as u8 + 1).unwrap();
        }
        assert_eq!(held.acquire(0x9000, 200), Err(Violation::TooDeep));
    }

    #[test]
    fn ticket_lock_basics() {
        let lock = TicketLock::new();
        assert!(!lock.is_locked());
        lock.lock();
        assert!(lock.is_locked());
        assert!(!lock.try_lock(), "a held lock cannot be taken");
        lock.unlock();
        assert!(lock.try_lock());
        lock.unlock();
        assert!(!lock.is_locked());
        // Forcing a held lock leaves it held by the forcer.
        lock.lock();
        lock.force();
        assert!(lock.is_locked());
        lock.unlock();
        assert!(!lock.is_locked());
    }

    struct Counter(UnsafeCell<u64>);
    // SAFETY: only touched while holding the lock under test.
    unsafe impl Sync for Counter {}

    /// Eight threads, each incrementing a plain counter under the lock: a
    /// lock that ever lets two in loses increments.
    #[test]
    fn ticket_lock_excludes() {
        const THREADS: u64 = 8;
        const ROUNDS: u64 = 20_000;
        let shared = Arc::new((TicketLock::new(), Counter(UnsafeCell::new(0))));
        let threads: Vec<_> = (0..THREADS)
            .map(|t| {
                let shared = Arc::clone(&shared);
                std::thread::spawn(move || {
                    for i in 0..ROUNDS {
                        // Mix blocking and trying acquisitions.
                        if (i + t) % 3 == 0 {
                            while !shared.0.try_lock() {
                                std::thread::yield_now();
                            }
                        } else {
                            shared.0.lock();
                        }
                        // SAFETY: the lock is held.
                        unsafe {
                            let value = shared.1.0.get();
                            let seen = value.read();
                            std::hint::black_box(seen);
                            value.write(seen + 1);
                        }
                        shared.0.unlock();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        // SAFETY: every thread has finished.
        assert_eq!(unsafe { *shared.1.0.get() }, THREADS * ROUNDS);
        assert!(!shared.0.is_locked());
    }

    #[test]
    fn counter_arithmetic() {
        // One second of any counter is ten million units.
        for frequency in [1_000_000, 3_579_545, 62_500_000, 2_999_999_999, 1 << 40] {
            assert_eq!(counter_to_time(frequency, frequency), 10_000_000);
            assert_eq!(counter_to_time(0, frequency), 0);
            assert_eq!(micros_to_counter(1_000_000, frequency), frequency);
        }
        // No overflow after a century of a fast counter.
        let century = 3_000_000_000u64 * 86_400 * 365 * 100;
        assert_eq!(
            counter_to_time(century, 3_000_000_000),
            86_400 * 365 * 100 * 10_000_000
        );
        // Rounds down: time never runs ahead of the counter.
        assert_eq!(counter_to_time(1, 3), 3_333_333);
        // A wait rounds up: never short.
        assert_eq!(micros_to_counter(1, 3_579_545), 4);
        assert_eq!(micros_to_counter(0, 3_579_545), 0);
        assert!(counter_to_time(micros_to_counter(1500, 3_579_545), 3_579_545) >= 15_000);
    }

    #[test]
    fn ticks() {
        assert_eq!(ticks_in(0), 0);
        assert_eq!(ticks_in(TIME_INCREMENT - 1), 0);
        assert_eq!(ticks_in(TIME_INCREMENT), 1);
        assert_eq!(ticks_in(10_000_000), 64, "64 ticks a second");
    }
}
