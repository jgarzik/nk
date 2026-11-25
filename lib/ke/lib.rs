//! Kernel-core logic with no hardware behind it, so the host can test it:
//! the rules for IRQL changes and lock nesting, and the spin lock itself.
//!
//! The kernel wraps these with the per-processor state and the IRQL
//! register; see `kernel/ke`. `doc/LOCKING.md` states the rules.

#![cfg_attr(not(test), no_std)]

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
