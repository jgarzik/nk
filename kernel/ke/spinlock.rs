//! NK's lock for its own data: a spin lock with a rank.
//!
//! This is not the driver-visible `KSPIN_LOCK`. Taking one:
//!
//! - raises the IRQL to the level of the lock's rank, so that nothing
//!   which could want the same lock (another thread on this processor, a
//!   DPC, for the console even an interrupt) can run here while it is
//!   held;
//! - waits its turn: waiters are served in order of arrival;
//! - is checked against the locks this processor already holds: ranks
//!   rise strictly inward, and a lock is never taken twice.
//!
//! Releasing must happen in the reverse order of taking, which is what
//! dropping guards in scope order does. A broken rule stops the system;
//! `doc/LOCKING.md` lists the ranks and the reasons.

use super::irql;
use crate::arch;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use nk_ke::TicketLock;

/// The order in which locks may nest: a lock may be taken only while every
/// lock held has a lower rank. See `doc/LOCKING.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Rank {
    /// The loaded-driver records (`io::driver`).
    Drivers = 10,
    /// The loaded-image table (`ldr`).
    Images = 20,
    /// The object namespace (`ob`).
    Namespace = 30,
    /// The executive pool (`mm::pool`).
    Pool = 40,
    /// Kernel address space and page tables (`mm::map`).
    AddressSpace = 50,
    /// The frame allocator (`mm`).
    Frames = 60,
    /// The diagnostic console (`kd`): innermost, so anything can print.
    Console = 250,
}

impl Rank {
    /// The IRQL at which locks of this rank are held.
    const fn level(self) -> u8 {
        match self {
            // Usable from any context, an interrupt included.
            Rank::Console => irql::HIGH_LEVEL,
            _ => irql::DISPATCH_LEVEL,
        }
    }
}

pub struct SpinLock<T> {
    lock: TicketLock,
    rank: Rank,
    value: UnsafeCell<T>,
}

// SAFETY: the lock gives one holder at a time exclusive access to `T`.
unsafe impl<T: Send> Sync for SpinLock<T> {}

pub struct Guard<'a, T> {
    lock: &'a SpinLock<T>,
    /// The IRQL to return to.
    old_irql: u8,
}

/// The lock taken by force on the way to stopping the system. It is never
/// released: nothing runs afterwards.
pub struct Forced<'a, T>(&'a SpinLock<T>);

impl<T> SpinLock<T> {
    pub const fn new(rank: Rank, value: T) -> Self {
        Self {
            lock: TicketLock::new(),
            rank,
            value: UnsafeCell::new(value),
        }
    }

    fn id(&self) -> usize {
        core::ptr::from_ref(self).addr()
    }

    pub fn lock(&self) -> Guard<'_, T> {
        let old_irql = irql::raise(self.rank.level());
        // SAFETY: at DISPATCH_LEVEL or above on this processor, and the
        // reference ends with this statement.
        if let Err(v) = unsafe { arch::percpu().held() }.acquire(self.id(), self.rank as u8) {
            irql::violation(v);
        }
        self.lock.lock();
        Guard {
            lock: self,
            old_irql,
        }
    }

    /// Take the lock even if it is held, checking nothing. For the path
    /// that stops the system only: the holder will never run again.
    pub fn force_lock(&self) -> Forced<'_, T> {
        arch::set_irql(irql::HIGH_LEVEL);
        self.lock.force();
        Forced(self)
    }
}

impl<T> Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: holding the guard means holding the lock.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: holding the guard means holding the lock.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        self.lock.lock.unlock();
        // SAFETY: still at the lock's level on this processor, and the
        // reference ends with this statement.
        if let Err(v) = unsafe { arch::percpu().held() }.release(self.lock.id()) {
            irql::violation(v);
        }
        irql::lower(self.old_irql);
    }
}

impl<T> Deref for Forced<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the system is stopping; this processor is the only one
        // that will touch the value again.
        unsafe { &*self.0.value.get() }
    }
}
