//! NK's own per-processor state: what the kernel keeps for each CPU that
//! no driver can see. It lives next to the processor control region and
//! is reached through `arch::percpu()`.

use super::dpc::Queue;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};
use nk_ke::Held;

pub struct PerCpu {
    /// The spin locks this processor holds.
    held: UnsafeCell<Held>,
    /// Clock interrupts this processor has taken.
    ticks: AtomicU64,
    /// Deferred procedure calls waiting to run here.
    dpcs: Queue,
}

// SAFETY: a processor only touches the non-atomic part of its own
// `PerCpu`, and only at HIGH_LEVEL, where nothing else on that processor
// can interleave (see `held`).
unsafe impl Sync for PerCpu {}

impl PerCpu {
    pub const fn new() -> Self {
        Self {
            held: UnsafeCell::new(Held::new()),
            ticks: AtomicU64::new(0),
            dpcs: Queue::new(),
        }
    }

    /// Clock interrupts this processor has taken. Any processor may ask.
    pub fn ticks(&self) -> u64 {
        self.ticks.load(Ordering::Relaxed)
    }

    /// This processor's queue of deferred procedure calls.
    pub fn dpcs(&self) -> &Queue {
        &self.dpcs
    }

    /// Count a clock interrupt on this processor.
    pub fn tick(&self) {
        self.ticks.fetch_add(1, Ordering::Relaxed);
    }

    /// The locks this processor holds.
    ///
    /// # Safety
    /// The caller is running on the processor this belongs to, at
    /// HIGH_LEVEL, and drops the reference before the IRQL falls: an
    /// interrupt handler may take a lock, and must not find the record
    /// half updated.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn held(&self) -> &mut Held {
        // SAFETY: per the contract, this is the only live reference.
        unsafe { &mut *self.held.get() }
    }
}
