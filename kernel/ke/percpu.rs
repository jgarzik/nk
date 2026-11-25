//! NK's own per-processor state: what the kernel keeps for each CPU that
//! no driver can see. It lives next to the processor control region and
//! is reached through `arch::percpu()`.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU64, Ordering};
use nk_ke::Held;

pub struct PerCpu {
    /// The spin locks this processor holds.
    held: UnsafeCell<Held>,
    /// Clock interrupts this processor has taken.
    ticks: AtomicU64,
}

// SAFETY: a processor only touches its own `PerCpu`, and only at
// DISPATCH_LEVEL or above, where nothing else on that processor can
// interleave with it at the same level (see `held`).
unsafe impl Sync for PerCpu {}

impl PerCpu {
    pub const fn new() -> Self {
        Self {
            held: UnsafeCell::new(Held::new()),
            ticks: AtomicU64::new(0),
        }
    }

    /// Clock interrupts this processor has taken. Any processor may ask.
    pub fn ticks(&self) -> u64 {
        self.ticks.load(Ordering::Relaxed)
    }

    /// Count a clock interrupt on this processor.
    pub fn tick(&self) {
        self.ticks.fetch_add(1, Ordering::Relaxed);
    }

    /// The locks this processor holds.
    ///
    /// # Safety
    /// The caller is running on the processor this belongs to, at
    /// DISPATCH_LEVEL or above, and drops the reference before the IRQL
    /// can fall or anything that takes or releases a lock can run.
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn held(&self) -> &mut Held {
        // SAFETY: per the contract, this is the only live reference.
        unsafe { &mut *self.held.get() }
    }
}
