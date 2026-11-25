//! Time on arm64: the generic timer. Its counter states its own
//! frequency, and its virtual timer raises the clock interrupt.

use crate::hal::platform;
use core::arch::asm;
use core::sync::atomic::{AtomicU64, Ordering};

/// IRQL of the clock interrupt: Windows' CLOCK_LEVEL.
const CLOCK_LEVEL: u8 = 13;
/// The virtual timer's interrupt where firmware does not say: the one
/// the architecture's base system specification assigns.
const VIRTUAL_TIMER_PPI: u32 = 27;

/// `(interrupt id, IRQL)` of the clock interrupt.
pub const CLOCK: (u32, u8) = (VIRTUAL_TIMER_PPI, CLOCK_LEVEL);

/// Counter ticks between clock interrupts.
static PERIOD: AtomicU64 = AtomicU64::new(0);

/// The counter's frequency, as the processor reports it.
pub fn calibrate() -> Result<u64, &'static str> {
    if platform::get()
        .firmware
        .virtual_timer
        .is_some_and(|id| id != VIRTUAL_TIMER_PPI)
    {
        return Err("firmware puts the virtual timer on an unexpected interrupt");
    }
    let frequency: u64;
    // SAFETY: reading the counter's frequency register has no side effects.
    unsafe { asm!("mrs {}, cntfrq_el0", out(reg) frequency, options(nomem, nostack)) };
    Ok(frequency)
}

fn arm(due: u64) {
    // SAFETY: programming this processor's virtual timer: compare value,
    // then enabled and unmasked.
    unsafe {
        asm!(
            "msr cntv_cval_el0, {due}",
            "msr cntv_ctl_el0, {on}",
            "isb",
            due = in(reg) due,
            on = in(reg) 1u64,
            options(nomem, nostack),
        );
    }
}

/// Start the clock interrupt, every `period` counter ticks.
pub fn start(period: u64, _frequency: u64) {
    PERIOD.store(period, Ordering::Relaxed);
    arm(super::counter() + period);
}

/// The clock interrupt was taken: set the next one. Each is due one
/// period after the last was due, not after it was handled, so lateness
/// does not accumulate; if a whole period was missed, start afresh.
pub fn next() {
    let period = PERIOD.load(Ordering::Relaxed);
    let now = super::counter();
    let last: u64;
    // SAFETY: reading this processor's timer compare value: when the
    // interrupt being handled was due.
    unsafe { asm!("mrs {}, cntv_cval_el0", out(reg) last, options(nomem, nostack)) };
    let mut due = last + period;
    if due <= now {
        due = now + period;
    }
    arm(due);
}
