//! Time on x86-64: the TSC as the counter, the local APIC timer as the
//! clock interrupt.
//!
//! Neither says how fast it runs, so both are measured against the ACPI
//! power-management timer, whose rate is fixed by the ACPI specification.

use super::apic;
use crate::hal::platform;
use nk_acpi::{PM_TIMER_HZ, PmTimer, pm_timer_delta};

/// `(vector, IRQL)` of the clock interrupt: Windows' CLOCK_LEVEL.
pub const CLOCK: (u32, u8) = (0xD1, 13);

/// How long each calibration watches the reference, in its ticks: 50 ms.
const WINDOW: u32 = (PM_TIMER_HZ / 20) as u32;

fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: reading the power-management timer's counter register has
    // no side effects.
    unsafe {
        core::arch::asm!("in eax, dx", in("dx") port, out("eax") value, options(nomem, nostack));
    }
    value
}

/// Wait for `ticks` of the reference timer to pass, from its next change.
/// Returns the TSC at the start and end of the window.
fn window(timer: PmTimer, ticks: u32) -> (u64, u64) {
    // Start on an edge, so the window is not short by a partial tick.
    let first = inl(timer.port);
    let mut start = inl(timer.port);
    while start == first {
        start = inl(timer.port);
    }
    let begin = super::counter();
    while pm_timer_delta(timer, start, inl(timer.port)) < ticks {
        core::hint::spin_loop();
    }
    (begin, super::counter())
}

/// Measure the TSC's frequency, and the APIC timer's against it.
pub fn calibrate() -> Result<u64, &'static str> {
    let timer = platform::get()
        .timer
        .ok_or("no ACPI power-management timer to calibrate against")?;
    apic::timer_count_down();
    let (begin, end) = window(timer, WINDOW);
    let apic_ticks = apic::timer_elapsed();
    // The window is 1/20 s.
    apic::set_timer_rate(u64::from(apic_ticks) * 20);
    Ok((end - begin) * 20)
}

/// Start the periodic clock interrupt. The period is given in counter
/// ticks; the APIC timer has its own rate, measured in `calibrate`.
pub fn start(period: u64, frequency: u64) {
    apic::timer_periodic(CLOCK.0, period, frequency);
}

/// Nothing to do: the APIC timer reloads itself.
pub fn next() {}
