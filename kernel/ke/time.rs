//! Time: the clock tick and what drivers read time from.
//!
//! All time comes from one free-running counter (the TSC on x86-64, the
//! generic timer's counter on arm64) and its frequency. The clock
//! interrupt fires 64 times a second, Windows' default, and on each one
//! the kernel recomputes the time from the counter. It does not count
//! interrupts: a tick that is late, or lost, costs no time.
//!
//! Drivers built with the WDK do not call the kernel for the tick count,
//! the interrupt time or the system time. They read them from a page at a
//! fixed address, `KUSER_SHARED_DATA`, so that page is part of the
//! contract and the tick keeps it current.

#![allow(non_snake_case)]

use super::interrupt;
use crate::{arch, mm};
use core::sync::atomic::{AtomicU64, Ordering};
use nk_bootinfo::BootInfo;
use nk_ke::{
    TICK_MULTIPLIER, TIME_INCREMENT, counter_to_time, micros_to_counter, plausible_frequency,
    ticks_in,
};
use nk_mm::pt::Prot;
use nk_ntabi::ke::{
    SHARED_DATA, SHARED_INTERRUPT_TIME, SHARED_SYSTEM_TIME, SHARED_TICK_COUNT,
    SHARED_TICK_MULTIPLIER,
};

/// The counter's ticks per second.
static FREQUENCY: AtomicU64 = AtomicU64::new(0);
/// The counter's value when time began (kernel start).
static EPOCH: AtomicU64 = AtomicU64::new(0);
/// Wall-clock time at the epoch, 100 ns units since 1601.
static BOOT_TIME: AtomicU64 = AtomicU64::new(0);
/// Counter ticks between clock interrupts.
static PERIOD: AtomicU64 = AtomicU64::new(0);

/// The counter's ticks per second.
pub fn frequency() -> u64 {
    FREQUENCY.load(Ordering::Relaxed)
}

/// Time since the kernel started, in 100 ns units, from the counter now.
pub fn interrupt_time() -> u64 {
    let count = arch::counter().wrapping_sub(EPOCH.load(Ordering::Relaxed));
    counter_to_time(count, frequency())
}

/// The wall clock now: 100 ns units since 1601, UTC.
pub fn system_time() -> u64 {
    boot_time() + interrupt_time()
}

/// The wall clock when interrupt time was zero.
pub fn boot_time() -> u64 {
    BOOT_TIME.load(Ordering::Relaxed)
}

/// Spin for at least `micros` microseconds.
pub fn stall(micros: u64) {
    let start = arch::counter();
    let wanted = micros_to_counter(micros, frequency());
    while arch::counter().wrapping_sub(start) < wanted {
        core::hint::spin_loop();
    }
}

/// Write a time into the shared page. A 64-bit time there is three
/// 32-bit words: low, high, and high again. 64-bit code reads the first
/// two as one value, so they are stored as one; the fields are not all
/// 8-byte aligned, so the store is an unaligned one.
fn publish(offset: usize, value: u64) {
    // SAFETY: the shared page is mapped for the life of the kernel and
    // the offsets are inside it; readers tolerate concurrent updates by
    // design.
    unsafe {
        let field = (SHARED_DATA as *mut u8).add(offset);
        field
            .add(8)
            .cast::<u32>()
            .write_unaligned((value >> 32) as u32);
        field.cast::<u64>().write_unaligned(value);
    }
}

/// Bring the shared page up to date from the counter.
fn update() {
    let now = interrupt_time();
    publish(SHARED_INTERRUPT_TIME, now);
    publish(SHARED_SYSTEM_TIME, BOOT_TIME.load(Ordering::Relaxed) + now);
    publish(SHARED_TICK_COUNT, ticks_in(now));
}

fn tick(_: u32) {
    arch::percpu().tick();
    super::dpc::watchdog();
    super::timer::tick(interrupt_time());
    super::thread::tick();
    // Every processor takes the tick; one of them keeps the time.
    if super::pcr::current_processor() == 0 {
        update();
    }
    arch::clock_next();
}

/// Start the clock interrupt on the processor running this code.
pub fn start_cpu() {
    arch::clock_start(PERIOD.load(Ordering::Relaxed));
}

/// Calibrate the counter, map the shared page and start the clock
/// interrupt on this processor.
pub fn init(info: &BootInfo) -> Result<(), &'static str> {
    let frequency = arch::clock_calibrate()?;
    if !plausible_frequency(frequency) {
        return Err("the time counter's frequency is implausible");
    }
    FREQUENCY.store(frequency, Ordering::Relaxed);
    EPOCH.store(arch::counter(), Ordering::Relaxed);
    BOOT_TIME.store(info.boot_time, Ordering::Relaxed);

    let frame = mm::alloc_frames(1).ok_or("no memory for the shared data page")?;
    mm::map::map(SHARED_DATA, frame, 1, Prot::RW).map_err(|_| "cannot map the shared data page")?;
    // SAFETY: the page was just mapped and zeroed; the field is aligned.
    unsafe {
        (SHARED_DATA as *mut u8)
            .add(SHARED_TICK_MULTIPLIER)
            .cast::<u32>()
            .write_volatile(TICK_MULTIPLIER);
    }
    update();

    let (vector, level) = arch::CLOCK;
    interrupt::register(vector, level, tick);
    PERIOD.store(
        micros_to_counter(TIME_INCREMENT / 10, frequency),
        Ordering::Relaxed,
    );
    start_cpu();
    kprintln!("ke: time counter at {frequency} Hz, clock at 64 Hz");
    Ok(())
}

/// [`KeQueryTimeIncrement`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequerytimeincrement):
/// the clock tick in 100 ns units.
pub extern "C" fn KeQueryTimeIncrement() -> u32 {
    TIME_INCREMENT as u32
}

/// [`KeQueryPerformanceCounter`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryperformancecounter).
///
/// # Safety
/// `performance_frequency` is null or points to an `i64` to fill in.
pub unsafe extern "C" fn KeQueryPerformanceCounter(performance_frequency: *mut i64) -> i64 {
    if !performance_frequency.is_null() {
        // SAFETY: per the contract.
        unsafe { performance_frequency.write_unaligned(frequency() as i64) };
    }
    arch::counter().wrapping_sub(EPOCH.load(Ordering::Relaxed)) as i64
}

/// [`KeStallExecutionProcessor`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kestallexecutionprocessor).
pub extern "C" fn KeStallExecutionProcessor(micro_seconds: u32) {
    stall(u64::from(micro_seconds));
}

// ---- tests --------------------------------------------------------------

fn shared(offset: usize) -> u64 {
    // SAFETY: as in `publish`; reading as a driver's inlined code does.
    unsafe {
        (SHARED_DATA as *const u8)
            .add(offset)
            .cast::<u64>()
            .read_unaligned()
    }
}

/// The counter never runs backwards, and a stall lasts at least as long
/// as asked by it. Returns the readings taken.
pub fn monotonic_test() -> Result<u64, &'static str> {
    let mut last = arch::counter();
    let mut readings = 0;
    let start = interrupt_time();
    while interrupt_time() - start < 500_000 {
        let now = arch::counter();
        if now < last {
            return Err("the time counter ran backwards");
        }
        last = now;
        readings += 1;
    }
    let before = interrupt_time();
    stall(2_000);
    if interrupt_time() - before < 20_000 {
        return Err("a 2 ms stall returned early");
    }
    Ok(readings)
}

/// The clock interrupt arrives at 64 Hz, give or take, and keeps the
/// shared page within a tick or two of the counter. Returns the
/// interrupts seen in a quarter of a second.
pub fn tick_test() -> Result<u64, &'static str> {
    let taken = arch::percpu().ticks();
    let page_before = shared(SHARED_INTERRUPT_TIME);
    stall(250_000);
    let seen = arch::percpu().ticks() - taken;
    // 16 expected. Wide bounds: an emulated machine delivers them late.
    if !(8..=24).contains(&seen) {
        return Err("the clock interrupt is not near 64 Hz");
    }
    let page = shared(SHARED_INTERRUPT_TIME);
    let now = interrupt_time();
    if page > now {
        return Err("the shared page's interrupt time is ahead of the counter");
    }
    if now - page > 4 * TIME_INCREMENT {
        return Err("the shared page's interrupt time is more than four ticks stale");
    }
    if page - page_before < 2_000_000 {
        return Err("the shared page's interrupt time advanced less than 200 ms in 250 ms");
    }
    Ok(seen)
}

/// The three times in the shared page agree with one another, and the
/// wall clock is later than 2020. Returns the tick count read.
pub fn shared_page_test() -> Result<u64, &'static str> {
    // Read between two ticks. The clock interrupt, on another
    // processor, writes the three one after another, so a read may find
    // some of them a tick ahead of the others, and reading one of them
    // twice does not show it: three values that disagree are read
    // again, a little later, and only ones that never agree are wrong.
    let mut wrong = "could not read the shared page between ticks";
    for _ in 0..8 {
        let interrupt = shared(SHARED_INTERRUPT_TIME);
        let system = shared(SHARED_SYSTEM_TIME);
        let ticks = shared(SHARED_TICK_COUNT);
        if interrupt != shared(SHARED_INTERRUPT_TIME) {
            continue;
        }
        if ticks != ticks_in(interrupt) {
            wrong = "the tick count is not the interrupt time in ticks";
            stall(2_000);
            continue;
        }
        if system - interrupt != BOOT_TIME.load(Ordering::Relaxed) {
            wrong = "system time is not boot time plus interrupt time";
            stall(2_000);
            continue;
        }
        // 2020-01-01, in 100 ns units since 1601.
        if system < 132_223_104_000_000_000 {
            return Err("the wall clock is earlier than 2020: firmware gave no time");
        }
        return Ok(ticks);
    }
    Err(wrong)
}

/// Two seconds by NK's clock, marked on the console for the test harness,
/// which times the marks with the host's clock: an outside check that
/// NK's second is a second.
pub fn host_mark_test() -> Result<u64, &'static str> {
    kprintln!("NK-CLOCK-MARK start");
    stall(2_000_000);
    kprintln!("NK-CLOCK-MARK end");
    Ok(2)
}
