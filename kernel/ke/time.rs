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
    SHARED_ACTIVE_GROUP_COUNT, SHARED_ACTIVE_PROCESSOR_COUNT, SHARED_COOKIE, SHARED_DATA,
    SHARED_IMAGE_NUMBER_HIGH, SHARED_IMAGE_NUMBER_LOW, SHARED_INTERRUPT_TIME,
    SHARED_LARGE_PAGE_MINIMUM, SHARED_MITIGATION_POLICIES, SHARED_NATIVE_PROCESSOR_ARCHITECTURE,
    SHARED_NT_BUILD_NUMBER, SHARED_NT_MAJOR_VERSION, SHARED_NT_MINOR_VERSION,
    SHARED_NT_PRODUCT_TYPE, SHARED_NT_SYSTEM_ROOT, SHARED_NUMBER_OF_PHYSICAL_PAGES,
    SHARED_PRODUCT_TYPE_IS_VALID, SHARED_QPC_DATA, SHARED_QPC_FREQUENCY, SHARED_SYSTEM_CALL,
    SHARED_SYSTEM_TIME, SHARED_TEST_RET_INSTRUCTION, SHARED_TICK_COUNT, SHARED_TICK_MULTIPLIER,
    SHARED_UNPARKED_PROCESSOR_COUNT,
};
use nk_ntabi::seh::x64::{XSTATE_CONTEXT, XSTATE_SAVE};
use nk_ntabi::status::{
    NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS,
};

/// Physical frame backing `KUSER_SHARED_DATA`, shared read-only into every
/// user process at `USER_SHARED_DATA`.
static SHARED_DATA_FRAME: AtomicU64 = AtomicU64::new(0);

/// Physical address of the `KUSER_SHARED_DATA` frame.
#[allow(dead_code)]
pub fn shared_data_frame() -> u64 {
    SHARED_DATA_FRAME.load(Ordering::Acquire)
}

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
    SHARED_DATA_FRAME.store(frame, Ordering::Release);
    mm::map::map(SHARED_DATA, frame, 1, Prot::RW).map_err(|_| "cannot map the shared data page")?;
    let page = SHARED_DATA as *mut u8;
    // SAFETY: the page was just mapped and zeroed; all offsets are checked
    // against `ntkrnlmp.x64.pdb` in `nk_ntabi::pdb`.
    unsafe {
        page.add(SHARED_TICK_MULTIPLIER)
            .cast::<u32>()
            .write_volatile(TICK_MULTIPLIER);
        let (image_machine, native_arch, test_ret): (u16, u16, u64) =
            if cfg!(target_arch = "x86_64") {
                (0x8664, 9, 0xC3)
            } else {
                (0xAA64, 12, 0)
            };
        page.add(SHARED_IMAGE_NUMBER_LOW)
            .cast::<u16>()
            .write_volatile(image_machine);
        page.add(SHARED_IMAGE_NUMBER_HIGH)
            .cast::<u16>()
            .write_volatile(image_machine);
        let root_utf16: [u16; 11] = [
            u16::from(b'C'),
            u16::from(b':'),
            u16::from(b'\\'),
            u16::from(b'W'),
            u16::from(b'i'),
            u16::from(b'n'),
            u16::from(b'd'),
            u16::from(b'o'),
            u16::from(b'w'),
            u16::from(b's'),
            0,
        ];
        for (i, ch) in root_utf16.iter().enumerate() {
            page.add(SHARED_NT_SYSTEM_ROOT)
                .cast::<u16>()
                .add(i)
                .write_volatile(*ch);
        }
        page.add(SHARED_LARGE_PAGE_MINIMUM)
            .cast::<u32>()
            .write_volatile(0x0020_0000);
        page.add(SHARED_NT_BUILD_NUMBER)
            .cast::<u32>()
            .write_volatile(19045);
        page.add(SHARED_NT_PRODUCT_TYPE)
            .cast::<u32>()
            .write_volatile(1);
        page.add(SHARED_PRODUCT_TYPE_IS_VALID).write_volatile(1);
        page.add(SHARED_NATIVE_PROCESSOR_ARCHITECTURE)
            .cast::<u16>()
            .write_volatile(native_arch);
        page.add(SHARED_NT_MAJOR_VERSION)
            .cast::<u32>()
            .write_volatile(10);
        page.add(SHARED_NT_MINOR_VERSION)
            .cast::<u32>()
            .write_volatile(0);
        // NXSupportPolicy = AlwaysOn (2 in bits 0..2).
        page.add(SHARED_MITIGATION_POLICIES).write_volatile(2);
        let (phys_pages, _, _) = mm::physical_memory();
        page.add(SHARED_NUMBER_OF_PHYSICAL_PAGES)
            .cast::<u32>()
            .write_volatile(phys_pages.min(u64::from(u32::MAX)) as u32);
        page.add(SHARED_TEST_RET_INSTRUCTION)
            .cast::<u64>()
            .write_volatile(test_ret);
        page.add(SHARED_QPC_FREQUENCY)
            .cast::<u64>()
            .write_volatile(frequency);
        page.add(SHARED_SYSTEM_CALL).cast::<u32>().write_volatile(0);
        let seed = arch::counter() ^ info.boot_time ^ 0x9E37_79B9_7F4A_7C15;
        let cookie = ((seed as u32) ^ ((seed >> 32) as u32)) | 1;
        page.add(SHARED_COOKIE).cast::<u32>().write_volatile(cookie);
        page.add(SHARED_UNPARKED_PROCESSOR_COUNT)
            .cast::<u16>()
            .write_volatile(1);
        page.add(SHARED_ACTIVE_PROCESSOR_COUNT)
            .cast::<u32>()
            .write_volatile(1);
        page.add(SHARED_ACTIVE_GROUP_COUNT).write_volatile(1);
        page.add(SHARED_QPC_DATA).cast::<u16>().write_volatile(0);
        arch::write_kusd_features(page);
        arch::write_kusd_xstate(page);
    }
    update();

    let (vector, level) = arch::CLOCK;
    interrupt::register(vector, level, tick);
    PERIOD.store(
        micros_to_counter(TIME_INCREMENT / 10, frequency),
        Ordering::Relaxed,
    );
    start_cpu();
    kprintln!(
        "ke: time counter at {frequency} Hz, clock at 64 Hz (xstate mask={:#x}, area={}B)",
        arch::xstate_enabled_mask(),
        arch::xstate_area_size()
    );
    Ok(())
}

/// Update `KUSER_SHARED_DATA` processor counts once APs have come online.
pub fn update_processor_count(count: usize) {
    let page = SHARED_DATA as *mut u8;
    // SAFETY: the shared data page is mapped from `time::init` onward.
    unsafe {
        page.add(SHARED_ACTIVE_PROCESSOR_COUNT)
            .cast::<u32>()
            .write_volatile(count as u32);
        page.add(SHARED_UNPARKED_PROCESSOR_COUNT)
            .cast::<u16>()
            .write_volatile(count as u16);
    }
}

/// [`KeQueryTimeIncrement`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequerytimeincrement):
/// the clock tick in 100 ns units.
pub extern "C" fn KeQueryTimeIncrement() -> u32 {
    TIME_INCREMENT as u32
}

/// [`ExQueryTimerResolution`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exquerytimerresolution):
/// the longest and the shortest clock tick the system can run with, and
/// the one it runs with, in 100 ns units. NK's clock has one rate, so
/// the three are the same.
///
/// # Safety
/// The three are writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn ExQueryTimerResolution(
    maximum_time: *mut u32,
    minimum_time: *mut u32,
    current_time: *mut u32,
) {
    // SAFETY: per the contract.
    unsafe {
        for time in [maximum_time, minimum_time, current_time] {
            time.write_unaligned(TIME_INCREMENT as u32);
        }
    }
}

/// [`KeQueryUnbiasedInterruptTime`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryunbiasedinterrupttime):
/// the time the system has been running and awake. NK never sleeps, so
/// that is the interrupt time.
#[allow(non_snake_case)]
pub extern "C" fn KeQueryUnbiasedInterruptTime() -> u64 {
    interrupt_time()
}

/// [`KeQueryInterruptTimePrecise`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryinterrupttimeprecise):
/// the interrupt time as of now, not of the last clock tick, and the
/// performance counter it was worked out from.
///
/// # Safety
/// `qpc_time_stamp` is writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeQueryInterruptTimePrecise(qpc_time_stamp: *mut u64) -> u64 {
    let count = arch::counter().wrapping_sub(EPOCH.load(Ordering::Relaxed));
    // SAFETY: per the contract.
    unsafe { qpc_time_stamp.write_unaligned(count) };
    counter_to_time(count, frequency())
}

/// [`NtQueryPerformanceCounter`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-kequeryperformancecounter):
/// return the monotonic performance counter and optionally its frequency.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
#[allow(non_snake_case)]
pub unsafe extern "C" fn NtQueryPerformanceCounter(
    counter: *mut i64,
    frequency_out: *mut i64,
) -> nk_ntabi::status::NTSTATUS {
    let mode = crate::svc::capture::mode();
    let count = arch::counter().wrapping_sub(EPOCH.load(Ordering::Relaxed)) as i64;
    // SAFETY: per the contract; `capture::write` probes user pointers.
    if let Err(st) = unsafe { crate::svc::capture::write(counter, count, mode) } {
        return st;
    }
    if !frequency_out.is_null() {
        let freq = frequency() as i64;
        // SAFETY: per the contract.
        if let Err(st) = unsafe { crate::svc::capture::write(frequency_out, freq, mode) } {
            return st;
        }
    }
    nk_ntabi::status::STATUS_SUCCESS
}

/// `NtQuerySystemTime`: return current UTC system time (100ns since 1601-01-01).
///
/// # Safety
/// `current_time` must satisfy `PreviousMode`.
#[allow(non_snake_case)]
pub unsafe extern "C" fn NtQuerySystemTime(current_time: *mut i64) -> nk_ntabi::status::NTSTATUS {
    let mode = crate::svc::capture::mode();
    let now = system_time() as i64;
    // SAFETY: per the contract; `capture::write` probes user pointers.
    match unsafe { crate::svc::capture::write(current_time, now, mode) } {
        Ok(()) => nk_ntabi::status::STATUS_SUCCESS,
        Err(st) => st,
    }
}

/// [`KeQueryUnbiasedInterruptTimePrecise`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryunbiasedinterrupttimeprecise):
/// [`KeQueryInterruptTimePrecise`], which on a system that never sleeps
/// is the same.
///
/// # Safety
/// `qpc_time_stamp` is writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeQueryUnbiasedInterruptTimePrecise(qpc_time_stamp: *mut u64) -> u64 {
    // SAFETY: per the contract.
    unsafe { KeQueryInterruptTimePrecise(qpc_time_stamp) }
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
        // Check static KUSER_SHARED_DATA fields and XState save/restore.
        let page = SHARED_DATA as *const u8;
        // SAFETY: the shared data page is mapped for the life of the kernel.
        let (major, build, qpc, cpus, cookie) = unsafe {
            (
                page.add(SHARED_NT_MAJOR_VERSION)
                    .cast::<u32>()
                    .read_volatile(),
                page.add(SHARED_NT_BUILD_NUMBER)
                    .cast::<u32>()
                    .read_volatile(),
                page.add(SHARED_QPC_FREQUENCY).cast::<u64>().read_volatile(),
                page.add(SHARED_ACTIVE_PROCESSOR_COUNT)
                    .cast::<u32>()
                    .read_volatile(),
                page.add(SHARED_COOKIE).cast::<u32>().read_volatile(),
            )
        };
        if major != 10 || build != 19045 {
            return Err("shared page OS version mismatch");
        }
        if qpc != frequency() {
            return Err("shared page QpcFrequency mismatch");
        }
        if cpus == 0 {
            return Err("shared page ActiveProcessorCount is zero");
        }
        if cookie == 0 {
            return Err("shared page Cookie is zero");
        }
        arch::xstate_self_test()?;
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

/// [`RtlGetEnabledExtendedFeatures`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetenabledextendedfeatures):
/// the components of `mask` the shared data page says are enabled, user
/// and supervisor, as Windows' routine reads them there.
#[allow(non_snake_case)]
pub extern "C" fn RtlGetEnabledExtendedFeatures(mask: u64) -> u64 {
    // SAFETY: the shared data page is mapped from boot on; aligned fields.
    unsafe {
        let page = SHARED_DATA as *const u8;
        let user = page
            .add(nk_ntabi::ke::SHARED_XSTATE_ENABLED)
            .cast::<u64>()
            .read_volatile();
        let supervisor = page
            .add(nk_ntabi::ke::SHARED_XSTATE_SUPERVISOR)
            .cast::<u64>()
            .read_volatile();
        (user | supervisor) & mask
    }
}

/// [`KeSaveExtendedProcessorState`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesaveextendedprocessorstate):
/// save the calling thread's extended processor state (x87, SSE, AVX) into a
/// buffer referenced by `xstate_save` so a driver may safely use vector units.
///
/// # Safety
/// `xstate_save` points to a writable caller-owned `XSTATE_SAVE` record that
/// remains valid until [`KeRestoreExtendedProcessorState`] is called on it.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeSaveExtendedProcessorState(
    mask: u64,
    xstate_save: *mut XSTATE_SAVE,
) -> NTSTATUS {
    if mask == 0 || xstate_save.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let enabled = arch::xstate_enabled_mask();
    if (mask & !enabled) != 0 {
        return STATUS_NOT_SUPPORTED;
    }
    let area_size = arch::xstate_area_size();
    let (raw, area) = if area_size > 0 {
        let raw = mm::pool::alloc(area_size + 64, u32::from_le_bytes(*b"XSta"));
        if raw.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let area = arch::xstate_align_area(raw);
        // SAFETY: `raw` is a fresh pool block of `area_size + 64` bytes, so
        // `area` is 64-byte aligned with `area_size` writable bytes. Zero the
        // buffer so `XSAVE_AREA_HEADER` starts clean before `xsave64`.
        unsafe {
            core::ptr::write_bytes(area, 0, area_size);
            arch::xstate_save_mask(area, mask);
        }
        (raw, area)
    } else {
        (core::ptr::null_mut(), core::ptr::null_mut())
    };
    // SAFETY: per the contract, `xstate_save` is a valid writable `XSTATE_SAVE`.
    unsafe {
        xstate_save.write(XSTATE_SAVE {
            Prev: core::ptr::null_mut(),
            Thread: super::thread::current().cast(),
            Level: super::irql::current() as i8,
            _pad: [0; 7],
            XStateContext: XSTATE_CONTEXT {
                Mask: mask,
                Length: area_size as u32,
                Reserved1: 0,
                Area: area.cast(),
                Buffer: raw.cast(),
            },
        });
    }
    STATUS_SUCCESS
}

/// [`KeRestoreExtendedProcessorState`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kerestoreextendedprocessorstate):
/// restore the extended processor state saved by [`KeSaveExtendedProcessorState`]
/// and release its save buffer.
///
/// # Safety
/// `xstate_save` was filled in by a matching successful call to
/// [`KeSaveExtendedProcessorState`] and has not yet been restored.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeRestoreExtendedProcessorState(xstate_save: *mut XSTATE_SAVE) {
    if xstate_save.is_null() {
        return;
    }
    // SAFETY: per the contract.
    unsafe {
        let ctx = &(*xstate_save).XStateContext;
        let area = ctx.Area.cast::<u8>();
        let raw = ctx.Buffer.cast::<u8>();
        let mask = ctx.Mask;
        if !area.is_null() {
            arch::xstate_restore_mask(area, mask);
        }
        if !raw.is_null() {
            let _ = mm::pool::free(raw);
        }
        (*xstate_save).XStateContext.Area = core::ptr::null_mut();
        (*xstate_save).XStateContext.Buffer = core::ptr::null_mut();
    }
}
