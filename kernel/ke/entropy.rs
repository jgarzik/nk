//! Interrupt-timing entropy: each processor folds the cycle count at
//! which its device interrupts arrive into a buffer of its own, and a
//! driver's routine is handed each half of it as it fills, as the pinned
//! kernel does for `cng.sys` (`KeInitializeEntropySystem`,
//! `KiScanInterruptObjectList`, `KiEntropyDpcRoutine`).
//!
//! Each processor's [`KENTROPY_TIMING_STATE`] lives in its `PerCpu`.
//! An interrupt takes the word the count names (32 interrupts to a word,
//! 64 words), rotates it right by five and XORs in the low half of the
//! cycle count; every 1024th interrupt fills a half, and once a routine
//! is registered a DPC on that processor hands the full half (128 bytes)
//! to it.

use super::seh::{self, Guard, Unhandled};
use crate::arch;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use nk_ntabi::ke::KENTROPY_TIMING_STATE;
use nk_ntabi::status::*;

/// Interrupts to a word of the buffer, words in it, and the interrupts
/// that fill a half.
const PER_WORD_SHIFT: u32 = 5;
const WORDS: u32 = 64;
const HALF_SHIFT: u32 = 10;
/// The bytes of a half, and of the state the initialisation routine is
/// shown.
const HALF_BYTES: usize = 0x80;
const STATE_BYTES: usize = 0x100;

/// Per-processor timing state gate: idle, being updated by `record`, or
/// exclusively owned by `register` during one-time initialisation.
const GATE_IDLE: u8 = 0;
const GATE_RECORDING: u8 = 1;
const GATE_INITIALIZING: u8 = 2;

/// One registration slot: claimed once before any per-processor state is
/// touched, then published after every processor's state is initialised.
struct Registry {
    claimed: AtomicBool,
    routine: AtomicUsize,
}

impl Registry {
    const fn new() -> Self {
        Self {
            claimed: AtomicBool::new(false),
            routine: AtomicUsize::new(0),
        }
    }

    /// Claim registration, initialise every processor's timing state in
    /// `timings` exclusively against its interrupt path, and publish
    /// `routine`. A second caller (concurrent or later) or a null routine
    /// receives `STATUS_INVALID_PARAMETER` without touching shared state.
    ///
    /// # Safety
    /// `routine` and `initialize` are callable functions of the forms
    /// expected by `KeInitializeEntropySystem`.
    unsafe fn register_on<'a>(
        &self,
        timings: impl IntoIterator<Item = &'a Timing>,
        routine: usize,
        initialize: usize,
        context: usize,
    ) -> NTSTATUS {
        if routine == 0 || initialize == 0 || self.claimed.swap(true, Ordering::AcqRel) {
            return STATUS_INVALID_PARAMETER;
        }
        for timing in timings {
            while timing
                .gate
                .compare_exchange(
                    GATE_IDLE,
                    GATE_INITIALIZING,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_err()
            {
                core::hint::spin_loop();
            }
            let state = timing.get();
            // SAFETY: exclusive ownership while `gate == GATE_INITIALIZING`
            // and before `routine` is published (so `deliver` cannot run).
            // The driver's routine runs in the caller's context, as on
            // Windows.
            unsafe {
                super::dpc::KeInitializeDpc(&raw mut (*state).Dpc, Some(deliver), state.cast());
                seh::call(
                    initialize,
                    [state.addr(), STATE_BYTES, context, 0],
                    &Guard::Nothing,
                );
            }
            timing.gate.store(GATE_IDLE, Ordering::Release);
        }
        self.routine.store(routine, Ordering::Release);
        STATUS_SUCCESS
    }
}

/// The system's entropy registration.
static SYSTEM: Registry = Registry::new();

/// One processor's timing state.
pub struct Timing {
    gate: AtomicU8,
    state: UnsafeCell<KENTROPY_TIMING_STATE>,
}

// SAFETY: a processor writes its own state only while holding `gate ==
// GATE_RECORDING` with interrupts off; one-time registration holds
// `gate == GATE_INITIALIZING` before `routine` is published; the DPC
// runs on the owning processor after publication.
unsafe impl Sync for Timing {}

impl Timing {
    pub const fn new() -> Self {
        Self {
            gate: AtomicU8::new(GATE_IDLE),
            // SAFETY: integers, raw pointers and an absent routine: all zero
            // is a valid state, the one Windows starts each processor with.
            state: UnsafeCell::new(unsafe { core::mem::zeroed() }),
        }
    }

    fn get(&self) -> *mut KENTROPY_TIMING_STATE {
        self.state.get()
    }

    /// Fold one interrupt timestamp into this state. Skips the sample if
    /// registration is currently initialising this state rather than
    /// spinning with interrupts masked.
    fn record_sample(&self, routine: &AtomicUsize, queue_dpc: bool) {
        let saved = arch::interrupts_off();
        let full = if self
            .gate
            .compare_exchange(
                GATE_IDLE,
                GATE_RECORDING,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_ok()
        {
            let state = self.get();
            let time = arch::counter() as u32;
            // SAFETY: exclusive ownership while `gate == GATE_RECORDING`
            // with interrupts masked on this processor.
            let full = unsafe {
                let count = (&raw const (*state).EntropyCount).read();
                let word = (count % (WORDS << PER_WORD_SHIFT)) >> PER_WORD_SHIFT;
                let slot = (&raw mut (*state).Buffer).cast::<u32>().add(word as usize);
                slot.write(slot.read().rotate_right(5) ^ time);
                let count = count.wrapping_add(1);
                (&raw mut (*state).EntropyCount).write(count);
                count % (1 << HALF_SHIFT) == 0
            };
            self.gate.store(GATE_IDLE, Ordering::Release);
            full
        } else {
            false
        };
        arch::interrupts_restore(saved);
        if queue_dpc && full && routine.load(Ordering::Acquire) != 0 {
            // SAFETY: the DPC was set up before `routine` was published.
            unsafe {
                super::dpc::KeInsertQueueDpc(
                    &raw mut (*self.get()).Dpc,
                    core::ptr::null_mut(),
                    core::ptr::null_mut(),
                );
            }
        }
    }
}

/// Record this interrupt's time on this processor. Called as a device
/// interrupt's service routines are called, at its IRQL.
pub fn record() {
    arch::percpu()
        .entropy()
        .record_sample(&SYSTEM.routine, true);
}

/// `KiEntropyDpcRoutine`: hand the routine the half the count last
/// filled, unless it already had it.
///
/// # Safety
/// Run as the DPC of a processor's timing state, with that state as its
/// context, on that processor, once a routine is registered.
unsafe extern "C" fn deliver(
    _dpc: *mut nk_ntabi::ke::KDPC,
    context: *mut c_void,
    _argument1: *mut c_void,
    _argument2: *mut c_void,
) {
    let state = context.cast::<KENTROPY_TIMING_STATE>();
    // SAFETY: the state of the processor this DPC runs on, which only
    // its interrupts write, and they write the other half.
    unsafe {
        let count = (&raw const (*state).EntropyCount).read();
        let half = ((count >> HALF_SHIFT).wrapping_sub(1)) & 1;
        if half == (&raw const (*state).LastDeliveredBuffer).read() {
            return;
        }
        let buffer = (&raw mut (*state).Buffer)
            .cast::<u8>()
            .add(half as usize * HALF_BYTES);
        // The driver's routine, at DISPATCH_LEVEL; nothing beneath it
        // can handle an exception it lets out.
        seh::call(
            SYSTEM.routine.load(Ordering::Acquire),
            [buffer.addr(), HALF_BYTES, 0, 0],
            &Guard::Base(Unhandled::KernelMode),
        );
        (&raw mut (*state).LastDeliveredBuffer).write(half);
    }
}

/// `KeInitializeEntropySystem`, which `ZwSetSystemInformation`'s class
/// `SystemEntropyInterruptTimingInformation` reaches: register `routine`
/// for the halves to come, having run `initialize(state, 0x100,
/// context)` over each processor's state. One routine only: a second
/// registration is `STATUS_INVALID_PARAMETER`.
///
/// # Safety
/// `routine` and `initialize` are the driver's functions of those
/// forms, callable from now on.
pub unsafe fn register(routine: usize, initialize: usize, context: usize) -> NTSTATUS {
    let timings =
        (0..super::smp::online_count()).filter_map(|n| Some(arch::percpu_of(n)?.entropy()));
    // SAFETY: per the contract.
    unsafe { SYSTEM.register_on(timings, routine, initialize, context) }
}

// ---- tests --------------------------------------------------------------

/// Concurrent callers racing `register` elect a single winner before any
/// per-CPU DPC or timing state is touched, and initialisation is
/// synchronised against concurrent `record` calls on each processor.
pub fn self_test() -> Result<(), &'static str> {
    use super::thread;
    use alloc::boxed::Box;
    use core::sync::atomic::AtomicU32;

    struct Fixture {
        registry: Registry,
        timings: [Timing; 2],
        init_calls: AtomicU32,
        init_saw_published: AtomicBool,
        init_saw_record_race: AtomicBool,
        wins: AtomicU32,
        rejects: AtomicU32,
        stop_recording: AtomicBool,
        start: AtomicBool,
    }

    extern "C" fn dummy_routine(_: *mut c_void, _: usize) {}

    extern "C" fn test_init(state: *mut KENTROPY_TIMING_STATE, size: usize, context: usize) {
        // SAFETY: `context` points to the live `Fixture` until all threads exit.
        let fx = unsafe { &*(context as *const Fixture) };
        if size != STATE_BYTES || fx.registry.routine.load(Ordering::Acquire) != 0 {
            fx.init_saw_published.store(true, Ordering::Release);
        }
        fx.init_calls.fetch_add(1, Ordering::AcqRel);
        // Hold ownership across yields so both a racing `register` and a
        // racing `record_sample` collide with initialisation.
        // SAFETY: exclusive ownership while `gate == GATE_INITIALIZING`.
        let before = unsafe { (&raw const (*state).EntropyCount).read() };
        for _ in 0..8 {
            thread::yield_now();
        }
        // SAFETY: as above.
        let after = unsafe { (&raw const (*state).EntropyCount).read() };
        if before != after {
            fx.init_saw_record_race.store(true, Ordering::Release);
        }
    }

    fn registrar(arg: usize) {
        // SAFETY: `arg` points to the live `Fixture`.
        let fx = unsafe { &*(arg as *const Fixture) };
        while !fx.start.load(Ordering::Acquire) {
            thread::yield_now();
        }
        // SAFETY: valid test callbacks.
        let status = unsafe {
            fx.registry.register_on(
                fx.timings.iter(),
                dummy_routine as *const () as usize,
                test_init as *const () as usize,
                arg,
            )
        };
        if status == STATUS_SUCCESS {
            fx.wins.fetch_add(1, Ordering::AcqRel);
        } else if status == STATUS_INVALID_PARAMETER {
            fx.rejects.fetch_add(1, Ordering::AcqRel);
        }
    }

    fn recorder(arg: usize) {
        // SAFETY: `arg` points to the live `Fixture`.
        let fx = unsafe { &*(arg as *const Fixture) };
        while !fx.stop_recording.load(Ordering::Acquire) {
            for t in &fx.timings {
                t.record_sample(&fx.registry.routine, false);
            }
            thread::yield_now();
        }
    }

    let fx = Box::new(Fixture {
        registry: Registry::new(),
        timings: [Timing::new(), Timing::new()],
        init_calls: AtomicU32::new(0),
        init_saw_published: AtomicBool::new(false),
        init_saw_record_race: AtomicBool::new(false),
        wins: AtomicU32::new(0),
        rejects: AtomicU32::new(0),
        stop_recording: AtomicBool::new(false),
        start: AtomicBool::new(false),
    });
    let ptr = core::ptr::from_ref(&*fx).addr();

    // Null routine is rejected without claiming the registry.
    // SAFETY: rejected before any callback is invoked.
    let null_status = unsafe {
        fx.registry
            .register_on(fx.timings.iter(), 0, test_init as *const () as usize, ptr)
    };
    if null_status != STATUS_INVALID_PARAMETER {
        return Err("null entropy routine was not rejected");
    }

    let before = thread::count();
    let t_rec =
        thread::create_referenced(recorder, ptr, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    let t1 = thread::create_referenced(registrar, ptr, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    let t2 = thread::create_referenced(registrar, ptr, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    fx.start.store(true, Ordering::Release);

    for t in [t1, t2] {
        // SAFETY: referenced thread object.
        unsafe {
            super::wait::wait(Some(t.cast()), None);
            crate::ob::object::dereference(t.cast());
        }
    }
    fx.stop_recording.store(true, Ordering::Release);
    // SAFETY: referenced thread object.
    unsafe {
        super::wait::wait(Some(t_rec.cast()), None);
        crate::ob::object::dereference(t_rec.cast());
    }
    thread::settle(before);

    // A later call is also rejected without touching `initialize`.
    // SAFETY: valid test callbacks.
    let late = unsafe {
        fx.registry.register_on(
            fx.timings.iter(),
            dummy_routine as *const () as usize,
            test_init as *const () as usize,
            ptr,
        )
    };
    if late != STATUS_INVALID_PARAMETER {
        return Err("a second entropy registration after completion was not rejected");
    }
    if fx.wins.load(Ordering::Acquire) != 1 || fx.rejects.load(Ordering::Acquire) != 1 {
        return Err("concurrent entropy registration did not elect exactly one winner");
    }
    if fx.init_calls.load(Ordering::Acquire) != 2 {
        return Err("entropy initializer did not run exactly once per processor");
    }
    if fx.init_saw_published.load(Ordering::Acquire) {
        return Err("entropy initializer ran after routine was published");
    }
    if fx.init_saw_record_race.load(Ordering::Acquire) {
        return Err("record() mutated timing state concurrently with register()");
    }
    if fx.registry.routine.load(Ordering::Acquire) != dummy_routine as *const () as usize {
        return Err("published entropy routine does not match the winner");
    }
    Ok(())
}
