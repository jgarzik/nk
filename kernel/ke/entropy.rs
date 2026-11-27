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
use core::sync::atomic::{AtomicUsize, Ordering};
use nk_ntabi::ke::KENTROPY_TIMING_STATE;
use nk_ntabi::status::*;

/// The registered routine, `fn(buffer, length)`, or 0.
static ROUTINE: AtomicUsize = AtomicUsize::new(0);

/// Interrupts to a word of the buffer, words in it, and the interrupts
/// that fill a half.
const PER_WORD_SHIFT: u32 = 5;
const WORDS: u32 = 64;
const HALF_SHIFT: u32 = 10;
/// The bytes of a half, and of the state the initialisation routine is
/// shown.
const HALF_BYTES: usize = 0x80;
const STATE_BYTES: usize = 0x100;

/// One processor's timing state.
pub struct Timing(UnsafeCell<KENTROPY_TIMING_STATE>);

// SAFETY: a processor writes its own state only with interrupts off; the
// DPC that reads a half runs on the same processor, and a driver reads
// it only through the pointers it is given.
unsafe impl Sync for Timing {}

impl Timing {
    pub const fn new() -> Self {
        // SAFETY: integers, raw pointers and an absent routine: all zero
        // is a valid state, the one Windows starts each processor with.
        Self(UnsafeCell::new(unsafe { core::mem::zeroed() }))
    }

    fn get(&self) -> *mut KENTROPY_TIMING_STATE {
        self.0.get()
    }
}

/// Record this interrupt's time on this processor. Called as a device
/// interrupt's service routines are called, at its IRQL.
pub fn record() {
    let saved = arch::interrupts_off();
    let state = arch::percpu().entropy().get();
    let time = arch::counter() as u32;
    // SAFETY: this processor's state, with interrupts off: nothing else
    // on this processor writes it meanwhile, and no other processor does.
    let full = unsafe {
        let count = (&raw const (*state).EntropyCount).read();
        let word = (count % (WORDS << PER_WORD_SHIFT)) >> PER_WORD_SHIFT;
        let slot = (&raw mut (*state).Buffer).cast::<u32>().add(word as usize);
        slot.write(slot.read().rotate_right(5) ^ time);
        let count = count.wrapping_add(1);
        (&raw mut (*state).EntropyCount).write(count);
        count % (1 << HALF_SHIFT) == 0
    };
    arch::interrupts_restore(saved);
    if full && ROUTINE.load(Ordering::Acquire) != 0 {
        // SAFETY: the DPC was set up before the routine was published.
        unsafe {
            super::dpc::KeInsertQueueDpc(
                &raw mut (*state).Dpc,
                core::ptr::null_mut(),
                core::ptr::null_mut(),
            );
        }
    }
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
            ROUTINE.load(Ordering::Acquire),
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
    if ROUTINE.load(Ordering::Acquire) != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    for number in 0..super::smp::online_count() {
        let Some(cpu) = arch::percpu_of(number) else {
            continue;
        };
        let state = cpu.entropy().get();
        // SAFETY: the processor's state; its DPC is not queued before a
        // routine is published, so it may be set up here. The driver's
        // routine runs in the caller's context, as on Windows.
        unsafe {
            super::dpc::KeInitializeDpc(&raw mut (*state).Dpc, Some(deliver), state.cast());
            seh::call(
                initialize,
                [state.addr(), STATE_BYTES, context, 0],
                &Guard::Nothing,
            );
        }
    }
    match ROUTINE.compare_exchange(0, routine, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => STATUS_SUCCESS,
        Err(_) => STATUS_INVALID_PARAMETER,
    }
}
