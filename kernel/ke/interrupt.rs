//! Interrupt dispatch, the part every architecture shares.
//!
//! The architecture layer takes the interrupt from its controller and
//! calls [`dispatch`] with the vector and the IRQL that vector runs at.
//! The handler then runs at that IRQL with interrupts enabled, so a more
//! urgent interrupt can preempt it and nothing at its own level or below
//! can. The controller is told the interrupt is finished (EOI) before the
//! IRQL comes back down: until then it holds back everything of the same
//! or lower priority.
//!
//! A "vector" is what the controller calls the interrupt: the vector
//! number on x86-64, the interrupt id (INTID) on arm64.

use super::irql;
use crate::arch;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

pub type Handler = fn(vector: u32);

/// More than either architecture has: x86-64 has 256 vectors, a GIC
/// 1020 interrupt ids.
const VECTORS: usize = 1024;

static HANDLERS: [AtomicPtr<()>; VECTORS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; VECTORS];
/// Interrupts that arrived on a vector nothing had registered.
static STRAY: AtomicU32 = AtomicU32::new(0);

/// Have `handler` run for interrupts on `vector`, at IRQL `level`.
pub fn register(vector: u32, level: u8, handler: Handler) {
    HANDLERS[vector as usize].store(handler as *mut (), Ordering::Release);
    arch::interrupt_enable(vector, level);
}

/// Stop handling `vector`. An interrupt on it afterwards is a stray.
pub fn unregister(vector: u32) {
    HANDLERS[vector as usize].store(core::ptr::null_mut(), Ordering::Release);
}

/// How many interrupts have arrived on vectors without a handler.
pub fn strays() -> u32 {
    STRAY.load(Ordering::Relaxed)
}

/// Run the handler for an interrupt the controller has delivered. Called
/// by the architecture layer with interrupts disabled; `eoi` tells the
/// controller the interrupt is finished.
pub fn dispatch(vector: u32, level: u8, eoi: impl FnOnce()) {
    let old = irql::current();
    arch::set_irql(level);
    arch::enable_interrupts();
    let handler = HANDLERS
        .get(vector as usize)
        .map_or(core::ptr::null_mut(), |h| h.load(Ordering::Acquire));
    if handler.is_null() {
        // Report the first few; a storm of them must not bury the log.
        if STRAY.fetch_add(1, Ordering::Relaxed) < 4 {
            kprintln!("ke: stray interrupt on vector {vector:#x}");
        }
    } else {
        // SAFETY: the only non-null values stored are `Handler`s.
        let handler: Handler = unsafe { core::mem::transmute(handler) };
        handler(vector);
    }
    arch::disable_interrupts();
    eoi();
    // Back to the thread's own level: if a switch is wanted, this is the
    // place. The controller has been told the interrupt is over, and the
    // thread resumes here, inside the interrupt's frame on its own
    // stack, when it next runs.
    if old < irql::DISPATCH_LEVEL && super::thread::switch_wanted() {
        arch::set_irql(irql::DISPATCH_LEVEL);
        arch::enable_interrupts();
        super::thread::preempt();
        arch::disable_interrupts();
    } else if old >= irql::DISPATCH_LEVEL && vector != arch::DPC.0 && super::thread::switch_wanted()
    {
        // The interrupted code is at DISPATCH_LEVEL or above, so the
        // switch must wait; but nothing would look again when it comes
        // down. Leave the DISPATCH-level interrupt pending: it arrives
        // the moment the IRQL allows, and its end is the place above.
        arch::self_interrupt(arch::DPC.0);
    }
    arch::set_irql(old);
}

// ---- tests --------------------------------------------------------------

static COUNT: AtomicU32 = AtomicU32::new(0);
/// IRQL seen by the last handler run.
static SEEN_IRQL: AtomicU32 = AtomicU32::new(u32::MAX);
/// Order of events in the nesting tests, four bits each.
static TRACE: AtomicU32 = AtomicU32::new(0);
/// What the handler on the low vector should do besides counting.
static LOW_FIRES_HIGH: AtomicU32 = AtomicU32::new(0);
static HIGH_FIRES_LOW: AtomicU32 = AtomicU32::new(0);

fn trace(event: u32) {
    let _ = TRACE.try_update(Ordering::Relaxed, Ordering::Relaxed, |t| {
        Some(t << 4 | event)
    });
}

fn low_handler(_: u32) {
    SEEN_IRQL.store(u32::from(irql::current()), Ordering::Relaxed);
    trace(1);
    if LOW_FIRES_HIGH.swap(0, Ordering::Relaxed) != 0 {
        arch::self_interrupt(arch::TEST_HIGH.0);
        settle();
    }
    trace(2);
    COUNT.fetch_add(1, Ordering::Relaxed);
}

fn high_handler(_: u32) {
    trace(3);
    if HIGH_FIRES_LOW.swap(0, Ordering::Relaxed) != 0 {
        arch::self_interrupt(arch::TEST_LOW.0);
        settle();
    }
    trace(4);
}

/// Give an interrupt this processor sent itself time to arrive, if it is
/// going to: delivery may lag the request by a few instructions.
fn settle() {
    for _ in 0..20_000 {
        core::hint::spin_loop();
    }
}

/// Interrupts arrive once, at their IRQL, are held off while the IRQL is
/// at or above theirs, nest by priority, and a stray one is survived.
pub fn self_test() -> Result<(), &'static str> {
    let (low, low_level) = arch::TEST_LOW;
    let (high, high_level) = arch::TEST_HIGH;
    let (stray, stray_level) = arch::TEST_STRAY;
    register(low, low_level, low_handler);
    register(high, high_level, high_handler);
    let check = || {
        // Delivered once, at its level, and the level comes back down.
        COUNT.store(0, Ordering::Relaxed);
        arch::self_interrupt(low);
        settle();
        if COUNT.load(Ordering::Relaxed) != 1 {
            return Err("a self-interrupt did not arrive exactly once");
        }
        if SEEN_IRQL.load(Ordering::Relaxed) != u32::from(low_level) {
            return Err("the handler did not run at its vector's IRQL");
        }
        if irql::current() != irql::PASSIVE_LEVEL {
            return Err("the IRQL did not return to PASSIVE_LEVEL after the interrupt");
        }
        // A second one arrives too: the controller was told the first
        // had finished.
        arch::self_interrupt(low);
        settle();
        if COUNT.load(Ordering::Relaxed) != 2 {
            return Err("a second interrupt on the same vector did not arrive");
        }

        // Held off while the IRQL is at its level, delivered on lowering.
        let old = irql::raise(low_level);
        arch::self_interrupt(low);
        settle();
        let early = COUNT.load(Ordering::Relaxed);
        irql::lower(old);
        settle();
        if early != 2 {
            return Err("an interrupt arrived while the IRQL was at its level");
        }
        if COUNT.load(Ordering::Relaxed) != 3 {
            return Err("an interrupt held off by the IRQL was lost");
        }

        // A more urgent interrupt preempts a handler...
        TRACE.store(0, Ordering::Relaxed);
        LOW_FIRES_HIGH.store(1, Ordering::Relaxed);
        arch::self_interrupt(low);
        settle();
        if TRACE.load(Ordering::Relaxed) != 0x1342 {
            return Err("a higher-priority interrupt did not preempt a handler");
        }
        // ...and a less urgent one waits for it to finish.
        TRACE.store(0, Ordering::Relaxed);
        HIGH_FIRES_LOW.store(1, Ordering::Relaxed);
        arch::self_interrupt(high);
        settle();
        if TRACE.load(Ordering::Relaxed) != 0x3412 {
            return Err("a lower-priority interrupt did not wait for a handler to finish");
        }

        // An interrupt nobody handles is counted and survived.
        let before = strays();
        arch::interrupt_enable(stray, stray_level);
        arch::self_interrupt(stray);
        settle();
        if strays() != before + 1 {
            return Err("a stray interrupt was not counted once");
        }
        Ok(())
    };
    let verdict = check();
    unregister(low);
    unregister(high);
    verdict
}
