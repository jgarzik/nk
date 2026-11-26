//! Tests of walking a kernel stack.
//!
//! Each walk starts in a function of this file and must pass through
//! the functions of this file known to be beneath it, in order, cross
//! whatever lies between (an interrupt frame, the change of stack around
//! a DPC routine), and end at the base of the thread's stack.

use crate::arch;
use crate::ke::dpc::{KeInitializeDpc, KeInsertQueueDpc};
use crate::ke::unwind::{Frame, WalkError, walk};
use crate::ke::{interrupt, irql, thread};
use crate::mm::stack::Stack;
use crate::test::{Group, Report, Slot};
use core::ffi::c_void;
use core::hint::black_box;
use core::sync::atomic::{AtomicBool, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::ke::{KDEFERRED_ROUTINE, KDPC};

pub static GROUP: Group = Group {
    names: &["seh.walk.thread", "seh.walk.dpc", "seh.walk.interrupt"],
    run,
    manual: false,
};

/// Frames kept of one walk: several times what the deepest takes.
const MAX: usize = 64;

/// One walk: its frames, innermost first, and how it ended.
struct Trace {
    frames: [Frame; MAX],
    /// Frames visited, which may be more than were kept.
    count: usize,
    end: Result<usize, WalkError>,
    /// The DPC stack of the processor the walk ran on, if it ran at
    /// `DISPATCH_LEVEL` or above.
    dpc_stack: Option<Stack>,
}

impl Trace {
    const fn new() -> Self {
        Self {
            frames: [Frame {
                pc: 0,
                sp: 0,
                function: None,
                interrupted: false,
            }; MAX],
            count: 0,
            end: Ok(0),
            dpc_stack: None,
        }
    }

    /// Walk the stack of the function this is written in.
    #[inline(always)]
    fn record(&mut self) {
        let regs = arch::unwind::capture();
        let (frames, count) = (&mut self.frames, &mut self.count);
        self.end = walk(&regs, false, |frame| {
            if let Some(slot) = frames.get_mut(*count) {
                *slot = *frame;
            }
            *count += 1;
        });
        if irql::current() >= irql::DISPATCH_LEVEL {
            self.dpc_stack = Some(arch::percpu().dpcs().stack());
        }
    }

    fn frames(&self) -> &[Frame] {
        &self.frames[..self.count.min(MAX)]
    }

    /// Index of the first frame at or after `from` that is in the
    /// function at `function`.
    fn find(&self, function: usize, from: usize) -> Option<usize> {
        let frames = self.frames().get(from..)?;
        let at = frames
            .iter()
            .position(|f| f.function == Some(function as u64))?;
        Some(from + at)
    }

    /// What every walk must show: it reached the end of the stack, which
    /// is the top of this thread's; the frames were all kept; and only
    /// the frames an interrupt stopped (`interrupts` of them) may be
    /// without an unwind entry.
    fn complete(&self, interrupts: usize) -> Result<(), &'static str> {
        if let Err(why) = self.end {
            kprintln!("seh: a walk stopped after {} frames: {why}", self.count);
        }
        if self.end != Ok(self.count) || self.count == 0 {
            return Err("the walk did not reach the end of the stack");
        }
        if self.count > MAX {
            return Err("the walk visited more frames than the test keeps");
        }
        let frames = self.frames();
        let stack = thread::current_stack();
        // The start stub's frame: a few words below the top.
        let last = frames[frames.len() - 1];
        if !(stack.top - 0x100..stack.top).contains(&last.sp) {
            return Err("the walk did not end at the top of the thread's stack");
        }
        if frames.iter().filter(|f| f.interrupted).count() != interrupts {
            return Err("the walk did not cross the interrupt frame it was beneath");
        }
        if frames
            .iter()
            .any(|f| f.function.is_none() && !f.interrupted)
        {
            return Err("a frame that made a call was walked as a leaf");
        }
        Ok(())
    }
}

/// The walk made by an interrupt handler or DPC routine, and whether it
/// has been made. The thread that asked writes the trace before asking
/// and reads it once `DONE` is set; the routine writes it in between.
static TRACE: Slot<Trace> = Slot::new();
static DONE: AtomicBool = AtomicBool::new(false);
static WALK_DPC: Slot<KDPC> = Slot::new();

/// Clear the shared trace before asking for a walk.
fn arm() {
    // SAFETY: no routine is using the slot: the last one asked for has
    // finished.
    unsafe { TRACE.ptr().write(Trace::new()) };
    DONE.store(false, Ordering::Release);
}

/// The shared trace, once the routine asked for has run.
fn collect() -> Result<&'static Trace, &'static str> {
    for _ in 0..50_000_000u32 {
        if DONE.load(Ordering::Acquire) {
            // SAFETY: the routine has finished writing, and nothing
            // writes again until the next `arm`.
            return Ok(unsafe { &*TRACE.ptr() });
        }
        core::hint::spin_loop();
    }
    Err("the routine that was to walk the stack did not run")
}

// ---- from a thread ------------------------------------------------------

type Level = fn(&mut Trace) -> u64;

#[inline(never)]
fn outer(trace: &mut Trace) -> u64 {
    black_box(middle(trace)) + 1
}

#[inline(never)]
fn middle(trace: &mut Trace) -> u64 {
    black_box(inner(trace)) + 2
}

#[inline(never)]
fn inner(trace: &mut Trace) -> u64 {
    trace.record();
    black_box(3)
}

fn thread_walk() -> Result<usize, &'static str> {
    let mut trace = Trace::new();
    outer(&mut trace);
    trace.complete(0)?;
    let chain = [inner as Level, middle, outer];
    for (at, function) in chain.into_iter().enumerate() {
        if trace.frames()[at].function != Some(function as usize as u64) {
            return Err("the first frames are not the functions that made the calls");
        }
    }
    Ok(trace.count)
}

// ---- from a DPC routine -------------------------------------------------

/// The DPC routine: walk from here.
///
/// # Safety
/// Called as a DPC routine with the shared trace armed.
#[inline(never)]
unsafe extern "C" fn in_dpc(_: *mut KDPC, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
    // SAFETY: the thread that armed the trace leaves it alone until
    // `DONE` is set.
    unsafe { (*TRACE.ptr()).record() };
    DONE.store(true, Ordering::Release);
}

/// Queue the DPC. Below `DISPATCH_LEVEL` it runs before the insert
/// returns, so this function's frame is beneath the routine's.
#[inline(never)]
fn queue_dpc() -> u8 {
    // SAFETY: static storage for a `KDPC`, not queued.
    let queued = unsafe {
        KeInitializeDpc(WALK_DPC.ptr(), Some(in_dpc), core::ptr::null_mut());
        KeInsertQueueDpc(WALK_DPC.ptr(), core::ptr::null_mut(), core::ptr::null_mut())
    };
    black_box(queued)
}

fn dpc_walk() -> Result<usize, &'static str> {
    arm();
    if queue_dpc() == 0 {
        return Err("the DPC was refused");
    }
    let trace = collect()?;
    trace.complete(1)?;
    let routine = in_dpc as KDEFERRED_ROUTINE as usize;
    if trace.frames()[0].function != Some(routine as u64) {
        return Err("the first frame is not the DPC routine");
    }
    let on = |stack: Stack, frame: &Frame| (stack.base..stack.top).contains(&frame.sp);
    if !trace.dpc_stack.is_some_and(|s| on(s, &trace.frames()[0])) {
        return Err("the DPC routine's frame is not on the DPC stack");
    }
    // Beneath the routine: off the DPC stack, through the interrupt, to
    // the function that queued.
    let queued = trace
        .find(queue_dpc as fn() -> u8 as usize, 1)
        .ok_or("the function that queued the DPC is not beneath its routine")?;
    let interrupt = trace.frames().iter().position(|f| f.interrupted);
    if !interrupt.is_some_and(|at| at <= queued) {
        return Err("the interrupt frame is not between the DPC routine and what it interrupted");
    }
    if !on(thread::current_stack(), &trace.frames()[queued]) {
        return Err("the walk did not cross from the DPC stack to the thread's");
    }
    Ok(trace.count)
}

// ---- from an interrupt handler ------------------------------------------

/// The interrupt handler: walk from here.
#[inline(never)]
fn in_interrupt(_: u32) {
    // SAFETY: the thread that armed the trace leaves it alone until
    // `DONE` is set.
    unsafe { (*TRACE.ptr()).record() };
    DONE.store(true, Ordering::Release);
}

/// Take the test interrupt and wait for its handler, staying on this
/// processor meanwhile: the interrupt stops this function or something
/// it called.
#[inline(never)]
fn take_interrupt() -> Result<&'static Trace, &'static str> {
    let old = irql::raise(irql::DISPATCH_LEVEL);
    arch::self_interrupt(arch::TEST_LOW.0);
    let trace = collect();
    irql::lower(old);
    black_box(trace)
}

fn interrupt_walk() -> Result<usize, &'static str> {
    let (vector, level) = arch::TEST_LOW;
    arm();
    interrupt::register(vector, level, in_interrupt);
    let trace = take_interrupt();
    interrupt::unregister(vector);
    let trace = trace?;
    trace.complete(1)?;
    if trace.frames()[0].function != Some(in_interrupt as fn(u32) as usize as u64) {
        return Err("the first frame is not the interrupt handler");
    }
    let interrupted = trace
        .frames()
        .iter()
        .position(|f| f.interrupted)
        .ok_or("no frame is the interrupted code")?;
    let taker = take_interrupt as fn() -> Result<&'static Trace, &'static str> as usize;
    if trace.find(taker, interrupted).is_none() {
        return Err("the function that took the interrupt is not beneath its handler");
    }
    Ok(trace.count)
}

fn walked(r: &mut Report, name: &str, result: Result<usize, &'static str>) {
    match result {
        Ok(frames) => r.ok_with(name, format_args!("frames: {frames}")),
        Err(why) => r.fail(name, format_args!("{why}")),
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    walked(r, "seh.walk.thread", thread_walk());
    walked(r, "seh.walk.dpc", dpc_walk());
    walked(r, "seh.walk.interrupt", interrupt_walk());
}
