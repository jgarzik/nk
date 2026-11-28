//! Walking a kernel stack by the images' function tables.
//!
//! A walk starts from a register set (`arch::unwind::capture`) and
//! undoes one frame at a time: find the image the program counter is
//! in, find the function's entry in that image's `.pdata`, and let
//! `nk_unwind` compute the registers of the frame beneath. It crosses
//! whatever the tables describe: compiled functions, the assembly
//! stubs, the change of stack around DPC routines, interrupt frames.
//!
//! The walk ends at a frame that returns to address zero: every stack
//! is entered as if called from address zero (`doc/design/image.md`, "Unwind
//! tables"). Code an interrupt stopped at address zero is not the end:
//! it was called through a null pointer, and is in no image.
//!
//! Three things make it fail instead of guess:
//!
//! - **Stack reads are bounded.** A slot is read only if it lies on the
//!   running thread's stack or, at `DISPATCH_LEVEL` and above, on this
//!   processor's DPC stack. Anything else ends the walk.
//! - **Images are read through their views** (`ldr::view`), whole and
//!   constant, so unwind data that points anywhere in its image reads
//!   bytes, never a fault.
//! - **A function with no entry is a leaf only where a leaf can be.** A
//!   leaf calls nothing, so the only place for one is right beneath an
//!   interrupt frame: the code the interrupt stopped. Every other frame
//!   is waiting for a call to return, so its function made a frame and
//!   must have an entry: a missing one (the prebuilt `core` and `alloc`
//!   have none) ends the walk, naming the place. Beneath an interrupt
//!   frame the two cannot be told apart: an interrupted function without
//!   an entry is taken for a leaf, which a prebuilt one need not be.

use super::irql;
use crate::arch::unwind::{self, Regs};
use crate::mm::stack::Stack;
use crate::{arch, ldr};
use core::fmt;
use nk_pe::modules::Module;
use nk_unwind::UnwindError;

/// Frames a walk visits before it gives up: more than fit on two stacks.
const MAX_FRAMES: usize = 4096;

/// One frame of a walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    /// Where the frame resumes: a return address, or the instruction an
    /// interrupt stopped at.
    pub pc: u64,
    pub sp: u64,
    /// Address of the start of the function `pc` is in; `None` for a
    /// leaf, which has no entry to say.
    pub function: Option<u64>,
    /// `pc` is where an interrupt stopped the frame, not a return
    /// address.
    pub interrupted: bool,
}

/// Why a walk stopped before the end of the stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkError {
    /// A program counter that is in no loaded image.
    NoImage { pc: u64 },
    /// Code that is waiting for a call to return and has no unwind
    /// entry.
    NoEntry { module: Module, offset: u64 },
    /// The frame could not be undone: bad unwind data, or a stack slot
    /// outside the stacks.
    Unwind {
        module: Module,
        offset: u64,
        error: UnwindError,
    },
    /// More frames than any stack holds.
    TooDeep,
}

impl fmt::Display for WalkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn name(module: &Module) -> &str {
            core::str::from_utf8(module.name()).unwrap_or("?")
        }
        match self {
            Self::NoImage { pc } => write!(f, "{pc:#x} is in no image"),
            Self::NoEntry { module, offset } => {
                write!(f, "{}+{offset:#x} has no unwind entry", name(module))
            }
            Self::Unwind {
                module,
                offset,
                error,
            } => write!(f, "{}+{offset:#x}: {error:?}", name(module)),
            Self::TooDeep => f.write_str("too many frames"),
        }
    }
}

/// The stacks code on this processor can be running on right now: the
/// thread's own, the segments it holds (`ke::expand`), and at
/// `DISPATCH_LEVEL` the processor's DPC stack.
pub(super) type Stacks = [Option<Stack>; 2 * super::thread::MAX_SEGMENTS + 3];

pub(super) fn stacks() -> Stacks {
    let mut stacks: Stacks = [None; 2 * super::thread::MAX_SEGMENTS + 3];
    for (slot, stack) in stacks.iter_mut().zip(super::thread::current_stacks()) {
        *slot = Some(stack);
    }
    // The DPC stack is the processor's, and a thread below
    // DISPATCH_LEVEL can change processors; but it is not on any DPC
    // stack either.
    if irql::current() >= irql::DISPATCH_LEVEL {
        stacks[2 * super::thread::MAX_SEGMENTS + 2] = Some(arch::percpu().dpcs().stack());
    }
    stacks
}

/// The stack `address` is on, if code on this processor can be
/// running on it right now.
pub fn stack_holding(address: u64) -> Option<Stack> {
    stacks()
        .into_iter()
        .flatten()
        .find(|stack| stack.base <= address && address < stack.top)
}

/// Read the stack slot at `address`, if it is one.
pub(super) fn read_slot(stacks: &Stacks, address: u64) -> Option<u64> {
    let on = |stack: &Stack| {
        address
            .checked_add(8)
            .is_some_and(|end| stack.base <= address && end <= stack.top)
    };
    if !address.is_multiple_of(8) || !stacks.iter().flatten().any(on) {
        return None;
    }
    // SAFETY: an aligned slot inside a kernel stack, which is mapped for
    // as long as its thread or processor exists; both are running this.
    Some(unsafe { (address as *const u64).read_volatile() })
}

/// Walk the current stack from `start`, calling `visit` with each frame,
/// innermost first. Returns the number of frames once the walk reaches
/// the end of the stack.
///
/// `start` is a capture, or the registers of code an interrupt stopped
/// (`interrupted`); the frames it describes must still be live: call
/// this from the function that captured, or from one it calls.
pub fn walk(
    start: &Regs,
    interrupted: bool,
    mut visit: impl FnMut(&Frame),
) -> Result<usize, WalkError> {
    let stacks = stacks();
    let mut read = |address| read_slot(&stacks, address);
    let (mut regs, mut interrupted) = (*start, interrupted);
    for count in 0..MAX_FRAMES {
        let (pc, sp) = (unwind::pc(&regs), unwind::sp(&regs));
        if pc == 0 && !interrupted {
            return Ok(count);
        }
        let module = ldr::module_containing(pc).ok_or(WalkError::NoImage { pc })?;
        let offset = pc - module.base;
        // SAFETY: the image's code is on the stack being walked, which
        // is this thread's own: it cannot be unloaded meanwhile.
        let image = unsafe { ldr::view(&module) };
        let step = unwind::step(
            image,
            module.pdata,
            offset as u32,
            &regs,
            !interrupted,
            &mut read,
        );
        let failed = |error| WalkError::Unwind {
            module,
            offset,
            error,
        };
        let mut frame = Frame {
            pc,
            sp,
            function: None,
            interrupted,
        };
        match step.map_err(failed)? {
            Some(step) => {
                frame.function = Some(module.base + u64::from(step.function));
                (regs, interrupted) = (step.regs, step.interrupted);
            }
            // Only interrupted code can be a leaf.
            None if interrupted => {
                regs = unwind::leaf(&regs, &mut read).map_err(failed)?;
                interrupted = false;
            }
            None => return Err(WalkError::NoEntry { module, offset }),
        }
        visit(&frame);
    }
    Err(WalkError::TooDeep)
}

/// [`RtlCaptureStackBackTrace`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlcapturestackbacktrace):
/// walk the calling thread's stack, skipping `frames_to_skip` frames above
/// this call, and store up to `frames_to_capture` return addresses into
/// `back_trace`. Returns the number of frames captured.
///
/// # Safety
/// `back_trace` is writable for `frames_to_capture` pointers;
/// `back_trace_hash` is null or writable.
#[allow(non_snake_case)]
#[inline(never)]
pub unsafe extern "C" fn RtlCaptureStackBackTrace(
    frames_to_skip: u32,
    frames_to_capture: u32,
    back_trace: *mut *mut core::ffi::c_void,
    back_trace_hash: *mut u32,
) -> u16 {
    if back_trace.is_null() || frames_to_capture == 0 {
        if !back_trace_hash.is_null() {
            // SAFETY: per the contract.
            unsafe { back_trace_hash.write_unaligned(0) };
        }
        return 0;
    }
    let regs = unwind::capture();
    let skip = (frames_to_skip as usize).saturating_add(1);
    let max = (frames_to_capture as usize).min(usize::from(u16::MAX));
    let mut seen = 0usize;
    let mut captured = 0usize;
    let mut hash = 0u32;
    let _ = walk(&regs, false, |frame| {
        if seen >= skip && captured < max {
            // SAFETY: `back_trace` has room for `frames_to_capture` pointers.
            unsafe {
                back_trace
                    .add(captured)
                    .write_unaligned(frame.pc as usize as *mut core::ffi::c_void);
            }
            hash = hash.wrapping_add(frame.pc as u32);
            captured += 1;
        }
        seen += 1;
    });
    if !back_trace_hash.is_null() {
        // SAFETY: per the contract.
        unsafe { back_trace_hash.write_unaligned(hash) };
    }
    captured as u16
}

/// [`RtlCaptureContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlcapturecontext):
/// capture the caller's register context into `context` (for telemetry and
/// crash diagnostics).
///
/// # Safety
/// `context` is writable for a `CONTEXT` structure.
#[allow(non_snake_case)]
#[inline(never)]
pub unsafe extern "C" fn RtlCaptureContext(context: *mut core::ffi::c_void) {
    if context.is_null() {
        return;
    }
    let regs = unwind::capture();
    // SAFETY: checked non-null; per the contract.
    unsafe { unwind::fill_context(&regs, context) };
}

/// `KeCapturePersistentThreadState` (undocumented): crash-dump triage helper
/// that serialises a minidump header for live kernel dump telemetry. NK writes
/// no crash dumps, so this returns 0 bytes captured.
#[allow(non_snake_case, clippy::too_many_arguments)]
pub extern "C" fn KeCapturePersistentThreadState(
    _context: *mut core::ffi::c_void,
    _thread: *mut core::ffi::c_void,
    _bugcheck_code: u32,
    _param1: usize,
    _param2: usize,
    _param3: usize,
    _param4: usize,
    _virtual_address: *mut core::ffi::c_void,
) -> u32 {
    0
}
