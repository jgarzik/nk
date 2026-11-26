//! Walking a kernel stack by the images' function tables.
//!
//! A walk starts from a register set (`arch::unwind::capture`) and
//! undoes one frame at a time: find the image the program counter is
//! in, find the function's entry in that image's `.pdata`, and let
//! `nk_unwind` compute the registers of the frame beneath. It crosses
//! whatever the tables describe: compiled functions, the assembly
//! stubs, the change of stack around DPC routines, interrupt frames.
//!
//! The walk ends at a frame whose program counter is zero: every stack
//! is entered as if called from address zero (`doc/DESIGN.md`, "Unwind
//! tables").
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

/// The stacks code on this processor can be running on right now.
pub(super) fn stacks() -> [Option<Stack>; 2] {
    // The DPC stack is the processor's, and a thread below
    // DISPATCH_LEVEL can change processors; but it is not on any DPC
    // stack either.
    let dpc = (irql::current() >= irql::DISPATCH_LEVEL).then(|| arch::percpu().dpcs().stack());
    [Some(super::thread::current_stack()), dpc]
}

/// Read the stack slot at `address`, if it is one.
pub(super) fn read_slot(stacks: &[Option<Stack>; 2], address: u64) -> Option<u64> {
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
        if pc == 0 {
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
