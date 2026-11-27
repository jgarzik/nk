//! Kernel stacks.
//!
//! Every stack is `KERNEL_STACK_SIZE` bytes of ordinary frames mapped in
//! the kernel's dynamic address space, with nothing mapped in the same
//! size below it. Running off the bottom therefore faults instead of
//! writing over whatever lies there, and the architecture layer reports
//! that fault as a stack overflow.
//!
//! The top of a stack is a multiple of twice its size; see
//! `nk_bootinfo::KERNEL_STACK_SIZE` for why.

use super::{PAGE_SIZE, alloc_frames, free_frames, map};
use nk_bootinfo::KERNEL_STACK_SIZE;
use nk_mm::pt::Prot;

pub const STACK_PAGES: usize = KERNEL_STACK_SIZE as usize / PAGE_SIZE;

/// A mapped kernel stack: `[base, top)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stack {
    pub base: u64,
    pub top: u64,
}

/// Allocate and map a stack. `None` if memory or address space ran out;
/// nothing is left allocated in that case.
pub fn alloc() -> Option<Stack> {
    // Reserve the stack and the unmapped stretch below it as one range.
    let low = map::alloc_va_aligned(2 * STACK_PAGES, 2 * KERNEL_STACK_SIZE)?;
    let stack = Stack {
        base: low + KERNEL_STACK_SIZE,
        top: low + 2 * KERNEL_STACK_SIZE,
    };
    for page in 0..STACK_PAGES {
        let va = stack.base + (page * PAGE_SIZE) as u64;
        let mapped = alloc_frames(1).is_some_and(|frame| {
            let ok = map::map(va, frame, 1, Prot::RW).is_ok();
            if !ok {
                free_frames(frame, 1);
            }
            ok
        });
        if !mapped {
            release(stack, page);
            return None;
        }
    }
    Some(stack)
}

/// Unmap the first `pages` pages of `stack`, free their frames and give
/// back the address space.
fn release(stack: Stack, pages: usize) {
    for page in 0..pages {
        let va = stack.base + (page * PAGE_SIZE) as u64;
        if let Some(frame) = map::translate(va) {
            // SAFETY: the stack's thread is gone, or never ran on it.
            unsafe { map::unmap(va, 1) };
            free_frames(frame, 1);
        }
    }
    // SAFETY: as above; the whole range the stack was given.
    unsafe { map::free_va(stack.base - KERNEL_STACK_SIZE, 2 * STACK_PAGES) };
}

/// Free a stack from `alloc`. Nothing may be running on it.
pub fn free(stack: Stack) {
    release(stack, STACK_PAGES);
}

/// Whether `address` is in the unmapped stretch below the stack whose
/// lowest address is `base`: where an overflowing stack lands.
pub fn is_overflow(base: u64, address: u64) -> bool {
    nk_bootinfo::below_stack(base, address)
}

/// A stack has the documented shape, holds data, is unmapped below, and
/// gives everything back when freed.
pub fn self_test() -> Result<(), &'static str> {
    let frames = super::free_frame_count();
    let stack = alloc().ok_or("cannot allocate a stack")?;
    let second = alloc().ok_or("cannot allocate a second stack")?;
    let check = || {
        if stack.top - stack.base != KERNEL_STACK_SIZE || stack.top % (2 * KERNEL_STACK_SIZE) != 0 {
            return Err("a stack does not have the documented size and alignment");
        }
        if stack == second || stack.base < second.top && second.base < stack.top {
            return Err("two stacks overlap");
        }
        // SAFETY: both ends are inside the stack just mapped, which
        // nothing else uses.
        unsafe {
            ((stack.top - 8) as *mut u64).write_volatile(0x1122_3344_5566_7788);
            (stack.base as *mut u64).write_volatile(!0x1122_3344_5566_7788);
            if ((stack.top - 8) as *const u64).read_volatile() != 0x1122_3344_5566_7788 {
                return Err("a stack does not hold what was written to it");
            }
        }
        let below = [stack.base - 8, stack.base - KERNEL_STACK_SIZE];
        if below.iter().any(|&va| map::translate(va).is_some()) {
            return Err("memory is mapped below a stack");
        }
        if !is_overflow(stack.base, below[0]) || !is_overflow(stack.base, below[1]) {
            return Err("an address just below a stack is not seen as an overflow");
        }
        if is_overflow(stack.base, stack.base) || is_overflow(stack.base, below[1] - 8) {
            return Err("an address outside the guard is seen as an overflow");
        }
        Ok(())
    };
    let verdict = check();
    free(second);
    free(stack);
    verdict?;
    // Page tables made for the stacks stay; the frames must come back.
    if super::free_frame_count() + (STACK_PAGES as u64) < frames {
        return Err("freeing a stack did not return its frames");
    }
    Ok(())
}
