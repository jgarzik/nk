//! Switching threads on arm64.
//!
//! A thread that is not running has its callee-saved state on its own
//! stack, and its stack pointer saved in its thread object. Switching is
//! an ordinary call that returns in another thread, so only what a call
//! preserves is kept: x19-x30, the low halves of v8-v15, and FPCR. x18
//! is the processor's, not the thread's, and is left alone.

use core::arch::global_asm;

/// Bytes the switch keeps on a stack.
const FRAME: u64 = 176;

global_asm!(
    r#"
    .text
    .globl nk_context_switch
// x0: where to save the outgoing stack pointer. x1: the stack pointer to
// continue on.
nk_context_switch:
    sub sp, sp, #176
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    stp d8, d9, [sp, #96]
    stp d10, d11, [sp, #112]
    stp d12, d13, [sp, #128]
    stp d14, d15, [sp, #144]
    mrs x9, fpcr
    str x9, [sp, #160]
    mov x9, sp
    str x9, [x0]
    mov sp, x1
    ldr x9, [sp, #160]
    msr fpcr, x9
    ldp x19, x20, [sp, #0]
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #48]
    ldp x27, x28, [sp, #64]
    ldp x29, x30, [sp, #80]
    ldp d8, d9, [sp, #96]
    ldp d10, d11, [sp, #112]
    ldp d12, d13, [sp, #128]
    ldp d14, d15, [sp, #144]
    add sp, sp, #176
    ret

    .globl nk_callee_saved_check
// x0: a seed. x1: a function to call. Returns 1 in x0 if every
// register a call preserves came back as it went in.
nk_callee_saved_check:
    sub sp, sp, #192
    stp x19, x20, [sp, #0]
    stp x21, x22, [sp, #16]
    stp x23, x24, [sp, #32]
    stp x25, x26, [sp, #48]
    stp x27, x28, [sp, #64]
    stp x29, x30, [sp, #80]
    stp d8, d9, [sp, #96]
    stp d10, d11, [sp, #112]
    stp d12, d13, [sp, #128]
    stp d14, d15, [sp, #144]
    str x0, [sp, #160]
    add x19, x0, #0
    add x20, x0, #1
    add x21, x0, #2
    add x22, x0, #3
    add x23, x0, #4
    add x24, x0, #5
    add x25, x0, #6
    add x26, x0, #7
    add x27, x0, #8
    add x28, x0, #9
    fmov d8, x19
    fmov d9, x20
    fmov d10, x21
    fmov d11, x22
    fmov d12, x23
    fmov d13, x24
    fmov d14, x25
    fmov d15, x26
    blr x1
    ldr x9, [sp, #160]
    mov x0, #0
    add x10, x9, #0
    cmp x19, x10
    b.ne 2f
    add x10, x9, #1
    cmp x20, x10
    b.ne 2f
    add x10, x9, #2
    cmp x21, x10
    b.ne 2f
    add x10, x9, #3
    cmp x22, x10
    b.ne 2f
    add x10, x9, #4
    cmp x23, x10
    b.ne 2f
    add x10, x9, #5
    cmp x24, x10
    b.ne 2f
    add x10, x9, #6
    cmp x25, x10
    b.ne 2f
    add x10, x9, #7
    cmp x26, x10
    b.ne 2f
    add x10, x9, #8
    cmp x27, x10
    b.ne 2f
    add x10, x9, #9
    cmp x28, x10
    b.ne 2f
    fmov x11, d8
    add x10, x9, #0
    cmp x11, x10
    b.ne 2f
    fmov x11, d9
    add x10, x9, #1
    cmp x11, x10
    b.ne 2f
    fmov x11, d10
    add x10, x9, #2
    cmp x11, x10
    b.ne 2f
    fmov x11, d11
    add x10, x9, #3
    cmp x11, x10
    b.ne 2f
    fmov x11, d12
    add x10, x9, #4
    cmp x11, x10
    b.ne 2f
    fmov x11, d13
    add x10, x9, #5
    cmp x11, x10
    b.ne 2f
    fmov x11, d14
    add x10, x9, #6
    cmp x11, x10
    b.ne 2f
    fmov x11, d15
    add x10, x9, #7
    cmp x11, x10
    b.ne 2f
    mov x0, #1
2:
    ldp x19, x20, [sp, #0]
    ldp x21, x22, [sp, #16]
    ldp x23, x24, [sp, #32]
    ldp x25, x26, [sp, #48]
    ldp x27, x28, [sp, #64]
    ldp x29, x30, [sp, #80]
    ldp d8, d9, [sp, #96]
    ldp d10, d11, [sp, #112]
    ldp d12, d13, [sp, #128]
    ldp d14, d15, [sp, #144]
    add sp, sp, #192
    ret
"#
);

unsafe extern "C" {
    fn nk_context_switch(save: *mut u64, load: u64);
    fn nk_callee_saved_check(seed: u64, call: extern "C" fn()) -> u64;
}

/// Save this thread's state on its stack, store its stack pointer in
/// `*save`, and continue the thread whose saved stack pointer is `load`.
/// Returns when something switches back.
///
/// # Safety
/// `save` is writable; `load` came from an earlier switch away from a
/// thread that is not running anywhere, or from [`new_context`]. The
/// caller is at DISPATCH_LEVEL and holds no lock.
pub unsafe fn context_switch(save: *mut u64, load: u64) {
    // SAFETY: per the contract.
    unsafe { nk_context_switch(save, load) }
}

/// Prepare the stack ending at `stack_top` so that switching to the
/// returned stack pointer calls `entry` on it.
///
/// # Safety
/// `stack_top` is the 16-byte-aligned top of a mapped stack nothing else
/// uses.
pub unsafe fn new_context(stack_top: u64, entry: extern "C" fn() -> !) -> u64 {
    let sp = stack_top - FRAME;
    // SAFETY: per the contract; everything written is inside the stack.
    // The switch "returns" through x30, with no frame behind it.
    unsafe {
        core::ptr::write_bytes(sp as *mut u8, 0, FRAME as usize);
        ((sp + 88) as *mut u64).write(entry as usize as u64);
    }
    sp
}

/// Wait for an interrupt, with no gap in which one could be missed.
/// Called with interrupts disabled; returns with them enabled.
pub fn wait_for_interrupt() {
    // SAFETY: `wfi` returns when an interrupt is pending even while
    // interrupts are masked, so none is missed; then they are unmasked.
    unsafe { core::arch::asm!("wfi", "msr daifclr, #2", options(nomem, nostack)) };
}

/// Fill every register a call preserves, the vector ones included, with
/// values made from `seed`; call `call`; report whether all of them came
/// back unchanged. For the test that switches threads inside `call`.
pub fn callee_saved_survive(seed: u64, call: extern "C" fn()) -> bool {
    // SAFETY: the routine saves and restores everything it changes.
    unsafe { nk_callee_saved_check(seed, call) == 1 }
}
