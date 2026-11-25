//! Switching threads on x86-64.
//!
//! A thread that is not running has its callee-saved state on its own
//! stack, and its stack pointer saved in its thread object. Switching is
//! an ordinary call that returns in another thread: the caller-saved
//! registers are dead across any call, so only the rest is kept. That is
//! rbx, rbp, rdi, rsi, r12-r15, xmm6-xmm15 and the MXCSR control word,
//! in the Microsoft convention NK is compiled to.

use core::arch::global_asm;

/// Bytes the switch keeps on a stack below the return address: eight
/// registers, ten vector registers, and MXCSR with padding.
const FRAME: u64 = 8 * 8 + SSE;
const SSE: u64 = 0xA8;
/// MXCSR as a fresh thread gets it: every exception masked, round to
/// nearest.
const MXCSR_DEFAULT: u32 = 0x1F80;

global_asm!(
    r#"
    .text
    .globl nk_context_switch
// rcx: where to save the outgoing stack pointer. rdx: the stack pointer
// to continue on.
nk_context_switch:
    push rbp
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0xA8
    movaps [rsp + 0x00], xmm6
    movaps [rsp + 0x10], xmm7
    movaps [rsp + 0x20], xmm8
    movaps [rsp + 0x30], xmm9
    movaps [rsp + 0x40], xmm10
    movaps [rsp + 0x50], xmm11
    movaps [rsp + 0x60], xmm12
    movaps [rsp + 0x70], xmm13
    movaps [rsp + 0x80], xmm14
    movaps [rsp + 0x90], xmm15
    stmxcsr [rsp + 0xA0]
    mov [rcx], rsp
    mov rsp, rdx
    ldmxcsr [rsp + 0xA0]
    movaps xmm6, [rsp + 0x00]
    movaps xmm7, [rsp + 0x10]
    movaps xmm8, [rsp + 0x20]
    movaps xmm9, [rsp + 0x30]
    movaps xmm10, [rsp + 0x40]
    movaps xmm11, [rsp + 0x50]
    movaps xmm12, [rsp + 0x60]
    movaps xmm13, [rsp + 0x70]
    movaps xmm14, [rsp + 0x80]
    movaps xmm15, [rsp + 0x90]
    add rsp, 0xA8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    pop rbp
    ret

    .globl nk_thread_start
// Where a new thread's first switch "returns". The stack is 16-byte
// aligned here; make the call a compiled function expects.
nk_thread_start:
    sub rsp, 0x20
    call rbx
    ud2

    .globl nk_callee_saved_check
// rcx: a seed. rdx: a function to call. Returns 1 in eax if every
// register a call preserves came back as it went in.
nk_callee_saved_check:
    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0xC8
    movaps [rsp + 0x20], xmm6
    movaps [rsp + 0x30], xmm7
    movaps [rsp + 0x40], xmm8
    movaps [rsp + 0x50], xmm9
    movaps [rsp + 0x60], xmm10
    movaps [rsp + 0x70], xmm11
    movaps [rsp + 0x80], xmm12
    movaps [rsp + 0x90], xmm13
    movaps [rsp + 0xa0], xmm14
    movaps [rsp + 0xb0], xmm15
    mov [rsp + 0xC0], rcx
    lea rbx, [rcx + 0]
    lea rbp, [rcx + 1]
    lea rdi, [rcx + 2]
    lea rsi, [rcx + 3]
    lea r12, [rcx + 4]
    lea r13, [rcx + 5]
    lea r14, [rcx + 6]
    lea r15, [rcx + 7]
    movq xmm6, rbx
    movq xmm7, rbp
    movq xmm8, rdi
    movq xmm9, rsi
    movq xmm10, r12
    movq xmm11, r13
    movq xmm12, r14
    movq xmm13, r15
    movq xmm14, rbx
    movq xmm15, rbp
    call rdx
    mov rcx, [rsp + 0xC0]
    xor eax, eax
    lea r10, [rcx + 0]
    cmp rbx, r10
    jne 2f
    lea r10, [rcx + 1]
    cmp rbp, r10
    jne 2f
    lea r10, [rcx + 2]
    cmp rdi, r10
    jne 2f
    lea r10, [rcx + 3]
    cmp rsi, r10
    jne 2f
    lea r10, [rcx + 4]
    cmp r12, r10
    jne 2f
    lea r10, [rcx + 5]
    cmp r13, r10
    jne 2f
    lea r10, [rcx + 6]
    cmp r14, r10
    jne 2f
    lea r10, [rcx + 7]
    cmp r15, r10
    jne 2f
    movq r11, xmm6
    lea r10, [rcx + 0]
    cmp r11, r10
    jne 2f
    movq r11, xmm7
    lea r10, [rcx + 1]
    cmp r11, r10
    jne 2f
    movq r11, xmm8
    lea r10, [rcx + 2]
    cmp r11, r10
    jne 2f
    movq r11, xmm9
    lea r10, [rcx + 3]
    cmp r11, r10
    jne 2f
    movq r11, xmm10
    lea r10, [rcx + 4]
    cmp r11, r10
    jne 2f
    movq r11, xmm11
    lea r10, [rcx + 5]
    cmp r11, r10
    jne 2f
    movq r11, xmm12
    lea r10, [rcx + 6]
    cmp r11, r10
    jne 2f
    movq r11, xmm13
    lea r10, [rcx + 7]
    cmp r11, r10
    jne 2f
    movq r11, xmm14
    lea r10, [rcx + 0]
    cmp r11, r10
    jne 2f
    movq r11, xmm15
    lea r10, [rcx + 1]
    cmp r11, r10
    jne 2f
    mov eax, 1
2:
    movaps xmm6, [rsp + 0x20]
    movaps xmm7, [rsp + 0x30]
    movaps xmm8, [rsp + 0x40]
    movaps xmm9, [rsp + 0x50]
    movaps xmm10, [rsp + 0x60]
    movaps xmm11, [rsp + 0x70]
    movaps xmm12, [rsp + 0x80]
    movaps xmm13, [rsp + 0x90]
    movaps xmm14, [rsp + 0xa0]
    movaps xmm15, [rsp + 0xb0]
    add rsp, 0xC8
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    ret
"#
);

unsafe extern "C" {
    fn nk_context_switch(save: *mut u64, load: u64);
    fn nk_thread_start();
    fn nk_callee_saved_check(seed: u64, call: extern "C" fn()) -> u32;
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
    // The return address goes where a `call` would have put it: 8 below
    // a 16-byte boundary. Above it is room the first frame may use.
    let return_slot = stack_top - 0x38;
    let sp = return_slot - FRAME;
    // SAFETY: per the contract; everything written is inside the stack.
    unsafe {
        core::ptr::write_bytes(sp as *mut u8, 0, FRAME as usize);
        ((sp + 0xA0) as *mut u32).write(MXCSR_DEFAULT);
        // rbx, restored by the switch, carries the entry point to the
        // start stub. It is the seventh of the eight pushed registers.
        ((sp + SSE + 6 * 8) as *mut u64).write(entry as usize as u64);
        (return_slot as *mut u64).write(nk_thread_start as *const () as usize as u64);
    }
    sp
}

/// Wait for an interrupt, with no gap in which one could be missed.
/// Called with interrupts disabled; returns with them enabled.
pub fn wait_for_interrupt() {
    // SAFETY: `sti` takes effect after the next instruction, so an
    // interrupt cannot arrive between enabling and halting.
    unsafe { core::arch::asm!("sti", "hlt", options(nomem, nostack)) };
}

/// Fill every register a call preserves, the vector ones included, with
/// values made from `seed`; call `call`; report whether all of them came
/// back unchanged. For the test that switches threads inside `call`.
pub fn callee_saved_survive(seed: u64, call: extern "C" fn()) -> bool {
    // SAFETY: the routine saves and restores everything it changes.
    unsafe { nk_callee_saved_check(seed, call) == 1 }
}
