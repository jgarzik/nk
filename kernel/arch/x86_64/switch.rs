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
    .seh_proc nk_context_switch
    push rbp
    .seh_pushreg rbp
    push rbx
    .seh_pushreg rbx
    push rdi
    .seh_pushreg rdi
    push rsi
    .seh_pushreg rsi
    push r12
    .seh_pushreg r12
    push r13
    .seh_pushreg r13
    push r14
    .seh_pushreg r14
    push r15
    .seh_pushreg r15
    sub rsp, 0xA8
    .seh_stackalloc 0xA8
    movaps [rsp + 0x00], xmm6
    .seh_savexmm xmm6, 0x00
    movaps [rsp + 0x10], xmm7
    .seh_savexmm xmm7, 0x10
    movaps [rsp + 0x20], xmm8
    .seh_savexmm xmm8, 0x20
    movaps [rsp + 0x30], xmm9
    .seh_savexmm xmm9, 0x30
    movaps [rsp + 0x40], xmm10
    .seh_savexmm xmm10, 0x40
    movaps [rsp + 0x50], xmm11
    .seh_savexmm xmm11, 0x50
    movaps [rsp + 0x60], xmm12
    .seh_savexmm xmm12, 0x60
    movaps [rsp + 0x70], xmm13
    .seh_savexmm xmm13, 0x70
    movaps [rsp + 0x80], xmm14
    .seh_savexmm xmm14, 0x80
    movaps [rsp + 0x90], xmm15
    .seh_savexmm xmm15, 0x90
    .seh_endprologue
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
    .seh_endproc

    .globl nk_thread_start
// Where a new thread's first switch "returns". The stack is 16-byte
// aligned here; make the call a compiled function expects. The word at
// the stack pointer on entry, where a caller's return address would be,
// is zero (`new_context`).
nk_thread_start:
    .seh_proc nk_thread_start
    sub rsp, 0x20
    .seh_stackalloc 0x20
    .seh_endprologue
    call rbx
    ud2
    .seh_endproc

    .globl nk_call_on_stack
// rcx: the top of a stack. rdx: a function. r8: its argument. Calls the
// function on that stack and returns on this one. rbp holds this stack's
// pointer meanwhile and is the frame register of the unwind information,
// so a stack walk crosses from that stack back to this one.
nk_call_on_stack:
    .seh_proc nk_call_on_stack
    push rbp
    .seh_pushreg rbp
    mov rbp, rsp
    .seh_setframe rbp, 0
    .seh_endprologue
    mov rsp, rcx
    sub rsp, 32
    mov rcx, r8
    call rdx
    mov rsp, rbp
    pop rbp
    ret
    .seh_endproc

    .globl nk_callee_saved_check
// rcx: a seed. rdx: a function to call. Returns 1 in eax if every
// register a call preserves came back as it went in.
nk_callee_saved_check:
    .seh_proc nk_callee_saved_check
    push rbx
    .seh_pushreg rbx
    push rbp
    .seh_pushreg rbp
    push rdi
    .seh_pushreg rdi
    push rsi
    .seh_pushreg rsi
    push r12
    .seh_pushreg r12
    push r13
    .seh_pushreg r13
    push r14
    .seh_pushreg r14
    push r15
    .seh_pushreg r15
    sub rsp, 0xC8
    .seh_stackalloc 0xC8
    movaps [rsp + 0x20], xmm6
    .seh_savexmm xmm6, 0x20
    movaps [rsp + 0x30], xmm7
    .seh_savexmm xmm7, 0x30
    movaps [rsp + 0x40], xmm8
    .seh_savexmm xmm8, 0x40
    movaps [rsp + 0x50], xmm9
    .seh_savexmm xmm9, 0x50
    movaps [rsp + 0x60], xmm10
    .seh_savexmm xmm10, 0x60
    movaps [rsp + 0x70], xmm11
    .seh_savexmm xmm11, 0x70
    movaps [rsp + 0x80], xmm12
    .seh_savexmm xmm12, 0x80
    movaps [rsp + 0x90], xmm13
    .seh_savexmm xmm13, 0x90
    movaps [rsp + 0xa0], xmm14
    .seh_savexmm xmm14, 0xa0
    movaps [rsp + 0xb0], xmm15
    .seh_savexmm xmm15, 0xb0
    .seh_endprologue
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
    .seh_endproc

    .globl nk_all_registers_check
// rcx: a seed. rdx: how many times to look. Fills every general and
// vector register with values made from the seed and checks them over
// and over without calling anything. Returns 1 in eax if none changed.
nk_all_registers_check:
    .seh_proc nk_all_registers_check
    push rbp
    .seh_pushreg rbp
    push rbx
    .seh_pushreg rbx
    push rdi
    .seh_pushreg rdi
    push rsi
    .seh_pushreg rsi
    push r12
    .seh_pushreg r12
    push r13
    .seh_pushreg r13
    push r14
    .seh_pushreg r14
    push r15
    .seh_pushreg r15
    sub rsp, 0xC8
    .seh_stackalloc 0xC8
    movaps [rsp + 0x20], xmm6
    .seh_savexmm xmm6, 0x20
    movaps [rsp + 0x30], xmm7
    .seh_savexmm xmm7, 0x30
    movaps [rsp + 0x40], xmm8
    .seh_savexmm xmm8, 0x40
    movaps [rsp + 0x50], xmm9
    .seh_savexmm xmm9, 0x50
    movaps [rsp + 0x60], xmm10
    .seh_savexmm xmm10, 0x60
    movaps [rsp + 0x70], xmm11
    .seh_savexmm xmm11, 0x70
    movaps [rsp + 0x80], xmm12
    .seh_savexmm xmm12, 0x80
    movaps [rsp + 0x90], xmm13
    .seh_savexmm xmm13, 0x90
    movaps [rsp + 0xa0], xmm14
    .seh_savexmm xmm14, 0xa0
    movaps [rsp + 0xb0], xmm15
    .seh_savexmm xmm15, 0xb0
    .seh_endprologue
    mov [rsp + 0xC0], rcx
    mov [rsp], rdx
    lea rax, [rcx + 100]
    movq xmm0, rax
    lea rax, [rcx + 101]
    movq xmm1, rax
    lea rax, [rcx + 102]
    movq xmm2, rax
    lea rax, [rcx + 103]
    movq xmm3, rax
    lea rax, [rcx + 104]
    movq xmm4, rax
    lea rax, [rcx + 105]
    movq xmm5, rax
    lea rax, [rcx + 106]
    movq xmm6, rax
    lea rax, [rcx + 107]
    movq xmm7, rax
    lea rax, [rcx + 108]
    movq xmm8, rax
    lea rax, [rcx + 109]
    movq xmm9, rax
    lea rax, [rcx + 110]
    movq xmm10, rax
    lea rax, [rcx + 111]
    movq xmm11, rax
    lea rax, [rcx + 112]
    movq xmm12, rax
    lea rax, [rcx + 113]
    movq xmm13, rax
    lea rax, [rcx + 114]
    movq xmm14, rax
    lea rax, [rcx + 115]
    movq xmm15, rax
    lea rax, [rcx + 0]
    lea rbx, [rcx + 1]
    lea rdx, [rcx + 3]
    lea rsi, [rcx + 4]
    lea rdi, [rcx + 5]
    lea rbp, [rcx + 6]
    lea r8, [rcx + 7]
    lea r9, [rcx + 8]
    lea r10, [rcx + 9]
    lea r11, [rcx + 10]
    lea r12, [rcx + 11]
    lea r13, [rcx + 12]
    lea r14, [rcx + 13]
    lea r15, [rcx + 14]
    lea rcx, [rcx + 2]
3:
    sub rax, [rsp + 0xC0]
    cmp rax, 0
    jne 2f
    add rax, [rsp + 0xC0]
    sub rbx, [rsp + 0xC0]
    cmp rbx, 1
    jne 2f
    add rbx, [rsp + 0xC0]
    sub rcx, [rsp + 0xC0]
    cmp rcx, 2
    jne 2f
    add rcx, [rsp + 0xC0]
    sub rdx, [rsp + 0xC0]
    cmp rdx, 3
    jne 2f
    add rdx, [rsp + 0xC0]
    sub rsi, [rsp + 0xC0]
    cmp rsi, 4
    jne 2f
    add rsi, [rsp + 0xC0]
    sub rdi, [rsp + 0xC0]
    cmp rdi, 5
    jne 2f
    add rdi, [rsp + 0xC0]
    sub rbp, [rsp + 0xC0]
    cmp rbp, 6
    jne 2f
    add rbp, [rsp + 0xC0]
    sub r8, [rsp + 0xC0]
    cmp r8, 7
    jne 2f
    add r8, [rsp + 0xC0]
    sub r9, [rsp + 0xC0]
    cmp r9, 8
    jne 2f
    add r9, [rsp + 0xC0]
    sub r10, [rsp + 0xC0]
    cmp r10, 9
    jne 2f
    add r10, [rsp + 0xC0]
    sub r11, [rsp + 0xC0]
    cmp r11, 10
    jne 2f
    add r11, [rsp + 0xC0]
    sub r12, [rsp + 0xC0]
    cmp r12, 11
    jne 2f
    add r12, [rsp + 0xC0]
    sub r13, [rsp + 0xC0]
    cmp r13, 12
    jne 2f
    add r13, [rsp + 0xC0]
    sub r14, [rsp + 0xC0]
    cmp r14, 13
    jne 2f
    add r14, [rsp + 0xC0]
    sub r15, [rsp + 0xC0]
    cmp r15, 14
    jne 2f
    add r15, [rsp + 0xC0]
    movq [rsp + 0x08], xmm0
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 100
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm1
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 101
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm2
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 102
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm3
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 103
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm4
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 104
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm5
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 105
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm6
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 106
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm7
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 107
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm8
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 108
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm9
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 109
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm10
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 110
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm11
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 111
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm12
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 112
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm13
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 113
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm14
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 114
    mov rax, [rsp + 0x10]
    jne 2f
    movq [rsp + 0x08], xmm15
    mov [rsp + 0x10], rax
    mov rax, [rsp + 0x08]
    sub rax, [rsp + 0xC0]
    cmp rax, 115
    mov rax, [rsp + 0x10]
    jne 2f
    sub qword ptr [rsp], 1
    jnz 3b
    mov eax, 1
    jmp 4f
2:
    xor eax, eax
4:
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
    pop rbx
    pop rbp
    ret
    .seh_endproc
"#
);

unsafe extern "C" {
    fn nk_context_switch(save: *mut u64, load: u64);
    fn nk_thread_start();
    fn nk_call_on_stack(top: u64, call: extern "C" fn(usize), argument: usize);
    fn nk_callee_saved_check(seed: u64, call: extern "C" fn()) -> u32;
    fn nk_all_registers_check(seed: u64, looks: u64) -> u32;
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
        // Where the start stub's own return address would be: zero, which
        // ends a walk of this stack.
        ((return_slot + 8) as *mut u64).write(0);
    }
    sp
}

/// Call `call(argument)` on the stack ending at `top`, and come back to
/// this one when it returns.
///
/// # Safety
/// `top` is the 16-byte-aligned top of a mapped stack nothing else is
/// using, and nothing switches threads until `call` has returned.
pub unsafe fn call_on_stack(top: u64, call: extern "C" fn(usize), argument: usize) {
    // SAFETY: per the contract.
    unsafe { nk_call_on_stack(top, call, argument) }
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

/// Fill every general and vector register with values made from `seed`
/// and look at them `looks` times, calling nothing. Whether none
/// changed. For the test that is interrupted and switched away from
/// while this runs.
pub fn all_registers_survive(seed: u64, looks: u64) -> bool {
    // SAFETY: the routine saves and restores what a call must preserve.
    unsafe { nk_all_registers_check(seed, looks) == 1 }
}
