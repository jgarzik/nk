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
    .seh_proc nk_context_switch
    sub sp, sp, #176
    .seh_stackalloc 176
    stp x19, x20, [sp, #0]
    .seh_save_regp x19, 0
    stp x21, x22, [sp, #16]
    .seh_save_regp x21, 16
    stp x23, x24, [sp, #32]
    .seh_save_regp x23, 32
    stp x25, x26, [sp, #48]
    .seh_save_regp x25, 48
    stp x27, x28, [sp, #64]
    .seh_save_regp x27, 64
    stp x29, x30, [sp, #80]
    .seh_save_fplr 80
    stp d8, d9, [sp, #96]
    .seh_save_fregp d8, 96
    stp d10, d11, [sp, #112]
    .seh_save_fregp d10, 112
    stp d12, d13, [sp, #128]
    .seh_save_fregp d12, 128
    stp d14, d15, [sp, #144]
    .seh_save_fregp d14, 144
    .seh_endprologue
    mrs x9, fpcr
    str x9, [sp, #160]
    mov x9, sp
    str x9, [x0]
    mov sp, x1
    ldr x9, [sp, #160]
    msr fpcr, x9
    .seh_startepilogue
    ldp x19, x20, [sp, #0]
    .seh_save_regp x19, 0
    ldp x21, x22, [sp, #16]
    .seh_save_regp x21, 16
    ldp x23, x24, [sp, #32]
    .seh_save_regp x23, 32
    ldp x25, x26, [sp, #48]
    .seh_save_regp x25, 48
    ldp x27, x28, [sp, #64]
    .seh_save_regp x27, 64
    ldp x29, x30, [sp, #80]
    .seh_save_fplr 80
    ldp d8, d9, [sp, #96]
    .seh_save_fregp d8, 96
    ldp d10, d11, [sp, #112]
    .seh_save_fregp d10, 112
    ldp d12, d13, [sp, #128]
    .seh_save_fregp d12, 128
    ldp d14, d15, [sp, #144]
    .seh_save_fregp d14, 144
    add sp, sp, #176
    .seh_stackalloc 176
    .seh_endepilogue
    ret
    .seh_endproc

// Where a new thread's first switch "returns": `nk_thread_start`, with
// the thread's entry point in x19. The first instruction is never
// executed. It is there for the unwind information, which says of the
// instructions after it that a frame record was pushed: `new_context`
// leaves one at the stack pointer, all zero, and a return address of
// zero ends a walk of this stack.
nk_thread_start_frame:
    .seh_proc nk_thread_start_frame
    stp x29, x30, [sp, #-16]!
    .seh_save_fplr_x 16
    .seh_endprologue
    .globl nk_thread_start
nk_thread_start:
    blr x19
    brk #0x1
    .seh_endproc

    .globl nk_call_on_stack
// x0: the top of a stack. x1: a function. x2: its argument. Calls the
// function on that stack and returns on this one. x29 holds this stack's
// pointer meanwhile, as the unwind information says, so a stack walk
// crosses from that stack back to this one.
nk_call_on_stack:
    .seh_proc nk_call_on_stack
    stp x29, x30, [sp, #-16]!
    .seh_save_fplr_x 16
    mov x29, sp
    .seh_set_fp
    .seh_endprologue
    mov sp, x0
    mov x0, x2
    blr x1
    .seh_startepilogue
    mov sp, x29
    .seh_set_fp
    ldp x29, x30, [sp], #16
    .seh_save_fplr_x 16
    .seh_endepilogue
    ret
    .seh_endproc

    .globl nk_callee_saved_check
// x0: a seed. x1: a function to call. Returns 1 in x0 if every
// register a call preserves came back as it went in.
nk_callee_saved_check:
    .seh_proc nk_callee_saved_check
    sub sp, sp, #192
    .seh_stackalloc 192
    stp x19, x20, [sp, #0]
    .seh_save_regp x19, 0
    stp x21, x22, [sp, #16]
    .seh_save_regp x21, 16
    stp x23, x24, [sp, #32]
    .seh_save_regp x23, 32
    stp x25, x26, [sp, #48]
    .seh_save_regp x25, 48
    stp x27, x28, [sp, #64]
    .seh_save_regp x27, 64
    stp x29, x30, [sp, #80]
    .seh_save_fplr 80
    stp d8, d9, [sp, #96]
    .seh_save_fregp d8, 96
    stp d10, d11, [sp, #112]
    .seh_save_fregp d10, 112
    stp d12, d13, [sp, #128]
    .seh_save_fregp d12, 128
    stp d14, d15, [sp, #144]
    .seh_save_fregp d14, 144
    .seh_endprologue
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
    .seh_startepilogue
    ldp x19, x20, [sp, #0]
    .seh_save_regp x19, 0
    ldp x21, x22, [sp, #16]
    .seh_save_regp x21, 16
    ldp x23, x24, [sp, #32]
    .seh_save_regp x23, 32
    ldp x25, x26, [sp, #48]
    .seh_save_regp x25, 48
    ldp x27, x28, [sp, #64]
    .seh_save_regp x27, 64
    ldp x29, x30, [sp, #80]
    .seh_save_fplr 80
    ldp d8, d9, [sp, #96]
    .seh_save_fregp d8, 96
    ldp d10, d11, [sp, #112]
    .seh_save_fregp d10, 112
    ldp d12, d13, [sp, #128]
    .seh_save_fregp d12, 128
    ldp d14, d15, [sp, #144]
    .seh_save_fregp d14, 144
    add sp, sp, #192
    .seh_stackalloc 192
    .seh_endepilogue
    ret
    .seh_endproc

    .globl nk_all_registers_check
// x0: a seed. x1: how many times to look. Fills the general registers
// (but x16-x18, x29, x30) and every vector register, both halves, with
// values made from the seed and checks them over and over without
// calling anything. Returns 1 in x0 if none changed.
nk_all_registers_check:
    .seh_proc nk_all_registers_check
    sub sp, sp, #192
    .seh_stackalloc 192
    stp x19, x20, [sp, #0]
    .seh_save_regp x19, 0
    stp x21, x22, [sp, #16]
    .seh_save_regp x21, 16
    stp x23, x24, [sp, #32]
    .seh_save_regp x23, 32
    stp x25, x26, [sp, #48]
    .seh_save_regp x25, 48
    stp x27, x28, [sp, #64]
    .seh_save_regp x27, 64
    stp x29, x30, [sp, #80]
    .seh_save_fplr 80
    stp d8, d9, [sp, #96]
    .seh_save_fregp d8, 96
    stp d10, d11, [sp, #112]
    .seh_save_fregp d10, 112
    stp d12, d13, [sp, #128]
    .seh_save_fregp d12, 128
    stp d14, d15, [sp, #144]
    .seh_save_fregp d14, 144
    .seh_endprologue
    str x0, [sp, #160]
    str x1, [sp, #168]
    mov x16, x0
    add x17, x16, #100
    dup v0.2d, x17
    add x17, x16, #101
    dup v1.2d, x17
    add x17, x16, #102
    dup v2.2d, x17
    add x17, x16, #103
    dup v3.2d, x17
    add x17, x16, #104
    dup v4.2d, x17
    add x17, x16, #105
    dup v5.2d, x17
    add x17, x16, #106
    dup v6.2d, x17
    add x17, x16, #107
    dup v7.2d, x17
    add x17, x16, #108
    dup v8.2d, x17
    add x17, x16, #109
    dup v9.2d, x17
    add x17, x16, #110
    dup v10.2d, x17
    add x17, x16, #111
    dup v11.2d, x17
    add x17, x16, #112
    dup v12.2d, x17
    add x17, x16, #113
    dup v13.2d, x17
    add x17, x16, #114
    dup v14.2d, x17
    add x17, x16, #115
    dup v15.2d, x17
    add x17, x16, #116
    dup v16.2d, x17
    add x17, x16, #117
    dup v17.2d, x17
    add x17, x16, #118
    dup v18.2d, x17
    add x17, x16, #119
    dup v19.2d, x17
    add x17, x16, #120
    dup v20.2d, x17
    add x17, x16, #121
    dup v21.2d, x17
    add x17, x16, #122
    dup v22.2d, x17
    add x17, x16, #123
    dup v23.2d, x17
    add x17, x16, #124
    dup v24.2d, x17
    add x17, x16, #125
    dup v25.2d, x17
    add x17, x16, #126
    dup v26.2d, x17
    add x17, x16, #127
    dup v27.2d, x17
    add x17, x16, #128
    dup v28.2d, x17
    add x17, x16, #129
    dup v29.2d, x17
    add x17, x16, #130
    dup v30.2d, x17
    add x17, x16, #131
    dup v31.2d, x17
    add x1, x16, #1
    add x2, x16, #2
    add x3, x16, #3
    add x4, x16, #4
    add x5, x16, #5
    add x6, x16, #6
    add x7, x16, #7
    add x8, x16, #8
    add x9, x16, #9
    add x10, x16, #10
    add x11, x16, #11
    add x12, x16, #12
    add x13, x16, #13
    add x14, x16, #14
    add x15, x16, #15
    add x19, x16, #16
    add x20, x16, #17
    add x21, x16, #18
    add x22, x16, #19
    add x23, x16, #20
    add x24, x16, #21
    add x25, x16, #22
    add x26, x16, #23
    add x27, x16, #24
    add x28, x16, #25
    add x0, x16, #0
3:
    ldr x16, [sp, #160]
    sub x17, x0, x16
    cmp x17, #0
    b.ne 2f
    sub x17, x1, x16
    cmp x17, #1
    b.ne 2f
    sub x17, x2, x16
    cmp x17, #2
    b.ne 2f
    sub x17, x3, x16
    cmp x17, #3
    b.ne 2f
    sub x17, x4, x16
    cmp x17, #4
    b.ne 2f
    sub x17, x5, x16
    cmp x17, #5
    b.ne 2f
    sub x17, x6, x16
    cmp x17, #6
    b.ne 2f
    sub x17, x7, x16
    cmp x17, #7
    b.ne 2f
    sub x17, x8, x16
    cmp x17, #8
    b.ne 2f
    sub x17, x9, x16
    cmp x17, #9
    b.ne 2f
    sub x17, x10, x16
    cmp x17, #10
    b.ne 2f
    sub x17, x11, x16
    cmp x17, #11
    b.ne 2f
    sub x17, x12, x16
    cmp x17, #12
    b.ne 2f
    sub x17, x13, x16
    cmp x17, #13
    b.ne 2f
    sub x17, x14, x16
    cmp x17, #14
    b.ne 2f
    sub x17, x15, x16
    cmp x17, #15
    b.ne 2f
    sub x17, x19, x16
    cmp x17, #16
    b.ne 2f
    sub x17, x20, x16
    cmp x17, #17
    b.ne 2f
    sub x17, x21, x16
    cmp x17, #18
    b.ne 2f
    sub x17, x22, x16
    cmp x17, #19
    b.ne 2f
    sub x17, x23, x16
    cmp x17, #20
    b.ne 2f
    sub x17, x24, x16
    cmp x17, #21
    b.ne 2f
    sub x17, x25, x16
    cmp x17, #22
    b.ne 2f
    sub x17, x26, x16
    cmp x17, #23
    b.ne 2f
    sub x17, x27, x16
    cmp x17, #24
    b.ne 2f
    sub x17, x28, x16
    cmp x17, #25
    b.ne 2f
    fmov x17, d0
    sub x17, x17, x16
    cmp x17, #100
    b.ne 2f
    mov x17, v0.d[1]
    sub x17, x17, x16
    cmp x17, #100
    b.ne 2f
    fmov x17, d1
    sub x17, x17, x16
    cmp x17, #101
    b.ne 2f
    mov x17, v1.d[1]
    sub x17, x17, x16
    cmp x17, #101
    b.ne 2f
    fmov x17, d2
    sub x17, x17, x16
    cmp x17, #102
    b.ne 2f
    mov x17, v2.d[1]
    sub x17, x17, x16
    cmp x17, #102
    b.ne 2f
    fmov x17, d3
    sub x17, x17, x16
    cmp x17, #103
    b.ne 2f
    mov x17, v3.d[1]
    sub x17, x17, x16
    cmp x17, #103
    b.ne 2f
    fmov x17, d4
    sub x17, x17, x16
    cmp x17, #104
    b.ne 2f
    mov x17, v4.d[1]
    sub x17, x17, x16
    cmp x17, #104
    b.ne 2f
    fmov x17, d5
    sub x17, x17, x16
    cmp x17, #105
    b.ne 2f
    mov x17, v5.d[1]
    sub x17, x17, x16
    cmp x17, #105
    b.ne 2f
    fmov x17, d6
    sub x17, x17, x16
    cmp x17, #106
    b.ne 2f
    mov x17, v6.d[1]
    sub x17, x17, x16
    cmp x17, #106
    b.ne 2f
    fmov x17, d7
    sub x17, x17, x16
    cmp x17, #107
    b.ne 2f
    mov x17, v7.d[1]
    sub x17, x17, x16
    cmp x17, #107
    b.ne 2f
    fmov x17, d8
    sub x17, x17, x16
    cmp x17, #108
    b.ne 2f
    mov x17, v8.d[1]
    sub x17, x17, x16
    cmp x17, #108
    b.ne 2f
    fmov x17, d9
    sub x17, x17, x16
    cmp x17, #109
    b.ne 2f
    mov x17, v9.d[1]
    sub x17, x17, x16
    cmp x17, #109
    b.ne 2f
    fmov x17, d10
    sub x17, x17, x16
    cmp x17, #110
    b.ne 2f
    mov x17, v10.d[1]
    sub x17, x17, x16
    cmp x17, #110
    b.ne 2f
    fmov x17, d11
    sub x17, x17, x16
    cmp x17, #111
    b.ne 2f
    mov x17, v11.d[1]
    sub x17, x17, x16
    cmp x17, #111
    b.ne 2f
    fmov x17, d12
    sub x17, x17, x16
    cmp x17, #112
    b.ne 2f
    mov x17, v12.d[1]
    sub x17, x17, x16
    cmp x17, #112
    b.ne 2f
    fmov x17, d13
    sub x17, x17, x16
    cmp x17, #113
    b.ne 2f
    mov x17, v13.d[1]
    sub x17, x17, x16
    cmp x17, #113
    b.ne 2f
    fmov x17, d14
    sub x17, x17, x16
    cmp x17, #114
    b.ne 2f
    mov x17, v14.d[1]
    sub x17, x17, x16
    cmp x17, #114
    b.ne 2f
    fmov x17, d15
    sub x17, x17, x16
    cmp x17, #115
    b.ne 2f
    mov x17, v15.d[1]
    sub x17, x17, x16
    cmp x17, #115
    b.ne 2f
    fmov x17, d16
    sub x17, x17, x16
    cmp x17, #116
    b.ne 2f
    mov x17, v16.d[1]
    sub x17, x17, x16
    cmp x17, #116
    b.ne 2f
    fmov x17, d17
    sub x17, x17, x16
    cmp x17, #117
    b.ne 2f
    mov x17, v17.d[1]
    sub x17, x17, x16
    cmp x17, #117
    b.ne 2f
    fmov x17, d18
    sub x17, x17, x16
    cmp x17, #118
    b.ne 2f
    mov x17, v18.d[1]
    sub x17, x17, x16
    cmp x17, #118
    b.ne 2f
    fmov x17, d19
    sub x17, x17, x16
    cmp x17, #119
    b.ne 2f
    mov x17, v19.d[1]
    sub x17, x17, x16
    cmp x17, #119
    b.ne 2f
    fmov x17, d20
    sub x17, x17, x16
    cmp x17, #120
    b.ne 2f
    mov x17, v20.d[1]
    sub x17, x17, x16
    cmp x17, #120
    b.ne 2f
    fmov x17, d21
    sub x17, x17, x16
    cmp x17, #121
    b.ne 2f
    mov x17, v21.d[1]
    sub x17, x17, x16
    cmp x17, #121
    b.ne 2f
    fmov x17, d22
    sub x17, x17, x16
    cmp x17, #122
    b.ne 2f
    mov x17, v22.d[1]
    sub x17, x17, x16
    cmp x17, #122
    b.ne 2f
    fmov x17, d23
    sub x17, x17, x16
    cmp x17, #123
    b.ne 2f
    mov x17, v23.d[1]
    sub x17, x17, x16
    cmp x17, #123
    b.ne 2f
    fmov x17, d24
    sub x17, x17, x16
    cmp x17, #124
    b.ne 2f
    mov x17, v24.d[1]
    sub x17, x17, x16
    cmp x17, #124
    b.ne 2f
    fmov x17, d25
    sub x17, x17, x16
    cmp x17, #125
    b.ne 2f
    mov x17, v25.d[1]
    sub x17, x17, x16
    cmp x17, #125
    b.ne 2f
    fmov x17, d26
    sub x17, x17, x16
    cmp x17, #126
    b.ne 2f
    mov x17, v26.d[1]
    sub x17, x17, x16
    cmp x17, #126
    b.ne 2f
    fmov x17, d27
    sub x17, x17, x16
    cmp x17, #127
    b.ne 2f
    mov x17, v27.d[1]
    sub x17, x17, x16
    cmp x17, #127
    b.ne 2f
    fmov x17, d28
    sub x17, x17, x16
    cmp x17, #128
    b.ne 2f
    mov x17, v28.d[1]
    sub x17, x17, x16
    cmp x17, #128
    b.ne 2f
    fmov x17, d29
    sub x17, x17, x16
    cmp x17, #129
    b.ne 2f
    mov x17, v29.d[1]
    sub x17, x17, x16
    cmp x17, #129
    b.ne 2f
    fmov x17, d30
    sub x17, x17, x16
    cmp x17, #130
    b.ne 2f
    mov x17, v30.d[1]
    sub x17, x17, x16
    cmp x17, #130
    b.ne 2f
    fmov x17, d31
    sub x17, x17, x16
    cmp x17, #131
    b.ne 2f
    mov x17, v31.d[1]
    sub x17, x17, x16
    cmp x17, #131
    b.ne 2f
    ldr x17, [sp, #168]
    subs x17, x17, #1
    str x17, [sp, #168]
    b.ne 3b
    mov x0, #1
    b 4f
2:
    mov x0, #0
4:
    .seh_startepilogue
    ldp x19, x20, [sp, #0]
    .seh_save_regp x19, 0
    ldp x21, x22, [sp, #16]
    .seh_save_regp x21, 16
    ldp x23, x24, [sp, #32]
    .seh_save_regp x23, 32
    ldp x25, x26, [sp, #48]
    .seh_save_regp x25, 48
    ldp x27, x28, [sp, #64]
    .seh_save_regp x27, 64
    ldp x29, x30, [sp, #80]
    .seh_save_fplr 80
    ldp d8, d9, [sp, #96]
    .seh_save_fregp d8, 96
    ldp d10, d11, [sp, #112]
    .seh_save_fregp d10, 112
    ldp d12, d13, [sp, #128]
    .seh_save_fregp d12, 128
    ldp d14, d15, [sp, #144]
    .seh_save_fregp d14, 144
    add sp, sp, #192
    .seh_stackalloc 192
    .seh_endepilogue
    ret
    .seh_endproc
"#
);

unsafe extern "C" {
    fn nk_context_switch(save: *mut u64, load: u64);
    fn nk_thread_start();
    fn nk_call_on_stack(top: u64, call: extern "C" fn(usize), argument: usize);
    fn nk_callee_saved_check(seed: u64, call: extern "C" fn()) -> u64;
    fn nk_all_registers_check(seed: u64, looks: u64) -> u64;
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
    // Above the switch's frame, the zero frame record that ends a walk of
    // this stack (see `nk_thread_start`).
    let sp = stack_top - 16 - FRAME;
    // SAFETY: per the contract; everything written is inside the stack.
    // The switch "returns" through x30, to the start stub, which finds
    // the entry point in x19, the first register of the frame.
    unsafe {
        core::ptr::write_bytes(sp as *mut u8, 0, FRAME as usize + 16);
        (sp as *mut u64).write(entry as usize as u64);
        ((sp + 88) as *mut u64).write(nk_thread_start as *const () as usize as u64);
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

/// Fill every general and vector register with values made from `seed`
/// and look at them `looks` times, calling nothing. Whether none
/// changed. For the test that is interrupted and switched away from
/// while this runs.
pub fn all_registers_survive(seed: u64, looks: u64) -> bool {
    // SAFETY: the routine saves and restores what a call must preserve.
    unsafe { nk_all_registers_check(seed, looks) == 1 }
}
