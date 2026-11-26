//! Assembly for the exception tests (`selftest::seh`): routines shaped
//! like a driver's compiled C, with the unwind information, the
//! language handler and the scope tables a compiler would give them.
//! No Rust function can stand in for these: Rust has no `__try`.

use core::arch::global_asm;

global_asm!(
    r#"
    .text
    .globl nk_seh_try
// `__try {{ body(argument) }} __except (filter(...)) {{ }}`.
// x0: body. x1: its argument. x2: a seed. Every register a call
// preserves, but the frame pointer, holds a value made from the seed
// while the body runs. Returns 0 if the body returned; if the
// `__except` block got control, the exception's code, or
// `REGISTERS_LOST` if one of those registers did not come back with
// its value.
nk_seh_try:
    .seh_proc nk_seh_try
    .seh_handler {c_handler}, @unwind, @except
    stp x29, x30, [sp, #-128]!
    .seh_save_fplr_x 128
    stp x19, x20, [sp, #16]
    .seh_save_regp x19, 16
    stp x21, x22, [sp, #32]
    .seh_save_regp x21, 32
    stp x23, x24, [sp, #48]
    .seh_save_regp x23, 48
    stp x25, x26, [sp, #64]
    .seh_save_regp x25, 64
    stp x27, x28, [sp, #80]
    .seh_save_regp x27, 80
    stp d8, d9, [sp, #96]
    .seh_save_fregp d8, 96
    .seh_endprologue
    str x2, [sp, #112]
    add x19, x2, #1
    add x20, x2, #2
    add x21, x2, #3
    add x22, x2, #4
    add x23, x2, #5
    add x24, x2, #6
    add x25, x2, #7
    add x26, x2, #8
    add x27, x2, #9
    add x28, x2, #10
    fmov d8, x19
    fmov d9, x20
    mov x9, x0
    mov x0, x1
nk_seh_try_begin:
    blr x9
nk_seh_try_end:
    mov x0, #0
    b 3f
// The `__except` block: x0 is the exception's code.
nk_seh_try_except:
    ldr x2, [sp, #112]
    add x9, x2, #1
    cmp x19, x9
    b.ne 2f
    fmov x10, d8
    cmp x10, x9
    b.ne 2f
    add x9, x2, #2
    cmp x20, x9
    b.ne 2f
    fmov x10, d9
    cmp x10, x9
    b.ne 2f
    add x9, x2, #3
    cmp x21, x9
    b.ne 2f
    add x9, x2, #4
    cmp x22, x9
    b.ne 2f
    add x9, x2, #5
    cmp x23, x9
    b.ne 2f
    add x9, x2, #6
    cmp x24, x9
    b.ne 2f
    add x9, x2, #7
    cmp x25, x9
    b.ne 2f
    add x9, x2, #8
    cmp x26, x9
    b.ne 2f
    add x9, x2, #9
    cmp x27, x9
    b.ne 2f
    add x9, x2, #10
    cmp x28, x9
    b.ne 2f
    mov w0, w0
    b 3f
2:  mov w0, #{lost_low}
    movk w0, #{lost_high}, lsl #16
3:
    .seh_startepilogue
    ldp d8, d9, [sp, #96]
    .seh_save_fregp d8, 96
    ldp x27, x28, [sp, #80]
    .seh_save_regp x27, 80
    ldp x25, x26, [sp, #64]
    .seh_save_regp x25, 64
    ldp x23, x24, [sp, #48]
    .seh_save_regp x23, 48
    ldp x21, x22, [sp, #32]
    .seh_save_regp x21, 32
    ldp x19, x20, [sp, #16]
    .seh_save_regp x19, 16
    ldp x29, x30, [sp], #128
    .seh_save_fplr_x 128
    .seh_endepilogue
    ret
    .seh_handlerdata
    .long 1
    .rva nk_seh_try_begin
    .rva nk_seh_try_end
    .rva {filter}
    .rva nk_seh_try_except
    .text
    .seh_endproc

    .globl nk_seh_finally
// `__try {{ body(argument) }} __finally {{ finally(...) }}`.
// x0: body. x1: its argument.
nk_seh_finally:
    .seh_proc nk_seh_finally
    .seh_handler {c_handler}, @unwind, @except
    stp x29, x30, [sp, #-16]!
    .seh_save_fplr_x 16
    .seh_endprologue
    mov x9, x0
    mov x0, x1
nk_seh_finally_begin:
    blr x9
nk_seh_finally_end:
    mov w0, #0
    add x1, sp, #16
    bl {finally}
    .seh_startepilogue
    ldp x29, x30, [sp], #16
    .seh_save_fplr_x 16
    .seh_endepilogue
    ret
    .seh_handlerdata
    .long 1
    .rva nk_seh_finally_begin
    .rva nk_seh_finally_end
    .rva {finally}
    .long 0
    .text
    .seh_endproc

    .globl nk_seh_edge
// A `__try` whose guarded range ends just before the call to the body:
// x0, with argument x1. On arm64 a frame is looked up by its call
// instruction, which is the first past the range: an exception the
// body raises is not this scope's.
nk_seh_edge:
    .seh_proc nk_seh_edge
    .seh_handler {c_handler}, @unwind, @except
    stp x29, x30, [sp, #-16]!
    .seh_save_fplr_x 16
    .seh_endprologue
    mov x9, x0
    mov x0, x1
nk_seh_edge_begin:
    nop
nk_seh_edge_end:
    blr x9
nk_seh_edge_except:
    .seh_startepilogue
    ldp x29, x30, [sp], #16
    .seh_save_fplr_x 16
    .seh_endepilogue
    ret
    .seh_handlerdata
    .long 1
    .rva nk_seh_edge_begin
    .rva nk_seh_edge_end
    .rva {filter}
    .rva nk_seh_edge_except
    .text
    .seh_endproc

    .globl nk_seh_clobber
// x0: body. x1: its argument. Calls the body with every register a
// call preserves, but the frame pointer, overwritten, as a function
// that uses them all may: whoever unwinds this frame must put the
// caller's values back.
nk_seh_clobber:
    .seh_proc nk_seh_clobber
    stp x29, x30, [sp, #-112]!
    .seh_save_fplr_x 112
    stp x19, x20, [sp, #16]
    .seh_save_regp x19, 16
    stp x21, x22, [sp, #32]
    .seh_save_regp x21, 32
    stp x23, x24, [sp, #48]
    .seh_save_regp x23, 48
    stp x25, x26, [sp, #64]
    .seh_save_regp x25, 64
    stp x27, x28, [sp, #80]
    .seh_save_regp x27, 80
    stp d8, d9, [sp, #96]
    .seh_save_fregp d8, 96
    .seh_endprologue
    mov x19, #-1
    mov x20, x19
    mov x21, x19
    mov x22, x19
    mov x23, x19
    mov x24, x19
    mov x25, x19
    mov x26, x19
    mov x27, x19
    mov x28, x19
    fmov d8, x19
    fmov d9, x19
    mov x9, x0
    mov x0, x1
    blr x9
    .seh_startepilogue
    ldp d8, d9, [sp, #96]
    .seh_save_fregp d8, 96
    ldp x27, x28, [sp, #80]
    .seh_save_regp x27, 80
    ldp x25, x26, [sp, #64]
    .seh_save_regp x25, 64
    ldp x23, x24, [sp, #48]
    .seh_save_regp x23, 48
    ldp x21, x22, [sp, #32]
    .seh_save_regp x21, 32
    ldp x19, x20, [sp, #16]
    .seh_save_regp x19, 16
    ldp x29, x30, [sp], #112
    .seh_save_fplr_x 112
    .seh_endepilogue
    ret
    .seh_endproc

    .globl nk_seh_no_unwind
// x0: body. x1: its argument. A function that calls another and has no
// unwind entry: what a walk must refuse to pass.
nk_seh_no_unwind:
    stp x29, x30, [sp, #-16]!
    mov x9, x0
    mov x0, x1
    blr x9
    ldp x29, x30, [sp], #16
    ret
"#,
    c_handler = sym crate::ke::seh::__C_specific_handler,
    filter = sym crate::selftest::except::filter,
    finally = sym crate::selftest::except::finally,
    lost_low = const REGISTERS_LOST & 0xFFFF,
    lost_high = const REGISTERS_LOST >> 16,
);

/// What `nk_seh_try` returns when its `__except` block was entered with
/// a call-preserved register changed.
pub const REGISTERS_LOST: u32 = 0xBAD0_BAD0;

/// The body the test routines call.
pub type Body = unsafe extern "C" fn(usize);

unsafe extern "C" {
    pub fn nk_seh_try(body: Body, argument: usize, seed: usize) -> u64;
    pub fn nk_seh_finally(body: Body, argument: usize);
    pub fn nk_seh_edge(body: Body, argument: usize);
    pub fn nk_seh_clobber(body: Body, argument: usize);
    pub fn nk_seh_no_unwind(body: Body, argument: usize);
}
