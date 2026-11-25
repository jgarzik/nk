//! Entry points for C functions with a variable number of arguments.
//!
//! Stable Rust cannot define one, so each is a few instructions of
//! assembly that turn the call's arguments into an array and pass its
//! address to an ordinary Rust function. On arm64 Windows passes a
//! variadic call's arguments in x0-x7, floating-point ones included,
//! and the rest on the stack. Pushing the eight registers directly
//! below the stack arguments makes all of them one array.

use core::arch::global_asm;

global_asm!(
    r#"
    .text
    .macro nk_variadic entry, target
    .globl \entry
\entry:
    sub sp, sp, #64
    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x29, x30, [sp, #-16]!
    add x0, sp, #16
    bl \target
    ldp x29, x30, [sp], #16
    add sp, sp, #64
    ret
    .endm

    nk_variadic nk_variadic_DbgPrint, nk_dbg_print
    nk_variadic nk_variadic__snwprintf, nk_snwprintf
"#
);
