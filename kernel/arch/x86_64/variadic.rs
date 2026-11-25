//! Entry points for C functions with a variable number of arguments.
//!
//! Stable Rust cannot define one, so each is a few instructions of
//! assembly that turn the call's arguments into an array and pass its
//! address to an ordinary Rust function. In the Microsoft x86-64
//! convention that is nearly free: the caller has left room above the
//! return address for the four register arguments ("home space"), and
//! the rest follow it on the stack. Storing the four registers there
//! makes all the arguments one array.

use core::arch::global_asm;

global_asm!(
    r#"
    .text
    .macro nk_variadic entry, target
    .globl \entry
\entry:
    .seh_proc \entry
    mov [rsp + 8], rcx
    mov [rsp + 16], rdx
    mov [rsp + 24], r8
    mov [rsp + 32], r9
    lea rcx, [rsp + 8]
    sub rsp, 40
    .seh_stackalloc 40
    .seh_endprologue
    call \target
    add rsp, 40
    ret
    .seh_endproc
    .endm

    nk_variadic nk_variadic_DbgPrint, nk_dbg_print
    nk_variadic nk_variadic__snwprintf, nk_snwprintf
"#
);
