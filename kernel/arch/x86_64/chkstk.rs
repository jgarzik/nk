//! `__chkstk`: the stack probe a compiler calls before a function takes
//! more than a page of stack.
//!
//! [The contract](https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog):
//! `rax` holds the bytes the caller is about to take; the routine
//! touches every page from the caller's stack pointer down to the new
//! one, so that a guard page is hit in order, and returns with every
//! register but the flags as it was. The caller then moves `rsp`. An NK
//! kernel stack is committed whole with an unmapped stretch below it:
//! a probe past the end faults there, as a stack overflow.

use core::arch::global_asm;

global_asm!(
    r#"
    .text
    .globl nk_chkstk
nk_chkstk:
    .seh_proc nk_chkstk
    push r10
    .seh_pushreg r10
    push r11
    .seh_pushreg r11
    .seh_endprologue
    // r11: the caller's stack pointer; r10: where it will be, or zero
    // if the size wraps.
    lea r11, [rsp + 24]
    mov r10, r11
    sub r10, rax
    jae 2f
    xor r10d, r10d
2:
    and r10, -4096
    and r11, -4096
3:
    cmp r10, r11
    jae 4f
    sub r11, 4096
    test byte ptr [r11], 0
    jmp 3b
4:
    pop r11
    pop r10
    ret
    .seh_endproc
"#
);

unsafe extern "C" {
    /// `__chkstk`, entered with the size in `rax`.
    pub fn nk_chkstk();
}

/// For the self-tests: a probe of three pages returns with the
/// registers it uses unchanged.
pub fn chkstk_test() -> Result<(), &'static str> {
    let (mut size, mut r10, mut r11) = (0x3000u64, 0x1010u64, 0x1111u64);
    // SAFETY: the routine's contract: the size in rax, nothing changed
    // but the flags. Three pages lie well within this thread's stack.
    unsafe {
        core::arch::asm!(
            "call {probe}",
            probe = sym nk_chkstk,
            inout("rax") size,
            inout("r10") r10,
            inout("r11") r11,
        );
    }
    if (size, r10, r11) != (0x3000, 0x1010, 0x1111) {
        return Err("the stack probe changed a register");
    }
    Ok(())
}
