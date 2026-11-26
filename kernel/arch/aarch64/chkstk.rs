//! `__chkstk`: the stack probe a compiler calls before a function takes
//! more than a page of stack.
//!
//! [The contract](https://learn.microsoft.com/en-us/cpp/build/arm64-windows-abi-conventions#stack):
//! `x15` holds the size the caller is about to take, in units of 16
//! bytes; the routine touches every page from the caller's stack
//! pointer down to the new one and returns with `x15` as it was. `x16`
//! and `x17` are its scratch. An NK kernel stack is committed whole
//! with an unmapped stretch below it: a probe past the end faults
//! there, as a stack overflow.

use core::arch::global_asm;

global_asm!(
    r#"
    .text
    .globl nk_chkstk
nk_chkstk:
    .seh_proc nk_chkstk
    .seh_endprologue
    lsl x16, x15, #4
    mov x17, sp
1:
    sub x17, x17, #4096
    subs x16, x16, #4096
    ldr xzr, [x17]
    b.gt 1b
    ret
    .seh_endproc
"#
);

unsafe extern "C" {
    /// `__chkstk`, entered with the size, in units of 16 bytes, in
    /// `x15`.
    pub fn nk_chkstk();
}

/// For the self-tests: a probe of three pages returns with its
/// argument unchanged.
pub fn chkstk_test() -> Result<(), &'static str> {
    let mut size = 0x300u64;
    // SAFETY: the routine's contract: the size in x15; x16, x17 and the
    // link register are its to change. Three pages lie well within this
    // thread's stack.
    unsafe {
        core::arch::asm!(
            "bl {probe}",
            probe = sym nk_chkstk,
            inout("x15") size,
            out("x16") _,
            out("x17") _,
            out("x30") _,
        );
    }
    if size != 0x300 {
        return Err("the stack probe changed its argument");
    }
    Ok(())
}
