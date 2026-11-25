//! Exceptions and interrupts: the vector table and the handler.
//!
//! Every vector funnels into one handler with a full register frame. A
//! breakpoint is counted and resumed (the boot self-test uses it to prove
//! the path works). Anything else is a fatal bugcheck with a register dump:
//! there is no SEH yet, so no driver or kernel code can handle a fault.

use core::arch::global_asm;
use core::sync::atomic::{AtomicU32, Ordering};

/// Registers saved by the entry stub, lowest address first.
#[repr(C)]
pub struct Frame {
    pub x: [u64; 31],
    pub sp: u64,
    pub elr: u64,
    pub spsr: u64,
    pub esr: u64,
    pub far: u64,
}

/// Exception class (ESR_EL1 bits 31:26) of a `brk` instruction.
const EC_BRK: u64 = 0x3C;
/// `brk` immediates, as Windows on arm64 assigns them.
const BRK_BREAKPOINT: u64 = 0xF000;
/// `__fastfail`: how MSVC-built code reports fatal corruption (a failed
/// stack-cookie check, for one). The reason code is in x0.
const BRK_FAST_FAIL: u64 = 0xF003;

static BREAKPOINTS: AtomicU32 = AtomicU32::new(0);

/// How many breakpoint exceptions have been taken and resumed.
pub fn breakpoints() -> u32 {
    BREAKPOINTS.load(Ordering::Relaxed)
}

// Sixteen vectors of 0x80 bytes each: {current EL with SP0, current EL
// with SPx, lower EL 64-bit, lower EL 32-bit} x {sync, IRQ, FIQ, SError}.
// Each makes room for a Frame, saves x0/x1, and passes its index in x0.
global_asm!(
    r#"
    .text
    .balign 0x800
    .globl nk_vectors
nk_vectors:
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #0
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #1
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #2
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #3
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #4
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #5
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #6
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #7
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #8
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #9
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #10
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #11
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #12
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #13
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #14
    b nk_trap_common
    .balign 0x80
    sub sp, sp, #288
    stp x0, x1, [sp]
    mov x0, #15
    b nk_trap_common

nk_trap_common:
    mov x1, x0
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    add x9, sp, #0x120
    stp x30, x9, [sp, #240]
    mrs x9, elr_el1
    mrs x10, spsr_el1
    stp x9, x10, [sp, #256]
    mrs x9, esr_el1
    mrs x10, far_el1
    stp x9, x10, [sp, #272]
    mov x0, sp
    bl {handler}
    ldp x9, x10, [sp, #256]
    msr elr_el1, x9
    msr spsr_el1, x10
    ldr x30, [sp, #240]
    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    add sp, sp, #0x120
    eret
"#,
    handler = sym trap_handler,
);

unsafe extern "C" {
    static nk_vectors: u8;
}

extern "C" fn trap_handler(frame: &mut Frame, vector: u64) {
    let brk = (vector & 3 == 0 && frame.esr >> 26 == EC_BRK).then_some(frame.esr & 0xFFFF);
    if brk == Some(BRK_BREAKPOINT) {
        // `brk` is a fault: step past the 4-byte instruction.
        BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
        frame.elr += 4;
        return;
    }
    let kind = match brk {
        Some(BRK_FAST_FAIL) => "driver fast-fail (reason code in x0)",
        _ => ["synchronous exception", "IRQ", "FIQ", "SError"][(vector & 3) as usize],
    };
    let x = &frame.x;
    crate::kd::bugcheck(format_args!(
        "{kind} (vector {vector}, esr {:#x}) at pc={:#018x}\n\
         far={:#018x} sp={:#018x} spsr={:#x} x18={:#018x}\n\
         x0 ={:#018x} x1 ={:#018x} x2 ={:#018x} x3 ={:#018x}\n\
         x4 ={:#018x} x5 ={:#018x} x6 ={:#018x} x7 ={:#018x}\n\
         x8 ={:#018x} x19={:#018x} x20={:#018x} x21={:#018x}\n\
         x29={:#018x} x30={:#018x}",
        frame.esr,
        frame.elr,
        frame.far,
        frame.sp,
        frame.spsr,
        x[18],
        x[0],
        x[1],
        x[2],
        x[3],
        x[4],
        x[5],
        x[6],
        x[7],
        x[8],
        x[19],
        x[20],
        x[21],
        x[29],
        x[30],
    ))
}

/// Install the vector table.
pub fn init() {
    // SAFETY: `nk_vectors` is the aligned table defined above; every entry
    // saves state and reaches `trap_handler`.
    unsafe {
        core::arch::asm!("msr vbar_el1, {}", "isb", in(reg) &raw const nk_vectors as u64, options(nomem, nostack));
    }
}

/// Execute a breakpoint instruction.
pub fn breakpoint() {
    // SAFETY: `brk` traps to the handler above, which resumes after it.
    unsafe { core::arch::asm!("brk #0xf000", options(nomem, nostack)) };
}
