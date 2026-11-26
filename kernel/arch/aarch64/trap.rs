//! Exceptions and interrupts: the vector table and the handler.
//!
//! Every vector funnels into one handler with a full register frame. A
//! fault that Windows turns into an exception (an access violation on a
//! user address, an undefined instruction, a breakpoint with no
//! debugger, the breakpoint compiled code executes for a division by
//! zero) is handed to the exception dispatcher with the interrupted
//! code's `CONTEXT`, and the code is resumed with whatever a handler
//! made of it. The rest are fatal: a bugcheck with a register dump.

use super::seh::{self, Context};
use core::arch::global_asm;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use nk_ntabi::seh::arm64::CONTEXT_FULL;

/// Registers saved by the entry stub, lowest address first.
///
/// All 32 vector registers are saved, not only the ones the calling
/// convention calls volatile: the kernel itself is compiled to use them,
/// and a function need only preserve the low half of v8-v15.
///
/// The order serves the entry stub's unwind information, whose codes
/// reach only so far and step by 16 bytes: `sp` and `elr` are a pair at
/// a multiple of 16, and the low halves of v8-v15 lie below offset 512.
#[repr(C)]
pub struct Frame {
    pub x: [u64; 31],
    pub spsr: u64,
    pub q: [[u64; 2]; 32],
    pub sp: u64,
    pub elr: u64,
    pub esr: u64,
    pub far: u64,
    pub fpcr: u64,
    pub fpsr: u64,
}

const _: () = assert!(size_of::<Frame>() == 816);
const _: () = assert!(core::mem::offset_of!(Frame, q) == 256);
const _: () = assert!(core::mem::offset_of!(Frame, sp) == 768);

/// Exception classes (ESR_EL1 bits 31:26): an instruction the processor
/// does not know; an instruction fetch and a data access that faulted,
/// taken from this exception level; a `brk` instruction.
const EC_UNKNOWN: u64 = 0x00;
const EC_INSTRUCTION_ABORT: u64 = 0x21;
const EC_DATA_ABORT: u64 = 0x25;
const EC_BRK: u64 = 0x3C;
/// ESR_EL1 of an abort: bits 5:0 say why, and below this value the page
/// tables did: no translation, no permission, or an address they do not
/// cover. Bit 6: the access was a write.
const ABORT_STATUS: u64 = 0x3F;
const ABORT_BY_TABLES: u64 = 0x10;
const ABORT_WRITE: u64 = 1 << 6;
/// SPSR_EL1: interrupts were masked; the condition flags, which are all
/// of it a handler's context may change.
const SPSR_I: u64 = 1 << 7;
const SPSR_NZCV: u64 = 0xF000_0000;
/// `brk` immediates, as Windows on arm64 assigns them.
const BRK_BREAKPOINT: u64 = 0xF000;
/// What a compiler for Windows puts after a division it found to be by
/// zero, the processor having no trap for one.
const BRK_DIVIDE_BY_ZERO: u64 = 0xF004;
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
//
// Exceptions are taken on the stack that was current, so before storing
// anything an entry checks that the frame it just made room for is still
// on a stack. Every kernel stack has one address bit set throughout and
// clear in the stretch below it (`nk_bootinfo::KERNEL_STACK_SIZE`); the
// stack pointer cannot be tested directly, so it is swapped into x0 and
// back with three additions. An overflow goes to `nk_stack_overflow`,
// which reports it from the processor's overflow stack.
// The common path saves the rest, including the vector registers and the
// floating-point control and status registers, and gives the handler the
// kernel's own control word (round to nearest, no traps).
//
// The vector table has no unwind information: while a vector's first
// instructions run, the interrupted code's pc is only in ELR_EL1, and
// for a few of them sp is not a stack pointer at all.
global_asm!(
    r#"
    .text
    .balign 0x800
    .globl nk_vectors
nk_vectors:
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #0
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #1
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #2
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #3
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #4
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #5
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #6
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #7
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #8
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #9
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #10
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #11
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #12
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #13
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #14
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow
    .balign 0x80
    sub sp, sp, #816
    add sp, sp, x0
    sub x0, sp, x0
    tbz x0, #{stack_shift}, 1f
    sub x0, sp, x0
    sub sp, sp, x0
    stp x0, x1, [sp]
    mov x0, #15
    b nk_trap_common
1:  sub x0, sp, x0
    sub sp, sp, x0
    b nk_stack_overflow

// Entered with sp and every register as at the exception, less the frame
// already subtracted from sp. Nothing can be saved on that stack. The
// report is entered with no return address: a walk of the overflow stack
// ends there.
nk_stack_overflow:
    msr tpidrro_el0, x0
    mrs x0, tpidr_el1
    ldr x0, [x0, #{overflow_top}]
    mov x1, sp
    mov sp, x0
    add x0, x1, #816
    mrs x1, elr_el1
    mrs x2, far_el1
    mov x29, xzr
    mov x30, xzr
    b {overflow}

// Unwind information: from the call of the handler until the frame is
// given up, a stack walk gets the interrupted code's sp and pc (the pair
// at #768 is what Windows' unwind codes call a machine frame), x19-x30
// and d8-d15 from where the frame holds them. The codes are attached to
// the instructions that store those, or to later ones. The entry
// sequence cannot be walked: until its last stores the interrupted pc is
// only in ELR_EL1, where no unwind code can find it.
nk_trap_common:
    .seh_proc nk_trap_common
    mov x1, x0
    .seh_pushframe
    stp x2, x3, [sp, #16]
    .seh_stackalloc 768
    stp x4, x5, [sp, #32]
    .seh_nop
    stp x6, x7, [sp, #48]
    .seh_nop
    stp x8, x9, [sp, #64]
    .seh_nop
    stp x10, x11, [sp, #80]
    .seh_nop
    stp x12, x13, [sp, #96]
    .seh_nop
    stp x14, x15, [sp, #112]
    .seh_nop
    stp x16, x17, [sp, #128]
    .seh_nop
    stp x18, x19, [sp, #144]
    .seh_save_reg x19, 152
    stp x20, x21, [sp, #160]
    .seh_save_regp x20, 160
    stp x22, x23, [sp, #176]
    .seh_save_regp x22, 176
    stp x24, x25, [sp, #192]
    .seh_save_regp x24, 192
    stp x26, x27, [sp, #208]
    .seh_save_regp x26, 208
    stp x28, x29, [sp, #224]
    .seh_save_reg x28, 224
    mrs x10, spsr_el1
    .seh_nop
    stp x30, x10, [sp, #240]
    .seh_save_fplr 232
    add x11, sp, #768
    .seh_nop
    add x9, sp, #816
    .seh_nop
    mrs x10, elr_el1
    .seh_nop
    stp x9, x10, [x11]
    .seh_nop
    mrs x9, esr_el1
    .seh_nop
    mrs x10, far_el1
    .seh_nop
    stp x9, x10, [x11, #16]
    .seh_nop
    stp q0, q1, [sp, #256]
    .seh_nop
    stp q2, q3, [sp, #288]
    .seh_nop
    stp q4, q5, [sp, #320]
    .seh_nop
    stp q6, q7, [sp, #352]
    .seh_nop
    stp q8, q9, [sp, #384]
    .seh_save_freg d8, 384
    stp q10, q11, [sp, #416]
    .seh_save_freg d9, 400
    stp q12, q13, [sp, #448]
    .seh_save_freg d10, 416
    stp q14, q15, [sp, #480]
    .seh_save_freg d11, 432
    stp q16, q17, [sp, #512]
    .seh_save_freg d12, 448
    stp q18, q19, [sp, #544]
    .seh_save_freg d13, 464
    stp q20, q21, [sp, #576]
    .seh_save_freg d14, 480
    stp q22, q23, [sp, #608]
    .seh_save_freg d15, 496
    stp q24, q25, [sp, #640]
    .seh_nop
    stp q26, q27, [sp, #672]
    .seh_nop
    stp q28, q29, [sp, #704]
    .seh_nop
    stp q30, q31, [sp, #736]
    .seh_nop
    mrs x9, fpcr
    .seh_nop
    mrs x10, fpsr
    .seh_nop
    stp x9, x10, [x11, #32]
    .seh_nop
    .seh_endprologue
    msr fpcr, xzr
    mov x0, sp
    bl {handler}
    add x11, sp, #768
    ldp x9, x10, [x11, #32]
    msr fpcr, x9
    msr fpsr, x10
    ldp q0, q1, [sp, #256]
    ldp q2, q3, [sp, #288]
    ldp q4, q5, [sp, #320]
    ldp q6, q7, [sp, #352]
    ldp q8, q9, [sp, #384]
    ldp q10, q11, [sp, #416]
    ldp q12, q13, [sp, #448]
    ldp q14, q15, [sp, #480]
    ldp q16, q17, [sp, #512]
    ldp q18, q19, [sp, #544]
    ldp q20, q21, [sp, #576]
    ldp q22, q23, [sp, #608]
    ldp q24, q25, [sp, #640]
    ldp q26, q27, [sp, #672]
    ldp q28, q29, [sp, #704]
    ldp q30, q31, [sp, #736]
    ldr x9, [x11, #8]
    ldr x10, [sp, #248]
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
    // x18 names the processor, not the thread: the thread being
    // resumed may have been taken by another processor since this
    // frame was saved. It comes from the processor, never the frame.
    ldr x19, [sp, #152]
    mrs x18, tpidr_el1
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    // The stack pointer comes from the frame: an exception handler may
    // have changed it. Nothing can be loaded into it from memory, and no
    // register is free, so x28 and x29 make the trip through the two
    // words below where it will point: the frame's last, already used,
    // unless it was changed.
    ldr x29, [sp, #768]
    ldr x28, [sp, #224]
    str x28, [x29, #-16]
    ldr x28, [sp, #232]
    str x28, [x29, #-8]
    mov sp, x29
    ldp x28, x29, [sp, #-16]
    eret
    .seh_endproc

// For `fp_trap_test`. Load v0-v31 and FPCR from the block at x0, take a
// breakpoint, store what they hold afterwards in the block at x1. A block
// is 32 16-byte registers, then FPCR. The low halves of v8-v15 and FPCR
// are the caller's to keep, so they are saved around it.
    .globl nk_fp_trap_probe
nk_fp_trap_probe:
    .seh_proc nk_fp_trap_probe
    sub sp, sp, #80
    .seh_stackalloc 80
    stp d8, d9, [sp]
    .seh_save_fregp d8, 0
    stp d10, d11, [sp, #16]
    .seh_save_fregp d10, 16
    stp d12, d13, [sp, #32]
    .seh_save_fregp d12, 32
    stp d14, d15, [sp, #48]
    .seh_save_fregp d14, 48
    .seh_endprologue
    mrs x9, fpcr
    str x9, [sp, #64]
    ldp q0, q1, [x0]
    ldp q2, q3, [x0, #32]
    ldp q4, q5, [x0, #64]
    ldp q6, q7, [x0, #96]
    ldp q8, q9, [x0, #128]
    ldp q10, q11, [x0, #160]
    ldp q12, q13, [x0, #192]
    ldp q14, q15, [x0, #224]
    ldp q16, q17, [x0, #256]
    ldp q18, q19, [x0, #288]
    ldp q20, q21, [x0, #320]
    ldp q22, q23, [x0, #352]
    ldp q24, q25, [x0, #384]
    ldp q26, q27, [x0, #416]
    ldp q28, q29, [x0, #448]
    ldp q30, q31, [x0, #480]
    ldr x9, [x0, #512]
    msr fpcr, x9
    brk #0xf000
    stp q0, q1, [x1]
    stp q2, q3, [x1, #32]
    stp q4, q5, [x1, #64]
    stp q6, q7, [x1, #96]
    stp q8, q9, [x1, #128]
    stp q10, q11, [x1, #160]
    stp q12, q13, [x1, #192]
    stp q14, q15, [x1, #224]
    stp q16, q17, [x1, #256]
    stp q18, q19, [x1, #288]
    stp q20, q21, [x1, #320]
    stp q22, q23, [x1, #352]
    stp q24, q25, [x1, #384]
    stp q26, q27, [x1, #416]
    stp q28, q29, [x1, #448]
    stp q30, q31, [x1, #480]
    mrs x9, fpcr
    str x9, [x1, #512]
    ldr x9, [sp, #64]
    msr fpcr, x9
    .seh_startepilogue
    ldp d8, d9, [sp]
    .seh_save_fregp d8, 0
    ldp d10, d11, [sp, #16]
    .seh_save_fregp d10, 16
    ldp d12, d13, [sp, #32]
    .seh_save_fregp d12, 32
    ldp d14, d15, [sp, #48]
    .seh_save_fregp d14, 48
    add sp, sp, #80
    .seh_stackalloc 80
    .seh_endepilogue
    ret
    .seh_endproc
// What code run from an interrupt is entitled to do: overwrite every
// vector register except the low halves of v8-v15. Returns the FPCR it
// runs with.
    .globl nk_fp_clobber
nk_fp_clobber:
    .seh_proc nk_fp_clobber
    .seh_endprologue
    mrs x0, fpcr
    mov x9, #-1
    movi v0.16b, #0xff
    movi v1.16b, #0xff
    movi v2.16b, #0xff
    movi v3.16b, #0xff
    movi v4.16b, #0xff
    movi v5.16b, #0xff
    movi v6.16b, #0xff
    movi v7.16b, #0xff
    ins v8.d[1], x9
    ins v9.d[1], x9
    ins v10.d[1], x9
    ins v11.d[1], x9
    ins v12.d[1], x9
    ins v13.d[1], x9
    ins v14.d[1], x9
    ins v15.d[1], x9
    movi v16.16b, #0xff
    movi v17.16b, #0xff
    movi v18.16b, #0xff
    movi v19.16b, #0xff
    movi v20.16b, #0xff
    movi v21.16b, #0xff
    movi v22.16b, #0xff
    movi v23.16b, #0xff
    movi v24.16b, #0xff
    movi v25.16b, #0xff
    movi v26.16b, #0xff
    movi v27.16b, #0xff
    movi v28.16b, #0xff
    movi v29.16b, #0xff
    movi v30.16b, #0xff
    movi v31.16b, #0xff
    ret
    .seh_endproc
"#,
    handler = sym trap_handler,
    overflow = sym stack_overflow,
    overflow_top = const super::cpu::OVERFLOW_TOP,
    stack_shift = const nk_bootinfo::KERNEL_STACK_SHIFT,
);

/// The kernel stack overflowed. Runs on the overflow stack; the registers
/// of the interrupted code, other than these, are gone.
extern "C" fn stack_overflow(sp: u64, pc: u64, far: u64) -> ! {
    crate::kd::bugcheck(format_args!(
        "kernel stack overflow at pc={pc:#018x}\nsp={sp:#018x} far={far:#018x}"
    ))
}

unsafe extern "C" {
    static nk_vectors: u8;
    fn nk_fp_trap_probe(load: *const FpBlock, store: *mut FpBlock);
    fn nk_fp_clobber() -> u64;
}

/// v0-v31 and FPCR, as `nk_fp_trap_probe` loads and stores them.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct FpBlock {
    q: [[u64; 2]; 32],
    fpcr: u64,
}

/// Set while `fp_trap_test` wants the breakpoint handler to overwrite the
/// vector registers.
static FP_CLOBBER: AtomicBool = AtomicBool::new(false);
/// The FPCR the handler ran with during that breakpoint.
static HANDLER_FPCR: AtomicU64 = AtomicU64::new(u64::MAX);

/// An exception must not disturb the vector registers or FPCR of the
/// code it interrupts, even when the handler (as a driver's code may)
/// overwrites every one the calling convention lets it; and the handler
/// must run with the kernel's own FPCR, not the interrupted code's.
pub fn fp_trap_test() -> Result<(), &'static str> {
    let mut load = FpBlock {
        q: [[0; 2]; 32],
        // Round toward zero (RMode = 0b11): a value no kernel code sets,
        // so finding it again afterwards means it was restored.
        fpcr: 0b11 << 22,
    };
    for (i, reg) in load.q.iter_mut().enumerate() {
        *reg = [0x0101_0101_0101_0101 * (i as u64 + 1), !(i as u64)];
    }
    let mut store = FpBlock {
        q: [[0; 2]; 32],
        fpcr: 0,
    };
    FP_CLOBBER.store(true, Ordering::Relaxed);
    crate::kd::expect_breakpoint(true);
    // SAFETY: both blocks are live and of the size the probe reads and
    // writes; it preserves what the calling convention says it must.
    unsafe { nk_fp_trap_probe(&raw const load, &raw mut store) };
    crate::kd::expect_breakpoint(false);
    FP_CLOBBER.store(false, Ordering::Relaxed);
    if HANDLER_FPCR.load(Ordering::Relaxed) != 0 {
        return Err("the handler ran with the interrupted code's FPCR");
    }
    if store.fpcr != load.fpcr {
        return Err("FPCR was not restored after the exception");
    }
    if store.q != load.q {
        return Err("a vector register was not restored after the exception");
    }
    Ok(())
}

/// The interrupted code as a `CONTEXT`.
fn context_of(frame: &Frame) -> Context {
    let mut c = seh::empty_context();
    c.ContextFlags = CONTEXT_FULL;
    c.Cpsr = frame.spsr as u32;
    c.X.copy_from_slice(&frame.x[..29]);
    (c.Fp, c.Lr, c.Sp, c.Pc) = (frame.x[29], frame.x[30], frame.sp, frame.elr);
    for (v, [low, high]) in c.V.iter_mut().zip(frame.q) {
        (v.Low, v.High) = (low, high as i64);
    }
    (c.Fpcr, c.Fpsr) = (frame.fpcr as u32, frame.fpsr as u32);
    c
}

/// Make the interrupted code resume as `c` says: every register (x18,
/// which is the processor's, excepted on the way out), the program
/// counter, the stack pointer and the condition flags.
fn resume_as(frame: &mut Frame, c: &Context) {
    frame.x[..29].copy_from_slice(&c.X);
    (frame.x[29], frame.x[30], frame.sp, frame.elr) = (c.Fp, c.Lr, c.Sp, c.Pc);
    frame.spsr = frame.spsr & !SPSR_NZCV | u64::from(c.Cpsr) & SPSR_NZCV;
    for (slot, v) in frame.q.iter_mut().zip(&c.V) {
        *slot = [v.Low, v.High as u64];
    }
    (frame.fpcr, frame.fpsr) = (u64::from(c.Fpcr), u64::from(c.Fpsr));
}

/// Hand the fault to the exception dispatcher as `code`. Returns if a
/// handler has the code continue; a handler that takes the exception
/// unwinds, and this frame is gone with the rest.
fn deliver(frame: &mut Frame, code: u32, parameters: &[u64]) {
    let mut context = context_of(frame);
    // Handlers run as the interrupted code did: with interrupts on, if
    // it had them on.
    let enabled = frame.spsr & SPSR_I == 0;
    if enabled {
        super::enable_interrupts();
    }
    // SAFETY: the context is the interrupted code's, whose frames lie
    // beneath this one; this function and its callers hold nothing a
    // destructor would have to give back.
    unsafe { crate::ke::seh::fault(&raw mut context, code, parameters) };
    if enabled {
        super::disable_interrupts();
    }
    resume_as(frame, &context);
}

extern "C" fn trap_handler(frame: &mut Frame, vector: u64) {
    use crate::ke::seh::{
        ACCESS_EXECUTE, ACCESS_READ, ACCESS_WRITE, STATUS_ACCESS_VIOLATION, STATUS_BREAKPOINT,
        STATUS_ILLEGAL_INSTRUCTION, STATUS_INTEGER_DIVIDE_BY_ZERO,
    };
    // Vectors come in fours: synchronous, IRQ, FIQ, SError.
    let class = (vector & 3 == 0).then_some(frame.esr >> 26);
    let brk = (class == Some(EC_BRK)).then_some(frame.esr & 0xFFFF);
    if brk == Some(BRK_BREAKPOINT) {
        if crate::kd::breakpoint(frame.elr) {
            BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
            // `brk` is a fault: going on means stepping past the 4-byte
            // instruction.
            frame.elr += 4;
            if FP_CLOBBER.load(Ordering::Relaxed) {
                // SAFETY: the routine only writes registers, as any
                // function may.
                HANDLER_FPCR.store(unsafe { nk_fp_clobber() }, Ordering::Relaxed);
            }
            return;
        }
        return deliver(frame, STATUS_BREAKPOINT, &[0]);
    }
    if vector & 3 == 1 {
        return super::gic::interrupt();
    }
    let mut stop = None;
    match class {
        Some(EC_BRK) if brk == Some(BRK_DIVIDE_BY_ZERO) => {
            return deliver(frame, STATUS_INTEGER_DIVIDE_BY_ZERO, &[]);
        }
        Some(EC_UNKNOWN) => return deliver(frame, STATUS_ILLEGAL_INSTRUCTION, &[]),
        Some(abort @ (EC_DATA_ABORT | EC_INSTRUCTION_ABORT))
            if frame.esr & ABORT_STATUS < ABORT_BY_TABLES =>
        {
            let access = match abort {
                EC_INSTRUCTION_ABORT => ACCESS_EXECUTE,
                _ if frame.esr & ABORT_WRITE != 0 => ACCESS_WRITE,
                _ => ACCESS_READ,
            };
            // The kernel's own access to memory that may not be there:
            // the routine returns an error instead.
            if let Some(resume) = seh::fixup(frame.elr) {
                (frame.elr, frame.x[9], frame.x[10]) = (resume, frame.far, access);
                return;
            }
            stop = crate::ke::seh::memory_fault(frame.far, access, frame.elr);
            if stop.is_none() {
                return deliver(frame, STATUS_ACCESS_VIOLATION, &[access, frame.far]);
            }
        }
        _ => {}
    }
    let kind = match brk {
        Some(BRK_FAST_FAIL) => "driver fast-fail (reason code in x0)",
        _ => ["synchronous exception", "IRQ", "FIQ", "SError"][(vector & 3) as usize],
    };
    let x = &frame.x;
    let image = crate::ldr::locate_fatal(frame.elr);
    let stop = crate::ke::seh::StopLine(stop);
    crate::kd::bugcheck(format_args!(
        "{stop}{kind} (vector {vector}, esr {:#x}) at pc={:#018x} in {image}\n\
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

/// Execute a breakpoint instruction: the kernel's own, for its tests.
pub fn breakpoint() {
    crate::kd::expect_breakpoint(true);
    // SAFETY: `brk` traps to the handler above, which resumes after it.
    unsafe { core::arch::asm!("brk #0xf000", options(nomem, nostack)) };
    crate::kd::expect_breakpoint(false);
}

/// Execute a breakpoint instruction the way a driver's `DbgBreakPoint`
/// does: unannounced.
pub fn driver_breakpoint() {
    // SAFETY: `brk` traps to the handler above.
    unsafe { core::arch::asm!("brk #0xf000", options(nomem, nostack)) };
}
