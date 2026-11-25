//! Exceptions and interrupts: the vector table and the handler.
//!
//! Every vector funnels into one handler with a full register frame. A
//! breakpoint is counted and resumed (the boot self-test uses it to prove
//! the path works). Anything else is a fatal bugcheck with a register dump:
//! there is no SEH yet, so no driver or kernel code can handle a fault.

use core::arch::global_asm;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Registers saved by the entry stub, lowest address first.
///
/// All 32 vector registers are saved, not only the ones the calling
/// convention calls volatile: the kernel itself is compiled to use them,
/// and a function need only preserve the low half of v8-v15.
#[repr(C)]
pub struct Frame {
    pub x: [u64; 31],
    pub sp: u64,
    pub elr: u64,
    pub spsr: u64,
    pub esr: u64,
    pub far: u64,
    pub q: [[u64; 2]; 32],
    pub fpcr: u64,
    pub fpsr: u64,
}

const _: () = assert!(size_of::<Frame>() == 816);

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
// already subtracted from sp. Nothing can be saved on that stack.
nk_stack_overflow:
    msr tpidrro_el0, x0
    mrs x0, tpidr_el1
    ldr x0, [x0, #{overflow_top}]
    mov x1, sp
    mov sp, x0
    add x0, x1, #816
    mrs x1, elr_el1
    mrs x2, far_el1
    bl {overflow}

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
    add x9, sp, #816
    stp x30, x9, [sp, #240]
    mrs x9, elr_el1
    mrs x10, spsr_el1
    stp x9, x10, [sp, #256]
    mrs x9, esr_el1
    mrs x10, far_el1
    stp x9, x10, [sp, #272]
    stp q0, q1, [sp, #288]
    stp q2, q3, [sp, #320]
    stp q4, q5, [sp, #352]
    stp q6, q7, [sp, #384]
    stp q8, q9, [sp, #416]
    stp q10, q11, [sp, #448]
    stp q12, q13, [sp, #480]
    stp q14, q15, [sp, #512]
    stp q16, q17, [sp, #544]
    stp q18, q19, [sp, #576]
    stp q20, q21, [sp, #608]
    stp q22, q23, [sp, #640]
    stp q24, q25, [sp, #672]
    stp q26, q27, [sp, #704]
    stp q28, q29, [sp, #736]
    stp q30, q31, [sp, #768]
    mrs x9, fpcr
    mrs x10, fpsr
    add x11, sp, #800
    stp x9, x10, [x11]
    msr fpcr, xzr
    mov x0, sp
    bl {handler}
    add x11, sp, #800
    ldp x9, x10, [x11]
    msr fpcr, x9
    msr fpsr, x10
    ldp q0, q1, [sp, #288]
    ldp q2, q3, [sp, #320]
    ldp q4, q5, [sp, #352]
    ldp q6, q7, [sp, #384]
    ldp q8, q9, [sp, #416]
    ldp q10, q11, [sp, #448]
    ldp q12, q13, [sp, #480]
    ldp q14, q15, [sp, #512]
    ldp q16, q17, [sp, #544]
    ldp q18, q19, [sp, #576]
    ldp q20, q21, [sp, #608]
    ldp q22, q23, [sp, #640]
    ldp q24, q25, [sp, #672]
    ldp q26, q27, [sp, #704]
    ldp q28, q29, [sp, #736]
    ldp q30, q31, [sp, #768]
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
    add sp, sp, #816
    eret

// For `fp_trap_test`. Load v0-v31 and FPCR from the block at x0, take a
// breakpoint, store what they hold afterwards in the block at x1. A block
// is 32 16-byte registers, then FPCR. The low halves of v8-v15 and FPCR
// are the caller's to keep, so they are saved around it.
    .globl nk_fp_trap_probe
nk_fp_trap_probe:
    sub sp, sp, #80
    stp d8, d9, [sp]
    stp d10, d11, [sp, #16]
    stp d12, d13, [sp, #32]
    stp d14, d15, [sp, #48]
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
    ldp d8, d9, [sp]
    ldp d10, d11, [sp, #16]
    ldp d12, d13, [sp, #32]
    ldp d14, d15, [sp, #48]
    add sp, sp, #80
    ret

// What code run from an interrupt is entitled to do: overwrite every
// vector register except the low halves of v8-v15. Returns the FPCR it
// runs with.
    .globl nk_fp_clobber
nk_fp_clobber:
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
    // SAFETY: both blocks are live and of the size the probe reads and
    // writes; it preserves what the calling convention says it must.
    unsafe { nk_fp_trap_probe(&raw const load, &raw mut store) };
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

extern "C" fn trap_handler(frame: &mut Frame, vector: u64) {
    let brk = (vector & 3 == 0 && frame.esr >> 26 == EC_BRK).then_some(frame.esr & 0xFFFF);
    if brk == Some(BRK_BREAKPOINT) {
        // `brk` is a fault: step past the 4-byte instruction.
        BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
        frame.elr += 4;
        if FP_CLOBBER.load(Ordering::Relaxed) {
            // SAFETY: the routine only writes registers, as any function
            // may.
            HANDLER_FPCR.store(unsafe { nk_fp_clobber() }, Ordering::Relaxed);
        }
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
