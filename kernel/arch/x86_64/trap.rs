//! Exceptions and interrupts: entry stubs, the IDT, and the handler.
//!
//! Every vector funnels into one handler with a full register frame. A
//! breakpoint is counted and resumed (the boot self-test uses it to prove
//! the path works). Anything else is a fatal bugcheck with a register dump:
//! there is no SEH yet, so no driver or kernel code can handle a fault.

use core::arch::global_asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// Registers saved by the entry stub, lowest address first.
///
/// The floating-point part is what Windows saves in a trap frame: the
/// volatile registers XMM0-XMM5 and MXCSR. Kernel code that an interrupt
/// goes on to run (a driver's DPC, say) may use those freely, so the
/// interrupted code would otherwise find them changed. XMM6-XMM15 are
/// preserved by every function that uses them, under the calling
/// convention, and are not saved here.
#[repr(C)]
pub struct Frame {
    pub xmm: [[u64; 2]; 6],
    /// MXCSR of the interrupted code, in the low 32 bits.
    pub mxcsr: u64,
    /// Scratch: the stub loads the kernel's MXCSR from here.
    scratch: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub rbp: u64,
    /// The return address into the vector's entry stub: where a stack
    /// walk goes on from, and what names the vector.
    stub: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const BREAKPOINT: u64 = 3;
const NMI: u64 = 2;
const DOUBLE_FAULT: u64 = 8;
const PAGE_FAULT: u64 = 14;
/// `int 0x29`: `__fastfail`, how MSVC-built code reports fatal corruption
/// (a failed stack-cookie check, for one). The reason code is in rcx.
const FAST_FAIL: u64 = 0x29;

static BREAKPOINTS: AtomicU32 = AtomicU32::new(0);

/// How many breakpoint exceptions have been taken and resumed.
pub fn breakpoints() -> u32 {
    BREAKPOINTS.load(Ordering::Relaxed)
}

// Every vector has an eight-byte stub that pushes a zero error code where
// the CPU pushes none and calls the common path; the return address the
// call leaves says which stub, so which vector. The common path saves the
// general-purpose registers, then XMM0-XMM5 and MXCSR, gives the handler
// the kernel's own MXCSR (all exceptions masked, round to nearest), and
// calls it with the Windows x64 convention: argument in rcx, 32 bytes of
// shadow space, 16-byte aligned.
//
// Unwind information (`.seh_*`) describes the stack at every instruction:
// a stub's is the CPU's frame and the error code; the common path's is
// its own pushes below an ordinary return address, with rbp as the frame
// register because the stack pointer is re-aligned for the handler. rbp
// is restored last; the two instructions after it each get an entry of
// their own, since x64 unwind codes describe a function's prologue and
// nothing that ends in `iretq` counts as its mirror image.
global_asm!(
    r#"
    .text
    .altmacro
    .macro nk_trap_stub vector
    .balign 8, 0xCC
nk_trap_\vector:
    .seh_proc nk_trap_\vector
    .if (\vector == 8) || ((\vector >= 10) && (\vector <= 14)) || (\vector == 17) || (\vector == 21) || (\vector == 29) || (\vector == 30)
    .seh_pushframe @code
    .else
    .seh_pushframe
    push 0
    .seh_stackalloc 8
    .endif
    .seh_endprologue
    call nk_trap_common
    int3
    .seh_endproc
    .endm

    .balign 8, 0xCC
    .globl nk_trap_stubs
nk_trap_stubs:
    .set nk_trap_vector, 0
    .rept 256
    nk_trap_stub %nk_trap_vector
    .set nk_trap_vector, nk_trap_vector + 1
    .endr
    .balign 8, 0xCC
    .noaltmacro

nk_trap_common:
    .seh_proc nk_trap_common
    push rbp
    .seh_pushreg rbp
    push rax
    .seh_pushreg rax
    push rcx
    .seh_pushreg rcx
    push rdx
    .seh_pushreg rdx
    push rbx
    .seh_pushreg rbx
    push rsi
    .seh_pushreg rsi
    push rdi
    .seh_pushreg rdi
    push r8
    .seh_pushreg r8
    push r9
    .seh_pushreg r9
    push r10
    .seh_pushreg r10
    push r11
    .seh_pushreg r11
    push r12
    .seh_pushreg r12
    push r13
    .seh_pushreg r13
    push r14
    .seh_pushreg r14
    push r15
    .seh_pushreg r15
    sub rsp, 112
    .seh_stackalloc 112
    mov rbp, rsp
    .seh_setframe rbp, 0
    movups xmmword ptr [rsp], xmm0
    .seh_savexmm xmm0, 0
    movups xmmword ptr [rsp + 16], xmm1
    .seh_savexmm xmm1, 16
    movups xmmword ptr [rsp + 32], xmm2
    .seh_savexmm xmm2, 32
    movups xmmword ptr [rsp + 48], xmm3
    .seh_savexmm xmm3, 48
    movups xmmword ptr [rsp + 64], xmm4
    .seh_savexmm xmm4, 64
    movups xmmword ptr [rsp + 80], xmm5
    .seh_savexmm xmm5, 80
    stmxcsr dword ptr [rsp + 96]
    mov dword ptr [rsp + 104], 0x1F80
    ldmxcsr dword ptr [rsp + 104]
    .seh_endprologue
    mov rcx, rsp
    and rsp, -16
    sub rsp, 32
    cld
    call {handler}
    mov rsp, rbp
    ldmxcsr dword ptr [rsp + 96]
    movups xmm0, xmmword ptr [rsp]
    movups xmm1, xmmword ptr [rsp + 16]
    movups xmm2, xmmword ptr [rsp + 32]
    movups xmm3, xmmword ptr [rsp + 48]
    movups xmm4, xmmword ptr [rsp + 64]
    movups xmm5, xmmword ptr [rsp + 80]
    add rsp, 112
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbx
    pop rdx
    pop rcx
    pop rax
    pop rbp
    .seh_endproc
// The stub's return address and the error code are still on the stack.
nk_trap_leave:
    .seh_proc nk_trap_leave
    .seh_pushframe @code
    .seh_stackalloc 8
    .seh_endprologue
    add rsp, 16
    .seh_endproc
// Only the CPU's frame is.
nk_trap_return:
    .seh_proc nk_trap_return
    .seh_pushframe
    .seh_endprologue
    iretq
    .seh_endproc

// For `fp_trap_test`. Load XMM0-XMM5 and MXCSR from the block at rcx, take
// a breakpoint, store what they hold afterwards in the block at rdx.
// A block is six 16-byte registers, then MXCSR.
    .globl nk_fp_trap_probe
nk_fp_trap_probe:
    .seh_proc nk_fp_trap_probe
    sub rsp, 8
    .seh_stackalloc 8
    .seh_endprologue
    stmxcsr dword ptr [rsp]
    movups xmm0, xmmword ptr [rcx]
    movups xmm1, xmmword ptr [rcx + 16]
    movups xmm2, xmmword ptr [rcx + 32]
    movups xmm3, xmmword ptr [rcx + 48]
    movups xmm4, xmmword ptr [rcx + 64]
    movups xmm5, xmmword ptr [rcx + 80]
    ldmxcsr dword ptr [rcx + 96]
    int3
    movups xmmword ptr [rdx], xmm0
    movups xmmword ptr [rdx + 16], xmm1
    movups xmmword ptr [rdx + 32], xmm2
    movups xmmword ptr [rdx + 48], xmm3
    movups xmmword ptr [rdx + 64], xmm4
    movups xmmword ptr [rdx + 80], xmm5
    stmxcsr dword ptr [rdx + 96]
    ldmxcsr dword ptr [rsp]
    add rsp, 8
    ret
    .seh_endproc

// What code run from an interrupt is entitled to do: overwrite every
// volatile vector register. Stores the MXCSR it runs with at rcx.
    .globl nk_fp_clobber
nk_fp_clobber:
    .seh_proc nk_fp_clobber
    .seh_endprologue
    stmxcsr dword ptr [rcx]
    pcmpeqd xmm0, xmm0
    movdqa xmm1, xmm0
    movdqa xmm2, xmm0
    movdqa xmm3, xmm0
    movdqa xmm4, xmm0
    movdqa xmm5, xmm0
    ret
    .seh_endproc
"#,
    handler = sym trap_handler,
);

/// Bytes from one vector's entry stub to the next.
const STUB_SIZE: u64 = 8;

unsafe extern "C" {
    /// The 256 entry stubs, by vector, `STUB_SIZE` bytes each.
    static nk_trap_stubs: u8;
    fn nk_fp_trap_probe(load: *const FpBlock, store: *mut FpBlock);
    fn nk_fp_clobber(mxcsr: *mut u32);
}

/// Address of the first vector's entry stub.
fn stubs() -> u64 {
    &raw const nk_trap_stubs as u64
}

/// XMM0-XMM5 and MXCSR, as `nk_fp_trap_probe` loads and stores them.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct FpBlock {
    xmm: [[u64; 2]; 6],
    mxcsr: u32,
}

/// MXCSR as the kernel runs: every exception masked, round to nearest.
const KERNEL_MXCSR: u32 = 0x1F80;
/// Set while `fp_trap_test` wants the breakpoint handler to overwrite the
/// volatile vector registers.
static FP_CLOBBER: AtomicBool = AtomicBool::new(false);
/// The MXCSR the handler ran with during that breakpoint.
static HANDLER_MXCSR: AtomicU32 = AtomicU32::new(0);

/// An exception must not disturb the vector registers or MXCSR of the
/// code it interrupts, even when the handler (as a driver's code may)
/// uses every volatile one; and the handler must run with the kernel's
/// own MXCSR, not the interrupted code's.
pub fn fp_trap_test() -> Result<(), &'static str> {
    let mut load = FpBlock {
        xmm: [[0; 2]; 6],
        // Round toward zero: a value no kernel code sets, so finding it
        // again afterwards means it was restored, not merely left alone.
        mxcsr: KERNEL_MXCSR | 0x6000,
    };
    for (i, reg) in load.xmm.iter_mut().enumerate() {
        *reg = [0x1111_1111_1111_1111 * (i as u64 + 1), !(i as u64)];
    }
    let mut store = FpBlock {
        xmm: [[0; 2]; 6],
        mxcsr: 0,
    };
    FP_CLOBBER.store(true, Ordering::Relaxed);
    crate::kd::expect_breakpoint(true);
    // SAFETY: both blocks are live and of the size the probe reads and
    // writes; it restores the caller's MXCSR, and XMM0-XMM5 are volatile.
    unsafe { nk_fp_trap_probe(&raw const load, &raw mut store) };
    crate::kd::expect_breakpoint(false);
    FP_CLOBBER.store(false, Ordering::Relaxed);
    if HANDLER_MXCSR.load(Ordering::Relaxed) != KERNEL_MXCSR {
        return Err("the handler ran with the interrupted code's MXCSR");
    }
    if store.mxcsr != load.mxcsr {
        return Err("MXCSR was not restored after the exception");
    }
    if store.xmm != load.xmm {
        return Err("a volatile vector register was not restored after the exception");
    }
    Ok(())
}

extern "C" fn trap_handler(frame: &mut Frame) {
    let vector = (frame.stub - stubs()) / STUB_SIZE;
    if vector == BREAKPOINT {
        // `int3` is a trap: rip already points past it. Whether to go
        // on is not this layer's to say.
        crate::kd::breakpoint(frame.rip - 1);
        BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
        if FP_CLOBBER.load(Ordering::Relaxed) {
            let mut mxcsr = 0;
            // SAFETY: the routine writes one `u32` and volatile registers.
            unsafe { nk_fp_clobber(&raw mut mxcsr) };
            HANDLER_MXCSR.store(mxcsr, Ordering::Relaxed);
        }
        return;
    }
    if vector == NMI && crate::kd::stopping() {
        // Another processor is stopping the system and said so.
        super::halt();
    }
    if vector >= 32 && vector != FAST_FAIL {
        return super::apic::interrupt(vector as u32);
    }
    let cr2: u64;
    // SAFETY: reading CR2 has no side effects.
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack)) };
    // A stack that overflows faults on the unmapped memory below it. The
    // page fault cannot push its own frame there, so it arrives as a
    // double fault, on the stack kept for that.
    let overflow = matches!(vector, DOUBLE_FAULT | PAGE_FAULT)
        && crate::mm::stack::is_overflow(super::cpu::kernel_stack(), cr2);
    let what = match vector {
        _ if overflow => "kernel stack overflow",
        0 => "divide error",
        6 => "invalid opcode",
        DOUBLE_FAULT => "double fault",
        13 => "general protection fault",
        PAGE_FAULT => "page fault",
        FAST_FAIL => "driver fast-fail (reason code in rcx)",
        _ => "exception",
    };
    let image = crate::ldr::locate_fatal(frame.rip);
    crate::kd::bugcheck(format_args!(
        "{what} (vector {}, error {:#x}) at rip={:#018x} in {image}\n\
         cr2={cr2:#018x} rsp={:#018x} rflags={:#x} cs={:#x}\n\
         rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}\n\
         rsi={:#018x} rdi={:#018x} rbp={:#018x} r8 ={:#018x}\n\
         r9 ={:#018x} r10={:#018x} r11={:#018x} r12={:#018x}\n\
         r13={:#018x} r14={:#018x} r15={:#018x}",
        vector,
        frame.error,
        frame.rip,
        frame.rsp,
        frame.rflags,
        frame.cs,
        frame.rax,
        frame.rbx,
        frame.rcx,
        frame.rdx,
        frame.rsi,
        frame.rdi,
        frame.rbp,
        frame.r8,
        frame.r9,
        frame.r10,
        frame.r11,
        frame.r12,
        frame.r13,
        frame.r14,
        frame.r15,
    ))
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Gate {
    offset_low: u16,
    selector: u16,
    ist: u8,
    kind: u8,
    offset_mid: u16,
    offset_high: u32,
    reserved: u32,
}

/// Present, ring 0, 64-bit interrupt gate.
const INTERRUPT_GATE: u8 = 0x8E;

struct Idt(UnsafeCell<[Gate; 256]>);

// SAFETY: written once by `init` on the boot CPU before interrupts or
// other CPUs exist, read-only afterwards.
unsafe impl Sync for Idt {}

static IDT: Idt = Idt(UnsafeCell::new(
    [Gate {
        offset_low: 0,
        selector: 0,
        ist: 0,
        kind: 0,
        offset_mid: 0,
        offset_high: 0,
        reserved: 0,
    }; 256],
));

/// Build and load the IDT. `code_selector` is the kernel code segment;
/// `fault_ist` is the interrupt-stack index for faults that must not trust
/// the current stack (double fault, NMI).
pub fn init(code_selector: u16, fault_ist: u8) {
    // SAFETY: single-threaded early boot; nothing else references the IDT.
    let idt = unsafe { &mut *IDT.0.get() };
    for (vector, gate) in idt.iter_mut().enumerate() {
        let addr = stubs() + vector as u64 * STUB_SIZE;
        *gate = Gate {
            offset_low: addr as u16,
            selector: code_selector,
            ist: if vector == 2 || vector == 8 {
                fault_ist
            } else {
                0
            },
            kind: INTERRUPT_GATE,
            offset_mid: (addr >> 16) as u16,
            offset_high: (addr >> 32) as u32,
            reserved: 0,
        };
    }
    let pointer = super::cpu::TablePointer {
        limit: (size_of::<[Gate; 256]>() - 1) as u16,
        base: IDT.0.get() as u64,
    };
    // SAFETY: the IDT is static and fully initialised; every gate targets a
    // stub that saves state and reaches `trap_handler`.
    unsafe {
        core::arch::asm!("lidt [{}]", in(reg) &raw const pointer, options(readonly, nostack))
    };
}

/// Load the IDT `init` built on a processor that is starting up. Every
/// processor shares the one table.
pub fn load() {
    let pointer = super::cpu::TablePointer {
        limit: (size_of::<[Gate; 256]>() - 1) as u16,
        base: IDT.0.get() as u64,
    };
    // SAFETY: as at the end of `init`.
    unsafe {
        core::arch::asm!("lidt [{}]", in(reg) &raw const pointer, options(readonly, nostack))
    };
}

/// Execute a breakpoint instruction: the kernel's own, for its tests.
pub fn breakpoint() {
    crate::kd::expect_breakpoint(true);
    // SAFETY: `int3` traps to the handler above, which resumes after it.
    unsafe { core::arch::asm!("int3", options(nomem, nostack)) };
    crate::kd::expect_breakpoint(false);
}

/// Execute a breakpoint instruction the way a driver's `DbgBreakPoint`
/// does: unannounced.
pub fn driver_breakpoint() {
    // SAFETY: `int3` traps to the handler above.
    unsafe { core::arch::asm!("int3", options(nomem, nostack)) };
}
