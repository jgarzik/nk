//! Exceptions and interrupts: entry stubs, the IDT, and the handler.
//!
//! Every vector funnels into one handler with a full register frame. A
//! breakpoint is counted and resumed (the boot self-test uses it to prove
//! the path works). Anything else is a fatal bugcheck with a register dump:
//! there is no SEH yet, so no driver or kernel code can handle a fault.

use core::arch::global_asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicU32, Ordering};

/// Registers saved by the entry stub, lowest address first.
#[repr(C)]
pub struct Frame {
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
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    pub vector: u64,
    pub error: u64,
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const BREAKPOINT: u64 = 3;
const PAGE_FAULT: u64 = 14;
/// Vectors 32 and up share one stub, which reports this number.
const UNEXPECTED: u64 = 255;

static BREAKPOINTS: AtomicU32 = AtomicU32::new(0);

/// How many breakpoint exceptions have been taken and resumed.
pub fn breakpoints() -> u32 {
    BREAKPOINTS.load(Ordering::Relaxed)
}

// Vectors 0-31 each get a stub that pushes a zero error code where the CPU
// pushes none, then the vector number. The common path saves the
// general-purpose registers and calls the handler with the Windows x64
// convention: argument in rcx, 32 bytes of shadow space, 16-byte aligned.
global_asm!(
    r#"
    .text
nk_trap_0:
    push 0
    push 0
    jmp nk_trap_common
nk_trap_1:
    push 0
    push 1
    jmp nk_trap_common
nk_trap_2:
    push 0
    push 2
    jmp nk_trap_common
nk_trap_3:
    push 0
    push 3
    jmp nk_trap_common
nk_trap_4:
    push 0
    push 4
    jmp nk_trap_common
nk_trap_5:
    push 0
    push 5
    jmp nk_trap_common
nk_trap_6:
    push 0
    push 6
    jmp nk_trap_common
nk_trap_7:
    push 0
    push 7
    jmp nk_trap_common
nk_trap_8:
    push 8
    jmp nk_trap_common
nk_trap_9:
    push 0
    push 9
    jmp nk_trap_common
nk_trap_10:
    push 10
    jmp nk_trap_common
nk_trap_11:
    push 11
    jmp nk_trap_common
nk_trap_12:
    push 12
    jmp nk_trap_common
nk_trap_13:
    push 13
    jmp nk_trap_common
nk_trap_14:
    push 14
    jmp nk_trap_common
nk_trap_15:
    push 0
    push 15
    jmp nk_trap_common
nk_trap_16:
    push 0
    push 16
    jmp nk_trap_common
nk_trap_17:
    push 17
    jmp nk_trap_common
nk_trap_18:
    push 0
    push 18
    jmp nk_trap_common
nk_trap_19:
    push 0
    push 19
    jmp nk_trap_common
nk_trap_20:
    push 0
    push 20
    jmp nk_trap_common
nk_trap_21:
    push 21
    jmp nk_trap_common
nk_trap_22:
    push 0
    push 22
    jmp nk_trap_common
nk_trap_23:
    push 0
    push 23
    jmp nk_trap_common
nk_trap_24:
    push 0
    push 24
    jmp nk_trap_common
nk_trap_25:
    push 0
    push 25
    jmp nk_trap_common
nk_trap_26:
    push 0
    push 26
    jmp nk_trap_common
nk_trap_27:
    push 0
    push 27
    jmp nk_trap_common
nk_trap_28:
    push 0
    push 28
    jmp nk_trap_common
nk_trap_29:
    push 29
    jmp nk_trap_common
nk_trap_30:
    push 30
    jmp nk_trap_common
nk_trap_31:
    push 0
    push 31
    jmp nk_trap_common
nk_trap_other:
    push 0
    push 255
nk_trap_common:
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rcx, rsp
    mov rbp, rsp
    and rsp, -16
    sub rsp, 32
    cld
    call {handler}
    mov rsp, rbp
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
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    add rsp, 16
    iretq

    .section .rdata
    .balign 8
    .globl nk_trap_table
nk_trap_table:
    .quad nk_trap_0
    .quad nk_trap_1
    .quad nk_trap_2
    .quad nk_trap_3
    .quad nk_trap_4
    .quad nk_trap_5
    .quad nk_trap_6
    .quad nk_trap_7
    .quad nk_trap_8
    .quad nk_trap_9
    .quad nk_trap_10
    .quad nk_trap_11
    .quad nk_trap_12
    .quad nk_trap_13
    .quad nk_trap_14
    .quad nk_trap_15
    .quad nk_trap_16
    .quad nk_trap_17
    .quad nk_trap_18
    .quad nk_trap_19
    .quad nk_trap_20
    .quad nk_trap_21
    .quad nk_trap_22
    .quad nk_trap_23
    .quad nk_trap_24
    .quad nk_trap_25
    .quad nk_trap_26
    .quad nk_trap_27
    .quad nk_trap_28
    .quad nk_trap_29
    .quad nk_trap_30
    .quad nk_trap_31
    .quad nk_trap_other
"#,
    handler = sym trap_handler,
);

unsafe extern "C" {
    /// Addresses of the 32 exception stubs, then the shared one.
    static nk_trap_table: [u64; 33];
}

extern "C" fn trap_handler(frame: &mut Frame) {
    if frame.vector == BREAKPOINT {
        // `int3` is a trap: rip already points past it.
        BREAKPOINTS.fetch_add(1, Ordering::Relaxed);
        return;
    }
    let cr2: u64;
    // SAFETY: reading CR2 has no side effects.
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack)) };
    let what = match frame.vector {
        0 => "divide error",
        6 => "invalid opcode",
        8 => "double fault",
        13 => "general protection fault",
        PAGE_FAULT => "page fault",
        UNEXPECTED => "unexpected interrupt",
        _ => "exception",
    };
    crate::kd::bugcheck(format_args!(
        "{what} (vector {}, error {:#x}) at rip={:#018x}\n\
         cr2={cr2:#018x} rsp={:#018x} rflags={:#x} cs={:#x}\n\
         rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}\n\
         rsi={:#018x} rdi={:#018x} rbp={:#018x} r8 ={:#018x}\n\
         r9 ={:#018x} r10={:#018x} r11={:#018x} r12={:#018x}\n\
         r13={:#018x} r14={:#018x} r15={:#018x}",
        frame.vector,
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
    // SAFETY: the assembly above defines 33 addresses at this symbol.
    let stubs = unsafe { &nk_trap_table };
    // SAFETY: single-threaded early boot; nothing else references the IDT.
    let idt = unsafe { &mut *IDT.0.get() };
    for (vector, gate) in idt.iter_mut().enumerate() {
        let addr = stubs[vector.min(32)];
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

/// Execute a breakpoint instruction.
pub fn breakpoint() {
    // SAFETY: `int3` traps to the handler above, which resumes after it.
    unsafe { core::arch::asm!("int3", options(nomem, nostack)) };
}
