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
// rcx: body. rdx: its argument. r8: a seed. Every register a call
// preserves holds a value made from the seed while the body runs.
// Returns 0 if the body returned; if the `__except` block got control,
// the exception's code; either way `REGISTERS_LOST` instead if one of
// those registers did not come back with its value.
nk_seh_try:
    .seh_proc nk_seh_try
    .seh_handler {c_handler}, @unwind, @except
    push rbx
    .seh_pushreg rbx
    push rbp
    .seh_pushreg rbp
    push rsi
    .seh_pushreg rsi
    push rdi
    .seh_pushreg rdi
    push r12
    .seh_pushreg r12
    push r13
    .seh_pushreg r13
    push r14
    .seh_pushreg r14
    push r15
    .seh_pushreg r15
    sub rsp, 0x48
    .seh_stackalloc 0x48
    movaps [rsp + 0x20], xmm6
    .seh_savexmm xmm6, 0x20
    .seh_endprologue
    mov [rsp + 0x30], r8
    lea rbx, [r8 + 1]
    lea rbp, [r8 + 2]
    lea rsi, [r8 + 3]
    lea rdi, [r8 + 4]
    lea r12, [r8 + 5]
    lea r13, [r8 + 6]
    lea r14, [r8 + 7]
    lea r15, [r8 + 8]
    movq xmm6, rbx
    mov rax, rcx
    mov rcx, rdx
nk_seh_try_begin:
    call rax
    nop
nk_seh_try_end:
    xor eax, eax
// The `__except` block: rax is the exception's code. The body's return
// arrives here too, with zero for a code.
nk_seh_try_except:
    mov r8, [rsp + 0x30]
    lea r10, [r8 + 1]
    cmp rbx, r10
    jne 2f
    movq r11, xmm6
    cmp r11, r10
    jne 2f
    lea r10, [r8 + 2]
    cmp rbp, r10
    jne 2f
    lea r10, [r8 + 3]
    cmp rsi, r10
    jne 2f
    lea r10, [r8 + 4]
    cmp rdi, r10
    jne 2f
    lea r10, [r8 + 5]
    cmp r12, r10
    jne 2f
    lea r10, [r8 + 6]
    cmp r13, r10
    jne 2f
    lea r10, [r8 + 7]
    cmp r14, r10
    jne 2f
    lea r10, [r8 + 8]
    cmp r15, r10
    jne 2f
    mov eax, eax
    jmp 3f
2:  mov eax, {registers_lost}
3:  movaps xmm6, [rsp + 0x20]
    add rsp, 0x48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
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
// rcx: body. rdx: its argument.
nk_seh_finally:
    .seh_proc nk_seh_finally
    .seh_handler {c_handler}, @unwind, @except
    sub rsp, 0x28
    .seh_stackalloc 0x28
    .seh_endprologue
    mov rax, rcx
    mov rcx, rdx
nk_seh_finally_begin:
    call rax
    nop
nk_seh_finally_end:
    xor ecx, ecx
    mov rdx, rsp
    call {finally}
    add rsp, 0x28
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
// A `__try` whose guarded range ends with the call to the body: rcx,
// with argument rdx. The call's return address is the first address
// past the range, so by Windows' rule for x86-64 the call is outside
// it, and an exception the body raises is not this scope's.
nk_seh_edge:
    .seh_proc nk_seh_edge
    .seh_handler {c_handler}, @unwind, @except
    sub rsp, 0x28
    .seh_stackalloc 0x28
    .seh_endprologue
    mov rax, rcx
    mov rcx, rdx
nk_seh_edge_begin:
    nop
    call rax
nk_seh_edge_end:
    nop
nk_seh_edge_except:
    add rsp, 0x28
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
// rcx: body. rdx: its argument. Calls the body with every register a
// call preserves overwritten, as a function that uses them all may:
// whoever unwinds this frame must put the caller's values back.
nk_seh_clobber:
    .seh_proc nk_seh_clobber
    push rbx
    .seh_pushreg rbx
    push rbp
    .seh_pushreg rbp
    push rsi
    .seh_pushreg rsi
    push rdi
    .seh_pushreg rdi
    push r12
    .seh_pushreg r12
    push r13
    .seh_pushreg r13
    push r14
    .seh_pushreg r14
    push r15
    .seh_pushreg r15
    sub rsp, 0x38
    .seh_stackalloc 0x38
    movaps [rsp + 0x20], xmm6
    .seh_savexmm xmm6, 0x20
    .seh_endprologue
    mov rbx, -1
    mov rbp, rbx
    mov rsi, rbx
    mov rdi, rbx
    mov r12, rbx
    mov r13, rbx
    mov r14, rbx
    mov r15, rbx
    movq xmm6, rbx
    mov rax, rcx
    mov rcx, rdx
    call rax
    nop
    movaps xmm6, [rsp + 0x20]
    add rsp, 0x38
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    ret
    .seh_endproc

// Bodies that fault, each a function that uses no stack.

    .globl nk_seh_read
// rcx: an address. Read there.
nk_seh_read:
    .seh_proc nk_seh_read
    .seh_endprologue
    mov rax, [rcx]
    ret
    .seh_endproc

    .globl nk_seh_write
// rcx: an address. Write there.
nk_seh_write:
    .seh_proc nk_seh_write
    .seh_endprologue
    mov qword ptr [rcx], 0x4E4B
    ret
    .seh_endproc

    .globl nk_seh_call
// rcx: an address. Call it.
nk_seh_call:
    .seh_proc nk_seh_call
    sub rsp, 0x28
    .seh_stackalloc 0x28
    .seh_endprologue
    call rcx
    nop
    add rsp, 0x28
    ret
    .seh_endproc

    .globl nk_seh_divide
// rcx: a divisor. Divide by it.
nk_seh_divide:
    .seh_proc nk_seh_divide
    .seh_endprologue
    xor edx, edx
    mov eax, 1
    div ecx
    ret
    .seh_endproc

    .globl nk_seh_illegal
// An instruction the processor does not have.
nk_seh_illegal:
    .seh_proc nk_seh_illegal
    .seh_endprologue
    ud2
    ret
    .seh_endproc

    .globl nk_seh_break
// A breakpoint, as `DbgBreakPoint` is one.
nk_seh_break:
    .seh_proc nk_seh_break
    .seh_endprologue
    int3
    ret
    .seh_endproc

    .globl nk_seh_overflow
// The overflow trap.
nk_seh_overflow:
    .seh_proc nk_seh_overflow
    .seh_endprologue
    int 4
    ret
    .seh_endproc

    .globl nk_seh_noncanonical
// A read of an address the processor does not have: a general
// protection fault, with no address to report.
nk_seh_noncanonical:
    .seh_proc nk_seh_noncanonical
    .seh_endprologue
    movabs rax, 0x0000800000000000
    mov rax, [rax]
    ret
    .seh_endproc

    .globl nk_seh_resume
// rcx: an address. rdx: where to put what is read there. Reads, and
// returns how far below its place at entry the stack pointer is right
// after the read: zero, unless whoever handled a fault of the read and
// had it continue moved it.
nk_seh_resume:
    .seh_proc nk_seh_resume
    .seh_endprologue
    mov r9, rsp
    mov rax, [rcx]
    mov [rdx], rax
    mov rax, r9
    sub rax, rsp
    mov rsp, r9
    ret
    .seh_endproc

    .globl nk_seh_no_unwind
// rcx: body. rdx: its argument. A function that calls another and has
// no unwind entry: what a walk must refuse to pass.
nk_seh_no_unwind:
    sub rsp, 0x28
    mov rax, rcx
    mov rcx, rdx
    call rax
    add rsp, 0x28
    ret
"#,
    c_handler = sym crate::ke::seh::__C_specific_handler,
    filter = sym crate::selftest::except::filter,
    finally = sym crate::selftest::except::finally,
    registers_lost = const REGISTERS_LOST,
);

/// What `nk_seh_try` returns when its `__except` block was entered with
/// a call-preserved register changed.
pub const REGISTERS_LOST: u32 = 0xBAD0_BAD0;

/// Where `nk_seh_try` keeps its seed, from the frame its filter is
/// given: the stack pointer after the prologue.
pub const SEED_SLOT: u64 = 0x30;

/// The body the test routines call.
pub type Body = unsafe extern "C" fn(usize);

unsafe extern "C" {
    pub fn nk_seh_try(body: Body, argument: usize, seed: usize) -> u64;
    pub fn nk_seh_finally(body: Body, argument: usize);
    pub fn nk_seh_edge(body: Body, argument: usize);
    pub fn nk_seh_clobber(body: Body, argument: usize);
    pub fn nk_seh_no_unwind(body: Body, argument: usize);
    pub fn nk_seh_read(address: usize);
    pub fn nk_seh_write(address: usize);
    pub fn nk_seh_call(address: usize);
    pub fn nk_seh_resume(address: usize, value: *mut u64) -> u64;
    fn nk_seh_divide(divisor: usize);
    fn nk_seh_illegal(unused: usize);
    fn nk_seh_break(unused: usize);
    fn nk_seh_overflow(unused: usize);
    fn nk_seh_noncanonical(unused: usize);
}

/// A fault that is neither a read, a write nor a call: the body that
/// takes it, the body's argument, and the exception it must arrive as,
/// with its parameters.
pub struct Fault {
    pub what: &'static str,
    pub body: Body,
    pub argument: usize,
    pub code: u32,
    pub parameters: &'static [u64],
}

/// The faults of that kind this architecture has.
pub const FAULTS: &[Fault] = &[
    Fault {
        what: "a division by zero",
        body: nk_seh_divide,
        argument: 0,
        code: 0xC000_0094,
        parameters: &[],
    },
    Fault {
        what: "an illegal instruction",
        body: nk_seh_illegal,
        argument: 0,
        code: 0xC000_001D,
        parameters: &[],
    },
    Fault {
        what: "a breakpoint",
        body: nk_seh_break,
        argument: 0,
        code: 0x8000_0003,
        parameters: &[0],
    },
    Fault {
        what: "the overflow trap",
        body: nk_seh_overflow,
        argument: 0,
        code: 0xC000_0095,
        parameters: &[],
    },
    Fault {
        what: "a general protection fault",
        body: nk_seh_noncanonical,
        argument: 0,
        code: 0xC000_0005,
        parameters: &[0, u64::MAX],
    },
];
