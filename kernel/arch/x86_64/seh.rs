//! Structured exception handling on x86-64: the assembly the dispatcher
//! (`ke::seh`) stands on, and the conversions between Windows' `CONTEXT`
//! and the register set `nk_unwind` works on.
//!
//! Four routines, each with unwind information and, where the dispatcher
//! must recognise the frame, a language handler of NK's own:
//!
//! - `nk_with_caller_context`: an exported routine that may raise is
//!   entered through it, and is handed a `CONTEXT` describing its caller
//!   as it will be once the call has returned;
//! - `nk_guarded_call`: how NK calls a driver's routine. Its frame holds
//!   the caller's guard record, which its handler acts on;
//! - `nk_call_handler_search`, `nk_call_handler_unwind`: how the
//!   dispatcher calls a language handler. The frame holds the
//!   dispatcher context in use, so that an exception raised inside the
//!   handler finds the dispatch it interrupted;
//! - `nk_restore_context`: resume at the end of an unwind.
//!
//! And `nk_fault_copy`, the one place NK touches memory that may not be
//! there (a requestor's buffer): a fault inside it is not an exception
//! but an error it returns, because the trap handler knows the
//! instruction ([`fixup`]) and resumes the routine at its way out.

use core::arch::global_asm;
use core::ffi::c_void;
use nk_ntabi::seh::x64::{CONTEXT, CONTEXT_FULL, CONTEXT_SEGMENTS, DISPATCHER_CONTEXT};
use nk_ntabi::seh::{EXCEPTION_RECORD, M128A};
use nk_unwind::x64::Regs;

pub type Context = CONTEXT;
pub type DispatcherContext = DISPATCHER_CONTEXT;
/// What a dispatcher context points to besides the context record:
/// nothing on x86-64.
pub struct Nonvolatile;

/// A language handler.
pub type Handler =
    unsafe extern "C" fn(*mut EXCEPTION_RECORD, u64, *mut Context, *mut DispatcherContext) -> u32;

/// Bytes from a frame's base (`rsp` after the prologue) to the slot
/// where `nk_guarded_call` keeps its guard and the handler-call routines
/// their dispatcher context: above the callee's home space.
const FRAME_SLOT: u64 = 0x20;

global_asm!(
    r#"
    .text
    .globl nk_with_caller_context
// rax: a function `extern "C" fn(a0, a1, a2, *mut CONTEXT)`. rcx, rdx,
// r8: its first three arguments, the caller's own. Calls it with a
// CONTEXT of the caller as it will be when this call has returned: the
// stack pointer above the return address, `rip` the return address,
// every other register as it is now. r10 and r11, which a call may
// destroy, are recorded as zero.
nk_with_caller_context:
    .seh_proc nk_with_caller_context
    pushfq
    .seh_stackalloc 8
    sub rsp, 0x4F0
    .seh_stackalloc 0x4F0
    .seh_endprologue
    lea r10, [rsp + 0x20]
    xor r11d, r11d
2:  mov qword ptr [r10 + r11], 0
    add r11, 8
    cmp r11, 0x4D0
    jb 2b
    mov dword ptr [r10 + 0x30], {flags}
    stmxcsr dword ptr [r10 + 0x34]
    mov word ptr [r10 + 0x38], cs
    mov word ptr [r10 + 0x3A], ds
    mov word ptr [r10 + 0x3C], es
    mov word ptr [r10 + 0x3E], fs
    mov word ptr [r10 + 0x40], gs
    mov word ptr [r10 + 0x42], ss
    mov r11, [rsp + 0x4F0]
    mov [r10 + 0x44], r11d
    mov [r10 + 0x78], rax
    mov [r10 + 0x80], rcx
    mov [r10 + 0x88], rdx
    mov [r10 + 0x90], rbx
    lea r11, [rsp + 0x500]
    mov [r10 + 0x98], r11
    mov [r10 + 0xA0], rbp
    mov [r10 + 0xA8], rsi
    mov [r10 + 0xB0], rdi
    mov [r10 + 0xB8], r8
    mov [r10 + 0xC0], r9
    mov [r10 + 0xD8], r12
    mov [r10 + 0xE0], r13
    mov [r10 + 0xE8], r14
    mov [r10 + 0xF0], r15
    mov r11, [rsp + 0x4F8]
    mov [r10 + 0xF8], r11
    stmxcsr dword ptr [r10 + 0x118]
    movups xmmword ptr [r10 + 0x1A0], xmm0
    movups xmmword ptr [r10 + 0x1B0], xmm1
    movups xmmword ptr [r10 + 0x1C0], xmm2
    movups xmmword ptr [r10 + 0x1D0], xmm3
    movups xmmword ptr [r10 + 0x1E0], xmm4
    movups xmmword ptr [r10 + 0x1F0], xmm5
    movups xmmword ptr [r10 + 0x200], xmm6
    movups xmmword ptr [r10 + 0x210], xmm7
    movups xmmword ptr [r10 + 0x220], xmm8
    movups xmmword ptr [r10 + 0x230], xmm9
    movups xmmword ptr [r10 + 0x240], xmm10
    movups xmmword ptr [r10 + 0x250], xmm11
    movups xmmword ptr [r10 + 0x260], xmm12
    movups xmmword ptr [r10 + 0x270], xmm13
    movups xmmword ptr [r10 + 0x280], xmm14
    movups xmmword ptr [r10 + 0x290], xmm15
    mov r9, r10
    call rax
    nop
    add rsp, 0x4F8
    ret
    .seh_endproc

// An exported routine entered with its caller's context: no frame of
// its own, so the caller of the common path is the driver.
    .macro nk_caller_context entry, target
    .globl \entry
\entry:
    .seh_proc \entry
    .seh_endprologue
    lea rax, [rip + \target]
    jmp nk_with_caller_context
    .seh_endproc
    .endm

    nk_caller_context nk_entry_ExRaiseStatus, nk_raise_status
    nk_caller_context nk_entry_ExRaiseAccessViolation, nk_raise_access_violation
    nk_caller_context nk_entry_ExRaiseDatatypeMisalignment, nk_raise_datatype_misalignment

    .globl nk_guarded_call
// rcx: a routine. rdx, r8, r9 and the fifth argument: its arguments.
// The sixth argument: the caller's guard record, kept in the frame for
// this routine's handler. The `nop` keeps the return address in the
// body: an unwinder takes one that is followed by `add rsp; ret` to be
// in the epilogue, where no handler is called.
nk_guarded_call:
    .seh_proc nk_guarded_call
    .seh_handler {guard_handler}, @unwind, @except
    sub rsp, 0x38
    .seh_stackalloc 0x38
    .seh_endprologue
    mov rax, [rsp + 0x68]
    mov [rsp + 0x20], rax
    mov rax, rcx
    mov rcx, rdx
    mov rdx, r8
    mov r8, r9
    mov r9, [rsp + 0x60]
    call rax
    nop
    add rsp, 0x38
    ret
    .seh_endproc

// rcx: the exception record. rdx: the frame. r8: the context record.
// r9: the dispatcher context, kept in the frame for this routine's
// handler. The fifth argument: the language handler to call with the
// first four.
    .macro nk_call_handler name, handler
    .globl \name
\name:
    .seh_proc \name
    .seh_handler \handler, @unwind, @except
    sub rsp, 0x38
    .seh_stackalloc 0x38
    .seh_endprologue
    mov [rsp + 0x20], r9
    mov rax, [rsp + 0x60]
    call rax
    nop
    add rsp, 0x38
    ret
    .seh_endproc
    .endm

    nk_call_handler nk_call_handler_search, {nested_handler}
    nk_call_handler nk_call_handler_unwind, {collided_handler}

    .globl nk_fault_copy
    .globl nk_fault_copy_access
    .globl nk_fault_copy_access_end
    .globl nk_fault_copy_fixup
// rcx: destination. rdx: source. r8: bytes. r9: two words for a fault's
// address and kind. Copies, and returns 0; or, if a byte of either
// range cannot be read or written, fills in the two words and returns 1.
// The trap handler resumes a fault in the one instruction that touches
// the ranges at `nk_fault_copy_fixup`, with the address in rax and the
// kind in rdx.
nk_fault_copy:
    .seh_proc nk_fault_copy
    push rsi
    .seh_pushreg rsi
    push rdi
    .seh_pushreg rdi
    .seh_endprologue
    mov rdi, rcx
    mov rsi, rdx
    mov rcx, r8
nk_fault_copy_access:
    rep movsb
nk_fault_copy_access_end:
    xor eax, eax
2:  pop rdi
    pop rsi
    ret
nk_fault_copy_fixup:
    mov [r9], rax
    mov [r9 + 8], rdx
    mov eax, 1
    jmp 2b
    .seh_endproc

    .globl nk_load_xmm6_to_15
// rcx: ten 16-byte values. Loads them into xmm6-xmm15: the registers a
// trap frame does not hold, for a context a handler changed.
nk_load_xmm6_to_15:
    .seh_proc nk_load_xmm6_to_15
    .seh_endprologue
    movups xmm6, xmmword ptr [rcx + 0x00]
    movups xmm7, xmmword ptr [rcx + 0x10]
    movups xmm8, xmmword ptr [rcx + 0x20]
    movups xmm9, xmmword ptr [rcx + 0x30]
    movups xmm10, xmmword ptr [rcx + 0x40]
    movups xmm11, xmmword ptr [rcx + 0x50]
    movups xmm12, xmmword ptr [rcx + 0x60]
    movups xmm13, xmmword ptr [rcx + 0x70]
    movups xmm14, xmmword ptr [rcx + 0x80]
    movups xmm15, xmmword ptr [rcx + 0x90]
    ret
    .seh_endproc

    .globl nk_restore_context
// rcx: a CONTEXT. Continue at its `rip` with its stack pointer, the
// registers a call preserves and `rax`. The stack pointer is loaded
// last and in one instruction: until then this runs on the old stack,
// where the context lies, and an interrupt may arrive at any point.
nk_restore_context:
    .seh_proc nk_restore_context
    .seh_endprologue
    movups xmm6, xmmword ptr [rcx + 0x200]
    movups xmm7, xmmword ptr [rcx + 0x210]
    movups xmm8, xmmword ptr [rcx + 0x220]
    movups xmm9, xmmword ptr [rcx + 0x230]
    movups xmm10, xmmword ptr [rcx + 0x240]
    movups xmm11, xmmword ptr [rcx + 0x250]
    movups xmm12, xmmword ptr [rcx + 0x260]
    movups xmm13, xmmword ptr [rcx + 0x270]
    movups xmm14, xmmword ptr [rcx + 0x280]
    movups xmm15, xmmword ptr [rcx + 0x290]
    mov rbx, [rcx + 0x90]
    mov rbp, [rcx + 0xA0]
    mov rsi, [rcx + 0xA8]
    mov rdi, [rcx + 0xB0]
    mov r12, [rcx + 0xD8]
    mov r13, [rcx + 0xE0]
    mov r14, [rcx + 0xE8]
    mov r15, [rcx + 0xF0]
    mov rax, [rcx + 0x78]
    mov rdx, [rcx + 0xF8]
    mov rsp, [rcx + 0x98]
    jmp rdx
    .seh_endproc
"#,
    flags = const CONTEXT_FULL | CONTEXT_SEGMENTS,
    guard_handler = sym crate::ke::seh::guard_handler,
    nested_handler = sym crate::ke::seh::nested_handler,
    collided_handler = sym crate::ke::seh::collided_handler,
);

unsafe extern "C" {
    fn nk_guarded_call(
        routine: usize,
        a0: usize,
        a1: usize,
        a2: usize,
        a3: usize,
        guard: *const c_void,
    ) -> usize;
    fn nk_call_handler_search(
        record: *mut EXCEPTION_RECORD,
        frame: u64,
        context: *mut Context,
        dispatcher: *mut DispatcherContext,
        handler: Handler,
    ) -> u32;
    fn nk_call_handler_unwind(
        record: *mut EXCEPTION_RECORD,
        frame: u64,
        context: *mut Context,
        dispatcher: *mut DispatcherContext,
        handler: Handler,
    ) -> u32;
    fn nk_restore_context(context: *const Context) -> !;
    fn nk_fault_copy(to: *mut u8, from: *const u8, len: usize, fault: *mut [u64; 2]) -> u64;
    fn nk_load_xmm6_to_15(values: *const M128A);
    static nk_fault_copy_access: u8;
    static nk_fault_copy_access_end: u8;
    static nk_fault_copy_fixup: u8;
    pub fn nk_entry_ExRaiseStatus(status: i32);
    pub fn nk_entry_ExRaiseAccessViolation();
    pub fn nk_entry_ExRaiseDatatypeMisalignment();
}

/// Call `routine` with `args` through the guarded frame.
///
/// # Safety
/// `routine` is the address of an `extern "C"` function that may be
/// called with these arguments; `guard` is null or stays valid until
/// the call returns or is unwound.
pub unsafe fn guarded_call(routine: usize, args: [usize; 4], guard: *const c_void) -> usize {
    // SAFETY: per the contract.
    unsafe { nk_guarded_call(routine, args[0], args[1], args[2], args[3], guard) }
}

/// The guard of the `nk_guarded_call` frame at `frame`.
///
/// # Safety
/// `frame` is the establisher frame a walk gave for `nk_guarded_call`.
pub unsafe fn guard_of(frame: u64) -> *const c_void {
    // SAFETY: per the contract, the slot the routine stored it in.
    unsafe { ((frame + FRAME_SLOT) as *const *const c_void).read() }
}

/// The dispatcher context of the handler-call frame at `frame`.
///
/// # Safety
/// `frame` is the establisher frame a walk gave for one of the
/// handler-call routines.
pub unsafe fn dispatcher_of(frame: u64) -> *mut DispatcherContext {
    // SAFETY: per the contract, the slot the routine stored it in.
    unsafe { ((frame + FRAME_SLOT) as *const *mut DispatcherContext).read() }
}

/// Call a language handler while searching for one that takes the
/// exception.
///
/// # Safety
/// `handler` is a language handler and the pointers are what it is
/// entitled to: a record, a context and a dispatcher context that stay
/// valid for the call.
pub unsafe fn call_handler_search(
    record: *mut EXCEPTION_RECORD,
    frame: u64,
    context: *mut Context,
    dispatcher: *mut DispatcherContext,
    handler: Handler,
) -> u32 {
    // SAFETY: per the contract.
    unsafe { nk_call_handler_search(record, frame, context, dispatcher, handler) }
}

/// Call a language handler while unwinding.
///
/// # Safety
/// As [`call_handler_search`].
pub unsafe fn call_handler_unwind(
    record: *mut EXCEPTION_RECORD,
    frame: u64,
    context: *mut Context,
    dispatcher: *mut DispatcherContext,
    handler: Handler,
) -> u32 {
    // SAFETY: per the contract.
    unsafe { nk_call_handler_unwind(record, frame, context, dispatcher, handler) }
}

/// Continue at `context`: its program counter and stack pointer, the
/// registers a call preserves, and the return-value register.
///
/// # Safety
/// `context` describes a live frame of this stack, at a place its code
/// can be resumed; everything above that frame is abandoned.
pub unsafe fn restore_context(context: &Context) -> ! {
    // SAFETY: per the contract.
    unsafe { nk_restore_context(context) }
}

/// Copy `len` bytes from `from` to `to`, either of which may be memory
/// that is not mapped or not writable. `Err` is the address that
/// faulted and the kind of access (`ke::seh::ACCESS_*`); some bytes may
/// have been copied by then.
///
/// # Safety
/// Whatever of the two ranges is mapped may be read and written by the
/// caller.
pub unsafe fn fault_copy(to: *mut u8, from: *const u8, len: usize) -> Result<(), (u64, u64)> {
    let mut fault = [0; 2];
    // SAFETY: per the contract; a fault is turned into the result.
    match unsafe { nk_fault_copy(to, from, len, &raw mut fault) } {
        0 => Ok(()),
        _ => Err((fault[0], fault[1])),
    }
}

/// Where the code at `pc` is to resume after a memory fault, if it is
/// the access of [`fault_copy`].
pub fn fixup(pc: u64) -> Option<u64> {
    let (start, end) = (
        &raw const nk_fault_copy_access as u64,
        &raw const nk_fault_copy_access_end as u64,
    );
    (start..end)
        .contains(&pc)
        .then_some(&raw const nk_fault_copy_fixup as u64)
}

/// Load xmm6-xmm15 from `context`.
pub fn load_nonvolatile_vectors(context: &Context) {
    // SAFETY: ten registers' worth of the context's sixteen, which a
    // called function is expected to leave as it found them: the caller
    // is the trap handler, restoring the interrupted code's.
    unsafe { nk_load_xmm6_to_15(context.FltSave.XmmRegisters[6..].as_ptr()) };
}

/// Make `context`'s first argument register hold `value`, and move its
/// stack pointer down by `drop` bytes.
pub fn repair(c: &mut Context, value: u64, drop: u64) {
    c.Rcx = value;
    c.Rsp -= drop;
}

/// A context with every field zero.
pub fn empty_context() -> Context {
    // SAFETY: the structure is integers throughout.
    unsafe { core::mem::zeroed() }
}

/// The context of the frame `regs` describes: its registers, and the
/// rest zero.
pub fn context_of(regs: &Regs) -> Context {
    let mut context = empty_context();
    context.ContextFlags = CONTEXT_FULL;
    set_regs(&mut context, regs, false);
    context
}

/// The registers of `context` an unwind works on.
pub fn regs(c: &Context) -> Regs {
    let mut xmm = [0u128; 10];
    for (out, x) in xmm.iter_mut().zip(&c.FltSave.XmmRegisters[6..]) {
        *out = u128::from(x.High as u64) << 64 | u128::from(x.Low);
    }
    Regs {
        gpr: [
            c.Rax, c.Rcx, c.Rdx, c.Rbx, c.Rsp, c.Rbp, c.Rsi, c.Rdi, c.R8, c.R9, c.R10, c.R11,
            c.R12, c.R13, c.R14, c.R15,
        ],
        rip: c.Rip,
        xmm,
    }
}

/// Put the registers an unwind produced into `context`. The last
/// argument says whether its program counter is a return address, which
/// only arm64 records.
pub fn set_regs(c: &mut Context, r: &Regs, _unwound_to_call: bool) {
    [
        c.Rax, c.Rcx, c.Rdx, c.Rbx, c.Rsp, c.Rbp, c.Rsi, c.Rdi, c.R8, c.R9, c.R10, c.R11, c.R12,
        c.R13, c.R14, c.R15,
    ] = r.gpr;
    c.Rip = r.rip;
    for (x, value) in c.FltSave.XmmRegisters[6..].iter_mut().zip(r.xmm) {
        *x = M128A {
            Low: value as u64,
            High: (value >> 64) as i64,
        };
    }
}

pub fn pc(c: &Context) -> u64 {
    c.Rip
}

pub fn sp(c: &Context) -> u64 {
    c.Rsp
}

/// Make `context` resume at `pc` with `value` as a call's return value.
pub fn set_resume(c: &mut Context, pc: u64, value: u64) {
    c.Rip = pc;
    c.Rax = value;
}

/// What a dispatcher context points to besides the context record.
pub fn nonvolatile(_: &Context) -> Nonvolatile {
    Nonvolatile
}

/// A dispatcher context for the handler of one frame.
#[expect(clippy::too_many_arguments, reason = "one per field")]
pub fn dispatcher_context(
    control_pc: u64,
    image_base: u64,
    function_entry: u64,
    establisher: u64,
    target: u64,
    context: *mut Context,
    handler: u64,
    handler_data: u64,
    scope_index: u32,
    _unwound_to_call: bool,
    _nonvolatile: &mut Nonvolatile,
) -> DispatcherContext {
    DispatcherContext {
        ControlPc: control_pc,
        ImageBase: image_base,
        FunctionEntry: function_entry as *mut _,
        EstablisherFrame: establisher,
        TargetIp: target,
        ContextRecord: context,
        LanguageHandler: handler as *mut c_void,
        HandlerData: handler_data as *mut c_void,
        HistoryTable: core::ptr::null_mut(),
        ScopeIndex: scope_index,
        Fill0: 0,
    }
}

/// Make `mine` the dispatcher context `theirs`, an unwind in progress
/// that the walk using `mine` has run into; where `mine` is to resume
/// stays its own.
///
/// # Safety
/// Both point to dispatcher contexts of the dispatcher's.
pub unsafe fn take_over(mine: *mut DispatcherContext, theirs: *const DispatcherContext) {
    // SAFETY: per the contract.
    unsafe {
        let target = (*mine).TargetIp;
        mine.copy_from_nonoverlapping(theirs, 1);
        (*mine).TargetIp = target;
    }
}

/// Where an unwind is to resume, as the dispatcher context says.
pub fn target(dispatcher: &DispatcherContext) -> u64 {
    dispatcher.TargetIp
}

/// Whether the frame's program counter is a return address: not
/// recorded on x86-64, where it makes no difference to a look-up.
pub fn unwound_to_call(_: &DispatcherContext) -> bool {
    false
}

/// The program counter a handler looks its scopes up by: on x86-64 the
/// frame's own, return address or not.
pub fn scope_pc(dispatcher: &DispatcherContext) -> u64 {
    dispatcher.ControlPc
}
