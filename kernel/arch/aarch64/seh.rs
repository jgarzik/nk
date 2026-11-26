//! Structured exception handling on arm64: the assembly the dispatcher
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
//! instructions ([`fixup`]) and resumes the routine at its way out.
//!
//! A frame's base, as a language handler is given it, is the stack
//! pointer its function was entered with.

use core::arch::global_asm;
use core::ffi::c_void;
use nk_ntabi::seh::EXCEPTION_RECORD;
use nk_ntabi::seh::arm64::{CONTEXT, CONTEXT_FULL, CONTEXT_UNWOUND_TO_CALL, DISPATCHER_CONTEXT};
use nk_unwind::arm64::Regs;

pub type Context = CONTEXT;
pub type DispatcherContext = DISPATCHER_CONTEXT;
/// What a dispatcher context points to besides the context record
/// (`DISPATCHER_CONTEXT.NonVolatileRegisters`): x19-x29, then d8-d15.
pub type Nonvolatile = [u64; 19];

/// A language handler.
pub type Handler =
    unsafe extern "C" fn(*mut EXCEPTION_RECORD, u64, *mut Context, *mut DispatcherContext) -> u32;

/// Bytes below a frame's base (the stack pointer at entry) of the slot
/// where `nk_guarded_call` keeps its guard and the handler-call routines
/// their dispatcher context.
const FRAME_SLOT: u64 = 16;

global_asm!(
    r#"
    .text
    .globl nk_with_caller_context
// x16: a function `extern "C" fn(a0, a1, a2, *mut CONTEXT)`. x0-x2: its
// first three arguments, the caller's own. Calls it with a CONTEXT of
// the caller as it will be when this call has returned: `pc` the return
// address, marked as one, and every other register as it is now. x9,
// x10, x16 and x17, which a call may destroy, are recorded as they
// happen to be.
nk_with_caller_context:
    .seh_proc nk_with_caller_context
    sub sp, sp, #0x3A0
    .seh_stackalloc 0x3A0
    stp x29, x30, [sp]
    .seh_save_fplr 0
    .seh_endprologue
    add x17, sp, #16
    mov x9, #0x390
2:  sub x9, x9, #16
    add x10, x17, x9
    stp xzr, xzr, [x10]
    cbnz x9, 2b
    mov w9, #{flags_low}
    movk w9, #{flags_high}, lsl #16
    str w9, [x17]
    mrs x9, nzcv
    mrs x10, daif
    orr x9, x9, x10
    mrs x10, CurrentEL
    orr x9, x9, x10
    orr x9, x9, #1
    str w9, [x17, #4]
    stp x0, x1, [x17, #0x08]
    stp x2, x3, [x17, #0x18]
    stp x4, x5, [x17, #0x28]
    stp x6, x7, [x17, #0x38]
    stp x8, x9, [x17, #0x48]
    stp x10, x11, [x17, #0x58]
    stp x12, x13, [x17, #0x68]
    stp x14, x15, [x17, #0x78]
    stp x16, x17, [x17, #0x88]
    stp x18, x19, [x17, #0x98]
    stp x20, x21, [x17, #0xA8]
    stp x22, x23, [x17, #0xB8]
    stp x24, x25, [x17, #0xC8]
    stp x26, x27, [x17, #0xD8]
    stp x28, x29, [x17, #0xE8]
    add x9, sp, #0x3A0
    stp x30, x9, [x17, #0xF8]
    str x30, [x17, #0x108]
    stp q0, q1, [x17, #0x110]
    stp q2, q3, [x17, #0x130]
    stp q4, q5, [x17, #0x150]
    stp q6, q7, [x17, #0x170]
    stp q8, q9, [x17, #0x190]
    stp q10, q11, [x17, #0x1B0]
    stp q12, q13, [x17, #0x1D0]
    stp q14, q15, [x17, #0x1F0]
    stp q16, q17, [x17, #0x210]
    stp q18, q19, [x17, #0x230]
    stp q20, q21, [x17, #0x250]
    stp q22, q23, [x17, #0x270]
    stp q24, q25, [x17, #0x290]
    stp q26, q27, [x17, #0x2B0]
    stp q28, q29, [x17, #0x2D0]
    stp q30, q31, [x17, #0x2F0]
    mrs x9, fpcr
    mrs x10, fpsr
    str w9, [x17, #0x310]
    str w10, [x17, #0x314]
    mov x3, x17
    blr x16
    .seh_startepilogue
    ldp x29, x30, [sp]
    .seh_save_fplr 0
    add sp, sp, #0x3A0
    .seh_stackalloc 0x3A0
    .seh_endepilogue
    ret
    .seh_endproc

// An exported routine entered with its caller's context: no frame of
// its own, so the caller of the common path is the driver.
    .macro nk_caller_context entry, target
    .globl \entry
\entry:
    .seh_proc \entry
    .seh_endprologue
    adrp x16, \target
    add x16, x16, :lo12:\target
    b nk_with_caller_context
    .seh_endproc
    .endm

    nk_caller_context nk_entry_ExRaiseStatus, nk_raise_status
    nk_caller_context nk_entry_ExRaiseAccessViolation, nk_raise_access_violation
    nk_caller_context nk_entry_ExRaiseDatatypeMisalignment, nk_raise_datatype_misalignment
    nk_caller_context nk_entry_ProbeForRead, nk_probe_for_read
    nk_caller_context nk_entry_ProbeForWrite, nk_probe_for_write
    nk_caller_context nk_entry_MmProbeAndLockPages, nk_probe_and_lock_pages

    .globl nk_guarded_call
// x0: a routine. x1-x4: its arguments. x5: the caller's guard record,
// kept in the frame for this routine's handler.
nk_guarded_call:
    .seh_proc nk_guarded_call
    .seh_handler {guard_handler}, @unwind, @except
    stp x29, x30, [sp, #-32]!
    .seh_save_fplr_x 32
    .seh_endprologue
    str x5, [sp, #16]
    mov x9, x0
    mov x0, x1
    mov x1, x2
    mov x2, x3
    mov x3, x4
    blr x9
    .seh_startepilogue
    ldp x29, x30, [sp], #32
    .seh_save_fplr_x 32
    .seh_endepilogue
    ret
    .seh_endproc

// x0: the exception record. x1: the frame. x2: the context record.
// x3: the dispatcher context, kept in the frame for this routine's
// handler. x4: the language handler to call with the first four.
    .macro nk_call_handler name, handler
    .globl \name
\name:
    .seh_proc \name
    .seh_handler \handler, @unwind, @except
    stp x29, x30, [sp, #-32]!
    .seh_save_fplr_x 32
    .seh_endprologue
    str x3, [sp, #16]
    blr x4
    .seh_startepilogue
    ldp x29, x30, [sp], #32
    .seh_save_fplr_x 32
    .seh_endepilogue
    ret
    .seh_endproc
    .endm

    nk_call_handler nk_call_handler_search, {nested_handler}
    nk_call_handler nk_call_handler_unwind, {collided_handler}

    .globl nk_fault_copy
    .globl nk_fault_copy_access
    .globl nk_fault_copy_access_end
    .globl nk_fault_copy_fixup
// x0: destination. x1: source. x2: bytes. x3: two words for a fault's
// address and kind. Copies, and returns 0; or, if a byte of either
// range cannot be read or written, fills in the two words and returns 1.
// The trap handler resumes a fault in the two instructions that touch
// the ranges at `nk_fault_copy_fixup`, with the address in x9 and the
// kind in x10.
nk_fault_copy:
    .seh_proc nk_fault_copy
    .seh_endprologue
    cbz x2, 3f
nk_fault_copy_access:
2:  ldrb w9, [x1], #1
    strb w9, [x0], #1
nk_fault_copy_access_end:
    subs x2, x2, #1
    b.ne 2b
3:  mov x0, #0
    ret
nk_fault_copy_fixup:
    stp x9, x10, [x3]
    mov x0, #1
    ret
    .seh_endproc

    .globl nk_restore_context
// x0: a CONTEXT. Continue at its `pc` with its stack pointer, the
// registers a call preserves and x0. Everything is loaded before the
// stack pointer moves: an interrupt is taken on the current stack, and
// would write over the context once it lay below.
nk_restore_context:
    .seh_proc nk_restore_context
    .seh_endprologue
    mov x16, x0
    ldp x19, x20, [x16, #0xA0]
    ldp x21, x22, [x16, #0xB0]
    ldp x23, x24, [x16, #0xC0]
    ldp x25, x26, [x16, #0xD0]
    ldp x27, x28, [x16, #0xE0]
    ldp x29, x30, [x16, #0xF0]
    ldp q8, q9, [x16, #0x190]
    ldp q10, q11, [x16, #0x1B0]
    ldp q12, q13, [x16, #0x1D0]
    ldp q14, q15, [x16, #0x1F0]
    ldr x0, [x16, #0x08]
    ldr x17, [x16, #0x108]
    ldr x16, [x16, #0x100]
    mov sp, x16
    br x17
    .seh_endproc
"#,
    flags_low = const (CONTEXT_FULL | CONTEXT_UNWOUND_TO_CALL) & 0xFFFF,
    flags_high = const (CONTEXT_FULL | CONTEXT_UNWOUND_TO_CALL) >> 16,
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
    static nk_fault_copy_access: u8;
    static nk_fault_copy_access_end: u8;
    static nk_fault_copy_fixup: u8;
    pub fn nk_entry_ExRaiseStatus(status: i32);
    pub fn nk_entry_ExRaiseAccessViolation();
    pub fn nk_entry_ExRaiseDatatypeMisalignment();
    pub fn nk_entry_ProbeForRead(address: *const c_void, length: usize, alignment: u32);
    pub fn nk_entry_ProbeForWrite(address: *mut c_void, length: usize, alignment: u32);
    pub fn nk_entry_MmProbeAndLockPages(mdl: *mut c_void, access_mode: i8, operation: u32);
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
    unsafe { ((frame - FRAME_SLOT) as *const *const c_void).read() }
}

/// The dispatcher context of the handler-call frame at `frame`.
///
/// # Safety
/// `frame` is the establisher frame a walk gave for one of the
/// handler-call routines.
pub unsafe fn dispatcher_of(frame: u64) -> *mut DispatcherContext {
    // SAFETY: per the contract, the slot the routine stored it in.
    unsafe { ((frame - FRAME_SLOT) as *const *mut DispatcherContext).read() }
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

/// Make `context`'s first argument register hold `value`, and move its
/// stack pointer down by `drop` bytes.
pub fn repair(c: &mut Context, value: u64, drop: u64) {
    c.X[0] = value;
    c.Sp -= drop;
}

/// A context with every field zero.
pub fn empty_context() -> Context {
    // SAFETY: the structure is integers throughout.
    unsafe { core::mem::zeroed() }
}

/// The context of the frame `regs` describes: its registers, and the
/// rest zero. Its program counter is a return address.
pub fn context_of(regs: &Regs) -> Context {
    let mut context = empty_context();
    context.ContextFlags = CONTEXT_FULL;
    set_regs(&mut context, regs, true);
    context
}

/// The registers of `context` an unwind works on.
pub fn regs(c: &Context) -> Regs {
    let mut x = [0; 12];
    x[..10].copy_from_slice(&c.X[19..]);
    x[10] = c.Fp;
    x[11] = c.Lr;
    let mut d = [0; 8];
    for (out, v) in d.iter_mut().zip(&c.V[8..16]) {
        *out = v.Low;
    }
    Regs {
        x,
        sp: c.Sp,
        pc: c.Pc,
        d,
    }
}

/// Put the registers an unwind produced into `context`, and record
/// whether its program counter is a return address, as Windows does in
/// the context's flags.
pub fn set_regs(c: &mut Context, r: &Regs, unwound_to_call: bool) {
    c.X[19..].copy_from_slice(&r.x[..10]);
    c.Fp = r.x[10];
    c.Lr = r.x[11];
    c.Sp = r.sp;
    c.Pc = r.pc;
    for (v, value) in c.V[8..16].iter_mut().zip(r.d) {
        v.Low = value;
    }
    if unwound_to_call {
        c.ContextFlags |= CONTEXT_UNWOUND_TO_CALL;
    } else {
        c.ContextFlags &= !CONTEXT_UNWOUND_TO_CALL;
    }
}

pub fn pc(c: &Context) -> u64 {
    c.Pc
}

pub fn sp(c: &Context) -> u64 {
    c.Sp
}

/// Make `context` resume at `pc` with `value` as a call's return value.
pub fn set_resume(c: &mut Context, pc: u64, value: u64) {
    c.Pc = pc;
    c.X[0] = value;
}

/// What a dispatcher context points to besides the context record: the
/// registers a call preserves, as the frame has them.
pub fn nonvolatile(c: &Context) -> Nonvolatile {
    let mut out = [0; 19];
    out[..10].copy_from_slice(&c.X[19..]);
    out[10] = c.Fp;
    for (slot, v) in out[11..].iter_mut().zip(&c.V[8..16]) {
        *slot = v.Low;
    }
    out
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
    unwound_to_call: bool,
    nonvolatile: &mut Nonvolatile,
) -> DispatcherContext {
    DispatcherContext {
        ControlPc: control_pc,
        ImageBase: image_base,
        FunctionEntry: function_entry as *mut _,
        EstablisherFrame: establisher,
        TargetPc: target,
        ContextRecord: context,
        LanguageHandler: handler as *mut c_void,
        HandlerData: handler_data as *mut c_void,
        HistoryTable: core::ptr::null_mut(),
        ScopeIndex: scope_index,
        ControlPcIsUnwound: u8::from(unwound_to_call),
        NonVolatileRegisters: nonvolatile.as_mut_ptr().cast(),
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
        let target = (*mine).TargetPc;
        mine.copy_from_nonoverlapping(theirs, 1);
        (*mine).TargetPc = target;
    }
}

/// Where an unwind is to resume, as the dispatcher context says.
pub fn target(dispatcher: &DispatcherContext) -> u64 {
    dispatcher.TargetPc
}

/// Whether the frame's program counter is a return address.
pub fn unwound_to_call(dispatcher: &DispatcherContext) -> bool {
    dispatcher.ControlPcIsUnwound != 0
}

/// The frame a filter or a `__finally` block is given: on arm64 not the
/// frame its language handler was given (the stack pointer the function
/// was entered with) but the function's frame pointer, which compiled
/// blocks take as their own (`mov x29, x1`) to reach the function's
/// variables. It is among the registers the dispatcher context points
/// to.
///
/// # Safety
/// `dispatcher` is the context a language handler was called with.
pub unsafe fn block_frame(dispatcher: &DispatcherContext, _frame: u64) -> u64 {
    // SAFETY: per the contract, it points to the frame's preserved
    // registers, x19 first, so x29 is the eleventh.
    unsafe { dispatcher.NonVolatileRegisters.cast::<u64>().add(10).read() }
}

/// The program counter a handler looks its scopes up by: the call
/// instruction when the frame's own is a return address, which may be
/// the first instruction after the guarded range.
pub fn scope_pc(dispatcher: &DispatcherContext) -> u64 {
    if unwound_to_call(dispatcher) {
        dispatcher.ControlPc - 4
    } else {
        dispatcher.ControlPc
    }
}
