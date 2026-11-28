//! x86-64 Ring 3 transition: `SYSCALL`/`SYSRETQ` entry and exit, initial
//! Ring 3 entry (`iretq`), and user-mode exception interception.

#![allow(non_snake_case)]

use super::cpu::{GS_KERNEL_RSP0, GS_USER_RSP, USER_CODE64, USER_DATA};
use super::trap::{self, Frame};
use crate::ke::thread;
use crate::svc::{self, MAX_SYSCALL_ARGS, capture};
use core::arch::global_asm;
use core::ffi::c_void;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use nk_ntabi::io::{KERNEL_MODE, USER_MODE};
use nk_ntabi::seh::EXCEPTION_RECORD;
use nk_ntabi::seh::x64::{
    CONTEXT, CONTEXT_CONTROL, CONTEXT_FLOATING_POINT, CONTEXT_FULL, CONTEXT_INTEGER,
    CONTEXT_SEGMENTS, KEXCEPTION_FRAME, KTRAP_FRAME,
};
use nk_ntabi::status::{
    NTSTATUS, STATUS_ACCESS_VIOLATION, STATUS_INVALID_PARAMETER, STATUS_INVALID_SYSTEM_SERVICE,
    STATUS_PRIVILEGED_INSTRUCTION, STATUS_SUCCESS,
};
use nk_ntabi::thread as thread_layout;

const EF_SIZE: usize = size_of::<KEXCEPTION_FRAME>();
const TF_SIZE: usize = size_of::<KTRAP_FRAME>();
const FRAME_TOTAL: usize = EF_SIZE + TF_SIZE;

const _: () = {
    assert!(EF_SIZE == 0x140);
    assert!(TF_SIZE == 0x190);
    assert!(FRAME_TOTAL == 0x2D0);
    assert!(offset_of!(KTRAP_FRAME, PreviousMode) == 0x28);
    assert!(offset_of!(KTRAP_FRAME, MxCsr) == 0x2C);
    assert!(offset_of!(KTRAP_FRAME, Rax) == 0x30);
    assert!(offset_of!(KTRAP_FRAME, Rcx) == 0x38);
    assert!(offset_of!(KTRAP_FRAME, Rdx) == 0x40);
    assert!(offset_of!(KTRAP_FRAME, R8) == 0x48);
    assert!(offset_of!(KTRAP_FRAME, R9) == 0x50);
    assert!(offset_of!(KTRAP_FRAME, R10) == 0x58);
    assert!(offset_of!(KTRAP_FRAME, R11) == 0x60);
    assert!(offset_of!(KTRAP_FRAME, Xmm0) == 0x70);
    assert!(offset_of!(KTRAP_FRAME, Rbx) == 0x140);
    assert!(offset_of!(KTRAP_FRAME, Rdi) == 0x148);
    assert!(offset_of!(KTRAP_FRAME, Rsi) == 0x150);
    assert!(offset_of!(KTRAP_FRAME, Rbp) == 0x158);
    assert!(offset_of!(KTRAP_FRAME, Rip) == 0x168);
    assert!(offset_of!(KTRAP_FRAME, SegCs) == 0x170);
    assert!(offset_of!(KTRAP_FRAME, EFlags) == 0x178);
    assert!(offset_of!(KTRAP_FRAME, Rsp) == 0x180);
    assert!(offset_of!(KTRAP_FRAME, SegSs) == 0x188);
    assert!(offset_of!(KEXCEPTION_FRAME, Xmm6) == 0x30);
    assert!(offset_of!(KEXCEPTION_FRAME, TrapFrame) == 0xD0);
    assert!(offset_of!(KEXCEPTION_FRAME, Rbp) == 0xF8);
    assert!(offset_of!(KEXCEPTION_FRAME, Rbx) == 0x100);
    assert!(offset_of!(KEXCEPTION_FRAME, Rdi) == 0x108);
    assert!(offset_of!(KEXCEPTION_FRAME, Rsi) == 0x110);
    assert!(offset_of!(KEXCEPTION_FRAME, R12) == 0x118);
    assert!(offset_of!(KEXCEPTION_FRAME, R13) == 0x120);
    assert!(offset_of!(KEXCEPTION_FRAME, R14) == 0x128);
    assert!(offset_of!(KEXCEPTION_FRAME, R15) == 0x130);
};

global_asm!(
    r#"
    .text
    .globl nk_syscall_entry
nk_syscall_entry:
    .seh_proc nk_syscall_entry
    swapgs
    mov gs:[{user_rsp}], rsp
    mov rsp, gs:[{kernel_rsp0}]
    sub rsp, {frame_total}
    .seh_stackalloc 0x2D0
    .seh_endprologue
    // `rsp + 0x000` = KEXCEPTION_FRAME (`ef`), `rsp + 0x140` = KTRAP_FRAME (`tf`).
    mov [rsp + 0x140 + 0x30], rax       // tf.Rax = syscall number
    mov [rsp + 0x140 + 0x38], r10       // tf.Rcx = arg0 (ntdll moves rcx -> r10)
    mov [rsp + 0x140 + 0x40], rdx       // tf.Rdx = arg1
    mov [rsp + 0x140 + 0x48], r8        // tf.R8  = arg2
    mov [rsp + 0x140 + 0x50], r9        // tf.R9  = arg3
    mov [rsp + 0x140 + 0x58], r10       // tf.R10 = arg0
    mov [rsp + 0x140 + 0x60], r11       // tf.R11 = user RFLAGS
    mov [rsp + 0x140 + 0x140], rbx      // tf.Rbx
    mov [rsp + 0x140 + 0x148], rdi      // tf.Rdi
    mov [rsp + 0x140 + 0x150], rsi      // tf.Rsi
    mov [rsp + 0x140 + 0x158], rbp      // tf.Rbp
    mov [rsp + 0x140 + 0x168], rcx      // tf.Rip = user RIP
    mov qword ptr [rsp + 0x140 + 0x170], {user_cs}
    mov [rsp + 0x140 + 0x178], r11      // tf.EFlags = user RFLAGS
    mov rax, gs:[{user_rsp}]
    mov [rsp + 0x140 + 0x180], rax      // tf.Rsp = user RSP
    mov qword ptr [rsp + 0x140 + 0x188], {user_ss}
    mov byte ptr [rsp + 0x140 + 0x28], 1 // tf.PreviousMode = UserMode
    stmxcsr dword ptr [rsp + 0x140 + 0x2C]
    mov dword ptr [rsp + 0x140 + 0x00], 0x1F80
    ldmxcsr dword ptr [rsp + 0x140 + 0x00]

    // Populate KEXCEPTION_FRAME with nonvolatile GPRs and XMM6..15 so context
    // inspection and `NtContinue` work uniformly across syscall frames.
    lea rax, [rsp + 0x140]
    mov [rsp + 0xD0], rax               // ef.TrapFrame = &tf
    mov [rsp + 0xF8], rbp               // ef.Rbp
    mov [rsp + 0x100], rbx              // ef.Rbx
    mov [rsp + 0x108], rdi              // ef.Rdi
    mov [rsp + 0x110], rsi              // ef.Rsi
    mov [rsp + 0x118], r12              // ef.R12
    mov [rsp + 0x120], r13              // ef.R13
    mov [rsp + 0x128], r14              // ef.R14
    mov [rsp + 0x130], r15              // ef.R15
    movups [rsp + 0x30], xmm6
    movups [rsp + 0x40], xmm7
    movups [rsp + 0x50], xmm8
    movups [rsp + 0x60], xmm9
    movups [rsp + 0x70], xmm10
    movups [rsp + 0x80], xmm11
    movups [rsp + 0x90], xmm12
    movups [rsp + 0xA0], xmm13
    movups [rsp + 0xB0], xmm14
    movups [rsp + 0xC0], xmm15

    mov rcx, rax                        // arg0 = &mut KTRAP_FRAME
    mov rdx, rsp                        // arg1 = &mut KEXCEPTION_FRAME
    sub rsp, 32
    cld
    sti
    call {dispatch}
    cli
    add rsp, 32

    // If `syscall_dispatch` returned non-zero (e.g. NtContinue / user APC),
    // restore the full frame via `iretq`.
    test al, al
    jnz 2f

    // Canonical user-mode RIP check (bits 63..47 must all be zero) and TF==0
    // before `sysretq` (prevents Ring 0 #GP on non-canonical `rcx`).
    mov rcx, [rsp + 0x140 + 0x168]
    mov r10, rcx
    shr r10, 47
    test r10, r10
    jnz 2f
    mov r11, [rsp + 0x140 + 0x178]
    test r11, 0x100                     // TF set -> iretq
    jnz 2f
    cmp word ptr [rsp + 0x140 + 0x170], {user_cs}
    jne 2f
    cmp word ptr [rsp + 0x140 + 0x188], {user_ss}
    jne 2f

    // Fast SYSRETQ return path.
    ldmxcsr dword ptr [rsp + 0x140 + 0x2C]
    movups xmm6, [rsp + 0x30]
    movups xmm7, [rsp + 0x40]
    movups xmm8, [rsp + 0x50]
    movups xmm9, [rsp + 0x60]
    movups xmm10, [rsp + 0x70]
    movups xmm11, [rsp + 0x80]
    movups xmm12, [rsp + 0x90]
    movups xmm13, [rsp + 0xA0]
    movups xmm14, [rsp + 0xB0]
    movups xmm15, [rsp + 0xC0]
    mov r12, [rsp + 0x118]
    mov r13, [rsp + 0x120]
    mov r14, [rsp + 0x128]
    mov r15, [rsp + 0x130]
    mov rbx, [rsp + 0x140 + 0x140]
    mov rdi, [rsp + 0x140 + 0x148]
    mov rsi, [rsp + 0x140 + 0x150]
    mov rbp, [rsp + 0x140 + 0x158]
    mov rax, [rsp + 0x140 + 0x30]       // NTSTATUS return value
    // Sanitize user RFLAGS: keep user flags, force IF=1 and bit 1=1.
    and r11, 0x0003CFFF
    or r11, 0x202
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    mov rsp, [rsp + 0x140 + 0x180]      // user RSP
    swapgs
    sysretq

2:
    // Full IRETQ return path (restores all GPRs, XMM0..15, and iret frame).
    ldmxcsr dword ptr [rsp + 0x140 + 0x2C]
    movups xmm0, [rsp + 0x140 + 0x70]
    movups xmm1, [rsp + 0x140 + 0x80]
    movups xmm2, [rsp + 0x140 + 0x90]
    movups xmm3, [rsp + 0x140 + 0xA0]
    movups xmm4, [rsp + 0x140 + 0xB0]
    movups xmm5, [rsp + 0x140 + 0xC0]
    movups xmm6, [rsp + 0x30]
    movups xmm7, [rsp + 0x40]
    movups xmm8, [rsp + 0x50]
    movups xmm9, [rsp + 0x60]
    movups xmm10, [rsp + 0x70]
    movups xmm11, [rsp + 0x80]
    movups xmm12, [rsp + 0x90]
    movups xmm13, [rsp + 0xA0]
    movups xmm14, [rsp + 0xB0]
    movups xmm15, [rsp + 0xC0]
    mov r12, [rsp + 0x118]
    mov r13, [rsp + 0x120]
    mov r14, [rsp + 0x128]
    mov r15, [rsp + 0x130]
    mov rax, [rsp + 0x140 + 0x30]
    mov rcx, [rsp + 0x140 + 0x38]
    mov rdx, [rsp + 0x140 + 0x40]
    mov r8,  [rsp + 0x140 + 0x48]
    mov r9,  [rsp + 0x140 + 0x50]
    mov r10, [rsp + 0x140 + 0x58]
    mov r11, [rsp + 0x140 + 0x60]
    mov rbx, [rsp + 0x140 + 0x140]
    mov rdi, [rsp + 0x140 + 0x148]
    mov rsi, [rsp + 0x140 + 0x150]
    mov rbp, [rsp + 0x140 + 0x158]
    add rsp, 0x140 + 0x168
    swapgs
    iretq
    .seh_endproc

    .globl nk_enter_user_mode
// rcx = user RIP, rdx = user RSP, r8 = initial user RCX (arg0), r9 = initial user RDX (arg1).
// Never returns: transitions to Ring 3 via `swapgs; iretq` with zeroed GPRs
// and default user RFLAGS (`0x202`, IF=1).
nk_enter_user_mode:
    .seh_proc nk_enter_user_mode
    .seh_endprologue
    cli
    mov ax, {user_ss}
    mov ds, ax
    mov es, ax
    xor eax, eax
    mov fs, ax
    push {user_ss}                      // SS
    push rdx                            // RSP
    push 0x202                          // RFLAGS (IF=1, reserved bit 1=1)
    push {user_cs}                      // CS
    push rcx                            // RIP
    mov rcx, r8                         // initial user RCX (arg0)
    mov rdx, r9                         // initial user RDX (arg1)
    xor eax, eax
    xor ebx, ebx
    xor esi, esi
    xor edi, edi
    xor ebp, ebp
    xor r8d, r8d
    xor r9d, r9d
    xor r10d, r10d
    xor r11d, r11d
    xor r12d, r12d
    xor r13d, r13d
    xor r14d, r14d
    xor r15d, r15d
    swapgs
    iretq
    .seh_endproc
"#,
    user_rsp = const GS_USER_RSP,
    kernel_rsp0 = const GS_KERNEL_RSP0,
    frame_total = const FRAME_TOTAL,
    user_cs = const USER_CODE64,
    user_ss = const USER_DATA,
    dispatch = sym syscall_dispatch,
);

unsafe extern "C" {
    fn nk_syscall_entry();
    fn nk_enter_user_mode(rip: u64, rsp: u64, arg0: u64, arg1: u64) -> !;
}

/// Entry address programmed into `IA32_LSTAR`.
pub fn syscall_entry_addr() -> u64 {
    nk_syscall_entry as *const () as usize as u64
}

/// Transition the current thread into Ring 3 at `(rip, rsp)` with `arg0` in `rcx`
/// and `arg1` in `rdx`.
///
/// # Safety
/// The current thread must belong to a user address space with valid user
/// mappings at `rip` (executable) and `rsp` (writable stack), at `PASSIVE_LEVEL`
/// with no locks held.
pub unsafe fn enter_user_mode(rip: u64, rsp: u64, arg0: u64, arg1: u64) -> ! {
    // SAFETY: per the contract.
    unsafe { nk_enter_user_mode(rip, rsp, arg0, arg1) }
}

/// Offset from `rsp` to `EXCEPTION_RECORD` (in `KiUserExceptionDispatcher`)
/// and `KCONTINUE_ARGUMENT` (in `KiUserApcDispatcher`) on Windows 10 19041 x64.
const USER_FRAME_EXTRA_OFFSET: u64 = 0x4F0;

/// Windows 10 `KCONTINUE_ARGUMENT` passed to `NtContinueEx` by `KiUserApcDispatcher`.
#[repr(C)]
#[derive(Clone, Copy)]
struct KContinueArgument {
    continue_type: u32,
    continue_flags: u32,
    reserved: [u64; 2],
}

const KCONTINUE_APC: u32 = 1;
const KCONTINUE_FLAG_TEST_ALERT: u32 = 0x1;

/// Build a Windows x64 `CONTEXT` from the active syscall trap + exception frames.
fn context_from_trap(tf: &KTRAP_FRAME, ef: &KEXCEPTION_FRAME) -> CONTEXT {
    // SAFETY: `CONTEXT` is all-zero valid.
    let mut c: CONTEXT = unsafe { core::mem::zeroed() };
    c.ContextFlags = CONTEXT_FULL | CONTEXT_SEGMENTS;
    c.MxCsr = tf.MxCsr;
    c.FltSave.MxCsr = tf.MxCsr;
    c.FltSave.ControlWord = 0x027F;
    c.FltSave.MxCsr_Mask = 0xFFFF;
    c.SegCs = USER_CODE64;
    c.SegDs = USER_DATA;
    c.SegEs = USER_DATA;
    c.SegFs = 0;
    c.SegGs = USER_DATA;
    c.SegSs = USER_DATA;
    c.EFlags = tf.EFlags;
    c.Rax = tf.Rax;
    c.Rcx = tf.Rcx;
    c.Rdx = tf.Rdx;
    c.Rbx = tf.Rbx;
    c.Rsp = tf.Rsp;
    c.Rbp = tf.Rbp;
    c.Rsi = tf.Rsi;
    c.Rdi = tf.Rdi;
    c.R8 = tf.R8;
    c.R9 = tf.R9;
    c.R10 = tf.R10;
    c.R11 = tf.R11;
    c.R12 = ef.R12;
    c.R13 = ef.R13;
    c.R14 = ef.R14;
    c.R15 = ef.R15;
    c.Rip = tf.Rip;
    c.FltSave.XmmRegisters[0] = tf.Xmm0;
    c.FltSave.XmmRegisters[1] = tf.Xmm1;
    c.FltSave.XmmRegisters[2] = tf.Xmm2;
    c.FltSave.XmmRegisters[3] = tf.Xmm3;
    c.FltSave.XmmRegisters[4] = tf.Xmm4;
    c.FltSave.XmmRegisters[5] = tf.Xmm5;
    c.FltSave.XmmRegisters[6] = ef.Xmm6;
    c.FltSave.XmmRegisters[7] = ef.Xmm7;
    c.FltSave.XmmRegisters[8] = ef.Xmm8;
    c.FltSave.XmmRegisters[9] = ef.Xmm9;
    c.FltSave.XmmRegisters[10] = ef.Xmm10;
    c.FltSave.XmmRegisters[11] = ef.Xmm11;
    c.FltSave.XmmRegisters[12] = ef.Xmm12;
    c.FltSave.XmmRegisters[13] = ef.Xmm13;
    c.FltSave.XmmRegisters[14] = ef.Xmm14;
    c.FltSave.XmmRegisters[15] = ef.Xmm15;
    c
}

/// Apply a user-supplied `CONTEXT` to the active syscall trap + exception frames.
fn apply_context_to_trap(c: &CONTEXT, tf: &mut KTRAP_FRAME, ef: &mut KEXCEPTION_FRAME) {
    let flags = c.ContextFlags;
    if (flags & (CONTEXT_CONTROL & 0xFF)) != 0 {
        tf.Rip = c.Rip;
        tf.Rsp = c.Rsp;
        tf.SegCs = USER_CODE64;
        tf.SegSs = USER_DATA;
        tf.EFlags = (c.EFlags & 0x0003_CFFF) | 0x202;
    }
    if (flags & (CONTEXT_INTEGER & 0xFF)) != 0 {
        tf.Rax = c.Rax;
        tf.Rcx = c.Rcx;
        tf.Rdx = c.Rdx;
        tf.Rbx = c.Rbx;
        tf.Rbp = c.Rbp;
        tf.Rsi = c.Rsi;
        tf.Rdi = c.Rdi;
        tf.R8 = c.R8;
        tf.R9 = c.R9;
        tf.R10 = c.R10;
        tf.R11 = c.R11;
        ef.Rbp = c.Rbp;
        ef.Rbx = c.Rbx;
        ef.Rdi = c.Rdi;
        ef.Rsi = c.Rsi;
        ef.R12 = c.R12;
        ef.R13 = c.R13;
        ef.R14 = c.R14;
        ef.R15 = c.R15;
    }
    if (flags & (CONTEXT_FLOATING_POINT & 0xFF)) != 0 {
        tf.MxCsr = c.MxCsr & 0xFFFF;
        tf.Xmm0 = c.FltSave.XmmRegisters[0];
        tf.Xmm1 = c.FltSave.XmmRegisters[1];
        tf.Xmm2 = c.FltSave.XmmRegisters[2];
        tf.Xmm3 = c.FltSave.XmmRegisters[3];
        tf.Xmm4 = c.FltSave.XmmRegisters[4];
        tf.Xmm5 = c.FltSave.XmmRegisters[5];
        ef.Xmm6 = c.FltSave.XmmRegisters[6];
        ef.Xmm7 = c.FltSave.XmmRegisters[7];
        ef.Xmm8 = c.FltSave.XmmRegisters[8];
        ef.Xmm9 = c.FltSave.XmmRegisters[9];
        ef.Xmm10 = c.FltSave.XmmRegisters[10];
        ef.Xmm11 = c.FltSave.XmmRegisters[11];
        ef.Xmm12 = c.FltSave.XmmRegisters[12];
        ef.Xmm13 = c.FltSave.XmmRegisters[13];
        ef.Xmm14 = c.FltSave.XmmRegisters[14];
        ef.Xmm15 = c.FltSave.XmmRegisters[15];
    }
}

/// Look up the current user process's `MappedSysDll`, if it is a user process.
fn current_sysdll() -> Option<crate::ps::sysdll::MappedSysDll> {
    let proc_ptr = crate::ps::process::PsGetCurrentProcess().cast::<u8>();
    if proc_ptr.is_null() || proc_ptr == crate::ps::process::system() {
        return None;
    }
    // SAFETY: `proc_ptr` is the current running process.
    unsafe { crate::ps::process::user_state(proc_ptr) }.map(|s| s.sysdll)
}

/// Set up a `KiUserApcDispatcher` frame on the user stack if a user APC is pending.
/// Returns `true` if `tf` was redirected to `KiUserApcDispatcher`.
fn deliver_user_apc(tf: &mut KTRAP_FRAME, ef: &mut KEXCEPTION_FRAME) -> bool {
    let Some(sysdll) = current_sysdll() else {
        return false;
    };
    let Some((normal, ctx_arg, arg1, arg2)) = crate::ke::apc::pop_user_apc() else {
        return false;
    };
    let mut ctx = context_from_trap(tf, ef);
    ctx.PHome[0] = ctx_arg;
    ctx.PHome[1] = arg1;
    ctx.PHome[2] = arg2;
    ctx.PHome[3] = normal;

    let frame_bytes = (USER_FRAME_EXTRA_OFFSET + size_of::<KContinueArgument>() as u64 + 15) & !15;
    let new_rsp = tf.Rsp.saturating_sub(frame_bytes) & !15;
    let cont_arg = KContinueArgument {
        continue_type: KCONTINUE_APC,
        continue_flags: KCONTINUE_FLAG_TEST_ALERT,
        reserved: [0; 2],
    };
    // SAFETY: `mm::user::copy` fault-protects writes to user memory.
    let ok = unsafe {
        crate::mm::user::in_range(new_rsp as usize, frame_bytes as usize)
            && crate::mm::user::copy(
                core::ptr::with_exposed_provenance_mut(new_rsp as usize),
                (&raw const ctx).cast::<u8>(),
                size_of::<CONTEXT>(),
            )
            .is_ok()
            && crate::mm::user::copy(
                core::ptr::with_exposed_provenance_mut(
                    (new_rsp + USER_FRAME_EXTRA_OFFSET) as usize,
                ),
                (&raw const cont_arg).cast::<u8>(),
                size_of::<KContinueArgument>(),
            )
            .is_ok()
    };
    if !ok {
        crate::ps::user::terminate_current_process(STATUS_ACCESS_VIOLATION);
    }
    tf.Rsp = new_rsp;
    tf.Rip = sysdll.ki_user_apc_dispatcher;
    tf.SegCs = USER_CODE64;
    tf.SegSs = USER_DATA;
    tf.EFlags = (tf.EFlags & !0x500) | 0x202;
    true
}

/// [`NtContinue`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwcontinue):
/// restore the calling thread's user-mode `CONTEXT` and optionally test for alerts/user APCs.
///
/// # Safety
/// `context_record` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtContinue(context_record: *const CONTEXT, test_alert: u8) -> NTSTATUS {
    let arg = core::ptr::with_exposed_provenance(usize::from(test_alert != 0));
    // SAFETY: per the contract.
    unsafe { NtContinueEx(context_record, arg) }
}

/// `NtContinueEx`: Windows 10 extended `NtContinue` accepting either a boolean
/// (`0`/`1`) or a pointer to `KCONTINUE_ARGUMENT` as `continue_argument`.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtContinueEx(
    context_record: *const CONTEXT,
    continue_argument: *const c_void,
) -> NTSTATUS {
    let mode = capture::mode();
    if context_record.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract; `capture::read` probes user pointers.
    let ctx = match unsafe { capture::read(context_record, mode) } {
        Ok(c) => c,
        Err(st) => return st,
    };
    let test_alert = match continue_argument.addr() {
        0 => false,
        1 => true,
        _ => {
            // SAFETY: non-boolean `continue_argument` points to `KCONTINUE_ARGUMENT`.
            match unsafe { capture::read(continue_argument.cast::<KContinueArgument>(), mode) } {
                Ok(arg) => {
                    (arg.continue_flags & KCONTINUE_FLAG_TEST_ALERT) != 0
                        || arg.continue_type == KCONTINUE_APC
                }
                Err(st) => return st,
            }
        }
    };
    let me = thread::current();
    // SAFETY: active syscall trap and exception frames live on the current thread's kernel stack.
    let (tf_ptr, ef_ptr) = unsafe {
        (
            thread::object_field::<u64>(me, thread_layout::TRAP_FRAME).read(),
            thread::active_ef(),
        )
    };
    if tf_ptr == 0 || ef_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: `tf_ptr` and `ef_ptr` are valid mutable frames belonging to this syscall.
    unsafe {
        let tf = &mut *core::ptr::with_exposed_provenance_mut::<KTRAP_FRAME>(tf_ptr as usize);
        let ef = &mut *core::ptr::with_exposed_provenance_mut::<KEXCEPTION_FRAME>(ef_ptr as usize);
        apply_context_to_trap(&ctx, tf, ef);
    }
    if test_alert {
        let _ = crate::ke::apc::NtTestAlert();
    }
    thread::set_force_iret(true);
    STATUS_SUCCESS
}

/// `NtRaiseException`: raise a user-mode exception (`first_chance != 0` dispatches
/// to `KiUserExceptionDispatcher`; `first_chance == 0` terminates the process).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtRaiseException(
    exception_record: *const EXCEPTION_RECORD,
    context_record: *const CONTEXT,
    first_chance: u8,
) -> NTSTATUS {
    let mode = capture::mode();
    if exception_record.is_null() || context_record.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract; `capture::read` probes user pointers.
    let exc = match unsafe { capture::read(exception_record, mode) } {
        Ok(e) => e,
        Err(st) => return st,
    };
    // SAFETY: per the contract; `capture::read` probes user pointers.
    let ctx = match unsafe { capture::read(context_record, mode) } {
        Ok(c) => c,
        Err(st) => return st,
    };
    if first_chance == 0 {
        let pid = crate::ps::process::PsGetCurrentProcessId().addr();
        kprintln!(
            "user: unhandled exception {:#010x} at {:#x} in pid {pid}",
            exc.ExceptionCode,
            exc.ExceptionAddress.addr()
        );
        crate::ps::user::terminate_current_process(exc.ExceptionCode as NTSTATUS);
    }
    let Some(sysdll) = current_sysdll() else {
        crate::ps::user::terminate_current_process(exc.ExceptionCode as NTSTATUS);
    };
    let me = thread::current();
    // SAFETY: active syscall trap and exception frames live on the current thread's kernel stack.
    let (tf_ptr, ef_ptr) = unsafe {
        (
            thread::object_field::<u64>(me, thread_layout::TRAP_FRAME).read(),
            thread::active_ef(),
        )
    };
    if tf_ptr == 0 || ef_ptr == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let frame_bytes = (USER_FRAME_EXTRA_OFFSET + size_of::<EXCEPTION_RECORD>() as u64 + 15) & !15;
    let new_rsp = ctx.Rsp.saturating_sub(frame_bytes) & !15;
    // SAFETY: `mm::user::copy` fault-protects writes to user memory.
    let ok = unsafe {
        crate::mm::user::in_range(new_rsp as usize, frame_bytes as usize)
            && crate::mm::user::copy(
                core::ptr::with_exposed_provenance_mut(new_rsp as usize),
                (&raw const ctx).cast::<u8>(),
                size_of::<CONTEXT>(),
            )
            .is_ok()
            && crate::mm::user::copy(
                core::ptr::with_exposed_provenance_mut(
                    (new_rsp + USER_FRAME_EXTRA_OFFSET) as usize,
                ),
                (&raw const exc).cast::<u8>(),
                size_of::<EXCEPTION_RECORD>(),
            )
            .is_ok()
    };
    if !ok {
        crate::ps::user::terminate_current_process(exc.ExceptionCode as NTSTATUS);
    }
    // SAFETY: `tf_ptr` and `ef_ptr` are valid mutable frames belonging to this syscall.
    unsafe {
        let tf = &mut *core::ptr::with_exposed_provenance_mut::<KTRAP_FRAME>(tf_ptr as usize);
        let ef = &mut *core::ptr::with_exposed_provenance_mut::<KEXCEPTION_FRAME>(ef_ptr as usize);
        apply_context_to_trap(&ctx, tf, ef);
        tf.Rip = sysdll.ki_user_exception_dispatcher;
        tf.Rsp = new_rsp;
        tf.SegCs = USER_CODE64;
        tf.SegSs = USER_DATA;
        tf.EFlags = (tf.EFlags & !0x500) | 0x202;
    }
    thread::set_force_iret(true);
    STATUS_SUCCESS
}

/// C-ABI system-call dispatcher invoked from `nk_syscall_entry`.
/// Returns `0` for fast `sysretq`, or `1` to return via full `iretq`.
extern "C" fn syscall_dispatch(tf: &mut KTRAP_FRAME, ef: &mut KEXCEPTION_FRAME) -> u8 {
    let nr = tf.Rax as u32;
    let me = thread::current();
    // SAFETY: `me` is the running thread; save and update its syscall metadata
    // and trap/exception frame pointers around service dispatch.
    let (old_tf, old_ef, old_mode) = unsafe {
        let tf_slot = thread::object_field::<u64>(me, thread_layout::TRAP_FRAME);
        let old_tf = tf_slot.read();
        tf_slot.write(core::ptr::from_mut(tf).addr() as u64);
        let old_ef = thread::swap_active_ef(core::ptr::from_mut(ef).addr() as u64);
        thread::object_field::<u32>(me, thread_layout::SYSTEM_CALL_NUMBER).write(nr);
        thread::object_field::<u64>(me, thread_layout::FIRST_ARGUMENT).write(tf.Rcx);
        let old_mode = thread::set_previous_mode(USER_MODE);
        (old_tf, old_ef, old_mode)
    };

    let status: NTSTATUS = match svc::meta(nr) {
        None => STATUS_INVALID_SYSTEM_SERVICE,
        Some(meta) => {
            let mut args = [0usize; MAX_SYSCALL_ARGS];
            args[0] = tf.Rcx as usize;
            args[1] = tf.Rdx as usize;
            args[2] = tf.R8 as usize;
            args[3] = tf.R9 as usize;
            let mut copy_ok = true;
            if meta.stack_args > 0 {
                let count = usize::from(meta.stack_args);
                let bytes = count * 8;
                let user_src = tf.Rsp.wrapping_add(0x28);
                if !crate::mm::user::in_range(user_src as usize, bytes) {
                    copy_ok = false;
                } else {
                    // SAFETY: `user_src` is verified inside the user range and
                    // `mm::user::copy` fault-protects the read; `args[4..]` has
                    // room for at least `count` slots (checked at compile time).
                    let copied = unsafe {
                        crate::mm::user::copy(
                            (&raw mut args[4]).cast::<u8>(),
                            core::ptr::with_exposed_provenance(user_src as usize),
                            bytes,
                        )
                    };
                    if copied.is_err() {
                        copy_ok = false;
                    }
                }
            }
            if !copy_ok {
                STATUS_ACCESS_VIOLATION
            } else {
                // SAFETY: `PreviousMode` is `UserMode` and all arguments are
                // captured/copied per the NT service contract.
                let st = unsafe { svc::dispatch(nr, &args) };
                if crate::kd::trace_svc() {
                    kprintln!(
                        "svc: #{nr} {}({:#x}, {:#x}, {:#x}, {:#x}) -> {st:#010x}",
                        meta.name,
                        args[0],
                        args[1],
                        args[2],
                        args[3]
                    );
                }
                st
            }
        }
    };

    let mut force_iret = thread::take_force_iret();
    if !force_iret {
        tf.Rax = u64::from(status as u32);
    }
    if crate::ke::apc::user_pending(me) && deliver_user_apc(tf, ef) {
        force_iret = true;
    }

    // SAFETY: `me` is still the running thread; restore prior mode and frame pointers.
    unsafe {
        thread::set_previous_mode(if old_mode == USER_MODE {
            KERNEL_MODE
        } else {
            old_mode
        });
        thread::swap_active_ef(old_ef);
        thread::object_field::<u64>(me, thread_layout::TRAP_FRAME).write(old_tf);
    }
    u8::from(force_iret)
}

/// Classify a Ring 3 `#GP` as `STATUS_PRIVILEGED_INSTRUCTION` if the faulting
/// opcode is a privileged instruction, else `STATUS_ACCESS_VIOLATION`.
pub fn gp_exception_code(rip: u64) -> u32 {
    let mut bytes = [0u8; 2];
    if !crate::mm::user::in_range(rip as usize, bytes.len()) {
        return STATUS_ACCESS_VIOLATION as u32;
    }
    // SAFETY: `rip` is inside the user range and `mm::user::copy` is fault-safe.
    if unsafe {
        crate::mm::user::copy(
            bytes.as_mut_ptr(),
            core::ptr::with_exposed_provenance(rip as usize),
            bytes.len(),
        )
    }
    .is_err()
    {
        return STATUS_ACCESS_VIOLATION as u32;
    }
    let privileged = matches!(
        bytes[0],
        0xFA // cli
            | 0xFB // sti
            | 0xF4 // hlt
            | 0xE4..=0xE7 // in/out imm8
            | 0xEC..=0xEF // in/out dx
            | 0x6C..=0x6F // ins/outs
    ) || (bytes[0] == 0x0F
        && matches!(
            bytes[1],
            0x00 | 0x01 // sldt/ltr/lgdt/lidt/swapgs
                | 0x06 // clts
                | 0x08 | 0x09 // invd/wbinvd
                | 0x20
                ..=0x23 // mov cr*/dr*
                | 0x30 | 0x32 | 0x33 // wrmsr/rdmsr/rdpmc
        ));
    if privileged {
        STATUS_PRIVILEGED_INSTRUCTION as u32
    } else {
        STATUS_ACCESS_VIOLATION as u32
    }
}

/// Test observer for Ring 3 isolation self-tests (`selftest::user`).
static OBSERVER_ARMED: AtomicBool = AtomicBool::new(false);
static OBSERVER_CODE: AtomicU32 = AtomicU32::new(0);
static OBSERVER_RIP: AtomicU64 = AtomicU64::new(0);
static OBSERVER_INFO0: AtomicU64 = AtomicU64::new(0);
static OBSERVER_INFO1: AtomicU64 = AtomicU64::new(0);

/// Arm or disarm the Ring 3 exception observer used by `user.stub`.
pub fn set_exception_observer(armed: bool) {
    if armed {
        OBSERVER_CODE.store(0, Ordering::Relaxed);
        OBSERVER_RIP.store(0, Ordering::Relaxed);
        OBSERVER_INFO0.store(0, Ordering::Relaxed);
        OBSERVER_INFO1.store(0, Ordering::Relaxed);
    }
    OBSERVER_ARMED.store(armed, Ordering::Release);
}

/// Last user-mode exception recorded while the observer was armed:
/// `(code, rip, info0, info1)`.
pub fn observed_exception() -> (u32, u64, u64, u64) {
    (
        OBSERVER_CODE.load(Ordering::Acquire),
        OBSERVER_RIP.load(Ordering::Acquire),
        OBSERVER_INFO0.load(Ordering::Acquire),
        OBSERVER_INFO1.load(Ordering::Acquire),
    )
}

/// Dispatch a Ring 3 hardware exception to `ntdll!KiUserExceptionDispatcher`
/// (or report to the `user.stub` observer when armed).
/// Returns `true` if `frame` was redirected to Ring 3 exception dispatch.
pub fn handle_user_exception(frame: &mut Frame, code: u32, parameters: &[u64]) -> bool {
    if OBSERVER_ARMED.load(Ordering::Acquire) {
        OBSERVER_CODE.store(code, Ordering::Relaxed);
        OBSERVER_RIP.store(frame.rip, Ordering::Relaxed);
        OBSERVER_INFO0.store(parameters.first().copied().unwrap_or(0), Ordering::Relaxed);
        OBSERVER_INFO1.store(parameters.get(1).copied().unwrap_or(0), Ordering::Relaxed);
        OBSERVER_ARMED.store(false, Ordering::Release);
        super::enable_interrupts();
        thread::exit();
    }
    let Some(sysdll) = current_sysdll() else {
        return false;
    };
    let ctx = trap::context_of(frame);
    let mut exc = EXCEPTION_RECORD {
        ExceptionCode: code,
        ExceptionFlags: 0,
        ExceptionRecord: core::ptr::null_mut(),
        ExceptionAddress: core::ptr::with_exposed_provenance_mut(frame.rip as usize),
        NumberParameters: parameters.len().min(15) as u32,
        ExceptionInformation: [0; 15],
    };
    for (dst, &src) in exc.ExceptionInformation.iter_mut().zip(parameters.iter()) {
        *dst = src;
    }
    // Re-enable interrupts so user stack demand/guard-page faults can resolve cleanly.
    super::enable_interrupts();
    let frame_bytes = (USER_FRAME_EXTRA_OFFSET + size_of::<EXCEPTION_RECORD>() as u64 + 15) & !15;
    let new_rsp = frame.rsp.saturating_sub(frame_bytes) & !15;
    // SAFETY: `mm::user::copy` fault-protects writes to user memory.
    let ok = unsafe {
        crate::mm::user::in_range(new_rsp as usize, frame_bytes as usize)
            && crate::mm::user::copy(
                core::ptr::with_exposed_provenance_mut(new_rsp as usize),
                (&raw const ctx).cast::<u8>(),
                size_of::<CONTEXT>(),
            )
            .is_ok()
            && crate::mm::user::copy(
                core::ptr::with_exposed_provenance_mut(
                    (new_rsp + USER_FRAME_EXTRA_OFFSET) as usize,
                ),
                (&raw const exc).cast::<u8>(),
                size_of::<EXCEPTION_RECORD>(),
            )
            .is_ok()
    };
    if !ok {
        kprintln!(
            "user: exception {code:#010x} at {:#x} could not push user stack frame",
            frame.rip
        );
        crate::ps::user::terminate_current_process(code as NTSTATUS);
    }
    frame.rip = sysdll.ki_user_exception_dispatcher;
    frame.rsp = new_rsp;
    frame.rflags = (frame.rflags & !0x500) | 0x202;
    true
}
