//! x86-64 Ring 3 transition: `SYSCALL`/`SYSRETQ` entry and exit, initial
//! Ring 3 entry (`iretq`), and user-mode exception interception.

use super::cpu::{GS_KERNEL_RSP0, GS_USER_RSP, USER_CODE64, USER_DATA};
use super::trap::Frame;
use crate::ke::thread;
use crate::svc::{self, MAX_SYSCALL_ARGS};
use core::arch::global_asm;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use nk_ntabi::io::{KERNEL_MODE, USER_MODE};
use nk_ntabi::seh::x64::{KEXCEPTION_FRAME, KTRAP_FRAME};
use nk_ntabi::status::{
    NTSTATUS, STATUS_ACCESS_VIOLATION, STATUS_INVALID_SYSTEM_SERVICE, STATUS_PRIVILEGED_INSTRUCTION,
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

/// C-ABI system-call dispatcher invoked from `nk_syscall_entry`.
/// Returns `0` for fast `sysretq`, or `1` to return via full `iretq`.
extern "C" fn syscall_dispatch(tf: &mut KTRAP_FRAME, _ef: &mut KEXCEPTION_FRAME) -> u8 {
    let nr = tf.Rax as u32;
    let me = thread::current();
    // SAFETY: `me` is the running thread; save and update its syscall metadata
    // and trap frame pointer around service dispatch.
    let (old_tf, old_mode) = unsafe {
        let tf_slot = thread::object_field::<u64>(me, thread_layout::TRAP_FRAME);
        let old_tf = tf_slot.read();
        tf_slot.write(core::ptr::from_mut(tf).addr() as u64);
        thread::object_field::<u32>(me, thread_layout::SYSTEM_CALL_NUMBER).write(nr);
        thread::object_field::<u64>(me, thread_layout::FIRST_ARGUMENT).write(tf.Rcx);
        let old_mode = thread::set_previous_mode(USER_MODE);
        (old_tf, old_mode)
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

    tf.Rax = u64::from(status as u32);
    // SAFETY: `me` is still the running thread; restore prior mode and trap frame.
    unsafe {
        thread::set_previous_mode(if old_mode == USER_MODE {
            KERNEL_MODE
        } else {
            old_mode
        });
        thread::object_field::<u64>(me, thread_layout::TRAP_FRAME).write(old_tf);
    }
    0
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

/// Handle a Ring 3 exception before Stage 3C wires `KiUserExceptionDispatcher`.
/// Returns `true` if handled (or terminates the faulting user thread directly).
pub fn handle_user_exception(frame: &mut Frame, code: u32, parameters: &[u64]) -> bool {
    if OBSERVER_ARMED.load(Ordering::Acquire) {
        OBSERVER_CODE.store(code, Ordering::Relaxed);
        OBSERVER_RIP.store(frame.rip, Ordering::Relaxed);
        OBSERVER_INFO0.store(parameters.first().copied().unwrap_or(0), Ordering::Relaxed);
        OBSERVER_INFO1.store(parameters.get(1).copied().unwrap_or(0), Ordering::Relaxed);
        OBSERVER_ARMED.store(false, Ordering::Release);
        // Re-enable interrupts before terminating the faulting user thread.
        super::enable_interrupts();
        thread::exit();
    }
    false
}
