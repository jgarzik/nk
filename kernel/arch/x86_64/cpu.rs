//! Per-CPU processor state: segment tables, task state segment, and the
//! processor control region that drivers reach through GS.
//!
//! Selector values follow Windows (kernel code 0x10, data 0x18, TSS 0x40).
//! Drivers do not depend on them, but debuggers and crash dumps read more
//! naturally when they match.

use crate::hal::platform::MAX_CPUS;
use crate::ke::percpu::PerCpu;
use crate::mm;
use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use nk_ntabi::pcr::NATIVE as PCR;

const PCR_SIZE: usize = PCR.size;

pub const KERNEL_CODE: u16 = 0x10;
const KERNEL_DATA: u16 = 0x18;
/// Ring 3 32-bit compatibility code selector (required for `IA32_STAR`).
pub const USER_CODE32: u16 = 0x23;
/// Ring 3 data/stack selector (`SS` on `sysretq` and `iretq`).
pub const USER_DATA: u16 = 0x2B;
/// Ring 3 64-bit code selector (`CS` on `sysretq` and `iretq`).
pub const USER_CODE64: u16 = 0x33;
const TSS_SELECTOR: u16 = 0x40;
/// Ring 3 TEB/data selector (matches Windows x64 `0x53`).
pub const USER_TEB: u16 = 0x53;
/// Interrupt-stack-table slot for faults that cannot trust the stack.
pub const FAULT_IST: u8 = 1;
const FAULT_STACK_SIZE: usize = 0x4000;
const MSR_EFER: u32 = 0xC000_0080;
const MSR_STAR: u32 = 0xC000_0081;
const MSR_LSTAR: u32 = 0xC000_0082;
const MSR_SFMASK: u32 = 0xC000_0084;
const MSR_GS_BASE: u32 = 0xC000_0101;
const MSR_KERNEL_GS_BASE: u32 = 0xC000_0102;
const CR4_SMEP: u64 = 1 << 20;
/// `IA32_STAR`: `SYSRET` CS/SS base (`0x23` -> CS=`0x33`, SS=`0x2B`) in bits 63:48,
/// `SYSCALL` CS/SS base (`0x10` -> CS=`0x10`, SS=`0x18`) in bits 47:32.
const STAR_VALUE: u64 = ((USER_CODE32 as u64) << 48) | ((KERNEL_CODE as u64) << 32);
/// `IA32_SFMASK`: clear `NT` (`0x4000`), `DF` (`0x0400`), `IF` (`0x0200`), `TF` (`0x0100`).
const SFMASK_VALUE: u64 = 0x4700;

/// Operand of `lgdt`/`lidt`.
#[repr(C, packed)]
pub struct TablePointer {
    pub limit: u16,
    pub base: u64,
}

/// The 64-bit task state segment. Only the interrupt stacks are used.
#[repr(C, packed)]
struct Tss {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    io_map_base: u16,
}

/// Everything one CPU owns. Page aligned so the PCR is too.
#[repr(C, align(4096))]
struct CpuArea {
    /// KPCR followed by KPRCB; GS points here.
    pcr: [u8; PCR_SIZE],
    /// NK's own per-processor state. No driver can see it.
    private: Private,
    fault_stack: [u8; FAULT_STACK_SIZE],
    gdt: [u64; 12],
    tss: Tss,
}

#[repr(C)]
struct Private {
    /// Top of the current thread's kernel stack, read by `nk_syscall_entry`.
    kernel_rsp0: AtomicU64,
    /// Scratch slot where `nk_syscall_entry` stashes the user RSP before
    /// switching to `kernel_rsp0`.
    user_rsp_scratch: AtomicU64,
    /// Lowest address of the kernel stack this processor is running on,
    /// or 0 while it is still on the loader's.
    stack_base: AtomicU64,
    /// State the generic kernel keeps per processor.
    generic: PerCpu,
}

/// Byte offset from `gs:[0]` (`CpuArea.pcr`) to `Private.kernel_rsp0`.
pub const GS_KERNEL_RSP0: usize = offset_of!(CpuArea, private) + offset_of!(Private, kernel_rsp0);
/// Byte offset from `gs:[0]` (`CpuArea.pcr`) to `Private.user_rsp_scratch`.
pub const GS_USER_RSP: usize = offset_of!(CpuArea, private) + offset_of!(Private, user_rsp_scratch);

struct Shared(UnsafeCell<CpuArea>);

// SAFETY: each CPU touches only its own area; the boot CPU initialises
// this one before anything else can observe it.
unsafe impl Sync for Shared {}

/// The boot processor's area. It is needed before memory can be
/// allocated; every other processor's is allocated.
static BOOT_CPU: Shared = Shared(UnsafeCell::new(CpuArea {
    pcr: [0; PCR_SIZE],
    private: Private {
        kernel_rsp0: AtomicU64::new(0),
        user_rsp_scratch: AtomicU64::new(0),
        stack_base: AtomicU64::new(0),
        generic: PerCpu::new(),
    },
    fault_stack: [0; FAULT_STACK_SIZE],
    gdt: [0; 12],
    tss: Tss {
        reserved0: 0,
        rsp: [0; 3],
        reserved1: 0,
        ist: [0; 7],
        reserved2: 0,
        reserved3: 0,
        io_map_base: size_of::<Tss>() as u16,
    },
}));

/// Each processor's area, by processor number; null until it has one.
static AREAS: [AtomicPtr<CpuArea>; MAX_CPUS] =
    [const { AtomicPtr::new(core::ptr::null_mut()) }; MAX_CPUS];

/// Allocate and record the area of processor `number`, which is about to
/// be started. `false` if memory ran out.
pub fn prepare(number: usize) -> bool {
    let pages = size_of::<CpuArea>().div_ceil(mm::PAGE_SIZE);
    let Some(frames) = mm::alloc_frames(pages) else {
        return false;
    };
    let area = mm::phys_to_virt(frames).cast::<CpuArea>();
    // SAFETY: fresh, zeroed, page-aligned memory of the right size that
    // nothing else references. Zero is a valid value for every field but
    // the two written here.
    unsafe {
        (&raw mut (*area).private).write(Private {
            kernel_rsp0: AtomicU64::new(0),
            user_rsp_scratch: AtomicU64::new(0),
            stack_base: AtomicU64::new(0),
            generic: PerCpu::new(),
        });
        (&raw mut (*area).tss.io_map_base).write_unaligned(size_of::<Tss>() as u16);
    }
    AREAS[number].store(area, Ordering::Release);
    true
}

/// The generic kernel's state for processor `number`, if it has been
/// prepared.
pub fn percpu_of(number: usize) -> Option<&'static PerCpu> {
    let area = AREAS.get(number)?.load(Ordering::Acquire);
    // SAFETY: a recorded area lives forever, and `generic` is only ever
    // accessed through shared references.
    (!area.is_null()).then(|| unsafe { &(*area).private.generic })
}

/// Load this CPU's GDT, TSS and PCR, and record that it is processor
/// `number`. Processor 0 uses the static area; any other must have been
/// `prepare`d.
pub fn init(number: u32) {
    let area = if number == 0 {
        AREAS[0].store(BOOT_CPU.0.get(), Ordering::Release);
        BOOT_CPU.0.get()
    } else {
        AREAS[number as usize].load(Ordering::Acquire)
    };
    assert!(!area.is_null(), "processor {number} has no area");
    // SAFETY: only this processor touches its area during its own
    // set-up, and the pointers written stay valid for ever: the area is
    // never freed.
    unsafe {
        let pcr = (&raw mut (*area).pcr).cast::<u8>();
        let tss = &raw mut (*area).tss;
        (*tss).ist[usize::from(FAULT_IST) - 1] =
            (&raw mut (*area).fault_stack) as u64 + FAULT_STACK_SIZE as u64;

        let tss_base = tss as u64;
        let gdt = &mut (*area).gdt;
        gdt[usize::from(KERNEL_CODE) / 8] = 0x0020_9B00_0000_0000; // 0x10: 64-bit code, ring 0
        gdt[usize::from(KERNEL_DATA) / 8] = 0x0000_9300_0000_0000; // 0x18: data, ring 0
        gdt[usize::from(USER_CODE32 & !3) / 8] = 0x00CF_FB00_0000_FFFF; // 0x20: 32-bit code, ring 3
        gdt[usize::from(USER_DATA & !3) / 8] = 0x00CF_F300_0000_FFFF; // 0x28: data, ring 3
        gdt[usize::from(USER_CODE64 & !3) / 8] = 0x0020_FB00_0000_0000; // 0x30: 64-bit code, ring 3
        gdt[usize::from(TSS_SELECTOR) / 8] = (size_of::<Tss>() as u64 - 1)
            | (tss_base & 0xFF_FFFF) << 16
            | 0x89 << 40 // present, available 64-bit TSS
            | (tss_base >> 24 & 0xFF) << 56;
        gdt[usize::from(TSS_SELECTOR) / 8 + 1] = tss_base >> 32;
        gdt[usize::from(USER_TEB & !3) / 8] = 0x00CF_F300_0000_FFFF; // 0x50: TEB/data, ring 3

        pcr.add(PCR.self_ptr).cast::<u64>().write(pcr as u64);
        pcr.add(PCR.current_prcb)
            .cast::<u64>()
            .write(pcr.add(PCR.prcb) as u64);
        pcr.add(PCR.number).cast::<u32>().write(number);
        if let Some(legacy) = PCR.legacy_number {
            // One byte: enough for the 64 processors of a group.
            pcr.add(legacy).write(number as u8);
        }

        // Drivers use SSE, and the trap entry saves it: make sure it is
        // on. CR0: no emulation, monitor the coprocessor, no lazy
        // switching. CR4: PGE (global kernel pages survive CR3 switches),
        // FXSAVE, and SSE exceptions enabled.
        core::arch::asm!(
            "mov {t}, cr0",
            "and {t}, {cr0_clear}",
            "or {t}, 2",
            "mov cr0, {t}",
            "mov {t}, cr4",
            "or {t}, 0x680",
            "mov cr4, {t}",
            t = out(reg) _,
            cr0_clear = const !0xCu64,
            options(nomem, nostack),
        );
        super::xstate::detect_and_enable(number == 0);
        if super::xstate::has_smep() {
            core::arch::asm!(
                "mov {t}, cr4",
                "or {t}, {smep}",
                "mov cr4, {t}",
                t = out(reg) _,
                smep = const CR4_SMEP,
                options(nomem, nostack),
            );
        }

        let pointer = TablePointer {
            limit: (size_of::<[u64; 12]>() - 1) as u16,
            base: gdt.as_ptr() as u64,
        };
        // Load the GDT, reload CS with a far return, then the data
        // segments and the task register. Loading GS clears its base, so
        // the PCR base is written last. CR8 = 0 is IRQL PASSIVE_LEVEL.
        core::arch::asm!(
            "lgdt [{ptr}]",
            "push {code}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {data:x}",
            "mov es, {data:x}",
            "mov ss, {data:x}",
            "xor {tmp:e}, {tmp:e}",
            "mov fs, {tmp:x}",
            "mov gs, {tmp:x}",
            "ltr {tss:x}",
            "mov cr8, {tmp}",
            ptr = in(reg) &raw const pointer,
            code = in(reg) u64::from(KERNEL_CODE),
            data = in(reg) u64::from(KERNEL_DATA),
            tss = in(reg) u64::from(TSS_SELECTOR),
            tmp = out(reg) _,
        );
        core::arch::asm!(
            "wrmsr",
            in("ecx") MSR_GS_BASE,
            in("eax") pcr as u64 as u32,
            in("edx") (pcr as u64 >> 32) as u32,
            options(nomem, nostack),
        );
        // Enable SYSCALL/SYSRET (`IA32_EFER.SCE`) and programme STAR, LSTAR,
        // SFMASK, and an initial zero user GS base (`IA32_KERNEL_GS_BASE`).
        let (efer_lo, efer_hi): (u32, u32);
        core::arch::asm!(
            "rdmsr",
            in("ecx") MSR_EFER,
            out("eax") efer_lo,
            out("edx") efer_hi,
            options(nomem, nostack),
        );
        core::arch::asm!(
            "wrmsr",
            in("ecx") MSR_EFER,
            in("eax") efer_lo | 1,
            in("edx") efer_hi,
            options(nomem, nostack),
        );
        core::arch::asm!(
            "wrmsr",
            in("ecx") MSR_STAR,
            in("eax") STAR_VALUE as u32,
            in("edx") (STAR_VALUE >> 32) as u32,
            options(nomem, nostack),
        );
        let lstar = super::user::syscall_entry_addr();
        core::arch::asm!(
            "wrmsr",
            in("ecx") MSR_LSTAR,
            in("eax") lstar as u32,
            in("edx") (lstar >> 32) as u32,
            options(nomem, nostack),
        );
        core::arch::asm!(
            "wrmsr",
            in("ecx") MSR_SFMASK,
            in("eax") SFMASK_VALUE as u32,
            in("edx") (SFMASK_VALUE >> 32) as u32,
            options(nomem, nostack),
        );
        core::arch::asm!(
            "wrmsr",
            in("ecx") MSR_KERNEL_GS_BASE,
            in("eax") 0u32,
            in("edx") 0u32,
            options(nomem, nostack),
        );
    }
}

/// This CPU's PCR, read back through GS the way a driver would find it.
pub fn pcr() -> *mut u8 {
    let pcr: u64;
    // SAFETY: GS points at the PCR once `init` has run; this loads its
    // self pointer.
    unsafe {
        core::arch::asm!("mov {}, gs:[{}]", out(reg) pcr, const PCR.self_ptr, options(readonly, nostack))
    };
    pcr as *mut u8
}

/// The thread running on this processor, loaded from the PCR in one
/// instruction, as a driver's in-line `KeGetCurrentThread()` does: the
/// thread cannot be moved between finding the PCR and reading it.
pub fn current_thread() -> *mut u8 {
    let thread: u64;
    // SAFETY: GS points at this processor's PCR once `init` has run.
    unsafe {
        core::arch::asm!("mov {}, gs:[{}]", out(reg) thread, const PCR.current_thread, options(readonly, nostack));
    }
    thread as *mut u8
}

/// This CPU's private state.
fn private() -> &'static Private {
    // SAFETY: the PCR is the first field of this CPU's `CpuArea`, which
    // lives forever; `Private` is only ever accessed through shared
    // references and holds atomics.
    unsafe { &*pcr().add(offset_of!(CpuArea, private)).cast::<Private>() }
}

/// Record the kernel stack this processor now runs on: `base` for the
/// overflow check, and `top` in `TSS.RSP0` and `Private.kernel_rsp0` so
/// Ring 3 interrupts, exceptions, and `syscall` land on this thread's stack.
pub fn set_kernel_stack(base: u64, top: u64) {
    let priv_ = private();
    priv_.stack_base.store(base, Ordering::Relaxed);
    priv_.kernel_rsp0.store(top, Ordering::Relaxed);
    let area = pcr().cast::<CpuArea>();
    // SAFETY: `pcr()` is the first field of this CPU's `CpuArea`, which lives
    // forever; only this processor writes its own `TSS.RSP0`.
    unsafe {
        (&raw mut (*area).tss.rsp[0]).write_unaligned(top);
    }
}

/// Set the user-mode GS base (`IA32_KERNEL_GS_BASE`), swapped into `GS_BASE`
/// by `swapgs` on return to Ring 3 (points to the user thread's `TEB`).
pub fn set_user_gs_base(base: u64) {
    // SAFETY: writing `IA32_KERNEL_GS_BASE` only affects the swapped-out GS
    // base visible after `swapgs`.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") MSR_KERNEL_GS_BASE,
            in("eax") base as u32,
            in("edx") (base >> 32) as u32,
            options(nomem, nostack),
        );
    }
}

/// Read the current user-mode GS base (`IA32_KERNEL_GS_BASE`).
#[allow(dead_code)]
pub fn user_gs_base() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: reading `IA32_KERNEL_GS_BASE` has no side effects.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") MSR_KERNEL_GS_BASE,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack),
        );
    }
    u64::from(lo) | (u64::from(hi) << 32)
}

/// Lowest address of the current kernel stack, or 0 if not recorded.
pub fn kernel_stack() -> u64 {
    private().stack_base.load(Ordering::Relaxed)
}

/// The generic kernel's state for this processor.
pub fn percpu() -> &'static PerCpu {
    &private().generic
}

/// The current IRQL. On x86-64 it is register CR8, the task priority,
/// which is where code built with the WDK reads it.
pub fn irql() -> u8 {
    let level: u64;
    // SAFETY: reading CR8 has no side effects.
    unsafe { core::arch::asm!("mov {}, cr8", out(reg) level, options(nomem, nostack)) };
    level as u8
}

/// Set the IRQL. The caller has checked the change is legal. Not
/// `nomem`: what is done at a raised IRQL (a lock's record, a
/// processor's own state) must not be moved across the change by the
/// compiler.
pub fn set_irql(level: u8) {
    // SAFETY: CR8 only holds the task priority; any value up to 15 is
    // valid.
    unsafe { core::arch::asm!("mov cr8, {}", in(reg) u64::from(level), options(nostack)) };
}
