//! Per-CPU processor state: the processor control region that drivers
//! reach through register x18.
//!
//! Windows reserves x18 in kernel mode for the KPCR, and drivers load
//! from it directly. Rust's UEFI targets never use x18 either, so setting
//! it once per CPU is enough: nothing NK compiles will disturb it.

use crate::ke::percpu::PerCpu;
use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::sync::atomic::{AtomicU8, Ordering};
use nk_bootinfo::{KERNEL_STACK_SIZE, stack_top_in};
use nk_ntabi::pcr::NATIVE as PCR;

const PCR_SIZE: usize = PCR.size;

/// Everything one CPU owns. Page aligned so the PCR is too.
#[repr(C, align(4096))]
struct CpuArea {
    /// KPCR followed by KPRCB; x18 points here.
    pcr: [u8; PCR_SIZE],
    /// Top of this processor's overflow stack. Exception entry loads it
    /// from here, relative to `TPIDR_EL1`, when it finds the stack it
    /// arrived on has overflowed.
    overflow_top: u64,
    /// The current IRQL. Drivers on arm64 ask the kernel for it, so where
    /// it is kept is NK's choice.
    irql: AtomicU8,
    /// State the generic kernel keeps per processor.
    generic: PerCpu,
    /// Stand-in for the current thread object. There are no threads yet,
    /// but `KeGetCurrentThread()` must return a stable non-null pointer.
    thread: [u8; 4096],
    /// Room for one stack at the alignment every kernel stack has.
    overflow_stack: [u8; OVERFLOW_ROOM],
}

const OVERFLOW_ROOM: usize = 3 * KERNEL_STACK_SIZE as usize;
/// Where exception entry finds `overflow_top`, from the PCR.
pub const OVERFLOW_TOP: usize = offset_of!(CpuArea, overflow_top);

struct Shared(UnsafeCell<CpuArea>);

// SAFETY: each CPU touches only its own area; the boot CPU initialises
// this one before anything else can observe it.
unsafe impl Sync for Shared {}

static BOOT_CPU: Shared = Shared(UnsafeCell::new(CpuArea {
    pcr: [0; PCR_SIZE],
    overflow_top: 0,
    irql: AtomicU8::new(0),
    generic: PerCpu::new(),
    thread: [0; 4096],
    overflow_stack: [0; OVERFLOW_ROOM],
}));

/// Point x18 at this CPU's PCR and record that it is processor `number`.
/// Boot CPU only for now.
pub fn init(number: u32) {
    let area = BOOT_CPU.0.get();
    // SAFETY: single-threaded early boot: this is the only reference to
    // the boot CPU's area, which is static, so the pointers stay valid.
    // x18 is reserved on this target; writing it cannot clobber compiler
    // state. TPIDR_EL1 holds the same pointer: it survives whatever a
    // lower exception level does to x18, once there is one.
    unsafe {
        let pcr = (&raw mut (*area).pcr).cast::<u8>();
        pcr.add(PCR.self_ptr).cast::<u64>().write(pcr as u64);
        pcr.add(PCR.current_prcb)
            .cast::<u64>()
            .write(pcr.add(PCR.prcb) as u64);
        pcr.add(PCR.current_thread)
            .cast::<u64>()
            .write((&raw mut (*area).thread) as u64);
        pcr.add(PCR.number).cast::<u32>().write(number);
        // Three stack sizes always hold one aligned stack.
        (*area).overflow_top = stack_top_in(
            (&raw mut (*area).overflow_stack) as u64,
            OVERFLOW_ROOM as u64,
        )
        .unwrap_or(0);
        core::arch::asm!("msr tpidr_el1, {0}", "mov x18, {0}", in(reg) pcr as u64, options(nomem, nostack));
    }
}

/// This CPU's PCR, read back through x18 the way a driver would find it.
pub fn pcr() -> *mut u8 {
    let pcr: u64;
    // SAFETY: x18 points at the PCR once `init` has run; this loads its
    // self pointer.
    unsafe {
        core::arch::asm!("ldr {}, [x18, #{}]", out(reg) pcr, const PCR.self_ptr, options(readonly, nostack))
    };
    pcr as *mut u8
}

/// This processor's area. The PCR is its first field.
fn area() -> &'static CpuArea {
    // SAFETY: x18 holds the address of this processor's `CpuArea`, which
    // lives forever; the fields reached through this reference are only
    // ever accessed through shared references.
    unsafe { &*pcr().cast::<CpuArea>() }
}

/// The generic kernel's state for this processor.
pub fn percpu() -> &'static PerCpu {
    &area().generic
}

/// The current IRQL.
pub fn irql() -> u8 {
    area().irql.load(Ordering::Relaxed)
}

/// Set the IRQL. The caller has checked the change is legal.
pub fn set_irql(level: u8) {
    area().irql.store(level, Ordering::Relaxed);
}
