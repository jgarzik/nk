//! Per-CPU processor state: the processor control region that drivers
//! reach through register x18.
//!
//! Windows reserves x18 in kernel mode for the KPCR, and drivers load
//! from it directly. Rust's UEFI targets never use x18 either, so setting
//! it once per CPU is enough: nothing NK compiles will disturb it.

use crate::hal::platform::MAX_CPUS;
use crate::ke::percpu::PerCpu;
use crate::mm;
use core::cell::UnsafeCell;
use core::mem::offset_of;
use core::sync::atomic::{AtomicPtr, AtomicU8, Ordering};
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

/// The boot processor's area. It is needed before memory can be
/// allocated; every other processor's is allocated.
static BOOT_CPU: Shared = Shared(UnsafeCell::new(CpuArea {
    pcr: [0; PCR_SIZE],
    overflow_top: 0,
    irql: AtomicU8::new(0),
    generic: PerCpu::new(),
    overflow_stack: [0; OVERFLOW_ROOM],
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
    // nothing else references. Zero is a valid value for every other
    // field.
    unsafe { (&raw mut (*area).generic).write(PerCpu::new()) };
    AREAS[number].store(area, Ordering::Release);
    true
}

/// The generic kernel's state for processor `number`, if it has been
/// prepared.
pub fn percpu_of(number: usize) -> Option<&'static PerCpu> {
    let area = AREAS.get(number)?.load(Ordering::Acquire);
    // SAFETY: a recorded area lives forever, and `generic` is only ever
    // accessed through shared references.
    (!area.is_null()).then(|| unsafe { &(*area).generic })
}

/// Point x18 at this CPU's PCR and record that it is processor `number`.
/// Processor 0 uses the static area; any other must have been
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
    // set-up, and the area is never freed, so the pointers stay valid.
    // x18 is reserved on this target; writing it cannot clobber compiler
    // state. TPIDR_EL1 holds the same pointer: it survives whatever a
    // lower exception level does to x18, once there is one.
    unsafe {
        let pcr = (&raw mut (*area).pcr).cast::<u8>();
        pcr.add(PCR.self_ptr).cast::<u64>().write(pcr as u64);
        pcr.add(PCR.current_prcb)
            .cast::<u64>()
            .write(pcr.add(PCR.prcb) as u64);
        pcr.add(PCR.number).cast::<u32>().write(number);
        // Three stack sizes always hold one aligned stack.
        (*area).overflow_top = stack_top_in(
            (&raw mut (*area).overflow_stack) as u64,
            OVERFLOW_ROOM as u64,
        )
        .unwrap_or(0);
        // The IRQL is enforced through the GIC's system registers, and
        // the first lock taken sets it.
        super::gic::enable_system_registers();
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

/// Set the IRQL: record it, and have the interrupt controller hold back
/// everything at or below it. The caller has checked the change is legal.
pub fn set_irql(level: u8) {
    area().irql.store(level, Ordering::Relaxed);
    super::gic::set_mask(level);
}
