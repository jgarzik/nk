//! arm64.

mod clock;
mod cpu;
mod gic;
pub mod platform;
mod trap;

pub use gic::{
    TEST_HIGH, TEST_LOW, TEST_STRAY, disable_interrupts, enable_interrupts,
    init as interrupts_init, interrupt_enable, self_interrupt,
};

pub use cpu::{irql, pcr, percpu, set_irql};
pub use trap::{breakpoint, breakpoints, fp_trap_test};

use core::sync::atomic::{AtomicU8, Ordering};
use nk_bootinfo::{BootInfo, Serial};

pub const NAME: &str = "aarch64";

/// The diagnostic UART: an ARM PL011, as firmware left it set up.
pub struct Uart {
    base: *mut u32,
}

// SAFETY: the pointer names device registers, not shared Rust data; all
// access is volatile and serialised by the console lock.
unsafe impl Send for Uart {}

impl Uart {
    pub fn new(info: &BootInfo) -> Option<Self> {
        let base = (info.hhdm_base + info.serial.base) as *mut u32;
        (info.serial.kind == Serial::MMIO_PL011).then_some(Self { base })
    }

    pub fn put(&self, byte: u8) {
        const FLAGS: usize = 0x18 / 4;
        const TX_FULL: u32 = 1 << 5;
        // SAFETY: `base` is the PL011 register block, mapped as device
        // memory in the direct map; these are its data and flag registers.
        unsafe {
            while self.base.add(FLAGS).read_volatile() & TX_FULL != 0 {
                core::hint::spin_loop();
            }
            self.base.write_volatile(u32::from(byte));
        }
    }
}

/// Stop this CPU for good.
pub fn halt() -> ! {
    loop {
        // SAFETY: masking interrupts and waiting touches no memory.
        unsafe { core::arch::asm!("msr daifset, #0xf", "wfi", options(nomem, nostack)) }
    }
}

/// Continue on a new stack: call `entry(info)` with the stack pointer at
/// `top`. Whatever was on the old stack is abandoned.
pub fn switch_stack(
    top: u64,
    entry: extern "C" fn(&'static BootInfo) -> !,
    info: &'static BootInfo,
) -> ! {
    // SAFETY: `top` is the top of a mapped stack nothing else uses, 16-byte
    // aligned; with no frame or return address the entry starts a fresh
    // call chain.
    unsafe {
        core::arch::asm!(
            "mov sp, {top}",
            "mov x29, xzr",
            "mov x30, xzr",
            "br {entry}",
            top = in(reg) top,
            entry = in(reg) entry,
            in("x0") info,
            options(noreturn),
        )
    }
}

/// Record the kernel stack this processor now runs on. Nothing to do
/// here: exception entry recognises an overflow from the stack pointer.
pub fn set_kernel_stack(_base: u64) {}

/// Take over the boot CPU, processor 0: exception vectors, PCR. Prints
/// nothing and takes no lock: it runs before either works.
pub fn cpu_init() {
    trap::init();
    cpu::init(0);
}

/// Indices into firmware's `MAIR_EL1`, which the loader looked up.
static MAIR_NORMAL: AtomicU8 = AtomicU8::new(0);
static MAIR_DEVICE: AtomicU8 = AtomicU8::new(0);

pub fn mm_init(info: &BootInfo) {
    MAIR_NORMAL.store(info.mair_normal, Ordering::Relaxed);
    MAIR_DEVICE.store(info.mair_device, Ordering::Relaxed);
}

/// Page-table entry encoding for this CPU.
pub fn pt_arch() -> nk_mm::pt::Aarch64 {
    nk_mm::pt::Aarch64 {
        mair_normal: MAIR_NORMAL.load(Ordering::Relaxed),
        mair_device: MAIR_DEVICE.load(Ordering::Relaxed),
    }
}

/// Physical address of the root of the kernel (TTBR1) page tables.
pub fn pt_root() -> u64 {
    let ttbr: u64;
    // SAFETY: reading TTBR1_EL1 has no side effects.
    unsafe { core::arch::asm!("mrs {}, ttbr1_el1", out(reg) ttbr, options(nomem, nostack)) };
    ttbr & 0x0000_FFFF_FFFF_F000
}

/// Drop any cached translation for the page at `va`.
pub fn flush_tlb_page(va: u64) {
    // SAFETY: TLB invalidation only discards cached translations.
    unsafe {
        core::arch::asm!("tlbi vaae1is, {}", "dsb ish", "isb", in(reg) va >> 12, options(nostack));
    }
}

/// Make new mappings visible: a table write must be synchronised before
/// the mapping is used.
pub fn mapping_sync() {
    // SAFETY: barriers have no memory-safety effect.
    unsafe { core::arch::asm!("dsb ishst", "isb", options(nostack)) };
}

pub use clock::{CLOCK, calibrate as clock_calibrate, next as clock_next};

/// Start the clock interrupt, every `period` counter ticks.
pub fn clock_start(period: u64) {
    clock::start(period, crate::ke::time::frequency());
}

/// The time counter: the generic timer's virtual count.
pub fn counter() -> u64 {
    let count: u64;
    // SAFETY: reading the virtual counter touches no memory.
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) count, options(nomem, nostack)) };
    count
}

/// Make freshly written code executable: clean the data cache to the
/// point of unification for the written range, then drop every cached
/// instruction (the code will run from a different virtual address than
/// it was written through).
pub fn sync_icache(start: *const u8, len: usize) {
    // The smallest cache line the architecture allows; a larger real line
    // just means some redundant operations.
    const LINE: usize = 16;
    let end = start as usize + len;
    let mut addr = start as usize & !(LINE - 1);
    while addr < end {
        // SAFETY: cache maintenance on a mapped address has no
        // memory-safety effect.
        unsafe { core::arch::asm!("dc cvau, {}", in(reg) addr, options(nostack)) };
        addr += LINE;
    }
    // SAFETY: as above.
    unsafe { core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb", options(nostack)) };
}
