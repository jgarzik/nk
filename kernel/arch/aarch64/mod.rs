//! arm64.

mod cpu;
pub mod platform;
mod trap;

pub use cpu::pcr;
pub use trap::{breakpoint, breakpoints};

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

/// Take over the boot CPU: exception vectors, PCR.
pub fn cpu_init() {
    trap::init();
    cpu::init();
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

/// A fast-changing counter, used only to vary stack-protector cookies.
pub fn cycle_counter() -> u64 {
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
