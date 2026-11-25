//! x86-64.

mod cpu;
pub mod platform;
mod trap;

pub use cpu::pcr;
pub use trap::{breakpoint, breakpoints};

use nk_bootinfo::{BootInfo, Serial};

pub const NAME: &str = "x86_64";

fn outb(port: u16, value: u8) {
    // SAFETY: only called on the diagnostic UART's ports, where a byte
    // write has no memory-safety effect.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack))
    }
}

fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: as in `outb`; reading a UART status port is side-effect free.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack))
    }
    value
}

/// The diagnostic UART: a 16550 on I/O ports, as firmware left it set up.
pub struct Uart {
    port: u16,
}

impl Uart {
    pub fn new(info: &BootInfo) -> Option<Self> {
        (info.serial.kind == Serial::PORT_16550).then_some(Self {
            port: info.serial.base as u16,
        })
    }

    pub fn put(&self, byte: u8) {
        const LINE_STATUS: u16 = 5;
        const TX_EMPTY: u8 = 0x20;
        while inb(self.port + LINE_STATUS) & TX_EMPTY == 0 {
            core::hint::spin_loop();
        }
        outb(self.port, byte);
    }
}

/// Stop this CPU for good.
pub fn halt() -> ! {
    loop {
        // SAFETY: disabling interrupts and halting touches no memory.
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) }
    }
}

/// Take over the boot CPU: descriptor tables, exception vectors, PCR.
pub fn cpu_init() {
    cpu::init();
    trap::init(cpu::KERNEL_CODE, cpu::FAULT_IST);
}

pub fn mm_init(_info: &BootInfo) {}

/// Page-table entry encoding for this CPU.
pub fn pt_arch() -> nk_mm::pt::X86_64 {
    nk_mm::pt::X86_64
}

/// Physical address of the root page table.
pub fn pt_root() -> u64 {
    let cr3: u64;
    // SAFETY: reading CR3 has no side effects.
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack)) };
    cr3 & 0x000F_FFFF_FFFF_F000
}

/// Drop any cached translation for the page at `va` on this CPU.
pub fn flush_tlb_page(va: u64) {
    // SAFETY: invlpg only discards a TLB entry.
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack)) };
}

/// Make new mappings visible. x86 needs nothing after adding an entry.
pub fn mapping_sync() {}

/// A fast-changing counter, used only to vary stack-protector cookies.
pub fn cycle_counter() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: rdtsc reads a counter and touches no memory.
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    u64::from(hi) << 32 | u64::from(lo)
}

/// Make freshly written code executable. x86 keeps instruction and data
/// caches coherent by itself.
pub fn sync_icache(_start: *const u8, _len: usize) {}
