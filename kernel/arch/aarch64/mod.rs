//! arm64.

mod cpu;
mod trap;

pub use cpu::pcr;
pub use trap::{breakpoint, breakpoints};

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
