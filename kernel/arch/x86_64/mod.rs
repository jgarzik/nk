//! x86-64.

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
