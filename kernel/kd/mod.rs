//! Diagnostics: the serial console and the panic path.

use crate::arch::{self, Uart};
use crate::ke::SpinLock;
use core::fmt;
use nk_bootinfo::BootInfo;

static CONSOLE: SpinLock<Option<Uart>> = SpinLock::new(None);

pub fn console_init(info: &BootInfo) {
    *CONSOLE.lock() = Uart::new(info);
}

struct Writer<'a>(&'a Uart);

impl fmt::Write for Writer<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.0.put(b'\r');
            }
            self.0.put(b);
        }
        Ok(())
    }
}

pub fn print(args: fmt::Arguments<'_>) {
    if let Some(uart) = CONSOLE.lock().as_ref() {
        let _ = fmt::Write::write_fmt(&mut Writer(uart), args);
    }
}

/// Print a line on the diagnostic console.
macro_rules! kprintln {
    ($($arg:tt)*) => {
        $crate::kd::print(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// A Rust panic is a kernel bug. Say so on the console in a form the boot
/// test recognises, then stop.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    // The panic may have happened while printing: take the console anyway.
    if let Some(uart) = CONSOLE.force_lock().as_ref() {
        let _ = fmt::Write::write_fmt(&mut Writer(uart), format_args!("\nKERNEL PANIC: {info}\n"));
    }
    crate::hal::power_off_or_halt()
}

/// Halt after a fatal error when even power-off is unavailable.
pub fn halt() -> ! {
    arch::halt()
}
