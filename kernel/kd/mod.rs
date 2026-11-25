//! Diagnostics: the serial console and the panic path.

use crate::arch::{self, Uart};
use crate::ke::{Rank, SpinLock};
use core::fmt;
use core::sync::atomic::{AtomicBool, Ordering};
use nk_bootinfo::BootInfo;

static CONSOLE: SpinLock<Option<Uart>> = SpinLock::new(Rank::Console, None);

pub fn console_init(info: &BootInfo) {
    *CONSOLE.lock() = Uart::new(info);
    DEBUGGER.store(info.option("debug") == Some("on"), Ordering::Relaxed);
}

/// A kernel debugger is attached and tells the kernel to go on at every
/// breakpoint: what Windows is like booted with debugging enabled and a
/// debugger answering. Set by `debug=on` on the command line.
static DEBUGGER: AtomicBool = AtomicBool::new(false);
/// The kernel's own tests are about to execute a breakpoint on purpose.
static EXPECTED_BREAKPOINT: AtomicBool = AtomicBool::new(false);

/// Whether a debugger that says go is taken to be attached.
pub fn debugger_attached() -> bool {
    DEBUGGER.load(Ordering::Relaxed)
}

/// Say that the breakpoint about to be executed is the kernel's own.
pub fn expect_breakpoint(expected: bool) {
    EXPECTED_BREAKPOINT.store(expected, Ordering::Relaxed);
}

/// A breakpoint instruction was executed at `address`. Returns if
/// execution is to go on past it.
///
/// A driver that executes one (`DbgBreakPoint`) gets what Windows gives
/// it. With no debugger the exception is nobody's to handle, and in a
/// system thread, which is all NK has, that stops the system. With a
/// debugger attached the debugger decides, and NK's stands for one that
/// always says go.
pub fn breakpoint(address: u64) {
    if EXPECTED_BREAKPOINT.load(Ordering::Relaxed) {
        return;
    }
    if DEBUGGER.load(Ordering::Relaxed) {
        print(format_args!(
            "kd: breakpoint at {address:#018x}; the debugger says go\n"
        ));
        return;
    }
    bugcheck(format_args!(
        "0x0000007E SYSTEM_THREAD_EXCEPTION_NOT_HANDLED: 0x80000003 (a breakpoint, and no \
         debugger to take it) at {address:#018x}"
    ));
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

/// Set by the first processor to stop the system.
static STOPPING: AtomicBool = AtomicBool::new(false);

/// Stop the system on an unrecoverable error: print `BUGCHECK: <why>` in
/// a form the boot test recognises, then power off.
pub fn bugcheck(why: fmt::Arguments<'_>) -> ! {
    // One processor reports; any other that gets here just stops.
    if STOPPING.swap(true, Ordering::SeqCst) {
        arch::halt();
    }
    if crate::ke::smp::online_count() > 1 {
        arch::stop_others();
    }
    // The error may have struck while printing: take the console anyway.
    if let Some(uart) = CONSOLE.force_lock().as_ref() {
        let _ = fmt::Write::write_fmt(&mut Writer(uart), format_args!("\nBUGCHECK: {why}\n"));
    }
    crate::hal::power_off_or_halt()
}

/// Whether the system is being stopped.
pub fn stopping() -> bool {
    STOPPING.load(Ordering::SeqCst)
}

/// Report that a driver broke a rule Windows itself does not enforce.
/// The driver carries on, as it would on Windows; the test harness fails
/// any boot that prints one of these.
pub fn verify(what: fmt::Arguments<'_>) {
    print(format_args!("NK-VERIFY {what}\n"));
}

/// A Rust panic is a kernel bug, reported like any other fatal error.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    bugcheck(format_args!("KERNEL PANIC: {info}"))
}

/// Halt after a fatal error when even power-off is unavailable.
pub fn halt() -> ! {
    arch::halt()
}
