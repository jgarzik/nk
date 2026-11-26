//! Diagnostics: the serial console and the panic path.

pub mod debugger;
pub mod variables;

use crate::arch::{self, Uart};
use crate::ke::{Rank, SpinLock};
use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use nk_bootinfo::BootInfo;

static CONSOLE: SpinLock<Option<Uart>> = SpinLock::new(Rank::Console, None);

pub fn console_init(info: &BootInfo) {
    *CONSOLE.lock() = Uart::new(info);
    variables::init(info);
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

/// A breakpoint instruction was executed at `address`. Returns whether
/// execution is to go on past it.
///
/// A driver that executes one (`DbgBreakPoint`) gets what Windows gives
/// it. A debugger, when one is attached, is asked first and decides;
/// NK's stands for one that always says go. With no debugger the
/// breakpoint is an exception like any other, for the code's own
/// handlers, and stops the system if none takes it.
pub fn breakpoint(address: u64) -> bool {
    if EXPECTED_BREAKPOINT.load(Ordering::Relaxed) {
        return true;
    }
    if DEBUGGER.load(Ordering::Relaxed) {
        print(format_args!(
            "kd: breakpoint at {address:#018x}; the debugger says go\n"
        ));
        return true;
    }
    false
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
    // What the stopping processor prints, a driver's bugcheck callback
    // included, goes out whoever held the console.
    if stopping_here() {
        return print_forced(args);
    }
    if let Some(uart) = CONSOLE.lock().as_ref() {
        let _ = fmt::Write::write_fmt(&mut Writer(uart), args);
    }
}

/// Print on the way to stopping the system: the error may have struck
/// while printing, so the console is taken anyway.
fn print_forced(args: fmt::Arguments<'_>) {
    if let Some(uart) = CONSOLE.force_lock().as_ref() {
        let _ = fmt::Write::write_fmt(&mut Writer(uart), args);
    }
}

/// Print a line on the diagnostic console.
macro_rules! kprintln {
    ($($arg:tt)*) => {
        $crate::kd::print(format_args!("{}\n", format_args!($($arg)*)))
    };
}

/// The processor that is stopping the system, as its number plus one;
/// zero while nothing is.
static STOPPER: AtomicU32 = AtomicU32::new(0);

/// Whether this processor is the one stopping the system.
fn stopping_here() -> bool {
    let stopper = STOPPER.load(Ordering::SeqCst);
    stopper != 0 && stopper == crate::ke::pcr::current_processor() + 1
}

/// Stop the system on an unrecoverable error: print `BUGCHECK: <why>` in
/// a form the boot test recognises, then power off.
pub fn bugcheck(why: fmt::Arguments<'_>) -> ! {
    stop(None, why)
}

/// Stop the system with a Windows bugcheck code and its four
/// parameters, which `KiBugCheckData` then holds for the drivers'
/// bugcheck callbacks.
pub fn bugcheck_with(data: [usize; 5], why: fmt::Arguments<'_>) -> ! {
    stop(Some(data), why)
}

/// Stop the other processors, report, call the drivers' bugcheck
/// callbacks (`ke::bugcheck`), power off. The report comes first, as
/// Windows' screen does: a callback that goes wrong cannot lose it.
fn stop(data: Option<[usize; 5]>, why: fmt::Arguments<'_>) -> ! {
    // From here this processor is where it is, and nothing interrupts.
    arch::set_irql(crate::ke::irql::HIGH_LEVEL);
    let here = crate::ke::pcr::current_processor() + 1;
    match STOPPER.compare_exchange(0, here, Ordering::SeqCst, Ordering::SeqCst) {
        Ok(_) => {}
        // A second error on the processor that is stopping the system,
        // in a bugcheck callback for one: the first is reported already,
        // and nothing more is called.
        Err(stopper) if stopper == here => {
            print_forced(format_args!("\na second error while stopping: {why}\n"));
            crate::hal::power_off_or_halt()
        }
        // One processor reports; any other that gets here just stops.
        Err(_) => arch::halt(),
    }
    if crate::ke::smp::online_count() > 1 {
        arch::stop_others();
    }
    if let Some(data) = data {
        crate::ke::bugcheck::record(data);
    }
    print_forced(format_args!("\nBUGCHECK: {why}\n"));
    // SAFETY: this processor alone runs, at HIGH_LEVEL, and gets here
    // once.
    unsafe { crate::ke::bugcheck::run_callbacks() };
    crate::hal::power_off_or_halt()
}

/// Whether the system is being stopped.
pub fn stopping() -> bool {
    STOPPER.load(Ordering::SeqCst) != 0
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
