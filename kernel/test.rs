//! Boot self-test reporting.
//!
//! The kernel's tests run at boot and report on the serial console in a
//! fixed, machine-readable form that `tools/boot_test.py` checks:
//!
//! ```text
//! NK-TEST <name>:OK
//! NK-TEST <name>:FAIL <why>
//! NK-TEST <name>:SKIP <why>
//! NK-TEST-COMPLETE pass=<n> fail=<n> skip=<n>
//! ```

use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};
use nk_bootinfo::BootInfo;

static PASS: AtomicU32 = AtomicU32::new(0);
static FAIL: AtomicU32 = AtomicU32::new(0);
static SKIP: AtomicU32 = AtomicU32::new(0);

pub fn ok(name: &str) {
    PASS.fetch_add(1, Ordering::Relaxed);
    kprintln!("NK-TEST {name}:OK");
}

pub fn fail(name: &str, why: fmt::Arguments<'_>) {
    FAIL.fetch_add(1, Ordering::Relaxed);
    kprintln!("NK-TEST {name}:FAIL {why}");
}

#[expect(dead_code, reason = "first used when a fixture can be absent")]
pub fn skip(name: &str, why: fmt::Arguments<'_>) {
    SKIP.fetch_add(1, Ordering::Relaxed);
    kprintln!("NK-TEST {name}:SKIP {why}");
}

/// Print the totals and power off. The run is over.
pub fn complete(info: &BootInfo) -> ! {
    kprintln!(
        "NK-TEST-COMPLETE pass={} fail={} skip={}",
        PASS.load(Ordering::Relaxed),
        FAIL.load(Ordering::Relaxed),
        SKIP.load(Ordering::Relaxed)
    );
    crate::hal::init(info);
    crate::hal::power_off_or_halt()
}
