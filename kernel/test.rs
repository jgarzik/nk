//! Boot self-tests: the registry, the runner and the report format.
//!
//! Tests are grouped. A [`Group`] declares every verdict it will report
//! and a function that reports them; the runner checks that each declared
//! name gets exactly one verdict and that the group gave back everything it
//! allocated. The serial console carries the results in a fixed form that
//! `tools/judge.py` checks:
//!
//! ```text
//! NK-TEST-PLAN <n>                 verdicts to expect, printed first
//! NK-TEST <name>:OK [<what was observed>]
//! NK-TEST <name>:FAIL <why>
//! NK-TEST <name>:SKIP <why>
//! NK-TEST-COMPLETE pass=<n> fail=<n> skip=<n>
//! ```
//!
//! The command-line word `test=<pattern>` selects groups: a group runs if
//! one of its names matches the pattern (`*` matches any run of
//! characters). A `manual` group runs only when a name of its own is
//! given exactly; those are the tests that end the boot on purpose.

use crate::selftest::resources;
use core::fmt;
use core::sync::atomic::{AtomicU32, Ordering};
use nk_bootinfo::BootInfo;
use nk_selftest::{ClaimError, Claims};

static PASS: AtomicU32 = AtomicU32::new(0);
static FAIL: AtomicU32 = AtomicU32::new(0);
static SKIP: AtomicU32 = AtomicU32::new(0);

/// Tests that share set-up, with the names of all their verdicts.
pub struct Group {
    /// Every verdict the group reports. At most 64.
    pub names: &'static [&'static str],
    pub run: fn(&mut Report, &BootInfo),
    /// Runs only when `test=` names it exactly.
    pub manual: bool,
}

/// Collects one group's verdicts and holds it to its declared names.
pub struct Report {
    claims: Claims<'static>,
}

fn count_fail(name: &str, why: fmt::Arguments<'_>) {
    FAIL.fetch_add(1, Ordering::Relaxed);
    kprintln!("NK-TEST {name}:FAIL {why}");
}

impl Report {
    /// Claim the verdict for `name`. `false` (and a failure on the
    /// console) if the group did not declare it or already reported it.
    fn claim(&mut self, name: &str) -> bool {
        match self.claims.claim(name) {
            Ok(()) => true,
            Err(ClaimError::Undeclared) => {
                count_fail(name, format_args!("verdict not declared by its group"));
                false
            }
            Err(ClaimError::Twice) => {
                count_fail(name, format_args!("reported twice"));
                false
            }
        }
    }

    pub fn ok(&mut self, name: &str) {
        if self.claim(name) {
            PASS.fetch_add(1, Ordering::Relaxed);
            kprintln!("NK-TEST {name}:OK");
        }
    }

    /// Pass, stating what was observed (a count, a measurement), so that
    /// a test which checked nothing is visible in the log.
    pub fn ok_with(&mut self, name: &str, observed: fmt::Arguments<'_>) {
        if self.claim(name) {
            PASS.fetch_add(1, Ordering::Relaxed);
            kprintln!("NK-TEST {name}:OK {observed}");
        }
    }

    pub fn fail(&mut self, name: &str, why: fmt::Arguments<'_>) {
        if self.claim(name) {
            count_fail(name, why);
        }
    }

    pub fn skip(&mut self, name: &str, why: fmt::Arguments<'_>) {
        if self.claim(name) {
            SKIP.fetch_add(1, Ordering::Relaxed);
            kprintln!("NK-TEST {name}:SKIP {why}");
        }
    }

    /// Run one check and report its verdict.
    pub fn check(&mut self, name: &str, test: impl FnOnce() -> Result<(), &'static str>) {
        match test() {
            Ok(()) => self.ok(name),
            Err(why) => self.fail(name, format_args!("{why}")),
        }
    }

    /// Skip every verdict not yet reported: what the tests need is absent.
    pub fn skip_rest(&mut self, why: fmt::Arguments<'_>) {
        for name in self.claims.missing() {
            self.skip(name, why);
        }
    }

    /// A declared verdict that was never reported is a failure, not a gap.
    fn finish(mut self) {
        for name in self.claims.missing() {
            self.fail(name, format_args!("no verdict: the group stopped early"));
        }
    }
}

fn selected(group: &Group, pattern: Option<&str>) -> bool {
    nk_selftest::selected(group.names, group.manual, pattern)
}

/// Report a failure that ends the boot before the tests can run.
pub fn abort(name: &str, why: fmt::Arguments<'_>) -> ! {
    count_fail(name, why);
    complete()
}

/// Run the selected groups, print the totals and power off.
pub fn run_all(groups: &[&Group], info: &BootInfo) -> ! {
    let pattern = info.option("test");
    let plan: usize = groups
        .iter()
        .filter(|g| selected(g, pattern))
        .map(|g| g.names.len())
        .sum();
    kprintln!("NK-TEST-PLAN {plan}");
    for group in groups.iter().filter(|g| selected(g, pattern)) {
        let before = resources();
        let mut report = Report {
            claims: Claims::new(group.names).expect("a group reports at most 64 verdicts"),
        };
        (group.run)(&mut report, info);
        report.finish();
        let after = resources();
        if after != before {
            // Outside the plan on purpose: the judge fails the boot on it.
            count_fail(
                "leak",
                format_args!(
                    "group of {}: before {before:?}, after {after:?}",
                    group.names[0]
                ),
            );
        }
    }
    complete()
}

/// Print the totals and power off. The run is over.
fn complete() -> ! {
    kprintln!(
        "NK-TEST-COMPLETE pass={} fail={} skip={}",
        PASS.load(Ordering::Relaxed),
        FAIL.load(Ordering::Relaxed),
        SKIP.load(Ordering::Relaxed)
    );
    crate::hal::power_off_or_halt()
}

/// Static storage for an object a test hands to the kernel by pointer,
/// as a driver would.
pub struct Slot<T>(core::cell::UnsafeCell<core::mem::MaybeUninit<T>>);

// SAFETY: reached only through the kernel routines, which take pointers
// and do their own locking.
unsafe impl<T> Sync for Slot<T> {}

impl<T> Slot<T> {
    pub const fn new() -> Self {
        Self(core::cell::UnsafeCell::new(core::mem::MaybeUninit::uninit()))
    }

    pub fn ptr(&self) -> *mut T {
        self.0.get().cast()
    }
}
