//! What the tests of this directory share: threads that contend, and
//! waiting for them with a limit, so that a waiter never let in fails
//! its test instead of hanging the boot.

use crate::ke::{thread, time, wait};

/// Sleep for about a millisecond.
pub fn nap() {
    // SAFETY: no object is involved.
    unsafe { wait::wait(None, Some(-10_000)) };
}

/// Wait until `ready` says so, looking every millisecond, for at most
/// `ms` milliseconds. Returns whether it did.
pub fn until(ms: u64, ready: impl Fn() -> bool) -> bool {
    let deadline = time::interrupt_time() + ms * 10_000;
    while !ready() {
        if time::interrupt_time() > deadline {
            return false;
        }
        nap();
    }
    true
}

/// How long one thread is given to be let in to what another has just
/// let go, or to end: thousands of times what it takes, since an
/// emulated machine on a busy host is slow, and slow is not wrong.
pub const PROMPT_MS: u64 = 10_000;

/// How long threads contending in a loop are given to finish.
pub const PATIENCE_MS: u64 = 60_000;

/// Run `count` threads, the `n`th calling `entry(n)`, and wait for all
/// of them to end.
pub fn run(count: usize, entry: thread::Entry) -> Result<(), &'static str> {
    let before = thread::count();
    for index in 0..count {
        thread::create(entry, index, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    }
    if until(PATIENCE_MS, || thread::count() == before) {
        Ok(())
    } else {
        Err("the threads did not finish: a waiter was never let in")
    }
}
