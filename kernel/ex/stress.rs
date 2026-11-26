//! What the tests of this directory share: threads that contend, and
//! waiting for them. A step one thread owes another at once is waited
//! for with a limit; the end of the threads themselves is waited for
//! without one, as [`thread::settle`] says.

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

/// Sleep until only `threads` threads exist, however long that takes:
/// [`thread::settle`], asleep between looks so that threads of any
/// priority get the processor.
pub fn ended(threads: u32) {
    while thread::count() != threads {
        nap();
    }
}

/// Run `count` threads, the `n`th calling `entry(n)`, and wait for all
/// of them to end: those that could be made, if not all could.
pub fn run(count: usize, entry: thread::Entry) -> Result<(), &'static str> {
    let before = thread::count();
    let made = (0..count).try_for_each(|index| {
        thread::create(entry, index, thread::NORMAL_PRIORITY, thread::ANYWHERE).map(|_| ())
    });
    ended(before);
    made
}
