//! The interrupt request level of the current processor.
//!
//! Where the level lives is the architecture's business (`arch::irql`):
//! register CR8 on x86-64, where drivers read it directly; a field of
//! NK's own on arm64, where they call the kernel for it. The rules for
//! changing it are the same everywhere and are checked on every change.

use crate::arch;
use nk_ke::Violation;
pub use nk_ntabi::pcr::{DISPATCH_LEVEL, HIGH_LEVEL, PASSIVE_LEVEL};

pub fn current() -> u8 {
    arch::irql()
}

/// Raise the IRQL to `new` and return the level it was at. Raising to a
/// lower level is a bug and stops the system.
pub fn raise(new: u8) -> u8 {
    let old = current();
    if let Err(v) = nk_ke::check_raise(old, new) {
        violation(v);
    }
    arch::set_irql(new);
    old
}

/// Lower the IRQL to `new`. Lowering to a higher level is a bug and stops
/// the system.
pub fn lower(new: u8) {
    if let Err(v) = nk_ke::check_lower(current(), new) {
        violation(v);
    }
    arch::set_irql(new);
}

/// Stop the system over a broken IRQL or locking rule, with the Windows
/// bugcheck code where Windows has one for it.
pub fn violation(v: Violation) -> ! {
    match v {
        Violation::RaiseBelow { current, new } => crate::kd::bugcheck(format_args!(
            "0x00000009 IRQL_NOT_GREATER_OR_EQUAL: raise from {current} to {new}"
        )),
        Violation::LowerAbove { current, new } => crate::kd::bugcheck(format_args!(
            "0x0000000A IRQL_NOT_LESS_OR_EQUAL: lower from {current} to {new}"
        )),
        Violation::Recursive => crate::kd::bugcheck(format_args!(
            "0x0000000F SPIN_LOCK_ALREADY_OWNED: a lock taken twice by one processor"
        )),
        Violation::NotHeld => crate::kd::bugcheck(format_args!(
            "0x00000010 SPIN_LOCK_NOT_OWNED: a lock released by a processor that does not hold it"
        )),
        other => crate::kd::bugcheck(format_args!("lock order violation: {other:?}")),
    }
}

/// Driver entry points and most kernel services run at PASSIVE_LEVEL.
/// Calling one with the IRQL raised (a lock still held, say) is a kernel
/// bug that a driver would only show much later, if at all.
pub fn expect_passive(what: &str) {
    let level = current();
    if level != PASSIVE_LEVEL {
        crate::kd::bugcheck(format_args!(
            "0x0000000A IRQL_NOT_LESS_OR_EQUAL: {what} at IRQL {level}, not PASSIVE_LEVEL"
        ));
    }
}

/// Raising and lowering move the level and report where it was; taking
/// locks moves it too, nests in rank order, and leaves nothing held.
pub fn self_test() -> Result<(), &'static str> {
    use super::{Rank, SpinLock};
    static OUTER: SpinLock<u32> = SpinLock::new(Rank::Pool, 1);
    static INNER: SpinLock<u32> = SpinLock::new(Rank::Frames, 2);
    static CONSOLE_RANKED: SpinLock<u32> = SpinLock::new(Rank::Console, 3);

    if current() != PASSIVE_LEVEL {
        return Err("the tests do not run at PASSIVE_LEVEL");
    }
    let old = raise(DISPATCH_LEVEL);
    if (old, current()) != (PASSIVE_LEVEL, DISPATCH_LEVEL) {
        return Err("raise did not report the old level and set the new one");
    }
    let old = raise(HIGH_LEVEL);
    if (old, current()) != (DISPATCH_LEVEL, HIGH_LEVEL) {
        return Err("raise from DISPATCH_LEVEL to HIGH_LEVEL went wrong");
    }
    lower(DISPATCH_LEVEL);
    lower(PASSIVE_LEVEL);
    if current() != PASSIVE_LEVEL {
        return Err("lower did not return to PASSIVE_LEVEL");
    }
    {
        let outer = OUTER.lock();
        if current() != DISPATCH_LEVEL {
            return Err("holding a lock did not raise the IRQL to DISPATCH_LEVEL");
        }
        let inner = INNER.lock();
        {
            let console = CONSOLE_RANKED.lock();
            if current() != HIGH_LEVEL {
                return Err("a console-rank lock did not raise the IRQL to HIGH_LEVEL");
            }
            if *outer + *inner + *console != 6 {
                return Err("locked values are wrong");
            }
        }
        if current() != DISPATCH_LEVEL {
            return Err("releasing the innermost lock did not restore DISPATCH_LEVEL");
        }
    }
    let old = raise(HIGH_LEVEL);
    // SAFETY: raised for the read, which ends with the statement.
    let depth = unsafe { arch::percpu().held() }.depth();
    lower(old);
    if depth != 0 || current() != PASSIVE_LEVEL {
        return Err("locks or a raised IRQL were left behind");
    }
    Ok(())
}
