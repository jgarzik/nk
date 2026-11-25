//! Kernel core: synchronisation and processor state.

pub mod event;
pub mod irql;
pub mod pcr;
pub mod percpu;
pub mod seh;
pub mod spinlock;

pub use spinlock::{Rank, SpinLock};

use crate::arch;

/// Take a breakpoint exception and come back: proves the vector table,
/// the entry stub's register save/restore and the handler all work.
pub fn trap_self_test() -> Result<(), &'static str> {
    let before = arch::breakpoints();
    // A value the stub must preserve across the exception.
    let canary = core::hint::black_box(0x5A5A_1234_ABCD_EF01u64);
    arch::breakpoint();
    if arch::breakpoints() != before + 1 {
        return Err("breakpoint was not counted");
    }
    if core::hint::black_box(canary) != 0x5A5A_1234_ABCD_EF01 {
        return Err("a register was corrupted across the exception");
    }
    Ok(())
}
