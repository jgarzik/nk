//! Atomic steps wider than a register.

use core::sync::atomic::Ordering;

/// Replace the 16 bytes at `target` with `new` if they are `old`, in one
/// atomic step. Returns whether they were.
///
/// # Safety
/// `target` points to 16 bytes, 16-byte aligned, valid for reads and
/// writes.
pub unsafe fn swap_pair(target: *mut u128, old: u128, new: u128) -> bool {
    /// # Safety
    /// As `swap_pair`; the processor has `CMPXCHG16B`.
    #[target_feature(enable = "cmpxchg16b")]
    unsafe fn locked(target: *mut u128, old: u128, new: u128) -> bool {
        // SAFETY: per the contract.
        let was = unsafe {
            core::arch::x86_64::cmpxchg16b(target, old, new, Ordering::SeqCst, Ordering::SeqCst)
        };
        was == old
    }
    // SAFETY: per the contract. Every processor 64-bit Windows 10 runs
    // on has the instruction (Windows requires it); one without would
    // stop here with an invalid-opcode trap.
    unsafe { locked(target, old, new) }
}
