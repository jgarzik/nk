//! Atomic steps wider than a register.

/// Replace the 16 bytes at `target` with `new` if they are `old`, in one
/// atomic step. Returns whether they were.
///
/// An exclusive load of the pair, a comparison, and an exclusive store
/// that fails, and is tried again, if anything wrote there in between.
///
/// # Safety
/// `target` points to 16 bytes, 16-byte aligned, valid for reads and
/// writes.
pub unsafe fn swap_pair(target: *mut u128, old: u128, new: u128) -> bool {
    let swapped: u64;
    // SAFETY: per the contract; the sequence touches only the 16 bytes
    // and the registers named.
    unsafe {
        core::arch::asm!(
            "2:",
            "ldxp {low}, {high}, [{target}]",
            "cmp {low}, {old_low}",
            "ccmp {high}, {old_high}, #0, eq",
            "b.ne 3f",
            "stxp {status:w}, {new_low}, {new_high}, [{target}]",
            "cbnz {status:w}, 2b",
            "3:",
            // Neither the store nor the branch on its status changes the
            // flags: they are still the comparison's.
            "cset {swapped}, eq",
            "clrex",
            target = in(reg) target,
            old_low = in(reg) old as u64,
            old_high = in(reg) (old >> 64) as u64,
            new_low = in(reg) new as u64,
            new_high = in(reg) (new >> 64) as u64,
            low = out(reg) _,
            high = out(reg) _,
            status = out(reg) _,
            swapped = out(reg) swapped,
            options(nostack),
        );
    }
    swapped != 0
}
