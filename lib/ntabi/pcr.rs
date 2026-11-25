//! The processor control region (KPCR) and the fields drivers reach
//! through it.
//!
//! Drivers do not call the kernel for the current thread or processor:
//! WDK headers compile those into direct loads relative to a reserved
//! register. That makes these offsets ABI.
//!
//! - x86-64: the GS segment base is the KPCR. `KeGetCurrentThread()` is
//!   `gs:[0x188]`; the processor number is the 32-bit `gs:[0x1A4]` (and,
//!   for code built with older headers, the byte `gs:[0x184]`); the
//!   current IRQL is register CR8, not memory.
//! - arm64: register x18 is the KPCR. `KeGetCurrentThread()` is
//!   `[x18, #0x988]`.
//!
//! Only the handful of fields NK fills in are named. The x86-64 offsets
//! are checked against the public symbols of the pinned kernel build
//! (`pdb.rs`), which cover the private processor block as well as the
//! public head of the KPCR. The arm64 offsets are the documented
//! convention and are not yet confirmed; see `doc/ABI.md`.

/// Layout facts for one architecture.
pub struct PcrLayout {
    /// Size of the KPCR, which ends with the embedded KPRCB.
    pub size: usize,
    /// `KPCR.Self`: pointer to the KPCR itself.
    pub self_ptr: usize,
    /// `KPCR.CurrentPrcb`: pointer to the embedded KPRCB.
    pub current_prcb: usize,
    /// Where the embedded `KPRCB` starts.
    pub prcb: usize,
    /// `KPRCB.CurrentThread`, as an offset from the KPCR.
    pub current_thread: usize,
    /// `KPRCB.Number`: this processor's index, 32 bits; offset from the
    /// KPCR.
    pub number: usize,
    /// `KPRCB.LegacyNumber`: the same index as one byte, where the
    /// architecture has it; offset from the KPCR.
    pub legacy_number: Option<usize>,
}

pub const X86_64: PcrLayout = PcrLayout {
    size: 0xB080,
    self_ptr: 0x18,
    current_prcb: 0x20,
    prcb: 0x180,
    current_thread: 0x188,
    number: 0x1A4,
    legacy_number: Some(0x184),
};

/// arm64: `self_ptr`, `current_prcb` and `current_thread` are the
/// documented convention. The size, and where the processor number sits,
/// are NK's own choices (the x86-64 PRCB offsets, moved to this PRCB):
/// nothing available says what Windows uses, and no binary NK can obtain
/// reads them.
pub const AARCH64: PcrLayout = PcrLayout {
    size: 0x2000,
    self_ptr: 0x18,
    current_prcb: 0x20,
    prcb: 0x980,
    current_thread: 0x988,
    number: 0x9A4,
    legacy_number: None,
};

#[cfg(target_arch = "x86_64")]
pub const NATIVE: PcrLayout = X86_64;
#[cfg(target_arch = "aarch64")]
pub const NATIVE: PcrLayout = AARCH64;

/// IRQL values (`KIRQL`).
pub const PASSIVE_LEVEL: u8 = 0;
pub const APC_LEVEL: u8 = 1;
pub const DISPATCH_LEVEL: u8 = 2;
/// The highest level; all interrupts masked.
pub const HIGH_LEVEL: u8 = 15;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_thread_is_second_prcb_field() {
        for l in [X86_64, AARCH64] {
            assert_eq!(l.current_thread, l.prcb + 8);
            assert!(l.current_thread + 8 <= l.size);
            assert!(l.number + 4 <= l.size);
            assert_eq!(l.size % 16, 0);
        }
    }
}
