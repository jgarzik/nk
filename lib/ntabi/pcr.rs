//! The processor control region (KPCR) and the fields drivers reach
//! through it.
//!
//! Drivers do not call the kernel for the current thread or processor:
//! WDK headers compile those into direct loads relative to a reserved
//! register. That makes these offsets ABI.
//!
//! - x86-64: the GS segment base is the KPCR. `KeGetCurrentThread()` is
//!   `gs:[0x188]`; the current IRQL is register CR8, not memory.
//! - arm64: register x18 is the KPCR. `KeGetCurrentThread()` is
//!   `[x18, #0x988]`.
//!
//! Only the handful of fields NK fills in are named. Source: the public
//! `KPCR` definition in the WDK's `ntddk.h` (x86-64), and the documented
//! arm64 convention. The arm64 offsets have not yet been confirmed
//! against a WDK-built probe; see `doc/ABI.md`.

/// Bytes NK reserves for the KPCR plus the KPRCB that follows it.
pub const PCR_SIZE: usize = 0x2000;

/// Layout facts for one architecture.
pub struct PcrLayout {
    /// `KPCR.Self`: pointer to the KPCR itself.
    pub self_ptr: usize,
    /// `KPCR.CurrentPrcb`: pointer to the embedded KPRCB.
    pub current_prcb: usize,
    /// Where the embedded `KPRCB` starts.
    pub prcb: usize,
    /// `KPRCB.CurrentThread`, as an offset from the KPCR.
    pub current_thread: usize,
}

pub const X86_64: PcrLayout = PcrLayout {
    self_ptr: 0x18,
    current_prcb: 0x20,
    prcb: 0x180,
    current_thread: 0x188,
};

pub const AARCH64: PcrLayout = PcrLayout {
    self_ptr: 0x18,
    current_prcb: 0x20,
    prcb: 0x980,
    current_thread: 0x988,
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
            assert!(l.current_thread + 8 <= PCR_SIZE);
        }
    }
}
