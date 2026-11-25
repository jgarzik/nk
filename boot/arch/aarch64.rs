//! arm64: firmware's identity map stays in TTBR0; the loader builds the
//! kernel half and installs it in TTBR1.
//!
//! Firmware runs with the MMU on. Turning it off to start clean would mean
//! flushing caches by hand, and changing `MAIR_EL1` under live firmware
//! mappings would break them. So the loader keeps firmware's attribute
//! register and looks up which indices mean "normal" and "device" memory.

use nk_bootinfo::{BootInfo, Serial};
use nk_mm::pt::{self, MairError};

pub const NAME: &str = "aarch64";
pub const MACHINE: u16 = nk_pe::MACHINE_ARM64;

pub type PtArch = pt::Aarch64;

/// QEMU `virt` PL011, used only if firmware has no SPCR table.
pub const DEFAULT_SERIAL: Serial = Serial::new(Serial::MMIO_PL011, 0x0900_0000);

/// How far the direct map reaches: all of RAM. Devices on the `virt`
/// machine sit below RAM, so they are covered too.
pub fn map_top(ram_top: u64) -> u64 {
    ram_top
}
pub const NEEDS_IDENTITY_MAP: bool = false;

pub fn pt_arch(info: &mut BootInfo) -> Result<PtArch, &'static str> {
    let (el, mair): (u64, u64);
    // SAFETY: reading two system registers has no side effects.
    unsafe {
        core::arch::asm!("mrs {}, CurrentEL", "mrs {}, mair_el1", out(reg) el, out(reg) mair);
    }
    if el >> 2 != 1 {
        return Err("firmware is not running at EL1");
    }
    let arch = pt::Aarch64::from_mair(mair).map_err(|e| match e {
        MairError::NoNormal => "MAIR_EL1 has no write-back normal memory attribute",
        MairError::NoDevice => "MAIR_EL1 has no device memory attribute",
    })?;
    info.mair_normal = arch.mair_normal;
    info.mair_device = arch.mair_device;
    Ok(arch)
}

/// TCR_EL1 fields for the TTBR1 half: 48-bit addresses (T1SZ=16), 4 KiB
/// granule, write-back cacheable inner-shareable table walks.
const TCR_T1_MASK: u64 = 0xFFFF_0000;
const TCR_T1: u64 = (16 << 16) | (1 << 24) | (1 << 26) | (3 << 28) | (2 << 30);

/// Install the kernel's page tables in TTBR1 and jump to its entry point.
///
/// # Safety
/// Boot services must have been exited. `root` must map `entry` executable
/// and `stack` writable in the high half; `info` is passed to the kernel as
/// its only argument.
pub unsafe fn enter(root: u64, entry: u64, stack: u64, info: u64) -> ! {
    // SAFETY: per the contract above. Only the TTBR1 half of TCR changes,
    // so the firmware identity map this code runs from is undisturbed.
    unsafe {
        core::arch::asm!(
            "msr daifset, #0xf",
            "msr ttbr1_el1, x1",
            "mrs x9, tcr_el1",
            "bic x9, x9, x5",
            "orr x9, x9, x6",
            "msr tcr_el1, x9",
            "isb",
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            "mov sp, x2",
            "br x3",
            in("x0") info,
            in("x1") root,
            in("x2") stack,
            in("x3") entry,
            in("x5") TCR_T1_MASK,
            in("x6") TCR_T1,
            options(noreturn),
        )
    }
}
