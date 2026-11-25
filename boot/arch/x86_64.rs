//! x86-64: the loader builds one address space for the kernel.
//!
//! Low half: identity map of physical memory, kept so UEFI runtime services
//! (which run at their physical addresses) stay callable. High half: the
//! direct map and the kernel image.

use nk_bootinfo::{BootInfo, Serial};
use nk_mm::pt;

pub const NAME: &str = "x86_64";
pub const MACHINE: u16 = nk_pe::MACHINE_AMD64;

pub type PtArch = pt::X86_64;

/// COM1. QEMU's x86 machines publish no SPCR table, so this is the default.
pub const DEFAULT_SERIAL: Serial = Serial::new(Serial::PORT_16550, 0x3F8);

/// How far the maps reach. Device registers (local APIC, I/O APIC, flash)
/// live below 4 GiB whatever the amount of RAM, so always at least that.
pub fn map_top(ram_top: u64) -> u64 {
    ram_top.max(4 << 30)
}

/// The loader's code keeps running from the identity map until the jump.
pub const NEEDS_IDENTITY_MAP: bool = true;

pub fn pt_arch(_info: &mut BootInfo) -> Result<PtArch, &'static str> {
    Ok(pt::X86_64)
}

/// Switch to the kernel's page tables and jump to its entry point.
///
/// # Safety
/// Boot services must have been exited. `root` must map the currently
/// executing code at its present address, `entry` executable, and `stack`
/// writable; `info` is passed to the kernel as its only argument.
pub unsafe fn enter(root: u64, entry: u64, stack: u64, info: u64) -> ! {
    // SAFETY: per the contract above. EFER.NXE must be set before loading
    // tables that use the NX bit, and CR0.WP makes read-only mappings bind
    // the kernel too. The stack is left as a `call` would leave it:
    // 16-byte aligned plus the return slot, with shadow space above.
    unsafe {
        core::arch::asm!(
            "cli",
            "mov ecx, 0xC0000080",
            "rdmsr",
            "or eax, 0x800",
            "wrmsr",
            "mov rax, cr0",
            "or rax, 0x10000",
            "mov cr0, rax",
            "mov cr3, r8",
            "lea rsp, [r9 - 0x28]",
            "mov rcx, r10",
            "jmp r11",
            in("r8") root,
            in("r9") stack,
            in("r10") info,
            in("r11") entry,
            options(noreturn),
        )
    }
}
