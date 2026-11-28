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

/// The cycle counter (`RDTSC`), as winload reads its performance counter.
pub fn cycles() -> u64 {
    // SAFETY: RDTSC only reads a counter, which firmware leaves readable.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// How many times an instruction that draws a random word is tried
/// before the generator is taken to be broken: SymCrypt's counts, which
/// winload uses.
const RDSEED_TRIES: u32 = 10_000_000;
const RDRAND_TRIES: u32 = 1_000_000;

/// Draw one word by `RDSEED` (`seed`) or `RDRAND`, trying `tries` times.
fn draw_word(seed: bool, tries: u32) -> Option<u64> {
    for _ in 0..tries {
        let (word, ok): (u64, u8);
        // SAFETY: the caller checked CPUID for the instruction; it writes
        // one register and the carry flag.
        unsafe {
            if seed {
                core::arch::asm!("rdseed {w}", "setc {c}", w = out(reg) word, c = out(reg_byte) ok, options(nomem, nostack));
            } else {
                core::arch::asm!("rdrand {w}", "setc {c}", w = out(reg) word, c = out(reg_byte) ok, options(nomem, nostack));
            }
        }
        if ok != 0 {
            return Some(word);
        }
    }
    None
}

/// Fill `seed` by `RDSEED` or, without it, `rdrand` by `RDRAND`, as
/// winload draws the processor's entropy, and give the bytes drawn;
/// `Ok(None)` without either instruction. A generator that never
/// answers is an error: winload stops the boot then (`SymCryptFatal`).
pub fn draw_random<'a>(
    seed: &'a mut [u8],
    rdrand: &'a mut [u8],
) -> Result<Option<&'a [u8]>, &'static str> {
    use core::arch::x86_64::{__cpuid, __cpuid_count};
    let has_rdrand = __cpuid(1).ecx & (1 << 30) != 0;
    let has_rdseed = __cpuid(0).eax >= 7 && __cpuid_count(7, 0).ebx & (1 << 18) != 0;
    let (out, use_seed, tries) = if has_rdseed {
        (seed, true, RDSEED_TRIES)
    } else if has_rdrand {
        (rdrand, false, RDRAND_TRIES)
    } else {
        return Ok(None);
    };
    for chunk in out.chunks_mut(8) {
        let word = draw_word(use_seed, tries)
            .ok_or("the processor's random number generator does not answer")?;
        chunk.copy_from_slice(&word.to_le_bytes()[..chunk.len()]);
    }
    Ok(Some(out))
}
