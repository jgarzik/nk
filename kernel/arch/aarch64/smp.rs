//! Starting the other processors on arm64.
//!
//! Firmware starts a processor on request (PSCI `CPU_ON`), at a physical
//! address with the MMU off. The stub below runs there. It installs the
//! boot processor's translation settings, with a one-page table that
//! maps the stub to itself for the moment the MMU comes on, and jumps to
//! the kernel proper on the stack it was given.

use super::{cpu, gic, trap};
use crate::hal::platform;
use crate::ke::smp;
use crate::mm::{self, map::Tables};
use core::arch::{asm, global_asm};
use core::sync::atomic::{AtomicU64, Ordering};
use nk_acpi::Psci;
use nk_bootinfo::BootInfo;
use nk_mm::pt::{self, Prot};

/// PSCI `CPU_ON`, 64-bit calling convention.
const CPU_ON: u64 = 0xC400_0003;

/// What the stub loads, in this order. The block sits in a frame of its
/// own, which the starting processor reads with its MMU off.
#[repr(C)]
struct Parameters {
    ttbr0: u64,
    ttbr1: u64,
    tcr: u64,
    mair: u64,
    sctlr: u64,
    cpacr: u64,
    stack: u64,
    entry: u64,
    number: u64,
}

/// The low 16 bits of `TCR_EL1` describe the lower half of the address
/// space. For the stub's table: 48-bit addresses, 4 KiB pages, cacheable
/// inner-shareable table walks.
const TCR_T0_MASK: u64 = 0xFFFF;
const TCR_T0: u64 = 16 | 1 << 8 | 1 << 10 | 3 << 12;

global_asm!(
    r#"
    .text
    .balign 256
    .globl nk_ap_stub
nk_ap_stub:
    // x0: physical address of the parameters. MMU off, interrupts off.
    msr daifset, #0xf
    ldp x1, x2, [x0]
    ldp x3, x4, [x0, #16]
    ldp x5, x6, [x0, #32]
    ldp x7, x8, [x0, #48]
    ldr x9, [x0, #64]
    msr mair_el1, x4
    msr tcr_el1, x3
    msr ttbr0_el1, x1
    msr ttbr1_el1, x2
    msr cpacr_el1, x6
    isb
    tlbi vmalle1
    dsb nsh
    isb
    msr sctlr_el1, x5
    isb
    mov sp, x7
    mov x0, x9
    mov x29, xzr
    mov x30, xzr
    br x8
    .globl nk_ap_stub_end
nk_ap_stub_end:
"#
);

unsafe extern "C" {
    static nk_ap_stub: u8;
    static nk_ap_stub_end: u8;
}

/// Physical address of the stub.
static STUB: AtomicU64 = AtomicU64::new(0);
/// Physical address of the parameter frame.
static PARAMETERS: AtomicU64 = AtomicU64::new(0);
/// The boot processor's lower-half table and translation control, which
/// a started processor adopts once it runs in the upper half.
static BOOT_TTBR0: AtomicU64 = AtomicU64::new(0);
static BOOT_TCR: AtomicU64 = AtomicU64::new(0);

/// The physical address behind kernel address `va`, as the processor
/// translates it.
fn physical(va: u64) -> Option<u64> {
    let par: u64;
    // SAFETY: an address-translation query; it writes only `PAR_EL1`.
    unsafe {
        asm!("at s1e1r, {va}", "isb", "mrs {par}, par_el1", va = in(reg) va, par = out(reg) par, options(nostack));
    }
    // Bit 0 reports a failed translation.
    (par & 1 == 0).then_some(par & 0x0000_FFFF_FFFF_F000 | va & 0xFFF)
}

/// Build what every start needs. Done once.
pub fn prepare(_: &BootInfo) -> Result<(), &'static str> {
    // SAFETY: the two symbols bracket the stub above.
    let (start, len) = unsafe {
        let start = &raw const nk_ap_stub;
        (start as u64, (&raw const nk_ap_stub_end).offset_from(start))
    };
    // Aligned to 256 bytes and no longer: it lies within one page.
    assert!(len <= 256);
    let stub = physical(start).ok_or("the start-up stub has no physical address")?;
    // Tables that map the stub's page to itself, executable.
    let root = mm::alloc_frames(1).ok_or("no memory for the start-up tables")?;
    pt::map(
        &mut Tables,
        &super::pt_arch(),
        root,
        stub & !0xFFF,
        stub & !0xFFF,
        0,
        Prot::RX,
    )
    .map_err(|_| "cannot build the start-up tables")?;
    let parameters = mm::alloc_frames(1).ok_or("no memory for the start-up parameters")?;

    let (ttbr0, tcr, mair, sctlr, cpacr): (u64, u64, u64, u64, u64);
    // SAFETY: reading this processor's translation and control registers.
    unsafe {
        asm!(
            "mrs {0}, ttbr0_el1", "mrs {1}, tcr_el1", "mrs {2}, mair_el1",
            "mrs {3}, sctlr_el1", "mrs {4}, cpacr_el1",
            out(reg) ttbr0, out(reg) tcr, out(reg) mair, out(reg) sctlr, out(reg) cpacr,
            options(nomem, nostack),
        );
    }
    BOOT_TTBR0.store(ttbr0, Ordering::Relaxed);
    BOOT_TCR.store(tcr, Ordering::Relaxed);
    // SAFETY: a fresh frame in the direct map, written before any
    // processor is started on it.
    unsafe {
        mm::phys_to_virt(parameters)
            .cast::<Parameters>()
            .write(Parameters {
                ttbr0: root,
                ttbr1: super::pt_root(),
                tcr: tcr & !TCR_T0_MASK | TCR_T0,
                mair,
                sctlr,
                cpacr,
                stack: 0,
                entry: entry as extern "C" fn(u64) -> ! as usize as u64,
                number: 0,
            });
    }
    STUB.store(stub, Ordering::Relaxed);
    PARAMETERS.store(parameters, Ordering::Relaxed);
    Ok(())
}

/// Ask firmware to start the processor with affinity `target` at
/// physical address `entry`, passing it `context`.
fn cpu_on(conduit: Psci, target: u64, entry: u64, context: u64) -> i64 {
    let status: i64;
    // SAFETY: a PSCI call follows the SMC calling convention: arguments
    // in x0-x3, result in x0, x4-x17 may be clobbered.
    unsafe {
        match conduit {
            Psci::Hvc => asm!(
                "hvc #0",
                inout("x0") CPU_ON => status, inout("x1") target => _,
                inout("x2") entry => _, inout("x3") context => _,
                clobber_abi("C"), options(nostack),
            ),
            Psci::Smc => asm!(
                "smc #0",
                inout("x0") CPU_ON => status, inout("x1") target => _,
                inout("x2") entry => _, inout("x3") context => _,
                clobber_abi("C"), options(nostack),
            ),
        }
    }
    status
}

/// Wake processor `number` to run on the stack ending at `stack_top`.
/// Returns once firmware has accepted the request; the processor reports
/// in by itself.
pub fn start(number: usize, stack_top: u64) -> Result<(), &'static str> {
    let conduit = platform::get()
        .firmware
        .psci
        .ok_or("firmware offers no PSCI to start processors with")?;
    let parameters = PARAMETERS.load(Ordering::Relaxed);
    let block = mm::phys_to_virt(parameters).cast::<Parameters>();
    // SAFETY: no processor is reading the block: starts are one at a
    // time, and the previous one has reported in. The starting processor
    // reads it with its caches off, so the lines written are pushed out
    // to memory first.
    unsafe {
        (&raw mut (*block).stack).write_volatile(stack_top);
        (&raw mut (*block).number).write_volatile(number as u64);
        for line in (0..size_of::<Parameters>()).step_by(16) {
            asm!("dc cvac, {}", in(reg) block.cast::<u8>().add(line), options(nostack));
        }
        asm!("dsb sy", options(nostack));
    }
    let target = platform::get().cpus()[number].hw_id;
    match cpu_on(conduit, target, STUB.load(Ordering::Relaxed), parameters) {
        0 => Ok(()),
        -2 => Err("firmware: CPU_ON invalid parameters"),
        -4 => Err("firmware: the processor is already on"),
        -9 => Err("firmware: CPU_ON invalid address"),
        _ => Err("firmware could not start a processor"),
    }
}

/// Where a started processor enters the kernel, in the upper half on its
/// own stack with interrupts off.
extern "C" fn entry(number: u64) -> ! {
    // SAFETY: this code runs from the upper half, so the lower half can
    // be exchanged for the boot processor's: every processor then has
    // the same view. Stale translations are dropped.
    unsafe {
        asm!(
            "msr ttbr0_el1, {ttbr0}",
            "msr tcr_el1, {tcr}",
            "isb",
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            ttbr0 = in(reg) BOOT_TTBR0.load(Ordering::Relaxed),
            tcr = in(reg) BOOT_TCR.load(Ordering::Relaxed),
            options(nostack),
        );
    }
    trap::init();
    cpu::init(number as u32);
    if let Err(why) = gic::init_cpu(number as usize) {
        panic!("processor {number}: {why}");
    }
    smp::ap_main(number as usize)
}
