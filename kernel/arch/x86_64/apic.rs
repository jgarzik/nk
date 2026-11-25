//! The local APIC: this processor's interrupt controller.
//!
//! Windows ties the IRQL to the APIC's task priority: an interrupt's
//! vector, divided by 16, is the IRQL it runs at, and register CR8 (the
//! task priority) holds back every vector whose class is at or below it.
//! NK does the same, so the IRQL is enforced by the hardware, and a
//! driver that writes CR8 itself, as code built with old headers does,
//! gets the masking it expects.
//!
//! Registers are reached through the x2APIC machine-specific registers
//! when the processor has that mode, and through memory otherwise.

use super::{inb, outb};
use crate::hal::platform;
use crate::ke::interrupt;
use crate::mm;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// `(vector, IRQL)` pairs the interrupt self-test uses. The IRQL of a
/// vector is its upper four bits.
pub const TEST_LOW: (u32, u8) = (0x51, 5);
pub const TEST_HIGH: (u32, u8) = (0x71, 7);
pub const TEST_STRAY: (u32, u8) = (0x61, 6);

const SPURIOUS_VECTOR: u32 = 0xFF;
const ERROR_VECTOR: u32 = 0xFE;

// Register offsets in the memory-mapped page; the x2APIC register number
// is the offset divided by 16.
const REG_EOI: u32 = 0x0B0;
const REG_SPURIOUS: u32 = 0x0F0;
const REG_ERROR_STATUS: u32 = 0x280;
const REG_ICR_LOW: u32 = 0x300;
const REG_LVT_TIMER: u32 = 0x320;
const REG_LVT_LINT0: u32 = 0x350;
const REG_LVT_LINT1: u32 = 0x360;
const REG_LVT_ERROR: u32 = 0x370;
const LVT_MASKED: u32 = 1 << 16;
const ICR_SELF: u32 = 1 << 18;

const MSR_APIC_BASE: u32 = 0x1B;
const APIC_BASE_ENABLE: u64 = 1 << 11;
const APIC_BASE_X2APIC: u64 = 1 << 10;
const MSR_X2APIC: u32 = 0x800;
const MSR_X2APIC_SELF_IPI: u32 = 0x83F;

/// Whether this machine's processors run in x2APIC mode.
static X2APIC: AtomicBool = AtomicBool::new(false);
/// Address of the memory-mapped registers, in the direct map.
static MMIO: AtomicU64 = AtomicU64::new(0);

fn rdmsr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: only called for APIC registers this processor implements.
    unsafe {
        core::arch::asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi, options(nomem, nostack));
    }
    u64::from(hi) << 32 | u64::from(lo)
}

fn wrmsr(msr: u32, value: u64) {
    // SAFETY: as `rdmsr`; the values written are valid for the register.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack),
        );
    }
}

fn read(reg: u32) -> u32 {
    if X2APIC.load(Ordering::Relaxed) {
        rdmsr(MSR_X2APIC + (reg >> 4)) as u32
    } else {
        // SAFETY: `MMIO` is the APIC register page in the direct map;
        // device registers are read with volatile accesses.
        unsafe { ((MMIO.load(Ordering::Relaxed) + u64::from(reg)) as *const u32).read_volatile() }
    }
}

fn write(reg: u32, value: u32) {
    if X2APIC.load(Ordering::Relaxed) {
        wrmsr(MSR_X2APIC + (reg >> 4), u64::from(value));
    } else {
        // SAFETY: as `read`.
        unsafe {
            ((MMIO.load(Ordering::Relaxed) + u64::from(reg)) as *mut u32).write_volatile(value)
        }
    }
}

/// Mask every input of an I/O APIC. Firmware may have left some routed
/// (its timer, for one); nothing here handles device interrupts yet.
fn quiet_io_apic(address: u64) {
    let base = mm::phys_to_virt(address);
    // SAFETY: `base` is the I/O APIC's register page in the direct map:
    // an index register at 0 and a data register at 0x10.
    unsafe {
        let select = |index: u32| base.cast::<u32>().write_volatile(index);
        let data = base.add(0x10).cast::<u32>();
        select(1);
        let inputs = (data.read_volatile() >> 16 & 0xFF) + 1;
        for input in 0..inputs {
            select(0x10 + input * 2);
            data.write_volatile(data.read_volatile() | LVT_MASKED);
        }
    }
}

/// Bring up this processor's local APIC with every source masked except
/// the ones NK asks for, and silence the legacy controllers.
pub fn init() -> Result<(), &'static str> {
    let platform = platform::get();
    // The two 8259 controllers: mask every line. Their interrupts would
    // arrive on vectors that mean something else.
    outb(0x21, 0xFF);
    outb(0xA1, 0xFF);
    for io in platform.controllers.io_apics() {
        quiet_io_apic(io.address);
    }

    let has_x2apic = core::arch::x86_64::__cpuid_count(1, 0).ecx & 1 << 21 != 0;
    let mut base = rdmsr(MSR_APIC_BASE) | APIC_BASE_ENABLE;
    if has_x2apic {
        base |= APIC_BASE_X2APIC;
    }
    wrmsr(MSR_APIC_BASE, base);
    X2APIC.store(has_x2apic, Ordering::Relaxed);
    MMIO.store(
        mm::phys_to_virt(platform.controllers.local_apic) as u64,
        Ordering::Relaxed,
    );

    write(REG_LVT_TIMER, LVT_MASKED);
    write(REG_LVT_LINT0, LVT_MASKED);
    write(REG_LVT_LINT1, LVT_MASKED);
    write(REG_LVT_ERROR, ERROR_VECTOR);
    write(REG_ERROR_STATUS, 0);
    // Software-enable the APIC and name the spurious vector.
    write(REG_SPURIOUS, 1 << 8 | SPURIOUS_VECTOR);
    // Acknowledge anything firmware left in service.
    write(REG_EOI, 0);
    kprintln!(
        "hal: local APIC in {} mode",
        if has_x2apic { "x2APIC" } else { "xAPIC" }
    );
    // Drain a byte from the keyboard controller's output, if any, so a
    // pending legacy interrupt does not sit asserted.
    let _ = inb(0x60);
    Ok(())
}

/// Nothing to do: a vector's IRQL is its upper four bits, and a local
/// vector needs no enabling.
pub fn interrupt_enable(vector: u32, level: u8) {
    assert!(
        vector >> 4 == u32::from(level),
        "vector {vector:#x} is not at IRQL {level}"
    );
}

/// Ask this processor's APIC to interrupt it on `vector`.
pub fn self_interrupt(vector: u32) {
    if X2APIC.load(Ordering::Relaxed) {
        wrmsr(MSR_X2APIC_SELF_IPI, u64::from(vector));
    } else {
        write(REG_ICR_LOW, ICR_SELF | vector);
    }
}

/// An interrupt arrived on `vector` (32 or above). Called from the trap
/// handler with interrupts disabled.
pub fn interrupt(vector: u32) {
    if vector == SPURIOUS_VECTOR {
        // The APIC withdrew the interrupt; there is nothing to finish.
        return;
    }
    if vector == ERROR_VECTOR {
        write(REG_ERROR_STATUS, 0);
        kprintln!(
            "hal: local APIC error, status {:#x}",
            read(REG_ERROR_STATUS)
        );
        write(REG_EOI, 0);
        return;
    }
    interrupt::dispatch(vector, (vector >> 4) as u8, || write(REG_EOI, 0));
}

pub fn enable_interrupts() {
    // SAFETY: the IDT and the APIC are set up; interrupts above the
    // current IRQL may now arrive.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
}

pub fn disable_interrupts() {
    // SAFETY: masking interrupts touches no memory.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
}
