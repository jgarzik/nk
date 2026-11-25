//! The GIC, version 3: arm64's interrupt controller.
//!
//! The IRQL is enforced by the GIC's priority mask. Every interrupt NK
//! enables gets a priority derived from the IRQL it runs at, and the mask
//! register holds back every interrupt whose priority is not more urgent
//! than the current IRQL's. Lower numbers are more urgent, so IRQL `n`
//! is priority `0xF0 - 0x10 * n` and the mask for IRQL `n` is that same
//! number: interrupts of IRQL `n` and below are then held back.
//!
//! The distributor (shared) and a redistributor per processor are memory
//! mapped; the processor's own interface is system registers.

use crate::hal::platform::{self, MAX_CPUS};
use crate::ke::interrupt;
use crate::ke::irql::HIGH_LEVEL;
use crate::mm;
use core::arch::asm;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

/// `(interrupt id, IRQL)` pairs the interrupt self-test uses: software
/// generated interrupts this processor sends itself.
pub const TEST_LOW: (u32, u8) = (5, 5);
pub const TEST_HIGH: (u32, u8) = (7, 7);
pub const TEST_STRAY: (u32, u8) = (6, 6);

/// Interrupt ids below this are private to each processor (software
/// generated 0-15, private peripheral 16-31).
const PRIVATE: u32 = 32;
/// Ids from here up mean "nothing to acknowledge".
const SPURIOUS: u32 = 1020;
/// The software-generated interrupt that stops a processor for good.
const STOP: u32 = 2;

// Distributor.
const GICD_CTLR: usize = 0x0;
const GICD_TYPER: usize = 0x4;
const GICD_ICENABLER: usize = 0x180;
const GICD_CTLR_ARE_NS: u32 = 1 << 4;
const GICD_CTLR_GROUP1NS: u32 = 1 << 1;
// Redistributor: a control frame, then the frame for private interrupts.
const GICR_TYPER: usize = 0x8;
const GICR_WAKER: usize = 0x14;
const GICR_FRAME: usize = 0x1_0000;
const GICR_STRIDE: u64 = 0x2_0000;
const SGI_IGROUPR0: usize = GICR_FRAME + 0x80;
const SGI_ISENABLER0: usize = GICR_FRAME + 0x100;
const SGI_ICENABLER0: usize = GICR_FRAME + 0x180;
const SGI_IPRIORITYR: usize = GICR_FRAME + 0x400;

/// This processor's redistributor, in the direct map. Boot CPU only for
/// now, so one cell.
static REDISTRIBUTORS: [AtomicU64; MAX_CPUS] = [const { AtomicU64::new(0) }; MAX_CPUS];
/// The private interrupts NK has enabled; each processor enables them.
static ENABLED: AtomicU32 = AtomicU32::new(0);
/// IRQL of each private interrupt that has been enabled.
static LEVELS: [AtomicU8; PRIVATE as usize] = [const { AtomicU8::new(0) }; PRIVATE as usize];

/// The priority of interrupts that run at IRQL `level`, which is also the
/// mask value that holds them back.
pub const fn priority(level: u8) -> u8 {
    0xF0 - 0x10 * level
}

fn read32(base: u64, offset: usize) -> u32 {
    // SAFETY: `base` is a GIC register frame in the direct map; device
    // registers are read with volatile accesses.
    unsafe { ((base as usize + offset) as *const u32).read_volatile() }
}

fn write32(base: u64, offset: usize, value: u32) {
    // SAFETY: as `read32`.
    unsafe { ((base as usize + offset) as *mut u32).write_volatile(value) }
}

/// The affinity fields of this processor's `MPIDR_EL1`, packed as the
/// redistributor's type register packs them.
fn affinity() -> u32 {
    let id = super::platform::current_cpu_id();
    ((id >> 32 & 0xFF) << 24 | id & 0xFF_FFFF) as u32
}

/// Find this processor's redistributor by its affinity. Never by
/// position: firmware need not list them in processor order.
fn find_redistributor() -> Option<u64> {
    let me = affinity();
    for region in platform::get().controllers.redistributors() {
        let mut frame = region.address;
        while frame + GICR_STRIDE <= region.address + region.length {
            let base = mm::phys_to_virt(frame) as u64;
            if read32(base, GICR_TYPER + 4) == me {
                return Some(base);
            }
            // Bit 4 of the type register marks the last frame of a region.
            if read32(base, GICR_TYPER) & 1 << 4 != 0 {
                break;
            }
            frame += GICR_STRIDE;
        }
    }
    None
}

/// Set the priority mask for IRQL `level`.
pub fn set_mask(level: u8) {
    // SAFETY: writing the priority mask only changes which interrupts
    // this processor accepts.
    unsafe {
        asm!("msr icc_pmr_el1, {}", "isb", in(reg) u64::from(priority(level)), options(nomem, nostack));
    }
}

/// The IRQL the priority mask stands for: the inverse of [`priority`].
pub fn mask_level() -> u8 {
    let mask: u64;
    // SAFETY: reading the priority mask has no side effects.
    unsafe { asm!("mrs {}, icc_pmr_el1", out(reg) mask, options(nomem, nostack)) };
    (priority(0) - mask as u8) >> 4
}

/// Turn on the system-register interface to the GIC. Needed before the
/// priority mask can be written, which the first lock does.
pub fn enable_system_registers() {
    // SAFETY: SRE (bit 0) selects the system-register interface that
    // GICv3 requires; bits 1 and 2 disable the legacy bypasses.
    unsafe { asm!("msr icc_sre_el1, {}", "isb", in(reg) 7u64, options(nomem, nostack)) };
}

/// Bring up the distributor and this processor's redistributor and
/// interface, with nothing enabled but what NK asks for.
pub fn init() -> Result<(), &'static str> {
    let controllers = &platform::get().controllers;
    if controllers.distributor == 0 {
        return Err("the MADT names no GIC distributor");
    }
    let distributor = mm::phys_to_virt(controllers.distributor) as u64;
    // Firmware may have left device interrupts enabled; nothing here
    // handles them yet.
    let lines = 32 * ((read32(distributor, GICD_TYPER) & 0x1F) + 1);
    for word in 1..lines / 32 {
        write32(distributor, GICD_ICENABLER + 4 * word as usize, u32::MAX);
    }
    write32(
        distributor,
        GICD_CTLR,
        GICD_CTLR_ARE_NS | GICD_CTLR_GROUP1NS,
    );

    // Urgent enough to interrupt anything that has not masked interrupts.
    LEVELS[STOP as usize].store(HIGH_LEVEL, Ordering::Relaxed);
    ENABLED.fetch_or(1 << STOP, Ordering::Relaxed);
    init_cpu(0)?;
    kprintln!("hal: GICv3, redistributor for affinity {:#x}", affinity());
    Ok(())
}

/// Bring up the redistributor and interface of the processor running
/// this code, which is processor `number`.
pub fn init_cpu(number: usize) -> Result<(), &'static str> {
    let redistributor = find_redistributor().ok_or("no GIC redistributor for a processor")?;
    // Wake the redistributor: clear ProcessorSleep, wait for
    // ChildrenAsleep to clear.
    write32(
        redistributor,
        GICR_WAKER,
        read32(redistributor, GICR_WAKER) & !(1 << 1),
    );
    let mut tries = 0;
    while read32(redistributor, GICR_WAKER) & 1 << 2 != 0 {
        tries += 1;
        if tries > 1_000_000 {
            return Err("the GIC redistributor did not wake");
        }
        core::hint::spin_loop();
    }
    // Private interrupts: all disabled (firmware's timer among them), all
    // in group 1, the group this interface takes as ordinary interrupts.
    write32(redistributor, SGI_ICENABLER0, u32::MAX);
    write32(redistributor, SGI_IGROUPR0, u32::MAX);

    // SAFETY: programming this processor's GIC interface: finest
    // priority grouping, group 1 enabled.
    unsafe {
        asm!(
            "msr icc_bpr1_el1, xzr",
            "msr icc_igrpen1_el1, {one}",
            "isb",
            one = in(reg) 1u64,
            options(nomem, nostack),
        );
    }
    // The mask must be able to tell every IRQL apart: write the mask for
    // the lowest level and see that it sticks.
    set_mask(0);
    let mask: u64;
    // SAFETY: reading the priority mask has no side effects.
    unsafe { asm!("mrs {}, icc_pmr_el1", out(reg) mask, options(nomem, nostack)) };
    if mask != u64::from(priority(0)) {
        return Err("the GIC implements too few priority levels for 16 IRQLs");
    }
    set_mask(super::cpu::irql());
    // What NK enabled before this processor ran.
    let enabled = ENABLED.load(Ordering::Relaxed);
    for vector in (0..PRIVATE).filter(|v| enabled & 1 << v != 0) {
        enable_on(redistributor, vector);
    }
    REDISTRIBUTORS[number].store(redistributor, Ordering::Release);
    Ok(())
}

/// Enable private interrupt `vector` in one processor's redistributor,
/// at the level recorded for it.
fn enable_on(redistributor: u64, vector: u32) {
    let level = LEVELS[vector as usize].load(Ordering::Relaxed);
    // One priority byte per interrupt.
    // SAFETY: a byte register of a redistributor.
    unsafe {
        ((redistributor as usize + SGI_IPRIORITYR + vector as usize) as *mut u8)
            .write_volatile(priority(level));
    }
    write32(redistributor, SGI_ISENABLER0, 1 << vector);
}

/// Enable private interrupt `vector` at IRQL `level`, on every processor
/// running and every one started later.
pub fn interrupt_enable(vector: u32, level: u8) {
    assert!(vector < PRIVATE, "only per-processor interrupts so far");
    LEVELS[vector as usize].store(level, Ordering::Relaxed);
    ENABLED.fetch_or(1 << vector, Ordering::Relaxed);
    for redistributor in &REDISTRIBUTORS {
        match redistributor.load(Ordering::Acquire) {
            0 => {}
            base => enable_on(base, vector),
        }
    }
}

/// Send software-generated interrupt `vector` to the processor with
/// MPIDR affinity `id`.
fn send(id: u64, vector: u32) {
    // Affinity levels 3..1 name a group of sixteen; the low bits list
    // the targets within it by their level-0 number.
    assert!(
        id & 0xFF < 16,
        "affinity level 0 above 15 needs a range selector"
    );
    let value = (id >> 32 & 0xFF) << 48
        | (id >> 16 & 0xFF) << 32
        | (id >> 8 & 0xFF) << 16
        | u64::from(vector) << 24
        | 1 << (id & 0xF);
    // SAFETY: generating an interrupt for a processor.
    unsafe { asm!("msr icc_sgi1r_el1, {}", "isb", in(reg) value, options(nomem, nostack)) };
}

/// Send software-generated interrupt `vector` to this processor.
pub fn self_interrupt(vector: u32) {
    send(super::platform::current_cpu_id(), vector);
}

/// Send software-generated interrupt `vector` to processor `number`.
pub fn send_interrupt(number: usize, vector: u32) {
    send(platform::get().cpus()[number].hw_id, vector);
}

/// Send every other running processor the interrupt that stops it. One
/// that has interrupts masked altogether does not take it.
pub fn stop_others() {
    let me = super::platform::current_cpu_id();
    for cpu in platform::get().cpus().iter().filter(|c| c.hw_id != me) {
        send(cpu.hw_id, STOP);
    }
}

/// An interrupt exception arrived. Called from the trap handler with
/// interrupts disabled.
pub fn interrupt() {
    let id: u64;
    // SAFETY: acknowledging takes the most urgent pending interrupt.
    unsafe { asm!("mrs {}, icc_iar1_el1", out(reg) id, options(nomem, nostack)) };
    let vector = id as u32 & 0xFF_FFFF;
    if vector >= SPURIOUS {
        return;
    }
    if vector == STOP && crate::kd::stopping() {
        // Another processor is stopping the system and said so.
        super::halt();
    }
    let level = LEVELS
        .get(vector as usize)
        .map_or(0, |l| l.load(Ordering::Relaxed));
    interrupt::dispatch(vector, level, || {
        // SAFETY: ends the interrupt acknowledged above.
        unsafe { asm!("msr icc_eoir1_el1, {}", "isb", in(reg) id, options(nomem, nostack)) };
    });
}

pub fn enable_interrupts() {
    // SAFETY: the vectors and the GIC are set up; interrupts above the
    // current IRQL may now arrive.
    unsafe { asm!("msr daifclr, #2", options(nomem, nostack)) };
}

pub fn disable_interrupts() {
    // SAFETY: masking interrupts touches no memory.
    unsafe { asm!("msr daifset, #2", options(nomem, nostack)) };
}
