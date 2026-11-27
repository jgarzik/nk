//! arm64.

mod atomic;
mod chkstk;
mod clock;
mod cpu;
mod device;
mod gic;
mod pci;
pub mod platform;
pub mod seh;
pub mod seh_test;
mod smp;
mod switch;
mod trap;
pub mod unwind;
mod variadic;

pub use atomic::swap_pair;
pub use chkstk::{chkstk_test, nk_chkstk};
pub use device::{
    InterruptVectors, TestSource as InterruptTestSource, acpi_device_interrupts, hal_hardware_id,
    interrupt_message, isa_line, level_line_polarity, line_enable, line_route, line_set,
};
pub use pci::{AML_FORBIDDEN_PORTS, PCI_PORTS, PciPorts, port_read, port_write};

pub use gic::{
    TEST_HIGH, TEST_LOW, TEST_STRAY, disable_interrupts, enable_interrupts,
    init as interrupts_init, interrupt_enable, interrupts_enabled, interrupts_off,
    interrupts_restore, self_interrupt, stop_others,
};

/// `(interrupt id, IRQL)` of the interrupt that runs a thread's kernel
/// APCs: APC_LEVEL.
pub const APC: (u32, u8) = (4, 1);

/// `(interrupt id, IRQL)` of the interrupt a processor sends itself to
/// run its deferred procedure calls: DISPATCH_LEVEL.
pub const DPC: (u32, u8) = (3, 2);

/// The interrupt model Windows' HAL reports to `acpi.sys`, which hands
/// it to the firmware's `_PIC` method: a version 3 GIC.
pub const INTERRUPT_MODEL: u32 = 3;

/// `(interrupt id, IRQL)` of the interprocessor interrupt.
pub const IPI: (u32, u8) = (1, 14);

/// Interrupt processor `number` on the interprocessor interrupt.
pub fn ipi_send(number: usize) {
    interrupt_processor(number, IPI.0);
}

/// Send processor `number` the software-generated interrupt `vector`.
pub fn interrupt_processor(number: usize, vector: u32) {
    gic::send_interrupt(number, vector);
}

pub use cpu::{current_thread, irql, pcr, percpu, percpu_of, prepare as cpu_prepare, set_irql};
pub use smp::{prepare as smp_prepare, start as cpu_start};
/// The hardware's own name for the processor running this code: its
/// MPIDR affinity, asked of the processor itself.
pub fn hardware_processor() -> u64 {
    platform::current_cpu_id()
}

pub use switch::{
    all_registers_survive, call_on_stack, callee_saved_survive, context_switch, new_context,
    wait_for_interrupt,
};
pub use trap::{breakpoint, breakpoints, driver_breakpoint, fp_trap_test};

use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use nk_bootinfo::{BootInfo, Serial};

pub const NAME: &str = "aarch64";

/// The diagnostic UART: an ARM PL011, as firmware left it set up.
pub struct Uart {
    base: *mut u32,
}

// SAFETY: the pointer names device registers, not shared Rust data; all
// access is volatile and serialised by the console lock.
unsafe impl Send for Uart {}

impl Uart {
    pub fn new(info: &BootInfo) -> Option<Self> {
        let base = (info.hhdm_base + info.serial.base) as *mut u32;
        (info.serial.kind == Serial::MMIO_PL011).then_some(Self { base })
    }

    pub fn put(&self, byte: u8) {
        const FLAGS: usize = 0x18 / 4;
        const TX_FULL: u32 = 1 << 5;
        // SAFETY: `base` is the PL011 register block, mapped as device
        // memory in the direct map; these are its data and flag registers.
        unsafe {
            while self.base.add(FLAGS).read_volatile() & TX_FULL != 0 {
                core::hint::spin_loop();
            }
            self.base.write_volatile(u32::from(byte));
        }
    }
}

/// Stop this CPU for good.
pub fn halt() -> ! {
    loop {
        // SAFETY: masking interrupts and waiting touches no memory.
        unsafe { core::arch::asm!("msr daifset, #0xf", "wfi", options(nomem, nostack)) }
    }
}

/// Continue on a new stack: call `entry(info)` with the stack pointer at
/// `top`. Whatever was on the old stack is abandoned.
pub fn switch_stack(
    top: u64,
    entry: extern "C" fn(&'static BootInfo) -> !,
    info: &'static BootInfo,
) -> ! {
    // SAFETY: `top` is the top of a mapped stack nothing else uses, 16-byte
    // aligned; with no frame or return address the entry starts a fresh
    // call chain.
    unsafe {
        core::arch::asm!(
            "mov sp, {top}",
            "mov x29, xzr",
            "mov x30, xzr",
            "br {entry}",
            top = in(reg) top,
            entry = in(reg) entry,
            in("x0") info,
            options(noreturn),
        )
    }
}

/// Nothing to undo once every processor is running.
pub fn smp_finish() {}

/// Record the kernel stack this processor now runs on. Nothing to do
/// here: exception entry recognises an overflow from the stack pointer.
pub fn set_kernel_stack(_base: u64) {}

/// Take over the boot CPU, processor 0: exception vectors, PCR. Prints
/// nothing and takes no lock: it runs before either works.
pub fn cpu_init() {
    trap::init();
    cpu::init(0);
}

/// Indices into firmware's `MAIR_EL1`, which the loader looked up.
static MAIR_NORMAL: AtomicU8 = AtomicU8::new(0);
static MAIR_DEVICE: AtomicU8 = AtomicU8::new(0);

pub fn mm_init(info: &BootInfo) {
    MAIR_NORMAL.store(info.mair_normal, Ordering::Relaxed);
    MAIR_DEVICE.store(info.mair_device, Ordering::Relaxed);
}

/// The low 16 bits of `TCR_EL1` describe the lower half of the address
/// space. NK's are what `nk_mm::pt` builds: 48-bit addresses, 4 KiB
/// pages, cacheable inner-shareable table walks. Firmware's own may
/// differ, so they are replaced along with its table.
const TCR_T0_MASK: u64 = 0xFFFF;
const TCR_T0: u64 = 16 | 1 << 8 | 1 << 10 | 3 << 12;

/// Physical address of the root of the low half's tables, once built.
static LOW_ROOT: AtomicU64 = AtomicU64::new(0);

/// Build NK's own low half and leave firmware's: a table holding only
/// the regions firmware's runtime services use, each at its physical
/// address. Code regions are writable too, because runtime driver
/// images mix code and data; device registers get device attributes.
/// Run once, on the boot processor, when memory can be allocated.
pub fn low_half_init() -> Result<(), &'static str> {
    use crate::mm::map::Tables;
    use nk_bootinfo::FirmwareUse;
    use nk_mm::pt::{Prot, TableMem};

    let root = Tables.alloc_table().ok_or("no memory for the low half")?;
    LOW_ROOT.store(root, Ordering::Relaxed);
    for (region, used_as) in crate::mm::firmware_regions() {
        let prot = match used_as {
            FirmwareUse::RuntimeCode => Prot::RWX,
            _ if region.is_ram() => Prot::RW,
            _ => Prot::DEVICE,
        };
        crate::mm::map::map(region.phys, region.phys, region.pages as usize, prot)
            .map_err(|_| "cannot map firmware's runtime regions")?;
    }
    adopt_low_half();
    Ok(())
}

/// Make NK's low half this processor's. The caller runs in the upper
/// half with interrupts masked, so nothing uses the lower one while the
/// table and its format change; stale translations are dropped.
pub fn adopt_low_half() {
    // SAFETY: per the above, and `LOW_ROOT` is a table in NK's format.
    unsafe {
        core::arch::asm!(
            "msr ttbr0_el1, {root}",
            "mrs {tcr}, tcr_el1",
            "bic {tcr}, {tcr}, {mask}",
            "orr {tcr}, {tcr}, {low}",
            "msr tcr_el1, {tcr}",
            "isb",
            "tlbi vmalle1",
            "dsb nsh",
            "isb",
            root = in(reg) LOW_ROOT.load(Ordering::Relaxed),
            tcr = out(reg) _,
            mask = in(reg) TCR_T0_MASK,
            low = in(reg) TCR_T0,
            options(nostack),
        );
    }
}

/// Physical address of the root of the table tree that translates `va`:
/// each half of the address space has its own.
pub fn pt_root_of(va: u64) -> u64 {
    if va >> 63 == 0 {
        LOW_ROOT.load(Ordering::Relaxed)
    } else {
        pt_root()
    }
}

/// Before a call into firmware's runtime code: nothing to do. The low
/// half of every processor holds the runtime regions at their physical
/// addresses.
pub fn firmware_enter() {}

/// After a firmware call that returned: nothing to undo.
pub fn firmware_leave() {}

/// Page-table entry encoding for this CPU.
pub fn pt_arch() -> nk_mm::pt::Aarch64 {
    nk_mm::pt::Aarch64 {
        mair_normal: MAIR_NORMAL.load(Ordering::Relaxed),
        mair_device: MAIR_DEVICE.load(Ordering::Relaxed),
    }
}

/// Physical address of the root of the kernel (TTBR1) page tables.
pub fn pt_root() -> u64 {
    let ttbr: u64;
    // SAFETY: reading TTBR1_EL1 has no side effects.
    unsafe { core::arch::asm!("mrs {}, ttbr1_el1", out(reg) ttbr, options(nomem, nostack)) };
    ttbr & 0x0000_FFFF_FFFF_F000
}

/// Drop any cached translation for the page at `va`, on every processor:
/// the instruction broadcasts. The table entry the caller just wrote is
/// made visible to the walkers first (`dsb ishst`): a walk after the
/// invalidation must not find the old entry and cache it again.
pub fn flush_tlb_page(va: u64) {
    // SAFETY: a barrier and TLB invalidation only order memory and
    // discard cached translations.
    unsafe {
        core::arch::asm!(
            "dsb ishst",
            "tlbi vaae1is, {}",
            "dsb ish",
            "isb",
            in(reg) va >> 12,
            options(nostack)
        );
    }
}

/// Make new mappings visible: a table write must be synchronised before
/// the mapping is used.
pub fn mapping_sync() {
    // SAFETY: barriers have no memory-safety effect.
    unsafe { core::arch::asm!("dsb ishst", "isb", options(nostack)) };
}

pub use clock::{CLOCK, calibrate as clock_calibrate, next as clock_next};

/// Start the clock interrupt, every `period` counter ticks.
pub fn clock_start(period: u64) {
    clock::start(period, crate::ke::time::frequency());
}

/// The time counter: the generic timer's virtual count.
pub fn counter() -> u64 {
    let count: u64;
    // SAFETY: reading the virtual counter touches no memory.
    unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) count, options(nomem, nostack)) };
    count
}

/// Make freshly written code executable: clean the data cache to the
/// point of unification for the written range, then drop every cached
/// instruction (the code will run from a different virtual address than
/// it was written through).
pub fn sync_icache(start: *const u8, len: usize) {
    // The smallest cache line the architecture allows; a larger real line
    // just means some redundant operations.
    const LINE: usize = 16;
    let end = start as usize + len;
    let mut addr = start as usize & !(LINE - 1);
    while addr < end {
        // SAFETY: cache maintenance on a mapped address has no
        // memory-safety effect.
        unsafe { core::arch::asm!("dc cvau, {}", in(reg) addr, options(nostack)) };
        addr += LINE;
    }
    // SAFETY: as above.
    unsafe { core::arch::asm!("dsb ish", "ic ialluis", "dsb ish", "isb", options(nostack)) };
}

/// Make memory hold what the data cache holds of a range, and drop
/// the cached lines, for a device that reads or writes the range
/// behind the processor's back.
pub fn sync_dcache(start: *const u8, len: usize) {
    // The smallest cache line the architecture allows.
    const LINE: usize = 16;
    let end = start as usize + len;
    let mut addr = start as usize & !(LINE - 1);
    while addr < end {
        // SAFETY: cache maintenance on a mapped address has no
        // memory-safety effect.
        unsafe { core::arch::asm!("dc civac, {}", in(reg) addr, options(nostack)) };
        addr += LINE;
    }
    // SAFETY: as above.
    unsafe { core::arch::asm!("dsb ish", options(nostack)) };
}
