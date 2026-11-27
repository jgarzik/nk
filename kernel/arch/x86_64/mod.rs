//! x86-64.

mod apic;
mod atomic;
mod chkstk;
mod clock;
mod cpu;
mod ioapic;
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
pub use ioapic::{
    InterruptVectors, TestSource as InterruptTestSource, acpi_device_interrupts, hal_hardware_id,
    interrupt_message, isa_line, level_line_polarity, line_enable, line_route, line_set,
};
pub use pci::{AML_FORBIDDEN_PORTS, PCI_PORTS, PciPorts, port_read, port_write};

pub use apic::{
    TEST_HIGH, TEST_LOW, TEST_STRAY, disable_interrupts, enable_interrupts,
    init as interrupts_init, interrupt_enable, interrupts_off, interrupts_restore, self_interrupt,
};

pub use cpu::{
    current_thread, irql, pcr, percpu, percpu_of, prepare as cpu_prepare, set_irql,
    set_kernel_stack,
};
pub use smp::{finish as smp_finish, prepare as smp_prepare};
/// The hardware's own name for the processor running this code: its
/// local APIC id, asked of the processor itself.
pub fn hardware_processor() -> u64 {
    platform::current_cpu_id()
}

pub use switch::{
    all_registers_survive, call_on_stack, callee_saved_survive, context_switch, new_context,
    wait_for_interrupt,
};
pub use trap::{breakpoint, breakpoints, driver_breakpoint, fp_trap_test};

use nk_bootinfo::{BootInfo, Serial};

pub const NAME: &str = "x86_64";

fn outb(port: u16, value: u8) {
    // SAFETY: only called on the diagnostic UART's ports, where a byte
    // write has no memory-safety effect.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack))
    }
}

fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: as in `outb`; reading a UART status port is side-effect free.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack))
    }
    value
}

/// The diagnostic UART: a 16550 on I/O ports, as firmware left it set up.
pub struct Uart {
    port: u16,
}

impl Uart {
    pub fn new(info: &BootInfo) -> Option<Self> {
        (info.serial.kind == Serial::PORT_16550).then_some(Self {
            port: info.serial.base as u16,
        })
    }

    pub fn put(&self, byte: u8) {
        const LINE_STATUS: u16 = 5;
        const TX_EMPTY: u8 = 0x20;
        while inb(self.port + LINE_STATUS) & TX_EMPTY == 0 {
            core::hint::spin_loop();
        }
        outb(self.port, byte);
    }
}

/// Stop this CPU for good.
pub fn halt() -> ! {
    loop {
        // SAFETY: disabling interrupts and halting touches no memory.
        unsafe { core::arch::asm!("cli", "hlt", options(nomem, nostack)) }
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
    // aligned; the 32 bytes are the callee's shadow space, and the push
    // leaves the stack as the convention requires at function entry. The
    // return address pushed is zero: `entry` never returns, and a walk of
    // the new stack ends there.
    unsafe {
        core::arch::asm!(
            "mov rsp, {top}",
            "xor ebp, ebp",
            "sub rsp, 32",
            "push 0",
            "jmp {entry}",
            top = in(reg) top,
            entry = in(reg) entry,
            in("rcx") info,
            options(noreturn),
        )
    }
}

/// Wake processor `number` to run on the stack ending at `stack_top`.
pub fn cpu_start(number: usize, stack_top: u64) -> Result<(), &'static str> {
    smp::start(number, smp::hardware_id(number), stack_top);
    Ok(())
}

/// `(vector, IRQL)` of the interrupt a processor sends itself to run its
/// deferred procedure calls: DISPATCH_LEVEL.
pub const DPC: (u32, u8) = (0x2F, 2);

/// The interrupt model Windows' HAL reports to `acpi.sys`, which hands
/// it to the firmware's `_PIC` method: the APIC.
pub const INTERRUPT_MODEL: u32 = 1;

/// `(vector, IRQL)` of the interprocessor interrupt: Windows' IPI_LEVEL.
pub const IPI: (u32, u8) = (0xE1, 14);

/// Interrupt processor `number` on the interprocessor vector.
pub fn ipi_send(number: usize) {
    interrupt_processor(number, IPI.0);
}

/// Interrupt processor `number` on `vector`.
pub fn interrupt_processor(number: usize, vector: u32) {
    apic::send_interrupt(smp::hardware_id(number) as u32, vector);
}

/// Stop every other processor where it stands, interrupts off or not:
/// each takes a non-maskable interrupt and halts in its handler.
pub fn stop_others() {
    apic::send_nmi_to_others();
}

/// Take over the boot CPU, processor 0: descriptor tables, exception
/// vectors, PCR. Prints nothing and takes no lock: it runs before either
/// works.
pub fn cpu_init() {
    cpu::init(0);
    trap::init(cpu::KERNEL_CODE, cpu::FAULT_IST);
}

pub fn mm_init(_info: &BootInfo) {}

/// The low half is already NK's own: nkload built it, in the one table
/// tree, holding firmware's runtime regions and nothing else.
pub fn low_half_init() -> Result<(), &'static str> {
    Ok(())
}

/// Physical address of the root of the table tree that translates `va`:
/// one tree holds both halves.
pub fn pt_root_of(_va: u64) -> u64 {
    pt_root()
}

/// Before a call into firmware's runtime code: nothing to do. Its
/// regions are identity-mapped in the low half of the one address space
/// every processor runs on.
pub fn firmware_enter() {}

/// After a firmware call that returned: nothing to undo.
pub fn firmware_leave() {}

/// Page-table entry encoding for this CPU.
pub fn pt_arch() -> nk_mm::pt::X86_64 {
    nk_mm::pt::X86_64
}

/// Physical address of the root page table.
pub fn pt_root() -> u64 {
    let cr3: u64;
    // SAFETY: reading CR3 has no side effects.
    unsafe { core::arch::asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack)) };
    cr3 & 0x000F_FFFF_FFFF_F000
}

/// Drop any cached translation for the page at `va`, on every processor:
/// each has to be asked.
pub fn flush_tlb_page(va: u64) {
    crate::ke::ipi::call_all(flush_local, va as usize);
}

fn flush_local(va: usize) {
    // SAFETY: invlpg only discards a TLB entry.
    unsafe { core::arch::asm!("invlpg [{}]", in(reg) va, options(nostack)) };
}

/// Make new mappings visible. x86 needs nothing after adding an entry.
pub fn mapping_sync() {}

pub use clock::{CLOCK, calibrate as clock_calibrate, next as clock_next};

/// Start the clock interrupt, every `period` counter ticks.
pub fn clock_start(period: u64) {
    clock::start(period, crate::ke::time::frequency());
}

/// The time counter: the processor's time-stamp counter.
pub fn counter() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: rdtsc reads a counter and touches no memory.
    unsafe { core::arch::asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack)) };
    u64::from(hi) << 32 | u64::from(lo)
}

/// Make freshly written code executable. x86 keeps instruction and data
/// caches coherent by itself.
pub fn sync_icache(_start: *const u8, _len: usize) {}

/// Make memory hold what the data cache holds of a range, for a
/// device that reads or writes it behind the processor's back. A
/// device's access on this architecture goes through the caches.
pub fn sync_dcache(_start: *const u8, _len: usize) {}
