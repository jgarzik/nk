//! x86-64.

mod apic;
mod clock;
mod cpu;
pub mod platform;
mod smp;
mod trap;

pub use apic::{
    TEST_HIGH, TEST_LOW, TEST_STRAY, disable_interrupts, enable_interrupts,
    init as interrupts_init, interrupt_enable, self_interrupt,
};

pub use cpu::{irql, pcr, percpu, percpu_of, prepare as cpu_prepare, set_irql, set_kernel_stack};
pub use smp::{finish as smp_finish, prepare as smp_prepare};
pub use trap::{breakpoint, breakpoints, fp_trap_test};

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
    // aligned; the 32 bytes are the callee's shadow space, and the call
    // leaves the stack as the convention requires at function entry.
    unsafe {
        core::arch::asm!(
            "mov rsp, {top}",
            "xor ebp, ebp",
            "sub rsp, 32",
            "call {entry}",
            "ud2",
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

/// `(vector, IRQL)` of the interprocessor interrupt: Windows' IPI_LEVEL.
pub const IPI: (u32, u8) = (0xE1, 14);

/// Interrupt processor `number` on the interprocessor vector.
pub fn ipi_send(number: usize) {
    apic::send_interrupt(smp::hardware_id(number) as u32, IPI.0);
}

/// Stop every other processor where it stands, interrupts off or not:
/// each takes a non-maskable interrupt and halts in its handler.
pub fn stop_others() {
    apic::send_nmi_to_others();
}

/// Wait for an interrupt. Interrupts must be enabled.
pub fn idle() {
    // SAFETY: `hlt` stops the processor until the next interrupt.
    unsafe { core::arch::asm!("hlt", options(nomem, nostack)) };
}

/// Take over the boot CPU, processor 0: descriptor tables, exception
/// vectors, PCR. Prints nothing and takes no lock: it runs before either
/// works.
pub fn cpu_init() {
    cpu::init(0);
    trap::init(cpu::KERNEL_CODE, cpu::FAULT_IST);
}

pub fn mm_init(_info: &BootInfo) {}

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
