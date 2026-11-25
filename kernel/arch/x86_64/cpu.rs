//! Per-CPU processor state: segment tables, task state segment, and the
//! processor control region that drivers reach through GS.
//!
//! Selector values follow Windows (kernel code 0x10, data 0x18, TSS 0x40).
//! Drivers do not depend on them, but debuggers and crash dumps read more
//! naturally when they match.

use core::cell::UnsafeCell;
use nk_ntabi::pcr::NATIVE as PCR;

const PCR_SIZE: usize = PCR.size;

pub const KERNEL_CODE: u16 = 0x10;
const KERNEL_DATA: u16 = 0x18;
const TSS_SELECTOR: u16 = 0x40;
/// Interrupt-stack-table slot for faults that cannot trust the stack.
pub const FAULT_IST: u8 = 1;
const FAULT_STACK_SIZE: usize = 0x4000;
const MSR_GS_BASE: u32 = 0xC000_0101;

/// Operand of `lgdt`/`lidt`.
#[repr(C, packed)]
pub struct TablePointer {
    pub limit: u16,
    pub base: u64,
}

/// The 64-bit task state segment. Only the interrupt stacks are used.
#[repr(C, packed)]
struct Tss {
    reserved0: u32,
    rsp: [u64; 3],
    reserved1: u64,
    ist: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    io_map_base: u16,
}

/// Everything one CPU owns. Page aligned so the PCR is too.
#[repr(C, align(4096))]
struct CpuArea {
    /// KPCR followed by KPRCB; GS points here.
    pcr: [u8; PCR_SIZE],
    /// Stand-in for the current thread object. There are no threads yet,
    /// but `KeGetCurrentThread()` must return a stable non-null pointer.
    thread: [u8; 4096],
    fault_stack: [u8; FAULT_STACK_SIZE],
    gdt: [u64; 10],
    tss: Tss,
}

struct Shared(UnsafeCell<CpuArea>);

// SAFETY: each CPU touches only its own area; the boot CPU initialises
// this one before anything else can observe it.
unsafe impl Sync for Shared {}

static BOOT_CPU: Shared = Shared(UnsafeCell::new(CpuArea {
    pcr: [0; PCR_SIZE],
    thread: [0; 4096],
    fault_stack: [0; FAULT_STACK_SIZE],
    gdt: [0; 10],
    tss: Tss {
        reserved0: 0,
        rsp: [0; 3],
        reserved1: 0,
        ist: [0; 7],
        reserved2: 0,
        reserved3: 0,
        io_map_base: size_of::<Tss>() as u16,
    },
}));

/// Load this CPU's GDT, TSS and PCR, and record that it is processor
/// `number`. Boot CPU only for now.
pub fn init(number: u32) {
    let area = BOOT_CPU.0.get();
    // SAFETY: single-threaded early boot: this is the only reference to
    // the boot CPU's area, and the pointers written stay valid forever
    // because the area is static.
    unsafe {
        let pcr = (&raw mut (*area).pcr).cast::<u8>();
        let tss = &raw mut (*area).tss;
        (*tss).ist[usize::from(FAULT_IST) - 1] =
            (&raw mut (*area).fault_stack) as u64 + FAULT_STACK_SIZE as u64;

        let tss_base = tss as u64;
        let gdt = &mut (*area).gdt;
        gdt[usize::from(KERNEL_CODE) / 8] = 0x0020_9B00_0000_0000; // 64-bit code, ring 0
        gdt[usize::from(KERNEL_DATA) / 8] = 0x0000_9300_0000_0000; // data, ring 0
        gdt[usize::from(TSS_SELECTOR) / 8] = (size_of::<Tss>() as u64 - 1)
            | (tss_base & 0xFF_FFFF) << 16
            | 0x89 << 40 // present, available 64-bit TSS
            | (tss_base >> 24 & 0xFF) << 56;
        gdt[usize::from(TSS_SELECTOR) / 8 + 1] = tss_base >> 32;

        pcr.add(PCR.self_ptr).cast::<u64>().write(pcr as u64);
        pcr.add(PCR.current_prcb)
            .cast::<u64>()
            .write(pcr.add(PCR.prcb) as u64);
        pcr.add(PCR.current_thread)
            .cast::<u64>()
            .write((&raw mut (*area).thread) as u64);
        pcr.add(PCR.number).cast::<u32>().write(number);
        if let Some(legacy) = PCR.legacy_number {
            // One byte: enough for the 64 processors of a group.
            pcr.add(legacy).write(number as u8);
        }

        // Drivers use SSE, and the trap entry saves it: make sure it is
        // on. CR0: no emulation, monitor the coprocessor, no lazy
        // switching. CR4: FXSAVE and SSE exceptions enabled.
        core::arch::asm!(
            "mov {t}, cr0",
            "and {t}, {cr0_clear}",
            "or {t}, 2",
            "mov cr0, {t}",
            "mov {t}, cr4",
            "or {t}, 0x600",
            "mov cr4, {t}",
            t = out(reg) _,
            cr0_clear = const !0xCu64,
            options(nomem, nostack),
        );

        let pointer = TablePointer {
            limit: (size_of::<[u64; 10]>() - 1) as u16,
            base: gdt.as_ptr() as u64,
        };
        // Load the GDT, reload CS with a far return, then the data
        // segments and the task register. Loading GS clears its base, so
        // the PCR base is written last. CR8 = 0 is IRQL PASSIVE_LEVEL.
        core::arch::asm!(
            "lgdt [{ptr}]",
            "push {code}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ds, {data:x}",
            "mov es, {data:x}",
            "mov ss, {data:x}",
            "xor {tmp:e}, {tmp:e}",
            "mov fs, {tmp:x}",
            "mov gs, {tmp:x}",
            "ltr {tss:x}",
            "mov cr8, {tmp}",
            ptr = in(reg) &raw const pointer,
            code = in(reg) u64::from(KERNEL_CODE),
            data = in(reg) u64::from(KERNEL_DATA),
            tss = in(reg) u64::from(TSS_SELECTOR),
            tmp = out(reg) _,
        );
        core::arch::asm!(
            "wrmsr",
            in("ecx") MSR_GS_BASE,
            in("eax") pcr as u64 as u32,
            in("edx") (pcr as u64 >> 32) as u32,
            options(nomem, nostack),
        );
    }
}

/// This CPU's PCR, read back through GS the way a driver would find it.
pub fn pcr() -> *mut u8 {
    let pcr: u64;
    // SAFETY: GS points at the PCR once `init` has run; this loads its
    // self pointer.
    unsafe {
        core::arch::asm!("mov {}, gs:[{}]", out(reg) pcr, const PCR.self_ptr, options(readonly, nostack))
    };
    pcr as *mut u8
}
