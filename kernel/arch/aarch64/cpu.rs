//! Per-CPU processor state: the processor control region that drivers
//! reach through register x18.
//!
//! Windows reserves x18 in kernel mode for the KPCR, and drivers load
//! from it directly. Rust's UEFI targets never use x18 either, so setting
//! it once per CPU is enough: nothing NK compiles will disturb it.

use core::cell::UnsafeCell;
use nk_ntabi::pcr::{NATIVE as PCR, PCR_SIZE};

/// Everything one CPU owns. Page aligned so the PCR is too.
#[repr(C, align(4096))]
struct CpuArea {
    /// KPCR followed by KPRCB; x18 points here.
    pcr: [u8; PCR_SIZE],
    /// Stand-in for the current thread object. There are no threads yet,
    /// but `KeGetCurrentThread()` must return a stable non-null pointer.
    thread: [u8; 4096],
}

struct Shared(UnsafeCell<CpuArea>);

// SAFETY: each CPU touches only its own area; the boot CPU initialises
// this one before anything else can observe it.
unsafe impl Sync for Shared {}

static BOOT_CPU: Shared = Shared(UnsafeCell::new(CpuArea {
    pcr: [0; PCR_SIZE],
    thread: [0; 4096],
}));

/// Point x18 at this CPU's PCR. Boot CPU only for now.
pub fn init() {
    let area = BOOT_CPU.0.get();
    // SAFETY: single-threaded early boot: this is the only reference to
    // the boot CPU's area, which is static, so the pointers stay valid.
    // x18 is reserved on this target; writing it cannot clobber compiler
    // state. TPIDR_EL1 holds the same pointer so exception entry can
    // restore x18 if a driver ever corrupts it.
    unsafe {
        let pcr = (&raw mut (*area).pcr).cast::<u8>();
        pcr.add(PCR.self_ptr).cast::<u64>().write(pcr as u64);
        pcr.add(PCR.current_prcb)
            .cast::<u64>()
            .write(pcr.add(PCR.prcb) as u64);
        pcr.add(PCR.current_thread)
            .cast::<u64>()
            .write((&raw mut (*area).thread) as u64);
        core::arch::asm!("msr tpidr_el1, {0}", "mov x18, {0}", in(reg) pcr as u64, options(nomem, nostack));
    }
}

/// This CPU's PCR, read back through x18 the way a driver would find it.
pub fn pcr() -> *mut u8 {
    let pcr: u64;
    // SAFETY: x18 points at the PCR once `init` has run; this loads its
    // self pointer.
    unsafe {
        core::arch::asm!("ldr {}, [x18, #{}]", out(reg) pcr, const PCR.self_ptr, options(readonly, nostack))
    };
    pcr as *mut u8
}
