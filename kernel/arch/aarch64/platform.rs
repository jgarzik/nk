//! arm64 reading of the ACPI MADT: the GIC.

use crate::hal::platform::MAX_CPUS;
use nk_hal::arm::MPIDR_AFFINITY;
pub use nk_hal::arm::usable_cpu;

/// Where the interrupt controllers are (`nk_hal::arm`): room for one
/// stretch of redistributors per processor.
pub type Controllers = nk_hal::arm::Controllers<MAX_CPUS>;

/// MPIDR affinity of the processor running this code.
pub fn current_cpu_id() -> u64 {
    let mpidr: u64;
    // SAFETY: reading an identification register has no side effects.
    unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nomem, nostack)) };
    mpidr & MPIDR_AFFINITY
}

/// What else firmware says that arm64 needs.
pub struct Firmware {
    /// The interrupt of the generic timer's virtual timer, where firmware
    /// names one.
    pub virtual_timer: Option<u32>,
    /// How to ask firmware to start a processor.
    pub psci: Option<nk_acpi::Psci>,
}

/// Read it from the ACPI tables `find` returns.
pub fn firmware<'a>(find: impl Fn(&[u8; 4]) -> Option<&'a [u8]>) -> Firmware {
    Firmware {
        virtual_timer: find(b"GTDT").and_then(nk_acpi::virtual_timer_interrupt),
        psci: find(b"FACP").and_then(nk_acpi::psci),
    }
}
