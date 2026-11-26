//! x86-64 reading of the ACPI MADT: local APICs and I/O APICs.

use core::arch::x86_64::__cpuid_count;
pub use nk_hal::x86::{Controllers, usable_cpu};

/// Local APIC id of the processor running this code.
pub fn current_cpu_id() -> u64 {
    // Leaf 0xB reports the full 32-bit x2APIC id; where it is absent (its
    // EBX reads zero) leaf 1 has the 8-bit id.
    let basic = __cpuid_count(0, 0);
    if basic.eax >= 0xB {
        let topo = __cpuid_count(0xB, 0);
        if topo.ebx != 0 {
            return u64::from(topo.edx);
        }
    }
    u64::from(__cpuid_count(1, 0).ebx >> 24)
}

/// What else firmware says that x86-64 needs.
pub struct Firmware {
    /// The reference the time counter is calibrated against: the ACPI
    /// power-management timer, where the machine has one.
    pub pm_timer: Option<nk_acpi::PmTimer>,
    /// Physical address of the high precision event timer's registers,
    /// where the machine has one.
    pub hpet: Option<u64>,
}

/// Read it from the ACPI tables `find` returns.
pub fn firmware<'a>(find: impl Fn(&[u8; 4]) -> Option<&'a [u8]>) -> Firmware {
    Firmware {
        pm_timer: find(b"FACP").and_then(nk_acpi::pm_timer),
        hpet: find(b"HPET").and_then(nk_acpi::hpet),
    }
}
