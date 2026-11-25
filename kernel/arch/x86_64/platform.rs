//! x86-64 reading of the ACPI MADT: local APICs and I/O APICs.

use crate::hal::platform::Cpu;
use core::arch::x86_64::__cpuid_count;
use core::fmt;
use nk_acpi::{Madt, MadtEntry};

const MAX_IO_APICS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoApic {
    pub id: u8,
    pub address: u64,
    /// First global system interrupt this I/O APIC serves.
    pub gsi_base: u32,
}

/// Where the interrupt controllers are.
pub struct Controllers {
    /// Physical address of the local APIC registers (xAPIC mode).
    pub local_apic: u64,
    io_apics: [IoApic; MAX_IO_APICS],
    n_io_apics: usize,
}

impl Controllers {
    pub fn from_madt(madt: &Madt<'_>) -> Self {
        let mut c = Controllers {
            local_apic: u64::from(madt.local_apic),
            io_apics: [IoApic {
                id: 0,
                address: 0,
                gsi_base: 0,
            }; MAX_IO_APICS],
            n_io_apics: 0,
        };
        for e in madt.entries() {
            match e {
                MadtEntry::LocalApicAddress(address) => c.local_apic = address,
                MadtEntry::IoApic {
                    id,
                    address,
                    gsi_base,
                } if c.n_io_apics < MAX_IO_APICS => {
                    c.io_apics[c.n_io_apics] = IoApic {
                        id,
                        address: u64::from(address),
                        gsi_base,
                    };
                    c.n_io_apics += 1;
                }
                _ => {}
            }
        }
        c
    }

    pub fn io_apics(&self) -> &[IoApic] {
        &self.io_apics[..self.n_io_apics]
    }
}

impl fmt::Display for Controllers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "local APIC at {:#x}", self.local_apic)?;
        for io in self.io_apics() {
            write!(
                f,
                ", I/O APIC {} at {:#x} from GSI {}",
                io.id, io.address, io.gsi_base
            )?;
        }
        Ok(())
    }
}

/// The processor a MADT entry describes, if it is one NK may start.
pub fn usable_cpu(entry: &MadtEntry) -> Option<Cpu> {
    match *entry {
        MadtEntry::LocalApic {
            uid,
            id,
            enabled: true,
            ..
        } => Some(Cpu {
            hw_id: u64::from(id),
            uid,
        }),
        _ => None,
    }
}

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
}

/// Read it from the ACPI tables `find` returns.
pub fn firmware<'a>(find: impl Fn(&[u8; 4]) -> Option<&'a [u8]>) -> Firmware {
    Firmware {
        pm_timer: find(b"FACP").and_then(nk_acpi::pm_timer),
    }
}
