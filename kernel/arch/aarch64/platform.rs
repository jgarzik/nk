//! arm64 reading of the ACPI MADT: the GIC.

use crate::hal::platform::{Cpu, MAX_CPUS};
use core::fmt;
use nk_acpi::{Madt, MadtEntry};

/// A stretch of redistributor frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Redistributors {
    pub address: u64,
    pub length: u64,
}

/// One GICv3 redistributor: two 64 KiB frames.
const REDISTRIBUTOR_SIZE: u64 = 0x2_0000;
/// The affinity fields of `MPIDR_EL1`: Aff3 and Aff2..Aff0.
const MPIDR_AFFINITY: u64 = 0xFF_00FF_FFFF;

/// Where the interrupt controllers are.
pub struct Controllers {
    /// Physical address of the GIC distributor.
    pub distributor: u64,
    /// GIC architecture version from the table; 0 means "ask the hardware".
    pub version: u8,
    /// Where redistributors may be: the table's regions, or one frame pair
    /// per processor when it lists them that way.
    redistributors: [Redistributors; MAX_CPUS],
    n_redistributors: usize,
}

impl Controllers {
    pub fn from_madt(madt: &Madt<'_>) -> Self {
        let mut c = Controllers {
            distributor: 0,
            version: 0,
            redistributors: [Redistributors {
                address: 0,
                length: 0,
            }; MAX_CPUS],
            n_redistributors: 0,
        };
        let add = |c: &mut Controllers, address, length| {
            if c.n_redistributors < MAX_CPUS {
                c.redistributors[c.n_redistributors] = Redistributors { address, length };
                c.n_redistributors += 1;
            }
        };
        // Regions take precedence: per-processor addresses are only used
        // by tables that have no region entries.
        for e in madt.entries() {
            match e {
                MadtEntry::Gicd { address, version } => {
                    (c.distributor, c.version) = (address, version);
                }
                MadtEntry::Gicr { address, length } => add(&mut c, address, u64::from(length)),
                _ => {}
            }
        }
        if c.n_redistributors == 0 {
            for e in madt.entries() {
                if let MadtEntry::Gicc {
                    enabled: true,
                    gicr_base,
                    ..
                } = e
                    && gicr_base != 0
                {
                    add(&mut c, gicr_base, REDISTRIBUTOR_SIZE);
                }
            }
        }
        c
    }

    pub fn redistributors(&self) -> &[Redistributors] {
        &self.redistributors[..self.n_redistributors]
    }
}

impl fmt::Display for Controllers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GICv{} distributor at {:#x}",
            self.version, self.distributor
        )?;
        for r in self.redistributors() {
            write!(f, ", redistributors at {:#x}+{:#x}", r.address, r.length)?;
        }
        Ok(())
    }
}

/// The processor a MADT entry describes, if it is one NK may start.
pub fn usable_cpu(entry: &MadtEntry) -> Option<Cpu> {
    match *entry {
        MadtEntry::Gicc {
            uid,
            mpidr,
            enabled: true,
            ..
        } => Some(Cpu {
            hw_id: mpidr & MPIDR_AFFINITY,
            uid,
        }),
        _ => None,
    }
}

/// MPIDR affinity of the processor running this code.
pub fn boot_cpu_id() -> u64 {
    let mpidr: u64;
    // SAFETY: reading an identification register has no side effects.
    unsafe { core::arch::asm!("mrs {}, mpidr_el1", out(reg) mpidr, options(nomem, nostack)) };
    mpidr & MPIDR_AFFINITY
}
