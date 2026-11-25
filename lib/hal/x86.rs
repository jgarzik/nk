//! x86-64: the local APIC and the I/O APICs.

use core::fmt;
use nk_acpi::{Cpu, Madt, MadtEntry};

/// The IRQL an interrupt vector runs at: its upper four bits, which is
/// also how the APIC itself ranks vectors.
pub const fn irql_of_vector(vector: u32) -> u8 {
    (vector >> 4) as u8
}

/// First of the MSRs an APIC in x2APIC mode is reached through.
const MSR_X2APIC: u32 = 0x800;

/// The MSR that is, in x2APIC mode, the register at offset `reg` of the
/// memory-mapped APIC: one MSR per 16-byte register.
pub const fn x2apic_msr(reg: u32) -> u32 {
    MSR_X2APIC + (reg >> 4)
}

/// The initial count that makes the APIC timer, which counts `rate`
/// times a second, interrupt every `period` ticks of a counter running
/// at `frequency` ticks per second. At least one, and at most what the
/// 32-bit register holds.
pub const fn timer_counts(period: u64, rate: u64, frequency: u64) -> u32 {
    let counts = period as u128 * rate as u128 / frequency as u128;
    if counts < 1 {
        1
    } else if counts > u32::MAX as u128 {
        u32::MAX
    } else {
        counts as u32
    }
}

/// How many I/O APICs are kept.
pub const MAX_IO_APICS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoApic {
    pub id: u8,
    pub address: u64,
    /// First global system interrupt this I/O APIC serves.
    pub gsi_base: u32,
}

/// Where the interrupt controllers are.
#[derive(Debug)]
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

#[cfg(test)]
mod tests {
    use super::*;

    use crate::table;
    use nk_acpi::madt;

    fn controllers(local_apic: u32, entries: &[Vec<u8>]) -> Controllers {
        let bytes = table::madt(local_apic, entries);
        Controllers::from_madt(&madt(&bytes).expect("a well-formed MADT"))
    }

    #[test]
    fn the_local_apic_and_the_io_apics_come_from_the_table() {
        let c = controllers(
            0xFEE0_0000,
            &[
                table::local_apic(0, 0, 1),
                table::io_apic(7, 0xFEC0_0000, 0),
                table::local_apic(1, 1, 1),
                table::io_apic(8, 0xFEC0_1000, 24),
            ],
        );
        assert_eq!(c.local_apic, 0xFEE0_0000);
        assert_eq!(
            c.io_apics(),
            [
                IoApic {
                    id: 7,
                    address: 0xFEC0_0000,
                    gsi_base: 0
                },
                IoApic {
                    id: 8,
                    address: 0xFEC0_1000,
                    gsi_base: 24
                },
            ]
        );
        assert_eq!(
            c.to_string(),
            "local APIC at 0xfee00000, I/O APIC 7 at 0xfec00000 from GSI 0, \
             I/O APIC 8 at 0xfec01000 from GSI 24"
        );
    }

    #[test]
    fn a_64_bit_local_apic_address_replaces_the_header_s() {
        let c = controllers(
            0xFEE0_0000,
            &[
                table::local_apic(0, 0, 1),
                table::local_apic_address(0x1_FEE0_0000),
            ],
        );
        assert_eq!(c.local_apic, 0x1_FEE0_0000);
        assert!(c.io_apics().is_empty());
        assert_eq!(c.to_string(), "local APIC at 0x1fee00000");
    }

    #[test]
    fn io_apics_beyond_the_eighth_are_left_out() {
        let entries: Vec<_> = (0..10u8)
            .map(|n| table::io_apic(n, 0xFEC0_0000 + u32::from(n) * 0x1000, u32::from(n) * 24))
            .collect();
        let c = controllers(0xFEE0_0000, &entries);
        assert_eq!(c.io_apics().len(), MAX_IO_APICS);
        assert_eq!(c.io_apics()[7].id, 7);
        // An entry after the ones left out is still read.
        let mut entries = entries;
        entries.push(table::local_apic_address(0x2_0000_0000));
        assert_eq!(controllers(0, &entries).local_apic, 0x2_0000_0000);
    }

    #[test]
    fn a_usable_processor_is_an_enabled_local_apic() {
        let cpu = |uid, id, enabled, online_capable| MadtEntry::LocalApic {
            uid,
            id,
            enabled,
            online_capable,
        };
        assert_eq!(
            usable_cpu(&cpu(3, 5, true, false)),
            Some(Cpu { hw_id: 5, uid: 3 })
        );
        // An x2APIC id does not fit eight bits.
        assert_eq!(
            usable_cpu(&cpu(9, 0x1_0000, true, false)),
            Some(Cpu {
                hw_id: 0x1_0000,
                uid: 9
            })
        );
        // Not enabled: not started, even if it could be brought online.
        assert_eq!(usable_cpu(&cpu(3, 5, false, false)), None);
        assert_eq!(usable_cpu(&cpu(3, 5, false, true)), None);
        assert_eq!(
            usable_cpu(&MadtEntry::IoApic {
                id: 0,
                address: 0xFEC0_0000,
                gsi_base: 0
            }),
            None
        );
        assert_eq!(
            usable_cpu(&MadtEntry::Gicc {
                uid: 0,
                mpidr: 0,
                enabled: true,
                gicr_base: 0
            }),
            None
        );
    }

    #[test]
    fn the_processors_of_a_table_are_its_enabled_ones_in_order() {
        let bytes = table::madt(
            0xFEE0_0000,
            &[
                table::local_apic(0, 0, 1),
                table::local_apic(1, 2, 0),
                table::io_apic(7, 0xFEC0_0000, 0),
                table::x2apic(0x1_0000, 1, 9),
                table::local_apic(3, 6, 2),
            ],
        );
        let ids: Vec<_> = madt(&bytes)
            .unwrap()
            .entries()
            .filter_map(|e| usable_cpu(&e))
            .map(|c| (c.uid, c.hw_id))
            .collect();
        assert_eq!(ids, [(0, 0), (9, 0x1_0000)]);
    }

    #[test]
    fn a_vector_runs_at_the_irql_in_its_upper_four_bits() {
        // The vectors NK uses: clock, DPC, the test interrupts.
        assert_eq!(irql_of_vector(0xD1), 13);
        assert_eq!(irql_of_vector(0x51), 5);
        assert_eq!(irql_of_vector(0x71), 7);
        assert_eq!(irql_of_vector(0x2F), 2);
        assert_eq!(irql_of_vector(0x20), 2);
        assert_eq!(irql_of_vector(0xFF), 15);
        assert_eq!(irql_of_vector(0x0F), 0);
    }

    #[test]
    fn an_x2apic_register_is_the_msr_for_its_offset() {
        // Values from the Intel manual's table of x2APIC MSRs.
        assert_eq!(x2apic_msr(0x020), 0x802); // id
        assert_eq!(x2apic_msr(0x0B0), 0x80B); // end of interrupt
        assert_eq!(x2apic_msr(0x0F0), 0x80F); // spurious vector
        assert_eq!(x2apic_msr(0x300), 0x830); // interrupt command
        assert_eq!(x2apic_msr(0x320), 0x832); // timer vector
        assert_eq!(x2apic_msr(0x380), 0x838); // timer initial count
        assert_eq!(x2apic_msr(0x3E0), 0x83E); // timer divide
    }

    #[test]
    fn the_timer_counts_a_period_at_its_own_rate() {
        // A 3 GHz counter, 64 Hz clock: 46,875,000 counter ticks. An
        // APIC timer at 62.5 MHz counts 976,562 in that time (and a
        // half, which is dropped).
        assert_eq!(timer_counts(46_875_000, 62_500_000, 3_000_000_000), 976_562);
        // The same rate as the counter: the period itself.
        assert_eq!(timer_counts(12_345, 1_000_000, 1_000_000), 12_345);
        // Half the rate, half the counts.
        assert_eq!(timer_counts(1000, 500, 1000), 500);
    }

    #[test]
    fn the_timer_never_counts_from_zero() {
        // A zero count stops the timer; a period too short for the
        // timer to resolve becomes its shortest.
        assert_eq!(timer_counts(1, 1, 1_000_000), 1);
        assert_eq!(timer_counts(0, 1_000_000, 1_000_000), 1);
        // An uncalibrated timer (rate zero) does not divide by anything
        // it should not, and still runs.
        assert_eq!(timer_counts(1000, 0, 1_000_000), 1);
    }

    #[test]
    fn the_timer_count_stops_at_what_its_register_holds() {
        assert_eq!(timer_counts(u64::from(u32::MAX), 1, 1), u32::MAX);
        assert_eq!(timer_counts(u64::from(u32::MAX) + 1, 1, 1), u32::MAX);
        // A product past 64 bits is still computed, then clamped.
        assert_eq!(timer_counts(u64::MAX, u64::MAX, 1), u32::MAX);
        assert_eq!(timer_counts(u64::MAX, u64::MAX, u64::MAX), u32::MAX);
        assert_eq!(timer_counts(u64::MAX, 1 << 31, u64::MAX), 1 << 31);
    }
}
