//! x86-64: the local APIC and the I/O APICs.

use crate::interrupt::{Line, Polarity, Trigger};
use core::fmt;
use nk_acpi::{Cpu, Madt, MadtEntry, Signal, SourceOverride};

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
    /// The interrupt source override of each ISA interrupt that has one.
    overrides: [Option<SourceOverride>; ISA_INTERRUPTS],
}

/// How many ISA interrupts there are.
const ISA_INTERRUPTS: usize = 16;

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
            overrides: [None; ISA_INTERRUPTS],
        };
        for o in madt.source_overrides() {
            if let Some(slot) = c.overrides.get_mut(usize::from(o.source)) {
                *slot = Some(o);
            }
        }
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

    /// The line ISA interrupt `irq` (0 to 15) arrives on. Without an
    /// interrupt source override that is the global system interrupt of
    /// the same number, signalling as the ISA bus does: edge triggered,
    /// active high. An override names another, or another way of
    /// signalling.
    pub fn isa_line(&self, irq: u8) -> Option<Line> {
        let over = self.overrides.get(usize::from(irq))?;
        Some(match over {
            None => Line {
                gsi: u32::from(irq),
                trigger: Trigger::Edge,
                polarity: Polarity::High,
            },
            Some(o) => Line {
                gsi: o.gsi,
                trigger: match o.trigger {
                    Signal::LowOrLevel => Trigger::Level,
                    Signal::BusDefault | Signal::HighOrEdge => Trigger::Edge,
                },
                polarity: match o.polarity {
                    Signal::LowOrLevel => Polarity::Low,
                    Signal::BusDefault | Signal::HighOrEdge => Polarity::High,
                },
            },
        })
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

/// The redirection-table register of an I/O APIC input, low half: the
/// interrupt arrives on `vector`, fixed delivery to one processor named
/// by its APIC id. Bit 13 is the polarity (set: active low), bit 15 the
/// trigger (set: level), bit 16 the mask.
pub const fn redirection(vector: u32, trigger: Trigger, polarity: Polarity, masked: bool) -> u32 {
    (vector & 0xFF)
        | (matches!(polarity, Polarity::Low) as u32) << 13
        | (matches!(trigger, Trigger::Level) as u32) << 15
        | (masked as u32) << 16
}

/// The mask bit of a redirection-table register.
pub const REDIRECTION_MASKED: u32 = 1 << 16;

/// The high half of a redirection-table register: the APIC id of the
/// processor the interrupt goes to. `None` for an id the eight-bit field
/// cannot name (or that means "all").
pub const fn redirection_target(apic_id: u64) -> Option<u32> {
    if apic_id < 0xFF {
        Some((apic_id as u32) << 24)
    } else {
        None
    }
}

/// How many inputs an I/O APIC has, from its version register.
pub const fn io_apic_inputs(version: u32) -> u32 {
    (version >> 16 & 0xFF) + 1
}

/// The message a device sends to interrupt the processor with APIC id
/// `apic_id` on `vector`: the address it writes to and the data it
/// writes (Intel SDM volume 3, "Message Signalled Interrupts"): fixed
/// delivery, edge, physical destination. `None` for an APIC id the
/// eight-bit destination field cannot name.
pub const fn message(vector: u32, apic_id: u64) -> Option<(u64, u32)> {
    if apic_id < 0xFF {
        Some((0xFEE0_0000 | apic_id << 12, vector & 0xFF))
    } else {
        None
    }
}

/// The vectors device interrupts may have: IRQL 3 to 11, sixteen each.
pub const DEVICE_VECTORS: core::ops::Range<u32> = 0x30..0xC0;

/// Which device vectors are in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorMap {
    /// A bit per vector, by number.
    used: [u64; 4],
}

impl Default for VectorMap {
    fn default() -> Self {
        Self::new()
    }
}

impl VectorMap {
    /// Every device vector free.
    pub const fn new() -> Self {
        Self { used: [0; 4] }
    }

    fn is_used(&self, vector: u32) -> bool {
        self.used[(vector / 64) as usize] & 1 << (vector % 64) != 0
    }

    fn set(&mut self, vector: u32, used: bool) {
        let (word, bit) = ((vector / 64) as usize, 1u64 << (vector % 64));
        if used {
            self.used[word] |= bit;
        } else {
            self.used[word] &= !bit;
        }
    }

    /// Keep `vector` from being handed out: something else uses it.
    pub fn reserve(&mut self, vector: u32) {
        if DEVICE_VECTORS.contains(&vector) {
            self.set(vector, true);
        }
    }

    /// Take `count` consecutive vectors of one IRQL, the first a
    /// multiple of `count`, which is what a device that sends several
    /// messages needs: it adds the message number to the low bits.
    /// `count` is a power of two, at most 16. Successive requests are
    /// spread over the IRQLs, lowest first. Returns the first vector.
    pub fn take(&mut self, count: u32) -> Option<u32> {
        if !count.is_power_of_two() || count > 16 {
            return None;
        }
        let classes = || DEVICE_VECTORS.step_by(16);
        let first = (0..16).step_by(count as usize).find_map(|offset| {
            classes()
                .map(|class| class + offset)
                .find(|&first| (first..first + count).all(|v| !self.is_used(v)))
        })?;
        for vector in first..first + count {
            self.set(vector, true);
        }
        Some(first)
    }

    /// Give back `count` vectors from [`take`](Self::take).
    pub fn give_back(&mut self, first: u32, count: u32) {
        for vector in first..first.saturating_add(count) {
            if DEVICE_VECTORS.contains(&vector) {
                self.set(vector, false);
            }
        }
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

    fn iso(source: u8, gsi: u32, flags: u16) -> Vec<u8> {
        let mut e = vec![2, 10, 0, source];
        e.extend_from_slice(&gsi.to_le_bytes());
        e.extend_from_slice(&flags.to_le_bytes());
        e
    }

    #[test]
    fn an_isa_interrupt_arrives_where_the_overrides_say() {
        // QEMU's table: the timer on GSI 2, and four lines level
        // triggered, active high.
        let c = controllers(
            0xFEE0_0000,
            &[
                table::io_apic(0, 0xFEC0_0000, 0),
                iso(0, 2, 0),
                iso(5, 5, 0b1101),
                iso(9, 9, 0b1101),
                iso(10, 10, 0b1111),
                iso(200, 3, 0b1111), // not an ISA interrupt
            ],
        );
        let line = |gsi, trigger, polarity| {
            Some(Line {
                gsi,
                trigger,
                polarity,
            })
        };
        assert_eq!(c.isa_line(0), line(2, Trigger::Edge, Polarity::High));
        assert_eq!(c.isa_line(5), line(5, Trigger::Level, Polarity::High));
        assert_eq!(c.isa_line(9), line(9, Trigger::Level, Polarity::High));
        assert_eq!(c.isa_line(10), line(10, Trigger::Level, Polarity::Low));
        // No override: the same number, edge triggered, active high.
        assert_eq!(c.isa_line(1), line(1, Trigger::Edge, Polarity::High));
        assert_eq!(c.isa_line(3), line(3, Trigger::Edge, Polarity::High));
        assert_eq!(c.isa_line(15), line(15, Trigger::Edge, Polarity::High));
        assert_eq!(c.isa_line(16), None);
    }

    #[test]
    fn a_redirection_entry_holds_vector_polarity_trigger_and_mask() {
        assert_eq!(
            redirection(0x51, Trigger::Edge, Polarity::High, false),
            0x51
        );
        assert_eq!(
            redirection(0x51, Trigger::Level, Polarity::High, false),
            0x8051
        );
        assert_eq!(
            redirection(0x51, Trigger::Level, Polarity::Low, false),
            0xA051
        );
        assert_eq!(
            redirection(0xB3, Trigger::Edge, Polarity::Low, true),
            0x1_20B3
        );
        assert_eq!(
            redirection(0x51, Trigger::Edge, Polarity::High, true) & REDIRECTION_MASKED,
            REDIRECTION_MASKED
        );
        assert_eq!(redirection_target(0), Some(0));
        assert_eq!(redirection_target(3), Some(0x0300_0000));
        assert_eq!(redirection_target(0xFE), Some(0xFE00_0000));
        assert_eq!(redirection_target(0xFF), None);
        assert_eq!(redirection_target(0x100), None);
        // QEMU's I/O APIC: version 0x20, 24 inputs.
        assert_eq!(io_apic_inputs(0x0017_0020), 24);
        assert_eq!(io_apic_inputs(0), 1);
    }

    #[test]
    fn a_message_names_the_processor_and_the_vector() {
        assert_eq!(message(0x41, 0), Some((0xFEE0_0000, 0x41)));
        assert_eq!(message(0x41, 3), Some((0xFEE0_3000, 0x41)));
        assert_eq!(message(0xB0, 0xFE), Some((0xFEEF_E000, 0xB0)));
        assert_eq!(message(0x41, 0xFF), None);
        assert_eq!(message(0x41, 0x1_0000), None);
    }

    #[test]
    fn vectors_are_spread_over_the_irqls() {
        let mut map = VectorMap::new();
        let firsts: Vec<u32> = (0..10).map(|_| map.take(1).unwrap()).collect();
        assert_eq!(
            firsts,
            [0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0x31]
        );
        // Every vector once: 144 of them.
        let mut all = firsts;
        while let Some(v) = map.take(1) {
            all.push(v);
        }
        assert_eq!(all.len(), 144);
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), 144);
        assert!(all.iter().all(|v| DEVICE_VECTORS.contains(v)));
        assert_eq!(map.take(1), None);
        map.give_back(0x77, 1);
        assert_eq!(map.take(1), Some(0x77));
    }

    #[test]
    fn a_block_of_vectors_is_aligned_and_of_one_irql() {
        let mut map = VectorMap::new();
        assert_eq!(map.take(1), Some(0x30));
        // Four vectors: not 0x30..0x34, which holds one in use.
        assert_eq!(map.take(4), Some(0x40));
        assert_eq!(map.take(4), Some(0x50));
        assert_eq!(map.take(16), Some(0x60));
        assert_eq!(map.take(2), Some(0x70));
        assert_eq!(map.take(8), Some(0x80));
        // Counts no device has.
        assert_eq!(map.take(0), None);
        assert_eq!(map.take(3), None);
        assert_eq!(map.take(32), None);
        // A reserved vector is never handed out, alone or in a block.
        let mut map = VectorMap::new();
        for reserved in [0x51, 0x61, 0x71, 0x20, 0xD1] {
            map.reserve(reserved);
        }
        let mut seen = Vec::new();
        while let Some(v) = map.take(2) {
            seen.extend([v, v + 1]);
        }
        assert_eq!(seen.len(), 144 - 6);
        assert!(!seen.contains(&0x51) && !seen.contains(&0x50));
        // Given back, a block can be taken again; vectors outside the
        // device range are not the map's to free.
        map.give_back(0x30, 2);
        map.give_back(0x20, 4);
        map.give_back(0xFE, 8);
        assert_eq!(map.take(2), Some(0x30));
        assert_eq!(VectorMap::default(), VectorMap::new());
    }
}
