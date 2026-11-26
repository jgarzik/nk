//! arm64: the GICv3 interrupt controller and the generic timer.
//!
//! A processor is named by the affinity fields of its `MPIDR_EL1`:
//! level 0 in bits 0-7, level 1 in 8-15, level 2 in 16-23 and level 3 in
//! bits 32-39.

use core::fmt;
use nk_acpi::{Cpu, Madt, MadtEntry};

/// The priority of interrupts that run at IRQL `level` (0 to 15), which
/// is also the mask value that holds them back. A higher IRQL is a
/// numerically lower priority, sixteen apart, so the sixteen levels fit
/// a GIC that implements only the top four priority bits.
pub const fn priority(level: u8) -> u8 {
    0xF0 - 0x10 * level
}

/// The IRQL a priority mask stands for: the inverse of [`priority`].
pub const fn level_of(mask: u8) -> u8 {
    (priority(0) - mask) >> 4
}

/// The affinity fields of processor `id`, packed as the upper half of a
/// redistributor's type register packs them: level 3 in the top byte.
pub const fn redistributor_affinity(id: u64) -> u32 {
    ((id >> 32 & 0xFF) << 24 | id & 0xFF_FFFF) as u32
}

/// The value of `ICC_SGI1R_EL1` that sends software-generated interrupt
/// `vector` to processor `id`. Affinity levels 3 to 1 name a group of
/// sixteen and the low bits list the targets within it by their level-0
/// number; `None` for a level-0 number above 15, which needs a range
/// selector.
pub const fn sgi(id: u64, vector: u32) -> Option<u64> {
    if id & 0xFF >= 16 {
        return None;
    }
    Some(
        (id >> 32 & 0xFF) << 48
            | (id >> 16 & 0xFF) << 32
            | (id >> 8 & 0xFF) << 16
            | (vector as u64) << 24
            | 1 << (id & 0xF),
    )
}

/// Interrupt ids from here up are not interrupts: "nothing pending".
const SPURIOUS: u32 = 1020;

/// The interrupt an acknowledge (`ICC_IAR1_EL1`) reported, or `None` if
/// there was nothing to take.
pub const fn acknowledged(iar: u64) -> Option<u32> {
    let vector = iar as u32 & 0xFF_FFFF;
    if vector >= SPURIOUS {
        None
    } else {
        Some(vector)
    }
}

/// How many interrupt lines a distributor has, from its type register.
pub const fn distributor_lines(typer: u32) -> u32 {
    32 * ((typer & 0x1F) + 1)
}

/// When the next clock interrupt is due (a timer compare value), given
/// when the one being handled was due, the period, and the counter now.
/// Each is due one period after the last was due, not after it was
/// handled, so lateness does not accumulate; if a whole period was
/// missed, start afresh from now.
pub const fn next_tick(last: u64, period: u64, now: u64) -> u64 {
    let due = last + period;
    if due <= now { now + period } else { due }
}

/// The first shared peripheral interrupt: ids below are private to a
/// processor.
pub const SPI_BASE: u32 = 32;

/// The IRQL a shared peripheral interrupt runs at. The GIC ties no
/// priority to an interrupt id, so NK spreads them over the device
/// levels, 3 to 11, by id.
pub const fn spi_level(intid: u32) -> u8 {
    3 + (intid % 9) as u8
}

/// Where interrupt `intid` is in a distributor register that holds one
/// bit per interrupt (enable, group): the offset of its 32-bit word from
/// the register's start, and its bit.
pub const fn bit_of(intid: u32) -> (usize, u32) {
    (4 * (intid / 32) as usize, 1 << (intid % 32))
}

/// Where interrupt `intid` is in the configuration register
/// (`GICD_ICFGR`), two bits per interrupt: the offset of its word and
/// the bit that makes it edge triggered.
pub const fn config_of(intid: u32) -> (usize, u32) {
    (4 * (intid / 16) as usize, 2 << (2 * (intid % 16)))
}

/// The routing register value (`GICD_IROUTER`) that sends an interrupt
/// to the processor with affinity `id`.
pub const fn route_to(id: u64) -> u64 {
    id & MPIDR_AFFINITY
}

/// A stretch of redistributor frames.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Redistributors {
    pub address: u64,
    pub length: u64,
}

/// One GICv3 redistributor: two 64 KiB frames.
pub const REDISTRIBUTOR_SIZE: u64 = 0x2_0000;
/// The affinity fields of `MPIDR_EL1`: Aff3 and Aff2..Aff0.
pub const MPIDR_AFFINITY: u64 = 0xFF_00FF_FFFF;

/// Where the interrupt controllers are, with room for `N` stretches of
/// redistributors.
#[derive(Debug)]
pub struct Controllers<const N: usize> {
    /// Physical address of the GIC distributor; 0 if the table names
    /// none.
    pub distributor: u64,
    /// GIC architecture version from the table; 0 means "ask the hardware".
    pub version: u8,
    /// Where redistributors may be: the table's regions, or one frame pair
    /// per processor when it lists them that way.
    redistributors: [Redistributors; N],
    n_redistributors: usize,
}

impl<const N: usize> Controllers<N> {
    pub fn from_madt(madt: &Madt<'_>) -> Self {
        let mut c = Controllers {
            distributor: 0,
            version: 0,
            redistributors: [Redistributors {
                address: 0,
                length: 0,
            }; N],
            n_redistributors: 0,
        };
        let add = |c: &mut Self, address, length| {
            if c.n_redistributors < N {
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

impl<const N: usize> fmt::Display for Controllers<N> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_shared_interrupt_has_a_device_irql_and_a_place_in_each_register() {
        assert_eq!(spi_level(32), 8);
        assert_eq!(spi_level(33), 9);
        assert_eq!(spi_level(36), 3);
        assert!((SPI_BASE..1020).all(|id| (3..=11).contains(&spi_level(id))));
        assert_eq!(bit_of(32), (4, 1));
        assert_eq!(bit_of(33), (4, 2));
        assert_eq!(bit_of(95), (8, 1 << 31));
        assert_eq!(config_of(32), (8, 2));
        assert_eq!(config_of(33), (8, 8));
        assert_eq!(config_of(47), (8, 2 << 30));
        assert_eq!(config_of(48), (12, 2));
        assert_eq!(route_to(0x0000_0001), 1);
        assert_eq!(route_to(0x8000_0003), 3, "bits that are not affinity");
        assert_eq!(route_to(0x12_0034_5678), 0x12_0034_5678);
    }

    use crate::table;
    use nk_acpi::madt;

    fn controllers<const N: usize>(entries: &[Vec<u8>]) -> Controllers<N> {
        let bytes = table::madt(0, entries);
        Controllers::from_madt(&madt(&bytes).expect("a well-formed MADT"))
    }

    #[test]
    fn the_distributor_and_redistributor_regions_come_from_the_table() {
        let c: Controllers<4> = controllers(&[
            table::gicc(0, 1, 0, 0),
            table::gicc(1, 1, 0, 1),
            table::gicd(0x0800_0000, 3),
            table::gicr(0x080A_0000, 0x00F6_0000),
            table::gicr(0x4000_0000, 0x0004_0000),
        ]);
        assert_eq!((c.distributor, c.version), (0x0800_0000, 3));
        assert_eq!(
            c.redistributors(),
            [
                Redistributors {
                    address: 0x080A_0000,
                    length: 0x00F6_0000
                },
                Redistributors {
                    address: 0x4000_0000,
                    length: 0x0004_0000
                },
            ]
        );
        assert_eq!(
            c.to_string(),
            "GICv3 distributor at 0x8000000, redistributors at 0x80a0000+0xf60000, \
             redistributors at 0x40000000+0x40000"
        );
    }

    #[test]
    fn without_regions_each_enabled_processor_gives_its_own_frames() {
        let c: Controllers<4> = controllers(&[
            table::gicc(0, 1, 0x1000_0000, 0),
            // Disabled: its redistributor is not one to look in.
            table::gicc(1, 0, 0x1002_0000, 1),
            // Enabled, but the table gives no address for it.
            table::gicc(2, 1, 0, 2),
            table::gicc(3, 1, 0x1006_0000, 3),
            table::gicd(0x0800_0000, 0),
        ]);
        assert_eq!(
            c.redistributors(),
            [
                Redistributors {
                    address: 0x1000_0000,
                    length: REDISTRIBUTOR_SIZE
                },
                Redistributors {
                    address: 0x1006_0000,
                    length: REDISTRIBUTOR_SIZE
                },
            ]
        );
        assert_eq!(c.version, 0);
    }

    #[test]
    fn regions_take_precedence_over_per_processor_addresses() {
        // The region entry comes last and still wins.
        let c: Controllers<4> = controllers(&[
            table::gicc(0, 1, 0x1000_0000, 0),
            table::gicc(1, 1, 0x1002_0000, 1),
            table::gicr(0x080A_0000, 0x0004_0000),
        ]);
        assert_eq!(
            c.redistributors(),
            [Redistributors {
                address: 0x080A_0000,
                length: 0x0004_0000
            }]
        );
    }

    #[test]
    fn a_table_with_no_gic_names_no_distributor() {
        let c: Controllers<4> = controllers(&[table::local_apic(0, 0, 1)]);
        assert_eq!(c.distributor, 0);
        assert!(c.redistributors().is_empty());
        assert_eq!(c.to_string(), "GICv0 distributor at 0x0");
        let c: Controllers<4> = controllers(&[]);
        assert_eq!(c.distributor, 0);
    }

    #[test]
    fn stretches_beyond_the_room_there_is_are_left_out() {
        let regions: Vec<_> = (0..5u64)
            .map(|n| table::gicr(0x1000_0000 + n * 0x10_0000, 0x2_0000))
            .collect();
        let c: Controllers<3> = controllers(&regions);
        assert_eq!(c.redistributors().len(), 3);
        assert_eq!(c.redistributors()[2].address, 0x1020_0000);
        let cpus: Vec<_> = (0..5u64)
            .map(|n| table::gicc(n as u32, 1, 0x2000_0000 + n * 0x2_0000, n))
            .collect();
        let c: Controllers<2> = controllers(&cpus);
        assert_eq!(c.redistributors().len(), 2);
        assert_eq!(c.redistributors()[1].address, 0x2002_0000);
        // No room at all is still an answer.
        let c: Controllers<0> = controllers(&regions);
        assert!(c.redistributors().is_empty());
    }

    #[test]
    fn a_usable_processor_is_an_enabled_gicc_named_by_its_affinity() {
        let cpu = |uid, mpidr, enabled| MadtEntry::Gicc {
            uid,
            mpidr,
            enabled,
            gicr_base: 0,
        };
        assert_eq!(
            usable_cpu(&cpu(7, 0x0102, true)),
            Some(Cpu {
                hw_id: 0x0102,
                uid: 7
            })
        );
        // Only the affinity fields name the processor: not the bits
        // between level 2 and level 3, nor those above.
        assert_eq!(
            usable_cpu(&cpu(1, 0xFFFF_FF04_8000_0001, true)).map(|c| c.hw_id),
            Some(0x04_0000_0001)
        );
        assert_eq!(usable_cpu(&cpu(7, 0x0102, false)), None);
        assert_eq!(
            usable_cpu(&MadtEntry::Gicd {
                address: 0x0800_0000,
                version: 3
            }),
            None
        );
        assert_eq!(
            usable_cpu(&MadtEntry::LocalApic {
                uid: 0,
                id: 0,
                enabled: true,
                online_capable: false
            }),
            None
        );
    }

    #[test]
    fn a_processor_is_named_the_same_by_the_table_and_by_its_redistributor() {
        // What `usable_cpu` keeps of an MPIDR is exactly what the
        // redistributor's affinity and the SGI encoding read.
        let mpidr = 0xFFFF_FF04_8003_0201;
        let id = mpidr & MPIDR_AFFINITY;
        assert_eq!(redistributor_affinity(id), 0x0403_0201);
        assert_eq!(redistributor_affinity(id), redistributor_affinity(mpidr));
        assert_eq!(sgi(id, 1), sgi(mpidr, 1));
    }

    #[test]
    fn each_irql_has_its_own_priority_and_higher_is_more_urgent() {
        assert_eq!(priority(0), 0xF0);
        assert_eq!(priority(1), 0xE0);
        assert_eq!(priority(2), 0xD0);
        assert_eq!(priority(13), 0x20);
        assert_eq!(priority(15), 0x00);
        for level in 1..=15 {
            // To a GIC a lower number is the more urgent.
            assert!(priority(level) < priority(level - 1));
            // Only the four bits every GIC implements are used.
            assert_eq!(priority(level) & 0x0F, 0);
        }
    }

    #[test]
    fn a_mask_reads_back_as_the_irql_that_set_it() {
        for level in 0..=15 {
            assert_eq!(level_of(priority(level)), level);
        }
        assert_eq!(level_of(0xF0), 0);
        assert_eq!(level_of(0xD0), 2);
        assert_eq!(level_of(0x00), 15);
    }

    #[test]
    fn a_redistributor_names_its_processor_with_level_3_on_top() {
        assert_eq!(redistributor_affinity(0), 0);
        assert_eq!(redistributor_affinity(3), 3);
        assert_eq!(redistributor_affinity(0x0102), 0x0102);
        assert_eq!(redistributor_affinity(0x03_0102), 0x03_0102);
        // Level 3 moves from bits 32-39 down to the top byte.
        assert_eq!(redistributor_affinity(0x04_0003_0201), 0x0403_0201);
        assert_eq!(redistributor_affinity(0xFF_00FF_FFFF), 0xFFFF_FFFF);
        // What MPIDR holds between and above the affinity fields is not
        // part of the name.
        assert_eq!(redistributor_affinity(0xFFFF_FF04_8000_0001), 0x0400_0001);
    }

    #[test]
    fn an_sgi_names_the_group_and_one_target_in_it() {
        // Processor 0, vector 0: just the target bit.
        assert_eq!(sgi(0, 0), Some(1));
        // Processor 3 of group 0, vector 2.
        assert_eq!(sgi(3, 2), Some(2 << 24 | 1 << 3));
        assert_eq!(sgi(15, 1), Some(1 << 24 | 1 << 15));
        // Levels 1, 2 and 3 go to bits 16, 32 and 48.
        assert_eq!(
            sgi(0x04_0003_0201, 5),
            Some(4 << 48 | 3 << 32 | 2 << 16 | 5 << 24 | 1 << 1)
        );
        assert_eq!(sgi(0x0100, 15), Some(1 << 16 | 15 << 24 | 1));
    }

    #[test]
    fn an_sgi_target_above_15_in_its_group_is_refused() {
        assert_eq!(sgi(16, 0), None);
        assert_eq!(sgi(0xFF, 0), None);
        assert_eq!(sgi(0x04_0003_0210, 5), None);
        // The group's number does not count: only level 0 is a bit.
        assert!(sgi(0x04_0003_FF0F, 5).is_some());
    }

    #[test]
    fn exactly_one_target_bit_is_set() {
        for target in 0..16 {
            let value = sgi(target, 0).unwrap();
            assert_eq!(value, 1 << target);
            assert_eq!((value & 0xFFFF).count_ones(), 1);
        }
    }

    #[test]
    fn an_acknowledge_yields_the_interrupt_or_nothing() {
        assert_eq!(acknowledged(0), Some(0));
        assert_eq!(acknowledged(27), Some(27));
        assert_eq!(acknowledged(1019), Some(1019));
        // The special ids: nothing to take.
        assert_eq!(acknowledged(1020), None);
        assert_eq!(acknowledged(1023), None);
        // Only the low 24 bits are the id.
        assert_eq!(acknowledged(0xFFFF_FFFF_0100_001B), Some(27));
        assert_eq!(acknowledged(0x0100_03FF), None);
    }

    #[test]
    fn a_distributor_has_32_lines_per_step_of_its_type_field() {
        assert_eq!(distributor_lines(0), 32);
        assert_eq!(distributor_lines(1), 64);
        assert_eq!(distributor_lines(0x1F), 1024);
        // The other fields of the register are not line counts.
        assert_eq!(distributor_lines(0xFFFF_FFE0 | 8), 288);
    }

    #[test]
    fn the_clock_keeps_its_rhythm_when_handled_late() {
        // Handled 30 counts late: the next is still one period after
        // the last was due.
        assert_eq!(next_tick(1000, 100, 1030), 1100);
        assert_eq!(next_tick(1000, 100, 1000), 1100);
        assert_eq!(next_tick(1000, 100, 1099), 1100);
    }

    #[test]
    fn the_clock_starts_afresh_after_a_missed_period() {
        // A compare value at or before now would fire at once, again
        // and again: the next is a full period from now instead.
        assert_eq!(next_tick(1000, 100, 1100), 1200);
        assert_eq!(next_tick(1000, 100, 5000), 5100);
        for now in [1100, 1101, 1500, 99_999] {
            assert!(next_tick(1000, 100, now) > now);
        }
    }
}
