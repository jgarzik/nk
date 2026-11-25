//! arm64: the GICv3 interrupt controller and the generic timer.
//!
//! A processor is named by the affinity fields of its `MPIDR_EL1`:
//! level 0 in bits 0-7, level 1 in 8-15, level 2 in 16-23 and level 3 in
//! bits 32-39.

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

#[cfg(test)]
mod tests {
    use super::*;

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
