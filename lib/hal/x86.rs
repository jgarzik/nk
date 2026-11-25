//! x86-64: the local APIC.

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

#[cfg(test)]
mod tests {
    use super::*;

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
