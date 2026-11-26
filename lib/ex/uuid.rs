//! Time-based UUIDs for `ExUuidCreate`: RFC 4122 version 1.
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-exuuidcreate>
//! <https://www.rfc-editor.org/rfc/rfc4122>
//!
//! A version-1 UUID is a 60-bit time in 100 ns units since 15 October
//! 1582, a 14-bit clock sequence, and a 48-bit node. [`version1`] lays
//! the three out as a `GUID` in memory.
//!
//! The node is a network card's address when the kernel has one. With
//! none it is random bits under two marks ([`local_node`]) and
//! `ExUuidCreate` then returns [`RPC_NT_UUID_LOCAL_ONLY`]
//! ([`is_universal`] decides).
//!
//! [`Sequencer`] picks the time of each UUID so that none is used twice,
//! whatever the clock does: each is later than the one before. Windows
//! too gives successive UUIDs successive times, from a range it reserves
//! ahead, and returns `STATUS_RETRY` when asked faster than its clock
//! moves; NK never does.

/// From the UUID epoch (15 October 1582) to the system time epoch
/// (1 January 1601), in 100 ns units: 6653 days.
pub const SYSTEM_TIME_EPOCH: u64 = 6653 * 24 * 60 * 60 * 10_000_000;

/// The success status for a UUID unique only on this machine.
pub const RPC_NT_UUID_LOCAL_ONLY: u32 = 0x4002_0056;

const TIMESTAMP_MASK: u64 = (1 << 60) - 1;
const SEQUENCE_MASK: u16 = (1 << 14) - 1;

/// The UUID timestamp for a system time (100 ns units since 1601).
pub const fn timestamp(system_time: u64) -> u64 {
    (system_time + SYSTEM_TIME_EPOCH) & TIMESTAMP_MASK
}

/// A node made of random bytes, marked as no network card's address
/// twice over: by the multicast bit of an IEEE 802 address, the lowest
/// of the first byte, as RFC 4122 asks; and by that byte's highest bit,
/// where the conformance driver expects Windows' mark.
pub const fn local_node(mut random: [u8; 6]) -> [u8; 6] {
    random[0] |= 0x81;
    random
}

/// One round of mixing: every bit of the input moves every bit of the
/// output (the finishing step of SplitMix64).
const fn mix(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// What one boot's UUIDs share, made from whatever the kernel can offer
/// that differs from boot to boot and machine to machine: a clock
/// sequence and a [`local_node`]. Every input counts toward both.
pub const fn identity(entropy: [u64; 3]) -> (u16, [u8; 6]) {
    let mut state = 0;
    let mut i = 0;
    while i < entropy.len() {
        state = mix(state ^ entropy[i]);
        i += 1;
    }
    let sequence = (mix(state) as u16) & SEQUENCE_MASK;
    let node = mix(state ^ 1).to_le_bytes();
    (
        sequence,
        local_node([node[0], node[1], node[2], node[3], node[4], node[5]]),
    )
}

/// Whether a node is a universally administered card address, and so a
/// UUID built on it unique everywhere: neither the multicast bit nor
/// the locally-administered bit is set.
pub const fn is_universal(node: [u8; 6]) -> bool {
    node[0] & 3 == 0
}

/// A version-1 UUID as the 16 bytes of a `GUID` in memory: `Data1` the
/// low 32 bits of the time, `Data2` the next 16, `Data3` the version and
/// the top 12, each little-endian; `Data4` the variant and clock
/// sequence, high byte first, then the node.
pub const fn version1(timestamp: u64, clock_sequence: u16, node: [u8; 6]) -> [u8; 16] {
    let time_low = (timestamp as u32).to_le_bytes();
    let time_mid = ((timestamp >> 32) as u16).to_le_bytes();
    let time_hi_and_version = (((timestamp >> 48) as u16 & 0x0FFF) | 1 << 12).to_le_bytes();
    let sequence = ((clock_sequence & SEQUENCE_MASK) | 0x8000).to_be_bytes();
    [
        time_low[0],
        time_low[1],
        time_low[2],
        time_low[3],
        time_mid[0],
        time_mid[1],
        time_hi_and_version[0],
        time_hi_and_version[1],
        sequence[0],
        sequence[1],
        node[0],
        node[1],
        node[2],
        node[3],
        node[4],
        node[5],
    ]
}

/// Chooses the timestamp of each UUID, and keeps the clock sequence
/// they all carry. No timestamp is given out twice by one sequencer.
///
/// While the clock moves forward a UUID carries the clock's time. When
/// the clock has not moved since the last one, or has gone back, the
/// UUID's time is one unit after the last: ahead of the clock, which
/// catches up. The clock sequence never changes: it is what keeps one
/// boot's UUIDs apart from another's, should their times meet.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Sequencer {
    /// The time of the last UUID.
    time: u64,
    sequence: u16,
}

impl Sequencer {
    /// Start from a clock sequence, which should be random.
    pub const fn new(clock_sequence: u16) -> Self {
        Self {
            time: 0,
            sequence: clock_sequence & SEQUENCE_MASK,
        }
    }

    /// The timestamp and clock sequence for the next UUID, given the
    /// clock's timestamp now.
    pub const fn next(&mut self, now: u64) -> (u64, u16) {
        self.time = if now > self.time { now } else { self.time + 1 };
        (self.time, self.sequence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn the_epochs_are_6653_days_apart() {
        // Both epochs to the Unix epoch are well known; so is their
        // difference.
        assert_eq!(
            SYSTEM_TIME_EPOCH,
            0x01B2_1DD2_1381_4000 - 116_444_736_000_000_000
        );
        assert_eq!(timestamp(0), SYSTEM_TIME_EPOCH);
        assert_eq!(timestamp(10_000_000), SYSTEM_TIME_EPOCH + 10_000_000);
        // 60 bits, wrapping in the year 5236.
        assert_eq!(timestamp((1 << 60) - SYSTEM_TIME_EPOCH + 5), 5);
    }

    #[test]
    fn every_field_lands_in_its_place() {
        let node = [0x00, 0xA0, 0xC9, 0x12, 0x34, 0x56];
        let uuid = version1(0x0123_4567_89AB_CDEF, 0x2A5C, node);
        // 89abcdef-4567-1123-aa5c-00a0c9123456
        assert_eq!(
            uuid,
            [
                0xEF, 0xCD, 0xAB, 0x89, // Data1, little-endian
                0x67, 0x45, // Data2
                0x23, 0x11, // Data3: version 1 over the top 12 bits
                0xAA, 0x5C, // variant 10 over the sequence's top 6 bits
                0x00, 0xA0, 0xC9, 0x12, 0x34, 0x56,
            ]
        );
    }

    #[test]
    fn version_and_variant_are_fixed_whatever_the_inputs() {
        for (time, sequence) in [(0, 0), (u64::MAX, u16::MAX), (1 << 60, 1 << 14)] {
            let uuid = version1(time, sequence, [0xFF; 6]);
            assert_eq!(uuid[7] >> 4, 1, "version");
            assert_eq!(uuid[8] >> 6, 0b10, "variant");
        }
        // Bits beyond the fields are dropped, not spilled.
        assert_eq!(
            version1(u64::MAX, u16::MAX, [0; 6])[..10],
            [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x1F, 0xBF, 0xFF]
        );
        assert_eq!(
            version1(1 << 60, 1 << 14, [0; 6])[..10],
            [0, 0, 0, 0, 0, 0, 0, 0x10, 0x80, 0]
        );
    }

    #[test]
    fn a_random_node_is_marked_as_no_cards_address() {
        assert_eq!(local_node([0; 6]), [0x81, 0, 0, 0, 0, 0]);
        assert_eq!(local_node([0x7E, 1, 2, 3, 4, 5]), [0xFF, 1, 2, 3, 4, 5]);
        assert!(!is_universal(local_node([
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC
        ])));
        // A card's own address is universal; a locally administered one
        // is not.
        assert!(is_universal([0x00, 0xA0, 0xC9, 0x12, 0x34, 0x56]));
        assert!(!is_universal([0x02, 0xA0, 0xC9, 0x12, 0x34, 0x56]));
        assert_eq!(RPC_NT_UUID_LOCAL_ONLY, 0x40020056);
    }

    #[test]
    fn an_identity_depends_on_every_input_and_is_local() {
        let base = [0x1234_5678, 0x9ABC_DEF0, 0x0FED_CBA9];
        let mut seen = HashSet::new();
        assert!(seen.insert(identity(base)));
        for input in 0..3 {
            for bit in 0..64 {
                let mut changed = base;
                changed[input] ^= 1 << bit;
                let (sequence, node) = identity(changed);
                assert!(sequence <= SEQUENCE_MASK);
                assert_eq!(node[0] & 0x81, 0x81);
                assert!(!is_universal(node));
                // A node is 46 free bits: no two of these collide.
                assert!(seen.insert((sequence, node)), "input {input} bit {bit}");
            }
        }
        let nodes: HashSet<_> = seen.iter().map(|&(_, node)| node).collect();
        assert_eq!(nodes.len(), seen.len());
        // The same inputs, the same identity.
        assert_eq!(identity(base), identity(base));
    }

    #[test]
    fn a_moving_clock_is_followed() {
        let mut s = Sequencer::new(0xFFFF);
        // Only 14 bits of the seed are a clock sequence.
        assert_eq!(s.next(100), (100, 0x3FFF));
        assert_eq!(s.next(101), (101, 0x3FFF));
        assert_eq!(s.next(5000), (5000, 0x3FFF));
    }

    #[test]
    fn a_stalled_or_reversed_clock_is_run_ahead_of() {
        let mut s = Sequencer::new(7);
        assert_eq!(s.next(100), (100, 7));
        assert_eq!(s.next(100), (101, 7));
        assert_eq!(s.next(40), (102, 7));
        // The clock catching up to the borrowed time is still a stall.
        assert_eq!(s.next(102), (103, 7));
        assert_eq!(s.next(104), (104, 7));
        // A clock at zero from the start is a stalled clock.
        let mut s = Sequencer::new(7);
        assert_eq!(s.next(0), (1, 7));
    }

    #[test]
    fn no_time_repeats_whatever_the_clock_does() {
        // Stalled, then creeping, jumping back, and stalled again.
        let stalled = core::iter::repeat_n(1000u64, 50_000);
        let creeping = (0..20_000u64).map(|i| 1000 + i / 3);
        let reversed = (0..20_000u64).map(|i| 900 + i % 7);
        let clock = stalled
            .clone()
            .chain(creeping)
            .chain(reversed)
            .chain(stalled);
        let mut s = Sequencer::new(0x1234);
        let mut uuids = HashSet::new();
        let mut last = 0;
        for now in clock {
            let (time, sequence) = s.next(now);
            assert_eq!(sequence, 0x1234);
            // Each later than the last, and never behind the clock.
            assert!(time > last && time >= now, "{time} after {last} at {now}");
            last = time;
            assert!(uuids.insert(version1(time, sequence, [1; 6])));
        }
        assert_eq!(uuids.len(), 140_000);
    }
}
