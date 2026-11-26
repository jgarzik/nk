//! Time-based UUIDs for `ExUuidCreate`: RFC 4122 version 1.
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-exuuidcreate>
//! <https://www.rfc-editor.org/rfc/rfc4122>
//!
//! A version-1 UUID is a 60-bit time in 100 ns units since 15 October
//! 1582, a 14-bit clock sequence, and a 48-bit node. [`version1`] lays
//! the three out as a `GUID` in memory.
//!
//! The node is a network card's address when the kernel has one. With
//! none it is 47 random bits under the multicast bit ([`local_node`]),
//! which no card's address has set, and `ExUuidCreate` then returns
//! [`RPC_NT_UUID_LOCAL_ONLY`] ([`is_universal`] decides).
//!
//! [`Sequencer`] picks the time and clock sequence of each UUID so that
//! no pair is used twice, whatever the clock does. Windows instead
//! returns `STATUS_RETRY` when asked faster than its clock moves; NK
//! never does.

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

/// A node made of random bytes: the multicast bit marks it as no
/// network card's address.
pub const fn local_node(mut random: [u8; 6]) -> [u8; 6] {
    random[0] |= 1;
    random
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

/// Chooses the (timestamp, clock sequence) of each UUID. Not one pair is
/// given out twice by one sequencer.
///
/// While the clock moves forward a UUID carries the clock's time. When
/// the clock has not moved since the last one, or has gone back, the
/// time stays and the clock sequence goes up; when the sequence wraps
/// to zero, where it might meet values already used at that time, the
/// time is moved one unit ahead of the clock.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Sequencer {
    /// The time of the last UUID.
    time: u64,
    /// The clock sequence of the last UUID.
    sequence: u16,
}

impl Sequencer {
    /// Start from a clock sequence, which should be random: it is what
    /// keeps this boot's UUIDs apart from the last boot's.
    pub const fn new(clock_sequence: u16) -> Self {
        Self {
            time: 0,
            sequence: clock_sequence & SEQUENCE_MASK,
        }
    }

    /// The timestamp and clock sequence for the next UUID, given the
    /// clock's timestamp now.
    pub const fn next(&mut self, now: u64) -> (u64, u16) {
        if now > self.time {
            self.time = now;
        } else {
            self.sequence = (self.sequence + 1) & SEQUENCE_MASK;
            if self.sequence == 0 {
                self.time += 1;
            }
        }
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
    fn a_random_node_is_marked_multicast() {
        assert_eq!(local_node([0; 6]), [1, 0, 0, 0, 0, 0]);
        assert_eq!(local_node([0xFE, 1, 2, 3, 4, 5]), [0xFF, 1, 2, 3, 4, 5]);
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
    fn a_moving_clock_is_followed_and_keeps_its_sequence() {
        let mut s = Sequencer::new(0xFFFF);
        // Only 14 bits of the seed are a clock sequence.
        assert_eq!(s.next(100), (100, 0x3FFF));
        assert_eq!(s.next(101), (101, 0x3FFF));
        assert_eq!(s.next(5000), (5000, 0x3FFF));
    }

    #[test]
    fn a_stalled_or_reversed_clock_moves_the_sequence() {
        let mut s = Sequencer::new(7);
        assert_eq!(s.next(100), (100, 7));
        assert_eq!(s.next(100), (100, 8));
        assert_eq!(s.next(40), (100, 9));
        assert_eq!(s.next(101), (101, 9));
        // A clock at zero from the start is a stalled clock.
        let mut s = Sequencer::new(7);
        assert_eq!(s.next(0), (0, 8));
    }

    #[test]
    fn a_wrapped_sequence_moves_the_time_ahead() {
        let mut s = Sequencer::new(0x3FFE);
        assert_eq!(s.next(100), (100, 0x3FFE));
        assert_eq!(s.next(100), (100, 0x3FFF));
        assert_eq!(s.next(100), (101, 0));
        // A whole turn of the sequence fits in the borrowed time.
        for sequence in 1..=0x3FFF {
            assert_eq!(s.next(100), (101, sequence));
        }
        assert_eq!(s.next(100), (102, 0));
        // The clock catching up to the borrowed time is still a stall.
        assert_eq!(s.next(102), (102, 1));
        assert_eq!(s.next(103), (103, 1));
    }

    #[test]
    fn no_pair_repeats_whatever_the_clock_does() {
        // Stalled long enough to wrap the sequence three times, then
        // creeping, jumping back, and stalled again.
        let stalled = core::iter::repeat_n(1000u64, 50_000);
        let creeping = (0..20_000u64).map(|i| 1000 + i / 3);
        let reversed = (0..20_000u64).map(|i| 900 + i % 7);
        let clock = stalled
            .clone()
            .chain(creeping)
            .chain(reversed)
            .chain(stalled);
        let mut s = Sequencer::new(0x1234);
        let mut seen = HashSet::new();
        let mut last = 0;
        for now in clock {
            let (time, sequence) = s.next(now);
            assert!(seen.insert((time, sequence)), "{time} {sequence} twice");
            assert!(sequence <= SEQUENCE_MASK);
            // Time never runs back, and is never behind the clock.
            assert!(time >= last && time >= now);
            last = time;
            // So the UUIDs differ too.
            assert_eq!(version1(time, sequence, [1; 6])[7] >> 4, 1);
        }
        assert_eq!(seen.len(), 140_000);
        let uuids: HashSet<_> = seen
            .iter()
            .map(|&(time, sequence)| version1(time, sequence, [1; 6]))
            .collect();
        assert_eq!(uuids.len(), seen.len());
    }
}
