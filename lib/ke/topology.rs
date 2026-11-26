//! How processors are named: by index, and by group and number within
//! the group (`PROCESSOR_NUMBER`), with the sets Windows makes of them.
//!
//! NK has one group, number 0, as every Windows system of up to 64
//! processors has, and one NUMA node, number 0. A processor's index and
//! its number in the group are the same. No processor is added while
//! the system runs, so the most a group can have is what it has.

/// `ALL_PROCESSOR_GROUPS`.
pub const ALL_GROUPS: u16 = 0xFFFF;
/// `INVALID_PROCESSOR_INDEX`.
pub const INVALID_INDEX: u32 = u32::MAX;

/// `KeGetProcessorIndexFromNumber`: the index of the processor
/// `number` of `group`, or [`INVALID_INDEX`] if there is none or the
/// reserved byte is not zero.
pub fn index_from_number(group: u16, number: u8, reserved: u8, processors: u32) -> u32 {
    if group == 0 && reserved == 0 && u32::from(number) < processors {
        u32::from(number)
    } else {
        INVALID_INDEX
    }
}

/// `KeGetProcessorNumberFromIndex`: the group and number of the
/// processor at `index`; `None` is `STATUS_INVALID_PARAMETER`.
pub fn number_from_index(index: u32, processors: u32) -> Option<(u16, u8)> {
    (index < processors).then_some((0, index as u8))
}

/// `KeQueryActiveProcessorCountEx`, `KeQueryMaximumProcessorCountEx`:
/// the processors of `group`, or of all groups.
pub fn count_in_group(group: u16, processors: u32) -> u32 {
    match group {
        0 | ALL_GROUPS => processors,
        _ => 0,
    }
}

/// `KeQueryGroupAffinity`: the running processors of `group`, as a
/// mask; none for a group there is not.
pub fn group_affinity(group: u16, online: u64) -> u64 {
    if group == 0 { online } else { 0 }
}

/// `KeQueryNodeActiveAffinity`: the running processors of NUMA node
/// `node`, as a mask of group 0, and how many they are.
pub fn node_affinity(node: u16, online: u64) -> (u64, u16) {
    if node == 0 {
        (online, online.count_ones() as u16)
    } else {
        (0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_index_is_a_number_in_group_zero() {
        assert_eq!(index_from_number(0, 0, 0, 4), 0);
        assert_eq!(index_from_number(0, 3, 0, 4), 3);
        assert_eq!(index_from_number(0, 4, 0, 4), INVALID_INDEX);
        assert_eq!(index_from_number(1, 0, 0, 4), INVALID_INDEX);
        assert_eq!(index_from_number(0, 0, 1, 4), INVALID_INDEX);
        assert_eq!(index_from_number(0, 0, 0, 0), INVALID_INDEX);
        assert_eq!(number_from_index(0, 4), Some((0, 0)));
        assert_eq!(number_from_index(3, 4), Some((0, 3)));
        assert_eq!(number_from_index(4, 4), None);
        assert_eq!(number_from_index(INVALID_INDEX, 4), None);
        for index in 0..64 {
            let (group, number) = number_from_index(index, 64).unwrap();
            assert_eq!(index_from_number(group, number, 0, 64), index);
        }
    }

    #[test]
    fn group_zero_and_node_zero_have_every_processor() {
        assert_eq!(count_in_group(0, 4), 4);
        assert_eq!(count_in_group(ALL_GROUPS, 4), 4);
        assert_eq!(count_in_group(1, 4), 0);
        assert_eq!(group_affinity(0, 0b1011), 0b1011);
        assert_eq!(group_affinity(1, 0b1011), 0);
        assert_eq!(group_affinity(ALL_GROUPS, 0b1011), 0);
        assert_eq!(node_affinity(0, 0b1011), (0b1011, 3));
        assert_eq!(node_affinity(1, 0b1011), (0, 0));
        assert_eq!(node_affinity(0, u64::MAX), (u64::MAX, 64));
    }
}
