//! How processors are named: by index, and by group and number within
//! the group (`PROCESSOR_NUMBER`), with the sets Windows makes of them.
//!
//! NK has one group, number 0, as every Windows system of up to 64
//! processors has, and one NUMA node, number 0. A processor's index and
//! its number in the group are the same. No processor is added while
//! the system runs, so the most a group can have is what it has.
//!
//! NK reads no topology from the processors or the firmware: every
//! logical processor is a core of its own in a package of its own, all
//! of one efficiency class, and no cache is known.

use nk_ntabi::interrupt::GROUP_AFFINITY;
use nk_ntabi::status::{
    NTSTATUS, STATUS_INFO_LENGTH_MISMATCH, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};
use nk_ntabi::sysinfo::{
    GROUP_RELATIONSHIP_ENTRY, NUMA_NODE_RELATIONSHIP_ENTRY, PROCESSOR_RELATIONSHIP_ENTRY,
    RELATION_ALL, RELATION_GROUP, RELATION_NUMA_NODE, RELATION_PROCESSOR_CORE,
    RELATION_PROCESSOR_PACKAGE,
};

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

/// One record of `SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX`, whole.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Record {
    /// A core or a package.
    Processor(PROCESSOR_RELATIONSHIP_ENTRY),
    NumaNode(NUMA_NODE_RELATIONSHIP_ENTRY),
    Group(GROUP_RELATIONSHIP_ENTRY),
}

impl Record {
    /// The bytes of the record.
    pub fn length(&self) -> u32 {
        match self {
            Record::Processor(e) => e.Size,
            Record::NumaNode(e) => e.Size,
            Record::Group(e) => e.Size,
        }
    }
}

fn of_group_0(mask: u64) -> GROUP_AFFINITY {
    GROUP_AFFINITY {
        Mask: mask as usize,
        Group: 0,
        Reserved: [0; 3],
    }
}

fn processor_record(relationship: u32, processor: u32) -> Record {
    Record::Processor(PROCESSOR_RELATIONSHIP_ENTRY {
        Relationship: relationship,
        Size: size_of::<PROCESSOR_RELATIONSHIP_ENTRY>() as u32,
        // No other logical processor shares the core.
        Flags: 0,
        EfficiencyClass: 0,
        Reserved: [0; 20],
        GroupCount: 1,
        GroupMask: of_group_0(1 << processor),
    })
}

/// [`KeQueryLogicalProcessorRelationship`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequerylogicalprocessorrelationship),
/// and `NtQuerySystemInformationEx` of the same records: the records
/// of `relationship` (a `LOGICAL_PROCESSOR_RELATIONSHIP`, or "all") for
/// the processor at index `processor`, or for all the processors
/// `online`. Each record that fits within `given` bytes is handed to
/// `write` with its offset. Returns the status and the bytes all the
/// records take, which is what the caller reports as the length
/// whatever the status.
///
/// As the pinned kernel orders them: for each processor its package,
/// then its core; then the NUMA node; then the groups, which a query
/// about one processor gets only by asking for them alone.
///
/// | Query | Status |
/// | --- | --- |
/// | every record fits | `STATUS_SUCCESS` |
/// | they take more than `given` | `STATUS_INFO_LENGTH_MISMATCH`; the records before the first that does not fit are written |
/// | there is no record: caches, a relationship Windows 10 has not | `STATUS_UNSUCCESSFUL` |
///
/// The caller has checked that `processor` is a running processor.
pub fn relationships(
    processor: Option<u32>,
    relationship: u32,
    online: u64,
    given: u32,
    mut write: impl FnMut(u32, &Record),
) -> (NTSTATUS, u32) {
    let wants = |one: u32| relationship == one || relationship == RELATION_ALL;
    let mut needed = 0u32;
    let mut status = STATUS_SUCCESS;
    let mut add = |record: Record| {
        let offset = needed;
        needed += record.length();
        if needed > given {
            status = STATUS_INFO_LENGTH_MISMATCH;
        } else {
            write(offset, &record);
        }
    };
    let about = match processor {
        Some(index) => 1 << index,
        None => online,
    };
    for index in (0..64).filter(|n| about & 1 << n != 0) {
        if wants(RELATION_PROCESSOR_PACKAGE) {
            add(processor_record(RELATION_PROCESSOR_PACKAGE, index));
        }
        if wants(RELATION_PROCESSOR_CORE) {
            add(processor_record(RELATION_PROCESSOR_CORE, index));
        }
    }
    if wants(RELATION_NUMA_NODE) {
        add(Record::NumaNode(NUMA_NODE_RELATIONSHIP_ENTRY {
            Relationship: RELATION_NUMA_NODE,
            Size: size_of::<NUMA_NODE_RELATIONSHIP_ENTRY>() as u32,
            NodeNumber: 0,
            Reserved: [0; 20],
            GroupMask: of_group_0(online),
        }));
    }
    if relationship == RELATION_GROUP || relationship == RELATION_ALL && processor.is_none() {
        let count = online.count_ones() as u8;
        add(Record::Group(GROUP_RELATIONSHIP_ENTRY {
            Relationship: RELATION_GROUP,
            Size: size_of::<GROUP_RELATIONSHIP_ENTRY>() as u32,
            MaximumGroupCount: 1,
            ActiveGroupCount: 1,
            Reserved: [0; 20],
            MaximumProcessorCount: count,
            ActiveProcessorCount: count,
            Reserved2: [0; 38],
            ActiveProcessorMask: online as usize,
        }));
    }
    if status == STATUS_SUCCESS && needed == 0 {
        status = STATUS_UNSUCCESSFUL;
    }
    (status, needed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nk_ntabi::sysinfo::RELATION_CACHE;

    type Written = Vec<(u32, u32, u64)>;

    /// The status, the length, and the records written as (offset,
    /// relationship, mask).
    fn ask(
        processor: Option<u32>,
        relationship: u32,
        online: u64,
        given: u32,
    ) -> (NTSTATUS, u32, Written) {
        let mut written = Vec::new();
        let (status, needed) = relationships(processor, relationship, online, given, |at, r| {
            assert!(at + r.length() <= given, "written past the buffer");
            written.push(match r {
                Record::Processor(e) => {
                    assert_eq!(
                        (e.Size, e.GroupCount, e.Flags, e.EfficiencyClass),
                        (0x30, 1, 0, 0)
                    );
                    assert_eq!((e.GroupMask.Group, e.Reserved), (0, [0; 20]));
                    (at, e.Relationship, e.GroupMask.Mask as u64)
                }
                Record::NumaNode(e) => {
                    assert_eq!((e.Size, e.NodeNumber, e.GroupMask.Group), (0x30, 0, 0));
                    (at, e.Relationship, e.GroupMask.Mask as u64)
                }
                Record::Group(e) => {
                    assert_eq!(
                        (e.Size, e.MaximumGroupCount, e.ActiveGroupCount),
                        (0x50, 1, 1)
                    );
                    assert_eq!(e.MaximumProcessorCount, e.ActiveProcessorCount);
                    assert_eq!(u32::from(e.ActiveProcessorCount), online.count_ones());
                    (at, e.Relationship, e.ActiveProcessorMask as u64)
                }
            });
        });
        (status, needed, written)
    }

    #[test]
    fn each_processor_is_a_core_and_a_package() {
        assert_eq!(
            ask(None, RELATION_PROCESSOR_CORE, 0b111, 0x90),
            (
                STATUS_SUCCESS,
                0x90,
                vec![(0, 0, 1), (0x30, 0, 2), (0x60, 0, 4)]
            )
        );
        assert_eq!(
            ask(None, RELATION_PROCESSOR_PACKAGE, 0b11, 0x1000),
            (STATUS_SUCCESS, 0x60, vec![(0, 3, 1), (0x30, 3, 2)])
        );
        assert_eq!(
            ask(Some(2), RELATION_PROCESSOR_CORE, 0b1111, 0x30),
            (STATUS_SUCCESS, 0x30, vec![(0, 0, 4)])
        );
        assert_eq!(
            ask(None, RELATION_PROCESSOR_CORE, 1 << 63, 0x30),
            (STATUS_SUCCESS, 0x30, vec![(0, 0, 1 << 63)])
        );
    }

    #[test]
    fn the_node_and_the_group_have_every_processor() {
        for processor in [None, Some(3)] {
            assert_eq!(
                ask(processor, RELATION_NUMA_NODE, 0b1011, 0x30),
                (STATUS_SUCCESS, 0x30, vec![(0, 1, 0b1011)])
            );
            assert_eq!(
                ask(processor, RELATION_GROUP, 0b1011, 0x50),
                (STATUS_SUCCESS, 0x50, vec![(0, 4, 0b1011)])
            );
        }
    }

    #[test]
    fn all_is_package_and_core_of_each_then_node_then_group() {
        assert_eq!(
            ask(None, RELATION_ALL, 0b11, 0x140),
            (
                STATUS_SUCCESS,
                0x140,
                vec![
                    (0, 3, 1),
                    (0x30, 0, 1),
                    (0x60, 3, 2),
                    (0x90, 0, 2),
                    (0xC0, 1, 3),
                    (0xF0, 4, 3)
                ]
            )
        );
        // About one processor: not the groups.
        assert_eq!(
            ask(Some(1), RELATION_ALL, 0b11, 0x1000),
            (
                STATUS_SUCCESS,
                0x90,
                vec![(0, 3, 2), (0x30, 0, 2), (0x60, 1, 3)]
            )
        );
    }

    #[test]
    fn a_short_buffer_gets_the_length_and_the_records_before_the_one_that_does_not_fit() {
        assert_eq!(
            ask(None, RELATION_ALL, 0b11, 0),
            (STATUS_INFO_LENGTH_MISMATCH, 0x140, vec![])
        );
        assert_eq!(
            ask(None, RELATION_ALL, 0b11, 0x13F),
            (
                STATUS_INFO_LENGTH_MISMATCH,
                0x140,
                vec![
                    (0, 3, 1),
                    (0x30, 0, 1),
                    (0x60, 3, 2),
                    (0x90, 0, 2),
                    (0xC0, 1, 3)
                ]
            )
        );
        assert_eq!(
            ask(None, RELATION_PROCESSOR_CORE, 0b11, 0x5F),
            (STATUS_INFO_LENGTH_MISMATCH, 0x60, vec![(0, 0, 1)])
        );
        assert_eq!(
            ask(None, RELATION_GROUP, 1, 0x4F),
            (STATUS_INFO_LENGTH_MISMATCH, 0x50, vec![])
        );
    }

    #[test]
    fn a_relationship_with_no_record_fails() {
        // No cache is known; 5 and up are not Windows 10's.
        for relationship in [RELATION_CACHE, 5, 6, 7, 0xFFFE, 0x1_0000] {
            for given in [0, 0x1000] {
                assert_eq!(
                    ask(None, relationship, 0b11, given),
                    (STATUS_UNSUCCESSFUL, 0, vec![]),
                    "{relationship}"
                );
            }
        }
    }

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
