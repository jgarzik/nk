//! The rules of `NtQuerySystemInformationEx`: the classes that take an
//! input buffer. Those the binaries NK runs ask for: the relationships
//! of logical processors, and whether interrupts are steered. The
//! decisions are the pinned kernel's (`NtQuerySystemInformationEx`,
//! `ExpQuerySystemInformation`, `KeQueryLogicalProcessorRelationship`,
//! `ExpQueryInterruptSteeringInformation`).

use nk_ntabi::interrupt::GROUP_AFFINITY;
use nk_ntabi::status::{
    NTSTATUS, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_PARAMETER, STATUS_UNSUCCESSFUL,
};
use nk_ntabi::sysinfo::{
    GROUP_RELATIONSHIP_ENTRY, NUMA_NODE_RELATIONSHIP_ENTRY, RELATION_GROUP, RELATION_NUMA_NODE,
    SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT,
};

/// What a query comes to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Answer<T> {
    /// Return the status; the return length, where there is one to
    /// set.
    Status(NTSTATUS, Option<u32>),
    /// Write the answer, report its length, return `STATUS_SUCCESS`.
    Written(T),
    /// A part of the class NK does not have: stop, naming it.
    NotImplemented,
}

/// What every class needs before it is looked at: an input buffer of
/// some length.
pub fn has_input(input_is_null: bool, input_length: u32) -> Result<(), NTSTATUS> {
    if input_is_null || input_length == 0 {
        Err(STATUS_INVALID_PARAMETER)
    } else {
        Ok(())
    }
}

/// One relationship of the machine's processors: the entries of
/// `SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX` NK can state, each whole.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Relationship {
    NumaNode(NUMA_NODE_RELATIONSHIP_ENTRY),
    Group(GROUP_RELATIONSHIP_ENTRY),
}

impl Relationship {
    /// The bytes of the entry.
    pub fn length(&self) -> u32 {
        match self {
            Relationship::NumaNode(e) => e.Size,
            Relationship::Group(e) => e.Size,
        }
    }
}

/// `SystemLogicalProcessorAndGroupInformation`: the entries of the
/// relationship the input names, for a machine of one group and one
/// NUMA node whose running processors are `online`. `input_length` is
/// that of the input, which is the relationship, a `u32`; `given` the
/// length of the output buffer.
///
/// The NUMA node and the group are answered. Cores, caches and
/// packages (and so "all") are not.
pub fn relationship(
    relationship: Option<u32>,
    input_length: u32,
    online: u64,
    given: u32,
) -> Answer<Relationship> {
    let Some(relationship) = relationship.filter(|_| input_length >= 4) else {
        return Answer::Status(STATUS_INVALID_PARAMETER, None);
    };
    let count = online.count_ones() as u8;
    let entry = match relationship {
        RELATION_NUMA_NODE => Relationship::NumaNode(NUMA_NODE_RELATIONSHIP_ENTRY {
            Relationship: RELATION_NUMA_NODE,
            Size: size_of::<NUMA_NODE_RELATIONSHIP_ENTRY>() as u32,
            NodeNumber: 0,
            Reserved: [0; 20],
            GroupMask: GROUP_AFFINITY {
                Mask: online as usize,
                Group: 0,
                Reserved: [0; 3],
            },
        }),
        RELATION_GROUP => Relationship::Group(GROUP_RELATIONSHIP_ENTRY {
            Relationship: RELATION_GROUP,
            Size: size_of::<GROUP_RELATIONSHIP_ENTRY>() as u32,
            MaximumGroupCount: 1,
            ActiveGroupCount: 1,
            Reserved: [0; 20],
            MaximumProcessorCount: count,
            ActiveProcessorCount: count,
            Reserved2: [0; 38],
            ActiveProcessorMask: online as usize,
        }),
        _ => return Answer::NotImplemented,
    };
    if online == 0 {
        // No processor, no entry: Windows' routine fails then.
        Answer::Status(STATUS_UNSUCCESSFUL, Some(0))
    } else if given < entry.length() {
        Answer::Status(STATUS_INFO_LENGTH_MISMATCH, Some(entry.length()))
    } else {
        Answer::Written(entry)
    }
}

/// `SystemInterruptSteeringInformation`: whether the kernel steers
/// interrupts between processors, which NK does not. The answer is a
/// `u32` whose low bit says so.
///
/// | Query | Outcome |
/// | --- | --- |
/// | an input that is not the 0x18-byte one | `STATUS_INFO_LENGTH_MISMATCH` |
/// | an output of under 4 bytes | `STATUS_INFO_LENGTH_MISMATCH`, the length 4 |
/// | the controller's interrupts, no particular one | 0: not steered |
/// | one interrupt's steering mode | not implemented |
pub fn interrupt_steering(
    input: Option<&SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT>,
    input_length: u32,
    given: u32,
) -> Answer<u32> {
    let wanted = size_of::<SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT>() as u32;
    let Some(input) = input.filter(|_| input_length == wanted) else {
        return Answer::Status(STATUS_INFO_LENGTH_MISMATCH, None);
    };
    if given < 4 {
        return Answer::Status(STATUS_INFO_LENGTH_MISMATCH, Some(4));
    }
    if input.ControllerInterrupt != 0 && input.Gsiv == u32::MAX {
        Answer::Written(0)
    } else {
        Answer::NotImplemented
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_input_is_required() {
        assert_eq!(has_input(false, 4), Ok(()));
        assert_eq!(has_input(true, 4), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(has_input(false, 0), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn the_numa_node_is_one_entry_of_the_running_processors() {
        let Answer::Written(Relationship::NumaNode(e)) = relationship(Some(1), 4, 0b1011, 0x30)
        else {
            panic!("no entry");
        };
        assert_eq!((e.Relationship, e.Size, e.NodeNumber), (1, 0x30, 0));
        assert_eq!((e.GroupMask.Mask, e.GroupMask.Group), (0b1011, 0));
        // pci.sys asks for the length first.
        assert_eq!(
            relationship(Some(1), 4, 0b1011, 0),
            Answer::Status(STATUS_INFO_LENGTH_MISMATCH, Some(0x30))
        );
        assert_eq!(
            relationship(Some(1), 4, 0b1011, 0x2F),
            Answer::Status(STATUS_INFO_LENGTH_MISMATCH, Some(0x30))
        );
    }

    #[test]
    fn the_group_is_one_entry() {
        let Answer::Written(Relationship::Group(e)) = relationship(Some(4), 8, 0b111, 0x100) else {
            panic!("no entry");
        };
        assert_eq!((e.Relationship, e.Size), (4, 0x50));
        assert_eq!((e.MaximumGroupCount, e.ActiveGroupCount), (1, 1));
        assert_eq!((e.MaximumProcessorCount, e.ActiveProcessorCount), (3, 3));
        assert_eq!(e.ActiveProcessorMask, 0b111);
        assert_eq!(
            relationship(Some(4), 4, 1, 0x4F),
            Answer::Status(STATUS_INFO_LENGTH_MISMATCH, Some(0x50))
        );
    }

    #[test]
    fn other_relationships_and_bad_inputs() {
        for kind in [0, 2, 3, 0xFFFF, 5] {
            assert_eq!(
                relationship(Some(kind), 4, 1, 0x100),
                Answer::NotImplemented
            );
        }
        assert_eq!(
            relationship(Some(1), 3, 1, 0x100),
            Answer::Status(STATUS_INVALID_PARAMETER, None)
        );
        assert_eq!(
            relationship(None, 4, 1, 0x100),
            Answer::Status(STATUS_INVALID_PARAMETER, None)
        );
        assert_eq!(
            relationship(Some(1), 4, 0, 0x100),
            Answer::Status(STATUS_UNSUCCESSFUL, Some(0))
        );
    }

    fn steering(gsiv: u32, controller: u8) -> SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT {
        SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT {
            Gsiv: gsiv,
            ControllerInterrupt: controller,
            EdgeInterrupt: 0,
            IsPrimaryInterrupt: 0,
            TargetAffinity: GROUP_AFFINITY {
                Mask: 0,
                Group: 0,
                Reserved: [0; 3],
            },
        }
    }

    #[test]
    fn interrupts_are_not_steered() {
        // pci.sys's question.
        let all = steering(u32::MAX, 1);
        assert_eq!(interrupt_steering(Some(&all), 0x18, 4), Answer::Written(0));
        assert_eq!(
            interrupt_steering(Some(&all), 0x18, 3),
            Answer::Status(STATUS_INFO_LENGTH_MISMATCH, Some(4))
        );
        assert_eq!(
            interrupt_steering(Some(&all), 0x10, 4),
            Answer::Status(STATUS_INFO_LENGTH_MISMATCH, None)
        );
        assert_eq!(
            interrupt_steering(None, 0x18, 4),
            Answer::Status(STATUS_INFO_LENGTH_MISMATCH, None)
        );
        // One interrupt's mode.
        assert_eq!(
            interrupt_steering(Some(&steering(5, 1)), 0x18, 4),
            Answer::NotImplemented
        );
        assert_eq!(
            interrupt_steering(Some(&steering(u32::MAX, 0)), 0x18, 4),
            Answer::NotImplemented
        );
    }
}
