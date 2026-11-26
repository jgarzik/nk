//! Hardware error sources (WHEA) as pure functions, so the host can
//! test them: the descriptor the kernel builds for a device driver that
//! registers as a source, the sizes that follow from it, and the table
//! of sources with the states one passes through.
//!
//! The numbers are those of the pinned Windows kernel's code
//! (`WheaAddErrorSourceDeviceDriver`, `WheapInitializeErrorSource`,
//! `WheapAddErrorSource`, `WheaRemoveErrorSource`).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use core::ffi::c_void;
use nk_ntabi::ex::GUID;
use nk_ntabi::status::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER_2};
use nk_ntabi::whea::{
    WHEA_DEVICE_DRIVER_DESCRIPTOR, WHEA_ERR_SRC_STATE_REMOVE_PENDING, WHEA_ERR_SRC_STATE_REMOVED,
    WHEA_ERR_SRC_STATE_STARTED, WHEA_ERR_SRC_STATE_STOPPED, WHEA_ERR_SRC_TYPE_DEVICE_DRIVER,
    WHEA_ERROR_SOURCE_CONFIGURATION_DD, WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER,
    WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1, WHEA_ERROR_SOURCE_DESCRIPTOR,
    WHEA_ERROR_SOURCE_DESCRIPTOR_INFO, WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION_11,
};

/// The creator of the records of a version 1 device driver source:
/// `{57217C8D-5E66-44FB-8033-9B74CACEDF5B}`, the default creator.
pub const DEFAULT_CREATOR: GUID = GUID {
    Data1: 0x5721_7C8D,
    Data2: 0x5E66,
    Data3: 0x44FB,
    Data4: [0x80, 0x33, 0x9B, 0x74, 0xCA, 0xCE, 0xDF, 0x5B],
};

/// The partition of the records of a version 1 device driver source:
/// none.
pub const NO_PARTITION: GUID = GUID {
    Data1: 0,
    Data2: 0,
    Data3: 0,
    Data4: [0; 8],
};

/// Whether a source of this `WHEA_ERROR_SOURCE_TYPE` may be added and
/// removed while the system runs: every kind but those the firmware's
/// error source table describes (machine check, corrected machine
/// check, corrected platform error, NMI, INIT, boot, and the Itanium
/// three).
pub fn is_non_hest(kind: u32) -> bool {
    !matches!(kind, 0..=3 | 6 | 7 | 10 | 11)
}

/// The version 2 configuration `WheaAddErrorSourceDeviceDriverV1` makes
/// of a version 1 one: one section a report, of at most
/// `max_data_length` bytes.
pub fn v2_of_v1(
    v1: &WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1,
    max_data_length: u32,
) -> Result<WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER, NTSTATUS> {
    if v1.Version != 1 {
        return Err(STATUS_INVALID_PARAMETER_2);
    }
    Ok(WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER {
        Version: 2,
        SourceGuid: v1.SourceGuid,
        LogTag: v1.LogTag,
        Reserved: v1.Reserved,
        Initialize: v1.Initialize,
        Uninitialize: v1.Uninitialize,
        MaxSectionDataLength: max_data_length,
        MaxSectionsPerReport: 1,
        CreatorId: DEFAULT_CREATOR,
        PartitionId: NO_PARTITION,
    })
}

/// The bytes of one report packet of a device driver source whose
/// reports hold `sections` sections and `data_length` bytes of section
/// data in all.
pub fn packet_length(data_length: u32, sections: u32) -> u32 {
    let raw = sections
        .wrapping_mul(72)
        .wrapping_add(0x6C)
        .wrapping_add(data_length);
    raw.wrapping_sub(raw.wrapping_sub(1) & 7).wrapping_add(0x6F)
}

/// The bytes of one preallocated error record of a source whose records
/// hold `sections` sections of `section_length` bytes each.
pub fn record_length(section_length: u32, sections: u32) -> u32 {
    section_length
        .wrapping_add(0x48)
        .wrapping_mul(sections)
        .wrapping_add(0xAF)
        & !7
}

/// What a device driver source's `Correct` answers: the bytes of one
/// section of its records.
pub fn device_driver_section_length(max_raw_data_length: u32) -> u32 {
    max_raw_data_length.wrapping_add(0x50)
}

/// The packets a device driver source is to have preallocated: how many
/// and of what length. None when it asked for no buffers or for no
/// data.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Packets {
    pub count: u32,
    pub length: u32,
}

/// The descriptor of the source a device driver registers with
/// `config`, asking for `buffers` preallocated reports, and the packets
/// to allocate for it. `correct` is the kernel's routine for the
/// descriptor's `Correct`. The descriptor names no packet memory yet.
pub fn device_driver_descriptor(
    config: &WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER,
    buffers: u32,
    correct: *mut c_void,
) -> Result<(WHEA_ERROR_SOURCE_DESCRIPTOR, Option<Packets>), NTSTATUS> {
    if config.Initialize.is_null() || config.Uninitialize.is_null() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if config.Version != 2 {
        return Err(STATUS_INVALID_PARAMETER_2);
    }
    // Two sections more than the driver's own: the kernel's.
    let sections = config.MaxSectionsPerReport.wrapping_add(2);
    let data_length = sections.wrapping_mul(config.MaxSectionDataLength);
    let packets = (buffers != 0 && data_length != 0).then(|| Packets {
        count: buffers,
        length: packet_length(data_length, sections),
    });
    let driver = WHEA_DEVICE_DRIVER_DESCRIPTOR {
        Type: 0,
        Enabled: 0,
        Reserved: 0,
        SourceGuid: config.SourceGuid,
        LogTag: config.LogTag,
        Reserved2: 0,
        PacketLength: packets.map_or(0, |p| p.length),
        PacketCount: packets.map_or(0, |p| p.count),
        PacketBuffer: core::ptr::null_mut(),
        Config: WHEA_ERROR_SOURCE_CONFIGURATION_DD {
            Initialize: config.Initialize,
            Uninitialize: config.Uninitialize,
            Correct: correct,
        },
        CreatorId: config.CreatorId,
        PartitionId: config.PartitionId,
        MaxSectionDataLength: packets.map_or(0, |_| config.MaxSectionDataLength),
        MaxSectionsPerRecord: packets.map_or(0, |_| config.MaxSectionsPerReport),
        PacketStateBuffer: core::ptr::null_mut(),
        OpenHandles: 0,
    };
    let mut info = WHEA_ERROR_SOURCE_DESCRIPTOR_INFO { Bytes: [0; 932] };
    info.DeviceDriverDescriptor = driver;
    let descriptor = WHEA_ERROR_SOURCE_DESCRIPTOR {
        Length: size_of::<WHEA_ERROR_SOURCE_DESCRIPTOR>() as u32,
        Version: WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION_11,
        Type: WHEA_ERR_SRC_TYPE_DEVICE_DRIVER,
        State: WHEA_ERR_SRC_STATE_STOPPED,
        MaxRawDataLength: data_length,
        NumRecordsToPreallocate: buffers,
        MaxSectionsPerRecord: sections,
        ErrorSourceId: 0,
        PlatformErrorSourceId: 0,
        Flags: 0,
        Info: info,
    };
    Ok((descriptor, packets))
}

/// One source in the table: the kernel's own record of it. What a
/// driver can see of a source is its descriptor, a block of its own at
/// `descriptor`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Source {
    pub id: u32,
    /// `WHEA_ERROR_SOURCE_TYPE`.
    pub kind: u32,
    /// `WHEA_ERROR_SOURCE_STATE`.
    pub state: u32,
    /// Calls into the source's routines in progress; -1 once it is
    /// being removed and no more may begin.
    pub busy: i32,
    /// What the source's routines are called with.
    pub context: usize,
    /// The address of the source's descriptor.
    pub descriptor: usize,
}

/// What removing a source finds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Retire {
    /// A call into the source is in progress: try again later.
    Busy,
    /// No call is in progress and none will begin.
    Quiet,
}

/// The table of sources. Ids are not used again.
pub struct Table {
    next_id: u32,
    sources: Vec<Source>,
}

impl Table {
    pub const fn new() -> Self {
        Self {
            next_id: 0,
            sources: Vec::new(),
        }
    }

    /// Enter a source, stopped, and give it the next id: ids count from
    /// zero in the order sources are added. None, and no id is used,
    /// when there is no memory for the entry.
    pub fn insert(&mut self, kind: u32, context: usize, descriptor: usize) -> Option<u32> {
        self.sources.try_reserve(1).ok()?;
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.sources.push(Source {
            id,
            kind,
            state: WHEA_ERR_SRC_STATE_STOPPED,
            busy: 0,
            context,
            descriptor,
        });
        Some(id)
    }

    fn any(&mut self, id: u32) -> Option<&mut Source> {
        self.sources.iter_mut().find(|s| s.id == id)
    }

    /// The source `id`, if it is started: the only state in which a
    /// source is found by its id.
    pub fn started(&self, id: u32) -> Option<Source> {
        self.sources
            .iter()
            .find(|s| s.id == id && s.state == WHEA_ERR_SRC_STATE_STARTED)
            .copied()
    }

    /// Set the state of source `id`, whatever it is now.
    pub fn set_state(&mut self, id: u32, state: u32) {
        if let Some(source) = self.any(id) {
            source.state = state;
        }
    }

    /// Begin a call into a routine of source `id`: false, and no call
    /// is to be made, when the source is removed or being removed.
    pub fn enter(&mut self, id: u32) -> bool {
        match self.any(id) {
            Some(source) if source.state != WHEA_ERR_SRC_STATE_REMOVED && source.busy >= 0 => {
                source.busy += 1;
                true
            }
            _ => false,
        }
    }

    /// End a call begun with [`Table::enter`].
    pub fn leave(&mut self, id: u32) {
        if let Some(source) = self.any(id) {
            source.busy -= 1;
        }
    }

    /// Begin removing source `id`: it must be started and of a kind
    /// that may be removed. It is then pending removal, and is no
    /// longer found by its id.
    pub fn begin_remove(&mut self, id: u32) -> Option<Source> {
        let found = self.started(id)?;
        if !is_non_hest(found.kind) {
            return None;
        }
        self.set_state(id, WHEA_ERR_SRC_STATE_REMOVE_PENDING);
        Some(found)
    }

    /// Close source `id`, pending removal, to new calls, if none is in
    /// progress.
    pub fn retire(&mut self, id: u32) -> Retire {
        match self.any(id) {
            Some(source) if source.busy > 0 => Retire::Busy,
            Some(source) => {
                source.busy = -1;
                Retire::Quiet
            }
            None => Retire::Quiet,
        }
    }

    /// Drop the entry of source `id`, which nothing can reach any more:
    /// one removed, or one whose start failed. Its id stays used.
    pub fn forget(&mut self, id: u32) {
        self.sources.retain(|s| s.id != id);
    }

    /// The bytes of memory the table itself holds.
    pub fn storage(&self) -> usize {
        self.sources.capacity() * size_of::<Source>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v1() -> WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1 {
        WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1 {
            Version: 1,
            SourceGuid: GUID {
                Data1: 1,
                Data2: 2,
                Data3: 3,
                Data4: [4; 8],
            },
            LogTag: 0x5453,
            Reserved: [0; 6],
            Initialize: 0x1000 as *mut c_void,
            Uninitialize: 0x2000 as *mut c_void,
        }
    }

    #[test]
    fn kinds_the_firmware_describes_are_not_added_at_run_time() {
        for kind in [0, 1, 2, 3, 6, 7, 10, 11] {
            assert!(!is_non_hest(kind), "{kind}");
        }
        for kind in [4, 5, 8, 9, 12, 13, 14, 15, 16, 17, 1000] {
            assert!(is_non_hest(kind), "{kind}");
        }
    }

    #[test]
    fn version_one_becomes_one_section_of_the_default_creator() {
        let v2 = v2_of_v1(&v1(), 0x464).unwrap();
        assert_eq!({ v2.Version }, 2);
        assert_eq!({ v2.MaxSectionDataLength }, 0x464);
        assert_eq!({ v2.MaxSectionsPerReport }, 1);
        assert_eq!({ v2.CreatorId }, DEFAULT_CREATOR);
        assert_eq!({ v2.PartitionId }, NO_PARTITION);
        assert_eq!({ v2.LogTag }, 0x5453);
        assert_eq!({ v2.Initialize } as usize, 0x1000);
        assert_eq!({ v2.Uninitialize } as usize, 0x2000);
        let mut other = v1();
        other.Version = 2;
        assert_eq!(v2_of_v1(&other, 1).err(), Some(STATUS_INVALID_PARAMETER_2));
    }

    #[test]
    fn lengths_are_those_of_windows() {
        // storport's source: one section of 0x464 bytes, so three in a
        // record and 0xD2C bytes of data.
        assert_eq!(packet_length(0xD2C, 3), 0xED8);
        assert_eq!(packet_length(1, 1), 0x120);
        assert_eq!(device_driver_section_length(0xD2C), 0xD7C);
        assert_eq!(record_length(0xD7C, 3), 0x29F8);
        assert_eq!(record_length(0, 0), 0xA8);
    }

    #[test]
    fn descriptor_of_a_device_driver() {
        let v2 = v2_of_v1(&v1(), 0x464).unwrap();
        let correct = 0x3000 as *mut c_void;
        let (d, packets) = device_driver_descriptor(&v2, 1, correct).unwrap();
        assert_eq!({ d.Length }, 0x3CC);
        assert_eq!({ d.Version }, 11);
        assert_eq!({ d.Type }, 16);
        assert_eq!({ d.State }, WHEA_ERR_SRC_STATE_STOPPED);
        assert_eq!({ d.MaxRawDataLength }, 0xD2C);
        assert_eq!({ d.NumRecordsToPreallocate }, 1);
        assert_eq!({ d.MaxSectionsPerRecord }, 3);
        assert_eq!(
            packets,
            Some(Packets {
                count: 1,
                length: 0xED8
            })
        );
        // SAFETY: the member the builder filled in.
        let dd = unsafe { d.Info.DeviceDriverDescriptor };
        assert_eq!({ dd.SourceGuid }, { v2.SourceGuid });
        assert_eq!({ dd.LogTag }, 0x5453);
        assert_eq!({ dd.PacketLength }, 0xED8);
        assert_eq!({ dd.PacketCount }, 1);
        assert_eq!({ dd.Config.Initialize } as usize, 0x1000);
        assert_eq!({ dd.Config.Uninitialize } as usize, 0x2000);
        assert_eq!({ dd.Config.Correct } as usize, 0x3000);
        assert_eq!({ dd.CreatorId }, DEFAULT_CREATOR);
        assert_eq!({ dd.MaxSectionDataLength }, 0x464);
        assert_eq!({ dd.MaxSectionsPerRecord }, 1);
        assert!({ dd.PacketBuffer }.is_null());

        // No buffers asked for: no packets, and the packet fields stay
        // zero.
        let (d, packets) = device_driver_descriptor(&v2, 0, correct).unwrap();
        assert_eq!(packets, None);
        // SAFETY: as above.
        let dd = unsafe { d.Info.DeviceDriverDescriptor };
        assert_eq!({ dd.PacketLength }, 0);
        assert_eq!({ dd.MaxSectionDataLength }, 0);
        assert_eq!({ d.MaxRawDataLength }, 0xD2C);
    }

    #[test]
    fn descriptor_refuses_what_windows_refuses() {
        let good = v2_of_v1(&v1(), 8).unwrap();
        let correct = core::ptr::null_mut();
        let mut bad = good;
        bad.Initialize = core::ptr::null_mut();
        assert_eq!(
            device_driver_descriptor(&bad, 1, correct).err(),
            Some(STATUS_INVALID_PARAMETER)
        );
        let mut bad = good;
        bad.Uninitialize = core::ptr::null_mut();
        assert_eq!(
            device_driver_descriptor(&bad, 1, correct).err(),
            Some(STATUS_INVALID_PARAMETER)
        );
        let mut bad = good;
        bad.Version = 1;
        assert_eq!(
            device_driver_descriptor(&bad, 1, correct).err(),
            Some(STATUS_INVALID_PARAMETER_2)
        );
    }

    #[test]
    fn ids_count_from_zero_and_a_source_is_found_only_started() {
        let mut table = Table::new();
        assert_eq!(table.storage(), 0);
        assert_eq!(table.insert(16, 7, 0x100), Some(0));
        assert!(table.storage() >= size_of::<Source>());
        assert_eq!(table.insert(4, 8, 0x200), Some(1));
        assert_eq!(table.started(0), None);
        table.set_state(0, WHEA_ERR_SRC_STATE_STARTED);
        let found = table.started(0).unwrap();
        assert_eq!(
            (found.kind, found.context, found.descriptor),
            (16, 7, 0x100)
        );
        assert_eq!(table.started(1), None);
        assert_eq!(table.started(2), None);
        // A state for a source that does not exist changes nothing.
        table.set_state(9, WHEA_ERR_SRC_STATE_STARTED);
        assert_eq!(table.started(9), None);
    }

    #[test]
    fn removal_waits_for_calls_and_closes_the_source() {
        let mut table = Table::new();
        let id = table.insert(16, 0, 0).unwrap();
        // Not started: not removable.
        assert_eq!(table.begin_remove(id), None);
        table.set_state(id, WHEA_ERR_SRC_STATE_STARTED);
        assert!(table.enter(id));
        assert_eq!(table.begin_remove(id).map(|s| s.id), Some(id));
        // Pending: not found, and not removable twice.
        assert_eq!(table.started(id), None);
        assert_eq!(table.begin_remove(id), None);
        assert_eq!(table.retire(id), Retire::Busy);
        table.leave(id);
        assert_eq!(table.retire(id), Retire::Quiet);
        assert!(!table.enter(id));
        table.set_state(id, WHEA_ERR_SRC_STATE_REMOVED);
        assert!(!table.enter(id));
        table.forget(id);
        table.set_state(id, WHEA_ERR_SRC_STATE_STARTED);
        assert_eq!(table.started(id), None);
        // The id is not used again.
        assert_eq!(table.insert(16, 0, 0), Some(1));
        // Nothing to do for sources that do not exist.
        assert!(!table.enter(77));
        table.leave(77);
        assert_eq!(table.retire(77), Retire::Quiet);
    }

    #[test]
    fn a_source_the_firmware_describes_is_not_removed() {
        let mut table = Table::new();
        let id = table.insert(0, 0, 0).unwrap();
        table.set_state(id, WHEA_ERR_SRC_STATE_STARTED);
        assert_eq!(table.begin_remove(id), None);
        assert!(table.started(id).is_some());
        // A removed source takes no calls even with none in progress.
        table.set_state(id, WHEA_ERR_SRC_STATE_REMOVED);
        assert!(!table.enter(id));
    }
}
