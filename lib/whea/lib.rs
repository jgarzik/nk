//! Hardware error sources (WHEA) as pure functions, so the host can
//! test them: the descriptor the kernel builds for a device driver that
//! registers as a source, the sizes that follow from it, and the table
//! of sources with the states one passes through, the routines
//! configured for each kind of source, and the error record made of a
//! report.
//!
//! The numbers are those of the pinned Windows kernel's code
//! (`WheaAddErrorSourceDeviceDriver`, `WheapInitializeErrorSource`,
//! `WheapAddErrorSource`, `WheaRemoveErrorSource`).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use core::ffi::c_void;
use nk_ntabi::ex::GUID;
use nk_ntabi::status::{
    NTSTATUS, STATUS_DEVICE_DOES_NOT_EXIST, STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER_2,
    STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};
use nk_ntabi::whea::{
    WHEA_DEVICE_DRIVER_DESCRIPTOR, WHEA_ERR_SEV_FATAL, WHEA_ERR_SEV_INFORMATIONAL,
    WHEA_ERR_SRC_STATE_REMOVE_PENDING, WHEA_ERR_SRC_STATE_REMOVED, WHEA_ERR_SRC_STATE_STARTED,
    WHEA_ERR_SRC_STATE_STOPPED, WHEA_ERR_SRC_TYPE_DEVICE_DRIVER, WHEA_ERROR_RECORD_HEADER,
    WHEA_ERROR_RECORD_SECTION_DESCRIPTOR, WHEA_ERROR_SOURCE_CONFIGURATION_DD,
    WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER,
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
    /// The report packets and their states the kernel allocated for
    /// the source, 0 for none. The descriptor names packets too, but
    /// a descriptor may come from a driver: these are the ones to free.
    pub packets: [usize; 2],
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
    pub fn insert(
        &mut self,
        kind: u32,
        context: usize,
        descriptor: usize,
        packets: [usize; 2],
    ) -> Option<u32> {
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
            packets,
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

/// `WHEA_RECORD_CREATOR_GUID`: the creator `WheaInitializeRecordHeader`
/// writes, Microsoft's.
pub const RECORD_CREATOR: GUID = GUID {
    Data1: 0xCF07_C4BD,
    Data2: 0xB789,
    Data3: 0x4E18,
    Data4: [0xB3, 0xC4, 0x1F, 0x73, 0x2C, 0xB5, 0x71, 0x31],
};

/// `DEVICE_DRIVER_NOTIFY_TYPE_GUID`: how the error of a device driver
/// source was notified.
pub const DEVICE_DRIVER_NOTIFY_TYPE: GUID = GUID {
    Data1: 0x0033_F803,
    Data2: 0x2E70,
    Data3: 0x4E88,
    Data4: [0x99, 0x2C, 0x6F, 0x26, 0xDA, 0xF3, 0xDB, 0x7A],
};

/// A `WHEA_TIMESTAMP` for `system_time` (100 ns units since 1601, UTC):
/// seconds, minutes, hours, a byte of flags (zero: not precise), day,
/// month, year in the century, century, a byte each from the lowest.
pub fn timestamp(system_time: u64) -> u64 {
    let seconds = system_time / 10_000_000;
    let (days, of_day) = (seconds / 86_400, seconds % 86_400);
    // Days since 1601-01-01 to a civil date: count from 1600-03-01, in
    // 400-year eras, with the year starting in March.
    let z = days + 306;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = 1600 + era * 400 + yoe + u64::from(month <= 2);
    u64::from_le_bytes([
        (of_day % 60) as u8,
        (of_day / 60 % 60) as u8,
        (of_day / 3_600) as u8,
        0,
        day as u8,
        month as u8,
        (year % 100) as u8,
        (year / 100) as u8,
    ])
}

/// The header `WheaInitializeRecordHeader` writes: a record of no
/// section yet, informational, made now by Microsoft's creator, with
/// the next record id.
pub fn record_header(system_time: u64, record_id: u64) -> WHEA_ERROR_RECORD_HEADER {
    WHEA_ERROR_RECORD_HEADER {
        Signature: u32::from_le_bytes(*b"CPER"),
        Revision: 0x210,
        SignatureEnd: 0xFFFF_FFFF,
        SectionCount: 0,
        Severity: WHEA_ERR_SEV_INFORMATIONAL,
        ValidBits: VALID_TIMESTAMP,
        Length: 0,
        Timestamp: timestamp(system_time),
        PlatformId: NO_PARTITION,
        PartitionId: NO_PARTITION,
        CreatorId: RECORD_CREATOR,
        NotifyType: NO_PARTITION,
        RecordId: record_id,
        Flags: 0,
        PersistenceInfo: 0,
        Reserved: [0; 12],
    }
}

/// `WHEA_ERROR_RECORD_HEADER_VALIDBITS`.
const VALID_PLATFORM_ID: u32 = 1;
const VALID_TIMESTAMP: u32 = 2;
const VALID_PARTITION_ID: u32 = 4;
/// `WHEA_ERROR_RECORD_HEADER_FLAGS`: the record is a device driver's.
const FLAG_DEVICE_DRIVER: u32 = 8;
/// A section descriptor's `ValidBits`: the FRU text is there. Its
/// `Flags`: the section is the primary one.
const SECTION_FRU_TEXT: u8 = 2;
const SECTION_PRIMARY: u32 = 1;

/// The bytes of a report's bookkeeping in its packet before any
/// section, and of each section's own.
const REPORT_OVERHEAD: u32 = 0x64;
const SECTION_OVERHEAD: u32 = 0x48;
/// The most log data a report carries.
pub const MAX_LOG_DATA: u32 = 0x24;

/// Whether a device driver source may report one section of
/// `data_length` bytes with `log_length` bytes of log data, by the
/// limits its descriptor holds: Windows' checks, each of which fails
/// with `STATUS_INSUFFICIENT_RESOURCES`. A source registered with no
/// buffers has no section to report in.
pub fn device_driver_report_fits(
    driver: &WHEA_DEVICE_DRIVER_DESCRIPTOR,
    max_raw_data_length: u32,
    data_length: u32,
    log_length: u32,
) -> bool {
    let after_section = REPORT_OVERHEAD
        .checked_add(data_length)
        .and_then(|used| used.checked_add(SECTION_OVERHEAD));
    driver.MaxSectionsPerRecord != 0
        && data_length <= driver.MaxSectionDataLength
        && REPORT_OVERHEAD.saturating_add(data_length) <= max_raw_data_length
        && after_section
            .and_then(|used| used.checked_add(log_length))
            .is_some_and(|used| used <= max_raw_data_length)
}

/// One report of a device driver source.
pub struct Report<'a> {
    /// The source's descriptor, as registered.
    pub driver: &'a WHEA_DEVICE_DRIVER_DESCRIPTOR,
    pub severity: u32,
    pub section_type: GUID,
    /// The device's name, without a terminator; cut to 19 characters.
    pub device_name: &'a [u8],
    pub data: &'a [u8],
    pub system_time: u64,
    pub record_id: u64,
}

/// The error record of a device driver's report: a header, one section
/// descriptor, the driver's data. None when there is no memory for it.
///
/// The header is `WheaInitializeRecordHeader`'s, with what Windows'
/// device driver source adds: the source's GUID as the platform, its
/// creator and partition, the device driver notify type and flag. The
/// section is the driver's, marked primary, its text the device name.
/// Windows' record also carries sections of its own (the error packet,
/// what the platform driver adds); NK's does not.
pub fn device_driver_record(report: &Report<'_>) -> Option<Vec<u8>> {
    let header_length = size_of::<WHEA_ERROR_RECORD_HEADER>();
    let descriptor_length = size_of::<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR>();
    let offset = header_length + descriptor_length;
    let length = offset.checked_add(report.data.len())?;
    let mut header = record_header(report.system_time, report.record_id);
    header.SectionCount = 1;
    header.Severity = report.severity;
    header.ValidBits |= VALID_PLATFORM_ID | VALID_PARTITION_ID;
    header.Length = u32::try_from(length).ok()?;
    header.PlatformId = report.driver.SourceGuid;
    header.PartitionId = report.driver.PartitionId;
    header.CreatorId = report.driver.CreatorId;
    header.NotifyType = DEVICE_DRIVER_NOTIFY_TYPE;
    header.Flags = FLAG_DEVICE_DRIVER;
    let mut text = [0u8; 20];
    for (to, from) in text.iter_mut().take(19).zip(report.device_name) {
        *to = *from;
    }
    let section = WHEA_ERROR_RECORD_SECTION_DESCRIPTOR {
        SectionOffset: offset as u32,
        SectionLength: report.data.len() as u32,
        Revision: 0x300,
        ValidBits: SECTION_FRU_TEXT,
        Reserved: 0,
        Flags: SECTION_PRIMARY,
        SectionType: report.section_type,
        FRUId: NO_PARTITION,
        SectionSeverity: report.severity,
        FRUText: text,
    };
    let mut record = Vec::new();
    record.try_reserve_exact(length).ok()?;
    // SAFETY: both are plain data of the sizes named, with no padding:
    // they are packed.
    unsafe {
        record.extend_from_slice(core::slice::from_raw_parts(
            (&raw const header).cast::<u8>(),
            header_length,
        ));
        record.extend_from_slice(core::slice::from_raw_parts(
            (&raw const section).cast::<u8>(),
            descriptor_length,
        ));
    }
    record.extend_from_slice(report.data);
    Some(record)
}

/// What `WheaReportHwError` does with a packet before it makes a
/// record.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Packet {
    /// Return this status.
    Status(NTSTATUS),
    /// Stop the system: `WHEA_INTERNAL_ERROR` (0x122), parameter 1 the
    /// number 9, "no such source".
    NoSourceStop,
    /// Make the record: the source is known. The severity is the
    /// packet's, without the two marks.
    Record { severity: u32 },
}

/// The two high bits of a packet's severity are marks the device
/// driver routines set, never both: a device driver's report, and a
/// fatal one.
const MARK_DEVICE_DRIVER: u32 = 1 << 31;
const MARK_FATAL_DEVICE_DRIVER: u32 = 1 << 30;
/// A packet's `Flags`: the error is of a previous session.
const PACKET_PREVIOUS_ERROR: u32 = 1;

/// Decide a packet by its severity and flags and whether its source is
/// a started one.
///
/// | Packet | Outcome |
/// | --- | --- |
/// | both marks set | `STATUS_INVALID_PARAMETER` |
/// | informational, not a device driver's | `STATUS_SUCCESS`, nothing done |
/// | no such source, recoverable or fatal, of this session | the system stops, `WHEA_INTERNAL_ERROR` |
/// | no such source otherwise | `STATUS_DEVICE_DOES_NOT_EXIST` |
pub fn packet(severity: u32, flags: u32, source_found: bool) -> Packet {
    let marks = MARK_DEVICE_DRIVER | MARK_FATAL_DEVICE_DRIVER;
    if severity & marks == marks {
        return Packet::Status(STATUS_INVALID_PARAMETER);
    }
    let device_driver = severity & MARK_DEVICE_DRIVER != 0;
    let severity = severity & !marks;
    if severity == WHEA_ERR_SEV_INFORMATIONAL && !device_driver {
        return Packet::Status(STATUS_SUCCESS);
    }
    if source_found {
        Packet::Record { severity }
    } else if severity <= WHEA_ERR_SEV_FATAL && flags & PACKET_PREVIOUS_ERROR == 0 {
        Packet::NoSourceStop
    } else {
        Packet::Status(STATUS_DEVICE_DOES_NOT_EXIST)
    }
}

/// A section of an error record, as `HalBugCheckSystem` looks at it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FatalSection {
    /// A non-maskable interrupt (`NMI_SECTION_GUID`), and whether it
    /// was the hypervisor's.
    Nmi { hypervisor: bool },
    /// A machine check (`XPF_MCA_SECTION_GUID`): its `MCi_STATUS`.
    MachineCheck { status: u64 },
    /// Anything else.
    Other,
}

/// `HalBugCheckSystem`: the stop code and parameters for the fatal
/// error whose record is at address `record`, with these `sections` in
/// order, from a source of type `source_type`. As the pinned kernel
/// decides it:
///
/// | First section that decides | Stop |
/// | --- | --- |
/// | an NMI not the hypervisor's | `NMI_HARDWARE_FAILURE` (0x80), parameter 1 0x4F4454 |
/// | a machine check | `WHEA_UNCORRECTABLE_ERROR` (0x124): the source's type, the record, the high and the low half of `MCi_STATUS` |
/// | none | `WHEA_UNCORRECTABLE_ERROR`: the source's type, the record, 0, 0 |
pub fn fatal_stop(
    source_type: u32,
    record: usize,
    sections: impl IntoIterator<Item = FatalSection>,
) -> (u32, [usize; 4]) {
    let mut status = 0u64;
    for section in sections {
        match section {
            FatalSection::Nmi { hypervisor: false } => return (0x80, [0x4F_4454, 0, 0, 0]),
            FatalSection::MachineCheck { status: bank } => {
                status = bank;
                break;
            }
            FatalSection::Nmi { hypervisor: true } | FatalSection::Other => {}
        }
    }
    (
        0x124,
        [
            source_type as i32 as isize as usize,
            record,
            (status >> 32) as usize,
            status as u32 as usize,
        ],
    )
}

/// The routines of one kind of source, 0 for one not given: what
/// `WheaConfigureErrorSource` records of a configuration, as far as NK
/// calls them.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Routines {
    pub correct: usize,
    pub initialize: usize,
    pub uninitialize: usize,
}

/// The configuration of every kind of source.
pub struct Configurations([Option<Routines>; KINDS]);

/// How many kinds of source can be configured: up to the device
/// driver's.
const KINDS: usize = WHEA_ERR_SRC_TYPE_DEVICE_DRIVER as usize + 1;

impl Configurations {
    pub const fn new() -> Self {
        Self([None; KINDS])
    }

    /// Record the routines of sources of `kind`:
    /// `STATUS_INVALID_PARAMETER` for a kind past the table,
    /// `STATUS_UNSUCCESSFUL` for one configured already.
    pub fn configure(&mut self, kind: u32, routines: Routines) -> NTSTATUS {
        match self.0.get_mut(kind as usize) {
            None => STATUS_INVALID_PARAMETER,
            Some(Some(_)) => STATUS_UNSUCCESSFUL,
            Some(slot) => {
                *slot = Some(routines);
                STATUS_SUCCESS
            }
        }
    }

    /// Forget the routines of sources of `kind`. As Windows' routine
    /// does, this answers `STATUS_UNSUCCESSFUL` whether or not the kind
    /// was configured, and `STATUS_INVALID_PARAMETER` past the table.
    pub fn unconfigure(&mut self, kind: u32) -> NTSTATUS {
        match self.0.get_mut(kind as usize) {
            None => STATUS_INVALID_PARAMETER,
            Some(slot) => {
                *slot = None;
                STATUS_UNSUCCESSFUL
            }
        }
    }

    /// The routines of sources of `kind`: none given where the kind is
    /// not configured.
    pub fn routines(&self, kind: u32) -> Routines {
        self.0
            .get(kind as usize)
            .copied()
            .flatten()
            .unwrap_or_default()
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
        assert_eq!(table.insert(16, 7, 0x100, [0x10, 0x20]), Some(0));
        assert!(table.storage() >= size_of::<Source>());
        assert_eq!(table.insert(4, 8, 0x200, [0; 2]), Some(1));
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
        let id = table.insert(16, 0, 0, [0; 2]).unwrap();
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
        assert_eq!(table.insert(16, 0, 0, [0; 2]), Some(1));
        // Nothing to do for sources that do not exist.
        assert!(!table.enter(77));
        table.leave(77);
        assert_eq!(table.retire(77), Retire::Quiet);
    }

    #[test]
    fn a_source_the_firmware_describes_is_not_removed() {
        let mut table = Table::new();
        let id = table.insert(0, 0, 0, [0; 2]).unwrap();
        table.set_state(id, WHEA_ERR_SRC_STATE_STARTED);
        assert_eq!(table.begin_remove(id), None);
        assert!(table.started(id).is_some());
        // A removed source takes no calls even with none in progress.
        table.set_state(id, WHEA_ERR_SRC_STATE_REMOVED);
        assert!(!table.enter(id));
    }

    fn driver() -> WHEA_DEVICE_DRIVER_DESCRIPTOR {
        let v2 = v2_of_v1(&v1(), 0x464).unwrap();
        let (d, _) = device_driver_descriptor(&v2, 1, core::ptr::null_mut()).unwrap();
        // SAFETY: the member the builder filled in.
        unsafe { d.Info.DeviceDriverDescriptor }
    }

    #[test]
    fn timestamps_are_calendar_fields() {
        let at = |unix: u64| timestamp((unix + 11_644_473_600) * 10_000_000);
        assert_eq!(timestamp(0).to_le_bytes(), [0, 0, 0, 0, 1, 1, 1, 16]);
        assert_eq!(at(0).to_le_bytes(), [0, 0, 0, 0, 1, 1, 70, 19]);
        // 2024-02-29 23:59:59, and the second after.
        assert_eq!(
            at(1_709_251_199).to_le_bytes(),
            [59, 59, 23, 0, 29, 2, 24, 20]
        );
        assert_eq!(at(1_709_251_200).to_le_bytes(), [0, 0, 0, 0, 1, 3, 24, 20]);
        // 2000-12-31 12:30:45: the last day of a leap century year.
        assert_eq!(
            at(978_265_845).to_le_bytes(),
            [45, 30, 12, 0, 31, 12, 0, 20]
        );
        // 2100-03-01: 2100 is not a leap year.
        assert_eq!(at(4_107_542_400).to_le_bytes(), [0, 0, 0, 0, 1, 3, 0, 21]);
    }

    #[test]
    fn a_fresh_header_is_an_empty_informational_record() {
        let h = record_header(0, 0x55);
        assert_eq!({ h.Signature }, 0x5245_5043);
        assert_eq!({ h.Revision }, 0x210);
        assert_eq!({ h.SignatureEnd }, u32::MAX);
        assert_eq!({ h.SectionCount }, 0);
        assert_eq!({ h.Severity }, 3);
        assert_eq!({ h.ValidBits }, 2);
        assert_eq!({ h.CreatorId }, RECORD_CREATOR);
        assert_eq!({ h.RecordId }, 0x55);
        assert_eq!({ h.Timestamp }, timestamp(0));
    }

    #[test]
    fn a_report_must_fit_the_source() {
        let d = driver();
        let raw = 3 * 0x464;
        assert!(device_driver_report_fits(&d, raw, 0x464, 0x24));
        assert!(device_driver_report_fits(&d, raw, 0, 0));
        // More than a section holds.
        assert!(!device_driver_report_fits(&d, raw, 0x465, 0));
        // More than the record holds, with and without the log data.
        assert!(!device_driver_report_fits(&d, 0x64 + 0x10 - 1, 0x10, 0));
        assert!(device_driver_report_fits(&d, 0x64 + 0x48 + 0x10, 0x10, 0));
        assert!(!device_driver_report_fits(&d, 0x64 + 0x48 + 0x10, 0x10, 1));
        assert!(!device_driver_report_fits(&d, u32::MAX, u32::MAX, 0x24));
        // A source registered without buffers has no section.
        let mut none = d;
        none.MaxSectionsPerRecord = 0;
        assert!(!device_driver_report_fits(&none, raw, 1, 0));
    }

    #[test]
    fn a_device_drivers_record() {
        let d = driver();
        let data = [0xA5u8; 0x30];
        let section_type = GUID {
            Data1: 9,
            Data2: 8,
            Data3: 7,
            Data4: [6; 8],
        };
        let record = device_driver_record(&Report {
            driver: &d,
            severity: 1,
            section_type,
            device_name: b"a device name of more than nineteen",
            data: &data,
            system_time: 0,
            record_id: 77,
        })
        .unwrap();
        assert_eq!(record.len(), 0x80 + 0x48 + 0x30);
        // SAFETY: the record begins with a header and a descriptor.
        let (h, s) = unsafe {
            (
                record
                    .as_ptr()
                    .cast::<WHEA_ERROR_RECORD_HEADER>()
                    .read_unaligned(),
                record
                    .as_ptr()
                    .add(0x80)
                    .cast::<WHEA_ERROR_RECORD_SECTION_DESCRIPTOR>()
                    .read_unaligned(),
            )
        };
        assert_eq!({ h.Signature }, 0x5245_5043);
        assert_eq!({ h.SectionCount }, 1);
        assert_eq!({ h.Severity }, 1);
        assert_eq!({ h.ValidBits }, 7);
        assert_eq!({ h.Length }, 0xF8);
        assert_eq!({ h.PlatformId }, { d.SourceGuid });
        assert_eq!({ h.CreatorId }, DEFAULT_CREATOR);
        assert_eq!({ h.PartitionId }, NO_PARTITION);
        assert_eq!({ h.NotifyType }, DEVICE_DRIVER_NOTIFY_TYPE);
        assert_eq!({ h.RecordId }, 77);
        assert_eq!({ h.Flags }, 8);
        assert_eq!({ s.SectionOffset }, 0xC8);
        assert_eq!({ s.SectionLength }, 0x30);
        assert_eq!({ s.Revision }, 0x300);
        assert_eq!({ s.ValidBits }, 2);
        assert_eq!({ s.Flags }, 1);
        assert_eq!({ s.SectionType }, section_type);
        assert_eq!({ s.SectionSeverity }, 1);
        assert_eq!(&s.FRUText, b"a device name of mo\0");
        assert_eq!(&record[0xC8..], &data);
    }

    #[test]
    fn a_fatal_error_stops_by_its_first_nmi_or_machine_check() {
        use FatalSection::{MachineCheck, Nmi, Other};
        let check = MachineCheck {
            status: 0xB200_0000_1234_5678,
        };
        let whea = |status: u64| {
            (
                0x124,
                [4, 0x7000, (status >> 32) as usize, status as u32 as usize],
            )
        };
        assert_eq!(fatal_stop(4, 0x7000, []), whea(0));
        assert_eq!(fatal_stop(4, 0x7000, [Other, Other]), whea(0));
        assert_eq!(
            fatal_stop(4, 0x7000, [Other, check]),
            whea(0xB200_0000_1234_5678)
        );
        let nmi = (0x80, [0x4F_4454, 0, 0, 0]);
        assert_eq!(fatal_stop(4, 0x7000, [Nmi { hypervisor: false }]), nmi);
        assert_eq!(
            fatal_stop(4, 0x7000, [Other, Nmi { hypervisor: false }, check]),
            nmi
        );
        // The hypervisor's NMI decides nothing.
        assert_eq!(
            fatal_stop(4, 0x7000, [Nmi { hypervisor: true }, Other]),
            whea(0)
        );
        assert_eq!(
            fatal_stop(4, 0x7000, [Nmi { hypervisor: true }, check]),
            whea(0xB200_0000_1234_5678)
        );
        // The first machine check ends the search: an NMI after it is
        // not looked at, nor a second machine check.
        assert_eq!(
            fatal_stop(
                4,
                0x7000,
                [check, Nmi { hypervisor: false }, MachineCheck { status: 1 }]
            ),
            whea(0xB200_0000_1234_5678)
        );
        // The type is a signed number, widened.
        assert_eq!(fatal_stop(0xFFFF_FFFF, 0, []).1[0], usize::MAX);
    }

    #[test]
    fn packets_are_judged_by_severity_and_source() {
        let dd = 1 << 31;
        let fatal_dd = 1 << 30;
        assert_eq!(
            packet(dd | fatal_dd | 1, 0, true),
            Packet::Status(STATUS_INVALID_PARAMETER)
        );
        // Informational: dropped, unless a device driver's.
        assert_eq!(packet(3, 0, true), Packet::Status(STATUS_SUCCESS));
        assert_eq!(packet(3, 0, false), Packet::Status(STATUS_SUCCESS));
        assert_eq!(packet(dd | 3, 0, true), Packet::Record { severity: 3 });
        assert_eq!(packet(dd | 1, 0, true), Packet::Record { severity: 1 });
        assert_eq!(
            packet(fatal_dd | 1, 0, true),
            Packet::Record { severity: 1 }
        );
        assert_eq!(packet(2, 0, true), Packet::Record { severity: 2 });
        // No such source.
        assert_eq!(packet(0, 0, false), Packet::NoSourceStop);
        assert_eq!(packet(1, 0, false), Packet::NoSourceStop);
        assert_eq!(
            packet(1, 1, false),
            Packet::Status(STATUS_DEVICE_DOES_NOT_EXIST)
        );
        assert_eq!(
            packet(2, 0, false),
            Packet::Status(STATUS_DEVICE_DOES_NOT_EXIST)
        );
    }

    #[test]
    fn a_kind_is_configured_once() {
        let mut c = Configurations::new();
        let routines = Routines {
            correct: 1,
            initialize: 2,
            uninitialize: 3,
        };
        assert_eq!(c.routines(4), Routines::default());
        assert_eq!(c.configure(4, routines), STATUS_SUCCESS);
        assert_eq!(c.routines(4), routines);
        assert_eq!(c.configure(4, Routines::default()), STATUS_UNSUCCESSFUL);
        assert_eq!(c.routines(4), routines);
        assert_eq!(c.configure(17, routines), STATUS_INVALID_PARAMETER);
        assert_eq!(c.routines(17), Routines::default());
        // Windows' routine reports failure even when it forgets one.
        assert_eq!(c.unconfigure(4), STATUS_UNSUCCESSFUL);
        assert_eq!(c.routines(4), Routines::default());
        assert_eq!(c.unconfigure(4), STATUS_UNSUCCESSFUL);
        assert_eq!(c.unconfigure(17), STATUS_INVALID_PARAMETER);
        assert_eq!(c.configure(16, routines), STATUS_SUCCESS);
    }
}
