//! The Windows Hardware Error Architecture, as far as a driver's own
//! structures go: what a driver hands the kernel to become a source of
//! hardware errors, and the descriptor the kernel keeps for it.
//!
//! Every structure here is packed to one byte, as `whea.h`'s are.

use crate::ex::GUID;
use core::ffi::c_void;

/// `WHEA_ERROR_SOURCE_TYPE`: what kind of source a descriptor is of.
pub const WHEA_ERR_SRC_TYPE_MCE: u32 = 0;
pub const WHEA_ERR_SRC_TYPE_PCIE: u32 = 4;
pub const WHEA_ERR_SRC_TYPE_BOOT: u32 = 7;
pub const WHEA_ERR_SRC_TYPE_DEVICE_DRIVER: u32 = 16;

/// `WHEA_ERROR_SOURCE_STATE`.
pub const WHEA_ERR_SRC_STATE_STOPPED: u32 = 1;
pub const WHEA_ERR_SRC_STATE_STARTED: u32 = 2;
pub const WHEA_ERR_SRC_STATE_REMOVED: u32 = 3;
pub const WHEA_ERR_SRC_STATE_REMOVE_PENDING: u32 = 4;

/// `WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION_11`: the version of the
/// descriptor the kernel builds for a device driver.
pub const WHEA_ERROR_SOURCE_DESCRIPTOR_VERSION_11: u32 = 11;

/// `WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1`: what a driver
/// hands [`WheaAddErrorSourceDeviceDriverV1`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-wheaadderrorsourcedevicedriverv1).
/// The callbacks are the driver's:
/// `NTSTATUS Initialize(PVOID Context, ULONG ErrorSourceId)` and
/// `VOID Uninitialize(PVOID Context)`.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1 {
    pub Version: u32,
    pub SourceGuid: GUID,
    pub LogTag: u16,
    pub Reserved: [u8; 6],
    pub Initialize: *mut c_void,
    pub Uninitialize: *mut c_void,
}

/// [`WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_error_source_configuration_device_driver):
/// version 2 of the above.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER {
    pub Version: u32,
    pub SourceGuid: GUID,
    pub LogTag: u16,
    pub Reserved: [u8; 6],
    pub Initialize: *mut c_void,
    pub Uninitialize: *mut c_void,
    pub MaxSectionDataLength: u32,
    pub MaxSectionsPerReport: u32,
    pub CreatorId: GUID,
    pub PartitionId: GUID,
}

/// `WHEA_ERROR_SOURCE_CONFIGURATION_DD`: a device driver source's
/// callbacks, as its descriptor holds them. `Correct` is the kernel's.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct WHEA_ERROR_SOURCE_CONFIGURATION_DD {
    pub Initialize: *mut c_void,
    pub Uninitialize: *mut c_void,
    pub Correct: *mut c_void,
}

/// `WHEA_DEVICE_DRIVER_DESCRIPTOR`: the part of a descriptor that is
/// particular to a device driver source.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct WHEA_DEVICE_DRIVER_DESCRIPTOR {
    pub Type: u16,
    pub Enabled: u8,
    pub Reserved: u8,
    pub SourceGuid: GUID,
    pub LogTag: u16,
    pub Reserved2: u16,
    pub PacketLength: u32,
    pub PacketCount: u32,
    pub PacketBuffer: *mut u8,
    pub Config: WHEA_ERROR_SOURCE_CONFIGURATION_DD,
    pub CreatorId: GUID,
    pub PartitionId: GUID,
    pub MaxSectionDataLength: u32,
    pub MaxSectionsPerRecord: u32,
    pub PacketStateBuffer: *mut u8,
    pub OpenHandles: i32,
}

/// The `Info` union of a descriptor: one member per kind of source.
/// NK names the one it fills in; the bytes give the union its size.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub union WHEA_ERROR_SOURCE_DESCRIPTOR_INFO {
    pub DeviceDriverDescriptor: WHEA_DEVICE_DRIVER_DESCRIPTOR,
    pub Bytes: [u8; 932],
}

/// [`WHEA_ERROR_SOURCE_DESCRIPTOR`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_error_source_descriptor):
/// one source of hardware errors.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct WHEA_ERROR_SOURCE_DESCRIPTOR {
    pub Length: u32,
    pub Version: u32,
    pub Type: u32,
    pub State: u32,
    pub MaxRawDataLength: u32,
    pub NumRecordsToPreallocate: u32,
    pub MaxSectionsPerRecord: u32,
    pub ErrorSourceId: u32,
    pub PlatformErrorSourceId: u32,
    pub Flags: u32,
    pub Info: WHEA_ERROR_SOURCE_DESCRIPTOR_INFO,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    type V1 = WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1;
    assert!(size_of::<V1>() == 0x2C);
    assert!(offset_of!(V1, SourceGuid) == 0x04);
    assert!(offset_of!(V1, LogTag) == 0x14);
    assert!(offset_of!(V1, Initialize) == 0x1C);
    assert!(offset_of!(V1, Uninitialize) == 0x24);
    type V2 = WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER;
    assert!(size_of::<V2>() == 0x54);
    assert!(offset_of!(V2, Initialize) == 0x1C);
    assert!(offset_of!(V2, MaxSectionDataLength) == 0x2C);
    assert!(offset_of!(V2, MaxSectionsPerReport) == 0x30);
    assert!(offset_of!(V2, CreatorId) == 0x34);
    assert!(offset_of!(V2, PartitionId) == 0x44);
    assert!(size_of::<WHEA_ERROR_SOURCE_CONFIGURATION_DD>() == 24);
    type DD = WHEA_DEVICE_DRIVER_DESCRIPTOR;
    assert!(size_of::<DD>() == 116);
    assert!(offset_of!(DD, SourceGuid) == 4);
    assert!(offset_of!(DD, LogTag) == 20);
    assert!(offset_of!(DD, PacketLength) == 24);
    assert!(offset_of!(DD, PacketCount) == 28);
    assert!(offset_of!(DD, PacketBuffer) == 32);
    assert!(offset_of!(DD, Config) == 40);
    assert!(offset_of!(DD, CreatorId) == 64);
    assert!(offset_of!(DD, PartitionId) == 80);
    assert!(offset_of!(DD, MaxSectionDataLength) == 96);
    assert!(offset_of!(DD, MaxSectionsPerRecord) == 100);
    assert!(offset_of!(DD, PacketStateBuffer) == 104);
    assert!(offset_of!(DD, OpenHandles) == 112);
    type D = WHEA_ERROR_SOURCE_DESCRIPTOR;
    assert!(size_of::<D>() == 972);
    assert!(offset_of!(D, Type) == 8);
    assert!(offset_of!(D, State) == 12);
    assert!(offset_of!(D, MaxRawDataLength) == 16);
    assert!(offset_of!(D, NumRecordsToPreallocate) == 20);
    assert!(offset_of!(D, MaxSectionsPerRecord) == 24);
    assert!(offset_of!(D, ErrorSourceId) == 28);
    assert!(offset_of!(D, PlatformErrorSourceId) == 32);
    assert!(offset_of!(D, Flags) == 36);
    assert!(offset_of!(D, Info) == 40);
};

/// `WHEA_ERROR_SOURCE_CONFIGURATION`: the routines of one kind of
/// source, which a driver hands
/// [`WheaConfigureErrorSource`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-wheaconfigureerrorsource).
/// `NTSTATUS Correct(PWHEA_ERROR_SOURCE_DESCRIPTOR, PULONG)`,
/// `NTSTATUS Initialize(ULONG Phase, PWHEA_ERROR_SOURCE_DESCRIPTOR, PVOID Context)`,
/// `VOID Uninitialize(PVOID Context)`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WHEA_ERROR_SOURCE_CONFIGURATION {
    pub Flags: u32,
    pub Correct: *mut c_void,
    pub Initialize: *mut c_void,
    pub CreateRecord: *mut c_void,
    pub Recover: *mut c_void,
    pub Uninitialize: *mut c_void,
    pub Reserved: *mut c_void,
}

/// `WHEA_ERROR_SEVERITY`.
pub const WHEA_ERR_SEV_RECOVERABLE: u32 = 0;
pub const WHEA_ERR_SEV_FATAL: u32 = 1;
pub const WHEA_ERR_SEV_CORRECTED: u32 = 2;
pub const WHEA_ERR_SEV_INFORMATIONAL: u32 = 3;

/// [`WHEA_ERROR_RECORD_HEADER`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_error_record_header):
/// the head of an error record, which is UEFI's common platform error
/// record.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct WHEA_ERROR_RECORD_HEADER {
    pub Signature: u32,
    pub Revision: u16,
    pub SignatureEnd: u32,
    pub SectionCount: u16,
    pub Severity: u32,
    pub ValidBits: u32,
    pub Length: u32,
    pub Timestamp: u64,
    pub PlatformId: GUID,
    pub PartitionId: GUID,
    pub CreatorId: GUID,
    pub NotifyType: GUID,
    pub RecordId: u64,
    pub Flags: u32,
    pub PersistenceInfo: u64,
    pub Reserved: [u8; 12],
}

/// `WHEA_ERROR_RECORD_SECTION_DESCRIPTOR`: one section of a record.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct WHEA_ERROR_RECORD_SECTION_DESCRIPTOR {
    pub SectionOffset: u32,
    pub SectionLength: u32,
    pub Revision: u16,
    pub ValidBits: u8,
    pub Reserved: u8,
    pub Flags: u32,
    pub SectionType: GUID,
    pub FRUId: GUID,
    pub SectionSeverity: u32,
    pub FRUText: [u8; 20],
}

/// [`WHEA_ERROR_PACKET_V2`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_whea_error_packet_v2):
/// what a source hands `WheaReportHwError`. The data follows.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct WHEA_ERROR_PACKET_V2 {
    pub Signature: u32,
    pub Version: u32,
    pub Length: u32,
    pub Flags: u32,
    pub ErrorType: u32,
    pub ErrorSeverity: u32,
    pub ErrorSourceId: u32,
    pub ErrorSourceType: u32,
    pub NotifyType: GUID,
    pub Context: u64,
    pub DataFormat: u32,
    pub Reserved1: u32,
    pub DataOffset: u32,
    pub DataLength: u32,
    pub PshedDataOffset: u32,
    pub PshedDataLength: u32,
}

/// `WHEA_EVENT_LOG_ENTRY_HEADER`: the head of what
/// `WheaLogInternalEvent` is handed. The payload follows.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct WHEA_EVENT_LOG_ENTRY_HEADER {
    pub Signature: u32,
    pub Version: u32,
    pub Length: u32,
    pub Type: u32,
    pub Owner: u32,
    pub Id: u32,
    pub Flags: u32,
    pub PayloadLength: u32,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    type C = WHEA_ERROR_SOURCE_CONFIGURATION;
    assert!(size_of::<C>() == 0x38);
    assert!(offset_of!(C, Correct) == 0x08);
    assert!(offset_of!(C, Initialize) == 0x10);
    assert!(offset_of!(C, CreateRecord) == 0x18);
    assert!(offset_of!(C, Recover) == 0x20);
    assert!(offset_of!(C, Uninitialize) == 0x28);
    type H = WHEA_ERROR_RECORD_HEADER;
    assert!(size_of::<H>() == 0x80);
    assert!(offset_of!(H, SignatureEnd) == 0x06);
    assert!(offset_of!(H, SectionCount) == 0x0A);
    assert!(offset_of!(H, Severity) == 0x0C);
    assert!(offset_of!(H, ValidBits) == 0x10);
    assert!(offset_of!(H, Length) == 0x14);
    assert!(offset_of!(H, Timestamp) == 0x18);
    assert!(offset_of!(H, PlatformId) == 0x20);
    assert!(offset_of!(H, PartitionId) == 0x30);
    assert!(offset_of!(H, CreatorId) == 0x40);
    assert!(offset_of!(H, NotifyType) == 0x50);
    assert!(offset_of!(H, RecordId) == 0x60);
    assert!(offset_of!(H, Flags) == 0x68);
    assert!(offset_of!(H, PersistenceInfo) == 0x6C);
    type S = WHEA_ERROR_RECORD_SECTION_DESCRIPTOR;
    assert!(size_of::<S>() == 0x48);
    assert!(offset_of!(S, Revision) == 0x08);
    assert!(offset_of!(S, Flags) == 0x0C);
    assert!(offset_of!(S, SectionType) == 0x10);
    assert!(offset_of!(S, FRUId) == 0x20);
    assert!(offset_of!(S, SectionSeverity) == 0x30);
    assert!(offset_of!(S, FRUText) == 0x34);
    type P = WHEA_ERROR_PACKET_V2;
    assert!(size_of::<P>() == 0x50);
    assert!(offset_of!(P, Flags) == 0x0C);
    assert!(offset_of!(P, ErrorSeverity) == 0x14);
    assert!(offset_of!(P, ErrorSourceId) == 0x18);
    assert!(offset_of!(P, ErrorSourceType) == 0x1C);
    assert!(offset_of!(P, NotifyType) == 0x20);
    assert!(offset_of!(P, DataFormat) == 0x38);
    assert!(offset_of!(P, DataOffset) == 0x40);
    assert!(size_of::<WHEA_EVENT_LOG_ENTRY_HEADER>() == 0x20);
};
