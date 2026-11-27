//! What a disk answers its control codes with: the codes and structures
//! of `ntdddisk.h` and `ntddstor.h` that NK's own requestor reads. No
//! export of the kernel takes or returns them; they are what
//! Microsoft's `disk.sys` and `classpnp.sys` write into a requestor's
//! buffer, and what NK's test disk writes into it the same way.

use crate::ex::GUID;
use crate::io::{METHOD_BUFFERED, ctl_code};

/// `FILE_DEVICE_DISK` and `FILE_DEVICE_MASS_STORAGE` (`IOCTL_DISK_BASE`,
/// `IOCTL_STORAGE_BASE`): the device types of the two families of
/// codes. A disk's device object has the first.
pub const FILE_DEVICE_DISK: u32 = 0x07;
pub const FILE_DEVICE_MASS_STORAGE: u32 = 0x2D;

/// `FILE_READ_ACCESS` in a control code: the handle must have been
/// opened for reading.
const FILE_READ_ACCESS: u32 = 1;

/// [`IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ni-ntdddisk-ioctl_disk_get_drive_geometry_ex):
/// answers a [`DISK_GEOMETRY_EX`].
pub const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 =
    ctl_code(FILE_DEVICE_DISK, 0x28, METHOD_BUFFERED, 0);
/// [`IOCTL_DISK_GET_LENGTH_INFO`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ni-ntdddisk-ioctl_disk_get_length_info):
/// answers a [`GET_LENGTH_INFORMATION`].
pub const IOCTL_DISK_GET_LENGTH_INFO: u32 =
    ctl_code(FILE_DEVICE_DISK, 0x17, METHOD_BUFFERED, FILE_READ_ACCESS);
/// [`IOCTL_DISK_GET_DRIVE_LAYOUT_EX`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ni-ntdddisk-ioctl_disk_get_drive_layout_ex):
/// answers a [`DRIVE_LAYOUT_INFORMATION_EX`] and its entries.
pub const IOCTL_DISK_GET_DRIVE_LAYOUT_EX: u32 =
    ctl_code(FILE_DEVICE_DISK, 0x14, METHOD_BUFFERED, 0);
/// [`IOCTL_STORAGE_GET_DEVICE_NUMBER`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ni-ntddstor-ioctl_storage_get_device_number):
/// answers a [`STORAGE_DEVICE_NUMBER`].
pub const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 =
    ctl_code(FILE_DEVICE_MASS_STORAGE, 0x420, METHOD_BUFFERED, 0);
/// [`IOCTL_STORAGE_QUERY_PROPERTY`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ni-ntddstor-ioctl_storage_query_property):
/// takes a [`STORAGE_PROPERTY_QUERY`] and answers the descriptor of the
/// property it names.
pub const IOCTL_STORAGE_QUERY_PROPERTY: u32 =
    ctl_code(FILE_DEVICE_MASS_STORAGE, 0x500, METHOD_BUFFERED, 0);

/// `MEDIA_TYPE`: a hard disk.
pub const FIXED_MEDIA: u32 = 12;

/// [`DISK_GEOMETRY`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_disk_geometry).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DISK_GEOMETRY {
    pub Cylinders: i64,
    pub MediaType: u32,
    pub TracksPerCylinder: u32,
    pub SectorsPerTrack: u32,
    pub BytesPerSector: u32,
}

/// [`DISK_GEOMETRY_EX`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_disk_geometry_ex).
/// `Data` is where a [`DISK_PARTITION_INFO`] and then a
/// [`DISK_DETECTION_INFO`] follow, if the requestor's buffer has room.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DISK_GEOMETRY_EX {
    pub Geometry: DISK_GEOMETRY,
    pub DiskSize: i64,
    pub Data: [u8; 1],
}

/// `PARTITION_STYLE`.
pub const PARTITION_STYLE_MBR: u32 = 0;
pub const PARTITION_STYLE_GPT: u32 = 1;
pub const PARTITION_STYLE_RAW: u32 = 2;

/// [`DISK_PARTITION_INFO`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_disk_partition_info).
/// `Id` is a union: an MBR disk's signature and checksum (two 32-bit
/// words), or a GPT disk's identifier.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DISK_PARTITION_INFO {
    pub SizeOfPartitionInfo: u32,
    pub PartitionStyle: u32,
    pub Id: GUID,
}

/// [`PARTITION_INFORMATION_MBR`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_partition_information_mbr).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PARTITION_INFORMATION_MBR {
    pub PartitionType: u8,
    pub BootIndicator: u8,
    pub RecognizedPartition: u8,
    pub HiddenSectors: u32,
    pub PartitionId: GUID,
}

/// [`PARTITION_INFORMATION_GPT`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_partition_information_gpt).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PARTITION_INFORMATION_GPT {
    pub PartitionType: GUID,
    pub PartitionId: GUID,
    pub Attributes: u64,
    pub Name: [u16; 36],
}

/// The style-dependent part of a [`PARTITION_INFORMATION_EX`].
#[repr(C)]
#[derive(Clone, Copy)]
pub union PARTITION_INFORMATION_STYLE {
    pub Mbr: PARTITION_INFORMATION_MBR,
    pub Gpt: PARTITION_INFORMATION_GPT,
}

/// [`PARTITION_INFORMATION_EX`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_partition_information_ex).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PARTITION_INFORMATION_EX {
    pub PartitionStyle: u32,
    pub StartingOffset: i64,
    pub PartitionLength: i64,
    pub PartitionNumber: u32,
    pub RewritePartition: u8,
    pub IsServicePartition: u8,
    pub Info: PARTITION_INFORMATION_STYLE,
}

/// [`DRIVE_LAYOUT_INFORMATION_GPT`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_drive_layout_information_gpt).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DRIVE_LAYOUT_INFORMATION_GPT {
    pub DiskId: GUID,
    pub StartingUsableOffset: i64,
    pub UsableLength: i64,
    pub MaxPartitionCount: u32,
}

/// The style-dependent part of a [`DRIVE_LAYOUT_INFORMATION_EX`]: an
/// MBR disk's signature and checksum, or the GPT header's facts.
#[repr(C)]
#[derive(Clone, Copy)]
pub union DRIVE_LAYOUT_STYLE {
    pub Mbr: [u32; 2],
    pub Gpt: DRIVE_LAYOUT_INFORMATION_GPT,
}

/// [`DRIVE_LAYOUT_INFORMATION_EX`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_drive_layout_information_ex):
/// `PartitionCount` entries follow from `PartitionEntry`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DRIVE_LAYOUT_INFORMATION_EX {
    pub PartitionStyle: u32,
    pub PartitionCount: u32,
    pub Info: DRIVE_LAYOUT_STYLE,
    pub PartitionEntry: [PARTITION_INFORMATION_EX; 1],
}

/// [`DISK_INT13_INFO`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_disk_int13_info).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DISK_INT13_INFO {
    pub DriveSelect: u16,
    pub MaxCylinders: u32,
    pub SectorsPerTrack: u16,
    pub MaxHeads: u16,
    pub NumberDrives: u16,
}

/// [`DISK_EX_INT13_INFO`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_disk_ex_int13_info).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DISK_EX_INT13_INFO {
    pub ExBufferSize: u16,
    pub ExFlags: u16,
    pub ExCylinders: u32,
    pub ExHeads: u32,
    pub ExSectorsPerTrack: u32,
    pub ExSectorsPerDrive: u64,
    pub ExSectorSize: u16,
    pub ExReserved: u16,
}

/// [`DISK_DETECTION_INFO`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_disk_detection_info):
/// what the firmware said of the disk, if anything (`DetectionType`
/// zero: nothing).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DISK_DETECTION_INFO {
    pub SizeOfDetectInfo: u32,
    pub DetectionType: u32,
    pub Int13: DISK_INT13_INFO,
    pub ExInt13: DISK_EX_INT13_INFO,
}

/// [`GET_LENGTH_INFORMATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntdddisk/ns-ntdddisk-_get_length_information).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GET_LENGTH_INFORMATION {
    pub Length: i64,
}

/// [`STORAGE_DEVICE_NUMBER`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_device_number).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct STORAGE_DEVICE_NUMBER {
    pub DeviceType: u32,
    pub DeviceNumber: u32,
    pub PartitionNumber: u32,
}

/// `STORAGE_PROPERTY_ID`: the properties NK's requestor asks for.
pub const STORAGE_DEVICE_PROPERTY: u32 = 0;
pub const STORAGE_ADAPTER_PROPERTY: u32 = 1;
pub const STORAGE_ACCESS_ALIGNMENT_PROPERTY: u32 = 6;

/// `STORAGE_QUERY_TYPE`: answer the descriptor, or only say whether the
/// property is supported.
pub const PROPERTY_STANDARD_QUERY: u32 = 0;
pub const PROPERTY_EXISTS_QUERY: u32 = 1;

/// [`STORAGE_PROPERTY_QUERY`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_property_query).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct STORAGE_PROPERTY_QUERY {
    pub PropertyId: u32,
    pub QueryType: u32,
    pub AdditionalParameters: [u8; 1],
}

/// [`STORAGE_DESCRIPTOR_HEADER`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_descriptor_header):
/// how every descriptor starts. `Size` is that of the whole answer,
/// whatever part of it the requestor's buffer had room for.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct STORAGE_DESCRIPTOR_HEADER {
    pub Version: u32,
    pub Size: u32,
}

/// [`STORAGE_BUS_TYPE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ne-ntddstor-storage_bus_type):
/// the ones NK meets, and the first value that is none.
pub const BUS_TYPE_RAM: u32 = 0x08;
pub const BUS_TYPE_SATA: u32 = 0x0B;
pub const BUS_TYPE_MAX: u32 = 0x14;

/// [`STORAGE_DEVICE_DESCRIPTOR`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_device_descriptor).
/// The offsets are from the start of the descriptor to strings ended by
/// a zero byte; zero means there is no such string.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct STORAGE_DEVICE_DESCRIPTOR {
    pub Version: u32,
    pub Size: u32,
    pub DeviceType: u8,
    pub DeviceTypeModifier: u8,
    pub RemovableMedia: u8,
    pub CommandQueueing: u8,
    pub VendorIdOffset: u32,
    pub ProductIdOffset: u32,
    pub ProductRevisionOffset: u32,
    pub SerialNumberOffset: u32,
    pub BusType: u32,
    pub RawPropertiesLength: u32,
    pub RawDeviceProperties: [u8; 1],
}

/// [`STORAGE_ADAPTER_DESCRIPTOR`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_adapter_descriptor).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct STORAGE_ADAPTER_DESCRIPTOR {
    pub Version: u32,
    pub Size: u32,
    pub MaximumTransferLength: u32,
    pub MaximumPhysicalPages: u32,
    pub AlignmentMask: u32,
    pub AdapterUsesPio: u8,
    pub AdapterScansDown: u8,
    pub CommandQueueing: u8,
    pub AcceleratedTransfer: u8,
    pub BusType: u8,
    pub BusMajorVersion: u16,
    pub BusMinorVersion: u16,
    pub SrbType: u8,
    pub AddressType: u8,
}

/// [`STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddstor/ns-ntddstor-_storage_access_alignment_descriptor).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR {
    pub Version: u32,
    pub Size: u32,
    pub BytesPerCacheLine: u32,
    pub BytesOffsetForCacheAlignment: u32,
    pub BytesPerLogicalSector: u32,
    pub BytesPerPhysicalSector: u32,
    pub BytesOffsetForSectorAlignment: u32,
}

const _: () = {
    use core::mem::offset_of;

    assert!(IOCTL_DISK_GET_DRIVE_GEOMETRY_EX == 0x0007_00A0);
    assert!(IOCTL_DISK_GET_LENGTH_INFO == 0x0007_405C);
    assert!(IOCTL_STORAGE_GET_DEVICE_NUMBER == 0x002D_1080);
    assert!(IOCTL_STORAGE_QUERY_PROPERTY == 0x002D_1400);
    assert!(IOCTL_DISK_GET_DRIVE_LAYOUT_EX == 0x0007_0050);

    assert!(size_of::<PARTITION_INFORMATION_MBR>() == 24);
    assert!(offset_of!(PARTITION_INFORMATION_MBR, HiddenSectors) == 4);
    assert!(offset_of!(PARTITION_INFORMATION_MBR, PartitionId) == 8);
    assert!(size_of::<PARTITION_INFORMATION_GPT>() == 112);
    assert!(offset_of!(PARTITION_INFORMATION_GPT, Attributes) == 32);
    assert!(offset_of!(PARTITION_INFORMATION_GPT, Name) == 40);
    assert!(size_of::<PARTITION_INFORMATION_EX>() == 144);
    assert!(offset_of!(PARTITION_INFORMATION_EX, StartingOffset) == 8);
    assert!(offset_of!(PARTITION_INFORMATION_EX, PartitionLength) == 16);
    assert!(offset_of!(PARTITION_INFORMATION_EX, PartitionNumber) == 24);
    assert!(offset_of!(PARTITION_INFORMATION_EX, IsServicePartition) == 29);
    assert!(offset_of!(PARTITION_INFORMATION_EX, Info) == 32);
    assert!(size_of::<DRIVE_LAYOUT_INFORMATION_GPT>() == 40);
    assert!(offset_of!(DRIVE_LAYOUT_INFORMATION_EX, Info) == 8);
    assert!(offset_of!(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry) == 48);

    assert!(size_of::<DISK_GEOMETRY>() == 24);
    assert!(offset_of!(DISK_GEOMETRY, MediaType) == 8);
    assert!(offset_of!(DISK_GEOMETRY, TracksPerCylinder) == 12);
    assert!(offset_of!(DISK_GEOMETRY, SectorsPerTrack) == 16);
    assert!(offset_of!(DISK_GEOMETRY, BytesPerSector) == 20);

    assert!(size_of::<DISK_GEOMETRY_EX>() == 40);
    assert!(offset_of!(DISK_GEOMETRY_EX, DiskSize) == 24);
    assert!(offset_of!(DISK_GEOMETRY_EX, Data) == 32);

    assert!(size_of::<DISK_PARTITION_INFO>() == 24);
    assert!(offset_of!(DISK_PARTITION_INFO, PartitionStyle) == 4);
    assert!(offset_of!(DISK_PARTITION_INFO, Id) == 8);

    assert!(size_of::<DISK_INT13_INFO>() == 16);
    assert!(offset_of!(DISK_INT13_INFO, MaxCylinders) == 4);
    assert!(offset_of!(DISK_INT13_INFO, NumberDrives) == 12);
    assert!(size_of::<DISK_EX_INT13_INFO>() == 32);
    assert!(offset_of!(DISK_EX_INT13_INFO, ExSectorsPerDrive) == 16);
    assert!(offset_of!(DISK_EX_INT13_INFO, ExSectorSize) == 24);
    assert!(size_of::<DISK_DETECTION_INFO>() == 56);
    assert!(offset_of!(DISK_DETECTION_INFO, DetectionType) == 4);
    assert!(offset_of!(DISK_DETECTION_INFO, Int13) == 8);
    assert!(offset_of!(DISK_DETECTION_INFO, ExInt13) == 24);

    assert!(size_of::<GET_LENGTH_INFORMATION>() == 8);

    assert!(size_of::<STORAGE_DEVICE_NUMBER>() == 12);
    assert!(offset_of!(STORAGE_DEVICE_NUMBER, DeviceNumber) == 4);
    assert!(offset_of!(STORAGE_DEVICE_NUMBER, PartitionNumber) == 8);

    assert!(size_of::<STORAGE_PROPERTY_QUERY>() == 12);
    assert!(offset_of!(STORAGE_PROPERTY_QUERY, QueryType) == 4);
    assert!(offset_of!(STORAGE_PROPERTY_QUERY, AdditionalParameters) == 8);

    assert!(size_of::<STORAGE_DESCRIPTOR_HEADER>() == 8);
    assert!(offset_of!(STORAGE_DESCRIPTOR_HEADER, Size) == 4);

    assert!(size_of::<STORAGE_DEVICE_DESCRIPTOR>() == 40);
    assert!(offset_of!(STORAGE_DEVICE_DESCRIPTOR, DeviceType) == 8);
    assert!(offset_of!(STORAGE_DEVICE_DESCRIPTOR, RemovableMedia) == 10);
    assert!(offset_of!(STORAGE_DEVICE_DESCRIPTOR, CommandQueueing) == 11);
    assert!(offset_of!(STORAGE_DEVICE_DESCRIPTOR, VendorIdOffset) == 12);
    assert!(offset_of!(STORAGE_DEVICE_DESCRIPTOR, ProductIdOffset) == 16);
    assert!(offset_of!(STORAGE_DEVICE_DESCRIPTOR, ProductRevisionOffset) == 20);
    assert!(offset_of!(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset) == 24);
    assert!(offset_of!(STORAGE_DEVICE_DESCRIPTOR, BusType) == 28);
    assert!(offset_of!(STORAGE_DEVICE_DESCRIPTOR, RawPropertiesLength) == 32);
    assert!(offset_of!(STORAGE_DEVICE_DESCRIPTOR, RawDeviceProperties) == 36);

    assert!(size_of::<STORAGE_ADAPTER_DESCRIPTOR>() == 32);
    assert!(offset_of!(STORAGE_ADAPTER_DESCRIPTOR, MaximumTransferLength) == 8);
    assert!(offset_of!(STORAGE_ADAPTER_DESCRIPTOR, MaximumPhysicalPages) == 12);
    assert!(offset_of!(STORAGE_ADAPTER_DESCRIPTOR, AlignmentMask) == 16);
    assert!(offset_of!(STORAGE_ADAPTER_DESCRIPTOR, AdapterUsesPio) == 20);
    assert!(offset_of!(STORAGE_ADAPTER_DESCRIPTOR, AcceleratedTransfer) == 23);
    assert!(offset_of!(STORAGE_ADAPTER_DESCRIPTOR, BusType) == 24);
    assert!(offset_of!(STORAGE_ADAPTER_DESCRIPTOR, BusMajorVersion) == 26);
    assert!(offset_of!(STORAGE_ADAPTER_DESCRIPTOR, BusMinorVersion) == 28);
    assert!(offset_of!(STORAGE_ADAPTER_DESCRIPTOR, SrbType) == 30);
    assert!(offset_of!(STORAGE_ADAPTER_DESCRIPTOR, AddressType) == 31);

    assert!(size_of::<STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR>() == 28);
    assert!(offset_of!(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR, BytesPerLogicalSector) == 16);
    assert!(offset_of!(STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR, BytesPerPhysicalSector) == 20);
    assert!(
        offset_of!(
            STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR,
            BytesOffsetForSectorAlignment
        ) == 24
    );
};
