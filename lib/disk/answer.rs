//! What a disk answered a control code with, read out of the bytes in
//! the requestor's buffer. The layouts are `nk_ntabi::disk`'s, which
//! links Microsoft's documentation of each; a field is read at its
//! offset there, whatever the alignment of the buffer.
//!
//! An answer that is too short for what it claims, or claims what the
//! structure cannot hold, is refused with the reason.

use core::mem::offset_of;
use nk_ntabi::disk::*;

/// A little-endian 32-bit word at `at`, if the answer reaches that far.
fn u32_at(answer: &[u8], at: usize) -> Option<u32> {
    let bytes = answer.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// A little-endian 64-bit word at `at`, if the answer reaches that far.
fn i64_at(answer: &[u8], at: usize) -> Option<i64> {
    let bytes = answer.get(at..at.checked_add(8)?)?;
    Some(i64::from_le_bytes(bytes.try_into().ok()?))
}

/// What `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX` answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub cylinders: i64,
    pub media_type: u32,
    pub tracks_per_cylinder: u32,
    pub sectors_per_track: u32,
    pub bytes_per_sector: u32,
    /// The disk's size in bytes.
    pub disk_size: i64,
    /// `DISK_PARTITION_INFO.PartitionStyle`, if the answer has the
    /// partition information.
    pub partition_style: Option<u32>,
    /// `DISK_DETECTION_INFO.DetectionType`, if the answer has the
    /// detection information.
    pub detection_type: Option<u32>,
}

/// Where the partition information of a geometry answer starts, and
/// the detection information after it.
const PARTITION_INFO: usize = offset_of!(DISK_GEOMETRY_EX, Data);
const DETECTION_INFO: usize = PARTITION_INFO + size_of::<DISK_PARTITION_INFO>();
/// A geometry answer with everything in it.
pub const GEOMETRY_EX_FULL: usize = DETECTION_INFO + size_of::<DISK_DETECTION_INFO>();

/// Read an `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX` answer: the geometry and
/// the size, which every answer has, and what follows them of the
/// partition and detection information. Each of those says its own
/// size first, and is taken to be there only if it does: on Windows
/// the partition manager fills them in, and a disk answering alone
/// may leave them out or leave them zero.
pub fn geometry_ex(answer: &[u8]) -> Result<Geometry, &'static str> {
    let short = "the geometry answer is shorter than the geometry and the disk's size";
    let word = |at| u32_at(answer, at).ok_or(short);
    // The word at `field` of the part at `part`, if the part is all
    // there and says it is `size` bytes.
    let part = |part: usize, size: usize, field: usize| {
        (answer.len() >= part + size && u32_at(answer, part) == Some(size as u32))
            .then(|| u32_at(answer, part + field))
            .flatten()
    };
    Ok(Geometry {
        cylinders: i64_at(answer, offset_of!(DISK_GEOMETRY, Cylinders)).ok_or(short)?,
        media_type: word(offset_of!(DISK_GEOMETRY, MediaType))?,
        tracks_per_cylinder: word(offset_of!(DISK_GEOMETRY, TracksPerCylinder))?,
        sectors_per_track: word(offset_of!(DISK_GEOMETRY, SectorsPerTrack))?,
        bytes_per_sector: word(offset_of!(DISK_GEOMETRY, BytesPerSector))?,
        disk_size: i64_at(answer, offset_of!(DISK_GEOMETRY_EX, DiskSize)).ok_or(short)?,
        partition_style: part(
            PARTITION_INFO,
            size_of::<DISK_PARTITION_INFO>(),
            offset_of!(DISK_PARTITION_INFO, PartitionStyle),
        ),
        detection_type: part(
            DETECTION_INFO,
            size_of::<DISK_DETECTION_INFO>(),
            offset_of!(DISK_DETECTION_INFO, DetectionType),
        ),
    })
}

impl Geometry {
    /// Hold the geometry to itself and to the length the disk gave
    /// (`IOCTL_DISK_GET_LENGTH_INFO`): a fixed disk of 512-byte sectors
    /// whose size is whole sectors and is that length, and whose
    /// cylinders are the whole cylinders that fit in it. (The geometry
    /// is made up to describe the size; what does not fill a cylinder
    /// is left out of it.) Returns the disk's sectors.
    pub fn check(&self, length: i64) -> Result<u64, &'static str> {
        if self.media_type != FIXED_MEDIA {
            return Err("the disk's media type is not that of a fixed disk");
        }
        if self.bytes_per_sector as usize != crate::pattern::SECTOR {
            return Err("the disk's sectors are not 512 bytes");
        }
        let sector = i64::from(self.bytes_per_sector);
        if self.disk_size <= 0 || self.disk_size % sector != 0 {
            return Err("the disk's size is not a number of whole sectors");
        }
        if self.disk_size != length {
            return Err("the disk's length is not the size its geometry gives");
        }
        if self.cylinders < 0 || self.tracks_per_cylinder == 0 || self.sectors_per_track == 0 {
            return Err("the disk's geometry has no tracks or no sectors");
        }
        let cylinder =
            i64::from(self.tracks_per_cylinder) * i64::from(self.sectors_per_track) * sector;
        match self.cylinders.checked_mul(cylinder) {
            Some(described)
                if described <= self.disk_size && self.disk_size - described < cylinder => {}
            _ => return Err("the disk's cylinders are not the whole cylinders of its size"),
        }
        Ok((self.disk_size / sector) as u64)
    }
}

/// Read an `IOCTL_DISK_GET_LENGTH_INFO` answer: the length in bytes.
pub fn length_info(answer: &[u8]) -> Result<i64, &'static str> {
    i64_at(answer, offset_of!(GET_LENGTH_INFORMATION, Length))
        .ok_or("the length answer is shorter than a length")
}

/// What `IOCTL_STORAGE_GET_DEVICE_NUMBER` answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceNumber {
    pub device_type: u32,
    pub device_number: u32,
    /// Zero for a whole disk.
    pub partition_number: u32,
}

/// Read an `IOCTL_STORAGE_GET_DEVICE_NUMBER` answer.
pub fn device_number(answer: &[u8]) -> Result<DeviceNumber, &'static str> {
    let word = |at| u32_at(answer, at).ok_or("the device number answer is too short");
    Ok(DeviceNumber {
        device_type: word(offset_of!(STORAGE_DEVICE_NUMBER, DeviceType))?,
        device_number: word(offset_of!(STORAGE_DEVICE_NUMBER, DeviceNumber))?,
        partition_number: word(offset_of!(STORAGE_DEVICE_NUMBER, PartitionNumber))?,
    })
}

/// The input of `IOCTL_STORAGE_QUERY_PROPERTY` that asks for the
/// descriptor of `property` (`PropertyStandardQuery`).
pub fn property_query(property: u32) -> [u8; size_of::<STORAGE_PROPERTY_QUERY>()] {
    let mut query = [0; size_of::<STORAGE_PROPERTY_QUERY>()];
    query[..4].copy_from_slice(&property.to_le_bytes());
    query[4..8].copy_from_slice(&PROPERTY_STANDARD_QUERY.to_le_bytes());
    query
}

/// The header of a descriptor: checked to be of a version that has the
/// `fixed` bytes NK reads, to claim no less than them, and to be there
/// that far. Returns the descriptor's own size, which may be more than
/// the answer holds of it.
fn header(answer: &[u8], fixed: usize) -> Result<usize, &'static str> {
    let short = "a property answer is shorter than its descriptor";
    let version = u32_at(answer, offset_of!(STORAGE_DESCRIPTOR_HEADER, Version)).ok_or(short)?;
    let size = u32_at(answer, offset_of!(STORAGE_DESCRIPTOR_HEADER, Size)).ok_or(short)?;
    if (version as usize) < fixed || size < version {
        return Err("a property answer's version or size is less than its descriptor");
    }
    if answer.len() < fixed {
        return Err(short);
    }
    Ok(size as usize)
}

/// What `StorageDeviceProperty` answers. The strings are as the device
/// gave them, without the spaces around them; one the device has not
/// got is `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Device<'a> {
    pub removable_media: bool,
    pub command_queueing: bool,
    pub bus_type: u32,
    pub vendor: Option<&'a [u8]>,
    pub product: Option<&'a [u8]>,
    pub revision: Option<&'a [u8]>,
    pub serial: Option<&'a [u8]>,
}

/// Read a `STORAGE_DEVICE_DESCRIPTOR`. Its strings lie inside the
/// descriptor's size and inside the answer, each ended by a zero byte.
pub fn device_descriptor(answer: &[u8]) -> Result<Device<'_>, &'static str> {
    let size = header(answer, size_of::<STORAGE_DEVICE_DESCRIPTOR>())?;
    let within = &answer[..size.min(answer.len())];
    let string = |field: usize| -> Result<Option<&[u8]>, &'static str> {
        let outside = "a string of the device descriptor is outside the descriptor";
        let at = u32_at(answer, field).ok_or(outside)? as usize;
        if at == 0 {
            return Ok(None);
        }
        let from = within.get(at..).ok_or(outside)?;
        let end = from.iter().position(|&byte| byte == 0).ok_or(outside)?;
        Ok(Some(from[..end].trim_ascii()))
    };
    let flag = |field: usize| answer[field] != 0;
    Ok(Device {
        removable_media: flag(offset_of!(STORAGE_DEVICE_DESCRIPTOR, RemovableMedia)),
        command_queueing: flag(offset_of!(STORAGE_DEVICE_DESCRIPTOR, CommandQueueing)),
        bus_type: u32_at(answer, offset_of!(STORAGE_DEVICE_DESCRIPTOR, BusType)).unwrap_or(0),
        vendor: string(offset_of!(STORAGE_DEVICE_DESCRIPTOR, VendorIdOffset))?,
        product: string(offset_of!(STORAGE_DEVICE_DESCRIPTOR, ProductIdOffset))?,
        revision: string(offset_of!(STORAGE_DEVICE_DESCRIPTOR, ProductRevisionOffset))?,
        serial: string(offset_of!(STORAGE_DEVICE_DESCRIPTOR, SerialNumberOffset))?,
    })
}

/// What `StorageAdapterProperty` answers, as far as a requestor's
/// transfers go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Adapter {
    /// The most bytes of one transfer.
    pub maximum_transfer_length: u32,
    /// The most pages a transfer's buffer may span.
    pub maximum_physical_pages: u32,
    /// The bits of a buffer's address that must be zero.
    pub alignment_mask: u32,
    pub bus_type: u32,
}

/// Read a `STORAGE_ADAPTER_DESCRIPTOR`.
pub fn adapter_descriptor(answer: &[u8]) -> Result<Adapter, &'static str> {
    header(answer, size_of::<STORAGE_ADAPTER_DESCRIPTOR>())?;
    let word = |at| u32_at(answer, at).unwrap_or(0);
    Ok(Adapter {
        maximum_transfer_length: word(offset_of!(
            STORAGE_ADAPTER_DESCRIPTOR,
            MaximumTransferLength
        )),
        maximum_physical_pages: word(offset_of!(STORAGE_ADAPTER_DESCRIPTOR, MaximumPhysicalPages)),
        alignment_mask: word(offset_of!(STORAGE_ADAPTER_DESCRIPTOR, AlignmentMask)),
        bus_type: u32::from(answer[offset_of!(STORAGE_ADAPTER_DESCRIPTOR, BusType)]),
    })
}

impl Adapter {
    /// The most bytes one transfer may have from a buffer that starts
    /// `page_offset` bytes into a page of `page` bytes: the adapter's
    /// most, cut to the pages it takes and to whole sectors. `None` if
    /// the adapter's limits leave no room for a sector, or its
    /// alignment does not allow a buffer to start there.
    pub fn largest_transfer(&self, page_offset: usize, page: usize) -> Option<usize> {
        if page_offset >= page || page_offset & self.alignment_mask as usize != 0 {
            return None;
        }
        let pages = (self.maximum_physical_pages as usize).checked_mul(page)?;
        let bytes = (self.maximum_transfer_length as usize).min(pages.checked_sub(page_offset)?);
        let whole = bytes - bytes % crate::pattern::SECTOR;
        (whole != 0).then_some(whole)
    }
}

/// What `StorageAccessAlignmentProperty` answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alignment {
    pub bytes_per_logical_sector: u32,
    pub bytes_per_physical_sector: u32,
    pub bytes_offset_for_sector_alignment: u32,
}

/// Read a `STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR`.
pub fn access_alignment(answer: &[u8]) -> Result<Alignment, &'static str> {
    header(answer, size_of::<STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR>())?;
    let word = |at| u32_at(answer, at).unwrap_or(0);
    Ok(Alignment {
        bytes_per_logical_sector: word(offset_of!(
            STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR,
            BytesPerLogicalSector
        )),
        bytes_per_physical_sector: word(offset_of!(
            STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR,
            BytesPerPhysicalSector
        )),
        bytes_offset_for_sector_alignment: word(offset_of!(
            STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR,
            BytesOffsetForSectorAlignment
        )),
    })
}

impl Alignment {
    /// Hold the alignment to the sector size the geometry gave: logical
    /// sectors of that size, physical sectors of a whole number of
    /// them.
    pub fn check(&self, bytes_per_sector: u32) -> Result<(), &'static str> {
        if self.bytes_per_logical_sector != bytes_per_sector {
            return Err("the disk's logical sector is not the sector of its geometry");
        }
        if self.bytes_per_physical_sector == 0
            || self.bytes_per_physical_sector % self.bytes_per_logical_sector != 0
        {
            return Err("the disk's physical sector is not whole logical sectors");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bytes of a hex string.
    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
            .collect()
    }

    // What Windows 10 19045.2006 answered for the two disks of the
    // reference machine (QEMU q35, `ide-hd` on the ICH9 AHCI controller,
    // storahci/storport/disk/classpnp): the bytes `DeviceIoControl`
    // returned, with a 4096-byte output buffer.

    /// The system disk: 40 GiB, GPT.
    const GEOMETRY_40G: &str = "65140000000000000c000000ff0000003f00000000020000000000000a0000001800000001000000c7db868ac596b6419ffd6b9c59e8302a3800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    /// The second disk: 64 MiB, MBR.
    const GEOMETRY_64M: &str = "08000000000000000c000000ff0000003f000000000200000000000400000000180000000000000047cd6484b73237d300000000000000003800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
    const ADAPTER: &str = "2000000020000000000002002100000001000000020001010b00020000000000";
    const ALIGNMENT: &str = "1c0000001c0000000000000000000000000200000002000000000000";

    /// The device descriptor of the system disk: 396 bytes, the strings
    /// from offset 40 and nothing but zeroes after them.
    fn device_bytes() -> Vec<u8> {
        let mut bytes = hex(concat!(
            "280000008c010000000000010000000028000000510000005a0000000b00000000000000",
            "0000000051454d5520484152444449534b"
        ));
        bytes.resize(81, 0);
        bytes.extend_from_slice(b"2.5+");
        bytes.resize(90, 0);
        bytes.extend_from_slice(b"QM00001");
        bytes.resize(396, 0);
        bytes
    }

    #[test]
    fn windows_geometry_answers_decode() {
        let system = geometry_ex(&hex(GEOMETRY_40G)).unwrap();
        assert_eq!(
            system,
            Geometry {
                cylinders: 5221,
                media_type: FIXED_MEDIA,
                tracks_per_cylinder: 255,
                sectors_per_track: 63,
                bytes_per_sector: 512,
                disk_size: 40 << 30,
                partition_style: Some(PARTITION_STYLE_GPT),
                detection_type: Some(0),
            }
        );
        assert_eq!(system.check(40 << 30), Ok(83_886_080));
        let second = geometry_ex(&hex(GEOMETRY_64M)).unwrap();
        assert_eq!(second.cylinders, 8);
        assert_eq!(second.partition_style, Some(PARTITION_STYLE_MBR));
        assert_eq!(second.check(64 << 20), Ok(131_072));
    }

    #[test]
    fn a_geometry_answer_has_as_much_as_fits() {
        let full = hex(GEOMETRY_40G);
        assert_eq!(full.len(), GEOMETRY_EX_FULL);
        // The geometry and the size alone.
        let bare = geometry_ex(&full[..32]).unwrap();
        assert_eq!((bare.partition_style, bare.detection_type), (None, None));
        assert_eq!(bare.disk_size, 40 << 30);
        // With the partition information.
        let partition = geometry_ex(&full[..56]).unwrap();
        assert_eq!(partition.partition_style, Some(PARTITION_STYLE_GPT));
        assert_eq!(partition.detection_type, None);
        // Too short for the size.
        assert!(geometry_ex(&full[..31]).is_err());
        assert!(geometry_ex(&[]).is_err());
        // What follows says its own size, or is not there: a disk
        // answering without the partition manager leaves it zero.
        let mut blank = full.clone();
        blank[32..].fill(0);
        let read = geometry_ex(&blank).unwrap();
        assert_eq!((read.partition_style, read.detection_type), (None, None));
        assert_eq!(read.check(40 << 30), Ok(83_886_080));
        let mut wrong = full;
        wrong[56] = 55;
        let read = geometry_ex(&wrong).unwrap();
        assert_eq!(read.partition_style, Some(PARTITION_STYLE_GPT));
        assert_eq!(read.detection_type, None);
    }

    #[test]
    fn a_geometry_is_held_to_itself() {
        let good = geometry_ex(&hex(GEOMETRY_64M)).unwrap();
        let fails = |change: fn(&mut Geometry), length: i64, why: &str| {
            let mut geometry = good;
            change(&mut geometry);
            let said = geometry.check(length).unwrap_err();
            assert!(said.contains(why), "{said}");
        };
        fails(|g| g.media_type = 11, 64 << 20, "media type");
        fails(|g| g.bytes_per_sector = 4096, 64 << 20, "512");
        fails(|g| g.disk_size = 0, 0, "whole sectors");
        fails(|g| g.disk_size += 1, (64 << 20) + 1, "whole sectors");
        fails(|_| (), 32 << 20, "length");
        fails(|g| g.tracks_per_cylinder = 0, 64 << 20, "no tracks");
        fails(|g| g.sectors_per_track = 0, 64 << 20, "no tracks");
        fails(|g| g.cylinders = -1, 64 << 20, "no tracks");
        // One cylinder too many, one too few, and too many to count.
        fails(|g| g.cylinders = 9, 64 << 20, "whole cylinders");
        fails(|g| g.cylinders = 7, 64 << 20, "whole cylinders");
        fails(|g| g.cylinders = i64::MAX, 64 << 20, "whole cylinders");
    }

    #[test]
    fn windows_length_and_number_answers_decode() {
        assert_eq!(length_info(&hex("000000000a000000")), Ok(40 << 30));
        assert_eq!(length_info(&hex("0000000400000000")), Ok(64 << 20));
        assert!(length_info(&[0; 7]).is_err());
        assert_eq!(
            device_number(&hex("070000000100000000000000")),
            Ok(DeviceNumber {
                device_type: FILE_DEVICE_DISK,
                device_number: 1,
                partition_number: 0,
            })
        );
        assert!(device_number(&[0; 11]).is_err());
    }

    #[test]
    fn the_windows_device_descriptor_decodes() {
        let bytes = device_bytes();
        assert_eq!(
            device_descriptor(&bytes),
            Ok(Device {
                removable_media: false,
                command_queueing: true,
                bus_type: BUS_TYPE_SATA,
                vendor: None,
                product: Some(b"QEMU HARDDISK"),
                revision: Some(b"2.5+"),
                serial: Some(b"QM00001"),
            })
        );
        // Only as much of it as the strings need.
        assert!(device_descriptor(&bytes[..98]).is_ok());
        // Cut inside the serial number, which is then not ended.
        assert!(device_descriptor(&bytes[..97]).is_err());
        // Cut before a string starts.
        assert!(device_descriptor(&bytes[..81]).is_err());
        // Cut inside the fixed part, or to nothing.
        assert!(device_descriptor(&bytes[..39]).is_err());
        assert!(device_descriptor(&bytes[..4]).is_err());
    }

    #[test]
    fn a_device_descriptor_is_held_to_its_own_size() {
        // A string past the size the descriptor claims, though the
        // answer has bytes there.
        let mut bytes = device_bytes();
        bytes[4..8].copy_from_slice(&80u32.to_le_bytes());
        assert!(device_descriptor(&bytes).is_err());
        // A version without the fields read.
        let mut bytes = device_bytes();
        bytes[0] = 36;
        assert!(device_descriptor(&bytes).is_err());
        // A size less than the version.
        let mut bytes = device_bytes();
        bytes[4..8].copy_from_slice(&39u32.to_le_bytes());
        assert!(device_descriptor(&bytes).is_err());
        // Strings padded with spaces, as ATA's are, come back bare.
        let mut bytes = device_bytes();
        bytes[81..85].copy_from_slice(b" 2. ");
        assert_eq!(
            device_descriptor(&bytes).unwrap().revision,
            Some(&b"2."[..])
        );
    }

    #[test]
    fn the_windows_adapter_descriptor_decodes() {
        let adapter = adapter_descriptor(&hex(ADAPTER)).unwrap();
        assert_eq!(
            adapter,
            Adapter {
                maximum_transfer_length: 128 << 10,
                maximum_physical_pages: 33,
                alignment_mask: 1,
                bus_type: BUS_TYPE_SATA,
            }
        );
        assert!(adapter_descriptor(&hex(ADAPTER)[..31]).is_err());
        // 128 KiB from a buffer that starts inside a page spans 33.
        assert_eq!(adapter.largest_transfer(0xA58, 4096), Some(128 << 10));
        assert_eq!(adapter.largest_transfer(0, 4096), Some(128 << 10));
        // An odd address is not the adapter's to take.
        assert_eq!(adapter.largest_transfer(0xA59, 4096), None);
        assert_eq!(adapter.largest_transfer(4096, 4096), None);
        // Fewer pages than the length would need: whole sectors of them.
        let few = Adapter {
            maximum_physical_pages: 2,
            ..adapter
        };
        assert_eq!(few.largest_transfer(0x100, 4096), Some(0x1E00));
        let none = Adapter {
            maximum_physical_pages: 0,
            ..adapter
        };
        assert_eq!(none.largest_transfer(0, 4096), None);
        let tiny = Adapter {
            maximum_transfer_length: 511,
            ..adapter
        };
        assert_eq!(tiny.largest_transfer(0, 4096), None);
    }

    #[test]
    fn the_windows_alignment_descriptor_decodes() {
        let alignment = access_alignment(&hex(ALIGNMENT)).unwrap();
        assert_eq!(
            alignment,
            Alignment {
                bytes_per_logical_sector: 512,
                bytes_per_physical_sector: 512,
                bytes_offset_for_sector_alignment: 0,
            }
        );
        assert_eq!(alignment.check(512), Ok(()));
        assert!(alignment.check(4096).is_err());
        let advanced = Alignment {
            bytes_per_physical_sector: 4096,
            ..alignment
        };
        assert_eq!(advanced.check(512), Ok(()));
        for physical in [0, 768] {
            let odd = Alignment {
                bytes_per_physical_sector: physical,
                ..alignment
            };
            assert!(odd.check(512).is_err());
        }
        assert!(access_alignment(&hex(ALIGNMENT)[..27]).is_err());
    }

    #[test]
    fn a_query_names_its_property() {
        assert_eq!(
            property_query(STORAGE_ACCESS_ALIGNMENT_PROPERTY),
            [6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
    }
}
