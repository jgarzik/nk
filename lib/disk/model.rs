//! A disk's side of the bargain, for NK's own test disk: which
//! transfers it takes, and the bytes it answers its control codes
//! with. The rules are those of Microsoft's class driver and disk
//! driver, as Microsoft publishes their source
//! ([classpnp](https://github.com/microsoft/Windows-driver-samples/tree/main/storage/class/classpnp),
//! [disk](https://github.com/microsoft/Windows-driver-samples/tree/main/storage/class/disk))
//! and documents the control codes (`nk_ntabi::disk` links each).

use alloc::vec::Vec;
use core::mem::offset_of;
use core::ops::Range;
use nk_ntabi::disk::*;
use nk_ntabi::status::*;

use crate::answer::GEOMETRY_EX_FULL;
use crate::pattern::SECTOR;

/// What a read or a write of `length` bytes at byte `offset` of a disk
/// of `size` bytes comes to: the bytes of the disk it transfers, none
/// for a transfer of no bytes, or the status it fails with.
///
/// As `DiskReadWriteVerification` and `ClassReadWrite` have it: a
/// length or an offset that is not whole sectors is the requestor's
/// mistake, `STATUS_INVALID_PARAMETER`. A transfer of whole sectors is
/// the drive's to judge: nothing, if it has no bytes, wherever it is;
/// and if it reaches past the end the drive says it has no such
/// sector, which the class driver reports as
/// `STATUS_NONEXISTENT_SECTOR`.
pub fn transfer(offset: i64, length: u32, size: u64) -> Result<Option<Range<usize>>, NTSTATUS> {
    let sector = SECTOR as u64;
    if u64::from(length) % sector != 0 || offset as u64 % sector != 0 {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if length == 0 {
        return Ok(None);
    }
    let end = u64::try_from(offset)
        .ok()
        .and_then(|start| start.checked_add(u64::from(length)))
        .filter(|&end| end <= size)
        .ok_or(STATUS_NONEXISTENT_SECTOR)?;
    Ok(Some(offset as usize..end as usize))
}

/// The geometry the class driver makes up for a disk of `size` bytes:
/// 255 tracks of 63 sectors to a cylinder, and as many whole cylinders
/// as the disk has.
pub fn geometry_of(size: u64) -> DISK_GEOMETRY {
    const TRACKS: u32 = 255;
    const SECTORS: u32 = 63;
    let cylinder = u64::from(TRACKS) * u64::from(SECTORS) * SECTOR as u64;
    DISK_GEOMETRY {
        Cylinders: (size / cylinder) as i64,
        MediaType: FIXED_MEDIA,
        TracksPerCylinder: TRACKS,
        SectorsPerTrack: SECTORS,
        BytesPerSector: SECTOR as u32,
    }
}

/// What a disk says of itself and of the adapter it is on.
#[derive(Debug, Clone, Copy)]
pub struct Identity<'a> {
    /// A disk with no vendor, as an ATA disk is, has an empty one.
    pub vendor: &'a str,
    pub product: &'a str,
    pub revision: &'a str,
    pub serial: &'a str,
    /// `STORAGE_BUS_TYPE`.
    pub bus_type: u32,
    /// The number of the disk among the system's disks.
    pub device_number: u32,
    pub maximum_transfer_length: u32,
    pub maximum_physical_pages: u32,
    pub alignment_mask: u32,
}

/// Bytes being put together, little-endian.
struct Bytes(Vec<u8>);

impl Bytes {
    fn u8(mut self, value: u8) -> Self {
        self.0.push(value);
        self
    }
    fn u16(mut self, value: u16) -> Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }
    fn u32(mut self, value: u32) -> Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }
    fn i64(mut self, value: i64) -> Self {
        self.0.extend_from_slice(&value.to_le_bytes());
        self
    }
    /// Zeroes up to `len` bytes in all.
    fn zeroes_to(mut self, len: usize) -> Self {
        self.0.resize(len, 0);
        self
    }
}

/// The whole `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX` answer of a disk with
/// no partition table: the geometry, the size, partition information
/// of the raw style and detection information that detected nothing.
fn geometry_ex(size: u64) -> Vec<u8> {
    let geometry = geometry_of(size);
    Bytes(Vec::new())
        .i64(geometry.Cylinders)
        .u32(geometry.MediaType)
        .u32(geometry.TracksPerCylinder)
        .u32(geometry.SectorsPerTrack)
        .u32(geometry.BytesPerSector)
        .i64(size as i64)
        .u32(size_of::<DISK_PARTITION_INFO>() as u32)
        .u32(PARTITION_STYLE_RAW)
        .zeroes_to(offset_of!(DISK_GEOMETRY_EX, Data) + size_of::<DISK_PARTITION_INFO>())
        .u32(size_of::<DISK_DETECTION_INFO>() as u32)
        .zeroes_to(GEOMETRY_EX_FULL)
        .0
}

/// The `STORAGE_DEVICE_DESCRIPTOR` of `identity`: the fixed part, then
/// the strings it has, each ended by a zero byte.
fn device_descriptor(identity: &Identity<'_>) -> Vec<u8> {
    let fixed = size_of::<STORAGE_DEVICE_DESCRIPTOR>();
    let strings = [
        identity.vendor,
        identity.product,
        identity.revision,
        identity.serial,
    ];
    let mut offsets = [0u32; 4];
    let mut at = fixed;
    for (offset, string) in offsets.iter_mut().zip(strings) {
        if !string.is_empty() {
            *offset = at as u32;
            at += string.len() + 1;
        }
    }
    let mut bytes = Bytes(Vec::new())
        .u32(fixed as u32)
        .u32(at as u32)
        // A direct-access device, of no modifier, not removable, that
        // queues commands.
        .u8(0)
        .u8(0)
        .u8(0)
        .u8(1);
    for offset in offsets {
        bytes = bytes.u32(offset);
    }
    let mut bytes = bytes.u32(identity.bus_type).u32(0).zeroes_to(fixed).0;
    for string in strings.iter().filter(|string| !string.is_empty()) {
        bytes.extend_from_slice(string.as_bytes());
        bytes.push(0);
    }
    bytes
}

/// The `STORAGE_ADAPTER_DESCRIPTOR` of `identity`'s adapter: one that
/// does no programmed I/O, queues commands, and takes requests in SCSI
/// request blocks addressed by bus, target and unit.
fn adapter_descriptor(identity: &Identity<'_>) -> Vec<u8> {
    let size = size_of::<STORAGE_ADAPTER_DESCRIPTOR>() as u32;
    Bytes(Vec::new())
        .u32(size)
        .u32(size)
        .u32(identity.maximum_transfer_length)
        .u32(identity.maximum_physical_pages)
        .u32(identity.alignment_mask)
        // AdapterUsesPio, AdapterScansDown, CommandQueueing,
        // AcceleratedTransfer.
        .u8(0)
        .u8(0)
        .u8(1)
        .u8(1)
        .u8(identity.bus_type as u8)
        .u8(0)
        // The bus's version: 1.0.
        .u16(1)
        .u16(0)
        // SrbType, AddressType.
        .u8(0)
        .u8(0)
        .0
}

/// The `STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR` of a disk whose physical
/// sectors are its logical ones.
fn access_alignment() -> Vec<u8> {
    let size = size_of::<STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR>() as u32;
    Bytes(Vec::new())
        .u32(size)
        .u32(size)
        .u32(0)
        .u32(0)
        .u32(SECTOR as u32)
        .u32(SECTOR as u32)
        .u32(0)
        .0
}

/// An answer of fixed size: all of it, or `STATUS_BUFFER_TOO_SMALL` if
/// the requestor has not `room` for it.
fn whole(answer: Vec<u8>, room: usize) -> Result<Vec<u8>, NTSTATUS> {
    if room < answer.len() {
        Err(STATUS_BUFFER_TOO_SMALL)
    } else {
        Ok(answer)
    }
}

/// What a disk of `size` bytes that is `identity` answers the control
/// code `code` with, given `input` and `room` bytes for the answer: the
/// bytes of the answer, no more than there is room for (their count is
/// the request's `Information`), or the status the request fails with.
///
/// - `IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`: the geometry and the size, and
///   after them the partition and the detection information, each only
///   if all of it fits; `STATUS_BUFFER_TOO_SMALL` without room for the
///   first two.
/// - `IOCTL_DISK_GET_LENGTH_INFO`, `IOCTL_STORAGE_GET_DEVICE_NUMBER`:
///   the structure, or `STATUS_BUFFER_TOO_SMALL`.
/// - `IOCTL_STORAGE_QUERY_PROPERTY`: an input shorter than a query is
///   `STATUS_INFO_LENGTH_MISMATCH`. The device, adapter and access
///   alignment properties are answered: nothing to a query whether the
///   property exists; to a standard query the descriptor, cut to the
///   room there is (its header says how long it is whole), or
///   `STATUS_BUFFER_TOO_SMALL` without room for a header. Any other
///   property or kind of query is `STATUS_NOT_SUPPORTED`.
/// - any other code: `STATUS_INVALID_DEVICE_REQUEST`.
pub fn control(
    code: u32,
    input: &[u8],
    room: usize,
    size: u64,
    identity: &Identity<'_>,
) -> Result<Vec<u8>, NTSTATUS> {
    match code {
        IOCTL_DISK_GET_DRIVE_GEOMETRY_EX => {
            let mut answer = geometry_ex(size);
            let bare = offset_of!(DISK_GEOMETRY_EX, Data);
            let partition = bare + size_of::<DISK_PARTITION_INFO>();
            let fits = [answer.len(), partition, bare]
                .into_iter()
                .find(|&len| len <= room)
                .ok_or(STATUS_BUFFER_TOO_SMALL)?;
            answer.truncate(fits);
            Ok(answer)
        }
        IOCTL_DISK_GET_LENGTH_INFO => whole((size as i64).to_le_bytes().to_vec(), room),
        IOCTL_STORAGE_GET_DEVICE_NUMBER => whole(
            Bytes(Vec::new())
                .u32(FILE_DEVICE_DISK)
                .u32(identity.device_number)
                .u32(0)
                .0,
            room,
        ),
        IOCTL_STORAGE_QUERY_PROPERTY => {
            let word = |at: usize| {
                input
                    .get(at..at + 4)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u32::from_le_bytes)
            };
            let (Some(property), Some(kind), true) = (
                word(offset_of!(STORAGE_PROPERTY_QUERY, PropertyId)),
                word(offset_of!(STORAGE_PROPERTY_QUERY, QueryType)),
                input.len() >= size_of::<STORAGE_PROPERTY_QUERY>(),
            ) else {
                return Err(STATUS_INFO_LENGTH_MISMATCH);
            };
            let mut answer = match property {
                STORAGE_DEVICE_PROPERTY => device_descriptor(identity),
                STORAGE_ADAPTER_PROPERTY => adapter_descriptor(identity),
                STORAGE_ACCESS_ALIGNMENT_PROPERTY => access_alignment(),
                _ => return Err(STATUS_NOT_SUPPORTED),
            };
            match kind {
                PROPERTY_EXISTS_QUERY => Ok(Vec::new()),
                PROPERTY_STANDARD_QUERY if room < size_of::<STORAGE_DESCRIPTOR_HEADER>() => {
                    Err(STATUS_BUFFER_TOO_SMALL)
                }
                PROPERTY_STANDARD_QUERY => {
                    answer.truncate(room);
                    Ok(answer)
                }
                _ => Err(STATUS_NOT_SUPPORTED),
            }
        }
        _ => Err(STATUS_INVALID_DEVICE_REQUEST),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::answer;

    const SIZE: u64 = 8 << 20;
    const DISK: Identity<'static> = Identity {
        vendor: "NK",
        product: "TEST DISK",
        revision: "1",
        serial: "NK0001",
        bus_type: BUS_TYPE_RAM,
        device_number: 7,
        maximum_transfer_length: 1 << 20,
        maximum_physical_pages: 257,
        alignment_mask: 3,
    };

    fn ask(code: u32, input: &[u8], room: usize) -> Result<Vec<u8>, NTSTATUS> {
        control(code, input, room, SIZE, &DISK)
    }

    #[test]
    fn whole_sectors_inside_the_disk_transfer() {
        assert_eq!(transfer(0, 512, SIZE), Ok(Some(0..512)));
        assert_eq!(transfer(1024, 4096, SIZE), Ok(Some(1024..5120)));
        // The last sector, and the whole disk.
        let last = SIZE as i64 - 512;
        assert_eq!(
            transfer(last, 512, SIZE),
            Ok(Some(last as usize..SIZE as usize))
        );
        assert_eq!(transfer(0, SIZE as u32, SIZE), Ok(Some(0..SIZE as usize)));
    }

    #[test]
    fn what_is_not_whole_sectors_is_the_requestor_s_mistake() {
        for (offset, length) in [(0, 1), (0, 511), (0, 513), (1, 512), (511, 512), (-1, 512)] {
            assert_eq!(
                transfer(offset, length, SIZE),
                Err(STATUS_INVALID_PARAMETER),
                "{offset} {length}"
            );
        }
        // Also beyond the end, and with no bytes.
        assert_eq!(
            transfer(SIZE as i64 + 1, 512, SIZE),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(transfer(3, 0, SIZE), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn no_bytes_is_no_transfer_anywhere() {
        assert_eq!(transfer(0, 0, SIZE), Ok(None));
        assert_eq!(transfer(SIZE as i64, 0, SIZE), Ok(None));
        assert_eq!(transfer(SIZE as i64 * 2, 0, SIZE), Ok(None));
        assert_eq!(transfer(-512, 0, SIZE), Ok(None));
    }

    #[test]
    fn past_the_end_there_is_no_such_sector() {
        let size = SIZE as i64;
        for (offset, length) in [
            (size, 512),
            (size - 512, 1024),
            (size * 4, 512),
            (-512, 512),
            (i64::MAX - 511, 1024),
            (0, SIZE as u32 + 512),
        ] {
            assert_eq!(
                transfer(offset, length, SIZE),
                Err(STATUS_NONEXISTENT_SECTOR),
                "{offset} {length}"
            );
        }
    }

    /// The geometries Windows gave the reference machine's disks.
    #[test]
    fn the_geometry_is_the_class_driver_s() {
        assert_eq!(geometry_of(40 << 30).Cylinders, 5221);
        let small = geometry_of(64 << 20);
        assert_eq!(
            (
                small.Cylinders,
                small.MediaType,
                small.TracksPerCylinder,
                small.SectorsPerTrack,
                small.BytesPerSector
            ),
            (8, FIXED_MEDIA, 255, 63, 512)
        );
    }

    #[test]
    fn the_geometry_answer_reads_back_and_holds() {
        let full = ask(IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[], 4096).unwrap();
        assert_eq!(full.len(), GEOMETRY_EX_FULL);
        let geometry = answer::geometry_ex(&full).unwrap();
        assert_eq!(geometry.disk_size, SIZE as i64);
        assert_eq!(geometry.cylinders, 1);
        assert_eq!(geometry.partition_style, Some(PARTITION_STYLE_RAW));
        assert_eq!(geometry.detection_type, Some(0));
        let length = ask(IOCTL_DISK_GET_LENGTH_INFO, &[], 8).unwrap();
        let length = answer::length_info(&length).unwrap();
        assert_eq!(geometry.check(length), Ok(SIZE / 512));
    }

    #[test]
    fn the_geometry_answer_has_the_parts_that_fit() {
        let lens = |room| ask(IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[], room).map(|a| a.len());
        assert_eq!(lens(112), Ok(112));
        assert_eq!(lens(111), Ok(56));
        assert_eq!(lens(56), Ok(56));
        assert_eq!(lens(55), Ok(32));
        assert_eq!(lens(32), Ok(32));
        assert_eq!(lens(31), Err(STATUS_BUFFER_TOO_SMALL));
        assert_eq!(lens(0), Err(STATUS_BUFFER_TOO_SMALL));
    }

    #[test]
    fn fixed_answers_need_their_room() {
        assert_eq!(
            ask(IOCTL_DISK_GET_LENGTH_INFO, &[], 7),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
        assert_eq!(
            ask(IOCTL_STORAGE_GET_DEVICE_NUMBER, &[], 11),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
        let number = ask(IOCTL_STORAGE_GET_DEVICE_NUMBER, &[], 64).unwrap();
        assert_eq!(number.len(), 12);
        assert_eq!(
            answer::device_number(&number),
            Ok(answer::DeviceNumber {
                device_type: FILE_DEVICE_DISK,
                device_number: 7,
                partition_number: 0,
            })
        );
    }

    fn property(id: u32, room: usize) -> Result<Vec<u8>, NTSTATUS> {
        ask(
            IOCTL_STORAGE_QUERY_PROPERTY,
            &answer::property_query(id),
            room,
        )
    }

    #[test]
    fn the_descriptors_read_back() {
        let device = property(STORAGE_DEVICE_PROPERTY, 4096).unwrap();
        assert_eq!(
            answer::device_descriptor(&device),
            Ok(answer::Device {
                removable_media: false,
                command_queueing: true,
                bus_type: BUS_TYPE_RAM,
                vendor: Some(b"NK"),
                product: Some(b"TEST DISK"),
                revision: Some(b"1"),
                serial: Some(b"NK0001"),
            })
        );
        // A disk with no vendor has no vendor string, as ATA's do not.
        let bare = Identity { vendor: "", ..DISK };
        let query = answer::property_query(STORAGE_DEVICE_PROPERTY);
        let device = control(IOCTL_STORAGE_QUERY_PROPERTY, &query, 4096, SIZE, &bare).unwrap();
        let read = answer::device_descriptor(&device).unwrap();
        assert_eq!((read.vendor, read.product), (None, Some(&b"TEST DISK"[..])));

        let adapter = property(STORAGE_ADAPTER_PROPERTY, 4096).unwrap();
        assert_eq!(adapter.len(), 32);
        assert_eq!(
            answer::adapter_descriptor(&adapter),
            Ok(answer::Adapter {
                maximum_transfer_length: 1 << 20,
                maximum_physical_pages: 257,
                alignment_mask: 3,
                bus_type: BUS_TYPE_RAM,
            })
        );
        let alignment = property(STORAGE_ACCESS_ALIGNMENT_PROPERTY, 4096).unwrap();
        assert_eq!(alignment.len(), 28);
        assert_eq!(
            answer::access_alignment(&alignment).unwrap().check(512),
            Ok(())
        );
    }

    #[test]
    fn a_descriptor_is_cut_to_the_room_and_says_its_size() {
        let whole = property(STORAGE_DEVICE_PROPERTY, 4096).unwrap();
        let header = property(STORAGE_DEVICE_PROPERTY, 8).unwrap();
        assert_eq!(header, whole[..8]);
        assert_eq!(
            u32::from_le_bytes(header[4..8].try_into().unwrap()) as usize,
            whole.len()
        );
        assert_eq!(property(STORAGE_DEVICE_PROPERTY, 50).unwrap(), whole[..50]);
        assert_eq!(
            property(STORAGE_DEVICE_PROPERTY, 7),
            Err(STATUS_BUFFER_TOO_SMALL)
        );
    }

    #[test]
    fn queries_the_disk_does_not_take() {
        // Shorter than a query.
        assert_eq!(
            ask(IOCTL_STORAGE_QUERY_PROPERTY, &[0; 11], 4096),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
        assert_eq!(
            ask(IOCTL_STORAGE_QUERY_PROPERTY, &[], 4096),
            Err(STATUS_INFO_LENGTH_MISMATCH)
        );
        // A property it has not got.
        assert_eq!(property(7, 4096), Err(STATUS_NOT_SUPPORTED));
        // Whether a property exists: yes, and no bytes.
        let mut exists = answer::property_query(STORAGE_ADAPTER_PROPERTY);
        exists[4] = PROPERTY_EXISTS_QUERY as u8;
        assert_eq!(
            ask(IOCTL_STORAGE_QUERY_PROPERTY, &exists, 0),
            Ok(Vec::new())
        );
        // A kind of query it does not know.
        exists[4] = 2;
        assert_eq!(
            ask(IOCTL_STORAGE_QUERY_PROPERTY, &exists, 4096),
            Err(STATUS_NOT_SUPPORTED)
        );
        // A code it does not know.
        assert_eq!(
            ask(0x0007_0000, &[], 4096),
            Err(STATUS_INVALID_DEVICE_REQUEST)
        );
    }
}
