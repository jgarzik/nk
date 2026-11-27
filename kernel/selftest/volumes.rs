//! Microsoft's volume drivers on the disk Microsoft's storage stack
//! makes: `partmgr.sys`, the disk class's upper filter, reads the
//! partition table of the FAT disk (`tools/fatdisk.py`) and answers for
//! it; `volmgr.sys` makes a volume of the partition, which `volume.sys`
//! serves. The proof is what the drivers answer; the numbers are the FAT
//! disk's, which `doc/TESTING.md` states.

use crate::io::file::{self, OpenRequest};
use crate::ldr;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_ntabi::disk::*;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &["vol.partmgr", "vol.volume", "vol.mount"],
    run,
    manual: true,
};

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];

/// The disk, as `disk.sys` names it.
const DISK: &str = "\\Device\\Harddisk0\\DR0";
/// The volume of its partition, as `volmgr.sys` names it.
const VOLUME: &str = "\\Device\\HarddiskVolume1";

/// Every image the scenario needs: the storage stack's and the
/// partition manager.
const IMAGES: [&str; 8] = [
    "acpi.sys",
    "pci.sys",
    "pshed.dll",
    "storport.sys",
    "storahci.sys",
    "classpnp.sys",
    "disk.sys",
    "partmgr.sys",
];

/// The FAT disk's partition (`tools/fatdisk.py`): sector 2048, 126976
/// sectors, of 512 bytes; the MBR's signature, and the type FAT32 with
/// LBA addressing.
const START: i64 = 2048 * 512;
const LENGTH: i64 = 126976 * 512;
const SIGNATURE: u32 = 0x4E4B_0001;
const FAT32_LBA: u8 = 0x0C;

/// `FILE_SHARE_READ | FILE_SHARE_WRITE`.
const SHARE_READ_WRITE: u32 = 0x3;

/// Wait for the device `name` to exist: the drivers hand partitions and
/// volumes on in work items of their own, after the disk has started.
/// Ten seconds, a tenth at a time.
fn arrives(name: &str) -> Result<(), &'static str> {
    let wide: alloc::vec::Vec<u16> = name.encode_utf16().collect();
    for _ in 0..100 {
        if let Ok((body, rest)) = crate::ob::lookup(None, &wide) {
            // SAFETY: the reference the look-up took for its caller.
            unsafe { crate::ob::object::dereference(body) };
            if rest.is_empty() {
                return Ok(());
            }
        }
        // SAFETY: no object is waited on; a relative tenth of a second.
        unsafe { crate::ke::wait::wait(None, Some(-1_000_000)) };
    }
    kprintln!("vol: {name} did not appear");
    Err("the device did not appear")
}

/// Open `name` for reading and writing, shared.
fn open(name: &str) -> Result<u64, &'static str> {
    let request = OpenRequest {
        share_access: SHARE_READ_WRITE,
        ..OpenRequest::new(name)
    };
    file::open(&request)
        .map(|(handle, _)| handle)
        .map_err(|status| {
            kprintln!("vol: opening {name}: {status:#x}");
            "the device could not be opened"
        })
}

/// The disk's layout as the driver on top of its stack answers it.
fn layout(room: &mut [u8]) -> Result<DRIVE_LAYOUT_INFORMATION_EX, &'static str> {
    let handle = open(DISK)?;
    let answer = file::device_control(handle, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &[], room);
    file::close(handle);
    let result = answer.map_err(|_| "the layout could not be asked for")?;
    if result.status != STATUS_SUCCESS {
        kprintln!("vol: IOCTL_DISK_GET_DRIVE_LAYOUT_EX: {:#x}", result.status);
        return Err("the disk's layout was refused");
    }
    if result.information < core::mem::size_of::<DRIVE_LAYOUT_INFORMATION_EX>() {
        return Err("the layout is shorter than its header and one entry");
    }
    // SAFETY: at least that many bytes were written; read unaligned.
    Ok(unsafe {
        room.as_ptr()
            .cast::<DRIVE_LAYOUT_INFORMATION_EX>()
            .read_unaligned()
    })
}

/// `partmgr.sys`, above `disk.sys`, read the MBR and answers with its
/// one FAT32 partition; the other entries of the table are empty.
fn partmgr() -> Result<(), &'static str> {
    let mut room = [0u8; 4096];
    let layout = layout(&mut room)?;
    if layout.PartitionStyle != PARTITION_STYLE_MBR {
        return Err("the disk is not seen as an MBR disk");
    }
    // SAFETY: an MBR layout has the MBR view.
    if unsafe { layout.Info.Mbr[0] } != SIGNATURE {
        return Err("the disk's signature is not the MBR's");
    }
    let count = layout.PartitionCount as usize;
    let entry_size = core::mem::size_of::<PARTITION_INFORMATION_EX>();
    let first = core::mem::offset_of!(DRIVE_LAYOUT_INFORMATION_EX, PartitionEntry);
    if count == 0 || first + count * entry_size > room.len() {
        return Err("the layout has no entries, or more than were room for");
    }
    for i in 0..count {
        // SAFETY: inside `room`, checked above; read unaligned.
        let entry = unsafe {
            room.as_ptr()
                .add(first + i * entry_size)
                .cast::<PARTITION_INFORMATION_EX>()
                .read_unaligned()
        };
        // SAFETY: an MBR entry has the MBR view.
        let mbr = unsafe { entry.Info.Mbr };
        if i == 0 {
            if entry.StartingOffset != START
                || entry.PartitionLength != LENGTH
                || entry.PartitionNumber != 1
                || mbr.PartitionType != FAT32_LBA
                || mbr.RecognizedPartition == 0
            {
                kprintln!(
                    "vol: partition 1 at {:#x}, {:#x} bytes, number {}, type {:#x}",
                    entry.StartingOffset,
                    entry.PartitionLength,
                    entry.PartitionNumber,
                    mbr.PartitionType
                );
                return Err("the first partition is not the FAT disk's");
            }
        } else if entry.PartitionLength != 0 {
            return Err("an entry other than the first holds a partition");
        }
    }
    Ok(())
}

/// `SL_OVERRIDE_VERIFY_VOLUME`: the request is to go through although
/// the volume waits to be verified by a file system.
const SL_OVERRIDE_VERIFY_VOLUME: u8 = 0x02;

/// Send `request`, built for the top of `top`'s stack, with the verify
/// override, and wait for it: its status and count.
///
/// # Safety
/// `top` is a referenced device; `request` was built for it with
/// `done` as its event and `status` as its status block.
unsafe fn send(
    top: *mut nk_ntabi::io::DEVICE_OBJECT,
    request: *mut nk_ntabi::io::IRP,
    done: *mut nk_ntabi::io::KEVENT,
    status: &nk_ntabi::io::IO_STATUS_BLOCK,
) -> (NTSTATUS, usize) {
    // SAFETY: per the contract.
    unsafe {
        (*crate::io::irp::next_location(request)).Flags |= SL_OVERRIDE_VERIFY_VOLUME;
        if crate::io::irp::IofCallDriver(top, request) == STATUS_PENDING {
            crate::ke::wait::wait(Some(done.cast()), None);
        }
        (
            core::ptr::read_volatile(&raw const status.Status),
            status.Information,
        )
    }
}

/// Ask the volume whose stack `top` heads which partition it is.
///
/// # Safety
/// `top` is a referenced device.
unsafe fn partition_info(
    top: *mut nk_ntabi::io::DEVICE_OBJECT,
) -> Result<PARTITION_INFORMATION_EX, &'static str> {
    use nk_ntabi::io::{IO_STATUS_BLOCK, KEVENT};
    // SAFETY: as in `read_sector`.
    unsafe {
        let mut room = [0u8; core::mem::size_of::<PARTITION_INFORMATION_EX>()];
        let mut done: KEVENT = core::mem::zeroed();
        crate::ke::wait::KeInitializeEvent(&raw mut done, 0, 0);
        let mut status = IO_STATUS_BLOCK {
            Status: STATUS_PENDING,
            Information: 0,
        };
        let request = crate::io::build::IoBuildDeviceIoControlRequest(
            IOCTL_DISK_GET_PARTITION_INFO_EX,
            top,
            core::ptr::null_mut(),
            0,
            room.as_mut_ptr().cast(),
            room.len() as u32,
            0,
            &raw mut done,
            &raw mut status,
        );
        if request.is_null() {
            return Err("no memory for a request");
        }
        let (answer, count) = send(top, request, &raw mut done, &status);
        if answer != STATUS_SUCCESS || count != room.len() {
            kprintln!("vol: IOCTL_DISK_GET_PARTITION_INFO_EX: {answer:#x}, {count} bytes");
            return Err("the volume did not say which partition it is");
        }
        Ok(room
            .as_ptr()
            .cast::<PARTITION_INFORMATION_EX>()
            .read_unaligned())
    }
}

/// `volmgr.sys` made a volume of the partition and `volume.sys`
/// serves it: the volume says where on the disk it lies and how long it
/// is. It is offline until `mountmgr.sys` brings it online, so it is not
/// read here (`vol.mount` reads it). No file system has mounted it, so
/// the request carries the verify override, as `partmgr.sys`'s own
/// requests of the disk do.
fn volume() -> Result<(), &'static str> {
    with_volume(|top| {
        // SAFETY: the referenced top of the volume's stack.
        let info = unsafe { partition_info(top) }?;
        if info.StartingOffset != START || info.PartitionLength != LENGTH {
            kprintln!(
                "vol: partition at {:#x}, {:#x} bytes",
                info.StartingOffset,
                info.PartitionLength
            );
            return Err("the volume is not where the partition is");
        }
        Ok(())
    })
}

/// Run `f` on the referenced top of the volume's stack, once the volume
/// exists.
fn with_volume(
    f: impl FnOnce(*mut nk_ntabi::io::DEVICE_OBJECT) -> Result<(), &'static str>,
) -> Result<(), &'static str> {
    arrives(VOLUME)?;
    let wide: alloc::vec::Vec<u16> = VOLUME.encode_utf16().collect();
    let (body, _) = crate::ob::lookup(None, &wide).map_err(|_| "the volume is not there")?;
    // SAFETY: the look-up's reference keeps the device; the top of its
    // stack is referenced for the requests and given back after.
    unsafe {
        let top = crate::io::device::IoGetAttachedDeviceReference(body.cast());
        let result = f(top);
        crate::ob::object::dereference(top.cast());
        crate::ob::object::dereference(body);
        result
    }
}

/// The drive letter `mountmgr.sys` gives the volume.
const DRIVE: &str = "\\GLOBAL??\\C:";

/// The volume's name: `volmgr.sys` gives a basic MBR volume a stable
/// GUID made of the disk's signature and the partition's offset, and
/// `mountmgr.sys` names the volume by it.
const VOLUME_NAME: &str = "\\GLOBAL??\\Volume{4e4b0001-0000-0000-0000-100000000000}";

/// `mountmgr.sys` named the volume and, from its reinitialisation
/// routine, gave it `C:`: both names lead to the volume, and the
/// mounted-devices key holds the letter. Through the letter the volume,
/// brought online, reads as the partition (its first sector the FAT32
/// boot sector, a read past its end refused), by way of the RAW file
/// system mounted on it.
fn mount() -> Result<(), &'static str> {
    arrives(DRIVE)?;
    let found = |name: &str| {
        let wide: alloc::vec::Vec<u16> = name.encode_utf16().collect();
        crate::ob::lookup(None, &wide).ok().map(|(body, rest)| {
            // SAFETY: the look-up's reference, given back at once; only
            // the address is compared.
            unsafe { crate::ob::object::dereference(body) };
            (body, rest.is_empty())
        })
    };
    let volume = found(VOLUME);
    if volume.is_none() || found(DRIVE) != volume || found(VOLUME_NAME) != volume {
        return Err("C: or the volume's name does not lead to the volume");
    }
    let names: alloc::vec::Vec<alloc::string::String> =
        crate::cm::values("Machine\\System\\MountedDevices")
            .iter()
            .map(|value| value.0.clone())
            .collect();
    if !names.iter().any(|name| name == "\\DosDevices\\C:") {
        kprintln!("vol: MountedDevices holds {names:?}");
        return Err("the mounted-devices key does not hold C:");
    }
    let handle = open("\\??\\C:")?;
    let result = (|| {
        let mut sector = [0u8; 512];
        let read =
            file::read_at(handle, 0, &mut sector).map_err(|_| "the volume could not be read")?;
        if read.status != STATUS_SUCCESS || read.information != sector.len() {
            kprintln!(
                "vol: reading C: {:#x}, {} bytes",
                read.status,
                read.information
            );
            return Err("the volume's first sector could not be read through C:");
        }
        let hidden = u32::from_le_bytes([sector[28], sector[29], sector[30], sector[31]]);
        if sector[510..] != [0x55, 0xAA] || &sector[82..90] != b"FAT32   " || hidden != 2048 {
            return Err("the volume's first sector is not the FAT32 boot sector");
        }
        let past = file::read_at(handle, LENGTH, &mut sector)
            .map_err(|_| "a read past the end could not be made")?;
        if past.status == STATUS_SUCCESS {
            return Err("a read past the volume's end succeeded");
        }
        Ok(())
    })();
    file::close(handle);
    result
}

fn run(r: &mut Report, _: &BootInfo) {
    crate::test::keeps_what_it_started();
    if let Some(absent) = IMAGES.iter().find(|file| ldr::boot_file(file).is_none()) {
        r.skip_rest(format_args!("module {absent} not provided"));
        return;
    }
    r.check("vol.partmgr", partmgr);
    if !crate::io::service::running("volmgr") {
        r.skip_rest(format_args!("volmgr.sys was not started"));
        return;
    }
    r.check("vol.volume", volume);
    if !crate::io::service::running("mountmgr") {
        r.skip_rest(format_args!("mountmgr.sys was not started"));
        return;
    }
    r.check("vol.mount", mount);
}
