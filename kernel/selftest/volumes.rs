//! Microsoft's volume drivers on the disk Microsoft's storage stack
//! makes: `partmgr.sys`, the disk class's upper filter, reads the
//! partition table of the FAT disk (`tools/fatdisk.py`) and answers for
//! it. The proof is what the drivers answer; the numbers are the FAT
//! disk's, which `doc/TESTING.md` states.

use crate::io::file::{self, OpenRequest};
use crate::ldr;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_ntabi::disk::*;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &["vol.partmgr"],
    run,
    manual: true,
};

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];

/// The disk, as `disk.sys` names it.
const DISK: &str = "\\Device\\Harddisk0\\DR0";

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

/// The disk's layout as the driver on top of its stack answers it.
fn layout(room: &mut [u8]) -> Result<DRIVE_LAYOUT_INFORMATION_EX, &'static str> {
    let request = OpenRequest {
        share_access: SHARE_READ_WRITE,
        ..OpenRequest::new(DISK)
    };
    let (handle, _) = file::open(&request).map_err(|status| {
        kprintln!("vol: opening {DISK}: {status:#x}");
        "the disk could not be opened"
    })?;
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

fn run(r: &mut Report, _: &BootInfo) {
    crate::test::keeps_what_it_started();
    if let Some(absent) = IMAGES.iter().find(|file| ldr::boot_file(file).is_none()) {
        r.skip_rest(format_args!("module {absent} not provided"));
        return;
    }
    r.check("vol.partmgr", partmgr);
}
