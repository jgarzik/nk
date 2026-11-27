//! Mounting and RAW (`io::mount`, `io::raw`), on NK's test disk: the
//! disk's block is mounted by the first open that is not a direct
//! device open, RAW claims it, and RAW lets the disk itself be opened
//! and nothing in it. Deleting the disk dismounts it: the group's own
//! count of what it leaves behind holds that.

use super::testdisk::{self, TestDisk};
use crate::io::file::{self, OpenRequest};
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &["disk.raw.direct", "disk.raw.unrecognized", "disk.raw.mount"],
    run,
    manual: false,
};

pub static GROUPS: &[&Group] = &[&GROUP];

/// `FILE_READ_ATTRIBUTES`: access a direct device open may ask for.
const FILE_READ_ATTRIBUTES: u32 = 0x80;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE`.
const SHARE_READ_WRITE: u32 = 0x3;

/// Open `name` for `access`: the handle, or the status.
fn open(name: &str, access: u32) -> Result<u64, NTSTATUS> {
    let request = OpenRequest {
        desired_access: access,
        share_access: SHARE_READ_WRITE,
        ..OpenRequest::new(name)
    };
    file::open(&request).map(|(handle, _)| handle)
}

/// The test disk's device and its block's flags and mounted device.
fn block() -> Option<(*mut DEVICE_OBJECT, u16, *mut DEVICE_OBJECT)> {
    let wide: alloc::vec::Vec<u16> = testdisk::NAME.encode_utf16().collect();
    let (body, _) = crate::ob::lookup(None, &wide).ok()?;
    // SAFETY: the look-up's reference keeps the device while it is read.
    unsafe {
        let device = body.cast::<DEVICE_OBJECT>();
        let vpb = (*device).Vpb.cast::<VPB>();
        Some((device, (*vpb).Flags, (*vpb).DeviceObject))
    }
}

/// An open of the disk for its attributes alone mounts nothing.
fn direct() -> Result<(), &'static str> {
    let handle =
        open(testdisk::NAME, FILE_READ_ATTRIBUTES).map_err(|_| "the disk could not be opened")?;
    let flags = block().map(|(_, flags, _)| flags);
    file::close(handle);
    match flags {
        Some(flags) if flags & VPB_MOUNTED == 0 => Ok(()),
        _ => Err("a direct device open mounted the disk"),
    }
}

/// An open of a name on the disk, whose block does not allow a raw
/// mount, finds no file system that claims it.
fn unrecognized() -> Result<(), &'static str> {
    let name = alloc::format!("{}\\FILE.TXT", testdisk::NAME);
    match open(&name, 0xC010_0000) {
        Err(STATUS_UNRECOGNIZED_VOLUME) => Ok(()),
        Ok(handle) => {
            file::close(handle);
            Err("a name on an unmounted disk was opened")
        }
        Err(_) => Err("a name on an unmounted disk was not refused as unrecognized"),
    }
}

/// An open of the disk for data mounts RAW, whose volume device then
/// serves the disk's requests: the first sector reads as the disk's.
/// With RAW mounted, a name on the disk is refused as RAW refuses it.
fn mount() -> Result<(), &'static str> {
    let handle = open(testdisk::NAME, 0xC010_0000).map_err(|_| "the disk could not be opened")?;
    let result = (|| {
        let (device, flags, volume) = block().ok_or("the disk is gone")?;
        if flags & VPB_MOUNTED == 0 || volume.is_null() || volume == device {
            return Err("opening the disk for data did not mount it");
        }
        // SAFETY: the mounted volume device, held while the disk is open.
        let driver = unsafe {
            let name = &raw const (*(*volume).DriverObject).DriverName;
            alloc::string::String::from_utf16_lossy(&crate::rtl::copy_unicode(name))
        };
        if driver != "\\FileSystem\\RAW" {
            return Err("the disk's volume is not RAW's");
        }
        let mut sector = [0u8; 512];
        let read =
            file::read_at(handle, 0, &mut sector).map_err(|_| "the disk could not be read")?;
        if read.status != STATUS_SUCCESS || read.information != sector.len() {
            return Err("a read through RAW did not succeed in full");
        }
        if nk_disk::pattern::check(&sector, 0, nk_disk::pattern::ORIGINAL).is_err() {
            return Err("a read through RAW did not return the disk's sector");
        }
        let name = alloc::format!("{}\\FILE.TXT", testdisk::NAME);
        match open(&name, 0xC010_0000) {
            Err(STATUS_INVALID_PARAMETER) => Ok(()),
            Ok(other) => {
                file::close(other);
                Err("RAW opened a file")
            }
            Err(_) => Err("RAW did not refuse a name as invalid"),
        }
    })();
    file::close(handle);
    result
}

fn run(r: &mut Report, _: &BootInfo) {
    let disk = match TestDisk::new() {
        Ok(disk) => disk,
        Err(why) => {
            r.skip_rest(format_args!("{why}"));
            return;
        }
    };
    r.check("disk.raw.direct", direct);
    r.check("disk.raw.unrecognized", unrecognized);
    r.check("disk.raw.mount", mount);
    drop(disk);
}
