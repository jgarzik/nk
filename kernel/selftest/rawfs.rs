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
    names: &["disk.raw.direct", "disk.raw.named", "disk.raw.mount"],
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
/// mount, is offered to RAW all the same when RAW is the only file
/// system on the disk queue, as Windows' `IopMountVolume` offers it:
/// RAW mounts the disk and refuses the name, as Windows' RAW does.
fn named() -> Result<(), &'static str> {
    let name = alloc::format!("{}\\FILE.TXT", testdisk::NAME);
    match open(&name, 0xC010_0000) {
        Err(STATUS_INVALID_PARAMETER) => {}
        Ok(handle) => {
            file::close(handle);
            return Err("a name on a raw disk was opened");
        }
        Err(_) => {
            return Err(
                "a name on a disk with RAW alone registered was not refused as RAW refuses it",
            );
        }
    }
    match block() {
        Some((_, flags, _)) if flags & VPB_MOUNTED != 0 => Ok(()),
        _ => Err("RAW, the only file system, was not mounted for a name on the disk"),
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
            Err(STATUS_INVALID_PARAMETER) => {}
            Ok(other) => {
                file::close(other);
                return Err("RAW opened a file");
            }
            Err(_) => return Err("RAW did not refuse a name as invalid"),
        }
        // F6: RAW QueryVolumeInformation (`FileFsAttributeInformation` -> "RAW",
        // `FileFsDeviceInformation`, `FileFsVolumeInformation`).
        let mut attr = [0u8; 32];
        let qv = file::query_volume_information(handle, FILE_FS_ATTRIBUTE_INFORMATION, &mut attr)
            .map_err(|_| "RAW FileFsAttributeInformation failed")?;
        if qv.status != STATUS_SUCCESS || qv.information != 18 || &attr[12..18] != b"R\0A\0W\0" {
            return Err("RAW FileFsAttributeInformation did not return RAW");
        }
        let mut dev_info = [0u8; 8];
        let qd = file::query_volume_information(handle, FILE_FS_DEVICE_INFORMATION, &mut dev_info)
            .map_err(|_| "RAW FileFsDeviceInformation failed")?;
        if qd.status != STATUS_SUCCESS || qd.information != 8 {
            return Err("RAW FileFsDeviceInformation failed");
        }
        // F6: RAW share-access conflict (exclusive open while shared open is held).
        let excl = OpenRequest {
            desired_access: 0xC010_0000,
            share_access: 0,
            ..OpenRequest::new(testdisk::NAME)
        };
        match file::open(&excl) {
            Err(STATUS_SHARING_VIOLATION) => {}
            Ok((other, _)) => {
                file::close(other);
                return Err("RAW allowed a conflicting exclusive open");
            }
            Err(_) => return Err("RAW did not return STATUS_SHARING_VIOLATION on conflict"),
        }
        // F6: RAW volume FSCTLs (`IS_VOLUME_MOUNTED`, `LOCK_VOLUME`, `UNLOCK_VOLUME`).
        let mounted = file::fs_control(handle, FSCTL_IS_VOLUME_MOUNTED, &[], &mut [])
            .map_err(|_| "RAW FSCTL_IS_VOLUME_MOUNTED failed")?;
        if mounted.status != STATUS_SUCCESS {
            return Err("RAW FSCTL_IS_VOLUME_MOUNTED did not succeed");
        }
        let locked = file::fs_control(handle, FSCTL_LOCK_VOLUME, &[], &mut [])
            .map_err(|_| "RAW FSCTL_LOCK_VOLUME failed")?;
        if locked.status != STATUS_SUCCESS {
            return Err("RAW FSCTL_LOCK_VOLUME did not succeed on sole open");
        }
        let unlocked = file::fs_control(handle, FSCTL_UNLOCK_VOLUME, &[], &mut [])
            .map_err(|_| "RAW FSCTL_UNLOCK_VOLUME failed")?;
        if unlocked.status != STATUS_SUCCESS {
            return Err("RAW FSCTL_UNLOCK_VOLUME did not succeed");
        }
        // F6: exercise `FO_SYNCHRONOUS_IO` per-file serialization lock.
        let fo =
            crate::ob::handle::reference(handle, Some(&raw const crate::ob::object::FILE_TYPE))
                .map_err(|_| "could not reference file object for lock test")?;
        // SAFETY: `fo` holds a live `FILE_OBJECT`.
        unsafe {
            if file::acquire_file_lock(fo.cast(), KERNEL_MODE) != STATUS_SUCCESS {
                return Err("acquire_file_lock failed on uncontended file");
            }
            file::release_file_lock(fo.cast());
        }
        Ok(())
    })();
    file::close(handle);
    result?;
    // F6: async non-`FO_SYNCHRONOUS_IO` read completing through `IopCompleteRequest` APC.
    let async_req = OpenRequest {
        desired_access: 0x8010_0000, // GENERIC_READ | SYNCHRONIZE
        share_access: SHARE_READ_WRITE,
        create_options: FILE_NON_DIRECTORY_FILE,
        ..OpenRequest::new(testdisk::NAME)
    };
    let (ah, _) = file::open(&async_req).map_err(|_| "async open on RAW disk failed")?;
    let mut ev: *mut core::ffi::c_void = core::ptr::null_mut();
    // SAFETY: local handle pointer.
    let ev_st = unsafe {
        crate::ob::event::ZwCreateEvent(&raw mut ev, 0x001F_0003, core::ptr::null(), 0, 0)
    };
    if ev_st != STATUS_SUCCESS {
        file::close(ah);
        return Err("could not create event for async read test");
    }
    let mut async_buf = [0u8; 512];
    let mut async_iosb = IO_STATUS_BLOCK {
        Status: STATUS_PENDING,
        Information: 0,
    };
    let buf = file::Buffer {
        address: async_buf.as_mut_ptr().addr(),
        len: async_buf.len(),
    };
    // SAFETY: `async_buf` and `async_iosb` stay alive until the event signals below.
    let st = unsafe {
        file::read_async(
            ah,
            Some(ev as u64),
            &raw mut async_iosb,
            buf,
            Some(0),
            KERNEL_MODE,
        )
    };
    let waited = if st == Ok(STATUS_PENDING) {
        // SAFETY: `ev` is a valid event handle.
        unsafe { crate::ob::event::ZwWaitForSingleObject(ev, 0, core::ptr::null()) }
    } else {
        STATUS_SUCCESS
    };
    crate::ob::handle::close(ev as u64);
    file::close(ah);
    if !matches!(st, Ok(STATUS_SUCCESS | STATUS_PENDING))
        || waited != STATUS_SUCCESS
        || async_iosb.Status != STATUS_SUCCESS
        || async_iosb.Information != 512
        || nk_disk::pattern::check(&async_buf, 0, nk_disk::pattern::ORIGINAL).is_err()
    {
        return Err("async read via IopCompleteRequest APC did not complete with disk data");
    }
    Ok(())
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
    r.check("disk.raw.named", named);
    r.check("disk.raw.mount", mount);
    drop(disk);
}
