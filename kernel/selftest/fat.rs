//! Microsoft's FAT file system on the volume `mountmgr.sys` names `C:`:
//! `fastfat.sys` starts as a boot driver, and the first open of a file
//! on the volume mounts it there; files the host wrote
//! (`tools/fatdisk.py`) read back as written.

use crate::io::file::{self, OpenRequest};
use crate::test::{Group, Report};
use alloc::vec;
use nk_bootinfo::BootInfo;
use nk_disk::pattern::{self, ORIGINAL, SECTOR};
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &["fat.load", "fat.read"],
    run,
    manual: true,
};

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];

/// `GENERIC_READ | SYNCHRONIZE`.
const READ: u32 = 0x8010_0000;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE`.
const SHARE_READ_WRITE: u32 = 0x3;

/// `fastfat.sys` started and made its control devices.
fn load() -> Result<(), &'static str> {
    if !crate::io::service::running("fastfat") {
        return Err("fastfat.sys was not started");
    }
    for name in ["\\Fat", "\\FatCdrom"] {
        let wide: alloc::vec::Vec<u16> = name.encode_utf16().collect();
        if !crate::ob::lookup(None, &wide).is_ok_and(|(_, rest)| rest.is_empty()) {
            return Err("fastfat.sys's control devices are not there");
        }
    }
    Ok(())
}

/// The bytes of the file `name` on `C:`, at most `room` of them.
fn contents(name: &str, room: usize) -> Result<alloc::vec::Vec<u8>, &'static str> {
    let request = OpenRequest {
        desired_access: READ,
        share_access: SHARE_READ_WRITE,
        ..OpenRequest::new(name)
    };
    let (handle, _) = file::open(&request).map_err(|status| {
        kprintln!("fat: opening {name}: {status:#x}");
        "a file on C: could not be opened"
    })?;
    let mut buffer = vec![0u8; room];
    let read = file::read_at(handle, 0, &mut buffer);
    file::close(handle);
    let read = read.map_err(|_| "a file on C: could not be read")?;
    match read.status {
        STATUS_SUCCESS => buffer.truncate(read.information),
        STATUS_END_OF_FILE => buffer.clear(),
        status => {
            kprintln!("fat: reading {name}: {status:#x}");
            return Err("reading a file on C: failed");
        }
    }
    Ok(buffer)
}

/// The host's files, read through `C:`: the first open mounts
/// `fastfat.sys` on the volume.
fn read() -> Result<(), &'static str> {
    super::volumes::arrives("\\GLOBAL??\\C:")?;
    let length = 3 * SECTOR + 100;
    let mut expected = vec![0u8; length.next_multiple_of(SECTOR)];
    pattern::fill(&mut expected, 0, ORIGINAL);
    expected.truncate(length);
    let checks: [(&str, &[u8]); 4] = [
        ("\\??\\C:\\PATTERN.BIN", &expected),
        ("\\??\\C:\\DIR1\\NESTED.TXT", b"nested\r\n"),
        (
            "\\??\\C:\\Long File Name.txt",
            b"a name longer than 8.3\r\n",
        ),
        ("\\??\\C:\\EMPTY.TXT", b""),
    ];
    for (name, want) in checks {
        let got = contents(name, 4 * SECTOR)?;
        if got != want {
            kprintln!(
                "fat: {name}: {} bytes, not the {} written",
                got.len(),
                want.len()
            );
            return Err("a file on C: does not hold what the host wrote");
        }
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    crate::test::keeps_what_it_started();
    if crate::ldr::boot_file("fastfat.sys").is_none() {
        r.skip_rest(format_args!("module fastfat.sys not provided"));
        return;
    }
    r.check("fat.load", load);
    r.check("fat.read", read);
}
