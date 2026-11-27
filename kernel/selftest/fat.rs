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

/// Writing, a scenario of its own: the read-only one proves a mount
/// changes nothing.
pub static WRITE: Group = Group {
    names: &["fat.write"],
    run: run_write,
    manual: true,
};

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP, &WRITE];

/// `GENERIC_READ | SYNCHRONIZE`.
const READ: u32 = 0x8010_0000;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE`.
const SHARE_READ_WRITE: u32 = 0x3;

/// What `fat.write` leaves on the volume, which `tools/fatdisk.py`
/// checks after the boot (`fat-written`): `NKWRITE.BIN` written from
/// `WRITE_FROM` to `WRITE_TO` with [`written`]'s bytes over a hole of
/// zeros, `OVERWRITE` bytes of 0xEE at `OVERWRITE_AT`, cut to `CUT_TO`;
/// `EMPTY.TXT` renamed `RENAMED.TXT`; `HELLO.TXT` deleted.
const WRITE_FROM: usize = 192 * 1024;
const WRITE_TO: usize = 392 * 1024;
const OVERWRITE_AT: usize = 300 * 1024;
const OVERWRITE: usize = 1024;
const CUT_TO: usize = 350 * 1024;

/// The byte `fat.write` writes at offset `at` of `NKWRITE.BIN`.
fn written(at: usize) -> u8 {
    ((at * 7 + 3) % 251) as u8
}

/// `NKWRITE.BIN` as `fat.write` leaves it.
fn expected_written() -> alloc::vec::Vec<u8> {
    (0..CUT_TO)
        .map(|at| match at {
            _ if at < WRITE_FROM => 0,
            _ if (OVERWRITE_AT..OVERWRITE_AT + OVERWRITE).contains(&at) => 0xEE,
            _ => written(at),
        })
        .collect()
}

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

fn run_write(r: &mut Report, _: &BootInfo) {
    crate::test::keeps_what_it_started();
    if crate::ldr::boot_file("fastfat.sys").is_none() {
        r.skip_rest(format_args!("module fastfat.sys not provided"));
        return;
    }
    if let Err(why) = super::volumes::arrives("\\GLOBAL??\\C:") {
        r.fail("fat.write", format_args!("{why}"));
        return;
    }
    r.check("fat.write", write);
}

/// `FILE_CREATE`.
const FILE_CREATE: u32 = 2;
/// `GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE`.
const READ_WRITE_DELETE: u32 = 0xC011_0000;
/// File information classes.
const FILE_STANDARD_INFORMATION: u32 = 5;
const FILE_RENAME_INFORMATION: u32 = 10;
const FILE_DISPOSITION_INFORMATION: u32 = 13;
const FILE_END_OF_FILE_INFORMATION: u32 = 20;

/// Open the file `name` on `C:` for reading, writing and deleting,
/// making it with `disposition`.
fn open_rw(name: &str, disposition: u32) -> Result<u64, &'static str> {
    let request = OpenRequest {
        desired_access: READ_WRITE_DELETE,
        share_access: SHARE_READ_WRITE,
        disposition,
        ..OpenRequest::new(name)
    };
    file::open(&request)
        .map(|(handle, _)| handle)
        .map_err(|status| {
            kprintln!("fat: opening {name}: {status:#x}");
            "a file on C: could not be opened for writing"
        })
}

/// A request on a file that must succeed.
fn must(what: &str, result: Result<file::IoResult, file::IoError>) -> Result<(), &'static str> {
    match result {
        Ok(r) if r.status == STATUS_SUCCESS => Ok(()),
        Ok(r) => {
            kprintln!("fat: {what}: {:#x}", r.status);
            Err("a request on a file on C: failed")
        }
        Err(_) => {
            kprintln!("fat: {what}: refused");
            Err("a request on a file on C: was refused")
        }
    }
}

/// Write through `fastfat.sys`: a new file written across two of the
/// cache manager's views over a hole, part of it written again, cut
/// short and flushed; a file renamed; a file deleted. The new file reads
/// back as written; the host checks the image after the boot.
fn write() -> Result<(), &'static str> {
    let handle = open_rw("\\??\\C:\\NKWRITE.BIN", FILE_CREATE)?;
    let result = (|| {
        let data: alloc::vec::Vec<u8> = (WRITE_FROM..WRITE_TO).map(written).collect();
        must("write", file::write_at(handle, WRITE_FROM as i64, &data))?;
        must(
            "overwrite",
            file::write_at(handle, OVERWRITE_AT as i64, &[0xEE; OVERWRITE]),
        )?;
        must(
            "end of file",
            file::set_information(
                handle,
                FILE_END_OF_FILE_INFORMATION,
                &(CUT_TO as i64).to_le_bytes(),
            ),
        )?;
        must("flush", file::flush(handle))?;
        // FILE_STANDARD_INFORMATION: allocation size, end of file, links,
        // delete pending, directory.
        let mut standard = [0u8; 24];
        must(
            "size",
            file::query_information(handle, FILE_STANDARD_INFORMATION, &mut standard),
        )?;
        let end = i64::from_le_bytes(standard[8..16].try_into().unwrap_or_default());
        if end != CUT_TO as i64 {
            kprintln!("fat: NKWRITE.BIN's end of file is {end}");
            return Err("the new file's size is not where it was cut");
        }
        let mut back = vec![0u8; CUT_TO + SECTOR];
        let read =
            file::read_at(handle, 0, &mut back).map_err(|_| "the new file could not be read")?;
        if read.status != STATUS_SUCCESS || read.information != CUT_TO {
            kprintln!(
                "fat: reading NKWRITE.BIN: {:#x}, {} bytes",
                read.status,
                read.information
            );
            return Err("the new file did not read back at its length");
        }
        back.truncate(CUT_TO);
        if back != expected_written() {
            let at = back
                .iter()
                .zip(expected_written())
                .position(|(a, b)| *a != b);
            kprintln!("fat: NKWRITE.BIN differs first at {at:?}");
            return Err("the new file does not read back as written");
        }
        Ok(())
    })();
    file::close(handle);
    result?;
    // Rename within the directory: the new name, no target directory.
    let renamed = open_rw("\\??\\C:\\EMPTY.TXT", 1)?;
    let name: alloc::vec::Vec<u16> = "RENAMED.TXT".encode_utf16().collect();
    let mut info = vec![0u8; 0x14 + name.len() * 2];
    info[0x10..0x14].copy_from_slice(&((name.len() * 2) as u32).to_le_bytes());
    for (i, unit) in name.iter().enumerate() {
        info[0x14 + 2 * i..0x16 + 2 * i].copy_from_slice(&unit.to_le_bytes());
    }
    let result = must(
        "rename",
        file::set_information(renamed, FILE_RENAME_INFORMATION, &info),
    );
    file::close(renamed);
    result?;
    let doomed = open_rw("\\??\\C:\\HELLO.TXT", 1)?;
    let result = must(
        "delete",
        file::set_information(doomed, FILE_DISPOSITION_INFORMATION, &[1]),
    );
    file::close(doomed);
    result
}
