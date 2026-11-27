//! Share access: the routines a file system keeps its `SHARE_ACCESS`
//! counts with. The rules are `nk_io::share`; this reads and writes the
//! file object's fields and the file system's counts through its
//! pointers.

#![allow(non_snake_case)]

use nk_io::share::{self, Counts, Open};
use nk_ntabi::io::{FILE_OBJECT, SHARE_ACCESS};
use nk_ntabi::status::{NTSTATUS, STATUS_SHARING_VIOLATION, STATUS_SUCCESS};

/// # Safety
/// `counts` points to a live `SHARE_ACCESS`.
unsafe fn read(counts: *const SHARE_ACCESS) -> Counts {
    // SAFETY: per the contract.
    let c = unsafe { counts.read() };
    Counts {
        open: c.OpenCount,
        readers: c.Readers,
        writers: c.Writers,
        deleters: c.Deleters,
        shared_read: c.SharedRead,
        shared_write: c.SharedWrite,
        shared_delete: c.SharedDelete,
    }
}

/// # Safety
/// `counts` points to a live `SHARE_ACCESS`.
unsafe fn write(counts: *mut SHARE_ACCESS, c: Counts) {
    // SAFETY: per the contract.
    unsafe {
        counts.write(SHARE_ACCESS {
            OpenCount: c.open,
            Readers: c.readers,
            Writers: c.writers,
            Deleters: c.deleters,
            SharedRead: c.shared_read,
            SharedWrite: c.shared_write,
            SharedDelete: c.shared_delete,
        });
    }
}

/// What `file` asked for and shares, from its fields.
///
/// # Safety
/// `file` is a live file object.
unsafe fn open_of(file: *const FILE_OBJECT) -> Open {
    // SAFETY: per the contract.
    unsafe {
        Open {
            read: (*file).ReadAccess != 0,
            write: (*file).WriteAccess != 0,
            delete: (*file).DeleteAccess != 0,
            shared_read: (*file).SharedRead != 0,
            shared_write: (*file).SharedWrite != 0,
            shared_delete: (*file).SharedDelete != 0,
        }
    }
}

/// Record `open` in `file`'s fields: its access always, what it shares
/// only if it has access that counts, as the pinned kernel does.
///
/// # Safety
/// `file` is a live file object.
unsafe fn set_fields(file: *mut FILE_OBJECT, open: &Open) {
    // SAFETY: per the contract.
    unsafe {
        (*file).ReadAccess = u8::from(open.read);
        (*file).WriteAccess = u8::from(open.write);
        (*file).DeleteAccess = u8::from(open.delete);
        if open.counts() {
            (*file).SharedRead = u8::from(open.shared_read);
            (*file).SharedWrite = u8::from(open.shared_write);
            (*file).SharedDelete = u8::from(open.shared_delete);
        }
    }
}

/// [`IoCheckShareAccess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocheckshareaccess).
///
/// # Safety
/// `file` is a live file object and `counts` a live `SHARE_ACCESS`.
pub unsafe extern "C" fn IoCheckShareAccess(
    access: u32,
    share_mode: u32,
    file: *mut FILE_OBJECT,
    counts: *mut SHARE_ACCESS,
    update: u8,
) -> NTSTATUS {
    let open = Open::new(access, share_mode);
    // SAFETY: per the contract.
    unsafe {
        set_fields(file, &open);
        if !open.counts() {
            return STATUS_SUCCESS;
        }
        let mut c = read(counts);
        if !share::allowed(&open, &c) {
            return STATUS_SHARING_VIOLATION;
        }
        if update != 0 {
            share::add(&open, &mut c);
            write(counts, c);
        }
    }
    STATUS_SUCCESS
}

/// [`IoSetShareAccess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iosetshareaccess):
/// the first open of a file: its counts are this open's alone.
///
/// # Safety
/// As [`IoCheckShareAccess`].
pub unsafe extern "C" fn IoSetShareAccess(
    access: u32,
    share_mode: u32,
    file: *mut FILE_OBJECT,
    counts: *mut SHARE_ACCESS,
) {
    let open = Open::new(access, share_mode);
    let mut c = Counts::default();
    if open.counts() {
        share::add(&open, &mut c);
    }
    // SAFETY: per the contract.
    unsafe {
        set_fields(file, &open);
        write(counts, c);
    }
}

/// [`IoUpdateShareAccess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioupdateshareaccess):
/// count `file`'s open, checked before.
///
/// # Safety
/// As [`IoCheckShareAccess`].
pub unsafe extern "C" fn IoUpdateShareAccess(file: *mut FILE_OBJECT, counts: *mut SHARE_ACCESS) {
    // SAFETY: per the contract.
    unsafe {
        let open = open_of(file);
        if open.counts() {
            let mut c = read(counts);
            share::add(&open, &mut c);
            write(counts, c);
        }
    }
}

/// [`IoRemoveShareAccess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioremoveshareaccess):
/// take `file`'s open out of the counts.
///
/// # Safety
/// As [`IoCheckShareAccess`].
pub unsafe extern "C" fn IoRemoveShareAccess(file: *mut FILE_OBJECT, counts: *mut SHARE_ACCESS) {
    // SAFETY: per the contract.
    unsafe {
        let open = open_of(file);
        if open.counts() {
            let mut c = read(counts);
            share::remove(&open, &mut c);
            write(counts, c);
        }
    }
}
