//! Paging I/O: the requests the memory manager sends a file system for
//! a section's pages, built as the pinned kernel's `IoPageReadEx` and
//! `IoSynchronousPageWriteEx` build them.
//!
//! - `Flags` = `IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO`
//!   (0x43) with the thread's I/O priority in bits 17-19, which for
//!   every NK thread is normal;
//! - the MDL, its locked pages, the event and the status block are the
//!   memory manager's: completion copies the status, signals the event
//!   and frees the IRP, with no APC, and leaves the MDL alone
//!   (`irp::complete_paging`);
//! - `UserBuffer` is the MDL's virtual address, `Thread` the caller,
//!   `OriginalFileObject` the file; the next location holds the major
//!   function, the file, the MDL's byte count and the offset (key 0).
//!
//! The caller waits on its event only when the call returns
//! `STATUS_PENDING`; otherwise the request is already complete (or was
//! never sent, for want of an IRP) and the status block holds its
//! result.

use super::irp;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, Ordering};
use nk_ntabi::io::*;
use nk_ntabi::ke::KEVENT;
use nk_ntabi::status::{NTSTATUS, STATUS_INSUFFICIENT_RESOURCES};

/// The next request finds no IRP, as when the pool has none: for the
/// tests of what the memory manager does then.
static FAIL_NEXT: AtomicBool = AtomicBool::new(false);

/// Have the next paging request fail for want of an IRP.
pub fn fail_next_allocation() {
    FAIL_NEXT.store(true, Ordering::Release);
}

/// Build and send one synchronous paging request.
///
/// # Safety
/// `file` is a live file object; `mdl` a locked MDL whose pages the
/// caller holds until `event` is signalled; `event` and `iosb` live as
/// long.
unsafe fn send(
    major: u8,
    file: *mut FILE_OBJECT,
    mdl: *mut MDL,
    offset: i64,
    event: *mut KEVENT,
    iosb: *mut IO_STATUS_BLOCK,
    sl_flags: u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let device = super::file::related_device(file);
        let irp = if FAIL_NEXT.swap(false, Ordering::AcqRel) {
            core::ptr::null_mut()
        } else {
            irp::alloc((*device).StackSize)
        };
        if irp.is_null() {
            // Nothing is sent, so nothing will signal the event.
            iosb.write(IO_STATUS_BLOCK {
                Status: STATUS_INSUFFICIENT_RESOURCES,
                Information: 0,
            });
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        (*irp).Flags =
            IRP_NOCACHE | IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO | IRP_PRIORITY_HINT_NORMAL;
        if major == IRP_MJ_READ && (*mdl).MdlFlags & MDL_IO_PAGE_READ != 0 {
            (*irp).AllocationFlags |= IRP_ALLOCATION_PAGE_READ;
        }
        (*irp).MdlAddress = mdl;
        (*irp).RequestorMode = KERNEL_MODE;
        (*irp).UserIosb = iosb;
        (*irp).UserEvent = event;
        (*irp).UserBuffer = (*mdl)
            .StartVa
            .cast::<u8>()
            .add((*mdl).ByteOffset as usize)
            .cast::<c_void>();
        (*irp).OriginalFileObject = file;
        (*irp).Thread = crate::ke::pcr::current_thread().cast();
        let next = irp::next_location(irp);
        (*next).MajorFunction = major;
        (*next).Flags = sl_flags;
        (*next).FileObject = file;
        (*next).Parameters[0] = u64::from((*mdl).ByteCount);
        (*next).Parameters[1] = 0;
        (*next).Parameters[2] = offset as u64;
        irp::IofCallDriver(device, irp)
    }
}

/// `IoPageReadEx` without its flags: read the MDL's pages from `file`
/// at `offset`. Returns what the file system's dispatch routine
/// returned.
///
/// # Safety
/// As [`send`].
pub unsafe fn page_read(
    file: *mut FILE_OBJECT,
    mdl: *mut MDL,
    offset: i64,
    event: *mut KEVENT,
    iosb: *mut IO_STATUS_BLOCK,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { send(IRP_MJ_READ, file, mdl, offset, event, iosb, 0) }
}
/// `IoSynchronousPageWriteEx`: write the MDL's pages to `file` at
/// `offset`; `sl_flags` go to the location's `Flags`.
///
/// # Safety
/// As [`send`].
pub unsafe fn synchronous_page_write(
    file: *mut FILE_OBJECT,
    mdl: *mut MDL,
    offset: i64,
    event: *mut KEVENT,
    iosb: *mut IO_STATUS_BLOCK,
    sl_flags: u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { send(IRP_MJ_WRITE, file, mdl, offset, event, iosb, sl_flags) }
}
