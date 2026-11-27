//! A file system's own filter callbacks
//! ([`FsRtlRegisterFileSystemFilterCallbacks`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlregisterfilesystemfiltercallbacks)):
//! the routines the kernel calls around the operations it starts on a
//! file system's behalf (taking the file for section creation, for the
//! modified-page writer, for a cache flush).
//!
//! As the pinned kernel does it: the driver's `FS_FILTER_CALLBACKS`,
//! `SizeOfFsFilterCallbacks` bytes of it, is copied into a block of
//! non-paged pool hung on `DriverExtension->FsFilterCallbacks`,
//! replacing any earlier one without freeing it; the block goes when
//! the driver object does (`io::driver::deleted`).

use crate::mm::pool;
use nk_ntabi::io::DRIVER_OBJECT;
use nk_ntabi::status::*;

/// The pool tag of the copy.
const TAG: u32 = u32::from_le_bytes(*b"FSmg");

/// `FsRtlRegisterFileSystemFilterCallbacks`: keep a copy of the
/// driver's callbacks.
///
/// # Safety
/// `driver` is null or a driver object; `callbacks` is null or an
/// `FS_FILTER_CALLBACKS` whose first `ULONG` gives its size.
#[allow(non_snake_case)]
pub unsafe extern "C" fn FsRtlRegisterFileSystemFilterCallbacks(
    driver: *mut DRIVER_OBJECT,
    callbacks: *const u32,
) -> NTSTATUS {
    if driver.is_null() || callbacks.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract, the structure's size is its first
    // ULONG, and that many bytes are readable.
    unsafe {
        let size = callbacks.read_unaligned() as usize;
        let copy = pool::alloc(size, TAG);
        if copy.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        core::ptr::copy_nonoverlapping(callbacks.cast::<u8>(), copy, size);
        (*(*driver).DriverExtension).FsFilterCallbacks = copy.cast();
    }
    STATUS_SUCCESS
}
