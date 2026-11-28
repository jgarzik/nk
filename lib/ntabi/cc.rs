//! What file systems hand the cache manager (`ntifs.h`). The cache
//! manager's own maps, views and buffer control blocks are opaque to
//! them and are NK's.

use crate::ke::KEVENT;
use core::ffi::c_void;

/// [`CC_FILE_SIZES`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_cc_file_sizes).
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CC_FILE_SIZES {
    pub AllocationSize: i64,
    pub FileSize: i64,
    pub ValidDataLength: i64,
}

/// `AcquireForLazyWrite` and `AcquireForReadAhead`: take the file's
/// resources for the cache manager's own I/O.
pub type ACQUIRE_FOR_CC = unsafe extern "C" fn(context: *mut c_void, wait: u8) -> u8;
/// `ReleaseFromLazyWrite` and `ReleaseFromReadAhead`.
pub type RELEASE_FROM_CC = unsafe extern "C" fn(context: *mut c_void);

/// [`CACHE_MANAGER_CALLBACKS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_cache_manager_callbacks):
/// the file system's routines `CcInitializeCacheMap` is given, which the
/// cache manager keeps a pointer to.
#[repr(C)]
pub struct CACHE_MANAGER_CALLBACKS {
    pub AcquireForLazyWrite: Option<ACQUIRE_FOR_CC>,
    pub ReleaseFromLazyWrite: Option<RELEASE_FROM_CC>,
    pub AcquireForReadAhead: Option<ACQUIRE_FOR_CC>,
    pub ReleaseFromReadAhead: Option<RELEASE_FROM_CC>,
}

/// `CACHE_UNINITIALIZE_EVENT`: what `CcUninitializeCacheMap` signals once
/// the file's shared cache map is deleted.
#[repr(C)]
pub struct CACHE_UNINITIALIZE_EVENT {
    pub Next: *mut CACHE_UNINITIALIZE_EVENT,
    pub Event: KEVENT,
}

/// `FILE_OBJECT.Flags` the cache manager and the fast I/O paths read and
/// set.
pub const FO_WRITE_THROUGH: u32 = 0x0000_0010;
pub const FO_SEQUENTIAL_ONLY: u32 = 0x0000_0020;
pub const FO_FILE_MODIFIED: u32 = 0x0000_1000;
pub const FO_FILE_SIZE_CHANGED: u32 = 0x0000_2000;
pub const FO_FILE_FAST_IO_READ: u32 = 0x0008_0000;
pub const FO_RANDOM_ACCESS: u32 = 0x0010_0000;

/// `FSRTL_COMMON_FCB_HEADER.Flags2`: the memory manager's modified-page
/// writer may write the stream's pages (without it, a stream file
/// object's are written by the cache manager only).
pub const FSRTL_FLAG2_DO_MODIFIED_WRITE: u8 = 0x01;

/// `CcMapData` flags.
pub const MAP_WAIT: u32 = 0x1;
pub const MAP_NO_READ: u32 = 0x10;
pub const MAP_HIGH_PRIORITY: u32 = 0x40;
/// Undocumented: page-fault clustering is off around the read.
pub const MAP_DISABLE_PAGEFAULT_CLUSTERING: u32 = 0x100;

/// `CcPinRead` and `CcPreparePinWrite` flags.
pub const PIN_WAIT: u32 = 0x1;
pub const PIN_EXCLUSIVE: u32 = 0x2;
pub const PIN_NO_READ: u32 = 0x4;
pub const PIN_IF_BCB: u32 = 0x8;
pub const PIN_CALLER_TRACKS_DIRTY_DATA: u32 = 0x20;
pub const PIN_HIGH_PRIORITY: u32 = 0x40;

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<CC_FILE_SIZES>() == 0x18);
    assert!(offset_of!(CC_FILE_SIZES, FileSize) == 0x08);
    assert!(offset_of!(CC_FILE_SIZES, ValidDataLength) == 0x10);
    assert!(size_of::<CACHE_MANAGER_CALLBACKS>() == 0x20);
    assert!(offset_of!(CACHE_MANAGER_CALLBACKS, ReleaseFromLazyWrite) == 0x08);
    assert!(offset_of!(CACHE_MANAGER_CALLBACKS, AcquireForReadAhead) == 0x10);
    assert!(offset_of!(CACHE_MANAGER_CALLBACKS, ReleaseFromReadAhead) == 0x18);
    assert!(size_of::<CACHE_UNINITIALIZE_EVENT>() == 0x20);
    assert!(offset_of!(CACHE_UNINITIALIZE_EVENT, Event) == 0x08);
};
