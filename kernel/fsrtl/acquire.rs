//! Taking a file system's file for what the kernel does on its behalf:
//! a flush of the cache manager's (`FsRtlAcquireFileForCcFlushEx`,
//! `FsRtlReleaseFileForCcFlush`) and the lazy writer's deletion of a
//! cache map (`FsRtlAcquireFileExclusive`, `FsRtlReleaseFile`).
//!
//! As the pinned kernel does it: inside a critical region kept until
//! the release, first the file system's own filter callback for the
//! operation (the copy `fsrtl::filter` keeps), whose
//! `STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY` means it did the work;
//! then the routine of its fast-I/O dispatch table, if the table is long
//! enough to hold it; and when there is none, or a flush's routine
//! answers `STATUS_INVALID_DEVICE_REQUEST`, the default on the FCB
//! header's resources. A failed acquisition leaves the critical region.
//! The post-operation callback, if the file system has one, follows a
//! pre-operation callback that succeeded.
//!
//! The device asked is the file system's own (the volume device of a
//! mounted file, else the file's device); NK attaches no filter to a
//! file system, so no other device's callbacks lie between.

use crate::ke::mutex::{KeEnterCriticalRegion, KeLeaveCriticalRegion};
use crate::ke::seh::{self, Guard};
use crate::mm::flush::FlushAcquire;
use core::ffi::c_void;
use nk_ntabi::fsrtl::*;
use nk_ntabi::io::{DEVICE_OBJECT, FAST_IO_DISPATCH, FILE_OBJECT, VPB};
use nk_ntabi::status::*;

/// Offsets in `FAST_IO_DISPATCH`.
const FAST_IO_ACQUIRE_FOR_CC_FLUSH: usize = 0xD0;
const FAST_IO_RELEASE_FOR_CC_FLUSH: usize = 0xD8;
const FAST_IO_ACQUIRE_FILE_FOR_NT_CREATE_SECTION: usize = 0x58;
const FAST_IO_RELEASE_FILE_FOR_NT_CREATE_SECTION: usize = 0x60;

/// The file system's own device for `file` (`IoGetBaseFileSystemDeviceObject`).
///
/// # Safety
/// `file` is an open file object.
unsafe fn base_device(file: *mut FILE_OBJECT) -> *mut DEVICE_OBJECT {
    // SAFETY: per the contract; an open file holds its device and the
    // volume block it was opened through.
    unsafe {
        let vpb = (*file).Vpb.cast::<VPB>();
        if !vpb.is_null() && !(*vpb).DeviceObject.is_null() {
            (*vpb).DeviceObject
        } else {
            (*file).DeviceObject
        }
    }
}

/// The routine at `offset` of a table whose first `ULONG` is its size,
/// if the table is long enough to hold it and it is set.
///
/// # Safety
/// `table` is null or such a table.
unsafe fn routine(table: *const u8, offset: usize) -> Option<usize> {
    if table.is_null() {
        return None;
    }
    // SAFETY: per the contract.
    unsafe {
        let size = table.cast::<u32>().read() as usize;
        if size < offset + 8 {
            return None;
        }
        let r = table.add(offset).cast::<usize>().read();
        (r != 0).then_some(r)
    }
}

/// What an operation is: its number, its pre-callback's offset, its
/// fast-I/O routine's, and the default.
struct Operation {
    code: u8,
    pre: usize,
    fast_io: usize,
    /// The fast-I/O routine returns a status (a flush's), or nothing.
    fast_io_status: bool,
    default: unsafe fn(*mut FSRTL_COMMON_FCB_HEADER),
    acquire: bool,
}

/// Run `op` on `file`. Returns the status.
///
/// # Safety
/// `file` is an open file object of a file system, at or below
/// `APC_LEVEL`.
unsafe fn run(file: *mut FILE_OBJECT, op: &Operation, parameters: [u64; 5]) -> NTSTATUS {
    // SAFETY: per the contract; the driver's tables are read as the
    // kernel reads them, by their sizes.
    unsafe {
        if op.acquire {
            KeEnterCriticalRegion();
        }
        let base = base_device(file);
        let driver = (*base).DriverObject;
        let callbacks = (*(*driver).DriverExtension)
            .FsFilterCallbacks
            .cast::<u8>()
            .cast_const();
        let fast_io = (*driver)
            .FastIoDispatch
            .cast::<FAST_IO_DISPATCH>()
            .cast::<u8>();
        let mut data = FS_FILTER_CALLBACK_DATA {
            SizeOfFsFilterCallbackData: size_of::<FS_FILTER_CALLBACK_DATA>() as u32,
            Operation: op.code,
            Reserved: 0,
            DeviceObject: base.cast(),
            FileObject: file.cast(),
            Parameters: parameters,
        };
        let mut context: *mut c_void = core::ptr::null_mut();
        let pre = routine(callbacks, op.pre);
        let post = routine(callbacks, op.pre + 8);
        let mut status = STATUS_SUCCESS;
        let mut done = false;
        if let Some(pre) = pre {
            status = seh::call(
                pre,
                [(&raw mut data).addr(), (&raw mut context).addr(), 0, 0],
                &Guard::Nothing,
            ) as i32;
            if status == STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY {
                status = STATUS_SUCCESS;
                done = true;
            } else if nt_error(status) {
                done = true;
            }
        }
        let pre_succeeded = pre.is_some() && !nt_error(status);
        if !done {
            status = STATUS_INVALID_DEVICE_REQUEST;
            if let Some(fast) = routine(fast_io, op.fast_io) {
                let returned = seh::call(fast, [file.addr(), base.addr(), 0, 0], &Guard::Nothing);
                if op.fast_io_status {
                    status = returned as i32;
                } else {
                    status = STATUS_SUCCESS;
                }
            }
            if status == STATUS_INVALID_DEVICE_REQUEST {
                (op.default)((*file).FsContext.cast());
                status = STATUS_SUCCESS;
            }
        }
        if pre_succeeded && let Some(post) = post {
            seh::call(
                post,
                [
                    (&raw mut data).addr(),
                    status as u32 as usize,
                    context.addr(),
                    0,
                ],
                &Guard::Nothing,
            );
        }
        if (op.acquire && nt_error(status)) || !op.acquire {
            KeLeaveCriticalRegion();
        }
        status
    }
}

/// The default acquisition for a flush: the main resource exclusive,
/// or shared again by a thread that holds it shared, then the paging
/// resource shared.
///
/// # Safety
/// `header` is null or a file's FCB header.
unsafe fn take_for_flush(header: *mut FSRTL_COMMON_FCB_HEADER) {
    use crate::ex::resource::*;
    // SAFETY: per the contract.
    unsafe {
        let Some(h) = header.as_ref() else { return };
        if !h.Resource.is_null() {
            if ExIsResourceAcquiredSharedLite(h.Resource) != 0 {
                ExAcquireResourceSharedLite(h.Resource, 1);
            } else {
                ExAcquireResourceExclusiveLite(h.Resource, 1);
            }
        }
        if !h.PagingIoResource.is_null() {
            ExAcquireResourceSharedLite(h.PagingIoResource, 1);
        }
    }
}

/// The default release for a flush: the paging resource, then the main.
///
/// # Safety
/// The thread took them as [`take_for_flush`] does.
unsafe fn give_for_flush(header: *mut FSRTL_COMMON_FCB_HEADER) {
    use crate::ex::resource::ExReleaseResourceLite;
    // SAFETY: per the contract.
    unsafe {
        let Some(h) = header.as_ref() else { return };
        if !h.PagingIoResource.is_null() {
            ExReleaseResourceLite(h.PagingIoResource);
        }
        if !h.Resource.is_null() {
            ExReleaseResourceLite(h.Resource);
        }
    }
}

/// The default exclusive acquisition: the main resource.
///
/// # Safety
/// As [`take_for_flush`].
unsafe fn take_exclusive(header: *mut FSRTL_COMMON_FCB_HEADER) {
    // SAFETY: per the contract.
    unsafe {
        if let Some(h) = header.as_ref()
            && !h.Resource.is_null()
        {
            crate::ex::resource::ExAcquireResourceExclusiveLite(h.Resource, 1);
        }
    }
}

/// The default release of [`take_exclusive`].
///
/// # Safety
/// The thread holds the main resource.
unsafe fn give_exclusive(header: *mut FSRTL_COMMON_FCB_HEADER) {
    // SAFETY: per the contract.
    unsafe {
        if let Some(h) = header.as_ref()
            && !h.Resource.is_null()
        {
            crate::ex::resource::ExReleaseResourceLite(h.Resource);
        }
    }
}

/// `FsRtlAcquireFileForCcFlushEx`: take `file` for a flush of the cache
/// manager's. Success leaves the thread in a critical region until
/// [`release_for_cc_flush`].
pub fn acquire_for_cc_flush(file: *mut FILE_OBJECT) -> NTSTATUS {
    const OP: Operation = Operation {
        code: FS_FILTER_ACQUIRE_FOR_CC_FLUSH,
        pre: PRE_ACQUIRE_FOR_CC_FLUSH,
        fast_io: FAST_IO_ACQUIRE_FOR_CC_FLUSH,
        fast_io_status: true,
        default: take_for_flush,
        acquire: true,
    };
    // SAFETY: the memory manager's flush of a file it holds open.
    unsafe { run(file, &OP, [0; 5]) }
}

/// `FsRtlReleaseFileForCcFlush`.
pub fn release_for_cc_flush(file: *mut FILE_OBJECT) {
    const OP: Operation = Operation {
        code: FS_FILTER_RELEASE_FOR_CC_FLUSH,
        pre: PRE_RELEASE_FOR_CC_FLUSH,
        fast_io: FAST_IO_RELEASE_FOR_CC_FLUSH,
        fast_io_status: true,
        default: give_for_flush,
        acquire: false,
    };
    // SAFETY: as above, after the acquisition.
    unsafe { run(file, &OP, [0; 5]) };
}

/// What the memory manager's flush is given when the cache manager has
/// it take the file (`MmFlushSection` asked to acquire).
pub const CC_FLUSH: FlushAcquire = FlushAcquire {
    acquire: acquire_for_cc_flush,
    release: release_for_cc_flush,
};

/// `FsRtlAcquireFileExclusive`: take `file` exclusive, as for a section
/// of no particular kind (`SyncTypeOther`); the thread stays in a
/// critical region until [`release_file`].
pub fn acquire_file_exclusive(file: *mut FILE_OBJECT) {
    const OP: Operation = Operation {
        code: FS_FILTER_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
        pre: PRE_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
        fast_io: FAST_IO_ACQUIRE_FILE_FOR_NT_CREATE_SECTION,
        fast_io_status: false,
        default: take_exclusive,
        acquire: true,
    };
    // SAFETY: the lazy writer's file, which a cache map holds open.
    unsafe { run(file, &OP, [u64::from(SYNC_TYPE_OTHER), 0, 0, 0, 0]) };
}

/// `FsRtlReleaseFile`.
pub fn release_file(file: *mut FILE_OBJECT) {
    const OP: Operation = Operation {
        code: FS_FILTER_RELEASE_FOR_SECTION_SYNCHRONIZATION,
        pre: PRE_RELEASE_FOR_SECTION_SYNCHRONIZATION,
        fast_io: FAST_IO_RELEASE_FILE_FOR_NT_CREATE_SECTION,
        fast_io_status: false,
        default: give_exclusive,
        acquire: false,
    };
    // SAFETY: as above, after the acquisition.
    unsafe { run(file, &OP, [0; 5]) };
}
