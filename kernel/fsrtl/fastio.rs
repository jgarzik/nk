//! The cached paths a file system's fast-I/O table points at:
//! `FsRtlCopyRead`, `FsRtlCopyWrite`, `FsRtlMdlReadDev`,
//! `FsRtlPrepareMdlWriteDev` and their completions.
//!
//! As the pinned kernel does them: FALSE (take the IRP path) when a
//! top-level IRP is set; the FCB header's main resource, shared, or
//! exclusive for a write that appends or passes the valid data length,
//! inside a critical region; FALSE unless the file is cached and fast
//! I/O is possible; reads clamped to the file size; writes refused past
//! the allocation size or more than 8 KiB beyond the valid data length,
//! the gap below the write zeroed (`CcZeroData`), the file size raised
//! first (under the paging resource) and put back on failure, and the
//! cache map's file size raised on success. The top-level IRP is
//! `FSRTL_FAST_IO_TOP_LEVEL_IRP` around the cache manager's call; a
//! failure in it is FALSE.
//!
//! NK's difference: a file whose fast I/O is questionable takes the IRP
//! path at once; Windows asks the file system's `FastIoCheckIfPossible`
//! first, which takes eight arguments, more than NK's guarded call into
//! a driver passes. Either way the caller falls back to an IRP when told
//! FALSE.

use crate::cc;
use crate::ex::resource::*;
use crate::io::fs::{IoGetTopLevelIrp, IoSetTopLevelIrp};
use crate::ke::mutex::{KeEnterCriticalRegion, KeLeaveCriticalRegion};
use core::ffi::c_void;
use nk_ntabi::cc::*;
use nk_ntabi::ex::ERESOURCE;
use nk_ntabi::fsrtl::FSRTL_COMMON_FCB_HEADER;
use nk_ntabi::io::{FILE_OBJECT, IO_STATUS_BLOCK, MDL};
use nk_ntabi::status::*;

/// `FSRTL_FAST_IO_TOP_LEVEL_IRP`.
const FAST_IO_TOP_LEVEL_IRP: usize = 4;
/// `IsFastIoPossible` values.
const FAST_IO_IS_NOT_POSSIBLE: u8 = 0;
const FAST_IO_IS_QUESTIONABLE: u8 = 2;
/// A write starts no further than this beyond the valid data length.
const ZERO_GAP: i64 = 0x2000;
/// Larger writes never take the fast path (`CcCopyWriteWontFlush`).
const WONT_FLUSH_LIMIT: u32 = 0x100_0000;

/// The header of `file`.
///
/// # Safety
/// `file` is a live file object of a file system.
unsafe fn header(file: *mut FILE_OBJECT) -> *mut FSRTL_COMMON_FCB_HEADER {
    // SAFETY: per the contract.
    unsafe { (*file).FsContext.cast() }
}

/// Whether fast I/O may go ahead on `file` with its header's resource
/// held: cached, and fast I/O neither impossible nor questionable.
///
/// # Safety
/// As [`header`].
unsafe fn possible(file: *mut FILE_OBJECT) -> bool {
    // SAFETY: per the contract.
    unsafe {
        let h = header(file);
        let state = (&raw const (*h).IsFastIoPossible).read();
        !(*file).PrivateCacheMap.is_null()
            && state != FAST_IO_IS_NOT_POSSIBLE
            && state != FAST_IO_IS_QUESTIONABLE
    }
}

/// Write a status block.
///
/// # Safety
/// `iosb` is writable.
unsafe fn report(iosb: *mut IO_STATUS_BLOCK, status: NTSTATUS, information: usize) {
    // SAFETY: per the contract.
    unsafe {
        iosb.write(IO_STATUS_BLOCK {
            Status: status,
            Information: information,
        })
    };
}

/// Take `resource` shared or exclusive in a critical region; false (the
/// region left) if it cannot be had without waiting.
///
/// # Safety
/// `resource` is an initialised resource.
unsafe fn take(resource: *mut ERESOURCE, exclusive: bool, wait: bool) -> bool {
    KeEnterCriticalRegion();
    // SAFETY: per the contract.
    let got = unsafe {
        if exclusive {
            ExAcquireResourceExclusiveLite(resource, u8::from(wait))
        } else {
            ExAcquireResourceSharedLite(resource, u8::from(wait))
        }
    } != 0;
    if !got {
        KeLeaveCriticalRegion();
    }
    got
}

/// Give back what [`take`] took.
///
/// # Safety
/// The thread holds `resource` from [`take`].
unsafe fn give(resource: *mut ERESOURCE) {
    // SAFETY: per the contract.
    unsafe { ExReleaseResourceLite(resource) };
    KeLeaveCriticalRegion();
}

/// Run `f` with the top-level IRP set to the fast-I/O value.
fn as_fast_io<R>(f: impl FnOnce() -> R) -> R {
    // SAFETY: the slot is the file system's to read; reset after.
    unsafe { IoSetTopLevelIrp(FAST_IO_TOP_LEVEL_IRP as *mut _) };
    let r = f();
    // SAFETY: as above.
    unsafe { IoSetTopLevelIrp(core::ptr::null_mut()) };
    r
}

/// The read paths' common shape: `read` runs with the header's resource
/// shared once the request is clamped to the file size; it returns
/// whether it did the read.
///
/// # Safety
/// `file` is a file object of a file system with an FCB header;
/// `offset` readable; `iosb` writable.
unsafe fn read_path(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    length: u32,
    wait: bool,
    iosb: *mut IO_STATUS_BLOCK,
    read: impl FnOnce(u64, u32) -> Result<bool, NTSTATUS>,
) -> u8 {
    if !IoGetTopLevelIrp().is_null() {
        return 0;
    }
    // SAFETY: per the contract.
    unsafe {
        if length == 0 {
            report(iosb, STATUS_SUCCESS, 0);
            return 1;
        }
        let start = offset.read_unaligned();
        if start.checked_add(i64::from(length)).is_none() || start < 0 {
            report(iosb, STATUS_INVALID_PARAMETER, 0);
            return 0;
        }
        let h = header(file);
        let resource = (*h).Resource;
        if !take(resource, false, wait) {
            return 0;
        }
        let done = 'body: {
            if !possible(file) {
                break 'body false;
            }
            let size = (&raw const (*h).FileSize).read();
            if start >= size {
                report(iosb, STATUS_END_OF_FILE, 0);
                break 'body true;
            }
            let length = (i64::from(length)).min(size - start) as u32;
            match as_fast_io(|| read(start as u64, length)) {
                Ok(true) => {
                    report(iosb, STATUS_SUCCESS, length as usize);
                    (*file).Flags |= FO_FILE_FAST_IO_READ;
                    (*file).CurrentByteOffset = start + i64::from(length);
                    true
                }
                Ok(false) | Err(_) => false,
            }
        };
        give(resource);
        u8::from(done)
    }
}

/// [`FsRtlCopyRead`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlcopyread).
///
/// # Safety
/// As the fast-I/O read routine of a file system using the cache.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn FsRtlCopyRead(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    length: u32,
    wait: u8,
    _lock_key: u32,
    buffer: *mut c_void,
    iosb: *mut IO_STATUS_BLOCK,
    _device: *mut c_void,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        read_path(file, offset, length, wait != 0, iosb, |at, len| {
            cc::copy::copy_read(file, at, len, wait != 0, buffer.cast())
        })
    }
}

/// [`FsRtlMdlReadDev`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlmdlreaddev).
///
/// # Safety
/// As the fast-I/O MDL read routine of a file system using the cache;
/// `chain` writable.
pub unsafe extern "C" fn FsRtlMdlReadDev(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    length: u32,
    _lock_key: u32,
    chain: *mut *mut MDL,
    iosb: *mut IO_STATUS_BLOCK,
    _device: *mut c_void,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        read_path(file, offset, length, true, iosb, |at, len| {
            cc::mdl::mdl_read(file, at, len, chain).map(|()| true)
        })
    }
}

/// [`FsRtlMdlReadCompleteDev`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlmdlreadcompletedev):
/// let go of an MDL read's pages.
///
/// # Safety
/// `chain` came from an MDL read of `file`.
pub unsafe extern "C" fn FsRtlMdlReadCompleteDev(
    _file: *mut FILE_OBJECT,
    chain: *mut MDL,
    _device: *mut c_void,
) -> u8 {
    // SAFETY: per the contract.
    unsafe { cc::mdl::mdl_read_complete2(chain) };
    1
}

/// The write paths' common shape: `write` runs with the header's
/// resource held and the file size raised for it, once the request
/// passes the checks; it returns whether it did the write. On success
/// the valid data length and the cache map's file size follow the
/// write.
///
/// # Safety
/// As [`read_path`].
unsafe fn write_path(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    length: u32,
    wait: bool,
    iosb: *mut IO_STATUS_BLOCK,
    write: impl FnOnce(u64, u32) -> Result<bool, NTSTATUS>,
) -> u8 {
    if !IoGetTopLevelIrp().is_null() {
        return 0;
    }
    // SAFETY: per the contract.
    unsafe {
        if cc::throttle::CcCanIWrite(file, length, u8::from(wait), 0) == 0
            || (*file).Flags & FO_WRITE_THROUGH != 0
            || length >= WONT_FLUSH_LIMIT
        {
            return 0;
        }
        if length == 0 {
            report(iosb, STATUS_SUCCESS, 0);
            return 1;
        }
        let h = header(file);
        let resource = (*h).Resource;
        let paging = (*h).PagingIoResource;
        let requested = offset.read_unaligned();
        let append = requested == -1;
        let valid = (&raw const (*h).ValidDataLength).read();
        let exclusive = append || requested + i64::from(length) > valid;
        if !take(resource, exclusive, wait) {
            return 0;
        }
        let done = 'body: {
            if !possible(file) {
                break 'body false;
            }
            let size = (&raw const (*h).FileSize).read();
            let valid = (&raw const (*h).ValidDataLength).read();
            let start = if append { size } else { requested };
            let Some(end) = start.checked_add(i64::from(length)) else {
                break 'body false;
            };
            if start < 0
                || start >= valid + ZERO_GAP
                || end > (&raw const (*h).AllocationSize).read()
                || (!exclusive && end > valid)
            {
                break 'body false;
            }
            let grows = end > size;
            let set = |field: *mut i64, value: i64| {
                if !paging.is_null() {
                    ExAcquireResourceExclusiveLite(paging, 1);
                }
                field.write(value);
                if !paging.is_null() {
                    ExReleaseResourceLite(paging);
                }
            };
            if grows {
                set(&raw mut (*h).FileSize, end);
            }
            let r = as_fast_io(|| {
                if start > valid {
                    let (from, to) = (valid, start);
                    if !cc::size::zero_data(file, from as u64, to as u64, wait)? {
                        return Ok(false);
                    }
                }
                write(start as u64, length)
            });
            if !matches!(r, Ok(true)) {
                if grows {
                    set(&raw mut (*h).FileSize, size);
                }
                break 'body false;
            }
            if end > valid {
                set(&raw mut (*h).ValidDataLength, end);
            }
            (*file).Flags |= FO_FILE_MODIFIED;
            if grows {
                if let Some(scm) = cc::scm_of(file).as_ref() {
                    let _m = cc::MASTER.lock();
                    scm.file_size.set(end);
                }
                (*file).Flags |= FO_FILE_SIZE_CHANGED;
            }
            (*file).CurrentByteOffset = end;
            report(iosb, STATUS_SUCCESS, length as usize);
            true
        };
        give(resource);
        u8::from(done)
    }
}

/// [`FsRtlCopyWrite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlcopywrite).
///
/// # Safety
/// As the fast-I/O write routine of a file system using the cache.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn FsRtlCopyWrite(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    length: u32,
    wait: u8,
    _lock_key: u32,
    buffer: *mut c_void,
    iosb: *mut IO_STATUS_BLOCK,
    _device: *mut c_void,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        write_path(file, offset, length, wait != 0, iosb, |at, len| {
            cc::copy::copy_write(file, at, len, wait != 0, buffer.cast_const().cast())
        })
    }
}

/// [`FsRtlPrepareMdlWriteDev`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlpreparemdlwritedev).
///
/// # Safety
/// As the fast-I/O prepare-MDL-write routine of a file system using the
/// cache; `chain` writable.
pub unsafe extern "C" fn FsRtlPrepareMdlWriteDev(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    length: u32,
    _lock_key: u32,
    chain: *mut *mut MDL,
    iosb: *mut IO_STATUS_BLOCK,
    _device: *mut c_void,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        write_path(file, offset, length, true, iosb, |at, len| {
            cc::mdl::prepare_mdl_write(file, at, len, chain).map(|()| true)
        })
    }
}

/// What `FsRtlMdlWriteCompleteDev` is entered as: the MDL write is
/// over (`CcMdlWriteComplete2`); a write-through failure is raised.
///
/// # Safety
/// `chain` came from a prepared MDL write of `file` at `offset`; with
/// `context` from `nk_with_caller_context`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_fsrtl_mdl_write_complete_dev(
    file: *mut FILE_OBJECT,
    offset: *const i64,
    chain: *mut MDL,
    context: *mut crate::arch::seh::Context,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let r = cc::mdl::mdl_write_complete2(file, offset.read_unaligned() as u64, chain);
        cc::or_raise(context, r);
    }
    1
}
