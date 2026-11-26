//! Memory descriptor lists: describing a buffer by its physical pages so
//! a driver can reach it through its own mapping (direct I/O).
//!
//! A buffer is the kernel's, or lies in the user range and is probed
//! as user memory (`mm::user`). `MmProbeAndLockPages` raises
//! `STATUS_ACCESS_VIOLATION` in its caller for a buffer that is not all
//! there, as Windows does.
//!
//! `MmProbeAndLockPages` holds its caller to the operation it names:
//! pages mapped read-only are not locked for writing. The system
//! mapping `MmMapLockedPagesSpecifyCache` makes of locked pages can be
//! written whatever they were locked for, as on Windows.
//!
//! Limits:
//! - Nothing is ever paged out, so "locking" pages records their frame
//!   numbers and marks the MDL; there is no pin count to take, and
//!   nothing keeps a user page mapped while it is locked.
//! - System mappings are always non-executable, whatever the caller's
//!   priority flags say.

#![allow(non_snake_case)]

use crate::kd;
use crate::ke::seh;
use crate::mm::{PAGE_SIZE, map, pool, user};
use core::ffi::c_void;
use nk_mm::pt::Prot;
use nk_ntabi::io::*;
use nk_ntabi::status::{NTSTATUS, STATUS_ACCESS_VIOLATION};

const TAG_MDL: u32 = u32::from_le_bytes(*b"Mdl ");
/// Largest buffer one MDL can describe: its `Size` field is 16 bits.
const MAX_MDL_BYTES: usize = i16::MAX as usize;

/// The page-frame-number array that follows an MDL header.
///
/// # Safety
/// `mdl` must be a live MDL from `IoAllocateMdl`.
unsafe fn pfns(mdl: *mut MDL) -> *mut u64 {
    // SAFETY: the array starts right after the header, in the same block.
    unsafe { mdl.add(1).cast() }
}

/// Pages the MDL's buffer spans.
///
/// # Safety
/// `mdl` must be a live MDL.
unsafe fn pages(mdl: *mut MDL) -> usize {
    // SAFETY: per the contract.
    unsafe { span_pages((*mdl).ByteOffset as usize, (*mdl).ByteCount as usize) }
}

/// `IoAllocateMdl`: allocate an MDL describing `length` bytes at
/// `virtual_address`, and optionally attach it to an IRP.
///
/// # Safety
/// `irp` must be null or a live IRP.
pub unsafe extern "C" fn IoAllocateMdl(
    virtual_address: *mut c_void,
    length: u32,
    secondary_buffer: u8,
    _charge_quota: u8,
    irp: *mut IRP,
) -> *mut MDL {
    let size = mdl_size(virtual_address as usize, length as usize);
    if size > MAX_MDL_BYTES {
        return core::ptr::null_mut();
    }
    let mdl = pool::alloc_zeroed(size, TAG_MDL).cast::<MDL>();
    if mdl.is_null() {
        return mdl;
    }
    // SAFETY: `mdl` is a fresh zeroed block of `size` bytes; `irp` is
    // valid per the contract.
    unsafe {
        (*mdl).Size = size as i16;
        (*mdl).StartVa = (virtual_address as usize & !(PAGE_SIZE - 1)) as PVOID;
        (*mdl).ByteOffset = (virtual_address as usize & (PAGE_SIZE - 1)) as u32;
        (*mdl).ByteCount = length;
        if !irp.is_null() {
            if secondary_buffer == 0 {
                (*irp).MdlAddress = mdl;
            } else {
                // A secondary buffer goes at the end of the IRP's chain.
                let mut tail = (*irp).MdlAddress;
                while !tail.is_null() && !(*tail).Next.is_null() {
                    tail = (*tail).Next;
                }
                if tail.is_null() {
                    (*irp).MdlAddress = mdl;
                } else {
                    (*tail).Next = mdl;
                }
            }
        }
    }
    mdl
}

/// `IoFreeMdl`. The pages must have been unlocked first.
///
/// # Safety
/// `mdl` must be a live MDL from `IoAllocateMdl`.
pub unsafe extern "C" fn IoFreeMdl(mdl: *mut MDL) {
    // SAFETY: per the contract.
    unsafe {
        if (*mdl).MdlFlags & MDL_PAGES_LOCKED != 0 {
            kd::bugcheck(format_args!(
                "IoFreeMdl: MDL {mdl:p} still has locked pages"
            ));
        }
    }
    if let Err(e) = pool::free(mdl.cast()) {
        kd::bugcheck(format_args!("IoFreeMdl: {mdl:p}: {e:?}"));
    }
}

/// Check that the MDL's buffer is all there for `access_mode` and for
/// `operation` (`IoReadAccess`, `IoWriteAccess`, `IoModifyAccess`), and
/// record the physical pages behind it: `MmProbeAndLockPages` without
/// the exception. A user-mode buffer must lie in the user range. `Err`
/// is the status Windows raises: a page is not mapped, the range is not
/// the mode's to name, or the caller means to write pages whose mapping
/// is read-only.
///
/// # Safety
/// `mdl` must be a live MDL whose pages are not already locked.
pub unsafe fn probe_and_lock(
    mdl: *mut MDL,
    access_mode: i8,
    operation: u32,
) -> Result<(), NTSTATUS> {
    // Reading asks nothing of the mapping; writing and modifying ask
    // that it can be written.
    let allowed = |writable: bool| writable || operation == IO_READ_ACCESS;
    // SAFETY: per the contract.
    unsafe {
        if (*mdl).MdlFlags & MDL_PAGES_LOCKED != 0 {
            kd::bugcheck(format_args!(
                "MmProbeAndLockPages: MDL {mdl:p} is already locked"
            ));
        }
        let start = (*mdl).StartVa as u64;
        for i in 0..pages(mdl) {
            let va = start + (i * PAGE_SIZE) as u64;
            // User mode can name only pages of the user range.
            let found = if access_mode == KERNEL_MODE || user::frame_of(va).is_some() {
                map::lookup(va)
            } else {
                None
            };
            let Some((pa, _)) = found.filter(|(_, writable)| allowed(*writable)) else {
                return Err(STATUS_ACCESS_VIOLATION);
            };
            pfns(mdl).add(i).write(pa / PAGE_SIZE as u64);
        }
        (*mdl).MdlFlags |= MDL_PAGES_LOCKED;
    }
    Ok(())
}

/// What [`MmProbeAndLockPages`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprobeandlockpages)
/// is entered as: probe and lock, and raise in the caller if the buffer
/// is not all there.
///
/// # Safety
/// Called through `nk_with_caller_context`; `mdl` as for
/// [`probe_and_lock`].
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_probe_and_lock_pages(
    mdl: *mut MDL,
    access_mode: i8,
    operation: u32,
    context: *mut seh::Context,
) {
    // SAFETY: per the contract; the context is the caller's.
    unsafe {
        if let Err(status) = probe_and_lock(mdl, access_mode, operation) {
            seh::raise(context, status as u32, seh::EXCEPTION_NONCONTINUABLE, &[]);
        }
    }
}

/// `MmUnlockPages`: undo `MmProbeAndLockPages`, removing any system
/// mapping made from the MDL.
///
/// # Safety
/// `mdl` must be a live MDL with locked pages.
pub unsafe extern "C" fn MmUnlockPages(mdl: *mut MDL) {
    // SAFETY: per the contract.
    unsafe {
        if (*mdl).MdlFlags & MDL_PAGES_LOCKED == 0 {
            kd::bugcheck(format_args!("MmUnlockPages: MDL {mdl:p} is not locked"));
        }
        if (*mdl).MdlFlags & MDL_MAPPED_TO_SYSTEM_VA != 0 {
            let va = (*mdl).MappedSystemVa as u64 & !(PAGE_SIZE as u64 - 1);
            map::unmap(va, pages(mdl));
            map::free_va(va, pages(mdl));
            (*mdl).MappedSystemVa = core::ptr::null_mut();
        }
        (*mdl).MdlFlags &= !(MDL_PAGES_LOCKED | MDL_MAPPED_TO_SYSTEM_VA);
    }
}

/// `MmMapLockedPagesSpecifyCache`: map the MDL's pages into system space
/// and return the address of the buffer's first byte there, or null.
///
/// # Safety
/// `mdl` must be a live MDL with locked pages.
pub unsafe extern "C" fn MmMapLockedPagesSpecifyCache(
    mdl: *mut MDL,
    access_mode: i8,
    _cache_type: u32,
    _requested_address: *mut c_void,
    bug_check_on_failure: u32,
    _priority: u32,
) -> *mut c_void {
    // SAFETY: per the contract.
    unsafe {
        if (*mdl).MdlFlags & MDL_PAGES_LOCKED == 0 {
            kd::bugcheck(format_args!(
                "MmMapLockedPagesSpecifyCache: MDL {mdl:p} is not locked"
            ));
        }
        if access_mode != KERNEL_MODE {
            kd::bugcheck(format_args!(
                "MmMapLockedPagesSpecifyCache: user-mode mappings are not implemented"
            ));
        }
        if (*mdl).MdlFlags & MDL_MAPPED_TO_SYSTEM_VA != 0 {
            return (*mdl).MappedSystemVa;
        }
        let count = pages(mdl);
        let mapped = map::alloc_va(count).and_then(|va| {
            for i in 0..count {
                let pa = pfns(mdl).add(i).read() * PAGE_SIZE as u64;
                if map::map(va + (i * PAGE_SIZE) as u64, pa, 1, Prot::RW).is_err() {
                    map::unmap(va, i);
                    map::free_va(va, count);
                    return None;
                }
            }
            Some(va)
        });
        let Some(va) = mapped else {
            if bug_check_on_failure != 0 {
                kd::bugcheck(format_args!(
                    "MmMapLockedPagesSpecifyCache: out of system address space"
                ));
            }
            return core::ptr::null_mut();
        };
        (*mdl).MappedSystemVa = (va + u64::from((*mdl).ByteOffset)) as PVOID;
        (*mdl).MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
        (*mdl).MappedSystemVa
    }
}

/// Unlock and free every MDL attached to an IRP. Part of final completion.
///
/// # Safety
/// `irp` must be a live IRP whose MDL chain came from `IoAllocateMdl`.
pub unsafe fn release_chain(irp: *mut IRP) {
    // SAFETY: per the contract.
    unsafe {
        let mut mdl = (*irp).MdlAddress;
        (*irp).MdlAddress = core::ptr::null_mut();
        while !mdl.is_null() {
            let next = (*mdl).Next;
            if (*mdl).MdlFlags & MDL_PAGES_LOCKED != 0 {
                MmUnlockPages(mdl);
            }
            IoFreeMdl(mdl);
            mdl = next;
        }
    }
}
