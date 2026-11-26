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
//! - `MmAllocatePagesForMdlEx` gives all the pages asked for or none,
//!   where Windows may give some.

#![allow(non_snake_case)]

use crate::kd;
use crate::ke::seh;
use crate::mm::{self, PAGE_SIZE, map, pool, user};
use core::ffi::c_void;
use nk_mm::frames::Within;
use nk_mm::protect;
use nk_mm::pt::Prot;
use nk_ntabi::io::*;
use nk_ntabi::status::{
    NTSTATUS, STATUS_ACCESS_VIOLATION, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_PAGE_PROTECTION, STATUS_NOT_MAPPED_VIEW, STATUS_SUCCESS,
};

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
/// and return the address of the buffer's first byte there, or null. An
/// MDL built over non-paged memory (`MmBuildMdlForNonPagedPool`) is in
/// system space already: the address it has there is returned.
///
/// # Safety
/// `mdl` must be a live MDL with locked pages, or one built over
/// non-paged memory.
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
        if (*mdl).MdlFlags & MDL_SOURCE_IS_NONPAGED_POOL != 0 {
            return (*mdl).MappedSystemVa;
        }
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

/// [`MmUnmapLockedPages`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmunmaplockedpages):
/// remove the system mapping `MmMapLockedPagesSpecifyCache` made of the
/// MDL's pages. For an MDL built over non-paged memory there is none to
/// remove. Unmapping what is not the MDL's mapping stops the system.
///
/// # Safety
/// `mdl` must be a live MDL.
pub unsafe extern "C" fn MmUnmapLockedPages(base_address: *mut c_void, mdl: *mut MDL) {
    // SAFETY: per the contract.
    unsafe {
        let flags = (*mdl).MdlFlags;
        if flags & MDL_MAPPED_TO_SYSTEM_VA != 0 && (*mdl).MappedSystemVa == base_address {
            let va = base_address as u64 & !(PAGE_SIZE as u64 - 1);
            map::unmap(va, pages(mdl));
            map::free_va(va, pages(mdl));
            (*mdl).MappedSystemVa = core::ptr::null_mut();
            (*mdl).MdlFlags &= !MDL_MAPPED_TO_SYSTEM_VA;
        } else if flags & MDL_SOURCE_IS_NONPAGED_POOL == 0 {
            kd::bugcheck(format_args!(
                "MmUnmapLockedPages: {base_address:p} is not where MDL {mdl:p} is mapped"
            ));
        }
    }
}

/// [`MmBuildMdlForNonPagedPool`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmbuildmdlfornonpagedpool):
/// fill in the pages of an MDL whose buffer is system memory that is
/// never paged: pool, contiguous memory, a mapping of device memory.
/// The buffer's own address is its system address. A buffer that is not
/// all mapped stops the system.
///
/// # Safety
/// `mdl` must be a live MDL from `IoAllocateMdl`, not locked or mapped.
pub unsafe extern "C" fn MmBuildMdlForNonPagedPool(mdl: *mut MDL) {
    // SAFETY: per the contract.
    unsafe {
        let start = (*mdl).StartVa as u64;
        for i in 0..pages(mdl) {
            let Some(pa) = map::physical(start + (i * PAGE_SIZE) as u64) else {
                kd::bugcheck(format_args!(
                    "MmBuildMdlForNonPagedPool: MDL {mdl:p} describes memory that is not mapped"
                ));
            };
            pfns(mdl).add(i).write(pa / PAGE_SIZE as u64);
        }
        (*mdl).MappedSystemVa = (start + u64::from((*mdl).ByteOffset)) as PVOID;
        (*mdl).Process = core::ptr::null_mut();
        (*mdl).MdlFlags |= MDL_SOURCE_IS_NONPAGED_POOL;
    }
}

/// `MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS` and the flags NK has nothing
/// to do for: memory is always zeroed, there is one node, nothing waits.
const MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS: u32 = 0x20;

/// [`MmAllocatePagesForMdlEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmallocatepagesformdlex):
/// allocate zeroed physical pages in a range of physical addresses,
/// mapped nowhere, and an MDL describing them. With a `skip_bytes`, the
/// pages come in runs of that many bytes, each beginning at a multiple
/// of it.
///
/// All of `total_bytes` or null: where Windows may return an MDL for
/// fewer pages than asked, NK returns none. The caching type is checked
/// and otherwise unused: it describes a mapping, and none is made here.
///
/// # Safety
/// None beyond being called as a driver calls it; unsafe because it
/// hands out memory the caller must give back with `MmFreePagesFromMdl`.
pub unsafe extern "C" fn MmAllocatePagesForMdlEx(
    low_address: i64,
    high_address: i64,
    skip_bytes: i64,
    total_bytes: usize,
    cache_type: u32,
    flags: u32,
) -> *mut MDL {
    let page = PAGE_SIZE as u64;
    let (skip, total) = (skip_bytes as u64, total_bytes.div_ceil(PAGE_SIZE));
    let run = if skip == 0 { 1 } else { (skip / page) as usize };
    let within = Within::bytes(low_address as u64, high_address as u64, 0, skip.max(page));
    let (Some(within), Some(_)) = (within, protect::uncached(cache_type)) else {
        return core::ptr::null_mut();
    };
    if total == 0 || u32::try_from(total * PAGE_SIZE).is_err() {
        return core::ptr::null_mut();
    }
    // A power of two is what the chunks flag is documented to require.
    if flags & MM_ALLOCATE_REQUIRE_CONTIGUOUS_CHUNKS != 0 && !skip.is_power_of_two() {
        return core::ptr::null_mut();
    }
    // SAFETY: an MDL for a buffer at no address, attached to no IRP.
    let mdl = unsafe {
        IoAllocateMdl(
            core::ptr::null_mut(),
            (total * PAGE_SIZE) as u32,
            0,
            0,
            core::ptr::null_mut(),
        )
    };
    if mdl.is_null() {
        return mdl;
    }
    let mut done = 0;
    while done < total {
        let count = run.min(total - done);
        let Some(pa) = mm::alloc_frames_within(count, &within) else {
            // SAFETY: the first `done` entries were written below, and
            // the MDL is the one just allocated.
            unsafe {
                for i in 0..done {
                    mm::free_frames(pfns(mdl).add(i).read() * page, 1);
                }
                IoFreeMdl(mdl);
            }
            return core::ptr::null_mut();
        };
        for i in 0..count {
            // SAFETY: the MDL has room for `total` frame numbers.
            unsafe { pfns(mdl).add(done + i).write(pa / page + i as u64) };
        }
        done += count;
    }
    // SAFETY: the MDL just allocated.
    unsafe { (*mdl).MdlFlags |= MDL_PAGES_LOCKED };
    mdl
}

/// [`MmFreePagesFromMdl`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmfreepagesfrommdl):
/// give back the pages `MmAllocatePagesForMdlEx` allocated. The MDL
/// itself is the caller's to free, with `ExFreePool`. Pages still
/// mapped stop the system.
///
/// # Safety
/// `mdl` came from `MmAllocatePagesForMdlEx` and its pages are not used
/// afterwards.
pub unsafe extern "C" fn MmFreePagesFromMdl(mdl: *mut MDL) {
    // SAFETY: per the contract.
    unsafe {
        if (*mdl).MdlFlags & MDL_MAPPED_TO_SYSTEM_VA != 0 {
            kd::bugcheck(format_args!(
                "MmFreePagesFromMdl: the pages of MDL {mdl:p} are still mapped"
            ));
        }
        for i in 0..pages(mdl) {
            mm::free_frames(pfns(mdl).add(i).read() * PAGE_SIZE as u64, 1);
        }
        (*mdl).MdlFlags &= !MDL_PAGES_LOCKED;
        (*mdl).ByteCount = 0;
    }
}

/// [`MmProtectMdlSystemAddress`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmprotectmdlsystemaddress):
/// change the protection of the system mapping
/// `MmMapLockedPagesSpecifyCache` made of the MDL's pages.
/// `STATUS_NOT_MAPPED_VIEW` for an MDL with no such mapping (one built
/// over non-paged memory has none of its own);
/// `STATUS_INVALID_PAGE_PROTECTION` for a protection that is not one.
///
/// # Safety
/// `mdl` must be a live MDL.
pub unsafe extern "C" fn MmProtectMdlSystemAddress(mdl: *mut MDL, new_protect: u32) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if (*mdl).MdlFlags & MDL_MAPPED_TO_SYSTEM_VA == 0 {
            return STATUS_NOT_MAPPED_VIEW;
        }
        let Some(protection) = protect::protection(new_protect) else {
            return STATUS_INVALID_PAGE_PROTECTION;
        };
        let prot = protection.access.then_some(Prot {
            write: protection.write,
            exec: protection.exec,
            device: protection.uncached,
        });
        let va = (*mdl).MappedSystemVa as u64 & !(PAGE_SIZE as u64 - 1);
        let frame = |i: usize| pfns(mdl).add(i).read() * PAGE_SIZE as u64;
        match map::remap(va, pages(mdl), frame, prot) {
            Ok(()) => STATUS_SUCCESS,
            Err(_) => STATUS_INSUFFICIENT_RESOURCES,
        }
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
