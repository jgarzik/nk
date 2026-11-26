//! Device memory in system space, and the physical address behind a
//! virtual one.
//!
//! A mapping made here is of 4 KiB pages in the dynamic region. Memory
//! that firmware's map does not call RAM is always mapped as device
//! memory (uncached on x86-64, device attributes on arm64), whatever
//! caching the caller names: a cached mapping of device registers is
//! what no driver means. RAM (an ACPI table, say) is mapped cached
//! unless the caller asks otherwise. Write combining is mapped as
//! uncached (`nk_mm::protect`).

#![allow(non_snake_case)]

use super::{PAGE_SIZE, map};
use core::ffi::c_void;
use nk_mm::protect::{self, Protection};
use nk_mm::pt::Prot;

/// The page-aligned span of `bytes` bytes at `address`: its first page
/// and how many pages. `None` for no bytes or a span that wraps.
fn span(address: u64, bytes: usize) -> Option<(u64, usize)> {
    let end = address.checked_add(u64::try_from(bytes).ok()?)?;
    let first = address & !(PAGE_SIZE as u64 - 1);
    let pages = (end.checked_next_multiple_of(PAGE_SIZE as u64)? - first) / PAGE_SIZE as u64;
    (bytes != 0).then_some((first, pages as usize))
}

/// Map `bytes` bytes of physical memory at `pa` into system space as
/// `protection` asks, and return the address of the first byte.
pub fn map_physical(pa: u64, bytes: usize, protection: Protection) -> Option<*mut u8> {
    if !protection.access {
        return None;
    }
    let (first, pages) = span(pa, bytes)?;
    let prot = Prot {
        write: protection.write,
        exec: protection.exec,
        device: protection.uncached || !super::is_ram(first, (pages * PAGE_SIZE) as u64),
    };
    let va = map::alloc_va(pages)?;
    if map::map(va, first, pages, prot).is_err() {
        map::unmap(va, pages);
        map::free_va(va, pages);
        return None;
    }
    Some((va + (pa - first)) as *mut u8)
}

/// Undo [`map_physical`] for the `bytes` bytes mapped at `va`.
pub fn unmap_physical(va: *mut u8, bytes: usize) {
    let Some((first, pages)) = span(va as u64, bytes) else {
        return;
    };
    map::unmap(first, pages);
    map::free_va(first, pages);
}

/// [`MmMapIoSpaceEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmmapiospaceex):
/// map a range of physical addresses into system space with the given
/// page protection. Null if the protection is not one a system mapping
/// can have, the range is empty, or there is no memory for the mapping.
pub extern "C" fn MmMapIoSpaceEx(
    physical_address: i64,
    number_of_bytes: usize,
    protect: u32,
) -> *mut c_void {
    protect::protection(protect)
        .and_then(|p| map_physical(physical_address as u64, number_of_bytes, p))
        .map_or(core::ptr::null_mut(), |va| va.cast())
}

/// [`MmUnmapIoSpace`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmunmapiospace):
/// remove a mapping `MmMapIoSpaceEx` made, named by the address and
/// length it was made with.
pub extern "C" fn MmUnmapIoSpace(base_address: *mut c_void, number_of_bytes: usize) {
    unmap_physical(base_address.cast(), number_of_bytes);
}

/// [`MmGetPhysicalAddress`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmgetphysicaladdress):
/// the physical address `base_address` is mapped to; zero if it is not
/// mapped. Callable at any IRQL: it takes no lock.
pub extern "C" fn MmGetPhysicalAddress(base_address: *mut c_void) -> i64 {
    map::physical(base_address as u64).unwrap_or(0) as i64
}

/// [`MmGetVirtualForPhysical`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-mmgetvirtualforphysical):
/// a system address mapped to `physical_address`.
///
/// NK answers with the address in its map of all RAM. For memory from
/// the pool or the contiguous-memory routines that is the address the
/// memory was handed out at. An address that is not RAM has no such
/// mapping: asking for one stops the system.
pub extern "C" fn MmGetVirtualForPhysical(physical_address: i64) -> *mut c_void {
    let pa = physical_address as u64;
    if !super::is_ram(pa, 1) {
        crate::kd::bugcheck(format_args!(
            "MmGetVirtualForPhysical: {pa:#x} is not memory"
        ));
    }
    super::phys_to_virt(pa).cast()
}
