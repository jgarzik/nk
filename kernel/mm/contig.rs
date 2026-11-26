//! Physically contiguous memory within a range of physical addresses:
//! what a device that cannot reach all of memory, or needs one run of
//! it, is given.
//!
//! The memory is a pool block of whole pages (`pool::alloc_contiguous`),
//! so it is counted and checked like any other, lies in the map of all
//! RAM, and is zeroed. It is always cached, readable and writable and
//! not executable: a request for other caching gets cached memory,
//! which no driver can tell apart on machines whose devices see what the
//! processor wrote; a request for executable memory is refused.

#![allow(non_snake_case)]

use super::{PAGE_SIZE, pool};
use core::ffi::c_void;
use nk_mm::frames::Within;
use nk_mm::protect;

const TAG: u32 = u32::from_le_bytes(*b"MmCm");

/// `bytes` bytes of contiguous memory whose every byte has a physical
/// address in `lowest..=highest`, not crossing a multiple of `boundary`
/// (0: no boundary). Null if there is no such run free.
pub fn alloc(bytes: usize, lowest: u64, highest: u64, boundary: u64) -> *mut u8 {
    match Within::bytes(lowest, highest, boundary, PAGE_SIZE as u64) {
        Some(within) if bytes != 0 => pool::alloc_contiguous(bytes, TAG, &within),
        _ => core::ptr::null_mut(),
    }
}

/// Free memory from [`alloc`]; anything else stops the system.
pub fn free(base: *mut u8) {
    if pool::free(base).is_err() {
        crate::kd::bugcheck(format_args!(
            "0x000000C2 BAD_POOL_CALLER: free of {base:p}, which is not live contiguous memory"
        ));
    }
}

/// [`MmAllocateContiguousNodeMemory`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmallocatecontiguousnodememory).
/// `protect` is `PAGE_READWRITE`, alone or with a caching modifier; an
/// executable protection, or one that is not a protection, gets null.
/// NK has one node: the preferred node is not looked at.
pub extern "C" fn MmAllocateContiguousNodeMemory(
    number_of_bytes: usize,
    lowest_acceptable_address: i64,
    highest_acceptable_address: i64,
    boundary_address_multiple: i64,
    protect: u32,
    _preferred_node: u32,
) -> *mut c_void {
    match protect::protection(protect) {
        Some(p) if p.access && p.write && !p.exec => alloc(
            number_of_bytes,
            lowest_acceptable_address as u64,
            highest_acceptable_address as u64,
            boundary_address_multiple as u64,
        )
        .cast(),
        _ => core::ptr::null_mut(),
    }
}

/// [`MmAllocateContiguousMemorySpecifyCache`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmallocatecontiguousmemoryspecifycache).
/// A caching type that is not one gets null.
pub extern "C" fn MmAllocateContiguousMemorySpecifyCache(
    number_of_bytes: usize,
    lowest_acceptable_address: i64,
    highest_acceptable_address: i64,
    boundary_address_multiple: i64,
    cache_type: u32,
) -> *mut c_void {
    if protect::uncached(cache_type).is_none() {
        return core::ptr::null_mut();
    }
    alloc(
        number_of_bytes,
        lowest_acceptable_address as u64,
        highest_acceptable_address as u64,
        boundary_address_multiple as u64,
    )
    .cast()
}

/// [`MmFreeContiguousMemory`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmfreecontiguousmemory).
pub extern "C" fn MmFreeContiguousMemory(base_address: *mut c_void) {
    free(base_address.cast());
}

/// [`MmFreeContiguousMemorySpecifyCache`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmfreecontiguousmemoryspecifycache).
/// The block knows its own size.
pub extern "C" fn MmFreeContiguousMemorySpecifyCache(
    base_address: *mut c_void,
    _number_of_bytes: usize,
    _cache_type: u32,
) {
    free(base_address.cast());
}
