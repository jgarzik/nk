//! Rust runtime glue: `alloc` collections draw from the kernel pool.
//!
//! Kernel-internal allocations therefore show up in pool accounting next
//! to driver allocations, under the tag `NkRs`. That is deliberate: the
//! driver-unload leak check then covers the kernel's own bookkeeping too.

use crate::mm::pool;
use core::alloc::{GlobalAlloc, Layout};

const TAG: u32 = u32::from_le_bytes(*b"NkRs");

struct PoolAllocator;

// SAFETY: `pool::alloc` returns exclusive memory of at least the requested
// size, 16-byte aligned for small blocks and page aligned for large ones;
// the size is raised below when the layout needs more alignment than a
// small block gives.
unsafe impl GlobalAlloc for PoolAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > crate::mm::PAGE_SIZE {
            return core::ptr::null_mut();
        }
        // Anything stricter than 16 bytes takes the page-aligned path.
        let size = if layout.align() > 16 {
            layout.size().max(crate::mm::PAGE_SIZE)
        } else {
            layout.size()
        };
        pool::alloc(size, TAG)
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if let Err(e) = pool::free(ptr) {
            panic!("kernel heap free failed: {e:?}");
        }
    }
}

#[global_allocator]
static ALLOCATOR: PoolAllocator = PoolAllocator;
