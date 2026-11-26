//! Rust runtime glue: `alloc` collections draw from the kernel pool.
//!
//! Kernel-internal allocations therefore show up in pool accounting next
//! to driver allocations, under the tag `NkRs`. That is deliberate: the
//! driver-unload leak check then covers the kernel's own bookkeeping too.
//!
//! A test may watch one thread's allocations ([`watch`]): they are
//! counted, and one of them, chosen by its number, is refused as if
//! memory had run out. That is how the tests reach the paths taken when
//! the pool gives nothing, which a pool with memory never takes.

use crate::mm::pool;
use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

const TAG: u32 = u32::from_le_bytes(*b"NkRs");

/// The thread whose allocations are watched, or null; how many it has
/// asked for since the watch began; and the number of the one to
/// refuse, 0 for none.
static WATCHED: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static MADE: AtomicU32 = AtomicU32::new(0);
static REFUSED: AtomicU32 = AtomicU32::new(0);

/// Watch the calling thread's allocations from the kernel's own heap
/// until [`unwatch`]: count them, and refuse the one numbered `refuse`,
/// counting from 1 (0 refuses none). What a DPC routine allocates on
/// top of the thread counts as the thread's. One watch at a time: the
/// tests run one after another.
pub fn watch(refuse: u32) {
    MADE.store(0, Ordering::Relaxed);
    REFUSED.store(refuse, Ordering::Relaxed);
    WATCHED.store(crate::ke::pcr::current_thread(), Ordering::Release);
}

/// End the watch. Returns the allocations the thread asked for
/// meanwhile, the refused one included.
pub fn unwatch() -> u32 {
    WATCHED.store(core::ptr::null_mut(), Ordering::Release);
    MADE.load(Ordering::Relaxed)
}

/// Whether this allocation is the one a watch says to refuse.
fn refused() -> bool {
    let watched = WATCHED.load(Ordering::Acquire);
    if watched.is_null() || watched != crate::ke::pcr::current_thread() {
        return false;
    }
    MADE.fetch_add(1, Ordering::Relaxed) + 1 == REFUSED.load(Ordering::Relaxed)
}

struct PoolAllocator;

// SAFETY: `pool::alloc` returns exclusive memory of at least the requested
// size, 16-byte aligned for small blocks and page aligned for large ones;
// the size is raised below when the layout needs more alignment than a
// small block gives.
unsafe impl GlobalAlloc for PoolAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if layout.align() > crate::mm::PAGE_SIZE || refused() {
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
