//! Lookaside lists: caches of freed blocks of one size.
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-lookaside-lists>
//!
//! Allocating from a list and freeing to it are code from the WDK's
//! headers, compiled into the driver: it pops and pushes `ListHead`,
//! counts in the structure, and on a miss calls the structure's
//! `Allocate` or `Free` routine itself. The kernel's part is to fill
//! the structure in (`nk_ex::lookaside` says with what) and, when the
//! list is deleted, to hand every block it still keeps to `Free`.
//!
//! `Allocate` and `Free` are therefore always callable: the driver's
//! own routines, or the pool's (`ExAllocatePoolWithTag`, `ExFreePool`).
//!
//! Windows links every list into one of two system-wide lists through
//! `ListEntry` and a periodic scan adjusts `Depth` from the miss counts.
//! NK has no scan: `ListEntry` is a list of the one entry, and `Depth`
//! stays as initialised.

#![allow(non_snake_case)]

use super::slist;
use crate::mm::pool;
use nk_ex::lookaside::{self, Fields};
use nk_ntabi::ex::{
    ALLOCATE_FUNCTION, FREE_FUNCTION, GENERAL_LOOKASIDE, NPAGED_LOOKASIDE_LIST,
    PAGED_LOOKASIDE_LIST,
};
use nk_ntabi::ke::LIST_ENTRY;

/// Fill in a list that keeps nothing yet.
///
/// # Safety
/// `list` points to writable storage for a `GENERAL_LOOKASIDE` nothing
/// else is using; the routines, where given, are callable as their
/// types say.
unsafe fn initialize(
    list: *mut GENERAL_LOOKASIDE,
    allocate: Option<ALLOCATE_FUNCTION>,
    free: Option<FREE_FUNCTION>,
    fields: Fields,
) {
    // SAFETY: per the contract.
    unsafe {
        // The counters, their `Last...` copies and `Future` start at
        // zero, and so does an empty list head.
        list.cast::<u8>()
            .write_bytes(0, size_of::<GENERAL_LOOKASIDE>());
        (&raw mut (*list).Depth).write(fields.depth);
        (&raw mut (*list).MaximumDepth).write(fields.maximum_depth);
        (&raw mut (*list).Type).write(fields.pool_type);
        (&raw mut (*list).Tag).write(fields.tag);
        (&raw mut (*list).Size).write(fields.size);
        (&raw mut (*list).Allocate).write(Some(allocate.unwrap_or(pool::ExAllocatePoolWithTag)));
        (&raw mut (*list).Free).write(Some(free.unwrap_or(pool::ExFreePool)));
        let entry = &raw mut (*list).ListEntry;
        entry.write(LIST_ENTRY {
            Flink: entry,
            Blink: entry,
        });
    }
}

/// Hand every block the list keeps to its `Free` routine.
///
/// # Safety
/// `list` points to an initialised `GENERAL_LOOKASIDE` that no thread
/// allocates from or frees to any more.
unsafe fn delete(list: *mut GENERAL_LOOKASIDE) {
    // SAFETY: per the contract. The blocks on the list are the list's
    // to free; each one's link is read before the block goes.
    unsafe {
        let Some(free) = (&raw const (*list).Free).read() else {
            crate::kd::bugcheck(format_args!(
                "a lookaside list at {list:p} was deleted with no Free routine: \
                 it was never initialised"
            ));
        };
        let mut entry = slist::ExpInterlockedFlushSList(&raw mut (*list).ListHead);
        while !entry.is_null() {
            let next = (&raw const (*entry).Next).read();
            free(entry.cast());
            entry = next;
        }
    }
}

/// [`ExInitializePagedLookasideList`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinitializepagedlookasidelist).
/// `flags` are pool flag bits, which join the pool type; `depth` is
/// reserved and ignored.
///
/// # Safety
/// `list` points to writable storage for the list; `allocate` and
/// `free`, where given, are callable as their types say.
pub unsafe extern "C" fn ExInitializePagedLookasideList(
    list: *mut PAGED_LOOKASIDE_LIST,
    allocate: Option<ALLOCATE_FUNCTION>,
    free: Option<FREE_FUNCTION>,
    flags: u32,
    size: usize,
    tag: u32,
    _depth: u16,
) {
    // SAFETY: per the contract.
    unsafe {
        initialize(
            &raw mut (*list).L,
            allocate,
            free,
            lookaside::paged(flags, size, tag),
        );
    }
}

/// [`ExInitializeNPagedLookasideList`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinitializenpagedlookasidelist).
///
/// # Safety
/// As `ExInitializePagedLookasideList`.
pub unsafe extern "C" fn ExInitializeNPagedLookasideList(
    list: *mut NPAGED_LOOKASIDE_LIST,
    allocate: Option<ALLOCATE_FUNCTION>,
    free: Option<FREE_FUNCTION>,
    flags: u32,
    size: usize,
    tag: u32,
    _depth: u16,
) {
    // SAFETY: per the contract.
    unsafe {
        initialize(
            &raw mut (*list).L,
            allocate,
            free,
            lookaside::npaged(flags, size, tag),
        );
    }
}

/// [`ExDeletePagedLookasideList`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exdeletepagedlookasidelist).
///
/// # Safety
/// `list` was initialised by `ExInitializePagedLookasideList` and no
/// thread uses it any more.
pub unsafe extern "C" fn ExDeletePagedLookasideList(list: *mut PAGED_LOOKASIDE_LIST) {
    // SAFETY: per the contract.
    unsafe { delete(&raw mut (*list).L) }
}

/// [`ExDeleteNPagedLookasideList`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exdeletenpagedlookasidelist).
///
/// # Safety
/// `list` was initialised by `ExInitializeNPagedLookasideList` and no
/// thread uses it any more.
pub unsafe extern "C" fn ExDeleteNPagedLookasideList(list: *mut NPAGED_LOOKASIDE_LIST) {
    // SAFETY: per the contract.
    unsafe { delete(&raw mut (*list).L) }
}

// ---- tests --------------------------------------------------------------

use crate::test::Slot;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

const TAG: u32 = u32::from_le_bytes(*b"NNkl");

static PAGED: Slot<PAGED_LOOKASIDE_LIST> = Slot::new();
static NPAGED: Slot<NPAGED_LOOKASIDE_LIST> = Slot::new();

/// What the header's `ExAllocateFrom...LookasideList` compiles to.
///
/// # Safety
/// `list` points to an initialised list.
unsafe fn allocate_from(list: *mut GENERAL_LOOKASIDE) -> *mut c_void {
    // SAFETY: per the contract; the driver's in-line code does these
    // reads, writes and calls.
    unsafe {
        let total = &raw mut (*list).TotalAllocates;
        total.write(total.read() + 1);
        let entry = slist::ExpInterlockedPopEntrySList(&raw mut (*list).ListHead);
        if !entry.is_null() {
            return entry.cast();
        }
        let misses = &raw mut (*list).AllocateMisses;
        misses.write(misses.read() + 1);
        match (&raw const (*list).Allocate).read() {
            Some(allocate) => allocate(
                (&raw const (*list).Type).read(),
                (&raw const (*list).Size).read() as usize,
                (&raw const (*list).Tag).read(),
            ),
            None => core::ptr::null_mut(),
        }
    }
}

/// What the header's `ExFreeTo...LookasideList` compiles to.
///
/// # Safety
/// `list` points to an initialised list and `block` came from it.
unsafe fn free_to(list: *mut GENERAL_LOOKASIDE, block: *mut c_void) {
    // SAFETY: per the contract.
    unsafe {
        let total = &raw mut (*list).TotalFrees;
        total.write(total.read() + 1);
        let head = &raw mut (*list).ListHead;
        if slist::ExQueryDepthSList(head) >= (&raw const (*list).Depth).read() {
            let misses = &raw mut (*list).FreeMisses;
            misses.write(misses.read() + 1);
            if let Some(free) = (&raw const (*list).Free).read() {
                free(block);
            }
        } else {
            slist::ExpInterlockedPushEntrySList(head, block.cast());
        }
    }
}

/// `Size`, `Tag`, `Type`, `Depth`, `MaximumDepth`.
///
/// # Safety
/// `list` points to an initialised list.
unsafe fn fields_of(list: *mut GENERAL_LOOKASIDE) -> (u32, u32, u32, u16, u16) {
    // SAFETY: per the contract.
    unsafe {
        (
            (&raw const (*list).Size).read(),
            (&raw const (*list).Tag).read(),
            (&raw const (*list).Type).read(),
            (&raw const (*list).Depth).read(),
            (&raw const (*list).MaximumDepth).read(),
        )
    }
}

/// `TotalAllocates`, `AllocateMisses`, `TotalFrees`, `FreeMisses`, and
/// how many blocks the list keeps.
///
/// # Safety
/// `list` points to an initialised list.
unsafe fn counts_of(list: *mut GENERAL_LOOKASIDE) -> (u32, u32, u32, u32, u16) {
    // SAFETY: per the contract.
    unsafe {
        (
            (&raw const (*list).TotalAllocates).read(),
            (&raw const (*list).AllocateMisses).read(),
            (&raw const (*list).TotalFrees).read(),
            (&raw const (*list).FreeMisses).read(),
            slist::ExQueryDepthSList(&raw mut (*list).ListHead),
        )
    }
}

/// Storage full of something that is not zero: what initialising must
/// overwrite.
fn dirty<T>(slot: &Slot<T>) -> *mut T {
    // SAFETY: static storage nobody else is using.
    unsafe { slot.ptr().cast::<u8>().write_bytes(0xEE, size_of::<T>()) };
    slot.ptr()
}

/// Initialising writes the fields the driver's in-line code reads, from
/// the arguments, and routines to call even where the driver gave none.
pub fn fields_test() -> Result<(), &'static str> {
    // SAFETY: static storage, initialised before it is read, used by
    // this thread alone; a list that keeps nothing needs no deleting,
    // and is deleted all the same.
    unsafe {
        let paged = dirty(&PAGED);
        ExInitializePagedLookasideList(paged, None, None, 0, 64, TAG, 0);
        let list = &raw mut (*paged).L;
        if fields_of(list) != (64, TAG, 1, 4, 256) {
            return Err("a paged list's size, tag, type or depths are not as initialised");
        }
        if counts_of(list) != (0, 0, 0, 0, 0) {
            return Err("a new list's counters are not zero, or it is not empty");
        }
        if (&raw const (*list).Allocate).read().is_none()
            || (&raw const (*list).Free).read().is_none()
        {
            return Err("a list initialised without routines has none to call");
        }
        ExDeletePagedLookasideList(paged);

        // A pool flag joins the type; the size is kept as given; the
        // depth argument is ignored.
        let paged = dirty(&PAGED);
        ExInitializePagedLookasideList(paged, None, None, 16, 24, TAG, 100);
        if fields_of(&raw mut (*paged).L) != (24, TAG, 0x11, 4, 256) {
            return Err("a pool flag, an odd size or a depth argument was not handled");
        }
        ExDeletePagedLookasideList(paged);

        let npaged = dirty(&NPAGED);
        ExInitializeNPagedLookasideList(npaged, None, None, 0x200, 48, TAG, 0);
        if fields_of(&raw mut (*npaged).L) != (48, TAG, 0x200, 4, 256) {
            return Err("a non-paged list's fields are not as initialised");
        }
        ExDeleteNPagedLookasideList(npaged);
    }
    Ok(())
}

/// A driver's in-line allocate and free against a list with the pool's
/// routines: a freed block is kept and handed out again, up to `Depth`
/// blocks, and deleting the list gives the pool every block back.
/// Returns the blocks the list kept at its fullest.
pub fn cache_test() -> Result<u16, &'static str> {
    let before = pool::usage();
    // SAFETY: static storage, initialised first, used by this thread
    // alone; every block is freed to the list it came from.
    let kept = unsafe {
        let paged = dirty(&PAGED);
        ExInitializePagedLookasideList(paged, None, None, 0, 64, TAG, 0);
        let list = &raw mut (*paged).L;
        let block = allocate_from(list);
        if block.is_null() || counts_of(list) != (1, 1, 0, 0, 0) {
            return Err("the first allocation did not miss and allocate");
        }
        block.cast::<u8>().write_bytes(0x5A, 64);
        free_to(list, block);
        if counts_of(list) != (1, 1, 1, 0, 1) {
            return Err("a freed block was not kept");
        }
        let again = allocate_from(list);
        if again != block || counts_of(list) != (2, 1, 1, 0, 0) {
            return Err("the kept block was not handed out again");
        }
        free_to(list, again);
        let mut blocks = [core::ptr::null_mut(); 6];
        for slot in &mut blocks {
            *slot = allocate_from(list);
            if slot.is_null() {
                return Err("an allocation failed");
            }
        }
        for block in blocks {
            free_to(list, block);
        }
        let counts = counts_of(list);
        if counts != (8, 6, 8, 2, 4) {
            return Err("six blocks in and out did not leave four kept and two freed");
        }
        ExDeletePagedLookasideList(paged);
        if slist::ExQueryDepthSList(&raw mut (*list).ListHead) != 0 {
            return Err("a deleted list still keeps blocks");
        }
        counts.4
    };
    if pool::usage() != before {
        return Err("deleting the list did not give its blocks back to the pool");
    }
    Ok(kept)
}

static ALLOCATED: AtomicU32 = AtomicU32::new(0);
static FREED: AtomicU32 = AtomicU32::new(0);
/// The arguments of the last call of the list's own allocate routine.
static ASKED_TYPE: AtomicU32 = AtomicU32::new(0);
static ASKED_SIZE: AtomicUsize = AtomicUsize::new(0);
static ASKED_TAG: AtomicU32 = AtomicU32::new(0);

/// # Safety
/// Called as a list's allocate routine.
unsafe extern "C" fn own_allocate(pool_type: u32, size: usize, tag: u32) -> *mut c_void {
    ALLOCATED.fetch_add(1, Ordering::AcqRel);
    ASKED_TYPE.store(pool_type, Ordering::Release);
    ASKED_SIZE.store(size, Ordering::Release);
    ASKED_TAG.store(tag, Ordering::Release);
    pool::ExAllocatePoolWithTag(pool_type, size, tag)
}

/// # Safety
/// Called as a list's free routine, with a block `own_allocate` made.
unsafe extern "C" fn own_free(block: *mut c_void) {
    FREED.fetch_add(1, Ordering::AcqRel);
    // SAFETY: per the contract.
    unsafe { pool::ExFreePoolWithTag(block, TAG) };
}

/// A list with routines of the driver's own: a miss calls its allocate
/// routine with the list's type, size and tag, and deleting the list
/// calls its free routine for each block kept. Returns the calls made.
pub fn routines_test() -> Result<u32, &'static str> {
    let before = pool::usage();
    ALLOCATED.store(0, Ordering::Release);
    FREED.store(0, Ordering::Release);
    // SAFETY: static storage, initialised first, used by this thread
    // alone.
    unsafe {
        let npaged = dirty(&NPAGED);
        ExInitializeNPagedLookasideList(npaged, Some(own_allocate), Some(own_free), 0, 48, TAG, 0);
        let list = &raw mut (*npaged).L;
        let block = allocate_from(list);
        let asked = (
            ALLOCATED.load(Ordering::Acquire),
            ASKED_TYPE.load(Ordering::Acquire),
            ASKED_SIZE.load(Ordering::Acquire),
            ASKED_TAG.load(Ordering::Acquire),
        );
        if block.is_null() || asked != (1, 0, 48, TAG) {
            return Err("a miss did not call the list's allocate routine with its type, size, tag");
        }
        free_to(list, block);
        if FREED.load(Ordering::Acquire) != 0 || counts_of(list) != (1, 1, 1, 0, 1) {
            return Err("a block the list had room for went to the free routine");
        }
        ExDeleteNPagedLookasideList(npaged);
        if FREED.load(Ordering::Acquire) != 1 {
            return Err("deleting the list did not call its free routine for the block kept");
        }
    }
    if pool::usage() != before {
        return Err("the list's block was not given back");
    }
    Ok(ALLOCATED.load(Ordering::Acquire) + FREED.load(Ordering::Acquire))
}
