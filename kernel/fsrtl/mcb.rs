//! The large mapping control block (`LARGE_MCB`): the exports, over the
//! rules of `nk_fsrtl::mcb`.
//!
//! The control block is the file system's memory; the array of pairs and
//! the mutex it points to are the kernel's, from the pool, as on
//! Windows. Each routine takes the mutex, copies the pairs out, applies
//! the rule and writes the pairs back, growing the array (doubling it)
//! when they no longer fit. The array is never made smaller; Windows
//! shrinks one that has become mostly empty, which no caller sees.
//!
//! The routines that may need memory raise `STATUS_INSUFFICIENT_RESOURCES`
//! in their caller when there is none, as the pinned kernel does for a
//! large MCB: they are entered through `nk_with_caller_context`, and give
//! up the mutex before raising.

use crate::arch::seh::{Context, fourth_argument};
use crate::ke::mutex::{KeAcquireGuardedMutex, KeInitializeGuardedMutex, KeReleaseGuardedMutex};
use crate::ke::seh::{EXCEPTION_NONCONTINUABLE, raise};
use crate::mm::pool;
use alloc::vec::Vec;
use core::mem::size_of;
use nk_fsrtl::mcb::{self, Pair};
use nk_ntabi::fsrtl::LARGE_MCB;
use nk_ntabi::ke::FAST_MUTEX;
use nk_ntabi::status::STATUS_INSUFFICIENT_RESOURCES;

/// The pool tag of the pair array.
const TAG_PAIRS: u32 = u32::from_le_bytes(*b"FSim");
/// The pool tag of the mutex.
const TAG_MUTEX: u32 = u32::from_le_bytes(*b"FSfm");
/// The pairs a new control block has room for.
const FIRST_PAIRS: u32 = 15;
/// `BASE_MCB.Flags`: raise when memory runs out, as a large MCB does.
const RAISE_ON_FAILURE: u16 = 1;

/// The control block's pairs.
///
/// # Safety
/// `mcb` is an initialised large MCB whose mutex the caller holds.
unsafe fn read(mcb: *const LARGE_MCB) -> Vec<Pair> {
    // SAFETY: per the contract; the array holds `PairCount` pairs.
    unsafe {
        let base = &raw const (*mcb).BaseMcb;
        let pairs = (*base).Mapping.cast::<Pair>();
        (0..(*base).PairCount as usize)
            .map(|i| pairs.add(i).read())
            .collect()
    }
}

/// Make `pairs` the control block's, growing its array if they do not
/// fit. False if there was no memory for that, the control block
/// unchanged.
///
/// # Safety
/// As [`read`].
unsafe fn write(mcb: *mut LARGE_MCB, pairs: &[Pair]) -> bool {
    // SAFETY: per the contract; the array is the pool block this module
    // allocated for it, `MaximumPairCount` pairs long.
    unsafe {
        let base = &raw mut (*mcb).BaseMcb;
        let mut room = (*base).MaximumPairCount;
        if pairs.len() > room as usize {
            while (room as usize) < pairs.len() {
                room *= 2;
            }
            let array = pool::alloc(room as usize * size_of::<Pair>(), TAG_PAIRS);
            if array.is_null() {
                return false;
            }
            let _ = pool::free((*base).Mapping.cast());
            (*base).Mapping = array.cast();
            (*base).MaximumPairCount = room;
        }
        let array = (*base).Mapping.cast::<Pair>();
        for (i, pair) in pairs.iter().enumerate() {
            array.add(i).write(*pair);
        }
        (*base).PairCount = pairs.len() as u32;
    }
    true
}

/// Run `f` on the control block's pairs with its mutex held.
///
/// # Safety
/// `mcb` is an initialised large MCB; the caller is at or below
/// `APC_LEVEL`.
unsafe fn locked<R>(mcb: *mut LARGE_MCB, f: impl FnOnce(&[Pair]) -> R) -> R {
    // SAFETY: per the contract.
    unsafe {
        KeAcquireGuardedMutex((*mcb).GuardedMutex);
        let r = f(&read(mcb));
        KeReleaseGuardedMutex((*mcb).GuardedMutex);
        r
    }
}

/// Replace the pairs with what `f` makes of them, with the mutex held;
/// raise in the caller if there is no memory for the result.
///
/// # Safety
/// As [`locked`]; `context` is the caller's, from
/// `nk_with_caller_context`.
unsafe fn update<R>(
    mcb: *mut LARGE_MCB,
    context: *mut Context,
    f: impl FnOnce(&[Pair]) -> (Option<Vec<Pair>>, R),
) -> R {
    // SAFETY: per the contract. Nothing is held when raising: the mutex
    // is given up and every Rust value dropped first.
    unsafe {
        KeAcquireGuardedMutex((*mcb).GuardedMutex);
        let (new, r) = f(&read(mcb));
        let stored = new.is_none_or(|pairs| write(mcb, &pairs));
        KeReleaseGuardedMutex((*mcb).GuardedMutex);
        if !stored {
            raise(
                context,
                STATUS_INSUFFICIENT_RESOURCES as u32,
                EXCEPTION_NONCONTINUABLE,
                &[],
            );
        }
        r
    }
}

/// Write a 64-bit number, a VBN, LBN or count, where the caller asked
/// for one: 32-bit values zero-extended, a hole's LBN as -1, as the
/// pinned kernel writes them.
///
/// # Safety
/// `to` is null or writable.
unsafe fn put(to: *mut i64, value: Option<u32>) {
    if !to.is_null() {
        // SAFETY: per the contract.
        unsafe { to.write_unaligned(value.map_or(-1, i64::from)) };
    }
}

/// What `FsRtlInitializeLargeMcb` is entered as: an empty control block
/// with room for its first pairs.
///
/// # Safety
/// `mcb` is the file system's control block; called through
/// `nk_with_caller_context`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_fsrtl_initialize_large_mcb(
    mcb: *mut LARGE_MCB,
    pool_type: u32,
    _: usize,
    context: *mut Context,
) {
    let mutex = pool::alloc(size_of::<FAST_MUTEX>(), TAG_MUTEX).cast::<FAST_MUTEX>();
    let array = pool::alloc(FIRST_PAIRS as usize * size_of::<Pair>(), TAG_PAIRS);
    if mutex.is_null() || array.is_null() {
        for block in [mutex.cast::<u8>(), array] {
            if !block.is_null() {
                let _ = pool::free(block);
            }
        }
        // SAFETY: the caller's context; nothing is held.
        unsafe {
            raise(
                context,
                STATUS_INSUFFICIENT_RESOURCES as u32,
                EXCEPTION_NONCONTINUABLE,
                &[],
            )
        }
    }
    // SAFETY: per the contract; the mutex is a fresh pool block.
    unsafe {
        KeInitializeGuardedMutex(mutex);
        (*mcb).GuardedMutex = mutex;
        let base = &raw mut (*mcb).BaseMcb;
        (*base).MaximumPairCount = FIRST_PAIRS;
        (*base).PairCount = 0;
        (*base).PoolType = pool_type as u16;
        (*base).Flags = RAISE_ON_FAILURE;
        (*base).Mapping = array.cast();
    }
}

/// [`FsRtlUninitializeLargeMcb`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtluninitializelargemcb):
/// free what the control block holds.
///
/// # Safety
/// `mcb` is an initialised large MCB nothing else uses.
#[allow(non_snake_case)]
pub unsafe extern "C" fn FsRtlUninitializeLargeMcb(mcb: *mut LARGE_MCB) {
    // SAFETY: per the contract; both blocks are this module's.
    unsafe {
        let _ = pool::free((*mcb).BaseMcb.Mapping.cast());
        let _ = pool::free((*mcb).GuardedMutex.cast());
        (*mcb).BaseMcb.Mapping = core::ptr::null_mut();
        (*mcb).GuardedMutex = core::ptr::null_mut();
    }
}

/// [`FsRtlResetLargeMcb`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlresetlargemcb):
/// empty the control block, taking its mutex unless the caller says it
/// holds the control block to itself.
///
/// # Safety
/// `mcb` is an initialised large MCB.
#[allow(non_snake_case)]
pub unsafe extern "C" fn FsRtlResetLargeMcb(mcb: *mut LARGE_MCB, self_synchronized: u8) {
    // SAFETY: per the contract.
    unsafe {
        if self_synchronized != 0 {
            (*mcb).BaseMcb.PairCount = 0;
        } else {
            KeAcquireGuardedMutex((*mcb).GuardedMutex);
            (*mcb).BaseMcb.PairCount = 0;
            KeReleaseGuardedMutex((*mcb).GuardedMutex);
        }
    }
}

/// What `FsRtlAddLargeMcbEntry` is entered as: map `count` VBNs from
/// `vbn` at the LBNs from `lbn`. False, the map unchanged, if part of
/// the range is mapped elsewhere.
///
/// # Safety
/// `mcb` is an initialised large MCB; called through
/// `nk_with_caller_context`.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_fsrtl_add_large_mcb_entry(
    mcb: *mut LARGE_MCB,
    vbn: i64,
    lbn: i64,
    context: *mut Context,
) -> u8 {
    // SAFETY: per the contract; the fourth argument is the count.
    unsafe {
        let count = fourth_argument(&*context) as u32;
        update(mcb, context, |pairs| {
            match mcb::add(pairs, vbn as u32, lbn as u32, count) {
                Some(new) => (Some(new), 1),
                None => (None, 0),
            }
        })
    }
}

/// What `FsRtlRemoveLargeMcbEntry` is entered as: make `count` VBNs from
/// `vbn` a hole.
///
/// # Safety
/// As [`nk_fsrtl_add_large_mcb_entry`].
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_fsrtl_remove_large_mcb_entry(
    mcb: *mut LARGE_MCB,
    vbn: i64,
    count: i64,
    context: *mut Context,
) {
    // SAFETY: per the contract.
    unsafe {
        update(mcb, context, |pairs| {
            (Some(mcb::remove(pairs, vbn as u32, count as u32)), ())
        })
    }
}

/// What `FsRtlTruncateLargeMcb` is entered as: forget every VBN from
/// `vbn` on.
///
/// # Safety
/// As [`nk_fsrtl_add_large_mcb_entry`].
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_fsrtl_truncate_large_mcb(
    mcb: *mut LARGE_MCB,
    vbn: i64,
    _: usize,
    context: *mut Context,
) {
    // SAFETY: per the contract.
    unsafe {
        update(mcb, context, |pairs| {
            (Some(mcb::truncate(pairs, vbn as u32)), ())
        })
    }
}

/// [`FsRtlLookupLargeMcbEntry`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtllookuplargemcbentry):
/// the run holding `vbn`, each answer written where the caller asked for
/// it. False if the map does not reach `vbn`.
///
/// # Safety
/// `mcb` is an initialised large MCB; each output is null or writable.
#[allow(non_snake_case, clippy::too_many_arguments)]
pub unsafe extern "C" fn FsRtlLookupLargeMcbEntry(
    mcb: *mut LARGE_MCB,
    vbn: i64,
    lbn: *mut i64,
    count_from_lbn: *mut i64,
    starting_lbn: *mut i64,
    count_from_starting_lbn: *mut i64,
    index: *mut u32,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let Some(found) = locked(mcb, |pairs| mcb::lookup(pairs, vbn as u32)) else {
            return 0;
        };
        put(lbn, found.lbn);
        put(count_from_lbn, Some(found.count_from_lbn));
        put(starting_lbn, found.starting_lbn);
        put(count_from_starting_lbn, Some(found.count_from_starting_lbn));
        if !index.is_null() {
            index.write_unaligned(found.index);
        }
        1
    }
}

/// [`FsRtlLookupLastLargeMcbEntryAndIndex`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtllookuplastlargemcbentryandindex):
/// the last VBN mapped, its LBN and its run's index. False for an empty
/// map.
///
/// # Safety
/// `mcb` is an initialised large MCB; the outputs are writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn FsRtlLookupLastLargeMcbEntryAndIndex(
    mcb: *mut LARGE_MCB,
    vbn: *mut i64,
    lbn: *mut i64,
    index: *mut u32,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let Some((last, at, run)) = locked(mcb, mcb::last) else {
            return 0;
        };
        put(vbn, Some(last));
        put(lbn, at);
        index.write_unaligned(run);
        1
    }
}

/// [`FsRtlGetNextLargeMcbEntry`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlgetnextlargemcbentry):
/// run `index`, holes included. False past the last.
///
/// # Safety
/// `mcb` is an initialised large MCB; the outputs are writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn FsRtlGetNextLargeMcbEntry(
    mcb: *mut LARGE_MCB,
    index: u32,
    vbn: *mut i64,
    lbn: *mut i64,
    count: *mut i64,
) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let Some((start, at, length)) = locked(mcb, |pairs| mcb::run(pairs, index)) else {
            return 0;
        };
        put(vbn, Some(start));
        put(lbn, at);
        put(count, Some(length));
        1
    }
}

/// [`FsRtlNumberOfRunsInLargeMcb`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlnumberofrunsinlargemcb):
/// the runs, holes included.
///
/// # Safety
/// `mcb` is an initialised large MCB.
#[allow(non_snake_case)]
pub unsafe extern "C" fn FsRtlNumberOfRunsInLargeMcb(mcb: *mut LARGE_MCB) -> u32 {
    // SAFETY: per the contract.
    unsafe { locked(mcb, |pairs| pairs.len() as u32) }
}
