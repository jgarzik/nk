//! [Run-down protection](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/run-down-protection):
//! a word of the driver's memory that counts the threads using an
//! object and lets its owner wait for them to be done. The word's
//! values are `nk_ex::rundown`'s, Windows' own; here each change is one
//! atomic operation through the driver's pointer.
//!
//! The thread that runs an object down while it has holders sleeps on
//! an event in a block on its own stack, whose address the word then
//! holds; the release that counts the block down to nothing wakes it.
//! The word is left that way, as on Windows, until the driver
//! initialises it again.
//!
//! The cache-aware kind is a word a processor. NK has one group of
//! processors and counts those that are running; the lines the words
//! lie on are [`CACHE_LINE`] bytes.

#![allow(non_snake_case)]

use crate::ke::{pcr, smp, wait};
use crate::mm::pool;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};
use nk_ex::rundown::{self, Release};
use nk_ntabi::ex::{EX_RUNDOWN_REF, EX_RUNDOWN_REF_CACHE_AWARE};
use nk_ntabi::ke::KEVENT;

/// The bytes of a cache line on the processors NK runs on, which is
/// what `KeGetRecommendedSharedDataAlignment` answers.
pub const CACHE_LINE: u32 = 64;

/// What Windows puts in `PoolToFree` of a cache-aware block whose
/// memory is the caller's.
const NOT_FROM_POOL: usize = 0x0BAD_CA11;

/// A thread waiting for an object's holders to be done: on its stack
/// while it sleeps.
#[repr(C)]
struct Block {
    /// The holders still to release.
    count: AtomicUsize,
    /// What the thread sleeps on.
    event: KEVENT,
}

/// The word of a driver's run-down reference.
///
/// # Safety
/// `reference` points to a live, aligned `EX_RUNDOWN_REF`.
unsafe fn word<'a>(reference: *mut EX_RUNDOWN_REF) -> &'a AtomicUsize {
    // SAFETY: per the contract; an atomic view is how a word that other
    // processors and the driver also touch must be accessed.
    unsafe { AtomicUsize::from_ptr(reference) }
}

fn acquire(word: &AtomicUsize) -> u8 {
    let mut old = word.load(Ordering::Relaxed);
    loop {
        let Some(new) = rundown::acquire(old) else {
            return 0;
        };
        match word.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return 1,
            Err(now) => old = now,
        }
    }
}

fn release(word: &AtomicUsize) {
    let mut old = word.load(Ordering::Relaxed);
    loop {
        match rundown::release(old) {
            Release::Store(new) => {
                match word.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Relaxed) {
                    Ok(_) => return,
                    Err(now) => old = now,
                }
            }
            Release::CountDown(block) => {
                let block = block as *mut Block;
                // SAFETY: the word names the block of a thread that
                // sleeps until its count is nothing, which only this
                // release, if it is the last, can make it.
                unsafe {
                    if (*block).count.fetch_sub(1, Ordering::AcqRel) == 1 {
                        wait::KeSetEvent(&raw mut (*block).event, 0, 0);
                    }
                }
                return;
            }
            Release::NotHeld => crate::kd::bugcheck(format_args!(
                "run-down protection at {:p} was released after the object was run down",
                word.as_ptr()
            )),
        }
    }
}

/// A block for the calling thread to sleep on, in `storage`.
fn block(storage: &mut MaybeUninit<Block>) -> *mut Block {
    let block = storage.as_mut_ptr();
    // SAFETY: the storage is the caller's frame, written whole before
    // anything can find it.
    unsafe {
        (&raw mut (*block).count).write(AtomicUsize::new(0));
        wait::KeInitializeEvent(&raw mut (*block).event, 1, 0);
    }
    block
}

/// Sleep until the last holder has counted `block` down.
///
/// # Safety
/// `block` is the calling thread's, from [`block`].
unsafe fn sleep(block: *mut Block) {
    // SAFETY: per the contract; the frame stays until the wait returns.
    unsafe { wait::wait(Some((&raw mut (*block).event).cast()), None) };
}

/// [`ExInitializeRundownProtection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinitializerundownprotection).
///
/// # Safety
/// `reference` is writable and nothing else is using it.
pub unsafe extern "C" fn ExInitializeRundownProtection(reference: *mut EX_RUNDOWN_REF) {
    // SAFETY: per the contract.
    unsafe { word(reference) }.store(0, Ordering::Release);
}

/// [`ExAcquireRundownProtection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquirerundownprotection):
/// `TRUE` with a hold on the object, `FALSE` once it is being run down.
///
/// # Safety
/// `reference` points to initialised run-down protection.
pub unsafe extern "C" fn ExAcquireRundownProtection(reference: *mut EX_RUNDOWN_REF) -> u8 {
    // SAFETY: per the contract.
    acquire(unsafe { word(reference) })
}

/// [`ExReleaseRundownProtection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exreleaserundownprotection).
///
/// # Safety
/// The caller holds the protection `reference` points to.
pub unsafe extern "C" fn ExReleaseRundownProtection(reference: *mut EX_RUNDOWN_REF) {
    // SAFETY: per the contract.
    release(unsafe { word(reference) });
}

/// [`ExWaitForRundownProtectionRelease`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exwaitforrundownprotectionrelease):
/// let nobody new in, and wait for the holders there are. For
/// `PASSIVE_LEVEL` and `APC_LEVEL`.
///
/// # Safety
/// `reference` points to initialised run-down protection that stays
/// valid until this returns.
pub unsafe extern "C" fn ExWaitForRundownProtectionRelease(reference: *mut EX_RUNDOWN_REF) {
    // SAFETY: per the contract.
    let word = unsafe { word(reference) };
    let mut storage = MaybeUninit::uninit();
    let mut mine = core::ptr::null_mut::<Block>();
    let mut old = word.load(Ordering::Relaxed);
    loop {
        if old & rundown::ACTIVE != 0 {
            // Run down already.
            return;
        }
        let new = if old == 0 {
            rundown::ACTIVE
        } else {
            if mine.is_null() {
                mine = block(&mut storage);
            }
            // SAFETY: the block is this frame's and not yet published.
            unsafe {
                (*mine)
                    .count
                    .store(rundown::holders(old) as usize, Ordering::Relaxed)
            };
            rundown::waited_for(mine.addr())
        };
        match word.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) if old == 0 => return,
            // SAFETY: the block is this frame's, and now the word's.
            Ok(_) => return unsafe { sleep(mine) },
            Err(now) => old = now,
        }
    }
}

/// The word, of a cache-aware block, of the processor at `index`.
///
/// # Safety
/// `block` points to an initialised cache-aware block with that many
/// words.
unsafe fn word_at<'a>(block: *mut EX_RUNDOWN_REF_CACHE_AWARE, index: u32) -> &'a AtomicUsize {
    // SAFETY: per the contract.
    unsafe {
        let stride = (&raw const (*block).RunRefSize).read() as usize;
        word(
            (&raw const (*block).RunRefs)
                .read()
                .byte_add(stride * index as usize),
        )
    }
}

/// The word the calling thread uses now: its processor's.
///
/// # Safety
/// As [`word_at`].
unsafe fn word_here<'a>(block: *mut EX_RUNDOWN_REF_CACHE_AWARE) -> &'a AtomicUsize {
    // SAFETY: per the contract.
    unsafe {
        let number = (&raw const (*block).Number).read();
        word_at(block, rundown::word_of(pcr::current_processor(), number))
    }
}

/// Fill in a cache-aware block's header and clear its words.
///
/// # Safety
/// `block` is writable, and the words named are too.
unsafe fn set_up(
    block: *mut EX_RUNDOWN_REF_CACHE_AWARE,
    words: rundown::Words,
    pool_to_free: *mut c_void,
) {
    // SAFETY: per the contract.
    unsafe {
        block.write(EX_RUNDOWN_REF_CACHE_AWARE {
            RunRefs: core::ptr::with_exposed_provenance_mut(words.first),
            PoolToFree: pool_to_free,
            RunRefSize: words.stride,
            Number: words.number,
        });
        for index in 0..words.number {
            word_at(block, index).store(0, Ordering::Release);
        }
    }
}

/// [`ExSizeOfRundownProtectionCacheAware`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exsizeofrundownprotectioncacheaware).
pub extern "C" fn ExSizeOfRundownProtectionCacheAware() -> usize {
    rundown::cache_aware_size(smp::online_count() as u32, CACHE_LINE)
}

/// [`ExInitializeRundownProtectionCacheAware`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinitializerundownprotectioncacheaware):
/// lay the block out in the caller's buffer.
///
/// # Safety
/// `block` is writable for `size` bytes, which is what
/// `ExSizeOfRundownProtectionCacheAware` returned.
pub unsafe extern "C" fn ExInitializeRundownProtectionCacheAware(
    block: *mut EX_RUNDOWN_REF_CACHE_AWARE,
    size: usize,
) {
    let words = rundown::cache_aware_words(block.expose_provenance(), size, CACHE_LINE);
    // SAFETY: per the contract; the words lie within the buffer.
    unsafe {
        set_up(
            block,
            words,
            core::ptr::without_provenance_mut(NOT_FROM_POOL),
        )
    };
}

/// [`ExAllocateCacheAwareRundownProtection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exallocatecacheawarerundownprotection):
/// a cache-aware block from the pool, or null without memory.
pub extern "C" fn ExAllocateCacheAwareRundownProtection(
    pool_type: u32,
    tag: u32,
) -> *mut EX_RUNDOWN_REF_CACHE_AWARE {
    let header = pool::ExAllocatePoolWithTag(pool_type, rundown::CACHE_AWARE_HEADER, tag)
        .cast::<EX_RUNDOWN_REF_CACHE_AWARE>();
    if header.is_null() {
        return header;
    }
    // The words alone, as a buffer of the caller's would hold them
    // after its header.
    let size = ExSizeOfRundownProtectionCacheAware() - rundown::CACHE_AWARE_HEADER;
    let memory = pool::ExAllocatePoolWithTag(pool_type, size, tag);
    if memory.is_null() {
        // SAFETY: the header was just allocated.
        unsafe { pool::ExFreePoolWithTag(header.cast(), tag) };
        return core::ptr::null_mut();
    }
    let words = rundown::cache_aware_words(
        memory.expose_provenance() - rundown::CACHE_AWARE_HEADER,
        size + rundown::CACHE_AWARE_HEADER,
        CACHE_LINE,
    );
    // SAFETY: both blocks are fresh; the words lie within the second.
    unsafe { set_up(header, words, memory) };
    header
}

/// [`ExFreeCacheAwareRundownProtection`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exfreecacheawarerundownprotection).
///
/// # Safety
/// `block` came from `ExAllocateCacheAwareRundownProtection` and is not
/// used afterwards.
pub unsafe extern "C" fn ExFreeCacheAwareRundownProtection(block: *mut EX_RUNDOWN_REF_CACHE_AWARE) {
    // SAFETY: per the contract.
    unsafe {
        pool::ExFreePool((&raw const (*block).PoolToFree).read());
        pool::ExFreePool(block.cast());
    }
}

/// [`ExReInitializeRundownProtectionCacheAware`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exreinitializerundownprotectioncacheaware):
/// let holders in again after a run-down.
///
/// # Safety
/// `block` is an initialised cache-aware block that has been run down.
pub unsafe extern "C" fn ExReInitializeRundownProtectionCacheAware(
    block: *mut EX_RUNDOWN_REF_CACHE_AWARE,
) {
    // SAFETY: per the contract.
    unsafe {
        for index in 0..(&raw const (*block).Number).read() {
            word_at(block, index).store(0, Ordering::Release);
        }
    }
}

/// [`ExAcquireRundownProtectionCacheAware`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquirerundownprotectioncacheaware).
///
/// # Safety
/// `block` is an initialised cache-aware block.
pub unsafe extern "C" fn ExAcquireRundownProtectionCacheAware(
    block: *mut EX_RUNDOWN_REF_CACHE_AWARE,
) -> u8 {
    // SAFETY: per the contract.
    acquire(unsafe { word_here(block) })
}

/// [`ExReleaseRundownProtectionCacheAware`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exreleaserundownprotectioncacheaware).
///
/// # Safety
/// The caller holds the protection of the cache-aware block.
pub unsafe extern "C" fn ExReleaseRundownProtectionCacheAware(
    block: *mut EX_RUNDOWN_REF_CACHE_AWARE,
) {
    // SAFETY: per the contract.
    release(unsafe { word_here(block) });
}

/// [`ExWaitForRundownProtectionReleaseCacheAware`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exwaitforrundownprotectionreleasecacheaware):
/// let nobody new in on any processor, and wait for the holders there
/// are. For `PASSIVE_LEVEL` and `APC_LEVEL`.
///
/// # Safety
/// `block` is an initialised cache-aware block that stays valid until
/// this returns.
pub unsafe extern "C" fn ExWaitForRundownProtectionReleaseCacheAware(
    block: *mut EX_RUNDOWN_REF_CACHE_AWARE,
) {
    let mut storage = MaybeUninit::uninit();
    let mine = self::block(&mut storage);
    // Each word in turn is closed and its holders taken over. A hold
    // given back meanwhile counts the block down below nothing, and the
    // sum added at the end makes that good.
    let mut holders = 0isize;
    // SAFETY: per the contract; the block is this frame's.
    unsafe {
        for index in 0..(&raw const (*block).Number).read() {
            let old =
                word_at(block, index).swap(rundown::waited_for(mine.addr()), Ordering::AcqRel);
            if old & rundown::ACTIVE == 0 {
                holders += rundown::holders(old);
            }
        }
        if holders != 0 {
            let before = (*mine).count.fetch_add(holders as usize, Ordering::AcqRel);
            if before.wrapping_add(holders as usize) != 0 {
                sleep(mine);
            }
        }
    }
}

/// The reference the test's two threads share.
static SHARED: AtomicUsize = AtomicUsize::new(0);
/// The cache-aware block they share.
static SHARED_BLOCK: AtomicUsize = AtomicUsize::new(0);
/// How many waits for run-down have returned.
static RUN_DOWN: AtomicUsize = AtomicUsize::new(0);

fn waiter(cache_aware: usize) {
    // SAFETY: the static reference, or the block the test allocated and
    // keeps until this thread has ended.
    unsafe {
        if cache_aware == 0 {
            ExWaitForRundownProtectionRelease(SHARED.as_ptr());
        } else {
            let block =
                core::ptr::with_exposed_provenance_mut(SHARED_BLOCK.load(Ordering::Acquire));
            ExWaitForRundownProtectionReleaseCacheAware(block);
        }
    }
    RUN_DOWN.fetch_add(1, Ordering::AcqRel);
}

/// Start a thread that runs the shared object down, and wait until it
/// has closed the door: `closed` says so.
fn run_down(cache_aware: bool, closed: impl Fn() -> bool) -> Result<(), &'static str> {
    use crate::ke::thread;
    thread::create(
        waiter,
        usize::from(cache_aware),
        thread::NORMAL_PRIORITY,
        thread::ANYWHERE,
    )?;
    if !super::stress::until(super::stress::PROMPT_MS, closed) {
        return Err("a wait for run-down did not close the protection to new holders");
    }
    Ok(())
}

/// Holders are counted, nobody gets in once run-down has begun, and the
/// thread that runs an object down sleeps until the last holder lets
/// go; for the plain kind and the cache-aware one, allocated and in a
/// buffer of the caller's. Returns the words of the cache-aware block.
pub fn self_test() -> Result<u32, &'static str> {
    use super::stress;
    let before = crate::ke::thread::count();
    let reference = SHARED.as_ptr();
    RUN_DOWN.store(0, Ordering::Release);
    // SAFETY: the static reference; the blocks are allocated here and
    // freed after the threads that use them have ended.
    unsafe {
        SHARED.store(7, Ordering::Release);
        ExInitializeRundownProtection(reference);
        if ExAcquireRundownProtection(reference) != 1
            || ExAcquireRundownProtection(reference) != 1
            || SHARED.load(Ordering::Acquire) != 4
        {
            return Err("two holders are not counted two to the word");
        }
        ExReleaseRundownProtection(reference);
        run_down(false, || SHARED.load(Ordering::Acquire) & 1 != 0)?;
        if RUN_DOWN.load(Ordering::Acquire) != 0 || ExAcquireRundownProtection(reference) != 0 {
            return Err("run-down did not wait for a holder, or let a new one in");
        }
        ExReleaseRundownProtection(reference);
        if !stress::until(stress::PROMPT_MS, || RUN_DOWN.load(Ordering::Acquire) == 1) {
            return Err("the last release did not wake the thread running the object down");
        }
        stress::ended(before);
        // With nobody inside there is nothing to wait for.
        ExInitializeRundownProtection(reference);
        ExWaitForRundownProtectionRelease(reference);
        if SHARED.load(Ordering::Acquire) != 1 || ExAcquireRundownProtection(reference) != 0 {
            return Err("an object with no holders was not run down at once");
        }

        // The cache-aware kind, from the pool.
        let block = ExAllocateCacheAwareRundownProtection(0, u32::from_le_bytes(*b"Test"));
        if block.is_null() {
            return Err("no memory for a cache-aware block");
        }
        let words = (*block).Number;
        if words != smp::online_count() as u32 || (*block).RunRefs.addr() % 8 != 0 {
            ExFreeCacheAwareRundownProtection(block);
            return Err("a cache-aware block does not have a word a processor");
        }
        SHARED_BLOCK.store(block.expose_provenance(), Ordering::Release);
        let acquired = ExAcquireRundownProtectionCacheAware(block);
        let closed =
            || (0..words).all(|index| word_at(block, index).load(Ordering::Acquire) & 1 != 0);
        let result = run_down(true, closed).and_then(|()| {
            if acquired != 1
                || RUN_DOWN.load(Ordering::Acquire) != 1
                || ExAcquireRundownProtectionCacheAware(block) != 0
            {
                return Err("cache-aware run-down did not wait for a holder, or let one in");
            }
            ExReleaseRundownProtectionCacheAware(block);
            if !stress::until(stress::PROMPT_MS, || RUN_DOWN.load(Ordering::Acquire) == 2) {
                return Err("the last cache-aware release did not wake the thread running down");
            }
            Ok(())
        });
        stress::ended(before);
        if result.is_ok() {
            ExReInitializeRundownProtectionCacheAware(block);
        }
        let again = ExAcquireRundownProtectionCacheAware(block);
        if again == 1 {
            ExReleaseRundownProtectionCacheAware(block);
        }
        ExFreeCacheAwareRundownProtection(block);
        result?;
        if again != 1 {
            return Err("a cache-aware block let nobody in after it was initialised again");
        }

        // And in memory of the caller's.
        let size = ExSizeOfRundownProtectionCacheAware();
        let buffer = pool::alloc(size, u32::from_le_bytes(*b"Test"));
        if buffer.is_null() {
            return Err("no memory for a caller's cache-aware block");
        }
        let own = buffer.cast::<EX_RUNDOWN_REF_CACHE_AWARE>();
        ExInitializeRundownProtectionCacheAware(own, size);
        let last = (*own)
            .RunRefs
            .byte_add(((*own).Number as usize - 1) * (*own).RunRefSize as usize);
        let fits = (*own).RunRefs.addr() >= buffer.addr() + rundown::CACHE_AWARE_HEADER
            && last.addr() + 8 <= buffer.addr() + size;
        let works = ExAcquireRundownProtectionCacheAware(own) == 1;
        if works {
            ExReleaseRundownProtectionCacheAware(own);
        }
        ExWaitForRundownProtectionReleaseCacheAware(own);
        let shut = ExAcquireRundownProtectionCacheAware(own) == 0;
        let marked = (*own).PoolToFree.addr() == NOT_FROM_POOL && (*own).Number == words;
        pool::ExFreePool(buffer.cast());
        if !(fits && works && shut && marked) {
            return Err("a cache-aware block in the caller's buffer is not laid out or run down");
        }
        Ok(words)
    }
}
