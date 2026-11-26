//! The IRQL and spin-lock routines drivers call.
//!
//! These are Windows' contracts, not NK's own locking (`spinlock.rs`).
//! A `KSPIN_LOCK` is one pointer-sized word the driver owns: zero when
//! free. NK never keeps a reference into it; every access is one atomic
//! operation through the driver's pointer.
//!
//! Misuse by a driver is treated as Windows treats it. Where a normal
//! Windows build would carry on (raising the IRQL to a lower level, say),
//! NK carries on too and reports the misuse on the console (`NK-VERIFY`),
//! which fails a test run without changing what the driver sees.

#![allow(non_snake_case)]

use super::irql;
use core::sync::atomic::{AtomicUsize, Ordering};
use nk_ntabi::ke::{KIRQL, KLOCK_QUEUE_HANDLE, KSPIN_LOCK, KSPIN_LOCK_QUEUE};

/// The word of a driver's lock.
///
/// # Safety
/// `lock` points to a live, aligned `KSPIN_LOCK`.
pub(super) unsafe fn word<'a>(lock: *mut KSPIN_LOCK) -> &'a AtomicUsize {
    // SAFETY: per the contract; an atomic view is how a word that other
    // processors and the driver also touch must be accessed.
    unsafe { AtomicUsize::from_ptr(lock) }
}

/// Spin until the lock is taken.
///
/// # Safety
/// As `word`.
pub(super) unsafe fn acquire(lock: *mut KSPIN_LOCK) {
    // SAFETY: per the contract.
    let word = unsafe { word(lock) };
    while word
        .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }
}

/// Set the IRQL for a driver. A driver asking for a move in the wrong
/// direction gets it, as on Windows, and a report.
pub(super) fn set_irql(new: KIRQL, raising: bool) -> KIRQL {
    let old = irql::current();
    if raising && new < old {
        crate::kd::verify(format_args!("IRQL raised from {old} down to {new}"));
    } else if !raising && new > old {
        crate::kd::verify(format_args!("IRQL lowered from {old} up to {new}"));
    }
    crate::arch::set_irql(new);
    old
}

/// [`KfRaiseIrql`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keraiseirql):
/// what `KeRaiseIrql` compiles to. Returns the previous level.
pub extern "C" fn KfRaiseIrql(new_irql: KIRQL) -> KIRQL {
    set_irql(new_irql, true)
}

/// [`KeLowerIrql`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kelowerirql).
pub extern "C" fn KeLowerIrql(new_irql: KIRQL) {
    set_irql(new_irql, false);
}

/// `KfLowerIrql`: the name arm64 drivers import `KeLowerIrql` under.
pub extern "C" fn KfLowerIrql(new_irql: KIRQL) {
    set_irql(new_irql, false);
}

/// [`KeGetCurrentIrql`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kegetcurrentirql).
pub extern "C" fn KeGetCurrentIrql() -> KIRQL {
    irql::current()
}

/// [`KeInitializeSpinLock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keinitializespinlock).
///
/// # Safety
/// `lock` points to a `KSPIN_LOCK` the caller owns.
pub unsafe extern "C" fn KeInitializeSpinLock(lock: *mut KSPIN_LOCK) {
    // SAFETY: per the contract.
    unsafe { word(lock) }.store(0, Ordering::Release);
}

/// [`KeAcquireSpinLockRaiseToDpc`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquirespinlockraisetodpc):
/// what `KeAcquireSpinLock` compiles to. Returns the previous IRQL.
///
/// # Safety
/// `lock` points to an initialised `KSPIN_LOCK`.
pub unsafe extern "C" fn KeAcquireSpinLockRaiseToDpc(lock: *mut KSPIN_LOCK) -> KIRQL {
    let old = set_irql(irql::DISPATCH_LEVEL, true);
    // SAFETY: per the contract.
    unsafe { acquire(lock) };
    old
}

/// [`KeReleaseSpinLock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereleasespinlock).
///
/// # Safety
/// `lock` is held by the caller, taken with the routine above.
pub unsafe extern "C" fn KeReleaseSpinLock(lock: *mut KSPIN_LOCK, new_irql: KIRQL) {
    // SAFETY: per the contract.
    unsafe { word(lock) }.store(0, Ordering::Release);
    set_irql(new_irql, false);
}

/// [`KeAcquireSpinLockAtDpcLevel`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquirespinlockatdpclevel).
///
/// # Safety
/// `lock` points to an initialised `KSPIN_LOCK`; the caller is at
/// DISPATCH_LEVEL or above.
pub unsafe extern "C" fn KeAcquireSpinLockAtDpcLevel(lock: *mut KSPIN_LOCK) {
    // SAFETY: per the contract.
    unsafe { acquire(lock) };
}

/// [`KeReleaseSpinLockFromDpcLevel`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereleasespinlockfromdpclevel).
///
/// # Safety
/// `lock` is held by the caller.
pub unsafe extern "C" fn KeReleaseSpinLockFromDpcLevel(lock: *mut KSPIN_LOCK) {
    // SAFETY: per the contract.
    unsafe { word(lock) }.store(0, Ordering::Release);
}

/// [`KeTryToAcquireSpinLockAtDpcLevel`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ketrytoacquirespinlockatdpclevel):
/// take the lock if it is free; nonzero if taken.
///
/// # Safety
/// As `KeAcquireSpinLockAtDpcLevel`.
pub unsafe extern "C" fn KeTryToAcquireSpinLockAtDpcLevel(lock: *mut KSPIN_LOCK) -> u8 {
    // SAFETY: per the contract.
    let taken = unsafe { word(lock) }
        .compare_exchange(0, 1, Ordering::Acquire, Ordering::Relaxed)
        .is_ok();
    u8::from(taken)
}

/// Bit 0 of a waiter's `LockQueue.Lock`: it is still waiting. The
/// holder before it clears the bit to hand the lock on.
const QUEUE_WAIT: usize = 1;

/// A field of a waiter's place in the queue, as an atomic.
///
/// # Safety
/// `field` is a pointer-sized field of a live `KSPIN_LOCK_QUEUE`.
unsafe fn queue_field<'a, T>(field: *mut *mut T) -> &'a AtomicUsize {
    // SAFETY: per the contract; other processors read and write it.
    unsafe { AtomicUsize::from_ptr(field.cast()) }
}

/// Take a queued spin lock: join the queue at its tail and spin until
/// the holder before hands the lock on. The lock's word names the last
/// in the queue, as on Windows, and each waiter the one behind it.
///
/// # Safety
/// `lock` points to an initialised `KSPIN_LOCK` used only through the
/// queued routines, and `handle` to storage the caller keeps until the
/// matching release; the caller is at `DISPATCH_LEVEL` or above.
unsafe fn acquire_queued(lock: *mut KSPIN_LOCK, handle: *mut KLOCK_QUEUE_HANDLE) {
    // SAFETY: per the contract; the handle's fields are written through
    // the raw pointer, and read by the neighbours in the queue through
    // atomics.
    unsafe {
        let queue = &raw mut (*handle).LockQueue;
        let (next, mine) = (
            queue_field(&raw mut (*queue).Next),
            queue_field(&raw mut (*queue).Lock),
        );
        next.store(0, Ordering::Relaxed);
        mine.store(lock.addr(), Ordering::Relaxed);
        let before = word(lock).swap(queue.addr(), Ordering::AcqRel);
        if before != 0 {
            // Waiting, and only then findable by the one before.
            mine.store(lock.addr() | QUEUE_WAIT, Ordering::Release);
            let before = before as *mut KSPIN_LOCK_QUEUE;
            queue_field(&raw mut (*before).Next).store(queue.addr(), Ordering::Release);
            while mine.load(Ordering::Acquire) & QUEUE_WAIT != 0 {
                core::hint::spin_loop();
            }
        }
    }
}

/// Give a queued spin lock to the next in the queue, or free it.
///
/// # Safety
/// `handle` was filled by the matching acquire and the lock is held.
unsafe fn release_queued(handle: *mut KLOCK_QUEUE_HANDLE) {
    // SAFETY: per the contract.
    unsafe {
        let queue = &raw mut (*handle).LockQueue;
        let next = queue_field(&raw mut (*queue).Next);
        let lock = (queue_field(&raw mut (*queue).Lock).load(Ordering::Relaxed) & !QUEUE_WAIT)
            as *mut KSPIN_LOCK;
        let mut behind = next.load(Ordering::Acquire);
        if behind == 0 {
            // Nobody behind, unless somebody is just joining: then the
            // word no longer names this handle, and the joiner is about
            // to say who it is.
            if word(lock)
                .compare_exchange(queue.addr(), 0, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
            loop {
                behind = next.load(Ordering::Acquire);
                if behind != 0 {
                    break;
                }
                core::hint::spin_loop();
            }
        }
        let behind = behind as *mut KSPIN_LOCK_QUEUE;
        queue_field(&raw mut (*behind).Lock).fetch_and(!QUEUE_WAIT, Ordering::Release);
    }
}

/// [`KeAcquireInStackQueuedSpinLock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquireinstackqueuedspinlock):
/// raise to `DISPATCH_LEVEL` and take the lock, waiting in line: the
/// lock goes to its waiters in the order they came.
///
/// # Safety
/// `lock` points to an initialised `KSPIN_LOCK` used only through the
/// queued routines, and `handle` to storage the caller keeps until the
/// matching release.
pub unsafe extern "C" fn KeAcquireInStackQueuedSpinLock(
    lock: *mut KSPIN_LOCK,
    handle: *mut KLOCK_QUEUE_HANDLE,
) {
    let old = set_irql(irql::DISPATCH_LEVEL, true);
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*handle).OldIrql).write(old);
        acquire_queued(lock, handle);
    }
}

/// [`KeReleaseInStackQueuedSpinLock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereleaseinstackqueuedspinlock).
///
/// # Safety
/// `handle` was filled by the matching acquire and the lock is held.
pub unsafe extern "C" fn KeReleaseInStackQueuedSpinLock(handle: *mut KLOCK_QUEUE_HANDLE) {
    // SAFETY: per the contract. The level is read first: the handle is
    // the caller's again once the lock is passed on.
    unsafe {
        let old = (&raw const (*handle).OldIrql).read();
        release_queued(handle);
        set_irql(old, false);
    }
}

/// [`KeAcquireInStackQueuedSpinLockAtDpcLevel`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquireinstackqueuedspinlockatdpclevel):
/// take the lock without touching the IRQL.
///
/// # Safety
/// As [`KeAcquireInStackQueuedSpinLock`]; the caller is at
/// `DISPATCH_LEVEL` or above.
pub unsafe extern "C" fn KeAcquireInStackQueuedSpinLockAtDpcLevel(
    lock: *mut KSPIN_LOCK,
    handle: *mut KLOCK_QUEUE_HANDLE,
) {
    // SAFETY: per the contract.
    unsafe { acquire_queued(lock, handle) };
}

/// [`KeReleaseInStackQueuedSpinLockFromDpcLevel`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereleaseinstackqueuedspinlockfromdpclevel).
///
/// # Safety
/// `handle` was filled by the matching acquire and the lock is held.
pub unsafe extern "C" fn KeReleaseInStackQueuedSpinLockFromDpcLevel(
    handle: *mut KLOCK_QUEUE_HANDLE,
) {
    // SAFETY: per the contract.
    unsafe { release_queued(handle) };
}

/// [`KeAcquireInStackQueuedSpinLockForDpc`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquireinstackqueuedspinlockfordpc):
/// take the lock from a routine that may run as an ordinary DPC or, on
/// Windows, as a threaded one below `DISPATCH_LEVEL`: the IRQL is
/// raised if it is lower, and the handle remembers what it was.
///
/// # Safety
/// As [`KeAcquireInStackQueuedSpinLock`].
pub unsafe extern "C" fn KeAcquireInStackQueuedSpinLockForDpc(
    lock: *mut KSPIN_LOCK,
    handle: *mut KLOCK_QUEUE_HANDLE,
) {
    let old = irql::current();
    if old < irql::DISPATCH_LEVEL {
        crate::arch::set_irql(irql::DISPATCH_LEVEL);
    }
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*handle).OldIrql).write(old);
        acquire_queued(lock, handle);
    }
}

/// [`KeReleaseInStackQueuedSpinLockForDpc`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereleaseinstackqueuedspinlockfordpc).
///
/// # Safety
/// `handle` was filled by the matching acquire and the lock is held.
pub unsafe extern "C" fn KeReleaseInStackQueuedSpinLockForDpc(handle: *mut KLOCK_QUEUE_HANDLE) {
    // SAFETY: per the contract.
    unsafe {
        let old = (&raw const (*handle).OldIrql).read();
        release_queued(handle);
        if old < irql::DISPATCH_LEVEL {
            crate::arch::set_irql(old);
        }
    }
}

/// [`KeGetEffectiveIrql`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kegeteffectiveirql):
/// the IRQL. Windows answers `HIGH_LEVEL` instead while the processor
/// has interrupts turned off below that level; NK turns them off only
/// by raising the IRQL, so the level is the answer.
pub extern "C" fn KeGetEffectiveIrql() -> KIRQL {
    irql::current()
}

/// A queued spin lock's word names its holder's handle while held and
/// is zero when free; the routines move the IRQL as they say; and a
/// second handle queued behind the first is handed the lock by its
/// release. Returns the handles used.
pub fn queued_test() -> Result<u32, &'static str> {
    let mut lock: KSPIN_LOCK = 0;
    let lock = &raw mut lock;
    let level = irql::current();
    // SAFETY: the lock and the handles are this frame's, used by this
    // thread alone; a zeroed handle is a valid one to fill.
    unsafe {
        let mut handles = core::mem::zeroed::<[KLOCK_QUEUE_HANDLE; 2]>();
        let first = (&raw mut handles).cast::<KLOCK_QUEUE_HANDLE>();
        let second = first.add(1);
        KeAcquireInStackQueuedSpinLock(lock, first);
        let held = (lock.read(), irql::current(), (*first).OldIrql);
        KeReleaseInStackQueuedSpinLock(first);
        if held != (first.addr(), irql::DISPATCH_LEVEL, level)
            || lock.read() != 0
            || irql::current() != level
        {
            return Err("a queued spin lock held alone is not its handle at DISPATCH_LEVEL");
        }
        KeAcquireInStackQueuedSpinLockForDpc(lock, first);
        let raised = irql::current();
        KeReleaseInStackQueuedSpinLockForDpc(first);
        if raised != irql::DISPATCH_LEVEL || irql::current() != level || lock.read() != 0 {
            return Err("the queued lock for a DPC did not raise and restore the IRQL");
        }
        // A waiter, as another processor would leave it: at the tail,
        // marked waiting, and linked behind the holder.
        KeAcquireInStackQueuedSpinLockAtDpcLevel(lock, first);
        let queue = &raw mut (*second).LockQueue;
        (&raw mut (*queue).Next).write(core::ptr::null_mut());
        (&raw mut (*queue).Lock).write(lock.map_addr(|address| address | QUEUE_WAIT));
        lock.write(queue.addr());
        (&raw mut (*first).LockQueue.Next).write(queue.cast());
        KeReleaseInStackQueuedSpinLockFromDpcLevel(first);
        if (*queue).Lock != lock || lock.read() != queue.addr() {
            return Err("releasing a queued spin lock did not hand it to the waiter behind");
        }
        KeReleaseInStackQueuedSpinLockFromDpcLevel(second);
        if lock.read() != 0 || irql::current() != level {
            return Err("the last holder's release did not free a queued spin lock");
        }
        if KeGetEffectiveIrql() != level {
            return Err("KeGetEffectiveIrql is not the IRQL");
        }
    }
    Ok(2)
}
