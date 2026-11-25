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
use nk_ntabi::ke::{KIRQL, KLOCK_QUEUE_HANDLE, KSPIN_LOCK};

/// The word of a driver's lock.
///
/// # Safety
/// `lock` points to a live, aligned `KSPIN_LOCK`.
unsafe fn word<'a>(lock: *mut KSPIN_LOCK) -> &'a AtomicUsize {
    // SAFETY: per the contract; an atomic view is how a word that other
    // processors and the driver also touch must be accessed.
    unsafe { AtomicUsize::from_ptr(lock) }
}

/// Spin until the lock is taken.
///
/// # Safety
/// As `word`.
unsafe fn acquire(lock: *mut KSPIN_LOCK) {
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
fn set_irql(new: KIRQL, raising: bool) -> KIRQL {
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

/// [`KeAcquireInStackQueuedSpinLock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquireinstackqueuedspinlock).
///
/// The lock is taken and the handle filled in as Windows fills it, but
/// waiters are not queued: they contend as for an ordinary spin lock, so
/// the first-come order Windows gives is absent.
///
/// # Safety
/// `lock` points to an initialised `KSPIN_LOCK` and `handle` to storage
/// the caller keeps until the matching release.
pub unsafe extern "C" fn KeAcquireInStackQueuedSpinLock(
    lock: *mut KSPIN_LOCK,
    handle: *mut KLOCK_QUEUE_HANDLE,
) {
    let old = set_irql(irql::DISPATCH_LEVEL, true);
    // SAFETY: per the contract; fields are written one by one through
    // the raw pointer, never through a reference to driver memory.
    unsafe {
        (&raw mut (*handle).LockQueue.Next).write(core::ptr::null_mut());
        (&raw mut (*handle).LockQueue.Lock).write(lock);
        (&raw mut (*handle).OldIrql).write(old);
        acquire(lock);
    }
}

/// [`KeReleaseInStackQueuedSpinLock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereleaseinstackqueuedspinlock).
///
/// # Safety
/// `handle` was filled by the matching acquire and the lock is held.
pub unsafe extern "C" fn KeReleaseInStackQueuedSpinLock(handle: *mut KLOCK_QUEUE_HANDLE) {
    // SAFETY: per the contract.
    let (lock, old) = unsafe {
        (
            (&raw const (*handle).LockQueue.Lock).read(),
            (&raw const (*handle).OldIrql).read(),
        )
    };
    // SAFETY: the handle names the lock the caller holds.
    unsafe { word(lock) }.store(0, Ordering::Release);
    set_irql(old, false);
}
