//! The [reader/writer spin lock](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/reader-writer-spin-locks)
//! (`EX_SPIN_LOCK`) and the lists a driver guards with a spin lock of
//! its own (`ExInterlocked...List`).
//!
//! An `EX_SPIN_LOCK` is a `LONG` the driver owns, with Windows' bits
//! (`nk_ex::spinlock`); NK changes it only by single atomic operations
//! through the driver's pointer and keeps nothing about it. Nobody
//! queues: readers and writers spin, a writer that has claimed the word
//! keeping new readers out while those inside leave.
//!
//! The interlocked list routines take the driver's `KSPIN_LOCK` with
//! the IRQL at `HIGH_LEVEL`, where Windows turns interrupts off: either
//! way nothing on the processor can come between, so the routines may
//! be called at any IRQL, and the lock must not be one the driver also
//! takes with the plain spin-lock routines.

#![allow(non_snake_case)]

use crate::ke::{irql, kspin};
use core::sync::atomic::{AtomicU32, Ordering};
use nk_ex::spinlock;
use nk_ntabi::ex::EX_SPIN_LOCK;
use nk_ntabi::ke::{KIRQL, KSPIN_LOCK, LIST_ENTRY, SINGLE_LIST_ENTRY};

/// The word of a driver's lock.
///
/// # Safety
/// `lock` points to a live, aligned `EX_SPIN_LOCK`.
unsafe fn word<'a>(lock: *mut EX_SPIN_LOCK) -> &'a AtomicU32 {
    // SAFETY: per the contract; an atomic view is how a word that other
    // processors and the driver also touch must be accessed.
    unsafe { AtomicU32::from_ptr(lock.cast()) }
}

/// Leave the note that somebody is spinning, and spin once.
fn spin(word: &AtomicU32, seen: u32) {
    if let Some(noted) = spinlock::note_contended(seen) {
        // Lost to another change, the note is left for the next turn.
        let _ = word.compare_exchange_weak(seen, noted, Ordering::Relaxed, Ordering::Relaxed);
    }
    core::hint::spin_loop();
}

fn enter_shared(word: &AtomicU32) {
    loop {
        let old = word.load(Ordering::Relaxed);
        match spinlock::enter_shared(old) {
            Some(new) => {
                if word
                    .compare_exchange_weak(old, new, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
                {
                    return;
                }
            }
            None => spin(word, old),
        }
    }
}

fn enter_exclusive(word: &AtomicU32) {
    // Claim the word against other writers, then wait out the readers.
    loop {
        let old = word.fetch_or(spinlock::EXCLUSIVE, Ordering::Acquire);
        if old & spinlock::EXCLUSIVE == 0 {
            break;
        }
        spin(word, old);
    }
    loop {
        let now = word.load(Ordering::Acquire);
        if spinlock::exclusive_alone(now) {
            return;
        }
        spin(word, now);
    }
}

fn leave_shared(word: &AtomicU32) {
    word.fetch_and(!spinlock::CONTENDED, Ordering::Relaxed);
    word.fetch_sub(1, Ordering::Release);
}

/// [`ExAcquireSpinLockSharedAtDpcLevel`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquirespinlockshareddpclevel).
///
/// # Safety
/// `lock` points to an initialised `EX_SPIN_LOCK`; the caller is at
/// `DISPATCH_LEVEL` or above.
pub unsafe extern "C" fn ExAcquireSpinLockSharedAtDpcLevel(lock: *mut EX_SPIN_LOCK) {
    // SAFETY: per the contract.
    enter_shared(unsafe { word(lock) });
}

/// [`ExReleaseSpinLockSharedFromDpcLevel`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exreleasespinlocksharedfromdpclevel).
///
/// # Safety
/// The caller holds `lock` shared.
pub unsafe extern "C" fn ExReleaseSpinLockSharedFromDpcLevel(lock: *mut EX_SPIN_LOCK) {
    // SAFETY: per the contract.
    leave_shared(unsafe { word(lock) });
}

/// [`ExAcquireSpinLockExclusiveAtDpcLevel`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquirespinlockexclusiveatdpclevel).
///
/// # Safety
/// As [`ExAcquireSpinLockSharedAtDpcLevel`].
pub unsafe extern "C" fn ExAcquireSpinLockExclusiveAtDpcLevel(lock: *mut EX_SPIN_LOCK) {
    // SAFETY: per the contract.
    enter_exclusive(unsafe { word(lock) });
}

/// [`ExReleaseSpinLockExclusiveFromDpcLevel`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exreleasespinlockexclusivefromdpclevel).
///
/// # Safety
/// The caller holds `lock` exclusive.
pub unsafe extern "C" fn ExReleaseSpinLockExclusiveFromDpcLevel(lock: *mut EX_SPIN_LOCK) {
    // SAFETY: per the contract.
    unsafe { word(lock) }.store(0, Ordering::Release);
}

/// [`ExAcquireSpinLockShared`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquirespinlockshared):
/// raise to `DISPATCH_LEVEL` and take the lock shared. Returns the
/// previous IRQL.
///
/// # Safety
/// `lock` points to an initialised `EX_SPIN_LOCK`.
pub unsafe extern "C" fn ExAcquireSpinLockShared(lock: *mut EX_SPIN_LOCK) -> KIRQL {
    let old = kspin::KfRaiseIrql(irql::DISPATCH_LEVEL);
    // SAFETY: per the contract.
    enter_shared(unsafe { word(lock) });
    old
}

/// [`ExReleaseSpinLockShared`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exreleasespinlockshared).
///
/// # Safety
/// The caller holds `lock` shared, taken with the routine above.
pub unsafe extern "C" fn ExReleaseSpinLockShared(lock: *mut EX_SPIN_LOCK, old_irql: KIRQL) {
    // SAFETY: per the contract.
    leave_shared(unsafe { word(lock) });
    kspin::KeLowerIrql(old_irql);
}

/// [`ExAcquireSpinLockExclusive`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquirespinlockexclusive):
/// raise to `DISPATCH_LEVEL` and take the lock for the caller alone.
/// Returns the previous IRQL.
///
/// # Safety
/// `lock` points to an initialised `EX_SPIN_LOCK`.
pub unsafe extern "C" fn ExAcquireSpinLockExclusive(lock: *mut EX_SPIN_LOCK) -> KIRQL {
    let old = kspin::KfRaiseIrql(irql::DISPATCH_LEVEL);
    // SAFETY: per the contract.
    enter_exclusive(unsafe { word(lock) });
    old
}

/// [`ExReleaseSpinLockExclusive`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exreleasespinlockexclusive).
///
/// # Safety
/// The caller holds `lock` exclusive, taken with the routine above.
pub unsafe extern "C" fn ExReleaseSpinLockExclusive(lock: *mut EX_SPIN_LOCK, old_irql: KIRQL) {
    // SAFETY: per the contract.
    unsafe { word(lock) }.store(0, Ordering::Release);
    kspin::KeLowerIrql(old_irql);
}

/// Run `change` with the driver's lock held and nothing able to
/// interrupt.
///
/// # Safety
/// `lock` points to an initialised `KSPIN_LOCK`.
unsafe fn interlocked<R>(lock: *mut KSPIN_LOCK, change: impl FnOnce() -> R) -> R {
    let old = irql::raise(irql::HIGH_LEVEL);
    // SAFETY: per the contract.
    unsafe { kspin::KeAcquireSpinLockAtDpcLevel(lock) };
    let result = change();
    // SAFETY: taken above.
    unsafe { kspin::KeReleaseSpinLockFromDpcLevel(lock) };
    irql::lower(old);
    result
}

/// [`ExInterlockedInsertHeadList`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinterlockedinsertheadlist):
/// put `entry` first. Returns the entry that was first, or null if the
/// list was empty.
///
/// # Safety
/// `head` is an initialised list guarded by `lock`, and `entry` is
/// writable and on no list.
pub unsafe extern "C" fn ExInterlockedInsertHeadList(
    head: *mut LIST_ENTRY,
    entry: *mut LIST_ENTRY,
    lock: *mut KSPIN_LOCK,
) -> *mut LIST_ENTRY {
    // SAFETY: per the contract; the list is changed with its lock held.
    unsafe {
        interlocked(lock, || {
            let first = (&raw const (*head).Flink).read();
            entry.write(LIST_ENTRY {
                Flink: first,
                Blink: head,
            });
            (&raw mut (*first).Blink).write(entry);
            (&raw mut (*head).Flink).write(entry);
            if first == head {
                core::ptr::null_mut()
            } else {
                first
            }
        })
    }
}

/// [`ExInterlockedInsertTailList`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinterlockedinserttaillist):
/// put `entry` last. Returns the entry that was last, or null if the
/// list was empty.
///
/// # Safety
/// As [`ExInterlockedInsertHeadList`].
pub unsafe extern "C" fn ExInterlockedInsertTailList(
    head: *mut LIST_ENTRY,
    entry: *mut LIST_ENTRY,
    lock: *mut KSPIN_LOCK,
) -> *mut LIST_ENTRY {
    // SAFETY: per the contract; the list is changed with its lock held.
    unsafe {
        interlocked(lock, || {
            let last = (&raw const (*head).Blink).read();
            entry.write(LIST_ENTRY {
                Flink: head,
                Blink: last,
            });
            (&raw mut (*last).Flink).write(entry);
            (&raw mut (*head).Blink).write(entry);
            if last == head {
                core::ptr::null_mut()
            } else {
                last
            }
        })
    }
}

/// [`ExInterlockedRemoveHeadList`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinterlockedremoveheadlist):
/// take the first entry off the list. Null if the list is empty.
///
/// # Safety
/// `head` is an initialised list guarded by `lock`.
pub unsafe extern "C" fn ExInterlockedRemoveHeadList(
    head: *mut LIST_ENTRY,
    lock: *mut KSPIN_LOCK,
) -> *mut LIST_ENTRY {
    // SAFETY: per the contract; the list is changed with its lock held.
    unsafe {
        interlocked(lock, || {
            let first = (&raw const (*head).Flink).read();
            if first == head {
                return core::ptr::null_mut();
            }
            let second = (&raw const (*first).Flink).read();
            (&raw mut (*head).Flink).write(second);
            (&raw mut (*second).Blink).write(head);
            first
        })
    }
}

/// [`ExInterlockedPushEntryList`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinterlockedpushentrylist):
/// put `entry` first on a singly linked list. Returns the entry that
/// was first, or null.
///
/// # Safety
/// `head` is a singly linked list guarded by `lock`, and `entry` is
/// writable and on no list.
pub unsafe extern "C" fn ExInterlockedPushEntryList(
    head: *mut SINGLE_LIST_ENTRY,
    entry: *mut SINGLE_LIST_ENTRY,
    lock: *mut KSPIN_LOCK,
) -> *mut SINGLE_LIST_ENTRY {
    // SAFETY: per the contract; the list is changed with its lock held.
    unsafe {
        interlocked(lock, || {
            let first = (&raw const (*head).Next).read();
            (&raw mut (*entry).Next).write(first);
            (&raw mut (*head).Next).write(entry);
            first
        })
    }
}

/// [`ExInterlockedPopEntryList`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinterlockedpopentrylist):
/// take the first entry off a singly linked list. Null if it is empty.
///
/// # Safety
/// `head` is a singly linked list guarded by `lock`.
pub unsafe extern "C" fn ExInterlockedPopEntryList(
    head: *mut SINGLE_LIST_ENTRY,
    lock: *mut KSPIN_LOCK,
) -> *mut SINGLE_LIST_ENTRY {
    // SAFETY: per the contract; the list is changed with its lock held.
    unsafe {
        interlocked(lock, || {
            let first = (&raw const (*head).Next).read();
            if !first.is_null() {
                (&raw mut (*head).Next).write((&raw const (*first).Next).read());
            }
            first
        })
    }
}

/// The word of a reader/writer spin lock as readers and a writer come
/// and go, with the IRQL the routines leave; and the lists guarded by a
/// spin lock, the sequenced list's first entry among them.
pub fn self_test() -> Result<(), &'static str> {
    use nk_ntabi::ex::{SLIST_ENTRY, SLIST_HEADER};
    let mut lock: EX_SPIN_LOCK = 0;
    let word = &raw mut lock;
    let level = irql::current();
    // SAFETY: every lock, list and entry is a local, used by this thread
    // alone; each lock taken is released before the next step.
    unsafe {
        let old = ExAcquireSpinLockShared(word);
        ExAcquireSpinLockSharedAtDpcLevel(word);
        let inside = (old, irql::current(), word.read());
        ExReleaseSpinLockSharedFromDpcLevel(word);
        let one = word.read();
        ExReleaseSpinLockShared(word, old);
        if inside != (level, irql::DISPATCH_LEVEL, 2) || one != 1 || word.read() != 0 {
            return Err("two readers are not a count of two at DISPATCH_LEVEL");
        }
        if irql::current() != level {
            return Err("releasing a reader/writer spin lock did not restore the IRQL");
        }
        let old = ExAcquireSpinLockExclusive(word);
        let inside = (old, irql::current(), word.read() as u32);
        ExReleaseSpinLockExclusive(word, old);
        if inside != (level, irql::DISPATCH_LEVEL, spinlock::EXCLUSIVE) || word.read() != 0 {
            return Err("a writer is not bit 31 of the word at DISPATCH_LEVEL");
        }
        ExAcquireSpinLockExclusiveAtDpcLevel(word);
        let held = word.read() as u32;
        ExReleaseSpinLockExclusiveFromDpcLevel(word);
        if held != spinlock::EXCLUSIVE || word.read() != 0 || irql::current() != level {
            return Err("the routines for DISPATCH_LEVEL moved the IRQL or miskept the word");
        }

        // A doubly linked list under a spin lock.
        let mut guard: KSPIN_LOCK = 0;
        let guard = &raw mut guard;
        let mut head = core::mem::zeroed::<LIST_ENTRY>();
        let mut entries = core::mem::zeroed::<[LIST_ENTRY; 3]>();
        let head = &raw mut head;
        let [a, b, c] = [0, 1, 2].map(|index| (&raw mut entries).cast::<LIST_ENTRY>().add(index));
        head.write(LIST_ENTRY {
            Flink: head,
            Blink: head,
        });
        let none = core::ptr::null_mut();
        let was = [
            ExInterlockedInsertHeadList(head, a, guard),
            ExInterlockedInsertTailList(head, b, guard),
            ExInterlockedInsertHeadList(head, c, guard),
        ];
        let taken = [
            ExInterlockedRemoveHeadList(head, guard),
            ExInterlockedRemoveHeadList(head, guard),
            ExInterlockedRemoveHeadList(head, guard),
            ExInterlockedRemoveHeadList(head, guard),
        ];
        if was != [none, a, a] || taken != [c, a, b, none] || (*head).Flink != head {
            return Err("the interlocked list routines linked or returned the wrong entries");
        }
        let empty = ExInterlockedInsertTailList(head, a, guard);
        if !empty.is_null() || ExInterlockedRemoveHeadList(head, guard) != a {
            return Err("an insert at the tail of an empty list did not return null");
        }
        if guard.read() != 0 || irql::current() != level {
            return Err("an interlocked list routine left its lock held or the IRQL raised");
        }

        // A singly linked one.
        let mut stack = core::mem::zeroed::<SINGLE_LIST_ENTRY>();
        let mut links = core::mem::zeroed::<[SINGLE_LIST_ENTRY; 2]>();
        let stack = &raw mut stack;
        let [x, y] = [0, 1].map(|index| (&raw mut links).cast::<SINGLE_LIST_ENTRY>().add(index));
        let none = core::ptr::null_mut();
        let was = [
            ExInterlockedPushEntryList(stack, x, guard),
            ExInterlockedPushEntryList(stack, y, guard),
        ];
        let taken = [
            ExInterlockedPopEntryList(stack, guard),
            ExInterlockedPopEntryList(stack, guard),
            ExInterlockedPopEntryList(stack, guard),
        ];
        if was != [none, x] || taken != [y, x, none] {
            return Err("the interlocked push and pop are not last in, first out");
        }

        // A sequenced list's first entry, without taking it.
        let mut header = core::mem::zeroed::<SLIST_HEADER>();
        let mut entry = core::mem::zeroed::<SLIST_ENTRY>();
        let (header, entry) = (&raw mut header, &raw mut entry);
        super::slist::InitializeSListHead(header);
        let first = super::slist::FirstEntrySList(header);
        super::slist::ExpInterlockedPushEntrySList(header, entry);
        let then = super::slist::FirstEntrySList(header);
        let depth = super::slist::ExQueryDepthSList(header);
        if !first.is_null() || then != entry || depth != 1 {
            return Err("FirstEntrySList is not the entry a pop would give");
        }

        // `ExAllocatePool` is the pool under the tag `None`.
        let block = crate::mm::pool::ExAllocatePool(0, 40);
        let labelled = crate::mm::pool::info(block.cast());
        crate::mm::pool::ExFreePool(block);
        if labelled.map(|(_, tag)| tag) != Some(u32::from_le_bytes(*b"None")) {
            return Err("ExAllocatePool did not allocate under the tag None");
        }
    }
    let (mut longest, mut shortest, mut current) = (0u32, 0u32, 0u32);
    // SAFETY: three locals.
    unsafe {
        crate::ke::time::ExQueryTimerResolution(
            &raw mut longest,
            &raw mut shortest,
            &raw mut current,
        )
    };
    let tick = crate::ke::time::KeQueryTimeIncrement();
    if [longest, shortest, current] != [tick; 3] || tick == 0 {
        return Err("ExQueryTimerResolution is not the clock's tick");
    }
    Ok(())
}
