//! Mutexes, fast mutexes and critical regions.
//!
//! A mutex (`KMUTANT`) is a dispatcher object with an owner: it is
//! waited for like an event, its owner may take it again, and only its
//! owner may release it, as many times as it was taken. While a thread
//! holds one, kernel APCs are off for it; the thread's
//! `KernelApcDisable` says so, as it does inside a critical region.
//! A mutex's owner and its place in the owner's list of mutexes belong
//! to the mutex's own lock.
//!
//! A fast mutex is a counter and an event: taking a free one is one
//! atomic step, and only a contended one waits. Taking it raises the
//! IRQL to `APC_LEVEL`.
//!
//! NK queues no APCs yet, so "APCs disabled" is so far only what
//! `KeAreApcsDisabled` reports and what the IRQL shows.

#![allow(non_snake_case)]

use super::object::{self, ObjectLock};
use super::{irql, thread, wait};
use crate::arch;
use core::ffi::c_void;
use core::sync::atomic::{AtomicI16, AtomicI32, AtomicPtr, Ordering};
use nk_ntabi::ke::{DISPATCHER_HEADER, FAST_MUTEX, KMUTANT, LIST_ENTRY, MUTANT_OBJECT};
use nk_ntabi::pcr::APC_LEVEL;
use nk_ntabi::thread::{KERNEL_APC_DISABLE, MUTANT_LIST_HEAD};

/// A thread's count of reasons kernel APCs are off: negative while there
/// are any.
///
/// # Safety
/// `thread` is a live thread, and stays live for `'a`.
unsafe fn apc_disable<'a>(thread: *mut thread::Thread) -> &'a AtomicI16 {
    // SAFETY: per the contract; an aligned 16-bit field of the thread's
    // block. The thread itself changes it, and so does whoever hands it
    // a mutex while it sleeps.
    unsafe { AtomicI16::from_ptr(thread::object_field(thread, KERNEL_APC_DISABLE)) }
}

fn mutant_list(thread: *mut thread::Thread) -> *mut LIST_ENTRY {
    thread::object_field(thread, MUTANT_LIST_HEAD)
}

/// A new thread holds no mutexes.
///
/// # Safety
/// `thread` is a thread being created.
pub unsafe fn init_thread(thread: *mut thread::Thread) {
    let head = mutant_list(thread);
    // SAFETY: per the contract. An empty list points at itself.
    unsafe {
        head.write(LIST_ENTRY {
            Flink: head,
            Blink: head,
        });
    }
}

/// Abandon any user-mode (`ApcDisable == 0`) mutants still held by `thread`
/// on exit, and bugcheck if any kernel mutex (`ApcDisable != 0`, from
/// `KeInitializeMutex`) is still held — matching Windows' `KeRundownThread`.
///
/// # Safety
/// `thread` is a thread that has ended and not yet been freed.
pub unsafe fn check_none_held(thread: *mut thread::Thread) {
    let head = mutant_list(thread);
    // SAFETY: per the contract.
    unsafe {
        loop {
            let entry = (*head).Flink;
            if entry == head {
                break;
            }
            let mutant = entry
                .cast::<u8>()
                .sub(core::mem::offset_of!(KMUTANT, MutantListEntry))
                .cast::<KMUTANT>();
            if (&raw const (*mutant).ApcDisable).read() != 0 {
                crate::kd::bugcheck(format_args!(
                    "0x0000004E THREAD_TERMINATE_HELD_MUTEX: a thread ended holding a mutex"
                ));
            }
            let header = mutant.cast::<DISPATCHER_HEADER>();
            let woken = {
                let _lock = ObjectLock::take(header);
                let LIST_ENTRY { Flink, Blink } = (&raw const (*mutant).MutantListEntry).read();
                (&raw mut (*Blink).Flink).write(Flink);
                (&raw mut (*Flink).Blink).write(Blink);
                (&raw mut (*mutant).OwnerThread).write(core::ptr::null_mut());
                (&raw mut (*mutant).MutantFlags).write(1);
                object::signal(header).store(1, Ordering::Relaxed);
                object::satisfy(header)
            };
            woken.ready();
        }
    }
}

/// The thread that owns a mutex, or null.
///
/// # Safety
/// `mutant` is live and its lock is held.
pub unsafe fn owner(mutant: *mut KMUTANT) -> *mut thread::Thread {
    // SAFETY: per the contract.
    unsafe { (&raw const (*mutant).OwnerThread).read().cast() }
}

/// `thread` takes the mutex, for the first time or again.
///
/// # Safety
/// `mutant` is live and its lock is held; the mutex is free or `thread`
/// owns it; `thread` is the running thread or one the caller has
/// claimed.
pub unsafe fn taken(mutant: *mut KMUTANT, thread: *mut thread::Thread) {
    // SAFETY: per the contract. The owner's list is only changed under
    // the lock of a mutex that is entering or leaving it, by the owner
    // or on its behalf while it sleeps.
    unsafe {
        let state = object::signal(mutant.cast());
        if state.fetch_sub(1, Ordering::Relaxed) != 1 {
            // Its owner took it again.
            return;
        }
        (&raw mut (*mutant).OwnerThread).write(thread.cast());
        apc_disable(thread).fetch_sub(
            i16::from((&raw const (*mutant).ApcDisable).read()),
            Ordering::Relaxed,
        );
        let head = mutant_list(thread);
        let entry = &raw mut (*mutant).MutantListEntry;
        let last = (*head).Blink;
        entry.write(LIST_ENTRY {
            Flink: head,
            Blink: last,
        });
        (&raw mut (*last).Flink).write(entry);
        (&raw mut (*head).Blink).write(entry);
    }
}

/// [`KeInitializeMutex`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keinitializemutex).
///
/// # Safety
/// `mutex` points to writable storage for a `KMUTANT`.
pub unsafe extern "C" fn KeInitializeMutex(mutex: *mut KMUTANT, _level: u32) {
    // SAFETY: per the contract.
    unsafe {
        mutex.cast::<u8>().write_bytes(0, size_of::<KMUTANT>());
        let header = &raw mut (*mutex).Header;
        (&raw mut (*header).Type).write(MUTANT_OBJECT);
        (&raw mut (*header).SignalState).write(1);
        object::init_wait_list(header);
        (&raw mut (*mutex).ApcDisable).write(1);
    }
}

/// [`KeReleaseMutex`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereleasemutex).
/// Returns the signal state before. A release by a thread that does not
/// own the mutex raises `STATUS_MUTANT_NOT_OWNED` on Windows; NK has no
/// exceptions to raise yet, and an unhandled one stops Windows too.
///
/// # Safety
/// `mutex` is a live, initialised `KMUTANT`.
pub unsafe extern "C" fn KeReleaseMutex(mutex: *mut KMUTANT, _wait: u8) -> i32 {
    let me = thread::current();
    // SAFETY: per the contract.
    unsafe {
        let header = mutex.cast::<DISPATCHER_HEADER>();
        let mut released = 0;
        let (previous, woken) = {
            let _lock = ObjectLock::take(header);
            if owner(mutex) != me {
                crate::kd::bugcheck(format_args!(
                    "0x0000001E KMODE_EXCEPTION_NOT_HANDLED: STATUS_MUTANT_NOT_OWNED \
                     (a mutex released by a thread that does not own it)"
                ));
            }
            let previous = object::signal(header).fetch_add(1, Ordering::Relaxed);
            if previous != 0 {
                // Still held: its owner took it more than once.
                (previous, object::Woken::none())
            } else {
                (&raw mut (*mutex).OwnerThread).write(core::ptr::null_mut());
                let LIST_ENTRY { Flink, Blink } = (&raw const (*mutex).MutantListEntry).read();
                (&raw mut (*Blink).Flink).write(Flink);
                (&raw mut (*Flink).Blink).write(Blink);
                released = i16::from((&raw const (*mutex).ApcDisable).read());
                (previous, object::satisfy(header))
            }
        };
        woken.ready();
        // The owner's kernel APCs, held back while it held the mutex,
        // may run now: the counter is the thread's own, so it is given
        // back with the mutex's lock dropped.
        super::apc::kernel_disable_raised(released);
        previous
    }
}

/// Initialize a user-mode `KMUTANT` (`KeInitializeMutant`: `ApcDisable = 0`),
/// optionally acquiring it immediately for the current thread if `initial_owner`
/// is true.
///
/// # Safety
/// `mutant` points to writable storage for a `KMUTANT`.
pub unsafe fn init_mutant(mutant: *mut KMUTANT, initial_owner: bool) {
    // SAFETY: per the contract.
    unsafe {
        mutant.cast::<u8>().write_bytes(0, size_of::<KMUTANT>());
        let header = &raw mut (*mutant).Header;
        (&raw mut (*header).Type).write(MUTANT_OBJECT);
        (&raw mut (*header).SignalState).write(1);
        object::init_wait_list(header);
        (&raw mut (*mutant).ApcDisable).write(0);
        if initial_owner {
            let _lock = ObjectLock::take(header);
            taken(mutant, thread::current());
        }
    }
}

/// Release a `KMUTANT` for the calling thread without bugchecking on ownership
/// mismatch (returns `Err(STATUS_MUTANT_NOT_OWNED)` for `NtReleaseMutant`).
///
/// # Safety
/// `mutant` is a live, initialized `KMUTANT`.
pub unsafe fn try_release_mutant(mutant: *mut KMUTANT) -> Result<i32, nk_ntabi::status::NTSTATUS> {
    let me = thread::current();
    // SAFETY: per the contract.
    unsafe {
        let header = mutant.cast::<DISPATCHER_HEADER>();
        let mut released = 0;
        let (previous, woken) = {
            let _lock = ObjectLock::take(header);
            if owner(mutant) != me {
                return Err(nk_ntabi::status::STATUS_MUTANT_NOT_OWNED);
            }
            let previous = object::signal(header).fetch_add(1, Ordering::Relaxed);
            if previous != 0 {
                (previous, object::Woken::none())
            } else {
                (&raw mut (*mutant).OwnerThread).write(core::ptr::null_mut());
                let LIST_ENTRY { Flink, Blink } = (&raw const (*mutant).MutantListEntry).read();
                (&raw mut (*Blink).Flink).write(Flink);
                (&raw mut (*Flink).Blink).write(Blink);
                released = i16::from((&raw const (*mutant).ApcDisable).read());
                (previous, object::satisfy(header))
            }
        };
        woken.ready();
        if released != 0 {
            super::apc::kernel_disable_raised(released);
        }
        Ok(previous)
    }
}

/// [`KeReadStateMutex`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereadstatemutex).
///
/// # Safety
/// `mutex` is a live, initialised `KMUTANT`.
pub unsafe extern "C" fn KeReadStateMutex(mutex: *mut KMUTANT) -> i32 {
    // SAFETY: per the contract.
    unsafe { object::signal(mutex.cast()).load(Ordering::Acquire) }
}

/// [`KeEnterCriticalRegion`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keentercriticalregion).
pub extern "C" fn KeEnterCriticalRegion() {
    // SAFETY: the running thread, live while it runs this.
    unsafe { apc_disable(thread::current()) }.fetch_sub(1, Ordering::Relaxed);
}

/// [`KeLeaveCriticalRegion`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keleavecriticalregion):
/// leaving the last one lets the thread's queued kernel APCs run.
pub extern "C" fn KeLeaveCriticalRegion() {
    super::apc::kernel_disable_raised(1);
}

/// Run `f` inside a critical region.
pub fn in_critical_region<R>(f: impl FnOnce() -> R) -> R {
    KeEnterCriticalRegion();
    let result = f();
    KeLeaveCriticalRegion();
    result
}

/// [`KeAreApcsDisabled`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keareapcsdisabled):
/// whether the thread is in a critical or guarded region.
pub extern "C" fn KeAreApcsDisabled() -> u8 {
    // The kernel and special counts together: `CombinedApcDisable`.
    // SAFETY: an aligned 32-bit field of the running thread's block.
    let combined =
        unsafe { thread::object_field::<u32>(thread::current(), KERNEL_APC_DISABLE).read() };
    u8::from(combined != 0)
}

/// # Safety
/// `mutex` points to a live `FAST_MUTEX`.
unsafe fn count<'a>(mutex: *mut FAST_MUTEX) -> &'a AtomicI32 {
    // SAFETY: per the contract.
    unsafe { AtomicI32::from_ptr(&raw mut (*mutex).Count) }
}

/// # Safety
/// `mutex` points to a live `FAST_MUTEX`.
unsafe fn fast_owner<'a>(mutex: *mut FAST_MUTEX) -> &'a AtomicPtr<c_void> {
    // SAFETY: per the contract.
    unsafe { AtomicPtr::from_ptr(&raw mut (*mutex).Owner) }
}

/// [`ExAcquireFastMutexUnsafe`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquirefastmutexunsafe):
/// take the mutex without touching the IRQL. The caller is at
/// `APC_LEVEL` or in a critical region.
///
/// # Safety
/// `mutex` is a live `FAST_MUTEX` initialised by `ExInitializeFastMutex`.
pub unsafe extern "C" fn ExAcquireFastMutexUnsafe(mutex: *mut FAST_MUTEX) {
    // SAFETY: per the contract.
    unsafe {
        if count(mutex).fetch_sub(1, Ordering::AcqRel) != 1 {
            // Held: the count now says one more thread waits, and the
            // holder's release will hand the mutex over through the
            // event, to one waiter per release.
            (&raw mut (*mutex).Contention)
                .write((&raw const (*mutex).Contention).read().wrapping_add(1));
            wait::wait(Some((&raw mut (*mutex).Event).cast()), None);
        }
        fast_owner(mutex).store(thread::current().cast(), Ordering::Release);
    }
}

/// [`ExReleaseFastMutexUnsafe`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exreleasefastmutexunsafe).
///
/// # Safety
/// `mutex` is a live `FAST_MUTEX` the calling thread holds.
pub unsafe extern "C" fn ExReleaseFastMutexUnsafe(mutex: *mut FAST_MUTEX) {
    // SAFETY: per the contract.
    unsafe {
        fast_owner(mutex).store(core::ptr::null_mut(), Ordering::Release);
        if count(mutex).fetch_add(1, Ordering::AcqRel) != 0 {
            // Someone waits: the mutex passes to one of them, held.
            wait::KeSetEvent(&raw mut (*mutex).Event, 0, 0);
        }
    }
}

/// [`ExAcquireFastMutex`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquirefastmutex):
/// take the mutex and raise the IRQL to `APC_LEVEL`.
///
/// # Safety
/// As `ExAcquireFastMutexUnsafe`; the caller is at or below `APC_LEVEL`.
pub unsafe extern "C" fn ExAcquireFastMutex(mutex: *mut FAST_MUTEX) {
    let old = irql::current();
    if old > APC_LEVEL {
        crate::kd::verify(format_args!("a fast mutex acquired at IRQL {old}"));
    }
    arch::set_irql(APC_LEVEL.max(old));
    // SAFETY: per the contract. The old level is the holder's to keep:
    // written only once the mutex is held.
    unsafe {
        ExAcquireFastMutexUnsafe(mutex);
        (&raw mut (*mutex).OldIrql).write(u32::from(old));
    }
}

/// [`ExTryToAcquireFastMutex`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-extrytoacquirefastmutex):
/// take the mutex if it is free, without waiting.
///
/// # Safety
/// As `ExAcquireFastMutex`.
pub unsafe extern "C" fn ExTryToAcquireFastMutex(mutex: *mut FAST_MUTEX) -> u8 {
    let old = irql::current();
    arch::set_irql(APC_LEVEL.max(old));
    // SAFETY: per the contract.
    unsafe {
        let got = count(mutex)
            .compare_exchange(1, 0, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok();
        if got {
            fast_owner(mutex).store(thread::current().cast(), Ordering::Release);
            (&raw mut (*mutex).OldIrql).write(u32::from(old));
        } else {
            arch::set_irql(old);
        }
        u8::from(got)
    }
}

/// [`ExReleaseFastMutex`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exreleasefastmutex):
/// release the mutex and restore the IRQL it was taken at.
///
/// # Safety
/// `mutex` is a live `FAST_MUTEX` the calling thread holds, taken with
/// `ExAcquireFastMutex` or `ExTryToAcquireFastMutex`.
pub unsafe extern "C" fn ExReleaseFastMutex(mutex: *mut FAST_MUTEX) {
    // SAFETY: per the contract. Read before releasing: afterwards the
    // field is the next holder's.
    unsafe {
        let old = (&raw const (*mutex).OldIrql).read() as u8;
        ExReleaseFastMutexUnsafe(mutex);
        arch::set_irql(old);
    }
}

/// [`KeInitializeGuardedMutex`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keinitializeguardedmutex).
/// A guarded mutex is a fast mutex in this Windows, structure and all:
/// free, unowned, with an event for its waiters.
///
/// # Safety
/// `mutex` points to writable storage for a `KGUARDED_MUTEX`.
pub unsafe extern "C" fn KeInitializeGuardedMutex(mutex: *mut FAST_MUTEX) {
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*mutex).Count).write(1);
        (&raw mut (*mutex).Owner).write(core::ptr::null_mut());
        (&raw mut (*mutex).Contention).write(0);
        wait::KeInitializeEvent(&raw mut (*mutex).Event, 1, 0);
        (&raw mut (*mutex).OldIrql).write(0);
    }
}

/// [`KeAcquireGuardedMutex`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquireguardedmutex):
/// what `ExAcquireFastMutex` does, as in the Windows NK follows: take
/// the mutex and raise the IRQL to `APC_LEVEL`.
///
/// # Safety
/// As `ExAcquireFastMutex`.
pub unsafe extern "C" fn KeAcquireGuardedMutex(mutex: *mut FAST_MUTEX) {
    // SAFETY: per the contract.
    unsafe { ExAcquireFastMutex(mutex) }
}

/// [`KeReleaseGuardedMutex`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereleaseguardedmutex).
///
/// # Safety
/// As `ExReleaseFastMutex`.
pub unsafe extern "C" fn KeReleaseGuardedMutex(mutex: *mut FAST_MUTEX) {
    // SAFETY: per the contract.
    unsafe { ExReleaseFastMutex(mutex) }
}

// ---- tests --------------------------------------------------------------

use crate::test::Slot;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64};

static MUTEX: Slot<KMUTANT> = Slot::new();
static FAST: Slot<FAST_MUTEX> = Slot::new();
/// What a helper thread got: a wait status, or a 0/1 answer.
static GOT: AtomicU32 = AtomicU32::new(0);
static INSIDE: AtomicBool = AtomicBool::new(false);
static WRONG: AtomicU32 = AtomicU32::new(0);
static COUNT: AtomicU64 = AtomicU64::new(0);

fn take_mutex(no_wait: bool) -> u32 {
    // SAFETY: a static, initialised mutex.
    unsafe { wait::wait(Some(MUTEX.ptr().cast()), no_wait.then_some(0)) }
}

fn release_mutex() -> i32 {
    // SAFETY: a static, initialised mutex the caller holds.
    unsafe { KeReleaseMutex(MUTEX.ptr(), 0) }
}

fn read_mutex() -> i32 {
    // SAFETY: a static, initialised mutex.
    unsafe { KeReadStateMutex(MUTEX.ptr()) }
}

fn init_fast() {
    // What `ExInitializeFastMutex` compiles to in a driver.
    // SAFETY: static storage for a fast mutex nobody holds.
    unsafe {
        let fast = FAST.ptr();
        (&raw mut (*fast).Count).write(1);
        (&raw mut (*fast).Owner).write(core::ptr::null_mut());
        (&raw mut (*fast).Contention).write(0);
        wait::KeInitializeEvent(&raw mut (*fast).Event, 1, 0);
    }
}

/// Run `entry` in another thread and wait for it to end.
fn in_another_thread(entry: thread::Entry) -> Result<(), &'static str> {
    let before = thread::count();
    let other = thread::create_referenced(entry, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    // SAFETY: the thread is referenced until the dereference.
    unsafe {
        wait::wait(Some(other.cast()), None);
        crate::ob::object::dereference(other.cast());
    }
    // A thread seen to have ended is buried: what it used is back.
    if thread::count() != before {
        return Err("a thread that ended was not buried");
    }
    Ok(())
}

/// A mutex has one owner, who may take it again and must release it as
/// often; while held, kernel APCs are off for the owner and no other
/// thread gets it.
pub fn ownership_test() -> Result<(), &'static str> {
    fn try_it(_: usize) {
        let status = take_mutex(true);
        if status == wait::STATUS_SUCCESS {
            release_mutex();
        }
        GOT.store(status, Ordering::Release);
    }
    // SAFETY: static storage for a mutex nobody holds.
    unsafe { KeInitializeMutex(MUTEX.ptr(), 0) };
    if read_mutex() != 1 || KeAreApcsDisabled() != 0 {
        return Err("a new mutex is not free, or APCs are off for no reason");
    }
    if take_mutex(false) != wait::STATUS_SUCCESS || read_mutex() != 0 {
        return Err("a free mutex was not taken");
    }
    if KeAreApcsDisabled() != 1 {
        return Err("holding a mutex did not turn kernel APCs off");
    }
    if take_mutex(false) != wait::STATUS_SUCCESS || read_mutex() != -1 {
        return Err("a mutex's owner could not take it again");
    }
    in_another_thread(try_it)?;
    if GOT.load(Ordering::Acquire) != wait::STATUS_TIMEOUT {
        return Err("another thread got a mutex that is held");
    }
    if (release_mutex(), read_mutex(), KeAreApcsDisabled()) != (-1, 0, 1) {
        return Err("the first of two releases freed the mutex");
    }
    if (release_mutex(), read_mutex(), KeAreApcsDisabled()) != (0, 1, 0) {
        return Err("as many releases as takings did not free the mutex and turn APCs on");
    }
    in_another_thread(try_it)?;
    if GOT.load(Ordering::Acquire) != wait::STATUS_SUCCESS || read_mutex() != 1 {
        return Err("another thread could not take and release a free mutex");
    }
    Ok(())
}

/// One thread at a time is inside what a lock guards, however the
/// threads are scheduled. `enter` and `leave` are the lock under test.
fn exclusion(enter: fn(), leave: fn()) -> Result<u64, &'static str> {
    const THREADS: u64 = 4;
    const ROUNDS: u64 = 2000;
    static ENTER: AtomicU64 = AtomicU64::new(0);
    static LEAVE: AtomicU64 = AtomicU64::new(0);
    fn body(_: usize) {
        // SAFETY: the two words hold the `fn()`s stored below.
        let (enter, leave): (fn(), fn()) = unsafe {
            (
                core::mem::transmute::<usize, fn()>(ENTER.load(Ordering::Acquire) as usize),
                core::mem::transmute::<usize, fn()>(LEAVE.load(Ordering::Acquire) as usize),
            )
        };
        for round in 0..ROUNDS {
            enter();
            if INSIDE.swap(true, Ordering::AcqRel) {
                WRONG.fetch_add(1, Ordering::Relaxed);
            }
            // Read, dawdle, write: lost updates show if two are inside.
            let seen = COUNT.load(Ordering::Relaxed);
            if round % 64 == 0 {
                thread::yield_now();
            }
            COUNT.store(seen + 1, Ordering::Relaxed);
            INSIDE.store(false, Ordering::Release);
            leave();
        }
    }
    let before = thread::count();
    ENTER.store(enter as usize as u64, Ordering::Release);
    LEAVE.store(leave as usize as u64, Ordering::Release);
    COUNT.store(0, Ordering::Relaxed);
    WRONG.store(0, Ordering::Relaxed);
    INSIDE.store(false, Ordering::Release);
    for _ in 0..THREADS {
        thread::create(body, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    }
    // However long it takes: an emulated machine on a busy host hands
    // a contended lock over slowly, and a waiter never let in hangs.
    while thread::count() != before {
        // SAFETY: no object is involved.
        unsafe { wait::wait(None, Some(-10_000)) };
    }
    if WRONG.load(Ordering::Relaxed) != 0 || COUNT.load(Ordering::Relaxed) != THREADS * ROUNDS {
        return Err("two threads were inside at once");
    }
    Ok(THREADS * ROUNDS)
}

/// Four threads contend for a mutex. Returns the times it was taken.
pub fn mutex_exclusion_test() -> Result<u64, &'static str> {
    // SAFETY: static storage for a mutex nobody holds.
    unsafe { KeInitializeMutex(MUTEX.ptr(), 0) };
    let taken = exclusion(
        || {
            take_mutex(false);
        },
        || {
            release_mutex();
        },
    )?;
    if read_mutex() != 1 {
        return Err("the mutex was not left free");
    }
    Ok(taken)
}

/// A fast mutex raises the IRQL to APC_LEVEL while held, refuses a
/// second taker, and keeps four contending threads apart. Returns the
/// times it was taken.
pub fn fast_mutex_test() -> Result<u64, &'static str> {
    fn try_it(_: usize) {
        // SAFETY: a static, initialised fast mutex.
        let got = unsafe { ExTryToAcquireFastMutex(FAST.ptr()) };
        if got != 0 {
            if irql::current() != APC_LEVEL {
                WRONG.fetch_add(1, Ordering::Relaxed);
            }
            // SAFETY: just taken.
            unsafe { ExReleaseFastMutex(FAST.ptr()) };
        }
        GOT.store(u32::from(got), Ordering::Release);
    }
    init_fast();
    WRONG.store(0, Ordering::Relaxed);
    // SAFETY: a static, initialised fast mutex, taken and released by
    // this thread as each call requires.
    unsafe {
        ExAcquireFastMutex(FAST.ptr());
        if irql::current() != APC_LEVEL {
            return Err("taking a fast mutex did not raise the IRQL to APC_LEVEL");
        }
        in_another_thread(try_it)?;
        if GOT.load(Ordering::Acquire) != 0 {
            return Err("a second thread got a fast mutex that is held");
        }
        ExReleaseFastMutex(FAST.ptr());
        if irql::current() != irql::PASSIVE_LEVEL {
            return Err("releasing a fast mutex did not restore the IRQL");
        }
        in_another_thread(try_it)?;
        if GOT.load(Ordering::Acquire) != 1 || WRONG.load(Ordering::Relaxed) != 0 {
            return Err("a second thread could not take a free fast mutex at APC_LEVEL");
        }
        // The unsafe pair leaves the IRQL alone.
        KeEnterCriticalRegion();
        ExAcquireFastMutexUnsafe(FAST.ptr());
        let level = irql::current();
        ExReleaseFastMutexUnsafe(FAST.ptr());
        KeLeaveCriticalRegion();
        if level != irql::PASSIVE_LEVEL {
            return Err("the unsafe fast-mutex routines changed the IRQL");
        }
    }
    let taken = exclusion(
        // SAFETY: a static, initialised fast mutex; each thread
        // releases what it took.
        || unsafe { ExAcquireFastMutex(FAST.ptr()) },
        // SAFETY: as for the taking.
        || unsafe { ExReleaseFastMutex(FAST.ptr()) },
    )?;
    // SAFETY: as above.
    if unsafe { count(FAST.ptr()) }.load(Ordering::Acquire) != 1 {
        return Err("the fast mutex was not left free");
    }
    Ok(taken)
}

/// Critical regions nest, and turn kernel APCs off for exactly as long
/// as the thread is inside one. Returns the depth tried.
pub fn region_test() -> Result<u32, &'static str> {
    const DEPTH: u32 = 5;
    if KeAreApcsDisabled() != 0 {
        return Err("APCs are off outside any critical region");
    }
    for _ in 0..DEPTH {
        KeEnterCriticalRegion();
        if KeAreApcsDisabled() != 1 || irql::current() != irql::PASSIVE_LEVEL {
            return Err("a critical region did not turn APCs off, or raised the IRQL");
        }
    }
    for left in (0..DEPTH).rev() {
        KeLeaveCriticalRegion();
        if KeAreApcsDisabled() != u8::from(left != 0) {
            return Err("critical regions did not nest");
        }
    }
    Ok(DEPTH)
}

/// A thread ends while it holds a mutex. The system must stop.
pub fn exit_holding_test() -> Result<(), &'static str> {
    fn body(_: usize) {
        take_mutex(false);
    }
    // SAFETY: static storage for a mutex nobody holds.
    unsafe { KeInitializeMutex(MUTEX.ptr(), 0) };
    in_another_thread(body)
}
