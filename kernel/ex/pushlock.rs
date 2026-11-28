//! Push locks (`EX_PUSH_LOCK`): the reader/writer lock that is one word
//! of the driver's memory.
//!
//! Microsoft documents the semantics under the filter manager's names
//! ([`FltAcquirePushLockExclusive`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltacquirepushlockexclusive)
//! and its siblings); drivers of this Windows import the `Ex...Ex`
//! routines here, whose second argument, flags, is zero.
//!
//! The word's transitions are `nk_ex::pushlock`'s, which also states the
//! protocol and checks its every interleaving. This file makes each
//! transition one compare-and-swap on the driver's word and supplies
//! what the logic leaves to the kernel:
//!
//! - **The queues.** A thread that must wait describes itself in a
//!   [`Waiter`] on its own stack and links it at the tail of one of
//!   [`QUEUES`] queues, picked by the lock's address. Each queue has a
//!   spin lock (`doc/LOCKING.md`); `WAITING` in a lock's word is set
//!   exactly while a queue holds a waiter for it, both changing only
//!   under that spin lock.
//! - **Sleeping and waking.** A waiter sleeps on a synchronization event
//!   in its `Waiter`. The releaser with the duty to wake takes waiters
//!   off the queue under the spin lock and sets their events after
//!   dropping it. A woken thread starts over: it is not handed the lock.
//!
//! A release of a lock the word says is not held stops the system.
//! Windows does not check; the word would no longer mean anything.

#![allow(non_snake_case)]

use crate::ke::{Rank, SpinLock, wait};
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::ops::{Deref, DerefMut};
use core::sync::atomic::{AtomicU64, Ordering};
use nk_ex::pushlock::{self, Access, Acquire, NotHeld, Release, Wake};
use nk_ntabi::ex::EX_PUSH_LOCK;
use nk_ntabi::ke::KEVENT;

/// A passive reader/writer lock built on [`EX_PUSH_LOCK`].
///
/// Acquiring enters a kernel critical region (`KeEnterCriticalRegion`) and
/// sleeps on contention, so it may only be taken at `<= APC_LEVEL` with no
/// spin lock held. Releasing leaves the critical region.
pub struct PushLock<T> {
    lock: UnsafeCell<EX_PUSH_LOCK>,
    value: UnsafeCell<T>,
}

// SAFETY: the push lock serialises mutable access and synchronises shared
// access to `T`.
unsafe impl<T: Send> Sync for PushLock<T> {}

/// Shared (reader) guard for [`PushLock`].
pub struct ReadGuard<'a, T> {
    lock: &'a PushLock<T>,
}

/// Exclusive (writer) guard for [`PushLock`].
pub struct WriteGuard<'a, T> {
    lock: &'a PushLock<T>,
}

impl<T> PushLock<T> {
    /// A new unlocked push lock protecting `value`.
    pub const fn new(value: T) -> Self {
        Self {
            lock: UnsafeCell::new(0),
            value: UnsafeCell::new(value),
        }
    }

    fn check_irql(&self) {
        let level = crate::ke::irql::current();
        if level >= crate::ke::irql::DISPATCH_LEVEL {
            crate::kd::bugcheck(format_args!(
                "0x0000000A IRQL_NOT_LESS_OR_EQUAL: passive PushLock at {:p} taken at IRQL {level}",
                self.lock.get()
            ));
        }
    }

    /// Acquire exclusive access (writer), entering a critical region.
    pub fn lock(&self) -> WriteGuard<'_, T> {
        self.check_irql();
        crate::ke::mutex::KeEnterCriticalRegion();
        // SAFETY: `self.lock` is a live `EX_PUSH_LOCK` and IRQL <= APC_LEVEL.
        unsafe { acquire(self.lock.get(), Access::Exclusive) };
        WriteGuard { lock: self }
    }

    /// Acquire shared access (reader), entering a critical region.
    pub fn read(&self) -> ReadGuard<'_, T>
    where
        T: Sync,
    {
        self.check_irql();
        crate::ke::mutex::KeEnterCriticalRegion();
        // SAFETY: `self.lock` is a live `EX_PUSH_LOCK` and IRQL <= APC_LEVEL.
        unsafe { acquire(self.lock.get(), Access::Shared) };
        ReadGuard { lock: self }
    }
}

impl<T> Deref for ReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: shared hold prevents concurrent writers.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> Drop for ReadGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: matching shared acquire in `PushLock::read`.
        unsafe { release(self.lock.lock.get(), pushlock::release_shared) };
        crate::ke::mutex::KeLeaveCriticalRegion();
    }
}

impl<T> Deref for WriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: exclusive hold prevents concurrent readers and writers.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for WriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: exclusive hold prevents concurrent readers and writers.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for WriteGuard<'_, T> {
    fn drop(&mut self) {
        // SAFETY: matching exclusive acquire in `PushLock::lock`.
        unsafe { release(self.lock.lock.get(), pushlock::release_exclusive) };
        crate::ke::mutex::KeLeaveCriticalRegion();
    }
}

/// A thread waiting for a push lock. It lives on that thread's stack,
/// which stays put while the thread sleeps: until its event is set.
struct Waiter {
    /// The lock waited for.
    lock: *mut EX_PUSH_LOCK,
    access: Access,
    /// What the thread sleeps on.
    event: KEVENT,
    /// The next waiter of the queue, newer than this one.
    next: *mut Waiter,
}

/// Waiters, oldest first, for the locks whose addresses lead here.
struct Queue {
    oldest: *mut Waiter,
    newest: *mut Waiter,
}

// SAFETY: the pointers name waiters on the stacks of sleeping threads,
// reached only under the queue's lock, from whichever processor.
unsafe impl Send for Queue {}

/// How many queues the waiters of all push locks are spread over.
const QUEUES: usize = 64;

static WAITERS: [SpinLock<Queue>; QUEUES] = [const {
    SpinLock::new(
        Rank::PushLock,
        Queue {
            oldest: core::ptr::null_mut(),
            newest: core::ptr::null_mut(),
        },
    )
}; QUEUES];

/// The queue the waiters of `lock` are on.
fn queue_of(lock: *mut EX_PUSH_LOCK) -> &'static SpinLock<Queue> {
    // Locks are words inside structures: the low bits say nothing, and
    // the multiplication spreads what is left over the top six.
    let mixed = ((lock as usize as u64) >> 3).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    &WAITERS[(mixed >> 58) as usize]
}

impl Queue {
    /// Link `waiter` in as the newest.
    ///
    /// # Safety
    /// `waiter` is a live `Waiter` on no queue, and stays live until it
    /// is taken off this one.
    unsafe fn push(&mut self, waiter: *mut Waiter) {
        // SAFETY: per the contract; queued waiters are live.
        unsafe {
            (&raw mut (*waiter).next).write(core::ptr::null_mut());
            if self.newest.is_null() {
                self.oldest = waiter;
            } else {
                (&raw mut (*self.newest).next).write(waiter);
            }
        }
        self.newest = waiter;
    }

    /// Take off the waiters of `lock` that a releaser is to wake: the
    /// oldest alone if it wants exclusive access, all of them if it
    /// wants shared. Returns them, oldest first, linked through `next`,
    /// and whether any waiter of `lock` is left.
    fn take(&mut self, lock: *mut EX_PUSH_LOCK) -> (*mut Waiter, bool) {
        let mut taken: *mut Waiter = core::ptr::null_mut();
        let mut last_taken: *mut Waiter = core::ptr::null_mut();
        let mut whom = None;
        let mut left = false;
        let mut before: *mut Waiter = core::ptr::null_mut();
        let mut at = self.oldest;
        while !at.is_null() {
            // SAFETY: a queued waiter is live until taken off, and this
            // queue's lock is held.
            unsafe {
                let next = (*at).next;
                let wanted = (*at).lock == lock
                    && match *whom.get_or_insert(pushlock::wake((*at).access)) {
                        Wake::Oldest => taken.is_null(),
                        Wake::All => true,
                    };
                if wanted {
                    if before.is_null() {
                        self.oldest = next;
                    } else {
                        (&raw mut (*before).next).write(next);
                    }
                    if self.newest == at {
                        self.newest = before;
                    }
                    (&raw mut (*at).next).write(core::ptr::null_mut());
                    if last_taken.is_null() {
                        taken = at;
                    } else {
                        (&raw mut (*last_taken).next).write(at);
                    }
                    last_taken = at;
                } else {
                    left |= (*at).lock == lock;
                    before = at;
                }
                at = next;
            }
        }
        (taken, left)
    }
}

/// The lock's word.
///
/// # Safety
/// `lock` points to a live, aligned `EX_PUSH_LOCK`.
unsafe fn word<'a>(lock: *mut EX_PUSH_LOCK) -> &'a AtomicU64 {
    // SAFETY: per the contract; an atomic view is how a word that other
    // processors and the driver also touch must be accessed.
    unsafe { AtomicU64::from_ptr(lock.cast()) }
}

/// Take the lock if `step` lets the caller in as the word stands; store
/// nothing if it would have to wait.
fn enter(word: &AtomicU64, step: fn(u64) -> (u64, Acquire)) -> bool {
    let mut old = word.load(Ordering::Relaxed);
    loop {
        let (new, Acquire::Acquired) = step(old) else {
            return false;
        };
        match word.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(now) => old = now,
        }
    }
}

/// Take the lock, sleeping until it can be had.
///
/// # Safety
/// `lock` points to a live push lock, which stays live until this
/// returns.
unsafe fn acquire(lock: *mut EX_PUSH_LOCK, access: Access) {
    let step = match access {
        Access::Exclusive => pushlock::acquire_exclusive,
        Access::Shared => pushlock::acquire_shared,
    };
    // SAFETY: per the contract.
    let word = unsafe { word(lock) };
    while !enter(word, step) {
        let mut storage = MaybeUninit::<Waiter>::uninit();
        let me = storage.as_mut_ptr();
        // SAFETY: `me` is this frame's storage, written whole before
        // anything can find it, and the frame stays until the wait has
        // returned, which is after a waker took `me` off the queue.
        unsafe {
            let event = &raw mut (*me).event;
            {
                let mut queue = queue_of(lock).lock();
                // Again, now that no waker can come between the look
                // and the queueing. Refused here, the word says WAITING.
                if pushlock::update(word, step) == Acquire::Acquired {
                    return;
                }
                (&raw mut (*me).lock).write(lock);
                (&raw mut (*me).access).write(access);
                wait::KeInitializeEvent(event, 1, 0);
                queue.push(me);
            }
            wait::wait(Some(event.cast()), None);
        }
    }
}

/// Give up a hold, and wake waiters if that falls to this releaser.
///
/// # Safety
/// `lock` points to a live push lock.
unsafe fn release(lock: *mut EX_PUSH_LOCK, step: fn(u64) -> Result<(u64, Release), NotHeld>) {
    // SAFETY: per the contract.
    let word = unsafe { word(lock) };
    let mut old = word.load(Ordering::Relaxed);
    let then = loop {
        let Ok((new, then)) = step(old) else {
            crate::kd::bugcheck(format_args!(
                "a push lock at {lock:p} was released by a thread that does not hold it \
                 that way (its word is {old:#x})"
            ));
        };
        match word.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => break then,
            Err(now) => old = now,
        }
    };
    if then == Release::Wake {
        let mut woken = {
            let mut queue = queue_of(lock).lock();
            let (woken, left) = queue.take(lock);
            // The duty is done, and WAITING goes with the last waiter,
            // before another thread can queue.
            pushlock::update(word, |old| (pushlock::end_wake(old, left), ()));
            woken
        };
        while !woken.is_null() {
            // SAFETY: a waiter taken off the queue sleeps, or is about
            // to, on its event, and its frame stays until the event is
            // set: its link is read first.
            unsafe {
                let next = (*woken).next;
                wait::KeSetEvent(&raw mut (*woken).event, 0, 0);
                woken = next;
            }
        }
    }
}

/// `ExAcquirePushLockExclusiveEx`: take the lock for the caller alone,
/// waiting for every holder to let go. The caller is in a critical
/// region, at or below `APC_LEVEL`.
///
/// # Safety
/// `lock` points to a push lock, zero when it was new, that stays valid
/// until this returns.
pub unsafe extern "C" fn ExAcquirePushLockExclusiveEx(lock: *mut EX_PUSH_LOCK, _flags: u32) {
    // SAFETY: per the contract.
    unsafe { acquire(lock, Access::Exclusive) }
}

/// `ExAcquirePushLockSharedEx`: take the lock together with any other
/// shared holders. With a thread waiting, the caller waits behind it.
///
/// # Safety
/// As `ExAcquirePushLockExclusiveEx`.
pub unsafe extern "C" fn ExAcquirePushLockSharedEx(lock: *mut EX_PUSH_LOCK, _flags: u32) {
    // SAFETY: per the contract.
    unsafe { acquire(lock, Access::Shared) }
}

/// `ExTryAcquirePushLockExclusiveEx`: take the lock for the caller
/// alone if nobody holds it; never waits. Nonzero if taken.
///
/// # Safety
/// `lock` points to a live push lock.
pub unsafe extern "C" fn ExTryAcquirePushLockExclusiveEx(
    lock: *mut EX_PUSH_LOCK,
    _flags: u32,
) -> u8 {
    // SAFETY: per the contract.
    u8::from(enter(unsafe { word(lock) }, pushlock::acquire_exclusive))
}

/// `ExReleasePushLockExclusiveEx`.
///
/// # Safety
/// `lock` points to a live push lock the caller holds exclusively.
pub unsafe extern "C" fn ExReleasePushLockExclusiveEx(lock: *mut EX_PUSH_LOCK, _flags: u32) {
    // SAFETY: per the contract.
    unsafe { release(lock, pushlock::release_exclusive) }
}

/// `ExReleasePushLockSharedEx`.
///
/// # Safety
/// `lock` points to a live push lock the caller holds shared.
pub unsafe extern "C" fn ExReleasePushLockSharedEx(lock: *mut EX_PUSH_LOCK, _flags: u32) {
    // SAFETY: per the contract.
    unsafe { release(lock, pushlock::release_shared) }
}

/// `ExReleasePushLockEx`: give up the caller's hold, whichever kind the
/// word shows.
///
/// # Safety
/// `lock` points to a live push lock the caller holds.
pub unsafe extern "C" fn ExReleasePushLockEx(lock: *mut EX_PUSH_LOCK, _flags: u32) {
    // SAFETY: per the contract.
    unsafe { release(lock, pushlock::release) }
}

// ---- tests --------------------------------------------------------------

use super::stress;
use crate::ke::mutex::{KeEnterCriticalRegion, KeLeaveCriticalRegion};
use crate::ke::thread;
use crate::test::Slot;
use core::sync::atomic::AtomicU32;
use nk_ex::pushlock::{LOCKED, SHARE_SHIFT, WAITING};

/// The lock under test, as a driver would keep it: a word of its own.
static LOCK: Slot<EX_PUSH_LOCK> = Slot::new();
/// Set to let the helper threads let go and end.
static GO: Slot<KEVENT> = Slot::new();
/// How many helpers are about to ask for the lock, or have.
static ASKED: AtomicU32 = AtomicU32::new(0);
/// How many helpers hold the lock.
static INSIDE: AtomicU32 = AtomicU32::new(0);
/// What trying without waiting gave a helper.
static TRIED: AtomicU32 = AtomicU32::new(0);

const EXCLUSIVE: usize = 0;
const SHARED: usize = 1;

/// `n` shared holders.
const fn shared_by(n: u64) -> u64 {
    LOCKED | n << SHARE_SHIFT
}

fn lock_word() -> u64 {
    // SAFETY: the static word.
    unsafe { word(LOCK.ptr()) }.load(Ordering::Acquire)
}

fn take(access: usize) {
    // SAFETY: the static lock, initialised by `fresh`.
    unsafe {
        if access == EXCLUSIVE {
            ExAcquirePushLockExclusiveEx(LOCK.ptr(), 0);
        } else {
            ExAcquirePushLockSharedEx(LOCK.ptr(), 0);
        }
    }
}

fn let_go(access: usize) {
    // SAFETY: the static lock, held by the caller in that way.
    unsafe {
        if access == EXCLUSIVE {
            ExReleasePushLockExclusiveEx(LOCK.ptr(), 0);
        } else {
            ExReleasePushLockSharedEx(LOCK.ptr(), 0);
        }
    }
}

fn try_exclusive() -> bool {
    // SAFETY: the static lock.
    unsafe { ExTryAcquirePushLockExclusiveEx(LOCK.ptr(), 0) != 0 }
}

/// A new lock, and nothing left over from the test before.
fn fresh() {
    // SAFETY: static storage nobody else is using: a push lock is
    // initialised by zeroing it.
    unsafe {
        LOCK.ptr().write(0);
        wait::KeInitializeEvent(GO.ptr(), 0, 0);
    }
    ASKED.store(0, Ordering::Release);
    INSIDE.store(0, Ordering::Release);
    TRIED.store(u32::MAX, Ordering::Release);
}

/// A helper thread: ask for the lock, hold it until told to go.
fn helper(access: usize) {
    KeEnterCriticalRegion();
    if access == EXCLUSIVE {
        let got = try_exclusive();
        if got {
            let_go(EXCLUSIVE);
        }
        TRIED.store(u32::from(got), Ordering::Release);
    }
    ASKED.fetch_add(1, Ordering::AcqRel);
    take(access);
    INSIDE.fetch_add(1, Ordering::AcqRel);
    // SAFETY: the static event, initialised by `fresh`.
    unsafe { wait::wait(Some(GO.ptr().cast()), None) };
    INSIDE.fetch_sub(1, Ordering::AcqRel);
    let_go(access);
    KeLeaveCriticalRegion();
}

fn start(access: usize) -> Result<(), &'static str> {
    thread::create(helper, access, thread::NORMAL_PRIORITY, thread::ANYWHERE).map(|_| ())
}

fn inside() -> u32 {
    INSIDE.load(Ordering::Acquire)
}

/// Let the helpers go and wait for them to end.
fn finish(threads_before: u32) -> Result<(), &'static str> {
    // SAFETY: the static event.
    unsafe { wait::KeSetEvent(GO.ptr(), 0, 0) };
    stress::ended(threads_before);
    if lock_word() != 0 {
        return Err("the lock was not left free");
    }
    Ok(())
}

/// What the word shows of each way to hold the lock, taken and let go by
/// one thread: the sequence a driver's own code produces.
pub fn words_test() -> Result<(), &'static str> {
    fresh();
    KeEnterCriticalRegion();
    let result = (|| {
        take(EXCLUSIVE);
        if lock_word() != LOCKED {
            return Err("held exclusively, the word is not the Locked bit alone");
        }
        if try_exclusive() || lock_word() != LOCKED {
            return Err("a held lock was had again by trying, or the try changed it");
        }
        let_go(EXCLUSIVE);
        if lock_word() != 0 {
            return Err("released, the word is not zero");
        }
        if !try_exclusive() || lock_word() != LOCKED {
            return Err("a free lock was not had by trying");
        }
        // SAFETY: the static lock, held.
        unsafe { ExReleasePushLockEx(LOCK.ptr(), 0) };
        if lock_word() != 0 {
            return Err("the release that is not told the kind did not free an exclusive hold");
        }
        take(SHARED);
        if lock_word() != shared_by(1) {
            return Err("held shared once, the word is not Locked and a count of one");
        }
        take(SHARED);
        if lock_word() != shared_by(2) {
            return Err("held shared twice, the count is not two");
        }
        if try_exclusive() || lock_word() != shared_by(2) {
            return Err("a lock held shared was had exclusively by trying");
        }
        let_go(SHARED);
        if lock_word() != shared_by(1) {
            return Err("one shared release did not take the count to one");
        }
        // SAFETY: the static lock, held.
        unsafe { ExReleasePushLockEx(LOCK.ptr(), 0) };
        if lock_word() != 0 {
            return Err("the release that is not told the kind did not free a shared hold");
        }
        Ok(())
    })();
    KeLeaveCriticalRegion();
    result
}

/// This thread holds the lock one way and a helper wants it another.
/// Unless both are shared the helper must wait, with `Locked` and
/// `Waiting` in the word, and be let in when this thread lets go.
fn hand_over(held: usize, wanted: usize) -> Result<(), &'static str> {
    fresh();
    let before = thread::count();
    KeEnterCriticalRegion();
    take(held);
    let result = start(wanted).and_then(|()| {
        if held == SHARED && wanted == SHARED {
            if !stress::until(stress::PROMPT_MS, || inside() == 1) {
                return Err("a second shared holder was not let in at once");
            }
            if lock_word() != shared_by(2) {
                return Err("two shared holders, and the count is not two");
            }
            return Ok(());
        }
        if !stress::until(stress::PROMPT_MS, || lock_word() & WAITING != 0) {
            return Err("a thread refused the lock did not set Waiting");
        }
        if inside() != 0 {
            return Err("a thread was let in to a lock held against it");
        }
        if wanted == EXCLUSIVE && TRIED.load(Ordering::Acquire) != 0 {
            return Err("a held lock was had by trying");
        }
        if lock_word() & 0xF != LOCKED | WAITING {
            return Err("with one waiter the low bits are not Locked and Waiting");
        }
        Ok(())
    });
    let_go(held);
    KeLeaveCriticalRegion();
    result?;
    if !stress::until(stress::PROMPT_MS, || inside() == 1) {
        return Err("a waiter was never let in after the holder let go");
    }
    let expected = if wanted == EXCLUSIVE {
        LOCKED
    } else {
        shared_by(1)
    };
    if lock_word() != expected {
        return Err("the waiter let in does not hold the lock as it asked");
    }
    finish(before)
}

/// A waiter is woken when the holder lets go, for each pairing of
/// exclusive and shared. Returns the pairings tried.
pub fn hand_over_test() -> Result<u32, &'static str> {
    let pairs = [
        (EXCLUSIVE, EXCLUSIVE),
        (SHARED, SHARED),
        (SHARED, EXCLUSIVE),
        (EXCLUSIVE, SHARED),
    ];
    for (held, wanted) in pairs {
        hand_over(held, wanted)?;
    }
    Ok(pairs.len() as u32)
}

/// Readers that waited behind a writer are all let in together when it
/// lets go; and a reader does not join a reader while a writer waits.
/// Returns the readers let in together.
pub fn readers_test() -> Result<u32, &'static str> {
    const READERS: u32 = 3;
    fresh();
    let before = thread::count();
    KeEnterCriticalRegion();
    take(EXCLUSIVE);
    let started = (0..READERS).try_for_each(|_| start(SHARED));
    // Asking and queueing are two steps: give the last one its moment.
    let queued = started.is_ok()
        && stress::until(stress::PROMPT_MS, || {
            ASKED.load(Ordering::Acquire) == READERS && lock_word() & WAITING != 0
        });
    for _ in 0..30 {
        stress::nap();
    }
    let early = inside();
    let_go(EXCLUSIVE);
    KeLeaveCriticalRegion();
    started?;
    if !queued || early != 0 {
        return Err("readers did not wait for the writer");
    }
    if !stress::until(stress::PROMPT_MS, || inside() == READERS) {
        return Err("the readers that waited were not all let in together");
    }
    if lock_word() != shared_by(u64::from(READERS)) {
        return Err("three readers inside, and the word does not say so");
    }
    finish(before)?;

    // A reader holds; a writer queues; a second reader must queue too.
    fresh();
    KeEnterCriticalRegion();
    take(SHARED);
    let started = start(EXCLUSIVE);
    let writer_waits =
        started.is_ok() && stress::until(stress::PROMPT_MS, || lock_word() & WAITING != 0);
    let started = started.and_then(|()| start(SHARED));
    let asked =
        started.is_ok() && stress::until(stress::PROMPT_MS, || ASKED.load(Ordering::Acquire) == 2);
    for _ in 0..30 {
        stress::nap();
    }
    let (joined, word_then) = (inside(), lock_word());
    let_go(SHARED);
    KeLeaveCriticalRegion();
    started?;
    if !writer_waits || !asked {
        return Err("the writer or the second reader never asked");
    }
    if joined != 0 || word_then != shared_by(1) | WAITING {
        return Err("a reader joined the holder past a waiting writer");
    }
    // The writer, oldest, is woken alone; the reader after it.
    if !stress::until(stress::PROMPT_MS, || inside() == 1) {
        return Err("the writer was never let in");
    }
    finish(before)?;
    Ok(READERS)
}

const THREADS: usize = 4;
const ROUNDS: u64 = 2000;
static WRITERS: AtomicU32 = AtomicU32::new(0);
static READERS: AtomicU32 = AtomicU32::new(0);
static WRONG: AtomicU32 = AtomicU32::new(0);
/// Written only under an exclusive hold, by read, dawdle, write: a lost
/// update shows two writers inside.
static VALUE: AtomicU64 = AtomicU64::new(0);
static WRITES: AtomicU64 = AtomicU64::new(0);

fn contender(index: usize) {
    let lock = LOCK.ptr();
    for round in 0..ROUNDS {
        let kind = (round + index as u64) % 4;
        KeEnterCriticalRegion();
        // SAFETY: the static lock; each hold is released the way it was
        // taken, or by the routine that reads the kind off the word.
        unsafe {
            if kind == 0 || (kind == 1 && ExTryAcquirePushLockExclusiveEx(lock, 0) != 0) {
                if kind == 0 {
                    ExAcquirePushLockExclusiveEx(lock, 0);
                }
                if WRITERS.fetch_add(1, Ordering::AcqRel) != 0
                    || READERS.load(Ordering::Acquire) != 0
                {
                    WRONG.fetch_add(1, Ordering::Relaxed);
                }
                let seen = VALUE.load(Ordering::Relaxed);
                if round % 64 == 0 {
                    thread::yield_now();
                }
                VALUE.store(seen + 1, Ordering::Relaxed);
                WRITES.fetch_add(1, Ordering::Relaxed);
                WRITERS.fetch_sub(1, Ordering::AcqRel);
                if round % 8 < 4 {
                    ExReleasePushLockExclusiveEx(lock, 0);
                } else {
                    ExReleasePushLockEx(lock, 0);
                }
            } else if kind != 1 {
                ExAcquirePushLockSharedEx(lock, 0);
                READERS.fetch_add(1, Ordering::AcqRel);
                let seen = VALUE.load(Ordering::Relaxed);
                if round % 64 == 2 {
                    thread::yield_now();
                }
                if WRITERS.load(Ordering::Acquire) != 0 || VALUE.load(Ordering::Relaxed) != seen {
                    WRONG.fetch_add(1, Ordering::Relaxed);
                }
                READERS.fetch_sub(1, Ordering::AcqRel);
                if round % 8 < 4 {
                    ExReleasePushLockSharedEx(lock, 0);
                } else {
                    ExReleasePushLockEx(lock, 0);
                }
            }
        }
        KeLeaveCriticalRegion();
    }
}

/// Threads take the lock every way at once: a writer is alone inside,
/// readers see no write, and nobody is left asleep. Returns the writes.
pub fn contention_test() -> Result<u64, &'static str> {
    fresh();
    for counter in [&WRITERS, &READERS, &WRONG] {
        counter.store(0, Ordering::Release);
    }
    VALUE.store(0, Ordering::Release);
    WRITES.store(0, Ordering::Release);
    stress::run(THREADS, contender)?;
    let writes = WRITES.load(Ordering::Acquire);
    if WRONG.load(Ordering::Acquire) != 0 || VALUE.load(Ordering::Acquire) != writes {
        return Err("a writer was not alone inside the lock");
    }
    if lock_word() != 0 {
        return Err("the lock was not left free");
    }
    Ok(writes)
}
