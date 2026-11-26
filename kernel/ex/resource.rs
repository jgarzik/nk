//! Executive resources (`ERESOURCE`): reader/writer locks that know
//! their owners.
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-eresource-routines>
//!
//! Who gets in, and who is let in next, is decided by
//! `nk_ex::resource`, one transition at a time. This file runs each
//! transition on the driver's `ERESOURCE` under the resource's own spin
//! lock (`ERESOURCE.SpinLock`), and supplies the rest:
//!
//! - **The state** is read from the Windows fields into the logic's
//!   `Resource` and written back: `Flag`, `OwnerEntry`, `ActiveEntries`,
//!   `ContentionCount` and the two waiter counts. `ActiveCount` is kept
//!   as 1 while anyone owns the resource and 0 otherwise.
//! - **The owner table** (`OwnerTable`) is a pool block of the
//!   kernel's: its first entry holds the number of entries
//!   (`TableSize`), the rest are owners. It is made, and doubled, when
//!   the logic says an owner has no room; `ExDeleteResourceLite` frees
//!   it.
//! - **Waiters.** A thread that must wait describes itself in a
//!   [`Waiter`] on its own stack and sleeps on the event that begins
//!   it. `ExclusiveWaiters` and `SharedWaiters` point to the oldest
//!   waiter of each kind, where Windows has an event and a semaphore
//!   that it allocates. Ownership is handed over: the releaser records
//!   the waiters it lets in as owners, under the spin lock, and sets
//!   their events after dropping it.
//!
//! A release or conversion by a thread that does not own the resource
//! stops the system (`RESOURCE_NOT_OWNED`), as on Windows. No priority
//! is raised for an owner that keeps others waiting.

#![allow(non_snake_case)]

use crate::ke::{kspin, thread, wait};
use crate::mm::pool;
use core::mem::MaybeUninit;
use nk_ex::resource::{Acquire, OwnerEntry, Release, Resource, Shared};
use nk_ntabi::ex::{ERESOURCE, OWNER_ENTRY};
use nk_ntabi::ke::{KEVENT, LIST_ENTRY};
use nk_ntabi::status::{NTSTATUS, STATUS_SUCCESS};

// The logic's entry is Windows': the table is handed to it as a slice.
const _: () = assert!(
    size_of::<OwnerEntry>() == size_of::<OWNER_ENTRY>()
        && align_of::<OwnerEntry>() == align_of::<OWNER_ENTRY>()
);

/// Pool tag of owner tables.
const TAG: u32 = u32::from_le_bytes(*b"ReTa");

/// Entries of a resource's first owner table, the one that counts them
/// included.
const FIRST_TABLE: u32 = 4;

/// A thread waiting for a resource. It lives on that thread's stack,
/// which stays put while the thread sleeps: until its event is set.
#[repr(C)]
struct Waiter {
    /// What the thread sleeps on. First, so that the resource's waiter
    /// fields point at a dispatcher object, as on Windows.
    event: KEVENT,
    /// The thread, as owners are named.
    thread: usize,
    /// The next waiter of the same kind, newer than this one.
    next: *mut Waiter,
}

/// The resource's spin lock, held until dropped.
struct Locked {
    resource: *mut ERESOURCE,
    old_irql: u8,
}

impl Locked {
    /// # Safety
    /// `resource` points to an initialised `ERESOURCE` that stays valid
    /// while the lock is held.
    unsafe fn take(resource: *mut ERESOURCE) -> Self {
        // SAFETY: per the contract.
        let old_irql = unsafe { kspin::KeAcquireSpinLockRaiseToDpc(&raw mut (*resource).SpinLock) };
        Self { resource, old_irql }
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        // SAFETY: taken in `take`; the resource is still valid.
        unsafe { kspin::KeReleaseSpinLock(&raw mut (*self.resource).SpinLock, self.old_irql) };
    }
}

/// The resource's state as the logic sees it.
///
/// # Safety
/// `resource` is live and its spin lock is held.
unsafe fn read(resource: *mut ERESOURCE) -> Resource {
    // SAFETY: per the contract.
    unsafe {
        Resource {
            flag: (&raw const (*resource).Flag).read(),
            owner: (&raw const (*resource).OwnerEntry)
                .cast::<OwnerEntry>()
                .read(),
            active_entries: (&raw const (*resource).ActiveEntries).read(),
            contention_count: (&raw const (*resource).ContentionCount).read(),
            shared_waiters: (&raw const (*resource).NumberOfSharedWaiters).read(),
            exclusive_waiters: (&raw const (*resource).NumberOfExclusiveWaiters).read(),
        }
    }
}

/// Store the state the logic left.
///
/// # Safety
/// `resource` is live and its spin lock is held.
unsafe fn write(resource: *mut ERESOURCE, state: &Resource) {
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*resource).Flag).write(state.flag);
        (&raw mut (*resource).OwnerEntry)
            .cast::<OwnerEntry>()
            .write(state.owner);
        (&raw mut (*resource).ActiveEntries).write(state.active_entries);
        (&raw mut (*resource).ActiveCount).write(i16::from(state.active_entries != 0));
        (&raw mut (*resource).ContentionCount).write(state.contention_count);
        (&raw mut (*resource).NumberOfSharedWaiters).write(state.shared_waiters);
        (&raw mut (*resource).NumberOfExclusiveWaiters).write(state.exclusive_waiters);
    }
}

/// How many entries the owner table has, its first included; zero with
/// no table.
///
/// # Safety
/// `resource` is live and its spin lock is held.
unsafe fn table_size(resource: *mut ERESOURCE) -> u32 {
    // SAFETY: per the contract; a table's first entry holds its size.
    unsafe {
        let table = (&raw const (*resource).OwnerTable).read();
        if table.is_null() {
            0
        } else {
            (&raw const (*table).Bits).read()
        }
    }
}

/// The owners in the table.
///
/// # Safety
/// `resource` is live and its spin lock is held for as long as the
/// slice is used.
unsafe fn owners<'a>(resource: *mut ERESOURCE) -> &'a mut [OwnerEntry] {
    // SAFETY: per the contract. The table is a pool block of the
    // kernel's own, written only under this spin lock: a driver holds
    // its address in the resource and has no business in it.
    unsafe {
        match table_size(resource) {
            0 => &mut [],
            size => core::slice::from_raw_parts_mut(
                (&raw const (*resource).OwnerTable)
                    .read()
                    .add(1)
                    .cast::<OwnerEntry>(),
                size as usize - 1,
            ),
        }
    }
}

/// Give the resource a larger owner table, unless another thread has
/// meanwhile. Sleeps and returns if there is no memory: the caller
/// asks again.
///
/// # Safety
/// `resource` points to an initialised `ERESOURCE`; the caller is below
/// `DISPATCH_LEVEL`.
unsafe fn grow(resource: *mut ERESOURCE) {
    // SAFETY: per the contract.
    unsafe {
        let seen = {
            let _lock = Locked::take(resource);
            table_size(resource)
        };
        let size = if seen == 0 { FIRST_TABLE } else { seen * 2 };
        // Zeroed: every owner slot free.
        let fresh =
            pool::alloc_zeroed(size as usize * size_of::<OWNER_ENTRY>(), TAG).cast::<OWNER_ENTRY>();
        if fresh.is_null() {
            wait::wait(None, Some(-100_000));
            return;
        }
        let stale = {
            let _lock = Locked::take(resource);
            if table_size(resource) == seen {
                (&raw mut (*fresh).Bits).write(size);
                let old = (&raw const (*resource).OwnerTable).read();
                if !old.is_null() {
                    core::ptr::copy_nonoverlapping(old.add(1), fresh.add(1), seen as usize - 1);
                }
                (&raw mut (*resource).OwnerTable).write(fresh);
                old
            } else {
                fresh
            }
        };
        if !stale.is_null() {
            let _ = pool::free(stale.cast());
        }
    }
}

/// The waiters of one kind: the field of the resource that points to
/// the oldest.
///
/// # Safety
/// `resource` is live.
unsafe fn queue(resource: *mut ERESOURCE, exclusive: bool) -> *mut *mut Waiter {
    // SAFETY: per the contract.
    unsafe {
        if exclusive {
            (&raw mut (*resource).ExclusiveWaiters).cast()
        } else {
            (&raw mut (*resource).SharedWaiters).cast()
        }
    }
}

/// Acquire the resource: exclusively, or shared in the way `how` says.
/// Returns whether the caller owns it; `false` only without `may_wait`.
///
/// # Safety
/// `resource` points to an initialised `ERESOURCE` that stays valid
/// until this returns.
unsafe fn acquire(resource: *mut ERESOURCE, may_wait: bool, how: Option<Shared>) -> bool {
    let me = thread::current() as usize;
    loop {
        let mut storage = MaybeUninit::<Waiter>::uninit();
        let waiter = storage.as_mut_ptr();
        // SAFETY: per the contract. `waiter` is this frame's storage,
        // written whole before it is linked, and the frame stays until
        // the wait has returned, which is after a releaser unlinked it.
        unsafe {
            let event = &raw mut (*waiter).event;
            let lock = Locked::take(resource);
            let mut state = read(resource);
            let answer = match how {
                None => state.acquire_exclusive(me, may_wait),
                Some(how) => state.acquire_shared(owners(resource), me, may_wait, how),
            };
            match answer {
                Acquire::Acquired => {
                    write(resource, &state);
                    return true;
                }
                Acquire::WouldBlock => return false,
                Acquire::TableFull => {
                    drop(lock);
                    grow(resource);
                }
                Acquire::Wait => {
                    wait::KeInitializeEvent(event, 1, 0);
                    (&raw mut (*waiter).thread).write(me);
                    (&raw mut (*waiter).next).write(core::ptr::null_mut());
                    // Last in the queue: waiters are served in order of
                    // arrival.
                    let mut link = queue(resource, how.is_none());
                    while !(*link).is_null() {
                        link = &raw mut (**link).next;
                    }
                    link.write(waiter);
                    write(resource, &state);
                    drop(lock);
                    // The releaser that sets the event has made this
                    // thread an owner first.
                    wait::wait(Some(event.cast()), None);
                    return true;
                }
            }
        }
    }
}

/// Let in the waiters a release or a conversion made room for. Returns
/// them, linked through `next`, to be woken once the spin lock is
/// dropped.
///
/// # Safety
/// `resource` is live and its spin lock is held; `state` is its state.
unsafe fn grant(resource: *mut ERESOURCE, state: &mut Resource, then: Release) -> *mut Waiter {
    // SAFETY: per the contract; queued waiters are live until woken.
    unsafe {
        match then {
            Release::Done => core::ptr::null_mut(),
            Release::WakeExclusive => {
                let oldest = queue(resource, true);
                let waiter = oldest.read();
                oldest.write((*waiter).next);
                (&raw mut (*waiter).next).write(core::ptr::null_mut());
                state.grant_exclusive((*waiter).thread);
                waiter
            }
            Release::WakeShared(_) => {
                // Every shared waiter: the logic kept a slot for each.
                let oldest = queue(resource, false);
                let waiters = oldest.read();
                oldest.write(core::ptr::null_mut());
                let mut waiter = waiters;
                while !waiter.is_null() {
                    state.grant_shared(owners(resource), (*waiter).thread);
                    waiter = (*waiter).next;
                }
                waiters
            }
        }
    }
}

/// Wake waiters that were let in.
///
/// # Safety
/// `waiters` came from `grant` and the resource's spin lock has been
/// dropped since.
unsafe fn wake(mut waiters: *mut Waiter) {
    while !waiters.is_null() {
        // SAFETY: a waiter taken off its queue sleeps, or is about to,
        // on its event, and its frame stays until the event is set: its
        // link is read first.
        unsafe {
            let next = (*waiters).next;
            wait::KeSetEvent(&raw mut (*waiters).event, 0, 0);
            waiters = next;
        }
    }
}

fn not_owned(resource: *mut ERESOURCE, thread: usize) -> ! {
    crate::kd::bugcheck(format_args!(
        "0x000000E3 RESOURCE_NOT_OWNED: the resource at {resource:p} is not owned by \
         thread {thread:#x} in the way it gives it up"
    ))
}

/// [`ExInitializeResourceLite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinitializeresourcelite).
/// Windows links every resource into a system-wide list through
/// `SystemResourcesList`; NK keeps no such list, and the entry is a list
/// of itself.
///
/// # Safety
/// `resource` points to writable storage for an `ERESOURCE` nothing
/// else is using.
pub unsafe extern "C" fn ExInitializeResourceLite(resource: *mut ERESOURCE) -> NTSTATUS {
    // SAFETY: per the contract. All zero is a resource nobody owns,
    // with no table and a free spin lock.
    unsafe {
        resource.cast::<u8>().write_bytes(0, size_of::<ERESOURCE>());
        let entry = &raw mut (*resource).SystemResourcesList;
        entry.write(LIST_ENTRY {
            Flink: entry,
            Blink: entry,
        });
    }
    STATUS_SUCCESS
}

/// [`ExReinitializeResourceLite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exreinitializeresourcelite):
/// back to a resource nobody owns, keeping its owner table.
///
/// # Safety
/// `resource` points to an initialised `ERESOURCE` that no thread owns
/// or waits for.
pub unsafe extern "C" fn ExReinitializeResourceLite(resource: *mut ERESOURCE) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let _lock = Locked::take(resource);
        let mut state = read(resource);
        state.reinitialize(owners(resource));
        write(resource, &state);
    }
    STATUS_SUCCESS
}

/// [`ExDeleteResourceLite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exdeleteresourcelite):
/// free what the kernel allocated for the resource.
///
/// # Safety
/// `resource` points to an initialised `ERESOURCE` that no thread owns,
/// waits for or will use again.
pub unsafe extern "C" fn ExDeleteResourceLite(resource: *mut ERESOURCE) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let table = {
            let _lock = Locked::take(resource);
            (&raw mut (*resource).OwnerTable).replace(core::ptr::null_mut())
        };
        if !table.is_null() {
            let _ = pool::free(table.cast());
        }
    }
    STATUS_SUCCESS
}

/// [`ExAcquireResourceExclusiveLite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquireresourceexclusivelite).
///
/// # Safety
/// `resource` points to an initialised `ERESOURCE` that stays valid
/// until this returns; with `wait` the caller is below `DISPATCH_LEVEL`.
pub unsafe extern "C" fn ExAcquireResourceExclusiveLite(resource: *mut ERESOURCE, wait: u8) -> u8 {
    // SAFETY: per the contract.
    u8::from(unsafe { acquire(resource, wait != 0, None) })
}

/// [`ExAcquireResourceSharedLite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquireresourcesharedlite).
///
/// # Safety
/// As `ExAcquireResourceExclusiveLite`.
pub unsafe extern "C" fn ExAcquireResourceSharedLite(resource: *mut ERESOURCE, wait: u8) -> u8 {
    // SAFETY: per the contract.
    u8::from(unsafe { acquire(resource, wait != 0, Some(Shared::Plain)) })
}

/// [`ExAcquireSharedStarveExclusive`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquiresharedstarveexclusive).
///
/// # Safety
/// As `ExAcquireResourceExclusiveLite`.
pub unsafe extern "C" fn ExAcquireSharedStarveExclusive(resource: *mut ERESOURCE, wait: u8) -> u8 {
    // SAFETY: per the contract.
    u8::from(unsafe { acquire(resource, wait != 0, Some(Shared::StarveExclusive)) })
}

/// [`ExAcquireSharedWaitForExclusive`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exacquiresharedwaitforexclusive).
///
/// # Safety
/// As `ExAcquireResourceExclusiveLite`.
pub unsafe extern "C" fn ExAcquireSharedWaitForExclusive(resource: *mut ERESOURCE, wait: u8) -> u8 {
    // SAFETY: per the contract.
    u8::from(unsafe { acquire(resource, wait != 0, Some(Shared::WaitForExclusive)) })
}

/// [`ExReleaseResourceForThreadLite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exreleaseresourceforthreadlite):
/// give up one acquisition by `thread`, which is what
/// `ExGetCurrentResourceThread` returned to the thread that acquired.
///
/// # Safety
/// `resource` points to an initialised `ERESOURCE`.
pub unsafe extern "C" fn ExReleaseResourceForThreadLite(resource: *mut ERESOURCE, thread: usize) {
    // SAFETY: per the contract.
    unsafe {
        let waiters = {
            let _lock = Locked::take(resource);
            let mut state = read(resource);
            let Ok(then) = state.release(owners(resource), thread) else {
                not_owned(resource, thread);
            };
            let waiters = grant(resource, &mut state, then);
            write(resource, &state);
            waiters
        };
        wake(waiters);
    }
}

/// [`ExReleaseResourceLite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exreleaseresourcelite).
///
/// # Safety
/// `resource` points to an initialised `ERESOURCE`.
pub unsafe extern "C" fn ExReleaseResourceLite(resource: *mut ERESOURCE) {
    // SAFETY: per the contract.
    unsafe { ExReleaseResourceForThreadLite(resource, thread::current() as usize) }
}

/// [`ExConvertExclusiveToSharedLite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exconvertexclusivetosharedlite):
/// the caller's exclusive access becomes shared, and the threads
/// waiting for shared access join it.
///
/// # Safety
/// `resource` points to an initialised `ERESOURCE`.
pub unsafe extern "C" fn ExConvertExclusiveToSharedLite(resource: *mut ERESOURCE) {
    let me = thread::current() as usize;
    // SAFETY: per the contract.
    unsafe {
        let waiters = {
            let _lock = Locked::take(resource);
            let mut state = read(resource);
            let Ok(then) = state.convert_exclusive_to_shared(me) else {
                not_owned(resource, me);
            };
            let waiters = grant(resource, &mut state, then);
            write(resource, &state);
            waiters
        };
        wake(waiters);
    }
}

/// [`ExIsResourceAcquiredExclusiveLite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exisresourceacquiredexclusivelite).
///
/// # Safety
/// `resource` points to an initialised `ERESOURCE`.
pub unsafe extern "C" fn ExIsResourceAcquiredExclusiveLite(resource: *mut ERESOURCE) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let _lock = Locked::take(resource);
        u8::from(read(resource).is_acquired_exclusive(thread::current() as usize))
    }
}

/// [`ExIsResourceAcquiredSharedLite`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exisresourceacquiredsharedlite):
/// how many times the caller has acquired the resource, either way.
///
/// # Safety
/// `resource` points to an initialised `ERESOURCE`.
pub unsafe extern "C" fn ExIsResourceAcquiredSharedLite(resource: *mut ERESOURCE) -> u32 {
    // SAFETY: per the contract.
    unsafe {
        let _lock = Locked::take(resource);
        read(resource).is_acquired_shared(owners(resource), thread::current() as usize)
    }
}

/// [`ExGetExclusiveWaiterCount`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exgetexclusivewaitercount).
///
/// # Safety
/// `resource` points to an initialised `ERESOURCE`.
pub unsafe extern "C" fn ExGetExclusiveWaiterCount(resource: *mut ERESOURCE) -> u32 {
    // SAFETY: per the contract.
    unsafe {
        let _lock = Locked::take(resource);
        (&raw const (*resource).NumberOfExclusiveWaiters).read()
    }
}

/// [`ExGetSharedWaiterCount`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exgetsharedwaitercount).
///
/// # Safety
/// `resource` points to an initialised `ERESOURCE`.
pub unsafe extern "C" fn ExGetSharedWaiterCount(resource: *mut ERESOURCE) -> u32 {
    // SAFETY: per the contract.
    unsafe {
        let _lock = Locked::take(resource);
        (&raw const (*resource).NumberOfSharedWaiters).read()
    }
}

// ---- tests --------------------------------------------------------------

use super::stress;
use crate::ke::mutex::{KeEnterCriticalRegion, KeLeaveCriticalRegion};
use crate::test::Slot;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use nk_ex::resource::RESOURCE_OWNED_EXCLUSIVE;

/// The resource under test, as a driver would keep it.
static RESOURCE: Slot<ERESOURCE> = Slot::new();
/// Set to let the helper threads let go and end.
static GO: Slot<KEVENT> = Slot::new();
/// How many helpers own the resource.
static INSIDE: AtomicU32 = AtomicU32::new(0);
/// What a helper was told when it asked without waiting, twice.
static TRIED: [AtomicU32; 2] = [AtomicU32::new(0), AtomicU32::new(0)];
/// Helpers that found themselves let in without being owners.
static WRONG: AtomicU32 = AtomicU32::new(0);

fn res() -> *mut ERESOURCE {
    RESOURCE.ptr()
}

// The exports, on the test's resource. Each is safe to call here: the
// resource is static and `fresh` initialised it.

fn exclusive(wait: bool) -> bool {
    // SAFETY: see above.
    unsafe { ExAcquireResourceExclusiveLite(res(), u8::from(wait)) != 0 }
}

fn shared(wait: bool) -> bool {
    // SAFETY: see above.
    unsafe { ExAcquireResourceSharedLite(res(), u8::from(wait)) != 0 }
}

fn starving(wait: bool) -> bool {
    // SAFETY: see above.
    unsafe { ExAcquireSharedStarveExclusive(res(), u8::from(wait)) != 0 }
}

fn yielding(wait: bool) -> bool {
    // SAFETY: see above.
    unsafe { ExAcquireSharedWaitForExclusive(res(), u8::from(wait)) != 0 }
}

fn try_exclusive() -> bool {
    exclusive(false)
}

fn let_go() {
    // SAFETY: see above; the caller owns the resource.
    unsafe { ExReleaseResourceLite(res()) }
}

/// Whether the caller owns it exclusively, how often it has acquired
/// it, and the "owned exclusively" flag.
fn held() -> (bool, u32, u16) {
    // SAFETY: see above.
    unsafe {
        (
            ExIsResourceAcquiredExclusiveLite(res()) != 0,
            ExIsResourceAcquiredSharedLite(res()),
            (&raw const (*res()).Flag).read() & RESOURCE_OWNED_EXCLUSIVE,
        )
    }
}

/// How many threads wait for it exclusively, and shared.
fn waiters() -> (u32, u32) {
    // SAFETY: see above.
    unsafe {
        (
            ExGetExclusiveWaiterCount(res()),
            ExGetSharedWaiterCount(res()),
        )
    }
}

/// A new resource, and nothing left over from the test before.
fn fresh() -> NTSTATUS {
    INSIDE.store(0, Ordering::Release);
    WRONG.store(0, Ordering::Release);
    for tried in &TRIED {
        tried.store(u32::MAX, Ordering::Release);
    }
    // SAFETY: static storage nobody else is using.
    unsafe {
        res().cast::<u8>().write_bytes(0xEE, size_of::<ERESOURCE>());
        wait::KeInitializeEvent(GO.ptr(), 0, 0);
        ExInitializeResourceLite(res())
    }
}

/// Free what the resource holds; the pool must be as it was `before`.
fn delete(before: nk_mm::heap::Usage) -> Result<(), &'static str> {
    // SAFETY: the static resource, which no thread uses any more.
    if unsafe { ExDeleteResourceLite(res()) } != STATUS_SUCCESS {
        return Err("deleting a resource failed");
    }
    if pool::usage() != before {
        return Err("a deleted resource left memory behind");
    }
    Ok(())
}

const WANTS_SHARED: usize = 0;
const WANTS_EXCLUSIVE: usize = 1;
const NEWCOMER: usize = 2;

/// Own the resource until told to go, then give it up, checking on the
/// way that the kernel agrees the thread owns it.
fn stay(owned: bool, release_by_name: bool) {
    if !owned {
        WRONG.fetch_add(1, Ordering::AcqRel);
    }
    INSIDE.fetch_add(1, Ordering::AcqRel);
    // SAFETY: the static event, initialised by `fresh`.
    unsafe { wait::wait(Some(GO.ptr().cast()), None) };
    INSIDE.fetch_sub(1, Ordering::AcqRel);
    if release_by_name {
        // SAFETY: the static resource, owned by this thread, named as
        // `ExGetCurrentResourceThread` names it.
        unsafe { ExReleaseResourceForThreadLite(res(), thread::current() as usize) };
    } else {
        let_go();
    }
}

fn helper(mode: usize) {
    KeEnterCriticalRegion();
    match mode {
        WANTS_SHARED => {
            for (tried, got) in TRIED.iter().zip([exclusive(false), shared(false)]) {
                if got {
                    let_go();
                }
                tried.store(u32::from(got), Ordering::Release);
            }
            shared(true);
            stay(held() == (false, 1, 0), false);
        }
        WANTS_EXCLUSIVE => {
            exclusive(true);
            stay(held() == (true, 1, RESOURCE_OWNED_EXCLUSIVE), true);
        }
        _ => {
            for (tried, got) in TRIED.iter().zip([shared(false), starving(false)]) {
                if got {
                    let_go();
                }
                tried.store(u32::from(got), Ordering::Release);
            }
        }
    }
    KeLeaveCriticalRegion();
}

fn start(mode: usize) -> Result<(), &'static str> {
    thread::create(helper, mode, thread::NORMAL_PRIORITY, thread::ANYWHERE).map(|_| ())
}

fn inside() -> u32 {
    INSIDE.load(Ordering::Acquire)
}

fn tried() -> (u32, u32) {
    (
        TRIED[0].load(Ordering::Acquire),
        TRIED[1].load(Ordering::Acquire),
    )
}

/// Let the helpers go and wait for them to end.
fn finish(threads_before: u32) -> Result<(), &'static str> {
    // SAFETY: the static event.
    unsafe { wait::KeSetEvent(GO.ptr(), 0, 0) };
    stress::ended(threads_before);
    if held() != (false, 0, 0) || waiters() != (0, 0) {
        return Err("the resource was not left free");
    }
    Ok(())
}

/// One thread acquires every way, again and again, and gives up as
/// often: exclusive access is recursive and takes shared requests as
/// more of the same; shared access is recursive and does not become
/// exclusive. Returns the acquisitions made.
pub fn recursion_test() -> Result<u32, &'static str> {
    let before = pool::usage();
    if fresh() != STATUS_SUCCESS || held() != (false, 0, 0) || waiters() != (0, 0) {
        return Err("a new resource is not free");
    }
    let mut acquired = 0;
    KeEnterCriticalRegion();
    let result = (|| {
        let flag = RESOURCE_OWNED_EXCLUSIVE;
        let ways: [fn() -> bool; 5] = [
            || exclusive(true),
            || exclusive(true),
            || shared(true),
            || exclusive(false),
            try_exclusive,
        ];
        for (count, way) in (1..).zip(ways) {
            if !way() || held() != (true, count, flag) {
                return Err("its exclusive owner did not get the resource once more");
            }
            acquired += 1;
        }
        for left in (0..5).rev() {
            let_go();
            if held() != (left > 0, left, if left > 0 { flag } else { 0 }) {
                return Err("released as often as acquired, exclusive access is not gone");
            }
        }

        if !shared(true) || held() != (false, 1, 0) || !shared(false) || held() != (false, 2, 0) {
            return Err("shared access was not had, twice");
        }
        if exclusive(false) || try_exclusive() {
            return Err("a shared owner got exclusive access without waiting");
        }
        if !starving(true) || held() != (false, 3, 0) || !yielding(true) || held() != (false, 4, 0)
        {
            return Err("with nobody waiting, the other shared routines did not acquire");
        }
        acquired += 4;
        for left in (0..4).rev() {
            let_go();
            if held() != (false, left, 0) {
                return Err("released as often as acquired, shared access is not gone");
            }
        }

        exclusive(true);
        // SAFETY: the static resource, owned exclusively by this thread.
        unsafe { ExConvertExclusiveToSharedLite(res()) };
        if held() != (false, 1, 0) {
            return Err("exclusive access was not converted to shared");
        }
        let_go();
        for take in [exclusive, shared] {
            take(true);
            // SAFETY: the static resource, owned by this thread.
            unsafe { ExReleaseResourceForThreadLite(res(), thread::current() as usize) };
            if held() != (false, 0, 0) {
                return Err("a release that names the thread did not release");
            }
        }
        acquired += 3;
        Ok(())
    })();
    KeLeaveCriticalRegion();
    result?;
    // SAFETY: the static resource, which nobody owns.
    if unsafe { ExReinitializeResourceLite(res()) } != STATUS_SUCCESS || held() != (false, 0, 0) {
        return Err("a reinitialised resource is not as new");
    }
    delete(before)?;
    Ok(acquired)
}

/// A thread waits for shared access behind an exclusive owner, is
/// counted, and owns the resource when the owner lets go.
pub fn hand_over_test() -> Result<(), &'static str> {
    let pool_before = pool::usage();
    fresh();
    let before = thread::count();
    KeEnterCriticalRegion();
    exclusive(true);
    let result = start(WANTS_SHARED).and_then(|()| {
        if !stress::until(stress::PROMPT_MS, || waiters() == (0, 1)) {
            return Err("a thread refused shared access is not counted as a shared waiter");
        }
        if tried() != (0, 0) || inside() != 0 {
            return Err("a thread got a resource owned exclusively by another");
        }
        Ok(())
    });
    let_go();
    let result = result.and_then(|()| {
        if !stress::until(stress::PROMPT_MS, || inside() == 1) {
            return Err("the shared waiter was never let in after the owner let go");
        }
        if WRONG.load(Ordering::Acquire) != 0 {
            return Err("the waiter was woken without being made an owner");
        }
        if waiters() != (0, 0) || held() != (false, 0, 0) {
            return Err("after the hand-over somebody still waits, or the old owner still owns");
        }
        if !shared(false) || held() != (false, 1, 0) {
            return Err("a second thread could not share the resource without waiting");
        }
        let got_exclusive = exclusive(false);
        let_go();
        if got_exclusive {
            return Err("exclusive access was had to a resource another thread shares");
        }
        Ok(())
    });
    KeLeaveCriticalRegion();
    result?;
    finish(before)?;
    delete(pool_before)
}

/// A thread waits for exclusive access behind a shared owner. The owner
/// still gets the resource again; a newcomer does not, unless it asks
/// to starve the waiter; and the waiter owns the resource when the
/// owner has let go as often as it acquired.
pub fn starve_test() -> Result<(), &'static str> {
    let pool_before = pool::usage();
    fresh();
    let before = thread::count();
    KeEnterCriticalRegion();
    shared(true);
    let mut owed = 1;
    let result = start(WANTS_EXCLUSIVE).and_then(|()| {
        if !stress::until(stress::PROMPT_MS, || waiters() == (1, 0)) {
            return Err("a thread refused exclusive access is not counted as an exclusive waiter");
        }
        if inside() != 0 {
            return Err("a thread got exclusive access to a shared resource");
        }
        if !shared(false) {
            return Err("a shared owner did not get the resource again past a waiter");
        }
        owed += 1;
        if held() != (false, 2, 0) {
            return Err("the owner's second acquisition was not counted");
        }
        if yielding(false) {
            owed += 1;
            return Err("the routine that yields to exclusive waiters did not yield");
        }
        start(NEWCOMER)?;
        stress::ended(before + 1);
        if tried() != (0, 1) {
            return Err("a newcomer got in past the waiter, or could not by starving it");
        }
        Ok(())
    });
    for left in (0..owed).rev() {
        let_go();
        if left == 1 && result.is_ok() && held() != (false, 1, 0) {
            KeLeaveCriticalRegion();
            return Err("one release of two gave up the resource");
        }
    }
    KeLeaveCriticalRegion();
    result?;
    if !stress::until(stress::PROMPT_MS, || inside() == 1) {
        return Err("the exclusive waiter was never let in after the owner let go");
    }
    if WRONG.load(Ordering::Acquire) != 0 {
        return Err("the waiter was woken without being made the owner");
    }
    if waiters() != (0, 0) {
        return Err("after the hand-over somebody is still counted as waiting");
    }
    KeEnterCriticalRegion();
    let got = shared(false);
    if got {
        let_go();
    }
    KeLeaveCriticalRegion();
    if got {
        return Err("a resource owned exclusively was shared without waiting");
    }
    finish(before)?;
    delete(pool_before)
}

const SHARERS: u32 = 12;

fn sharer(_: usize) {
    KeEnterCriticalRegion();
    shared(true);
    stay(held() == (false, 1, 0), false);
    KeLeaveCriticalRegion();
}

/// More threads share the resource than its first owner table has room
/// for: the table grows, every owner is still an owner afterwards, and
/// deleting the resource frees the table. Returns the table's entries.
pub fn table_test() -> Result<u32, &'static str> {
    let pool_before = pool::usage();
    fresh();
    let before = thread::count();
    for _ in 0..SHARERS {
        thread::create(sharer, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    }
    if !stress::until(stress::PROMPT_MS, || inside() == SHARERS) {
        return Err("the threads were not all let in to share the resource");
    }
    // SAFETY: the static resource; its owners are parked, so its fields
    // hold still.
    let (active, size) = unsafe {
        let _lock = Locked::take(res());
        (
            (&raw const (*res()).ActiveEntries).read(),
            table_size(res()),
        )
    };
    if active != SHARERS || size < SHARERS {
        return Err("the owners are not all counted, or the table has no room for them");
    }
    finish(before)?;
    if WRONG.load(Ordering::Acquire) != 0 {
        return Err("an owner was lost when the table grew");
    }
    delete(pool_before)?;
    Ok(size)
}

const THREADS: usize = 4;
const ROUNDS: u64 = 2000;
static WRITERS: AtomicU32 = AtomicU32::new(0);
static READERS: AtomicU32 = AtomicU32::new(0);
static CLASHES: AtomicU32 = AtomicU32::new(0);
/// Written only under exclusive access, by read, dawdle, write.
static VALUE: AtomicU64 = AtomicU64::new(0);
static WRITES: AtomicU64 = AtomicU64::new(0);

fn write_inside(round: u64) {
    if WRITERS.fetch_add(1, Ordering::AcqRel) != 0 || READERS.load(Ordering::Acquire) != 0 {
        CLASHES.fetch_add(1, Ordering::Relaxed);
    }
    let seen = VALUE.load(Ordering::Relaxed);
    if round % 64 == 0 {
        thread::yield_now();
    }
    VALUE.store(seen + 1, Ordering::Relaxed);
    WRITES.fetch_add(1, Ordering::Relaxed);
    WRITERS.fetch_sub(1, Ordering::AcqRel);
}

fn read_inside(round: u64) {
    READERS.fetch_add(1, Ordering::AcqRel);
    let seen = VALUE.load(Ordering::Relaxed);
    if round % 64 == 2 {
        thread::yield_now();
    }
    if WRITERS.load(Ordering::Acquire) != 0 || VALUE.load(Ordering::Relaxed) != seen {
        CLASHES.fetch_add(1, Ordering::Relaxed);
    }
    READERS.fetch_sub(1, Ordering::AcqRel);
}

fn contender(index: usize) {
    for round in 0..ROUNDS {
        KeEnterCriticalRegion();
        match (round + index as u64) % 5 {
            0 => {
                // Exclusive, taken twice over, then turned shared.
                exclusive(true);
                shared(true);
                write_inside(round);
                let_go();
                // SAFETY: the static resource, owned exclusively here.
                unsafe { ExConvertExclusiveToSharedLite(res()) };
                read_inside(round);
                let_go();
            }
            1 => {
                if try_exclusive() {
                    write_inside(round);
                    let_go();
                }
            }
            2 => {
                shared(true);
                shared(true);
                read_inside(round);
                let_go();
                let_go();
            }
            3 => {
                starving(true);
                read_inside(round);
                let_go();
            }
            _ => {
                yielding(true);
                read_inside(round);
                // SAFETY: the static resource, owned by this thread.
                unsafe { ExReleaseResourceForThreadLite(res(), thread::current() as usize) };
            }
        }
        KeLeaveCriticalRegion();
    }
}

/// Threads acquire the resource every way at once: a writer is alone
/// inside, readers see no write, nobody is left asleep, and nobody is
/// left an owner. Returns the writes.
pub fn contention_test() -> Result<u64, &'static str> {
    let pool_before = pool::usage();
    fresh();
    for counter in [&WRITERS, &READERS, &CLASHES] {
        counter.store(0, Ordering::Release);
    }
    VALUE.store(0, Ordering::Release);
    WRITES.store(0, Ordering::Release);
    stress::run(THREADS, contender)?;
    let writes = WRITES.load(Ordering::Acquire);
    if CLASHES.load(Ordering::Acquire) != 0 || VALUE.load(Ordering::Acquire) != writes {
        return Err("a writer was not alone inside the resource");
    }
    // SAFETY: the static resource; the threads have ended.
    let active = unsafe { (&raw const (*res()).ActiveEntries).read() };
    if active != 0 || held() != (false, 0, 0) || waiters() != (0, 0) {
        return Err("the resource was not left free");
    }
    delete(pool_before)?;
    Ok(writes)
}
