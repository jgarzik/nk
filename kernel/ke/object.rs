//! Dispatcher objects: what a thread can wait on.
//!
//! Every such object begins with a `DISPATCHER_HEADER`: its type, a
//! signal state, and the list of wait blocks of the threads waiting for
//! it. The driver owns the object; NK reads and writes it through the
//! driver's pointer, under the object's own lock, which is bit 7 of the
//! header's type byte, as on Windows.
//!
//! An object's lock covers its signal state, its wait list, and the wait
//! blocks linked into that list. It is taken at `DISPATCH_LEVEL`, before
//! any ranked lock, and no thread is made ready with one held: a waker
//! collects the threads it has claimed and readies them after letting
//! go (`doc/LOCKING.md`).

use super::{irql, mutex, thread};
use crate::arch;
use core::sync::atomic::{AtomicI32, AtomicU8, Ordering};
use nk_ke::Claimed;
use nk_ntabi::ke::{
    DISPATCHER_HEADER, EVENT_SYNCHRONIZATION_OBJECT, KWAIT_BLOCK, LIST_ENTRY, MUTANT_OBJECT,
    OBJECT_LOCK, SEMAPHORE_OBJECT, TIMER_SYNCHRONIZATION_OBJECT, WAIT_BLOCK_ACTIVE,
    WAIT_BLOCK_INACTIVE,
};

/// # Safety
/// `object` points to a live dispatcher object.
unsafe fn type_byte<'a>(object: *mut DISPATCHER_HEADER) -> &'a AtomicU8 {
    // SAFETY: per the contract.
    unsafe { AtomicU8::from_ptr(&raw mut (*object).Type) }
}

/// The object's signal state.
///
/// # Safety
/// `object` points to a live dispatcher object.
pub unsafe fn signal<'a>(object: *mut DISPATCHER_HEADER) -> &'a AtomicI32 {
    // SAFETY: per the contract.
    unsafe { AtomicI32::from_ptr(&raw mut (*object).SignalState) }
}

/// `KWAIT_BLOCK.WaitType`: the block is part of a wait for all.
const WAIT_ALL: u8 = 0;
/// `KWAIT_BLOCK.WaitType`: the block belongs to a `WaitCompletionPacket` (`ex::tp`).
pub const WAIT_WCP: u8 = 2;

/// An object's lock, held at `DISPATCH_LEVEL` until dropped.
pub struct ObjectLock {
    object: *mut DISPATCHER_HEADER,
    old_irql: u8,
}

impl ObjectLock {
    /// # Safety
    /// `object` points to a dispatcher object that stays valid for as
    /// long as the lock is held.
    pub unsafe fn take(object: *mut DISPATCHER_HEADER) -> Self {
        let old_irql = irql::current();
        if old_irql < irql::DISPATCH_LEVEL {
            arch::set_irql(irql::DISPATCH_LEVEL);
        }
        // SAFETY: per the contract.
        let byte = unsafe { type_byte(object) };
        while byte.fetch_or(OBJECT_LOCK, Ordering::Acquire) & OBJECT_LOCK != 0 {
            core::hint::spin_loop();
        }
        Self { object, old_irql }
    }
}

impl Drop for ObjectLock {
    fn drop(&mut self) {
        // SAFETY: the object was live when the lock was taken and stays
        // so while it is held.
        unsafe { type_byte(self.object) }.fetch_and(!OBJECT_LOCK, Ordering::Release);
        arch::set_irql(self.old_irql);
    }
}

/// What kind of object this is.
///
/// # Safety
/// `object` points to a live dispatcher object.
unsafe fn kind(object: *mut DISPATCHER_HEADER) -> u8 {
    // SAFETY: per the contract.
    unsafe { type_byte(object) }.load(Ordering::Relaxed) & !OBJECT_LOCK
}

/// Whether `thread` may take the object as it stands: it is signalled,
/// or it is a mutex the thread already owns.
///
/// # Safety
/// `object` is live and its lock is held.
pub unsafe fn available(object: *mut DISPATCHER_HEADER, thread: *mut thread::Thread) -> bool {
    // SAFETY: per the contract.
    unsafe {
        signal(object).load(Ordering::Relaxed) > 0
            || (kind(object) == MUTANT_OBJECT && mutex::owner(object.cast()) == thread)
    }
}

/// `thread` takes the object: use up what taking this kind of object
/// uses up. An event or timer that lets one waiter through and a
/// semaphore's count go down by one; a mutex gets its owner.
///
/// # Safety
/// `object` is live, its lock is held, and it is `available` to
/// `thread`, which is the running thread or one the caller has claimed.
pub unsafe fn take(object: *mut DISPATCHER_HEADER, thread: *mut thread::Thread) {
    // SAFETY: per the contract.
    unsafe {
        match kind(object) {
            EVENT_SYNCHRONIZATION_OBJECT | SEMAPHORE_OBJECT | TIMER_SYNCHRONIZATION_OBJECT => {
                signal(object).fetch_sub(1, Ordering::Relaxed);
            }
            MUTANT_OBJECT => mutex::taken(object.cast(), thread),
            _ => {}
        }
    }
}

/// Make an object's wait list empty.
///
/// # Safety
/// `object` points to writable storage for a dispatcher object nothing
/// waits on.
pub unsafe fn init_wait_list(object: *mut DISPATCHER_HEADER) {
    // SAFETY: per the contract. An empty list points at itself.
    unsafe {
        let head = &raw mut (*object).WaitListHead;
        head.write(LIST_ENTRY {
            Flink: head,
            Blink: head,
        });
    }
}

/// Link `block`, already filled in, at the end of the object's wait
/// list.
///
/// # Safety
/// `object` is live and its lock is held; `block` is a wait block of a
/// live thread, linked nowhere.
pub unsafe fn link(object: *mut DISPATCHER_HEADER, block: *mut KWAIT_BLOCK) {
    // SAFETY: per the contract; the list is circular through the head.
    unsafe {
        let head = &raw mut (*object).WaitListHead;
        let entry = block.cast::<LIST_ENTRY>();
        let last = (*head).Blink;
        entry.write(LIST_ENTRY {
            Flink: head,
            Blink: last,
        });
        (&raw mut (*last).Flink).write(entry);
        (&raw mut (*head).Blink).write(entry);
        (&raw mut (*block).BlockState).write(WAIT_BLOCK_ACTIVE);
    }
}

/// Unlink `block` from the object it is linked on, if it still is.
///
/// # Safety
/// The lock of the object `block` was linked on is held.
pub unsafe fn unlink(block: *mut KWAIT_BLOCK) {
    // SAFETY: per the contract; a linked block's neighbours are live.
    unsafe {
        if (&raw const (*block).BlockState).read() != WAIT_BLOCK_ACTIVE {
            return;
        }
        let LIST_ENTRY { Flink, Blink } = block.cast::<LIST_ENTRY>().read();
        (&raw mut (*Blink).Flink).write(Flink);
        (&raw mut (*Flink).Blink).write(Blink);
        (&raw mut (*block).BlockState).write(WAIT_BLOCK_INACTIVE);
    }
}

/// Threads a waker has claimed and must make ready, plus any wait completion
/// packets fired by the signal, once it has let go of the object.
#[must_use = "claimed threads sleep for ever unless they are made ready"]
pub struct Woken {
    threads: *mut thread::Thread,
    wcps: *mut u8,
}

impl Woken {
    pub const fn none() -> Self {
        Self {
            threads: core::ptr::null_mut(),
            wcps: core::ptr::null_mut(),
        }
    }

    /// Make claimed threads ready and fire associated wait completion packets.
    /// No object lock may be held.
    pub fn ready(self) {
        let mut next = self.threads;
        while !next.is_null() {
            let thread = next;
            // SAFETY: claimed asleep, the thread is this waker's alone
            // until it is made ready; its link was written in `satisfy`.
            unsafe {
                next = thread::take_wake_link(thread);
                thread::make_ready(thread);
            }
        }
        let mut wcp = self.wcps;
        while !wcp.is_null() {
            let cur = wcp;
            // SAFETY: `cur` was unlinked and owns a reference transferred from `satisfy`.
            unsafe {
                wcp = crate::ex::tp::take_wcp_wake_link(cur);
                crate::ex::tp::fire_wcp(cur);
            }
        }
    }
}

/// Let waiting threads take what the object's signal state allows, in
/// the order they began waiting. Each is claimed with its wait block's
/// key as the status its wait returns, and takes the object as it is
/// claimed: a mutex has its new owner before that owner has run.
///
/// # Safety
/// `object` is live and its lock is held.
pub unsafe fn satisfy(object: *mut DISPATCHER_HEADER) -> Woken {
    let mut woken = Woken::none();
    // SAFETY: per the contract. Linked blocks belong to live threads or WCPs:
    // a thread unlinks its blocks, under this lock, before its wait returns.
    unsafe {
        let state = signal(object);
        let head = &raw mut (*object).WaitListHead;
        let mut entry = (*head).Flink;
        while entry != head && state.load(Ordering::Relaxed) > 0 {
            let block = entry.cast::<KWAIT_BLOCK>();
            entry = (*entry).Flink;
            let wait_type = (&raw const (*block).WaitType).read();
            if wait_type == WAIT_WCP {
                let wcp = (&raw const (*block).Thread).read().cast::<u8>();
                unlink(block);
                if kind(object) != MUTANT_OBJECT {
                    take(object, core::ptr::null_mut());
                }
                crate::ex::tp::set_wcp_wake_link(wcp, woken.wcps);
                woken.wcps = wcp;
                continue;
            }
            let waiter = (&raw const (*block).Thread).read().cast::<thread::Thread>();
            let key = u32::from((&raw const (*block).WaitKey).read());
            // A thread already woken by something else keeps its block
            // here until it gets round to unlinking it: pass over it.
            let Some(found) = thread::wait_register(waiter).claim(key) else {
                continue;
            };
            unlink(block);
            // A thread waiting for all of several objects takes them
            // itself, all or none, when it has looked: it is only woken.
            if (&raw const (*block).WaitType).read() != WAIT_ALL {
                take(object, waiter);
            }
            if found == Claimed::Asleep {
                thread::set_wake_link(waiter, woken.threads);
                woken.threads = waiter;
            }
        }
    }
    woken
}
