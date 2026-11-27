//! NK's lock for its own data: a spin lock with a rank.
//!
//! This is not the driver-visible `KSPIN_LOCK`. Taking one:
//!
//! - raises the IRQL to the level of the lock's rank, so that nothing
//!   which could want the same lock (another thread on this processor, a
//!   DPC, for the console even an interrupt) can run here while it is
//!   held;
//! - waits its turn: waiters are served in order of arrival;
//! - is checked against the locks this processor already holds: ranks
//!   rise strictly inward, and a lock is never taken twice.
//!
//! Releasing must happen in the reverse order of taking, which is what
//! dropping guards in scope order does. A broken rule stops the system;
//! `doc/LOCKING.md` lists the ranks and the reasons.

use super::irql;
use crate::arch;
use core::cell::UnsafeCell;
use core::ops::{Deref, DerefMut};
use nk_ke::TicketLock;

/// The order in which locks may nest: a lock may be taken only while every
/// lock held has a lower rank. See `doc/LOCKING.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Rank {
    /// The loaded-driver records (`io::driver`).
    Drivers = 10,
    /// The devices registered for a shutdown request (`io::shutdown`).
    Shutdown = 11,
    /// The device tree and what drivers asked of the Plug and Play
    /// manager (`pnp`).
    DeviceTree = 20,
    /// Whether a volume parameter block is mounted, on what, and its
    /// reference count (`io::mount`).
    Vpb = 24,
    /// Devices' reference counts, delete-pending marks and attachment
    /// chains (`io::device`).
    IoDatabase = 25,
    /// The errata manager's database (`ex::em`).
    Errata = 26,
    /// Devices registered with WMI and the requests owed them
    /// (`io::wmi`).
    IoWmi = 27,
    /// The sources of hardware errors (`whea`).
    Whea = 28,
    /// Which interrupts each device has been given (`io::interrupt`).
    DeviceInterrupts = 29,
    /// The object namespace (`ob`).
    Namespace = 30,
    /// The routines registered with the kernel debugger for power
    /// transitions (`kd::debugger`).
    KdPower = 31,
    /// The registry (`cm`).
    Registry = 33,
    /// The watches on registry keys (`cm::notify`).
    RegistryWatches = 34,
    /// The kernel handle table (`ob::handle`).
    Handles = 35,
    /// The ranges of the dynamic kernel region that are handed out
    /// (`mm::map`).
    Mappings = 36,
    /// The power manager's records (`po`).
    Power = 37,
    /// The firmware table providers drivers registered (`ex::firmware`).
    FirmwareTables = 38,
    /// The firmware's variable services, entered one call at a time
    /// (`hal::variables`).
    FirmwareVariables = 39,
    /// The executive pool (`mm::pool`).
    Pool = 40,
    /// Kernel address space and page tables (`mm::map`).
    AddressSpace = 50,
    /// The frame allocator (`mm`).
    Frames = 60,
    /// The interprocessor call in progress (`ke::ipi`).
    Ipi = 200,
    /// A queue of work items (`ex::work`).
    WorkQueue = 210,
    /// Connecting and disconnecting interrupt objects (`ke::kinterrupt`).
    InterruptConnect = 212,
    /// A queue of threads waiting for push locks (`ex::pushlock`).
    PushLock = 215,
    /// A thread's APC queues (`ke::apc`).
    Apc = 216,
    /// What a boot's UUIDs share (`ex::uuid`).
    Uuid = 217,
    /// Which vector each device interrupt has, and the interrupt
    /// controllers' routing registers (`hal::interrupt`).
    InterruptRouting = 218,
    /// The registrations of every callback object (`ex::callback`).
    Callbacks = 219,
    /// A processor's ready queues (`ke::thread`).
    Ready = 220,
    /// A processor's table of pending timers (`ke::timer`).
    TimerTable = 230,
    /// The store of security descriptors (`ob::security`).
    Descriptors = 232,
    /// Silo context slots and the host silo's storage (`ps::silo`).
    Silo = 233,
    /// What every thread impersonates (`se::impersonate`).
    Impersonation = 234,
    /// An object's own lock, a word of its header (`ob::security`):
    /// innermost of the locks held at `DISPATCH_LEVEL`.
    ObjectHeader = 235,
    /// PCI configuration space (`hal::pci`): read and written from any
    /// context.
    PciConfig = 238,
    /// A processor's queue of deferred procedure calls (`ke::dpc`).
    DpcQueue = 240,
    /// The bugcheck callback records drivers registered (`ke::bugcheck`):
    /// registered and taken back at any IRQL.
    BugCheckCallbacks = 242,
    /// The table of loaded images (`ldr`): searched from any context.
    Modules = 245,
    /// The diagnostic console (`kd`): innermost, so anything can print.
    Console = 250,
}

impl Rank {
    /// The IRQL at which locks of this rank are held.
    const fn level(self) -> u8 {
        match self {
            // Usable from any context, an interrupt included.
            Rank::Console
            | Rank::Modules
            | Rank::BugCheckCallbacks
            | Rank::DpcQueue
            | Rank::PciConfig => irql::HIGH_LEVEL,
            _ => irql::DISPATCH_LEVEL,
        }
    }
}

/// Update this processor's record of the locks it holds. The caller is
/// at `DISPATCH_LEVEL` or above, so stays on this processor.
///
/// The update runs with interrupts off. An interrupt handler may take a
/// lock too (the console, a DPC queue), and one arriving half-way
/// through an update would read, and then overwrite, a record that is
/// not yet whole. Masking interrupts costs less than raising the IRQL to
/// `HIGH_LEVEL` and back, and keeps them out as surely.
fn held<R>(update: impl FnOnce(&mut nk_ke::Held) -> R) -> R {
    let saved = arch::interrupts_off();
    // SAFETY: with interrupts off nothing else runs on this processor,
    // and the reference ends with the closure.
    let result = update(unsafe { arch::percpu().held() });
    arch::interrupts_restore(saved);
    result
}

/// Raise to the level of `rank` and enter the lock `id` in the record:
/// the part of taking a lock that is the same for every kind. Returns
/// the IRQL to go back to. Not generic, so one copy serves every
/// `SpinLock<T>`.
fn enter(id: usize, rank: Rank) -> u8 {
    let old_irql = irql::raise(rank.level());
    if let Err(v) = held(|held| held.acquire(id, rank as u8)) {
        irql::violation(v);
    }
    old_irql
}

/// Strike the lock `id` from the record and go back to `old_irql`: the
/// reverse of [`enter`], once the lock's word is free.
fn leave(id: usize, old_irql: u8) {
    if let Err(v) = held(|held| held.release(id)) {
        irql::violation(v);
    }
    irql::lower(old_irql);
}

/// Take `lock`, known by `id`, of `rank`: what [`SpinLock::lock`] does,
/// apart from its type.
fn acquire(lock: &TicketLock, id: usize, rank: Rank) -> u8 {
    let old_irql = enter(id, rank);
    lock.lock();
    old_irql
}

/// Free `lock` and undo [`acquire`].
fn release(lock: &TicketLock, id: usize, old_irql: u8) {
    lock.unlock();
    leave(id, old_irql);
}

/// A hold on a lock whose word is not a [`SpinLock`]'s: one that lies
/// where Windows has it, in an object's header. The holder spins on the
/// word itself; this raises the IRQL to the level of `rank` and enters
/// the lock, known by the address `id`, in the processor's record, so
/// the rules of rank apply to it as to any other. Dropping it does the
/// reverse; the word is to be free again by then.
pub struct Ranked {
    id: usize,
    old_irql: u8,
}

impl Ranked {
    pub fn enter(id: usize, rank: Rank) -> Self {
        Self {
            id,
            old_irql: enter(id, rank),
        }
    }
}

impl Drop for Ranked {
    fn drop(&mut self) {
        leave(self.id, self.old_irql);
    }
}

pub struct SpinLock<T> {
    lock: TicketLock,
    rank: Rank,
    value: UnsafeCell<T>,
}

// SAFETY: the lock gives one holder at a time exclusive access to `T`.
unsafe impl<T: Send> Sync for SpinLock<T> {}

pub struct Guard<'a, T> {
    lock: &'a SpinLock<T>,
    /// The IRQL to return to.
    old_irql: u8,
}

/// The lock taken by force on the way to stopping the system. It is never
/// released: nothing runs afterwards.
pub struct Forced<'a, T>(&'a SpinLock<T>);

impl<T> SpinLock<T> {
    pub const fn new(rank: Rank, value: T) -> Self {
        Self {
            lock: TicketLock::new(),
            rank,
            value: UnsafeCell::new(value),
        }
    }

    fn id(&self) -> usize {
        core::ptr::from_ref(self).addr()
    }

    pub fn lock(&self) -> Guard<'_, T> {
        Guard {
            lock: self,
            old_irql: acquire(&self.lock, self.id(), self.rank),
        }
    }

    /// Take the lock even if it is held, checking nothing. For the path
    /// that stops the system only: the holder will never run again.
    pub fn force_lock(&self) -> Forced<'_, T> {
        arch::set_irql(irql::HIGH_LEVEL);
        self.lock.force();
        Forced(self)
    }
}

impl<T> Deref for Guard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: holding the guard means holding the lock.
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> DerefMut for Guard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: holding the guard means holding the lock.
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> Drop for Guard<'_, T> {
    fn drop(&mut self) {
        release(&self.lock.lock, self.lock.id(), self.old_irql);
    }
}

impl<T> Deref for Forced<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        // SAFETY: the system is stopping; this processor is the only one
        // that will touch the value again.
        unsafe { &*self.0.value.get() }
    }
}

// ---- tests --------------------------------------------------------------

use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use nk_ntabi::ke::KDPC;

/// A lock ordinary code takes, and one an interrupt handler takes.
static OUTER: SpinLock<u64> = SpinLock::new(Rank::Drivers, 0);
static INNER: SpinLock<u64> = SpinLock::new(Rank::DpcQueue, 0);
static FLOODING: AtomicBool = AtomicBool::new(false);
/// Interrupts the handler has taken.
static HANDLED: AtomicU64 = AtomicU64::new(0);

/// The most interrupts the test sends.
const FLOOD: u64 = 200_000;

struct FloodDpc(UnsafeCell<core::mem::MaybeUninit<KDPC>>);
// SAFETY: accessed only through the DPC routines, by pointer.
unsafe impl Sync for FloodDpc {}
static FLOOD_DPC: FloodDpc = FloodDpc(UnsafeCell::new(core::mem::MaybeUninit::uninit()));

fn take_inner(_: u32) {
    *INNER.lock() += 1;
    HANDLED.fetch_add(1, Ordering::Release);
}

/// Interrupt processor 0 over and over, from another processor.
///
/// # Safety
/// Called as a DPC routine; it dereferences none of its arguments.
unsafe extern "C" fn flood(_: *mut KDPC, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
    // As many as fit in a third of a second: an emulated machine is
    // slow, and a DPC must not run long.
    let deadline = super::time::interrupt_time() + 3_000_000;
    for sent in 0..FLOOD {
        if super::time::interrupt_time() > deadline {
            break;
        }
        arch::interrupt_processor(0, arch::TEST_LOW.0);
        // Wait for it to be taken, so that none merges with the next.
        let mut patience = 100_000;
        while HANDLED.load(Ordering::Acquire) <= sent && patience > 0 {
            core::hint::spin_loop();
            patience -= 1;
        }
    }
    FLOODING.store(false, Ordering::Release);
}

fn start_flood(_: usize) {
    // SAFETY: static storage for a `KDPC` that is not queued.
    unsafe {
        let dpc = FLOOD_DPC.0.get().cast::<KDPC>();
        super::dpc::KeInitializeDpc(dpc, Some(flood), core::ptr::null_mut());
        super::dpc::KeInsertQueueDpc(dpc, core::ptr::null_mut(), core::ptr::null_mut());
    }
}

/// Interrupts whose handler takes a lock arrive, from another processor
/// and so at any instant, while this one takes and releases a lock as
/// fast as it can. The record of locks held must survive. Returns how
/// many times the handler took its lock.
pub fn interrupted_test() -> Result<u64, &'static str> {
    let (vector, level) = arch::TEST_LOW;
    *INNER.lock() = 0;
    HANDLED.store(0, Ordering::Relaxed);
    super::interrupt::register(vector, level, take_inner);
    let other = super::smp::online_count() - 1;
    let mut taken = 0u64;
    if other == 0 {
        // Alone: the interrupts can only come between the locks.
        for _ in 0..FLOOD / 100 {
            arch::self_interrupt(vector);
            *OUTER.lock() += 1;
            taken += 1;
        }
    } else {
        FLOODING.store(true, Ordering::Release);
        super::ipi::call_on(other, start_flood, 0);
        while FLOODING.load(Ordering::Acquire) {
            *OUTER.lock() += 1;
            taken += 1;
        }
    }
    super::time::stall(1000);
    super::interrupt::unregister(vector);
    let handled = *INNER.lock();
    if taken == 0 || handled == 0 {
        return Err("no lock was taken under interrupts");
    }
    if irql::current() != irql::PASSIVE_LEVEL {
        return Err("the IRQL did not come back down");
    }
    Ok(handled)
}
