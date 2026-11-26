//! Interrupt objects: a driver's service routine connected to a device
//! interrupt.
//!
//! A `KINTERRUPT` is allocated here, with Windows' layout, and linked
//! into the chain of its vector: several objects share a vector when
//! their devices share a line. When the vector's interrupt arrives
//! ([`service`], at the vector's IRQL, on whichever processor the
//! controller sent it to), each object's routine is called at the
//! object's `SynchronizeIrql` with its spin lock held:
//!
//! - one object on the vector: its routine, once;
//! - several, level triggered: in turn, until one says the interrupt
//!   was its device's;
//! - several, edge triggered: all of them, again and again until a
//!   whole pass finds no device that asked, since one edge may stand
//!   for several devices.
//!
//! An interrupt no routine claims is counted ([`unclaimed`]).
//!
//! **The chain's gate.** A chain is walked without a lock a routine
//! could meet: a count of the processors walking it, and a bit that a
//! processor changing it sets, at `HIGH_LEVEL`, to hold new walkers
//! back and wait for the ones inside to leave (`doc/LOCKING.md`). So a
//! disconnected object is never in use by a service routine when it is
//! freed.

#![allow(non_snake_case)]

use super::{Rank, SpinLock, interrupt, irql, kspin, seh};
use crate::arch;
use crate::hal;
use crate::mm::pool;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};
use nk_hal::interrupt::{Polarity, Trigger};
use nk_ntabi::interrupt::{
    GROUP_AFFINITY, INTERRUPT_OBJECT, KINTERRUPT, KMESSAGE_SERVICE_ROUTINE, KSERVICE_ROUTINE,
    KSYNCHRONIZE_ROUTINE,
};
use nk_ntabi::io::DEVICE_OBJECT;
use nk_ntabi::ke::{KIRQL, KSPIN_LOCK, LIST_ENTRY};
use nk_ntabi::status::{
    NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
};

const TAG: u32 = u32::from_le_bytes(*b"Int ");
const VECTORS: usize = 1024;
/// Set in a gate while a processor changes the chain.
const CHANGING: u32 = 1 << 31;

/// The interrupt objects connected to one vector.
struct Chain {
    /// The processors walking the chain, and [`CHANGING`].
    gate: AtomicU32,
    /// The first object; the rest are linked to it in a ring through
    /// `InterruptListEntry`. Written only through the gate.
    first: AtomicPtr<KINTERRUPT>,
    /// Interrupts no service routine claimed.
    unclaimed: AtomicU32,
}

static CHAINS: [Chain; VECTORS] = [const {
    Chain {
        gate: AtomicU32::new(0),
        first: AtomicPtr::new(core::ptr::null_mut()),
        unclaimed: AtomicU32::new(0),
    }
}; VECTORS];

/// Serialises connecting and disconnecting, so that a vector's first
/// connection and last disconnection turn its interrupt on and off in
/// order.
static CONNECT: SpinLock<()> = SpinLock::new(Rank::InterruptConnect, ());

impl Chain {
    /// Walk the chain: `walk` is given the first object, or null.
    fn walking<R>(&self, walk: impl FnOnce(*mut KINTERRUPT) -> R) -> R {
        loop {
            let gate = self.gate.load(Ordering::Relaxed);
            if gate & CHANGING == 0
                && self
                    .gate
                    .compare_exchange_weak(gate, gate + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                break;
            }
            core::hint::spin_loop();
        }
        let result = walk(self.first.load(Ordering::Acquire));
        self.gate.fetch_sub(1, Ordering::Release);
        result
    }

    /// Change the chain, with no processor walking it: at `HIGH_LEVEL`,
    /// so the vector's interrupt cannot arrive here and wait for itself.
    fn changing<R>(&self, change: impl FnOnce(&AtomicPtr<KINTERRUPT>) -> R) -> R {
        let old = irql::raise(irql::HIGH_LEVEL);
        while self.gate.fetch_or(CHANGING, Ordering::Acquire) & CHANGING != 0 {
            // Another processor is changing it: wait for the bit to clear.
            while self.gate.load(Ordering::Relaxed) & CHANGING != 0 {
                core::hint::spin_loop();
            }
        }
        while self.gate.load(Ordering::Acquire) != CHANGING {
            core::hint::spin_loop();
        }
        let result = change(&self.first);
        self.gate.store(0, Ordering::Release);
        irql::lower(old);
        result
    }
}

/// The object whose `InterruptListEntry` is `entry`.
fn object_of(entry: *mut LIST_ENTRY) -> *mut KINTERRUPT {
    entry
        .wrapping_byte_sub(core::mem::offset_of!(KINTERRUPT, InterruptListEntry))
        .cast()
}

/// The object after `interrupt` in its ring.
///
/// # Safety
/// `interrupt` is a linked interrupt object, and the chain is being
/// walked or changed by the caller.
unsafe fn next(interrupt: *mut KINTERRUPT) -> *mut KINTERRUPT {
    // SAFETY: per the contract.
    object_of(unsafe { (&raw const (*interrupt).InterruptListEntry.Flink).read() })
}

/// A counter of an interrupt object, which a debugger may read.
///
/// # Safety
/// `field` points into a live interrupt object.
unsafe fn count(field: *mut u32) {
    // SAFETY: per the contract; several processors may count at once.
    unsafe { AtomicU32::from_ptr(field) }.fetch_add(1, Ordering::Relaxed);
}

/// Call one object's service routine: at its `SynchronizeIrql`, with
/// its lock held. Whether the routine claimed the interrupt.
///
/// # Safety
/// `interrupt` is a connected interrupt object and the chain is being
/// walked by the caller, at or below the object's `SynchronizeIrql`.
unsafe fn serve(interrupt: *mut KINTERRUPT) -> bool {
    // SAFETY: per the contract; the object's fields are read one by one
    // through the raw pointer.
    unsafe {
        let synchronize = (&raw const (*interrupt).SynchronizeIrql).read();
        let lock = (&raw const (*interrupt).ActualLock).read();
        let context = (&raw const (*interrupt).ServiceContext).read();
        let old = irql::current();
        if synchronize > old {
            arch::set_irql(synchronize);
        }
        kspin::acquire(lock);
        count(&raw mut (*interrupt).DispatchCount);
        // No driver's frame lies beneath a service routine.
        let guard = seh::Guard::Base(seh::Unhandled::KernelMode);
        let claimed = match (&raw const (*interrupt).MessageServiceRoutine).read() {
            Some(routine) => {
                let message = (&raw const (*interrupt).MessageIndex).read();
                seh::call(
                    routine as usize,
                    [interrupt as usize, context as usize, message as usize, 0],
                    &guard,
                )
            }
            None => {
                let routine = (&raw const (*interrupt).ServiceRoutine).read();
                let routine = routine.map_or(0, |r| r as usize);
                seh::call(
                    routine,
                    [interrupt as usize, context as usize, 0, 0],
                    &guard,
                )
            }
        } as u8
            != 0;
        kspin::word(lock).store(0, Ordering::Release);
        if synchronize > old {
            arch::set_irql(old);
        }
        if claimed {
            count(&raw mut (*interrupt).ServiceCount);
        }
        claimed
    }
}

/// The interrupt on `vector` arrived: call the service routines
/// connected to it. Runs at the vector's IRQL.
fn service(vector: u32) {
    let chain = &CHAINS[vector as usize];
    let claimed = chain.walking(|first| {
        if first.is_null() {
            return false;
        }
        // SAFETY: the chain is being walked, so its objects are linked
        // and live; every object of a chain has the same mode.
        unsafe {
            if next(first) == first {
                return serve(first);
            }
            let edge = (&raw const (*first).Mode).read() == Trigger::Edge.mode();
            let mut claimed = false;
            loop {
                let mut this_pass = false;
                let mut interrupt = first;
                loop {
                    if serve(interrupt) {
                        this_pass = true;
                        if !edge {
                            break;
                        }
                    }
                    interrupt = next(interrupt);
                    if interrupt == first {
                        break;
                    }
                }
                claimed |= this_pass;
                if !edge || !this_pass {
                    return claimed;
                }
            }
        }
    });
    if !claimed {
        chain.unclaimed.fetch_add(1, Ordering::Relaxed);
    }
}

/// How many interrupts on `vector` no service routine claimed.
pub fn unclaimed(vector: u32) -> u32 {
    CHAINS
        .get(vector as usize)
        .map_or(0, |c| c.unclaimed.load(Ordering::Relaxed))
}

/// How many interrupt objects are connected to `vector`, and how many
/// times their service routines have been called between them
/// (`DispatchCount`).
pub fn served(vector: u32) -> (u32, u32) {
    let Some(chain) = CHAINS.get(vector as usize) else {
        return (0, 0);
    };
    chain.walking(|first| {
        let (mut objects, mut calls) = (0, 0u32);
        if first.is_null() {
            return (objects, calls);
        }
        let mut interrupt = first;
        loop {
            objects += 1;
            // SAFETY: the chain is being walked, so its objects are
            // linked and live; the counter is read through a pointer,
            // other processors counting in it meanwhile.
            unsafe {
                calls = calls.wrapping_add(
                    AtomicU32::from_ptr(&raw mut (*interrupt).DispatchCount)
                        .load(Ordering::Relaxed),
                );
                interrupt = next(interrupt);
            }
            if interrupt == first {
                return (objects, calls);
            }
        }
    })
}

/// What a connection's service routine is.
#[derive(Clone, Copy)]
pub enum Routine {
    Line(KSERVICE_ROUTINE),
    /// A message's routine and the message's number.
    Message(KMESSAGE_SERVICE_ROUTINE, u32),
}

/// What to connect.
#[derive(Clone, Copy)]
pub struct Connection {
    pub vector: u32,
    pub irql: KIRQL,
    /// At least `irql`.
    pub synchronize_irql: KIRQL,
    pub trigger: Trigger,
    pub polarity: Polarity,
    /// Whether other objects may be connected to the vector.
    pub share: bool,
    pub routine: Routine,
    pub context: *mut c_void,
    /// The driver's lock, or null for the object's own.
    pub lock: *mut KSPIN_LOCK,
    pub floating_save: bool,
    pub device: *mut DEVICE_OBJECT,
}

/// Allocate an interrupt object for `connection` and connect it.
///
/// `STATUS_INVALID_PARAMETER`: the vector is not one a device's
/// translated resources name, the IRQL is not the vector's, the
/// synchronisation IRQL is below it, or the vector is in use and one
/// side does not share or signals differently.
///
/// # Safety
/// The routine, context and lock are the driver's, valid until the
/// object is disconnected.
pub unsafe fn connect(connection: &Connection) -> Result<*mut KINTERRUPT, NTSTATUS> {
    let info = hal::interrupt::info(connection.vector).ok_or(STATUS_INVALID_PARAMETER)?;
    if !hal::interrupt::is_device_vector(connection.vector)
        || connection.irql != info.level
        || connection.synchronize_irql < connection.irql
        || connection.synchronize_irql > irql::HIGH_LEVEL
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    let size = size_of::<KINTERRUPT>();
    let interrupt = pool::alloc_zeroed(size, TAG).cast::<KINTERRUPT>();
    if interrupt.is_null() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: a fresh, zeroed block of the object's size.
    unsafe {
        let own_lock = &raw mut (*interrupt).SpinLock;
        let (routine, message_routine, message) = match connection.routine {
            Routine::Line(routine) => (Some(routine), None, 0),
            Routine::Message(routine, message) => (None, Some(routine), message),
        };
        interrupt.write(KINTERRUPT {
            Type: INTERRUPT_OBJECT,
            Size: size as i16,
            InterruptListEntry: LIST_ENTRY {
                Flink: core::ptr::null_mut(),
                Blink: core::ptr::null_mut(),
            },
            ServiceRoutine: routine,
            MessageServiceRoutine: message_routine,
            MessageIndex: message,
            ServiceContext: connection.context,
            SpinLock: 0,
            TickCount: 0,
            ActualLock: if connection.lock.is_null() {
                own_lock
            } else {
                connection.lock
            },
            DispatchAddress: core::ptr::null_mut(),
            Vector: connection.vector,
            Irql: connection.irql,
            SynchronizeIrql: connection.synchronize_irql,
            FloatingSave: u8::from(connection.floating_save),
            Connected: 0,
            Number: u32::from(info.processor),
            ShareVector: u8::from(connection.share),
            EmulateActiveBoth: 0,
            ActiveCount: 0,
            InternalState: 0,
            Mode: connection.trigger.mode(),
            Polarity: connection.polarity.value(),
            ServiceCount: 0,
            DispatchCount: 0,
            PassiveEvent: core::ptr::null_mut(),
            TrapFrame: core::ptr::null_mut(),
            DisconnectData: core::ptr::null_mut(),
            ServiceThread: core::ptr::null_mut(),
            ConnectionData: core::ptr::null_mut(),
            IntTrackEntry: core::ptr::null_mut(),
            IsrDpcStats: [0; 12],
            RedirectObject: core::ptr::null_mut(),
            PhysicalDeviceObject: connection.device,
        });
        if activate(interrupt) {
            Ok(interrupt)
        } else {
            free(interrupt);
            Err(STATUS_INVALID_PARAMETER)
        }
    }
}

/// Free an interrupt object that is not connected.
///
/// # Safety
/// `interrupt` came from [`connect`] and is not in a chain.
unsafe fn free(interrupt: *mut KINTERRUPT) {
    if pool::free(interrupt.cast()).is_err() {
        crate::kd::bugcheck(format_args!(
            "{interrupt:p} is not an interrupt object to free"
        ));
    }
}

/// Link `interrupt` into its vector's chain, so its routine is called;
/// the vector's first object turns the interrupt on. `false`, and
/// nothing changed, if the vector is in use and either side does not
/// share it, or they signal differently. An object already linked
/// stays linked.
///
/// # Safety
/// `interrupt` is a live interrupt object from [`connect`].
pub unsafe fn activate(interrupt: *mut KINTERRUPT) -> bool {
    let _serial = CONNECT.lock();
    // SAFETY: per the contract; connection state changes only under
    // `CONNECT`.
    unsafe {
        if (*interrupt).Connected != 0 {
            return true;
        }
        let vector = (*interrupt).Vector;
        let chain = &CHAINS[vector as usize];
        let first = chain.first.load(Ordering::Acquire);
        if !first.is_null()
            && ((*first).ShareVector == 0
                || (*interrupt).ShareVector == 0
                || (*first).Mode != (*interrupt).Mode)
        {
            return false;
        }
        let entry = &raw mut (*interrupt).InterruptListEntry;
        chain.changing(|head| {
            if first.is_null() {
                (*entry).Flink = entry;
                (*entry).Blink = entry;
                head.store(interrupt, Ordering::Release);
            } else {
                // Before the first: at the end of the ring.
                let ring = &raw mut (*first).InterruptListEntry;
                let last = (*ring).Blink;
                (*entry).Flink = ring;
                (*entry).Blink = last;
                (*last).Flink = entry;
                (*ring).Blink = entry;
            }
        });
        (*interrupt).Connected = 1;
        if first.is_null() {
            interrupt::register(vector, (*interrupt).Irql, service);
            hal::interrupt::enable(vector, true);
        }
    }
    true
}

/// Unlink `interrupt` from its vector's chain: once this returns its
/// routine is not running and will not be called. The vector's last
/// object turns the interrupt off. An object not linked stays so.
///
/// # Safety
/// `interrupt` is a live interrupt object from [`connect`].
pub unsafe fn deactivate(interrupt: *mut KINTERRUPT) {
    let _serial = CONNECT.lock();
    // SAFETY: per the contract; as in `activate`.
    unsafe {
        if (*interrupt).Connected == 0 {
            return;
        }
        let vector = (*interrupt).Vector;
        let entry = &raw mut (*interrupt).InterruptListEntry;
        let alone = (*entry).Flink == entry;
        if alone {
            // Nothing is left to serve the interrupt: hold it back first.
            hal::interrupt::enable(vector, false);
        }
        CHAINS[vector as usize].changing(|head| {
            if alone {
                head.store(core::ptr::null_mut(), Ordering::Release);
            } else {
                let (after, before) = ((*entry).Flink, (*entry).Blink);
                (*before).Flink = after;
                (*after).Blink = before;
                if head.load(Ordering::Relaxed) == interrupt {
                    head.store(object_of(after), Ordering::Release);
                }
            }
        });
        (*interrupt).Connected = 0;
    }
}

/// Disconnect `interrupt` and free it.
///
/// # Safety
/// `interrupt` came from [`connect`] and is not used afterwards.
pub unsafe fn disconnect(interrupt: *mut KINTERRUPT) {
    // SAFETY: per the contract.
    unsafe {
        deactivate(interrupt);
        free(interrupt);
    }
}

/// [`KeAcquireInterruptSpinLock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keacquireinterruptspinlock):
/// raise to the interrupt's `SynchronizeIrql` and take its lock, which
/// keeps its service routine out on every processor. Returns the IRQL
/// to go back to.
///
/// # Safety
/// `interrupt` is a connected interrupt object.
pub unsafe extern "C" fn KeAcquireInterruptSpinLock(interrupt: *mut KINTERRUPT) -> KIRQL {
    // SAFETY: per the contract.
    unsafe {
        let old = kspin::set_irql((&raw const (*interrupt).SynchronizeIrql).read(), true);
        kspin::acquire((&raw const (*interrupt).ActualLock).read());
        old
    }
}

/// [`KeReleaseInterruptSpinLock`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kereleaseinterruptspinlock).
///
/// # Safety
/// The caller holds the interrupt's lock, taken with the routine above.
pub unsafe extern "C" fn KeReleaseInterruptSpinLock(interrupt: *mut KINTERRUPT, old_irql: KIRQL) {
    // SAFETY: per the contract.
    unsafe {
        kspin::word((&raw const (*interrupt).ActualLock).read()).store(0, Ordering::Release);
    }
    kspin::set_irql(old_irql, false);
}

/// What `KeSynchronizeExecution` holds while the driver's routine runs.
struct Held {
    interrupt: *mut KINTERRUPT,
    old_irql: KIRQL,
}

/// Give up what [`Held`] names: the routine did not return.
///
/// # Safety
/// `held` points to the `Held` of a call in progress.
unsafe fn let_go(held: *mut c_void) {
    // SAFETY: per the contract.
    unsafe {
        let held = held.cast::<Held>();
        KeReleaseInterruptSpinLock((*held).interrupt, (*held).old_irql);
    }
}

/// [`KeSynchronizeExecution`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kesynchronizeexecution):
/// run the driver's routine as the interrupt's service routine runs, at
/// its `SynchronizeIrql` with its lock held, so the two never run at
/// once. Returns what the routine returns.
///
/// # Safety
/// `interrupt` is a connected interrupt object; the routine may be
/// called with `context`.
pub unsafe extern "C" fn KeSynchronizeExecution(
    interrupt: *mut KINTERRUPT,
    routine: Option<KSYNCHRONIZE_ROUTINE>,
    context: *mut c_void,
) -> u8 {
    let Some(routine) = routine else {
        return 0;
    };
    // SAFETY: per the contract.
    unsafe {
        let mut held = Held {
            interrupt,
            old_irql: KeAcquireInterruptSpinLock(interrupt),
        };
        let guard = seh::Guard::Undo {
            undo: let_go,
            context: (&raw mut held).cast(),
        };
        let result = seh::call(routine as usize, [context as usize, 0, 0, 0], &guard) as u8;
        KeReleaseInterruptSpinLock(interrupt, held.old_irql);
        result
    }
}

/// [`IoGetAffinityInterrupt`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetaffinityinterrupt):
/// the processors the interrupt may arrive on: the one it is sent to,
/// of group 0.
///
/// # Safety
/// `interrupt` is a connected interrupt object, or null; `affinity` is
/// valid for writes, or null.
pub unsafe extern "C" fn IoGetAffinityInterrupt(
    interrupt: *mut KINTERRUPT,
    affinity: *mut GROUP_AFFINITY,
) -> NTSTATUS {
    if interrupt.is_null() || affinity.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract.
    unsafe {
        affinity.write(GROUP_AFFINITY {
            Mask: 1 << (&raw const (*interrupt).Number).read(),
            Group: 0,
            Reserved: [0; 3],
        });
    }
    STATUS_SUCCESS
}
