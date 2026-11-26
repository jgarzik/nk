//! Silos: there is one, the host, and it is spelled null.
//!
//! A silo is a job that isolates what runs in it (a container). NK has
//! no jobs, so the only silo is the host silo, which Windows too names
//! by a null pointer. What drivers do with silos is nonetheless real
//! here, for that one silo:
//!
//! - a thread can be attached to a silo, which is one field of the
//!   thread (`ETHREAD.Silo`), as on Windows;
//! - drivers allocate slots and keep one context per slot in the host
//!   silo's storage. A context is an object; the storage holds a
//!   reference;
//! - a silo monitor is told when silos come and go. The host silo is
//!   there from the start, so a monitor that watches the host hears of
//!   it when the monitor starts, and of its end when the monitor is
//!   unregistered; no other silo is ever announced.
//!
//! A silo pointer that is not null names no silo: where Windows would
//! go on to read the job behind it, NK stops by name.
//!
//! Two locks (`doc/LOCKING.md`). The slots and the host's storage are
//! under a spin lock, held to read or change a word. Starting and
//! unregistering monitors is serialised by a mutex, held while the
//! monitor's callbacks run, as Windows holds its monitor lock; a mutex
//! also keeps kernel APCs off, like the critical region Windows calls
//! them in.

#![allow(non_snake_case)]

use crate::ke::seh::{self, Guard};
use crate::ke::{Rank, SpinLock, mutex, thread, wait};
use crate::mm::pool;
use crate::ob::object;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use nk_ntabi::ke::KMUTANT;
use nk_ntabi::process as process_layout;
use nk_ntabi::silo::{SILO_MONITOR_REGISTRATION, THREAD_NOT_ATTACHED};
use nk_ntabi::status::*;
use nk_ntabi::thread as thread_layout;
use nk_ps::silo::{SLOTS, Slots};

/// Pool tag of silo monitors, Windows' own for them.
const MONITOR_TAG: u32 = u32::from_le_bytes(*b"SilM");

/// `PagedPool` and `NonPagedPoolNx`: the pools a context may ask for.
const PAGED_POOL: u32 = 1;
const NON_PAGED_POOL_NX: u32 = 0x200;

/// Stop: `silo` is not null, and there is no silo but the host.
fn no_such_silo(routine: &str, silo: *mut c_void) -> ! {
    crate::kd::bugcheck(format_args!(
        "{routine}: {silo:p} is not a silo: there is none but the host silo, which is null"
    ))
}

/// The calling thread's `ETHREAD.Silo`.
fn attached() -> *mut *mut c_void {
    thread::object_field(thread::current(), thread_layout::SILO)
}

/// [`PsAttachSiloToCurrentThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psattachsilotocurrentthread):
/// attach the calling thread to `silo` and return what it was attached
/// to, for [`PsDetachSiloFromCurrentThread`] to put back. A thread
/// attached to nothing, which is how a thread starts, returns Windows'
/// mark for that (-3), not a silo.
pub extern "C" fn PsAttachSiloToCurrentThread(silo: *mut c_void) -> *mut c_void {
    // SAFETY: a pointer-aligned field of the running thread's block,
    // which only the thread itself reads and writes.
    unsafe { attached().replace(silo) }
}

/// [`PsDetachSiloFromCurrentThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psdetachsilofromcurrentthread):
/// put back what [`PsAttachSiloToCurrentThread`] returned.
pub extern "C" fn PsDetachSiloFromCurrentThread(previous: *mut c_void) {
    // SAFETY: as in `PsAttachSiloToCurrentThread`.
    unsafe { attached().write(previous) };
}

/// The calling thread's process's field at `offset`: a job or a silo,
/// and so null. Anything else there is not NK's doing.
fn of_process(routine: &str, offset: usize) -> *mut c_void {
    // SAFETY: the running thread names its process, which lives for
    // ever, at pointer-aligned offsets.
    let found = unsafe {
        thread::object_field::<*mut u8>(thread::current(), thread_layout::PROCESS)
            .read()
            .add(offset)
            .cast::<*mut c_void>()
            .read()
    };
    if !found.is_null() {
        no_such_silo(routine, found);
    }
    found
}

/// [`PsGetCurrentSilo`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetcurrentsilo):
/// the silo the calling thread is attached to, or else the silo of its
/// process's job. The System process is in no job, so that is the host
/// silo: null.
pub extern "C" fn PsGetCurrentSilo() -> *mut c_void {
    // SAFETY: as in `PsAttachSiloToCurrentThread`.
    let silo = unsafe { attached().read() };
    if silo.addr() != THREAD_NOT_ATTACHED {
        return silo;
    }
    of_process("PsGetCurrentSilo", process_layout::JOB)
}

/// [`PsGetCurrentServerSilo`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetcurrentserversilo):
/// the server silo the calling thread is in, or null in none: the
/// process's (`EPROCESS.ServerSilo`) for a thread attached to nothing,
/// none for a thread attached to the host silo. Windows also answers
/// null from an interrupt or a DPC routine, where the thread is
/// anybody's; that is the answer here in any case.
pub extern "C" fn PsGetCurrentServerSilo() -> *mut c_void {
    // SAFETY: as in `PsAttachSiloToCurrentThread`.
    let silo = unsafe { attached().read() };
    if silo.addr() == THREAD_NOT_ATTACHED {
        return of_process("PsGetCurrentServerSilo", process_layout::SERVER_SILO);
    }
    if !silo.is_null() {
        no_such_silo("PsGetCurrentServerSilo", silo);
    }
    silo
}

/// [`PsIsHostSilo`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psishostsilo):
/// the host silo is the null one.
pub extern "C" fn PsIsHostSilo(silo: *mut c_void) -> u8 {
    u8::from(silo.is_null())
}

/// [`PsGetJobSilo`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetjobsilo):
/// the silo a job is, or is in. It wants a job
/// (`STATUS_INVALID_PARAMETER` for none, and nothing is written), and
/// there are no jobs: any other pointer stops the system.
pub extern "C" fn PsGetJobSilo(job: *mut c_void, _silo: *mut *mut c_void) -> NTSTATUS {
    if job.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    crate::kd::bugcheck(format_args!(
        "PsGetJobSilo: {job:p} is not a job: there are none"
    ))
}

// ---- contexts and slots -------------------------------------------------

/// What NK keeps about a silo context, in front of the object
/// (`ob::object::own_record`): the silo it was made for and the
/// driver's routine to call when it goes.
#[repr(C)]
struct ContextRecord {
    silo: *mut c_void,
    cleanup: usize,
}

/// How much room that takes.
pub const CONTEXT_RECORD: usize = size_of::<ContextRecord>();

/// Whether `body` is a silo context.
///
/// # Safety
/// `body` is an object-manager object.
unsafe fn is_context(body: *mut u8) -> bool {
    // SAFETY: per the contract.
    let ty = unsafe { object::type_of(body) };
    core::ptr::eq(ty, &raw const object::SILO_CONTEXT_PAGED_TYPE)
        || core::ptr::eq(ty, &raw const object::SILO_CONTEXT_NONPAGED_TYPE)
}

/// The delete procedure of both context types: the driver's cleanup
/// routine is called with the context, once, before its memory goes.
///
/// # Safety
/// `body` is a silo context nothing refers to any more.
pub unsafe extern "C" fn context_deleted(body: *mut c_void) {
    // SAFETY: per the contract: the record `PsCreateSiloContext` wrote.
    // The routine is the driver's, given for exactly this call. An
    // exception it lets out owes nothing: the context is then left
    // allocated, as it would be on Windows.
    unsafe {
        let record = object::own_record(body.cast())
            .cast::<ContextRecord>()
            .read();
        if record.cleanup != 0 {
            seh::call(record.cleanup, [body.addr(), 0, 0, 0], &Guard::Nothing);
        }
    }
}

/// [`PsCreateSiloContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pscreatesilocontext):
/// a context of `size` bytes for `silo`, an object with one reference,
/// the caller's ([`PsDereferenceSiloContext`]). `cleanup`, if any, is
/// called with the context when the last reference goes. The pool is
/// `PagedPool` or `NonPagedPoolNx` and decides the object's type, as
/// on Windows; any other is `STATUS_INVALID_PARAMETER`. NK's pool does
/// not page either kind out.
///
/// # Safety
/// `context` points to room for a pointer; `cleanup` is null or a
/// routine that may be called with the context.
pub unsafe extern "C" fn PsCreateSiloContext(
    silo: *mut c_void,
    size: u32,
    pool_type: u32,
    cleanup: *mut c_void,
    context: *mut *mut c_void,
) -> NTSTATUS {
    let ty = match pool_type {
        PAGED_POOL => &object::SILO_CONTEXT_PAGED_TYPE,
        NON_PAGED_POOL_NX => &object::SILO_CONTEXT_NONPAGED_TYPE,
        _ => return STATUS_INVALID_PARAMETER,
    };
    let Some(body) = object::create(ty, size as usize) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: a fresh context, whose block begins with room for the
    // record; per the contract for the result.
    unsafe {
        object::own_record(body)
            .cast::<ContextRecord>()
            .write(ContextRecord {
                silo,
                cleanup: cleanup.addr(),
            });
        context.write_unaligned(body.cast());
    }
    STATUS_SUCCESS
}

/// [`PsDereferenceSiloContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psdereferencesilocontext):
/// give up a reference to a context.
///
/// # Safety
/// `context` is a silo context the caller holds a reference to.
pub unsafe extern "C" fn PsDereferenceSiloContext(context: *mut c_void) {
    // SAFETY: per the contract.
    unsafe { object::dereference(context.cast()) };
}

/// The slots, and what the host silo keeps in each: a context it holds
/// a reference to, or null.
struct Host {
    slots: Slots,
    contexts: [*mut u8; SLOTS],
}

// SAFETY: the pointers are objects the storage holds references to;
// whoever holds the lock may use them from any processor.
unsafe impl Send for Host {}

static HOST: SpinLock<Host> = SpinLock::new(
    Rank::Silo,
    Host {
        slots: Slots::new(),
        contexts: [core::ptr::null_mut(); SLOTS],
    },
);

/// [`PsAllocSiloContextSlot`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psallocsilocontextslot):
/// a slot number, the lowest free one. Without one left,
/// `STATUS_INSUFFICIENT_RESOURCES`, and nothing is written.
///
/// # Safety
/// `slot` points to room for a 32-bit number.
pub unsafe extern "C" fn PsAllocSiloContextSlot(_reserved: usize, slot: *mut u32) -> NTSTATUS {
    let allocated = HOST.lock().slots.allocate();
    match allocated {
        Some(number) => {
            // SAFETY: per the contract.
            unsafe { slot.write_unaligned(number) };
            STATUS_SUCCESS
        }
        None => STATUS_INSUFFICIENT_RESOURCES,
    }
}

/// [`PsFreeSiloContextSlot`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psfreesilocontextslot):
/// give a slot number back. `STATUS_INVALID_PARAMETER` for a number
/// that is not an allocated slot. What the host silo holds in the slot
/// stays there, as on Windows, where only silos that are jobs are
/// looked at: a driver empties its slots first.
pub extern "C" fn PsFreeSiloContextSlot(slot: u32) -> NTSTATUS {
    if HOST.lock().slots.free(slot) {
        STATUS_SUCCESS
    } else {
        STATUS_INVALID_PARAMETER
    }
}

/// [`PsInsertPermanentSiloContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psinsertpermanentsilocontext):
/// put a context in a slot of the host silo, to stay. The storage
/// takes a reference of its own.
///
/// | Refusal | Status |
/// | --- | --- |
/// | the context was made for another silo | `STATUS_INVALID_PARAMETER` |
/// | no such slot number | `STATUS_INVALID_PARAMETER` |
/// | the slot holds a context already | `STATUS_NOT_SUPPORTED` |
///
/// A slot number that was never allocated stops the system, as
/// Windows' fast fail does (`0x139`).
///
/// # Safety
/// `context` is an object the caller holds a reference to.
pub unsafe extern "C" fn PsInsertPermanentSiloContext(
    silo: *mut c_void,
    slot: u32,
    context: *mut c_void,
) -> NTSTATUS {
    if !silo.is_null() {
        no_such_silo("PsInsertPermanentSiloContext", silo);
    }
    let body = context.cast::<u8>();
    // SAFETY: per the contract; a context's record was written when it
    // was made.
    unsafe {
        if is_context(body)
            && !(*object::own_record(body).cast::<ContextRecord>())
                .silo
                .is_null()
        {
            return STATUS_INVALID_PARAMETER;
        }
    }
    if !Slots::exists(slot) {
        return STATUS_INVALID_PARAMETER;
    }
    // The storage's reference, taken before the context can be found
    // there and given back if it is not put there.
    // SAFETY: per the contract.
    unsafe { object::reference(body) };
    let placed = {
        let mut host = HOST.lock();
        if !host.slots.allocated(slot) {
            crate::kd::bugcheck(format_args!(
                "0x00000139 KERNEL_SECURITY_CHECK_FAILURE: a silo context for slot {slot}, \
                 which is not allocated (parameters 0x5, 0, 0, 0)"
            ));
        }
        let held = &mut host.contexts[slot as usize];
        if held.is_null() {
            *held = body;
            true
        } else {
            false
        }
    };
    if placed {
        STATUS_SUCCESS
    } else {
        // SAFETY: the reference taken above.
        unsafe { object::dereference(body) };
        STATUS_NOT_SUPPORTED
    }
}

/// [`PsGetPermanentSiloContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetpermanentsilocontext):
/// the context in a slot of the host silo. No reference is taken: the
/// context is there to stay. The caller's pointer is set to null
/// first, whatever follows: `STATUS_INVALID_PARAMETER` for no such
/// slot number, `STATUS_NOT_FOUND` for an empty slot.
///
/// # Safety
/// `context` points to room for a pointer.
pub unsafe extern "C" fn PsGetPermanentSiloContext(
    silo: *mut c_void,
    slot: u32,
    context: *mut *mut c_void,
) -> NTSTATUS {
    if !silo.is_null() {
        no_such_silo("PsGetPermanentSiloContext", silo);
    }
    // SAFETY: per the contract.
    unsafe { context.write_unaligned(core::ptr::null_mut()) };
    if !Slots::exists(slot) {
        return STATUS_INVALID_PARAMETER;
    }
    let held = HOST.lock().contexts[slot as usize];
    if held.is_null() {
        return STATUS_NOT_FOUND;
    }
    // SAFETY: per the contract.
    unsafe { context.write_unaligned(held.cast()) };
    STATUS_SUCCESS
}

// ---- monitors -----------------------------------------------------------

/// A silo monitor: what `PsRegisterSiloMonitor` hands back, opaque to
/// the driver.
struct Monitor {
    /// Its create callback has run for the silos there are.
    started: bool,
    /// It watches the host silo.
    monitor_host: bool,
    /// The slot allocated for it.
    slot: u32,
    create: usize,
    terminate: usize,
}

/// The mutex that serialises starting and unregistering monitors.
struct Monitors(UnsafeCell<MaybeUninit<KMUTANT>>);

// SAFETY: a mutex is made to be shared; it is only reached through the
// mutex routines.
unsafe impl Sync for Monitors {}

static MONITORS: Monitors = Monitors(UnsafeCell::new(MaybeUninit::uninit()));

/// Make the monitors' mutex. Once, before the first driver.
pub fn init() {
    // SAFETY: static storage for a mutex nothing has yet.
    unsafe { mutex::KeInitializeMutex(MONITORS.0.get().cast(), 0) };
}

fn lock_monitors() {
    // SAFETY: the mutex `init` made.
    unsafe { wait::wait(Some(MONITORS.0.get().cast()), None) };
}

/// Release the monitors' mutex. Also what a call to a monitor's
/// callback owes when an exception unwinds it.
///
/// # Safety
/// The calling thread holds the mutex.
unsafe fn unlock_monitors(_: *mut c_void) {
    // SAFETY: per the contract.
    unsafe { mutex::KeReleaseMutex(MONITORS.0.get().cast(), 0) };
}

/// Call a monitor's callback for the host silo, with the monitors'
/// mutex held.
///
/// # Safety
/// `routine` is the driver's callback; the calling thread holds the
/// mutex.
unsafe fn call_monitor(routine: usize) -> NTSTATUS {
    let guard = Guard::Undo {
        undo: unlock_monitors,
        context: core::ptr::null_mut(),
    };
    // SAFETY: per the contract; the host silo is the null argument.
    unsafe { seh::call(routine, [0, 0, 0, 0], &guard) as NTSTATUS }
}

/// [`PsRegisterSiloMonitor`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psregistersilomonitor):
/// make a monitor from a registration and give it a slot of its own.
/// Nothing is called until the monitor is started.
///
/// | Refusal | Status |
/// | --- | --- |
/// | version 0; no component name, or an empty one; neither callback | `STATUS_INVALID_PARAMETER` |
/// | the calling thread is not in the host silo | `STATUS_PRIVILEGE_NOT_HELD` |
/// | no memory, or no slot left | `STATUS_INSUFFICIENT_RESOURCES` |
///
/// # Safety
/// `registration` points to a `SILO_MONITOR_REGISTRATION`; `monitor`
/// points to room for a pointer.
pub unsafe extern "C" fn PsRegisterSiloMonitor(
    registration: *const SILO_MONITOR_REGISTRATION,
    monitor: *mut *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract; the driver's memory, read field by
    // field through its pointer.
    let (version, monitor_host, name, create, terminate) = unsafe {
        (
            (&raw const (*registration).Version).read(),
            (&raw const (*registration).MonitorHost).read() != 0,
            (&raw const (*registration).ComponentName).read_unaligned(),
            (&raw const (*registration).CreateCallback)
                .read_unaligned()
                .addr(),
            (&raw const (*registration).TerminateCallback)
                .read_unaligned()
                .addr(),
        )
    };
    // SAFETY: a non-null name points to a counted string.
    let named = !name.is_null() && unsafe { (&raw const (*name).Length).read_unaligned() } != 0;
    if version == 0 || !named || (create == 0 && terminate == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if PsIsHostSilo(PsGetCurrentSilo()) == 0 {
        return STATUS_PRIVILEGE_NOT_HELD;
    }
    let new = pool::alloc(size_of::<Monitor>(), MONITOR_TAG).cast::<Monitor>();
    if new.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let Some(slot) = HOST.lock().slots.allocate() else {
        let freed = pool::free(new.cast());
        debug_assert!(freed.is_ok());
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: a fresh block of a monitor's size, which the pool aligns
    // for it; per the contract for the result.
    unsafe {
        new.write(Monitor {
            started: false,
            monitor_host,
            slot,
            create,
            terminate,
        });
        monitor.write_unaligned(new.cast());
    }
    STATUS_SUCCESS
}

/// [`PsGetSiloMonitorContextSlot`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetsilomonitorcontextslot):
/// the slot a monitor was given.
///
/// # Safety
/// `monitor` came from [`PsRegisterSiloMonitor`].
pub unsafe extern "C" fn PsGetSiloMonitorContextSlot(monitor: *mut c_void) -> u32 {
    // SAFETY: per the contract; the slot is written once.
    unsafe { (&raw const (*monitor.cast::<Monitor>()).slot).read() }
}

/// [`PsStartSiloMonitor`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psstartsilomonitor):
/// tell a monitor of the silos there are. A monitor that watches the
/// host has its create callback called for the host silo, then and
/// there, on the calling thread; no other silo exists to tell it of.
///
/// As Windows 10 does it: a monitor already started, or one without a
/// create callback, is left as it is, with success; and if the create
/// callback fails, the terminate callback, if there is one, is called
/// to undo it, the monitor is not started, and the callback's status
/// is returned.
///
/// # Safety
/// `monitor` came from [`PsRegisterSiloMonitor`]; the caller is at
/// `PASSIVE_LEVEL`.
pub unsafe extern "C" fn PsStartSiloMonitor(monitor: *mut c_void) -> NTSTATUS {
    let monitor = monitor.cast::<Monitor>();
    lock_monitors();
    // SAFETY: per the contract; the monitor is NK's own memory, and its
    // state belongs to the mutex. The callbacks are the driver's, given
    // to be called for a silo; nothing of the monitor is borrowed
    // across them.
    let status = unsafe {
        let Monitor {
            started,
            monitor_host,
            create,
            terminate,
            ..
        } = monitor.read();
        if started || create == 0 {
            STATUS_SUCCESS
        } else {
            let created = if monitor_host {
                call_monitor(create)
            } else {
                STATUS_SUCCESS
            };
            if created >= 0 {
                (&raw mut (*monitor).started).write(true);
                STATUS_SUCCESS
            } else {
                if terminate != 0 {
                    call_monitor(terminate);
                }
                created
            }
        }
    };
    // SAFETY: taken above.
    unsafe { unlock_monitors(core::ptr::null_mut()) };
    status
}

/// [`PsUnregisterSiloMonitor`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psunregistersilomonitor):
/// end a monitor. One that was started and watches the host has its
/// terminate callback called for the host silo. Then, the lock let go,
/// the host silo gives up what it holds in the monitor's slot, the
/// slot is freed, and the monitor is gone.
///
/// # Safety
/// `monitor` came from [`PsRegisterSiloMonitor`] and is not used
/// again; the caller is at `PASSIVE_LEVEL`.
pub unsafe extern "C" fn PsUnregisterSiloMonitor(monitor: *mut c_void) {
    let monitor = monitor.cast::<Monitor>();
    lock_monitors();
    // SAFETY: per the contract, as in `PsStartSiloMonitor`.
    let (monitor_host, slot) = unsafe {
        let Monitor {
            started,
            monitor_host,
            slot,
            terminate,
            ..
        } = monitor.read();
        if started {
            (&raw mut (*monitor).started).write(false);
            if terminate != 0 && monitor_host {
                call_monitor(terminate);
            }
        }
        unlock_monitors(core::ptr::null_mut());
        (monitor_host, slot)
    };
    if monitor_host {
        let held = core::mem::replace(
            &mut HOST.lock().contexts[slot as usize],
            core::ptr::null_mut(),
        );
        if !held.is_null() {
            // SAFETY: the storage's reference, given up outside its
            // lock: the context's cleanup routine may run.
            unsafe { object::dereference(held) };
        }
    }
    let was_allocated = HOST.lock().slots.free(slot);
    debug_assert!(was_allocated);
    let freed = pool::free(monitor.cast());
    debug_assert!(freed.is_ok());
}

// ---- tests --------------------------------------------------------------

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

/// What the tests' callbacks saw: calls of each kind, the context the
/// last cleanup was for, and whether a callback ran as it should.
static CREATED: AtomicU32 = AtomicU32::new(0);
static TERMINATED: AtomicU32 = AtomicU32::new(0);
static CLEANED: AtomicU32 = AtomicU32::new(0);
static LAST_CLEANED: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
static WRONG: AtomicU32 = AtomicU32::new(0);
/// The thread that starts and ends the monitor under test, and the
/// status its create callback is to return.
static STARTER: AtomicPtr<thread::Thread> = AtomicPtr::new(core::ptr::null_mut());
static CREATE_STATUS: AtomicU32 = AtomicU32::new(0);

/// A callback for the host silo runs on the thread that started or
/// ended the monitor, at `PASSIVE_LEVEL`, with kernel APCs off.
fn seen(silo: *mut c_void) {
    let starter = STARTER.load(Ordering::Acquire);
    if !silo.is_null()
        || crate::ke::irql::current() != crate::ke::irql::PASSIVE_LEVEL
        || (!starter.is_null() && thread::current() != starter)
        || mutex::KeAreApcsDisabled() == 0
        || PsGetCurrentSilo() != silo
    {
        WRONG.fetch_add(1, Ordering::Relaxed);
    }
}

extern "C" fn on_create(silo: *mut c_void) -> NTSTATUS {
    seen(silo);
    CREATED.fetch_add(1, Ordering::AcqRel);
    CREATE_STATUS.load(Ordering::Acquire) as NTSTATUS
}

extern "C" fn on_terminate(silo: *mut c_void) {
    seen(silo);
    TERMINATED.fetch_add(1, Ordering::AcqRel);
}

extern "C" fn on_cleanup(context: *mut c_void) {
    LAST_CLEANED.store(context, Ordering::Release);
    CLEANED.fetch_add(1, Ordering::AcqRel);
}

fn counts() -> [u32; 3] {
    [
        CREATED.load(Ordering::Acquire),
        TERMINATED.load(Ordering::Acquire),
        CLEANED.load(Ordering::Acquire),
    ]
}

/// A context as a driver makes one; the status and the context.
fn new_context(silo: *mut c_void, pool_type: u32, cleanup: bool) -> (NTSTATUS, *mut c_void) {
    let mut context = core::ptr::dangling_mut::<c_void>();
    let routine = if cleanup {
        on_cleanup as *mut c_void
    } else {
        core::ptr::null_mut()
    };
    // SAFETY: the result is a local; the routine takes a context.
    let status = unsafe { PsCreateSiloContext(silo, 64, pool_type, routine, &raw mut context) };
    (status, context)
}

fn permanent(slot: u32) -> (NTSTATUS, *mut c_void) {
    let mut found = core::ptr::dangling_mut::<c_void>();
    // SAFETY: the result is a local.
    let status = unsafe { PsGetPermanentSiloContext(core::ptr::null_mut(), slot, &raw mut found) };
    (status, found)
}

/// What the silo routines say where there is no container: one silo,
/// the host, spelled null; threads attach to it and detach; contexts
/// are objects that are cleaned up with their last reference; slots
/// are handed out and taken back. Returns the calls made.
pub fn self_test() -> Result<u32, &'static str> {
    static PEER_STARTED_WITH: AtomicPtr<c_void> = AtomicPtr::new(core::ptr::null_mut());
    fn peer(_: usize) {
        let previous = PsAttachSiloToCurrentThread(core::ptr::null_mut());
        PEER_STARTED_WITH.store(previous, Ordering::Release);
        PsDetachSiloFromCurrentThread(previous);
    }
    let host = core::ptr::null_mut::<c_void>();
    let mark = core::ptr::without_provenance_mut::<c_void>(THREAD_NOT_ATTACHED);
    if !PsGetCurrentSilo().is_null() || !PsGetCurrentServerSilo().is_null() {
        return Err("a system thread is not in the host silo, in no server silo");
    }
    if PsIsHostSilo(host) != 1 || PsIsHostSilo(core::ptr::dangling_mut()) != 0 {
        return Err("the host silo is not the null one");
    }
    let mut silo = core::ptr::dangling_mut::<c_void>();
    if PsGetJobSilo(host, &raw mut silo) != STATUS_INVALID_PARAMETER
        || silo != core::ptr::dangling_mut()
    {
        return Err("no job was taken for a job, or the caller's pointer was written");
    }

    // Attaching: what comes back is what to put back.
    let previous = PsAttachSiloToCurrentThread(host);
    let attached_to = (PsGetCurrentSilo(), PsGetCurrentServerSilo());
    let inner = PsAttachSiloToCurrentThread(host);
    PsDetachSiloFromCurrentThread(inner);
    PsDetachSiloFromCurrentThread(previous);
    let again = PsAttachSiloToCurrentThread(host);
    PsDetachSiloFromCurrentThread(again);
    if previous != mark || again != mark || !inner.is_null() {
        return Err("attaching did not return what the thread was attached to before");
    }
    if attached_to != (host, host) || !PsGetCurrentSilo().is_null() {
        return Err("a thread attached to the host silo is not in the host silo");
    }
    // Every thread starts attached to nothing.
    PEER_STARTED_WITH.store(host, Ordering::Release);
    let other = thread::create_referenced(peer, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    // SAFETY: a thread this test holds a reference to, which it gives
    // up here; the wait is for that thread's end.
    unsafe {
        wait::wait(Some(other.cast()), None);
        object::dereference(other.cast());
    }
    if PEER_STARTED_WITH.load(Ordering::Acquire) != mark {
        return Err("a new thread does not start attached to no silo");
    }

    // Contexts.
    let before = counts();
    let (status, untouched) = new_context(host, 0, true);
    if status != STATUS_INVALID_PARAMETER || untouched != core::ptr::dangling_mut() {
        return Err("a context was made from a pool it is not made from");
    }
    for (pool_type, ty) in [
        (
            NON_PAGED_POOL_NX,
            &raw const object::SILO_CONTEXT_NONPAGED_TYPE,
        ),
        (PAGED_POOL, &raw const object::SILO_CONTEXT_PAGED_TYPE),
    ] {
        let cleaned = CLEANED.load(Ordering::Acquire);
        let (status, context) = new_context(host, pool_type, true);
        if status != STATUS_SUCCESS {
            return Err("no memory for a silo context");
        }
        // SAFETY: a context this test holds the references to: its 64
        // bytes are zero and its own; a second reference keeps it past
        // the first release.
        unsafe {
            let body = context.cast::<[u8; 64]>();
            let zeroed = body.read() == [0; 64];
            body.write([0x5A; 64]);
            let its_type = core::ptr::eq(object::type_of(context.cast()), ty);
            object::ObfReferenceObject(context);
            PsDereferenceSiloContext(context);
            let kept = CLEANED.load(Ordering::Acquire) == cleaned;
            PsDereferenceSiloContext(context);
            if !zeroed || !its_type {
                return Err("a silo context is not a zeroed object of its pool's type");
            }
            if !kept {
                return Err("a silo context was cleaned up while it was referenced");
            }
        }
        if CLEANED.load(Ordering::Acquire) != cleaned + 1
            || LAST_CLEANED.load(Ordering::Acquire) != context
        {
            return Err("a silo context was not cleaned up once, by its routine, with itself");
        }
    }
    // One made without a routine just goes.
    let (status, context) = new_context(host, PAGED_POOL, false);
    if status != STATUS_SUCCESS {
        return Err("no memory for a silo context");
    }
    // SAFETY: the creating reference.
    unsafe { PsDereferenceSiloContext(context) };
    if counts() != [before[0], before[1], before[2] + 2] {
        return Err("a callback ran that should not have");
    }

    // Slots.
    let (mut first, mut second) = (u32::MAX, u32::MAX);
    // SAFETY: the results are locals.
    let allocated = unsafe {
        [
            PsAllocSiloContextSlot(0, &raw mut first),
            PsAllocSiloContextSlot(0, &raw mut second),
        ]
    };
    if allocated != [STATUS_SUCCESS; 2] || first == second || !Slots::exists(first) {
        return Err("two slots could not be allocated");
    }
    let looked = [permanent(first), permanent(0xFFFF)];
    let freed = [
        PsFreeSiloContextSlot(second),
        PsFreeSiloContextSlot(first),
        PsFreeSiloContextSlot(first),
        PsFreeSiloContextSlot(0xFFFF),
    ];
    if looked != [(STATUS_NOT_FOUND, host), (STATUS_INVALID_PARAMETER, host)] {
        return Err("an empty slot, or a slot there is not, was not reported as such");
    }
    let invalid = STATUS_INVALID_PARAMETER;
    if freed != [STATUS_SUCCESS, STATUS_SUCCESS, invalid, invalid] {
        return Err("a slot was not freed exactly once");
    }
    Ok(27)
}

fn registration(
    monitor_host: bool,
    name: *const nk_ntabi::io::UNICODE_STRING,
    create: bool,
    terminate: bool,
) -> SILO_MONITOR_REGISTRATION {
    SILO_MONITOR_REGISTRATION {
        Version: nk_ntabi::silo::SILO_MONITOR_REGISTRATION_VERSION,
        MonitorHost: u8::from(monitor_host),
        MonitorExistingSilos: 1,
        Reserved: [0; 5],
        ComponentName: name,
        CreateCallback: if create {
            on_create as *mut c_void
        } else {
            core::ptr::null_mut()
        },
        TerminateCallback: if terminate {
            on_terminate as *mut c_void
        } else {
            core::ptr::null_mut()
        },
    }
}

fn register(registration: &SILO_MONITOR_REGISTRATION) -> (NTSTATUS, *mut c_void) {
    let mut monitor = core::ptr::dangling_mut::<c_void>();
    // SAFETY: locals that outlive the call.
    let status = unsafe { PsRegisterSiloMonitor(registration, &raw mut monitor) };
    (status, monitor)
}

/// A monitor's whole life as a driver lives it: registered, started
/// (the host silo is announced then and there), a context kept in its
/// slot, unregistered (the host silo's end is announced and the
/// context cleaned up). Returns the calls made.
pub fn monitor_test() -> Result<u32, &'static str> {
    let host = core::ptr::null_mut::<c_void>();
    let component: [u16; 2] = [0x4E, 0x4B];
    let name = nk_ntabi::io::UNICODE_STRING {
        Length: 4,
        MaximumLength: 4,
        Buffer: component.as_ptr().cast_mut(),
    };
    let empty = nk_ntabi::io::UNICODE_STRING { Length: 0, ..name };
    WRONG.store(0, Ordering::Relaxed);
    CREATE_STATUS.store(0, Ordering::Release);
    STARTER.store(thread::current(), Ordering::Release);
    let before = counts();
    let since = || {
        let now = counts();
        [now[0] - before[0], now[1] - before[1], now[2] - before[2]]
    };

    // Registrations that are refused.
    let untouched = core::ptr::dangling_mut::<c_void>();
    let refused = [
        register(&SILO_MONITOR_REGISTRATION {
            Version: 0,
            ..registration(true, &raw const name, true, true)
        }),
        register(&registration(true, &raw const name, false, false)),
        register(&registration(true, core::ptr::null(), true, true)),
        register(&registration(true, &raw const empty, true, true)),
    ];
    if refused != [(STATUS_INVALID_PARAMETER, untouched); 4] {
        return Err("a registration that says too little was accepted");
    }
    // A thread attached to something that is not the host silo.
    let previous = PsAttachSiloToCurrentThread(core::ptr::dangling_mut());
    let elsewhere = register(&registration(true, &raw const name, true, true));
    PsDetachSiloFromCurrentThread(previous);
    if elsewhere != (STATUS_PRIVILEGE_NOT_HELD, untouched) {
        return Err("a monitor was registered from outside the host silo");
    }

    // Registered: nothing is called, and the monitor has a slot.
    let (status, monitor) = register(&registration(true, &raw const name, true, true));
    if status != STATUS_SUCCESS || since() != [0, 0, 0] {
        return Err("a monitor could not be registered, or registering called something");
    }
    // SAFETY: the monitor just registered, until it is unregistered.
    let verdict = unsafe {
        (|| {
            let slot = PsGetSiloMonitorContextSlot(monitor);
            if !Slots::exists(slot) || permanent(slot) != (STATUS_NOT_FOUND, host) {
                return Err("a monitor's slot is not an empty slot of its own");
            }
            // Started: the host silo is announced, once.
            if PsStartSiloMonitor(monitor) != STATUS_SUCCESS || since() != [1, 0, 0] {
                return Err("starting a monitor of the host did not call its create callback once");
            }
            if PsStartSiloMonitor(monitor) != STATUS_SUCCESS || since() != [1, 0, 0] {
                return Err("starting a started monitor did something");
            }
            // A context in the monitor's slot, to stay.
            let (made, context) = new_context(host, NON_PAGED_POOL_NX, true);
            let (made_too, second) = new_context(host, NON_PAGED_POOL_NX, true);
            let (for_other, stranger) =
                new_context(core::ptr::dangling_mut(), NON_PAGED_POOL_NX, false);
            if (made, made_too, for_other) != (STATUS_SUCCESS, STATUS_SUCCESS, STATUS_SUCCESS) {
                return Err("no memory for a silo context");
            }
            let inserted = [
                PsInsertPermanentSiloContext(host, slot, stranger),
                PsInsertPermanentSiloContext(host, 0xFFFF, context),
                PsInsertPermanentSiloContext(host, slot, context),
                PsInsertPermanentSiloContext(host, slot, second),
            ];
            PsDereferenceSiloContext(stranger);
            PsDereferenceSiloContext(second);
            let second_gone =
                since() == [1, 0, 1] && LAST_CLEANED.load(Ordering::Acquire) == second;
            let found = permanent(slot);
            // The maker lets go: the slot holds the context.
            PsDereferenceSiloContext(context);
            let held = since() == [1, 0, 1] && permanent(slot) == (STATUS_SUCCESS, context);
            let invalid = STATUS_INVALID_PARAMETER;
            if inserted != [invalid, invalid, STATUS_SUCCESS, STATUS_NOT_SUPPORTED] {
                return Err("a context was not put in a slot exactly when it may be");
            }
            if !second_gone {
                return Err("a context that was refused a slot was not cleaned up when let go");
            }
            if found != (STATUS_SUCCESS, context) || !held {
                return Err("a slot does not hold the context put there");
            }
            Ok((slot, context))
        })()
    };
    // Unregistered: the host silo's end is announced, the context in
    // the slot is cleaned up, and the slot is free again.
    // SAFETY: the monitor registered above, not used again.
    unsafe { PsUnregisterSiloMonitor(monitor) };
    let (slot, context) = verdict?;
    if since() != [1, 1, 2] || LAST_CLEANED.load(Ordering::Acquire) != context {
        return Err("unregistering did not announce the end once and clean up the slot's context");
    }
    if permanent(slot) != (STATUS_NOT_FOUND, host)
        || PsFreeSiloContextSlot(slot) != STATUS_INVALID_PARAMETER
    {
        return Err("an unregistered monitor's slot was not emptied and freed");
    }

    // A monitor that does not watch the host: nothing is ever called.
    // One with only a terminate callback is never started, so that is
    // not called either.
    for quiet in [
        registration(false, &raw const name, true, true),
        registration(true, &raw const name, false, true),
    ] {
        let (status, monitor) = register(&quiet);
        if status != STATUS_SUCCESS {
            return Err("a monitor could not be registered");
        }
        // SAFETY: the monitor just registered, not used after.
        let started = unsafe {
            let started = PsStartSiloMonitor(monitor);
            PsUnregisterSiloMonitor(monitor);
            started
        };
        if started != STATUS_SUCCESS || since() != [1, 1, 2] {
            return Err("a monitor with nothing to be told of was told something");
        }
    }

    // A create callback that fails: its status comes back, the
    // terminate callback undoes it, and the monitor is not started.
    let (status, monitor) = register(&registration(true, &raw const name, true, true));
    if status != STATUS_SUCCESS {
        return Err("a monitor could not be registered");
    }
    CREATE_STATUS.store(STATUS_UNSUCCESSFUL as u32, Ordering::Release);
    // SAFETY: the monitor just registered, not used after.
    let failed = unsafe {
        let failed = PsStartSiloMonitor(monitor);
        let after_start = since();
        PsUnregisterSiloMonitor(monitor);
        (failed, after_start)
    };
    CREATE_STATUS.store(0, Ordering::Release);
    STARTER.store(core::ptr::null_mut(), Ordering::Release);
    if failed != (STATUS_UNSUCCESSFUL, [2, 2, 2]) || since() != [2, 2, 2] {
        return Err("a failing create callback did not fail the start and get undone once");
    }
    if WRONG.load(Ordering::Relaxed) != 0 {
        return Err(
            "a callback was not called for the host silo, on the caller's thread, at PASSIVE_LEVEL with APCs off",
        );
    }
    Ok(34)
}

/// Monitors, slots and contexts from threads on every processor at
/// once: every start is announced once and every context cleaned up
/// once, and nothing is left. Returns the monitors that lived.
pub fn smp_test() -> Result<u32, &'static str> {
    const ROUNDS: u32 = 200;
    static FAILED: AtomicU32 = AtomicU32::new(0);
    fn body(_: usize) {
        let host = core::ptr::null_mut::<c_void>();
        let component: [u16; 2] = [0x4E, 0x4B];
        let name = nk_ntabi::io::UNICODE_STRING {
            Length: 4,
            MaximumLength: 4,
            Buffer: component.as_ptr().cast_mut(),
        };
        for _ in 0..ROUNDS {
            let (status, monitor) = register(&registration(true, &raw const name, true, true));
            let (made, context) = new_context(host, NON_PAGED_POOL_NX, true);
            if status != STATUS_SUCCESS || made != STATUS_SUCCESS {
                FAILED.fetch_add(1, Ordering::Relaxed);
                return;
            }
            // SAFETY: a monitor and a context of this thread's own.
            unsafe {
                let slot = PsGetSiloMonitorContextSlot(monitor);
                let previous = PsAttachSiloToCurrentThread(host);
                let ok = PsStartSiloMonitor(monitor) == STATUS_SUCCESS
                    && PsInsertPermanentSiloContext(host, slot, context) == STATUS_SUCCESS
                    && permanent(slot) == (STATUS_SUCCESS, context)
                    && PsGetCurrentSilo().is_null();
                PsDetachSiloFromCurrentThread(previous);
                PsDereferenceSiloContext(context);
                PsUnregisterSiloMonitor(monitor);
                if !ok || previous.addr() != THREAD_NOT_ATTACHED {
                    FAILED.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
    let before = counts();
    let threads_before = thread::count();
    FAILED.store(0, Ordering::Relaxed);
    WRONG.store(0, Ordering::Relaxed);
    STARTER.store(core::ptr::null_mut(), Ordering::Release);
    CREATE_STATUS.store(0, Ordering::Release);
    let processors = crate::ke::smp::online_count();
    let threads = processors.max(2) as u32;
    for n in 0..threads as usize {
        thread::create(body, 0, thread::NORMAL_PRIORITY, 1 << (n % processors))?;
    }
    thread::settle(threads_before);
    let lived = threads * ROUNDS;
    if FAILED.load(Ordering::Relaxed) != 0 || WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a monitor's life went wrong on some processor");
    }
    let now = counts();
    if [now[0] - before[0], now[1] - before[1], now[2] - before[2]] != [lived; 3] {
        return Err("starts, ends and cleanups do not number the monitors that lived");
    }
    Ok(lived)
}
