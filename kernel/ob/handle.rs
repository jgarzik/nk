//! Kernel handles: small numbers that stand for references to objects.
//!
//! One table for the whole kernel. A handle holds a reference to its
//! object until it is closed. Kernel handles have their high bits set
//! (`nk_ntabi::ob`), as on Windows; there are no per-process tables yet,
//! and no access checks.

#![allow(non_snake_case)]

use super::object::{self, ObjectType};
use crate::ke::{Rank, SpinLock};
use core::ffi::c_void;
use core::sync::atomic::Ordering;
use nk_ntabi::ob::{kernel_handle, kernel_handle_index};
use nk_ntabi::status::*;
use nk_ob::Slots;

/// `NtCurrentThread()` and `NtCurrentProcess()`: not entries of any
/// table, they name whichever thread uses them and its process.
const CURRENT_THREAD: u64 = -2i64 as u64;
const CURRENT_PROCESS: u64 = -1i64 as u64;

/// An object in the table.
struct Entry(*mut u8);

// SAFETY: the table holds a reference to each object it lists, and the
// pointer is only used under the table's lock or with a reference taken
// there.
unsafe impl Send for Entry {}

static TABLE: SpinLock<Slots<Entry>> = SpinLock::new(Rank::Handles, Slots::new());

/// The pool memory the table itself occupies, as `(blocks, bytes)`. It
/// grows with the most handles ever open at once and is kept, so a leak
/// check must not count it as lost.
pub fn storage() -> (usize, usize) {
    let bytes = TABLE.lock().storage();
    (usize::from(bytes != 0), bytes)
}

/// Handles that are open.
pub fn count() -> usize {
    TABLE.lock().count()
}

/// Open a handle to an object. The handle takes its own reference.
///
/// # Safety
/// `body` is an object from `object::create` that the caller holds a
/// reference to.
pub unsafe fn open(body: *mut u8) -> u64 {
    // SAFETY: per the contract.
    unsafe {
        object::reference(body);
        object::handle_count(body).fetch_add(1, Ordering::AcqRel);
    }
    kernel_handle(TABLE.lock().insert(Entry(body)))
}

/// The object a handle names, with a new reference for the caller, if
/// it is of type `ty` (or of any type, given none).
pub fn reference(handle: u64, ty: Option<*const ObjectType>) -> Result<*mut u8, NTSTATUS> {
    let current = match handle {
        CURRENT_THREAD => Some((
            crate::ke::thread::current().cast::<u8>(),
            &raw const object::THREAD_TYPE,
        )),
        CURRENT_PROCESS => Some((
            crate::ps::process::system(),
            &raw const object::PROCESS_TYPE,
        )),
        _ => None,
    };
    if let Some((body, its_type)) = current {
        if ty.is_some_and(|ty| !core::ptr::eq(ty, its_type)) {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        // SAFETY: the running thread holds a reference on itself, and
        // the System process lives for ever.
        unsafe { object::reference(body) };
        return Ok(body);
    }
    let index = kernel_handle_index(handle).ok_or(STATUS_INVALID_HANDLE)?;
    let table = TABLE.lock();
    let Some(Entry(body)) = table.get(index) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    // SAFETY: the table holds a reference, and its lock is held, so the
    // object cannot go away before the new reference is taken.
    unsafe {
        if ty.is_some_and(|ty| !core::ptr::eq(ty, object::type_of(*body))) {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        object::reference(*body);
    }
    Ok(*body)
}

/// Close a handle: it stops naming its object and gives up its
/// reference.
pub fn close(handle: u64) -> NTSTATUS {
    let Some(index) = kernel_handle_index(handle) else {
        return STATUS_INVALID_HANDLE;
    };
    let Some(Entry(body)) = TABLE.lock().take(index) else {
        return STATUS_INVALID_HANDLE;
    };
    // SAFETY: the entry held a reference, which this gives up, outside
    // the table's lock: freeing takes the pool's.
    unsafe {
        object::handle_count(body).fetch_sub(1, Ordering::AcqRel);
        object::dereference(body);
    }
    STATUS_SUCCESS
}

/// [`ObReferenceObjectByHandle`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle).
/// There are no access checks: the desired access and the access mode
/// are not looked at.
///
/// # Safety
/// `object` points to room for a pointer; `handle_information` is null
/// or points to room for an `OBJECT_HANDLE_INFORMATION`.
pub unsafe extern "C" fn ObReferenceObjectByHandle(
    handle: *mut c_void,
    _desired_access: u32,
    object_type: *const ObjectType,
    _access_mode: i8,
    object: *mut *mut c_void,
    handle_information: *mut [u32; 2],
) -> NTSTATUS {
    let wanted = (!object_type.is_null()).then_some(object_type);
    // SAFETY: per the contract.
    unsafe {
        match reference(handle as u64, wanted) {
            Ok(body) => {
                object.write_unaligned(body.cast());
                if !handle_information.is_null() {
                    // Attributes and granted access: none recorded.
                    handle_information.write_unaligned([0, 0]);
                }
                STATUS_SUCCESS
            }
            Err(status) => {
                object.write_unaligned(core::ptr::null_mut());
                status
            }
        }
    }
}

/// [`ObOpenObjectByPointer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-obopenobjectbypointer):
/// a handle to an object the caller has a pointer to. Every handle is
/// a kernel handle, and there are no access checks: the attributes,
/// access state, desired access and access mode are not looked at.
///
/// # Safety
/// `object` is an object-manager object the caller holds a reference
/// to; `handle` points to room for a handle.
pub unsafe extern "C" fn ObOpenObjectByPointer(
    object: *mut c_void,
    _handle_attributes: u32,
    _access_state: *mut c_void,
    _desired_access: u32,
    object_type: *const ObjectType,
    _access_mode: i8,
    handle: *mut *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if !object_type.is_null() && !core::ptr::eq(object_type, object::type_of(object.cast())) {
            handle.write_unaligned(core::ptr::null_mut());
            return STATUS_OBJECT_TYPE_MISMATCH;
        }
        handle.write_unaligned(open(object.cast()) as *mut c_void);
    }
    STATUS_SUCCESS
}

// ---- tests --------------------------------------------------------------

use crate::ke::{thread, time, wait};
use crate::mm::pool;
use nk_ntabi::ke::KEVENT;

/// Pool blocks in use, the table's own storage aside.
fn blocks() -> usize {
    pool::usage().blocks - storage().0
}

fn new_event() -> Result<*mut u8, &'static str> {
    let body = object::create(&object::EVENT_TYPE, size_of::<KEVENT>()).ok_or("no memory")?;
    // SAFETY: fresh storage of an event's size.
    unsafe { wait::KeInitializeEvent(body.cast(), 1, 0) };
    Ok(body)
}

/// An object lives exactly as long as it is referenced. Returns the
/// references taken and dropped.
pub fn reference_test() -> Result<u32, &'static str> {
    let before = blocks();
    let body = new_event()?;
    // SAFETY: `body` is a live object this test holds references to,
    // until the last line, which gives up the last one.
    unsafe {
        if blocks() != before + 1 {
            return Err("creating an object did not allocate exactly one block");
        }
        if !core::ptr::eq(object::type_of(body), &raw const object::EVENT_TYPE) {
            return Err("an object does not know its type");
        }
        let up = [object::reference(body), object::reference(body)];
        let down = [
            object::ObfDereferenceObject(body.cast()),
            object::dereference(body) as isize,
        ];
        if up != [2, 3] || down != [2, 1] {
            return Err("reference counts did not go 2, 3, 2, 1");
        }
        if blocks() != before + 1 {
            return Err("an object was freed while still referenced");
        }
        if object::dereference(body) != 0 || blocks() != before {
            return Err("dropping the last reference did not free the object");
        }
    }
    Ok(6)
}

/// A handle names its object until closed, keeps it alive, and is
/// checked against the type asked for. Returns the look-ups made.
pub fn handle_test() -> Result<u32, &'static str> {
    let by_handle = |handle: u64, ty: *const ObjectType| {
        let mut out = core::ptr::dangling_mut::<c_void>();
        let mut information = [u32::MAX; 2];
        // SAFETY: both outputs are locals.
        let status = unsafe {
            ObReferenceObjectByHandle(
                handle as *mut c_void,
                0,
                ty,
                0,
                &raw mut out,
                &raw mut information,
            )
        };
        (status, out.cast::<u8>(), information)
    };
    let (before, pool_before) = (count(), blocks());
    let body = new_event()?;
    let event_type = object::ExEventObjectType.value();
    // SAFETY: `body` is a live object this test holds references to.
    unsafe {
        let handle = open(body);
        if kernel_handle_index(handle).is_none() || handle % 4 != 0 {
            return Err("a kernel handle does not look like one");
        }
        if count() != before + 1 || object::handle_count(body).load(Ordering::Acquire) != 1 {
            return Err("opening a handle was not counted");
        }
        // The right type, and no type asked for.
        for ty in [event_type, core::ptr::null()] {
            let (status, found, information) = by_handle(handle, ty);
            if status != STATUS_SUCCESS || found != body || information != [0, 0] {
                return Err("a handle did not give back its object");
            }
            object::dereference(body);
        }
        // The low bits of a handle carry nothing.
        if by_handle(handle | 3, event_type).0 != STATUS_SUCCESS {
            return Err("the low two bits of a handle were not ignored");
        }
        object::dereference(body);
        let (status, found, _) = by_handle(handle, &raw const object::THREAD_TYPE);
        if status != STATUS_OBJECT_TYPE_MISMATCH || !found.is_null() {
            return Err("a handle to an event was accepted as a thread");
        }
        for bogus in [0, 4, handle + 4096, handle & 0xFFFF_FFFF] {
            let (status, found, _) = by_handle(bogus, core::ptr::null());
            if status != STATUS_INVALID_HANDLE || !found.is_null() {
                return Err("something that is not an open handle was accepted");
            }
        }
        // The creator lets go: the handle alone keeps the object.
        object::dereference(body);
        if wait::KeSetEvent(body.cast(), 0, 0) != 0 {
            return Err("an object kept alive by a handle was not usable");
        }
        if close(handle) != STATUS_SUCCESS || close(handle) != STATUS_INVALID_HANDLE {
            return Err("a handle was not closed exactly once");
        }
        if by_handle(handle, core::ptr::null()).0 != STATUS_INVALID_HANDLE {
            return Err("a closed handle still names its object");
        }
    }
    if count() != before || blocks() != pool_before {
        return Err("closing the last handle did not free the object");
    }
    Ok(10)
}

/// A thread is an object: it can be waited for, it stays valid after it
/// ends for as long as it is referenced, and a handle can keep it.
/// Returns the waits made.
pub fn thread_test() -> Result<u32, &'static str> {
    fn body(ms: usize) {
        let interval = -(ms as i64) * 10_000;
        // SAFETY: the interval is a local.
        unsafe { wait::KeDelayExecutionThread(0, 0, &raw const interval) };
    }
    let join = |thread: *mut thread::Thread, ms: Option<i64>| {
        // SAFETY: the test holds a reference to the thread.
        unsafe { wait::wait(Some(thread.cast()), ms.map(|ms| -ms * 10_000)) }
    };
    let (pool_before, threads_before) = (blocks(), thread::count());
    let started = time::interrupt_time();
    let short = thread::create_referenced(body, 30, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    let long = thread::create_referenced(body, 300, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    // SAFETY: both threads are referenced by this test until the end.
    unsafe {
        let handle = open(long.cast());
        if join(long, Some(5)) != wait::STATUS_TIMEOUT {
            return Err("a wait for a running thread did not time out");
        }
        if join(short, None) != wait::STATUS_SUCCESS || time::interrupt_time() - started < 300_000 {
            return Err("a wait for a thread returned before the thread ended");
        }
        // Ended, but referenced: still an object, still signalled.
        if join(short, Some(0)) != wait::STATUS_SUCCESS {
            return Err("a thread that ended is not signalled");
        }
        object::dereference(short.cast());
        // The other is reached through its handle after the pointer is
        // given up.
        object::dereference(long.cast());
        let by_handle = reference(handle, Some(&raw const object::THREAD_TYPE))
            .map_err(|_| "a handle to a thread did not give it back")?;
        if by_handle != long.cast() || join(long, None) != wait::STATUS_SUCCESS {
            return Err("a thread could not be waited for through its handle");
        }
        if time::interrupt_time() - started < 3_000_000 {
            return Err("a wait for a thread returned before the thread ended");
        }
        object::dereference(by_handle);
        if close(handle) != STATUS_SUCCESS {
            return Err("the thread's handle could not be closed");
        }
    }
    // A thread is signalled as it is buried, a moment before its own
    // reference goes: wait for the burial to be over.
    let deadline = time::interrupt_time() + 50_000_000;
    while thread::count() != threads_before && time::interrupt_time() < deadline {
        thread::yield_now();
    }
    if blocks() != pool_before {
        return Err("threads that ended and were let go of were not freed");
    }
    Ok(5)
}
