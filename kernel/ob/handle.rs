//! Kernel handles: small numbers that stand for references to objects.
//!
//! One table for the whole kernel: the System process's, which is where
//! Windows keeps kernel handles too. A handle holds a reference to its
//! object until it is closed, and remembers the access it was opened
//! with and its attributes (`nk_ob::handles`). Kernel handles have
//! their high bits set (`nk_ntabi::ob`), as on Windows; there are no
//! per-process tables yet.
//!
//! The access is checked when a handle is used on behalf of user mode
//! and never for kernel mode, as
//! [`ObReferenceObjectByHandle`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle)
//! documents. Nothing decides what access a subject may have: a handle
//! is granted what its opener asked for.

#![allow(non_snake_case)]

use super::object::{self, ObjectType};
use crate::ke::{Rank, SpinLock};
use core::ffi::c_void;
use core::sync::atomic::Ordering;
use nk_ntabi::ob::{kernel_handle, kernel_handle_index};
use nk_ntabi::status::*;
use nk_ob::handles::{Attributes, HandleError, Handles, Mode};

/// `NtCurrentThread()` and `NtCurrentProcess()`: not entries of any
/// table, they name whichever thread uses them and its process.
const CURRENT_THREAD: u64 = -2i64 as u64;
const CURRENT_PROCESS: u64 = -1i64 as u64;
/// What they are good for: everything (`THREAD_ALL_ACCESS`,
/// `PROCESS_ALL_ACCESS`).
const ALL_ACCESS: u32 = 0x001F_FFFF;

/// Handle attributes as `OBJECT_ATTRIBUTES` and
/// `OBJECT_HANDLE_INFORMATION` spell them.
const OBJ_PROTECT_CLOSE: u32 = 0x1;
const OBJ_INHERIT: u32 = 0x2;

/// An object in the table.
struct Entry(*mut u8);

// SAFETY: the table holds a reference to each object it lists, and the
// pointer is only used under the table's lock or with a reference taken
// there.
unsafe impl Send for Entry {}

static TABLE: SpinLock<Handles<Entry>> = SpinLock::new(Rank::Handles, Handles::new());

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

fn status(error: HandleError) -> NTSTATUS {
    match error {
        HandleError::Invalid => STATUS_INVALID_HANDLE,
        HandleError::Denied => STATUS_ACCESS_DENIED,
        HandleError::Protected => STATUS_HANDLE_NOT_CLOSABLE,
        HandleError::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
    }
}

/// Open a handle to an object, granted `access` (generic rights are
/// turned into what they mean for the object's type). The handle takes
/// its own reference.
///
/// # Safety
/// `body` is an object from `object::create` that the caller holds a
/// reference to.
pub unsafe fn open(body: *mut u8, access: u32) -> Result<u64, NTSTATUS> {
    // SAFETY: per the contract.
    unsafe { open_with(body, access, Attributes::default()) }
}

/// As [`open`], with the handle's attributes.
///
/// # Safety
/// As [`open`].
unsafe fn open_with(body: *mut u8, access: u32, attributes: Attributes) -> Result<u64, NTSTATUS> {
    // SAFETY: per the contract.
    let granted = unsafe { object::type_of(body) }.map_generic(access);
    let index = TABLE
        .lock()
        .insert(Entry(body), granted, attributes)
        .map_err(status)?;
    // SAFETY: per the contract. The handle is in the table before it
    // has its reference, but nobody knows its number yet.
    unsafe {
        object::reference(body);
        object::handle_count(body).fetch_add(1, Ordering::AcqRel);
    }
    Ok(kernel_handle(index))
}

/// What a handle is, besides its object: the access it was granted and
/// its attributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Information {
    pub granted: u32,
    pub attributes: Attributes,
}

/// The object a handle names, with a new reference for the caller, if
/// it is of type `ty` (or of any type, given none). For kernel mode:
/// the handle's access is not looked at.
pub fn reference(handle: u64, ty: Option<*const ObjectType>) -> Result<*mut u8, NTSTATUS> {
    reference_for(handle, ty, 0, Mode::Kernel).map(|(body, _)| body)
}

/// As [`reference`], on behalf of `mode`: user mode gets the object
/// only if the handle was granted every right in `desired`. Also says
/// what the handle is.
pub fn reference_for(
    handle: u64,
    ty: Option<*const ObjectType>,
    desired: u32,
    mode: Mode,
) -> Result<(*mut u8, Information), NTSTATUS> {
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
        let information = Information {
            granted: ALL_ACCESS,
            attributes: Attributes::default(),
        };
        return Ok((body, information));
    }
    let index = kernel_handle_index(handle).ok_or(STATUS_INVALID_HANDLE)?;
    let table = TABLE.lock();
    let Entry(body) = table.reference(index, desired, mode).map_err(status)?;
    // SAFETY: the table holds a reference, and its lock is held, so the
    // object cannot go away before the new reference is taken.
    unsafe {
        if ty.is_some_and(|ty| !core::ptr::eq(ty, object::type_of(*body))) {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        object::reference(*body);
    }
    let information = table.get(index).map_or(
        Information {
            granted: 0,
            attributes: Attributes::default(),
        },
        |open| Information {
            granted: open.granted,
            attributes: open.attributes,
        },
    );
    Ok((*body, information))
}

/// Close a handle on the kernel's own behalf: what `ZwClose` returns.
/// See [`close_for`].
pub fn close(handle: u64) -> NTSTATUS {
    close_for(handle, Mode::Kernel)
}

/// Close a handle on behalf of `mode`: it stops naming its object, the
/// object's type is told (with the number of handles there were, this
/// one included), and the handle's reference is given up. What
/// `NtClose` returns.
///
/// A handle protected from close stays open. User mode is told so
/// (`STATUS_HANDLE_NOT_CLOSABLE`); kernel code that closes a protected
/// kernel handle has a bug, and the system stops as Windows does:
/// [`INVALID_KERNEL_HANDLE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x93--invalid-kernel-handle),
/// whose parameters are the handle, then zeros.
pub fn close_for(handle: u64, mode: Mode) -> NTSTATUS {
    let Some(index) = kernel_handle_index(handle) else {
        return STATUS_INVALID_HANDLE;
    };
    let closed = TABLE.lock().close(index);
    let body = match closed {
        Ok(Entry(body)) => body,
        Err(HandleError::Protected) if mode == Mode::Kernel => crate::kd::bugcheck(format_args!(
            "0x00000093 INVALID_KERNEL_HANDLE: kernel mode closed a handle protected \
                 from close (parameters {handle:#x}, 0, 0, 0)"
        )),
        Err(error) => return status(error),
    };
    // SAFETY: the entry held a reference, which this gives up, outside
    // the table's lock: the type's procedure may call a driver, and
    // freeing takes the pool's lock. Every handle is the System
    // process's, so its count of handles is the system's.
    unsafe {
        let handles = object::handle_count(body).fetch_sub(1, Ordering::AcqRel) as usize;
        if let Some(closed) = object::type_of(body).close_procedure() {
            closed(
                crate::ps::process::system().cast(),
                body.cast(),
                handles,
                handles,
            );
        }
        object::dereference(body);
    }
    STATUS_SUCCESS
}

/// [`ObReferenceObjectByHandle`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle).
/// The desired access is checked against the handle's for `UserMode`
/// and ignored for `KernelMode`.
///
/// # Safety
/// `object` points to room for a pointer; `handle_information` is null
/// or points to room for an `OBJECT_HANDLE_INFORMATION`.
pub unsafe extern "C" fn ObReferenceObjectByHandle(
    handle: *mut c_void,
    desired_access: u32,
    object_type: *const ObjectType,
    access_mode: i8,
    object: *mut *mut c_void,
    handle_information: *mut [u32; 2],
) -> NTSTATUS {
    let wanted = (!object_type.is_null()).then_some(object_type);
    let mode = match access_mode {
        nk_ntabi::io::KERNEL_MODE => Mode::Kernel,
        _ => Mode::User,
    };
    // SAFETY: per the contract.
    unsafe {
        match reference_for(handle as u64, wanted, desired_access, mode) {
            Ok((body, information)) => {
                object.write_unaligned(body.cast());
                if !handle_information.is_null() {
                    // `HandleAttributes`, then `GrantedAccess`.
                    let mut attributes = 0;
                    if information.attributes.inherit {
                        attributes |= OBJ_INHERIT;
                    }
                    if information.attributes.protect_from_close {
                        attributes |= OBJ_PROTECT_CLOSE;
                    }
                    handle_information.write_unaligned([attributes, information.granted]);
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

/// [`ObReferenceObjectByHandleWithTag`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandlewithtag):
/// [`ObReferenceObjectByHandle`], whose reference the tag would name
/// for object reference tracing (`object::ObfReferenceObjectWithTag`).
///
/// # Safety
/// As [`ObReferenceObjectByHandle`].
pub unsafe extern "C" fn ObReferenceObjectByHandleWithTag(
    handle: *mut c_void,
    desired_access: u32,
    object_type: *const ObjectType,
    access_mode: i8,
    _tag: u32,
    object: *mut *mut c_void,
    handle_information: *mut [u32; 2],
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        ObReferenceObjectByHandle(
            handle,
            desired_access,
            object_type,
            access_mode,
            object,
            handle_information,
        )
    }
}

/// [`ObOpenObjectByPointer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-obopenobjectbypointer):
/// a handle to an object the caller has a pointer to, granted the
/// desired access and given the attributes asked for. Every handle is
/// a kernel handle, and no access is checked: the access state and the
/// access mode are not looked at.
///
/// # Safety
/// `object` is an object-manager object the caller holds a reference
/// to; `handle` points to room for a handle.
pub unsafe extern "C" fn ObOpenObjectByPointer(
    object: *mut c_void,
    handle_attributes: u32,
    _access_state: *mut c_void,
    desired_access: u32,
    object_type: *const ObjectType,
    _access_mode: i8,
    handle: *mut *mut c_void,
) -> NTSTATUS {
    let attributes = Attributes {
        inherit: handle_attributes & OBJ_INHERIT != 0,
        protect_from_close: handle_attributes & OBJ_PROTECT_CLOSE != 0,
    };
    // SAFETY: per the contract.
    unsafe {
        if !object_type.is_null() && !core::ptr::eq(object_type, object::type_of(object.cast())) {
            handle.write_unaligned(core::ptr::null_mut());
            return STATUS_OBJECT_TYPE_MISMATCH;
        }
        match open_with(object.cast(), desired_access, attributes) {
            Ok(opened) => {
                handle.write_unaligned(opened as *mut c_void);
                STATUS_SUCCESS
            }
            Err(status) => {
                handle.write_unaligned(core::ptr::null_mut());
                status
            }
        }
    }
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
        // As a driver takes and drops them, with a tag and without:
        // each returns the count it made, and a tag changes no count.
        const TAG: u32 = u32::from_le_bytes(*b"NKob");
        let up = [
            object::ObfReferenceObject(body.cast()),
            object::ObfReferenceObjectWithTag(body.cast(), TAG),
        ];
        let down = [
            object::ObfDereferenceObject(body.cast()),
            object::ObfDereferenceObjectWithTag(body.cast(), TAG),
        ];
        if up != [2, 3] || down != [2, 1] {
            return Err("a driver's references did not count 2, 3, 2, 1");
        }
        if blocks() != before + 1 {
            return Err("an object was freed while still referenced");
        }
        if object::dereference(body) != 0 || blocks() != before {
            return Err("dropping the last reference did not free the object");
        }
    }
    Ok(10)
}

static SHARED: core::sync::atomic::AtomicPtr<u8> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());
static SHARED_WRONG: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// Threads on every processor take and drop references to one object
/// at once, as drivers do; none is lost and none invented. Returns the
/// references taken.
pub fn shared_reference_test() -> Result<u32, &'static str> {
    const ROUNDS: u32 = 5000;
    fn body(_: usize) {
        let shared = SHARED.load(Ordering::Acquire);
        for round in 0..ROUNDS {
            // SAFETY: the test holds a reference to the object until
            // every thread has ended.
            unsafe {
                let up = if round % 2 == 0 {
                    object::ObfReferenceObject(shared.cast())
                } else {
                    object::ObfReferenceObjectWithTag(shared.cast(), 1)
                };
                let down = object::ObfDereferenceObjectWithTag(shared.cast(), 1);
                // The test's own reference is always there besides.
                if up < 2 || down < 1 {
                    SHARED_WRONG.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
    let (pool_before, threads_before) = (blocks(), thread::count());
    let shared = new_event()?;
    SHARED.store(shared, Ordering::Release);
    SHARED_WRONG.store(0, Ordering::Relaxed);
    let processors = crate::ke::smp::online_count();
    let threads = processors.max(2) as u32;
    for n in 0..threads as usize {
        thread::create(body, 0, thread::NORMAL_PRIORITY, 1 << (n % processors))?;
    }
    let deadline = time::interrupt_time() + 100_000_000;
    while thread::count() != threads_before && time::interrupt_time() < deadline {
        thread::yield_now();
    }
    if thread::count() != threads_before {
        return Err("the threads did not finish");
    }
    // SAFETY: the creating reference, which must be the last.
    let left = unsafe { object::dereference(shared) };
    if SHARED_WRONG.load(Ordering::Relaxed) != 0 {
        return Err("a reference returned a count below what was certainly held");
    }
    if left != 0 || blocks() != pool_before {
        return Err("references taken on several processors were lost or invented");
    }
    Ok(threads * ROUNDS)
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
        let handle = open(body, 0).map_err(|_| "no memory for a handle")?;
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
        let handle = open(long.cast(), 0).map_err(|_| "no memory for a handle")?;
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

/// A handle remembers the access it was opened with and its
/// attributes; user mode gets the object only for access the handle
/// has, kernel mode always. Returns the look-ups made.
pub fn access_test() -> Result<u32, &'static str> {
    use nk_ntabi::io::{KERNEL_MODE, USER_MODE};
    // `EVENT_QUERY_STATE`, `EVENT_MODIFY_STATE`, `SYNCHRONIZE`.
    const QUERY: u32 = 0x1;
    const MODIFY: u32 = 0x2;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    let by_handle = |handle: u64, desired: u32, mode: i8| {
        let mut out = core::ptr::dangling_mut::<c_void>();
        let mut information = [u32::MAX; 2];
        // SAFETY: both outputs are locals.
        let status = unsafe {
            ObReferenceObjectByHandle(
                handle as *mut c_void,
                desired,
                core::ptr::null(),
                mode,
                &raw mut out,
                &raw mut information,
            )
        };
        if status == STATUS_SUCCESS {
            // SAFETY: the reference the look-up took.
            unsafe { object::dereference(out.cast()) };
        }
        (status, out.cast::<u8>(), information)
    };
    let (before, pool_before) = (count(), blocks());
    let body = new_event()?;
    let mut looked = 0;
    // SAFETY: `body` is a live object this test holds a reference to
    // until the end.
    let verdict = unsafe {
        (|| {
            let handle = open(body, QUERY).map_err(|_| "no memory for a handle")?;
            // Kernel mode is not held to the handle's access.
            for desired in [0, QUERY, MODIFY, QUERY | MODIFY | SYNCHRONIZE] {
                looked += 1;
                if by_handle(handle, desired, KERNEL_MODE) != (STATUS_SUCCESS, body, [0, QUERY]) {
                    return Err("kernel mode did not get the object and what the handle is");
                }
            }
            // User mode gets what the handle was granted, and no more.
            for desired in [0, QUERY] {
                looked += 1;
                if by_handle(handle, desired, USER_MODE) != (STATUS_SUCCESS, body, [0, QUERY]) {
                    return Err("user mode was refused access the handle has");
                }
            }
            for desired in [MODIFY, QUERY | MODIFY, SYNCHRONIZE] {
                looked += 1;
                let (status, found, _) = by_handle(handle, desired, USER_MODE);
                if status != STATUS_ACCESS_DENIED || !found.is_null() {
                    return Err("user mode was given access the handle does not have");
                }
            }
            // A second handle, with its own access and attributes.
            let mut second = core::ptr::null_mut();
            let status = ObOpenObjectByPointer(
                body.cast(),
                0x200 | OBJ_INHERIT,
                core::ptr::null_mut(),
                QUERY | MODIFY,
                object::ExEventObjectType.value(),
                KERNEL_MODE,
                &raw mut second,
            );
            let second = second as u64;
            let through = (
                by_handle(second, MODIFY, USER_MODE),
                by_handle(second, SYNCHRONIZE, USER_MODE).0,
                by_handle(handle, MODIFY, USER_MODE).0,
            );
            looked += 3;
            let closed = [close(second), close(handle)];
            let expected = (
                (STATUS_SUCCESS, body, [OBJ_INHERIT, QUERY | MODIFY]),
                STATUS_ACCESS_DENIED,
                STATUS_ACCESS_DENIED,
            );
            if status != STATUS_SUCCESS || through != expected {
                return Err("a handle opened by pointer does not have the access asked for");
            }
            if closed != [STATUS_SUCCESS; 2] {
                return Err("a handle could not be closed");
            }
            // The caller's own thread, by the handle that needs no table.
            looked += 1;
            let (status, found, information) = by_handle(CURRENT_THREAD, SYNCHRONIZE, USER_MODE);
            if status != STATUS_SUCCESS
                || found != crate::ke::thread::current().cast()
                || information != [0, ALL_ACCESS]
            {
                return Err("NtCurrentThread() is not a handle with every access");
            }
            Ok(())
        })()
    };
    // SAFETY: the creating reference.
    unsafe { object::dereference(body) };
    verdict?;
    // Generic rights are granted as what they mean for the type: a
    // key's `GENERIC_READ` is `KEY_READ`.
    let path: alloc::vec::Vec<u16> = "\\Registry\\Machine".encode_utf16().collect();
    let name = nk_ntabi::io::UNICODE_STRING {
        Length: (path.len() * 2) as u16,
        MaximumLength: (path.len() * 2) as u16,
        Buffer: path.as_ptr().cast_mut(),
    };
    let attributes = nk_ntabi::ob::OBJECT_ATTRIBUTES {
        Length: size_of::<nk_ntabi::ob::OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: core::ptr::null_mut(),
        ObjectName: &raw const name,
        Attributes: 0x240,
        SecurityDescriptor: core::ptr::null_mut(),
        SecurityQualityOfService: core::ptr::null_mut(),
    };
    let mut key = core::ptr::null_mut();
    // SAFETY: locals that outlive the call.
    let opened = unsafe { crate::cm::ZwOpenKey(&raw mut key, 0x8000_0000, &raw const attributes) };
    let information = by_handle(key as u64, 0x0002_0019, USER_MODE);
    let refused = by_handle(key as u64, 0x2, USER_MODE).0;
    looked += 2;
    close(key as u64);
    drop(path);
    if opened != STATUS_SUCCESS
        || (information.0, information.2) != (STATUS_SUCCESS, [0, 0x0002_0019])
        || refused != STATUS_ACCESS_DENIED
    {
        return Err("a handle asked for a generic right was not granted what it means");
    }
    if count() != before || blocks() != pool_before {
        return Err("handles or memory were left behind");
    }
    Ok(looked)
}

/// A handle protected from close: user mode is refused and the handle
/// stays good; then kernel mode closes it, which must stop the system.
/// `armed` is called just before that. Returns only if something went
/// wrong, saying what.
pub fn protected_close_test(armed: impl FnOnce()) -> &'static str {
    let Ok(body) = new_event() else {
        return "no memory";
    };
    let mut handle = core::ptr::null_mut();
    // SAFETY: a live object this test holds a reference to; the handle
    // is a local.
    let status = unsafe {
        ObOpenObjectByPointer(
            body.cast(),
            OBJ_PROTECT_CLOSE,
            core::ptr::null_mut(),
            0,
            object::ExEventObjectType.value(),
            nk_ntabi::io::KERNEL_MODE,
            &raw mut handle,
        )
    };
    let handle = handle as u64;
    if status != STATUS_SUCCESS {
        return "a protected handle could not be opened";
    }
    if close_for(handle, Mode::User) != STATUS_HANDLE_NOT_CLOSABLE {
        return "user mode was not told that a protected handle cannot be closed";
    }
    match reference(handle, None) {
        // SAFETY: the reference the look-up took.
        Ok(found) if found == body => unsafe {
            object::dereference(found);
        },
        _ => return "a protected handle user mode tried to close no longer names its object",
    }
    armed();
    close(handle);
    "kernel mode closed a protected kernel handle and the system went on"
}
