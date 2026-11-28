//! Handles: small numbers that stand for references to objects.
//!
//! One table for the whole kernel: the System process's, which is where
//! Windows keeps kernel handles too. A handle holds a reference to its
//! object until it is closed, and remembers the access it was opened
//! with and its attributes (`nk_ob::handles`).
//!
//! An entry has two names (`nk_ntabi::ob`). The kernel handle has its
//! high bits set, as on Windows, and is a handle for kernel mode only.
//! The same number without those bits is the System process's own
//! handle to the entry, good in that process for either mode; every
//! thread is in that process. A driver's open always gives the kernel
//! handle, with `OBJ_KERNEL_HANDLE` or without: on Windows a handle
//! made in the System process is in the kernel's table whatever was
//! asked. The other name is what NK's own requests on behalf of user
//! mode go by. There are no other processes and so no other tables.
//!
//! The access is checked when a handle is used on behalf of user mode
//! and never for kernel mode, as
//! [`ObReferenceObjectByHandle`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obreferenceobjectbyhandle)
//! documents. Nothing decides what access a subject may have: a handle
//! is granted what its opener asked for.

#![allow(non_snake_case)]

use super::object::{self, ObRef, ObjectType};
use crate::ex::pushlock::PushLock;
use core::ffi::c_void;
use core::sync::atomic::Ordering;
use nk_ntabi::ob::{handle_index, kernel_handle, process_handle};
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
/// `OBJ_KERNEL_HANDLE`: the opener wants the kernel handle.
pub const OBJ_KERNEL_HANDLE: u32 = 0x200;

/// An object in a handle table.
struct Entry(*mut u8);

// SAFETY: the table holds a reference to each object it lists, and the
// pointer is only used under the table's lock or with a reference taken
// there. Shared readers only read the pointer identity and bump the atomic
// reference count.
unsafe impl Send for Entry {}
// SAFETY: as above.
unsafe impl Sync for Entry {}

/// One process's handle table (`EPROCESS.ObjectTable`), guarded by a passive
/// push lock.
pub struct HandleTable(PushLock<Handles<Entry>>);

impl HandleTable {
    /// An empty handle table.
    pub const fn new() -> Self {
        Self(PushLock::new(Handles::new()))
    }

    /// Number of open handles in this table.
    pub fn count(&self) -> usize {
        self.0.read().count()
    }

    /// Pool bytes occupied by the table's slot array.
    pub fn storage(&self) -> usize {
        self.0.read().storage()
    }
}

/// The System process's handle table, which is also the kernel handle table.
static TABLE: HandleTable = HandleTable::new();

/// Pointer to the kernel / System process handle table (stored in the System
/// process's `EPROCESS.ObjectTable`).
pub fn kernel_table() -> *mut HandleTable {
    (&raw const TABLE).cast_mut()
}

/// Pool tag for per-process handle tables.
const TAG_HANDLE_TABLE: u32 = u32::from_le_bytes(*b"ObHt");

/// Allocate an empty per-process handle table in the pool.
pub fn create_table() -> Option<*mut HandleTable> {
    let raw = pool::alloc(size_of::<HandleTable>(), TAG_HANDLE_TABLE).cast::<HandleTable>();
    if raw.is_null() {
        return None;
    }
    // SAFETY: `raw` is a freshly allocated, aligned block of `HandleTable` size.
    unsafe { raw.write(HandleTable::new()) };
    Some(raw)
}

/// Close every handle in `table` (calling each object type's `CloseProcedure`
/// and dropping each handle's reference), then free `table`.
///
/// # Safety
/// `process` is the owning `EPROCESS`; `table` was returned by [`create_table`]
/// and is no longer reachable from any live thread.
pub unsafe fn destroy_table(process: *mut u8, table: *mut HandleTable) {
    if table.is_null() || core::ptr::eq(table, &raw const TABLE) {
        return;
    }
    // SAFETY: per the contract; exclusive ownership at process teardown.
    let entries = unsafe {
        let entries = (*table).0.lock().drain_all();
        core::ptr::drop_in_place(table);
        let _ = pool::free(table.cast());
        entries
    };
    for Entry(body) in entries {
        // SAFETY: each entry held a reference and a handle count.
        unsafe {
            let handles = object::handle_count(body).fetch_sub(1, Ordering::AcqRel) as usize;
            if let Some(closed) = object::type_of(body).close_procedure() {
                closed(process.cast(), body.cast(), 1, handles);
            }
            object::dereference(body);
        }
    }
}

/// Duplicate every `OBJ_INHERIT` handle from `parent`'s handle table into
/// `child`'s handle table.
///
/// # Safety
/// Both `parent` and `child` are live `EPROCESS` objects with valid
/// `ObjectTable` pointers.
pub unsafe fn inherit_handles(parent: *mut u8, child: *mut u8) -> Result<(), NTSTATUS> {
    // SAFETY: per the contract.
    let Some(src) = (unsafe { process_table(parent) }) else {
        return Ok(());
    };
    // SAFETY: per the contract.
    let Some(dst) = (unsafe { process_table(child) }) else {
        return Err(STATUS_INVALID_HANDLE);
    };
    if core::ptr::eq(src, dst) {
        return Ok(());
    }
    // Snapshot inheritable handles under `src`'s shared lock with fresh
    // references so we never hold two handle-table locks simultaneously.
    let mut inherited = alloc::vec::Vec::new();
    {
        let src_guard = src.0.read();
        for (_, h) in src_guard.iter() {
            if h.attributes.inherit {
                let target = h.object.0;
                // SAFETY: `src` holds a reference while locked.
                let held = unsafe { ObRef::new(target) };
                if inherited.try_reserve(1).is_err() {
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
                inherited.push((held, h.granted, h.attributes));
            }
        }
    }
    for (held, granted, attrs) in inherited {
        let target = held.body();
        // SAFETY: `held` keeps `target` alive while opening into `child`.
        let _ = unsafe { open_in(child, target, granted, attrs, false) }?;
    }
    Ok(())
}

/// The current thread's attached process (`EPROCESS`).
fn current_process() -> *mut u8 {
    let p = crate::ps::process::PsGetCurrentProcess().cast::<u8>();
    if p.is_null() {
        crate::ps::process::system()
    } else {
        p
    }
}

/// The handle table belonging to `process` (`EPROCESS.ObjectTable`), or
/// `&TABLE` for the System process.
///
/// # Safety
/// `process` is null or a live `EPROCESS`.
unsafe fn process_table<'a>(process: *mut u8) -> Option<&'a HandleTable> {
    if process.is_null() || process == crate::ps::process::system() {
        return Some(&TABLE);
    }
    // SAFETY: per the contract; `ObjectTable` is a pointer-aligned field.
    let ptr = unsafe {
        process
            .add(nk_ntabi::process::OBJECT_TABLE)
            .cast::<*mut HandleTable>()
            .read()
    };
    if ptr.is_null() {
        None
    } else {
        // SAFETY: `process` is live and owns its handle table until teardown.
        Some(unsafe { &*ptr })
    }
}

/// Select the handle table for `handle` in `process`: kernel handles always
/// address `&TABLE` (the System/kernel table); non-kernel handles address
/// `process`'s table.
///
/// # Safety
/// `process` is null or a live `EPROCESS`.
unsafe fn table_for<'a>(process: *mut u8, handle: u64) -> Option<&'a HandleTable> {
    if handle & nk_ntabi::ob::KERNEL_HANDLE == nk_ntabi::ob::KERNEL_HANDLE {
        Some(&TABLE)
    } else {
        // SAFETY: per the contract.
        unsafe { process_table(process) }
    }
}

/// The pool memory the kernel handle table itself occupies, as `(blocks, bytes)`. It
/// grows with the most handles ever open at once and is kept, so a leak
/// check must not count it as lost.
pub fn storage() -> (usize, usize) {
    let bytes = TABLE.storage();
    (usize::from(bytes != 0), bytes)
}

/// Handles that are open in the kernel/System handle table.
pub fn count() -> usize {
    TABLE.count()
}

fn status(error: HandleError) -> NTSTATUS {
    match error {
        HandleError::Invalid => STATUS_INVALID_HANDLE,
        HandleError::Denied => STATUS_ACCESS_DENIED,
        HandleError::Protected => STATUS_HANDLE_NOT_CLOSABLE,
        HandleError::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
    }
}

/// Open a kernel handle to an object, granted `access` (generic rights
/// are turned into what they mean for the object's type). The handle
/// takes its own reference.
///
/// # Safety
/// `body` is an object from `object::create` that the caller holds a
/// reference to.
pub unsafe fn open(body: *mut u8, access: u32) -> Result<u64, NTSTATUS> {
    // SAFETY: per the contract.
    unsafe { open_with(body, access, Attributes::default(), true) }
}

/// As [`open`], with the handle's attributes; `kernel` says whether to open
/// in the kernel handle table (returning a kernel handle) or in the current
/// process's handle table (returning a process handle).
///
/// # Safety
/// As [`open`].
pub unsafe fn open_with(
    body: *mut u8,
    access: u32,
    attributes: Attributes,
    kernel: bool,
) -> Result<u64, NTSTATUS> {
    // SAFETY: per the contract.
    unsafe { open_in(current_process(), body, access, attributes, kernel) }
}

/// Open a handle to `body` in `process`'s table (or the kernel table when
/// `kernel` is true).
///
/// # Safety
/// `process` is null or a live `EPROCESS`; `body` is a live object the caller
/// holds a reference to.
pub unsafe fn open_in(
    process: *mut u8,
    body: *mut u8,
    access: u32,
    attributes: Attributes,
    kernel: bool,
) -> Result<u64, NTSTATUS> {
    // SAFETY: per the contract.
    let ty = unsafe { object::type_of(body) };
    let mut granted = ty.map_generic(access);
    let owner = if kernel || process.is_null() {
        crate::ps::process::system()
    } else {
        process
    };
    if let Some(open_proc) = ty.open_procedure() {
        let mode = if kernel {
            nk_ntabi::io::KERNEL_MODE
        } else {
            nk_ntabi::io::USER_MODE
        };
        // SAFETY: per the contract; `body` is referenced by the caller and the
        // type's open procedure runs before the handle is inserted.
        let count = unsafe { object::handle_count(body).load(Ordering::Acquire) } as u32;
        // SAFETY: per `OB_OPEN_METHOD` contract.
        let status =
            unsafe { open_proc(0, mode, owner.cast(), body.cast(), &raw mut granted, count) };
        if !nt_success(status) {
            return Err(status);
        }
    }
    let handle_table = if kernel {
        &TABLE
    } else {
        // SAFETY: per the contract.
        unsafe { process_table(process) }.ok_or(STATUS_INVALID_HANDLE)?
    };
    let mut table = handle_table.0.lock();
    let index = table
        .insert(Entry(body), granted, attributes)
        .map_err(status)?;
    // SAFETY: per the contract. The handle gets its reference and its
    // place in the object's handle count before the table's lock is
    // released, at the end: its number is the lowest free slot's, which
    // anyone can guess, and a close takes the entry out under the same
    // lock before it gives either back.
    unsafe {
        object::reference(body);
        object::handle_count(body).fetch_add(1, Ordering::AcqRel);
    }
    Ok(if kernel {
        kernel_handle(index)
    } else {
        process_handle(index)
    })
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
pub fn reference(handle: u64, ty: Option<*const ObjectType>) -> Result<ObRef, NTSTATUS> {
    reference_for(handle, ty, 0, Mode::Kernel).map(|(body, _)| body)
}

/// As [`reference`], on behalf of `mode`: user mode gets the object
/// only if the handle was granted every right in `desired`, and a
/// kernel handle is no handle for it (`STATUS_INVALID_HANDLE`). Also
/// says what the handle is.
pub fn reference_for(
    handle: u64,
    ty: Option<*const ObjectType>,
    desired: u32,
    mode: Mode,
) -> Result<(ObRef, Information), NTSTATUS> {
    // SAFETY: current process is live for the duration of the call.
    unsafe { reference_in(current_process(), handle, ty, desired, mode) }
}

/// As [`reference_for`], resolving non-kernel handles against `process`'s
/// handle table.
///
/// # Safety
/// `process` is null or a live `EPROCESS`.
pub unsafe fn reference_in(
    process: *mut u8,
    handle: u64,
    ty: Option<*const ObjectType>,
    desired: u32,
    mode: Mode,
) -> Result<(ObRef, Information), NTSTATUS> {
    let current = match handle {
        CURRENT_THREAD => Some((
            crate::ke::thread::current().cast::<u8>(),
            &raw const object::THREAD_TYPE,
        )),
        CURRENT_PROCESS => Some((
            if process.is_null() {
                crate::ps::process::system()
            } else {
                process
            },
            &raw const object::PROCESS_TYPE,
        )),
        _ => None,
    };
    if let Some((body, its_type)) = current {
        if ty.is_some_and(|ty| !core::ptr::eq(ty, its_type)) {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        // SAFETY: the running thread holds a reference on itself, and
        // `process` is live per the contract.
        let body = unsafe { ObRef::new(body) };
        let information = Information {
            granted: ALL_ACCESS,
            attributes: Attributes::default(),
        };
        return Ok((body, information));
    }
    let index = handle_index(handle, mode == Mode::Kernel).ok_or(STATUS_INVALID_HANDLE)?;
    // SAFETY: per the contract.
    let handle_table = unsafe { table_for(process, handle) }.ok_or(STATUS_INVALID_HANDLE)?;
    let table = handle_table.0.read();
    let Entry(body) = table.reference(index, desired, mode).map_err(status)?;
    // SAFETY: the table holds a reference, and its lock is held, so the
    // object cannot go away before the new reference is taken.
    let body = unsafe {
        if ty.is_some_and(|ty| !core::ptr::eq(ty, object::type_of(*body))) {
            return Err(STATUS_OBJECT_TYPE_MISMATCH);
        }
        ObRef::new(*body)
    };
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
    Ok((body, information))
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
    // SAFETY: current process is live for the duration of the call.
    unsafe { close_in(current_process(), handle, mode) }
}

/// Close `handle` in `process`'s table (or the kernel table for a kernel
/// handle) on behalf of `mode`.
///
/// # Safety
/// `process` is null or a live `EPROCESS`.
pub unsafe fn close_in(process: *mut u8, handle: u64, mode: Mode) -> NTSTATUS {
    let Some(index) = handle_index(handle, mode == Mode::Kernel) else {
        return STATUS_INVALID_HANDLE;
    };
    // SAFETY: per the contract.
    let Some(handle_table) = (unsafe { table_for(process, handle) }) else {
        return STATUS_INVALID_HANDLE;
    };
    let owner = if handle & nk_ntabi::ob::KERNEL_HANDLE == nk_ntabi::ob::KERNEL_HANDLE
        || process.is_null()
    {
        crate::ps::process::system()
    } else {
        process
    };
    let veto_check = {
        let table = handle_table.0.read();
        if let Some(open) = table.get(index) {
            let body = open.object.0;
            // SAFETY: the table holds a reference while locked.
            unsafe {
                object::type_of(body)
                    .okay_to_close_procedure()
                    .map(|proc| (ObRef::new(body), proc))
            }
        } else {
            None
        }
    };
    if let Some((held, okay_to_close)) = veto_check {
        let prev = match mode {
            Mode::Kernel => nk_ntabi::io::KERNEL_MODE,
            Mode::User => nk_ntabi::io::USER_MODE,
        };
        // SAFETY: `held` keeps the object alive across `OkayToCloseProcedure`.
        let allowed = unsafe {
            okay_to_close(
                owner.cast(),
                held.body().cast(),
                handle as *mut c_void,
                prev,
            )
        };
        if allowed == 0 {
            return STATUS_HANDLE_NOT_CLOSABLE;
        }
    }
    let closed = handle_table.0.lock().close(index);
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
    // freeing takes the pool's lock.
    unsafe {
        let handles = object::handle_count(body).fetch_sub(1, Ordering::AcqRel) as usize;
        if let Some(closed) = object::type_of(body).close_procedure() {
            closed(owner.cast(), body.cast(), handles, handles);
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
                // The driver's reference now.
                object.write_unaligned(body.into_raw().cast());
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
/// desired access and given the attributes asked for. It is a kernel
/// handle with `OBJ_KERNEL_HANDLE` or without, as every handle made in
/// the System process is on Windows. No access is checked: the access
/// state and the access mode are not looked at.
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
        let kernel = handle_attributes & OBJ_KERNEL_HANDLE != 0
            || current_process() == crate::ps::process::system();
        match open_with(object.cast(), desired_access, attributes, kernel) {
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
    thread::settle(threads_before);
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
        if handle_index(handle, true).is_none() || (handle as i64) >= 0 || handle % 4 != 0 {
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
        // Nothing is a job: there are none.
        let (status, found, _) = by_handle(handle, object::PsJobType.value());
        if status != STATUS_OBJECT_TYPE_MISMATCH || !found.is_null() {
            return Err("a handle to an event was accepted as a job");
        }
        for bogus in [0, handle + 4096, handle & 0xFFFF_FFFF] {
            let (status, found, _) = by_handle(bogus, core::ptr::null());
            if status != STATUS_INVALID_HANDLE || !found.is_null() {
                return Err("something that is not an open handle was accepted");
            }
        }
        // The entry's other name: the System process's own handle.
        let own = handle & !nk_ntabi::ob::KERNEL_HANDLE;
        let (status, found, _) = by_handle(own, event_type);
        if status != STATUS_SUCCESS || found != body {
            return Err("the System process's own handle does not name the kernel handle's entry");
        }
        object::dereference(body);
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
    Ok(12)
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
        if by_handle.body() != long.cast() || join(long, None) != wait::STATUS_SUCCESS {
            return Err("a thread could not be waited for through its handle");
        }
        if time::interrupt_time() - started < 3_000_000 {
            return Err("a wait for a thread returned before the thread ended");
        }
        drop(by_handle);
        if close(handle) != STATUS_SUCCESS {
            return Err("the thread's handle could not be closed");
        }
    }
    // A thread seen to have ended is buried: its own reference went
    // before the waits for it returned.
    if thread::count() != threads_before || blocks() != pool_before {
        return Err("threads that ended and were let go of were not freed");
    }
    Ok(5)
}

/// A handle remembers the access it was opened with and its
/// attributes; user mode gets the object only for access the handle
/// has, kernel mode always; and a kernel handle is no handle for user
/// mode. Returns the look-ups made.
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
            let handle = open_with(body, QUERY, Attributes::default(), false)
                .map_err(|_| "no memory for a handle")?;
            if (handle as i64) <= 0 || handle % 4 != 0 {
                return Err("the System process's own handle is not a small positive number");
            }
            // The same entry as a kernel handle: nothing for user mode,
            // whatever it asks; the object for kernel mode.
            let kernel = handle | nk_ntabi::ob::KERNEL_HANDLE;
            for desired in [0, QUERY] {
                looked += 1;
                let (status, found, information) = by_handle(kernel, desired, USER_MODE);
                if status != STATUS_INVALID_HANDLE
                    || !found.is_null()
                    || information != [u32::MAX; 2]
                {
                    return Err("a kernel handle was a handle for user mode");
                }
            }
            looked += 1;
            if by_handle(kernel, MODIFY, KERNEL_MODE) != (STATUS_SUCCESS, body, [0, QUERY]) {
                return Err("kernel mode did not get the object through the kernel handle");
            }
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
                OBJ_INHERIT,
                core::ptr::null_mut(),
                QUERY | MODIFY,
                object::ExEventObjectType.value(),
                KERNEL_MODE,
                &raw mut second,
            );
            let second = second as u64;
            // Asked for with `OBJ_KERNEL_HANDLE` or without, the kernel
            // handle comes back.
            let mut third = core::ptr::null_mut();
            let opened = ObOpenObjectByPointer(
                body.cast(),
                OBJ_KERNEL_HANDLE,
                core::ptr::null_mut(),
                QUERY,
                object::ExEventObjectType.value(),
                KERNEL_MODE,
                &raw mut third,
            );
            let third = third as u64;
            looked += 1;
            let kinds = ((second as i64) < 0, (third as i64) < 0);
            let refused = (
                by_handle(second, 0, USER_MODE).0,
                by_handle(third, 0, USER_MODE).0,
            );
            if opened != STATUS_SUCCESS || close(third) != STATUS_SUCCESS {
                return Err("a kernel handle could not be opened by pointer and closed");
            }
            if kinds != (true, true) || refused != (STATUS_INVALID_HANDLE, STATUS_INVALID_HANDLE) {
                return Err(
                    "an open by pointer did not give a kernel handle, which user mode has no use of",
                );
            }
            // The System process's own name for the second handle's
            // entry: by it user mode gets what the handle was granted.
            let own = second & !nk_ntabi::ob::KERNEL_HANDLE;
            let through = (
                by_handle(own, MODIFY, USER_MODE),
                by_handle(own, SYNCHRONIZE, USER_MODE).0,
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
    // Asked of the entry by the name user mode can use.
    let own = key as u64 & !nk_ntabi::ob::KERNEL_HANDLE;
    let information = by_handle(own, 0x0002_0019, USER_MODE);
    let refused = by_handle(own, 0x2, USER_MODE).0;
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
    // User mode knows the entry by the System process's own name for it.
    if close_for(handle & !nk_ntabi::ob::KERNEL_HANDLE, Mode::User) != STATUS_HANDLE_NOT_CLOSABLE {
        return "user mode was not told that a protected handle cannot be closed";
    }
    match reference(handle, None) {
        Ok(found) if found.body() == body => {}
        _ => return "a protected handle user mode tried to close no longer names its object",
    }
    armed();
    close(handle);
    "kernel mode closed a protected kernel handle and the system went on"
}
