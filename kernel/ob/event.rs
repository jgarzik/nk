//! Events and waits by handle: `ZwCreateEvent`, `ZwOpenEvent`,
//! `ZwWaitForSingleObject`.
//!
//! An event made here is an object-manager object whose body is a
//! `KEVENT`; the handle is the only thing that holds it. A wait by
//! handle is a wait on the object the handle names, for the types
//! whose body begins with what a thread can wait on: an event, a
//! thread, the process.

#![allow(non_snake_case)]

use super::handle::{self, OBJ_KERNEL_HANDLE};
use super::object::{self, ObRef, ObjectType};
use crate::ke::wait;
use core::ffi::c_void;
use nk_ntabi::io::KERNEL_MODE;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::*;
use nk_ob::handles::Attributes;

/// `SYNCHRONIZE`: the right to wait on an object.
const SYNCHRONIZE: u32 = 0x0010_0000;
/// `OBJ_INHERIT`.
const OBJ_INHERIT: u32 = 0x2;
/// `OBJ_PERMANENT`, `OBJ_EXCLUSIVE`, `OBJ_OPENIF`, `OBJ_OPENLINK`.
const OBJ_PERMANENT: u32 = 0x10;
const OBJ_EXCLUSIVE: u32 = 0x20;
const OBJ_OPENIF: u32 = 0x80;
const OBJ_OPENLINK: u32 = 0x100;

/// [`ZwCreateEvent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwcreateevent):
/// a new event (`event_type` 0 for a notification event, 1 for a
/// synchronization event) and a handle to it, granted the access asked
/// for: a kernel handle with `OBJ_KERNEL_HANDLE` or without, as every
/// handle made in the System process is on Windows.
///
/// With a name in the attributes, the event is entered in the
/// namespace at that path (from the root or from `RootDirectory`): a
/// temporary event loses its name when its last handle closes, a
/// permanent one (`OBJ_PERMANENT`) keeps it until made temporary; a
/// collision fails with `STATUS_OBJECT_NAME_COLLISION`, or with
/// `OBJ_OPENIF` opens an existing event and returns
/// `STATUS_OBJECT_NAME_EXISTS`. `OBJ_EXCLUSIVE` is refused with
/// `STATUS_NOT_IMPLEMENTED` (the gap the ledger's "partial" stands
/// for). A security descriptor in the attributes is not looked at:
/// nothing checks access to an object.
///
/// # Safety
/// `event_handle` points to room for a handle; `object_attributes` is
/// null or points to an `OBJECT_ATTRIBUTES`.
pub unsafe extern "C" fn NtCreateEvent(
    event_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    event_type: u32,
    initial_state: u8,
) -> NTSTATUS {
    if event_type > 1 {
        return STATUS_INVALID_PARAMETER;
    }
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract; fault-protected for `UserMode`.
    let oa =
        match unsafe { crate::svc::capture::capture_object_attributes(object_attributes, mode) } {
            Ok(oa) => oa,
            Err(status) => return status,
        };
    let (root, name, attributes) = match oa {
        Some(oa) => {
            if oa.attributes & OBJ_OPENLINK != 0 {
                return STATUS_INVALID_PARAMETER;
            }
            if oa.attributes & OBJ_EXCLUSIVE != 0 {
                return STATUS_NOT_IMPLEMENTED;
            }
            (oa.root, oa.name.unwrap_or_default(), oa.attributes)
        }
        None => (core::ptr::null_mut(), alloc::vec::Vec::new(), 0),
    };
    let start = match super::resolve_namespace_root(root, name.is_empty(), mode) {
        Ok(start) => start,
        Err(status) => return status,
    };
    let made = super::create_event(
        start.as_ref().map(ObRef::body),
        &name,
        attributes & OBJ_PERMANENT != 0,
        attributes & OBJ_OPENIF != 0,
        event_type,
        initial_state,
    );
    drop(start);
    let (body, existed) = match made {
        Ok(made) => made,
        Err(status) => return status,
    };
    let kernel_handle = !crate::svc::capture::is_user(mode);
    // SAFETY: the reference `create_event` returned is given up once
    // the handle, if there is one, holds the event.
    unsafe {
        let opened = handle::open_with(
            body,
            desired_access,
            Attributes {
                inherit: attributes & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            kernel_handle,
        );
        if opened.is_err() && !existed && !name.is_empty() {
            // No handle was ever open: undo the namespace entry.
            super::make_temporary(body);
        }
        object::dereference(body);
        match opened {
            Ok(opened) => {
                if let Err(status) =
                    crate::svc::capture::write(event_handle, opened as *mut c_void, mode)
                {
                    let _ = handle::close_for(opened, crate::svc::capture::handle_mode(mode));
                    return status;
                }
                if existed {
                    STATUS_OBJECT_NAME_EXISTS
                } else {
                    STATUS_SUCCESS
                }
            }
            Err(status) => status,
        }
    }
}

/// [`ZwOpenEvent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwopenevent):
/// a handle, granted the access asked for, to the event the attributes
/// name (absolute, or relative to `RootDirectory`). A name that leads
/// to nothing is what the namespace says of it
/// (`STATUS_OBJECT_NAME_NOT_FOUND`, `STATUS_OBJECT_PATH_NOT_FOUND`); to
/// an object that is not an event, `STATUS_OBJECT_TYPE_MISMATCH`.
/// `mountmgr.sys` asks for an event the session manager makes on
/// Windows, which no one makes on NK: it is not found.
///
/// # Safety
/// `event_handle` points to room for a handle; `object_attributes`
/// points to an `OBJECT_ATTRIBUTES` whose name is a counted string.
pub unsafe extern "C" fn NtOpenEvent(
    event_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract; fault-protected for `UserMode`.
    let Some(oa) =
        (match unsafe { crate::svc::capture::capture_object_attributes(object_attributes, mode) } {
            Ok(oa) => oa,
            Err(status) => return status,
        })
    else {
        return STATUS_INVALID_PARAMETER;
    };
    if oa.attributes & OBJ_OPENLINK != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(wide) = oa.name else {
        return STATUS_OBJECT_NAME_INVALID;
    };
    let root = oa.root;
    let given = oa.attributes;
    // SAFETY: no parse context is needed for opening an event object.
    let (held, granted) = match unsafe {
        super::open_by_name(
            root,
            &wide,
            given,
            Some(&object::EVENT_TYPE),
            desired_access,
            mode,
            core::ptr::null_mut(),
        )
    } {
        Ok(found) => found,
        Err(status) => return status,
    };
    let body = held.body();
    let kernel_handle = !crate::svc::capture::is_user(mode);
    // SAFETY: the look-up's reference, given up once the handle, if
    // there is one, holds the event.
    unsafe {
        let opened = handle::open_with(
            body,
            granted,
            Attributes {
                inherit: given & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            kernel_handle,
        );
        drop(held);
        match opened {
            Ok(opened) => {
                if let Err(status) =
                    crate::svc::capture::write(event_handle, opened as *mut c_void, mode)
                {
                    let _ = handle::close_for(opened, crate::svc::capture::handle_mode(mode));
                    return status;
                }
                STATUS_SUCCESS
            }
            Err(status) => status,
        }
    }
}

/// Whether an object of type `ty` begins with a dispatcher header, so
/// that a wait on the object is a wait on its body.
fn waitable(ty: &ObjectType) -> bool {
    [
        &raw const object::EVENT_TYPE,
        &raw const object::THREAD_TYPE,
        &raw const object::PROCESS_TYPE,
        &raw const object::TIMER_TYPE,
        &raw const object::MUTANT_TYPE,
        &raw const object::SEMAPHORE_TYPE,
    ]
    .iter()
    .any(|&known| core::ptr::eq(ty, known))
}

/// [`ZwWaitForSingleObject`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwwaitforsingleobject):
/// wait, in kernel mode, on the object a handle names, which stays
/// referenced for the wait. Returns what the wait returns
/// (`STATUS_SUCCESS`, `STATUS_TIMEOUT`, `STATUS_ALERTED` if alertable),
/// or why the handle gave no object.
///
/// Events, threads and the process can be waited on. A handle to an
/// object of another type, which Windows would wait on through the
/// type's default object, stops the system by name: the ledger's
/// "partial".
///
/// # Safety
/// `timeout` is null or points to a due time.
pub unsafe extern "C" fn NtWaitForSingleObject(
    handle: *mut c_void,
    alertable: u8,
    timeout: *const i64,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    let timeout_val = if timeout.is_null() {
        None
    } else {
        // SAFETY: per the contract; fault-protected for `UserMode`.
        match unsafe { crate::svc::capture::read(timeout, mode) } {
            Ok(v) => Some(v),
            Err(status) => return status,
        }
    };
    let held = match handle::reference_for(
        handle as u64,
        None,
        SYNCHRONIZE,
        crate::svc::capture::handle_mode(mode),
    ) {
        Ok((held, _)) => held,
        Err(status) => return status,
    };
    let body = held.body();
    // SAFETY: the object is referenced until the wait is over; its
    // type says its body is a dispatcher object.
    unsafe {
        let ty = object::type_of(body);
        if !waitable(ty) {
            let name: alloc::string::String = char::decode_utf16(ty.name().iter().copied())
                .map(|c| c.unwrap_or('?'))
                .collect();
            crate::kd::bugcheck(format_args!(
                "ZwWaitForSingleObject: waiting on a handle to an object of type {name} is not \
                 implemented"
            ));
        }
        wait::wait_as(Some(body.cast()), timeout_val, mode, alertable != 0) as NTSTATUS
    }
}

const EVENT_MODIFY_STATE: u32 = 0x2;

/// [`NtSetEvent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwsetevent).
///
/// # Safety
/// `previous_state` is null or satisfies `PreviousMode`.
pub unsafe extern "C" fn NtSetEvent(
    event_handle: *mut c_void,
    previous_state: *mut i32,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    let (held, _) = match handle::reference_for(
        event_handle as u64,
        Some(&raw const object::EVENT_TYPE),
        EVENT_MODIFY_STATE,
        crate::svc::capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `held` keeps the `KEVENT` alive.
    let prev = unsafe { wait::KeSetEvent(held.body().cast(), 0, 0) };
    if !previous_state.is_null() {
        // SAFETY: per the contract.
        if let Err(st) = unsafe { crate::svc::capture::write(previous_state, prev, mode) } {
            return st;
        }
    }
    STATUS_SUCCESS
}

/// [`NtResetEvent`](https://learn.microsoft.com/en-us/windows/win32/devnotes/ntresetevent).
///
/// # Safety
/// `previous_state` is null or satisfies `PreviousMode`.
pub unsafe extern "C" fn NtResetEvent(
    event_handle: *mut c_void,
    previous_state: *mut i32,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    let (held, _) = match handle::reference_for(
        event_handle as u64,
        Some(&raw const object::EVENT_TYPE),
        EVENT_MODIFY_STATE,
        crate::svc::capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `held` keeps the `KEVENT` alive.
    let prev = unsafe { wait::KeResetEvent(held.body().cast()) };
    if !previous_state.is_null() {
        // SAFETY: per the contract.
        if let Err(st) = unsafe { crate::svc::capture::write(previous_state, prev, mode) } {
            return st;
        }
    }
    STATUS_SUCCESS
}

/// `NtSetEventBoostPriority`: set event with priority boost (NK does not apply boosts).
pub extern "C" fn NtSetEventBoostPriority(event_handle: *mut c_void) -> NTSTATUS {
    // SAFETY: `previous_state` is null.
    unsafe { NtSetEvent(event_handle, core::ptr::null_mut()) }
}

/// `NtClearEvent`: reset an event without returning its previous state.
pub extern "C" fn NtClearEvent(event_handle: *mut c_void) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    let (held, _) = match handle::reference_for(
        event_handle as u64,
        Some(&raw const object::EVENT_TYPE),
        EVENT_MODIFY_STATE,
        crate::svc::capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `held` keeps the `KEVENT` alive.
    unsafe { wait::KeClearEvent(held.body().cast()) };
    STATUS_SUCCESS
}

/// [`NtWaitForMultipleObjects`](https://learn.microsoft.com/en-us/windows/win32/devnotes/ntwaitformultipleobjects).
///
/// # Safety
/// `handles` and `timeout` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtWaitForMultipleObjects(
    count: u32,
    handles: *const *mut c_void,
    wait_type: u32,
    alertable: u8,
    timeout: *const i64,
) -> NTSTATUS {
    const MAX_WAIT: usize = 64;
    let n = count as usize;
    if n == 0 || n > MAX_WAIT || wait_type > 1 || handles.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let mode = crate::svc::capture::mode();
    let timeout_val = if timeout.is_null() {
        None
    } else {
        // SAFETY: per the contract.
        match unsafe { crate::svc::capture::read(timeout, mode) } {
            Ok(v) => Some(v),
            Err(st) => return st,
        }
    };
    let mut raw_handles = alloc::vec![core::ptr::null_mut::<c_void>(); n];
    // SAFETY: per the contract; `copy_from_caller` probes user pointers.
    let cp = unsafe {
        crate::svc::capture::copy_from_caller(
            core::slice::from_raw_parts_mut(
                raw_handles.as_mut_ptr().cast::<u8>(),
                n * size_of::<*mut c_void>(),
            ),
            handles.cast::<u8>(),
            mode,
        )
    };
    if let Err(st) = cp {
        return st;
    }
    let hmode = crate::svc::capture::handle_mode(mode);
    let mut refs: alloc::vec::Vec<ObRef> = alloc::vec::Vec::with_capacity(n);
    let mut ptrs: alloc::vec::Vec<*mut c_void> = alloc::vec::Vec::with_capacity(n);
    for &h in &raw_handles {
        let (held, _) = match handle::reference_for(h as u64, None, SYNCHRONIZE, hmode) {
            Ok(found) => found,
            Err(st) => return st,
        };
        // SAFETY: `held` is a live object.
        let ty = unsafe { object::type_of(held.body()) };
        if !waitable(ty) {
            return STATUS_INVALID_HANDLE;
        }
        let p = held.body().cast::<c_void>();
        if wait_type == 0 && ptrs.contains(&p) {
            return STATUS_INVALID_PARAMETER_2;
        }
        ptrs.push(p);
        refs.push(held);
    }
    // SAFETY: `KWAIT_BLOCK` is all-zero valid.
    let mut blocks: [nk_ntabi::ke::KWAIT_BLOCK; MAX_WAIT] = unsafe { core::mem::zeroed() };
    let due_ptr = timeout_val
        .as_ref()
        .map_or(core::ptr::null(), core::ptr::from_ref);
    // SAFETY: `refs` keeps all dispatcher objects alive for the duration of the wait;
    // `blocks` has `MAX_WAIT >= n` entries.
    let status = unsafe {
        wait::KeWaitForMultipleObjects(
            count,
            ptrs.as_ptr(),
            wait_type,
            0,
            mode,
            alertable,
            due_ptr,
            blocks.as_mut_ptr(),
        )
    };
    drop(refs);
    status
}

/// [`NtCreateMutant`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntcreatemutant).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtCreateMutant(
    mutant_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    initial_owner: u8,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract.
    let oa =
        match unsafe { crate::svc::capture::capture_object_attributes(object_attributes, mode) } {
            Ok(oa) => oa,
            Err(st) => return st,
        };
    let (root, name, attributes) = match oa {
        Some(oa) => {
            if oa.attributes & OBJ_OPENLINK != 0 {
                return STATUS_INVALID_PARAMETER;
            }
            if oa.attributes & OBJ_EXCLUSIVE != 0 {
                return STATUS_NOT_IMPLEMENTED;
            }
            (oa.root, oa.name.unwrap_or_default(), oa.attributes)
        }
        None => (core::ptr::null_mut(), alloc::vec::Vec::new(), 0),
    };
    let start = match super::resolve_namespace_root(root, name.is_empty(), mode) {
        Ok(s) => s,
        Err(st) => return st,
    };
    let leaf_name = super::leaf(&name);
    let body = if name.is_empty() {
        object::create(&object::MUTANT_TYPE, size_of::<nk_ntabi::ke::KMUTANT>())
    } else {
        object::create_named(
            &object::MUTANT_TYPE,
            size_of::<nk_ntabi::ke::KMUTANT>(),
            leaf_name,
        )
    };
    let Some(body) = body else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: fresh zeroed `KMUTANT` storage.
    unsafe { crate::ke::mutex::init_mutant(body.cast(), initial_owner != 0) };
    let (final_body, existed) = if name.is_empty() {
        (body, false)
    } else {
        // SAFETY: `body` is a fresh named `MUTANT_TYPE` object.
        match unsafe {
            super::insert_named(
                start.as_ref().map(ObRef::body),
                &name,
                body,
                &object::MUTANT_TYPE,
                attributes & OBJ_PERMANENT != 0,
                attributes & OBJ_OPENIF != 0,
            )
        } {
            Ok((b, ex)) => {
                if ex {
                    // Existing object returned; release initial ownership if we took it on `body`.
                    if initial_owner != 0 {
                        // SAFETY: `body` was initialized above.
                        let _ = unsafe { crate::ke::mutex::try_release_mutant(body.cast()) };
                    }
                    // SAFETY: `body` was not inserted.
                    unsafe { object::dereference(body) };
                }
                (b, ex)
            }
            Err(st) => {
                if initial_owner != 0 {
                    // SAFETY: `body` was initialized above.
                    let _ = unsafe { crate::ke::mutex::try_release_mutant(body.cast()) };
                }
                // SAFETY: `body` was not inserted.
                unsafe { object::dereference(body) };
                return st;
            }
        }
    };
    drop(start);
    let kernel_handle =
        !crate::svc::capture::is_user(mode) || (attributes & OBJ_KERNEL_HANDLE) != 0;
    // SAFETY: `final_body` carries one caller reference.
    unsafe {
        let opened = handle::open_with(
            final_body,
            desired_access,
            Attributes {
                inherit: attributes & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            kernel_handle,
        );
        if opened.is_err() && !existed && !name.is_empty() {
            super::make_temporary(final_body);
        }
        object::dereference(final_body);
        match opened {
            Ok(h) => {
                if let Err(st) = crate::svc::capture::write(mutant_handle, h as *mut c_void, mode) {
                    let _ = handle::close_for(h, crate::svc::capture::handle_mode(mode));
                    return st;
                }
                if existed {
                    STATUS_OBJECT_NAME_EXISTS
                } else {
                    STATUS_SUCCESS
                }
            }
            Err(st) => st,
        }
    }
}

/// `NtOpenMutant`: open an existing named `MUTANT_TYPE` object.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtOpenMutant(
    mutant_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract.
    let Some(oa) =
        (match unsafe { crate::svc::capture::capture_object_attributes(object_attributes, mode) } {
            Ok(oa) => oa,
            Err(st) => return st,
        })
    else {
        return STATUS_INVALID_PARAMETER;
    };
    let Some(wide) = oa.name else {
        return STATUS_OBJECT_NAME_INVALID;
    };
    // SAFETY: `parse_context` is null for mutant opens.
    let (held, granted) = match unsafe {
        super::open_by_name(
            oa.root,
            &wide,
            oa.attributes,
            Some(&object::MUTANT_TYPE),
            desired_access,
            mode,
            core::ptr::null_mut(),
        )
    } {
        Ok(found) => found,
        Err(st) => return st,
    };
    let kernel_handle =
        !crate::svc::capture::is_user(mode) || (oa.attributes & OBJ_KERNEL_HANDLE) != 0;
    // SAFETY: `held` keeps the mutant alive while opening the handle.
    let h = match unsafe {
        handle::open_with(
            held.body(),
            granted,
            Attributes {
                inherit: oa.attributes & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            kernel_handle,
        )
    } {
        Ok(h) => h,
        Err(st) => return st,
    };
    // SAFETY: per the contract.
    if let Err(st) = unsafe { crate::svc::capture::write(mutant_handle, h as *mut c_void, mode) } {
        let _ = handle::close_for(h, crate::svc::capture::handle_mode(mode));
        return st;
    }
    STATUS_SUCCESS
}

/// `NtReleaseMutant`: release a `MUTANT_TYPE` object owned by the calling thread.
///
/// # Safety
/// `previous_count` is null or satisfies `PreviousMode`.
pub unsafe extern "C" fn NtReleaseMutant(
    mutant_handle: *mut c_void,
    previous_count: *mut i32,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    let (held, _) = match handle::reference_for(
        mutant_handle as u64,
        Some(&raw const object::MUTANT_TYPE),
        0,
        crate::svc::capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `held` is a live `KMUTANT`.
    let prev = match unsafe { crate::ke::mutex::try_release_mutant(held.body().cast()) } {
        Ok(p) => p,
        Err(st) => return st,
    };
    if !previous_count.is_null() {
        // SAFETY: per the contract.
        if let Err(st) = unsafe { crate::svc::capture::write(previous_count, prev, mode) } {
            return st;
        }
    }
    STATUS_SUCCESS
}

/// `NtCreateSemaphore`: create a `SEMAPHORE_TYPE` (`KSEMAPHORE`) object.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtCreateSemaphore(
    semaphore_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    initial_count: i32,
    maximum_count: i32,
) -> NTSTATUS {
    if maximum_count <= 0 || initial_count < 0 || initial_count > maximum_count {
        return STATUS_INVALID_PARAMETER;
    }
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract.
    let oa =
        match unsafe { crate::svc::capture::capture_object_attributes(object_attributes, mode) } {
            Ok(oa) => oa,
            Err(st) => return st,
        };
    let (root, name, attributes) = match oa {
        Some(oa) => {
            if oa.attributes & OBJ_OPENLINK != 0 {
                return STATUS_INVALID_PARAMETER;
            }
            if oa.attributes & OBJ_EXCLUSIVE != 0 {
                return STATUS_NOT_IMPLEMENTED;
            }
            (oa.root, oa.name.unwrap_or_default(), oa.attributes)
        }
        None => (core::ptr::null_mut(), alloc::vec::Vec::new(), 0),
    };
    let start = match super::resolve_namespace_root(root, name.is_empty(), mode) {
        Ok(s) => s,
        Err(st) => return st,
    };
    let leaf_name = super::leaf(&name);
    let body = if name.is_empty() {
        object::create(
            &object::SEMAPHORE_TYPE,
            size_of::<nk_ntabi::ke::KSEMAPHORE>(),
        )
    } else {
        object::create_named(
            &object::SEMAPHORE_TYPE,
            size_of::<nk_ntabi::ke::KSEMAPHORE>(),
            leaf_name,
        )
    };
    let Some(body) = body else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: fresh zeroed `KSEMAPHORE` storage.
    unsafe { wait::KeInitializeSemaphore(body.cast(), initial_count, maximum_count) };
    let (final_body, existed) = if name.is_empty() {
        (body, false)
    } else {
        // SAFETY: `body` is a fresh named `SEMAPHORE_TYPE` object.
        match unsafe {
            super::insert_named(
                start.as_ref().map(ObRef::body),
                &name,
                body,
                &object::SEMAPHORE_TYPE,
                attributes & OBJ_PERMANENT != 0,
                attributes & OBJ_OPENIF != 0,
            )
        } {
            Ok((b, ex)) => {
                if ex {
                    // SAFETY: `body` was not inserted.
                    unsafe { object::dereference(body) };
                }
                (b, ex)
            }
            Err(st) => {
                // SAFETY: `body` was not inserted.
                unsafe { object::dereference(body) };
                return st;
            }
        }
    };
    drop(start);
    let kernel_handle =
        !crate::svc::capture::is_user(mode) || (attributes & OBJ_KERNEL_HANDLE) != 0;
    // SAFETY: `final_body` carries one caller reference.
    unsafe {
        let opened = handle::open_with(
            final_body,
            desired_access,
            Attributes {
                inherit: attributes & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            kernel_handle,
        );
        if opened.is_err() && !existed && !name.is_empty() {
            super::make_temporary(final_body);
        }
        object::dereference(final_body);
        match opened {
            Ok(h) => {
                if let Err(st) =
                    crate::svc::capture::write(semaphore_handle, h as *mut c_void, mode)
                {
                    let _ = handle::close_for(h, crate::svc::capture::handle_mode(mode));
                    return st;
                }
                if existed {
                    STATUS_OBJECT_NAME_EXISTS
                } else {
                    STATUS_SUCCESS
                }
            }
            Err(st) => st,
        }
    }
}

/// `NtOpenSemaphore`: open an existing named `SEMAPHORE_TYPE` object.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtOpenSemaphore(
    semaphore_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let mode = crate::svc::capture::mode();
    // SAFETY: per the contract.
    let Some(oa) =
        (match unsafe { crate::svc::capture::capture_object_attributes(object_attributes, mode) } {
            Ok(oa) => oa,
            Err(st) => return st,
        })
    else {
        return STATUS_INVALID_PARAMETER;
    };
    let Some(wide) = oa.name else {
        return STATUS_OBJECT_NAME_INVALID;
    };
    // SAFETY: `parse_context` is null for semaphore opens.
    let (held, granted) = match unsafe {
        super::open_by_name(
            oa.root,
            &wide,
            oa.attributes,
            Some(&object::SEMAPHORE_TYPE),
            desired_access,
            mode,
            core::ptr::null_mut(),
        )
    } {
        Ok(found) => found,
        Err(st) => return st,
    };
    let kernel_handle =
        !crate::svc::capture::is_user(mode) || (oa.attributes & OBJ_KERNEL_HANDLE) != 0;
    // SAFETY: `held` keeps the semaphore alive while opening the handle.
    let h = match unsafe {
        handle::open_with(
            held.body(),
            granted,
            Attributes {
                inherit: oa.attributes & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            kernel_handle,
        )
    } {
        Ok(h) => h,
        Err(st) => return st,
    };
    // SAFETY: per the contract.
    if let Err(st) = unsafe { crate::svc::capture::write(semaphore_handle, h as *mut c_void, mode) }
    {
        let _ = handle::close_for(h, crate::svc::capture::handle_mode(mode));
        return st;
    }
    STATUS_SUCCESS
}

/// `NtReleaseSemaphore`: increment a `SEMAPHORE_TYPE` object's count.
///
/// # Safety
/// `previous_count` is null or satisfies `PreviousMode`.
pub unsafe extern "C" fn NtReleaseSemaphore(
    semaphore_handle: *mut c_void,
    release_count: i32,
    previous_count: *mut i32,
) -> NTSTATUS {
    const SEMAPHORE_MODIFY_STATE: u32 = 0x0002;
    let mode = crate::svc::capture::mode();
    let (held, _) = match handle::reference_for(
        semaphore_handle as u64,
        Some(&raw const object::SEMAPHORE_TYPE),
        SEMAPHORE_MODIFY_STATE,
        crate::svc::capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `held` is a live `KSEMAPHORE`.
    let prev = match unsafe { wait::try_release_semaphore(held.body().cast(), release_count) } {
        Ok(p) => p,
        Err(st) => return st,
    };
    if !previous_count.is_null() {
        // SAFETY: per the contract.
        if let Err(st) = unsafe { crate::svc::capture::write(previous_count, prev, mode) } {
            return st;
        }
    }
    STATUS_SUCCESS
}

// ---- tests --------------------------------------------------------------

/// Events made and waited on through handles, as a driver does it, and
/// the other things a handle can be waited on for. Returns the waits
/// made.
pub fn self_test() -> Result<u32, &'static str> {
    use crate::ke::{thread, time};
    const EVENT_ALL_ACCESS: u32 = 0x001F_0003;
    let attributes = |flags: u32| OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: core::ptr::null_mut(),
        ObjectName: core::ptr::null(),
        Attributes: flags,
        SecurityDescriptor: core::ptr::null_mut(),
        SecurityQualityOfService: core::ptr::null_mut(),
    };
    let create = |given: Option<&OBJECT_ATTRIBUTES>, kind: u32, state: u8| {
        let mut opened = core::ptr::dangling_mut::<c_void>();
        let given = given.map_or(core::ptr::null(), core::ptr::from_ref);
        // SAFETY: locals that outlive the call.
        let status =
            unsafe { ZwCreateEvent(&raw mut opened, EVENT_ALL_ACCESS, given, kind, state) };
        (status, opened)
    };
    let wait_on = |opened: *mut c_void, alertable: u8, ms: Option<i64>| {
        let due = ms.map(|ms| -ms * 10_000);
        let timeout = due.as_ref().map_or(core::ptr::null(), core::ptr::from_ref);
        // SAFETY: the due time is a local.
        unsafe { ZwWaitForSingleObject(opened, alertable, timeout) }
    };
    let close = |opened: *mut c_void| handle::close(opened as u64);
    let kernel = attributes(OBJ_KERNEL_HANDLE);

    // A notification event, signalled, through a kernel handle.
    let (status, event) = create(Some(&kernel), 0, 1);
    if status != STATUS_SUCCESS || (event as i64) >= 0 {
        return Err("an event could not be created with a kernel handle");
    }
    let mut body = core::ptr::null_mut();
    // SAFETY: the output is a local; the reference is dropped below.
    let found = unsafe {
        handle::ObReferenceObjectByHandle(
            event,
            EVENT_ALL_ACCESS,
            object::ExEventObjectType.value(),
            KERNEL_MODE,
            &raw mut body,
            core::ptr::null_mut(),
        )
    };
    if found != STATUS_SUCCESS {
        close(event);
        return Err("the handle of a new event does not name an event object");
    }
    let asked = time::interrupt_time();
    // SAFETY: the event, referenced above until the end of the block.
    let notification = unsafe {
        let signalled = wait_on(event, 0, Some(0));
        wait::KeResetEvent(body.cast());
        let reset = [wait_on(event, 0, Some(0)), wait_on(event, 0, Some(20))];
        let waited = time::interrupt_time() - asked;
        wait::KeSetEvent(body.cast(), 0, 0);
        let set = [wait_on(event, 0, None), wait_on(event, 0, None)];
        object::dereference(body.cast());
        (signalled, reset, waited >= 200_000, set)
    };
    let closed = close(event);
    if notification != (0, [STATUS_TIMEOUT; 2], true, [0; 2]) || closed != STATUS_SUCCESS {
        return Err("a wait by handle did not follow the event's state and the time limit");
    }

    // A synchronization event satisfies one wait. No attributes: the
    // handle is a kernel handle all the same.
    let (status, event) = create(None, 1, 1);
    let kernel_handle = (event as i64) < 0;
    let once = [wait_on(event, 0, Some(0)), wait_on(event, 0, Some(0))];
    let closed = close(event);
    if status != STATUS_SUCCESS || !kernel_handle || closed != STATUS_SUCCESS {
        return Err("an event could not be created without object attributes");
    }
    if once != [0, STATUS_TIMEOUT] {
        return Err("a synchronization event by handle did not satisfy exactly one wait");
    }

    // Named events: temporary, collision, OBJ_OPENIF, ZwOpenEvent,
    // permanent + ZwMakeTemporaryObject, and what is still refused.
    let named: alloc::vec::Vec<u16> = "\\NkNamedEvent".encode_utf16().collect();
    let name = nk_ntabi::io::UNICODE_STRING {
        Length: (named.len() * 2) as u16,
        MaximumLength: (named.len() * 2) as u16,
        Buffer: named.as_ptr().cast_mut(),
    };
    let with_name = |flags: u32| OBJECT_ATTRIBUTES {
        ObjectName: &raw const name,
        ..attributes(flags)
    };
    let open = |given: &OBJECT_ATTRIBUTES| {
        let mut opened = core::ptr::dangling_mut::<c_void>();
        // SAFETY: locals that outlive the call.
        let status = unsafe { ZwOpenEvent(&raw mut opened, EVENT_ALL_ACCESS, given) };
        (status, opened)
    };
    let (status, first) = create(Some(&with_name(OBJ_KERNEL_HANDLE)), 0, 1);
    if status != STATUS_SUCCESS {
        return Err("a named event could not be created");
    }
    let collision = create(Some(&with_name(OBJ_KERNEL_HANDLE)), 0, 0).0;
    let (existed, second) = create(Some(&with_name(OBJ_KERNEL_HANDLE | OBJ_OPENIF)), 0, 0);
    let (opened_status, third) = open(&with_name(OBJ_KERNEL_HANDLE));
    let waited = (wait_on(second, 0, Some(0)), wait_on(third, 0, Some(0)));
    close(first);
    close(second);
    close(third);
    // Temporary: the name is gone once the last handle closes.
    let gone = open(&with_name(OBJ_KERNEL_HANDLE)).0;
    if collision != STATUS_OBJECT_NAME_COLLISION
        || existed != STATUS_OBJECT_NAME_EXISTS
        || opened_status != STATUS_SUCCESS
        || waited != (0, 0)
        || gone != STATUS_OBJECT_NAME_NOT_FOUND
    {
        return Err("a temporary named event did not follow Windows' rules");
    }
    // Permanent: outlives its handle until ZwMakeTemporaryObject.
    let (status, perm) = create(Some(&with_name(OBJ_KERNEL_HANDLE | OBJ_PERMANENT)), 0, 0);
    if status != STATUS_SUCCESS {
        return Err("a permanent named event could not be created");
    }
    close(perm);
    let (reopened_status, reopened) = open(&with_name(OBJ_KERNEL_HANDLE));
    if reopened_status != STATUS_SUCCESS {
        return Err("a permanent named event lost its name with its handle");
    }
    let made_temp = super::directory::ZwMakeTemporaryObject(reopened);
    close(reopened);
    let gone_after = open(&with_name(OBJ_KERNEL_HANDLE)).0;
    if made_temp != STATUS_SUCCESS || gone_after != STATUS_OBJECT_NAME_NOT_FOUND {
        return Err("a permanent event made temporary kept its name after close");
    }

    // What is refused, and that a refusal writes no handle.
    let short = OBJECT_ATTRIBUTES {
        Length: 24,
        ..attributes(0)
    };
    let untouched = core::ptr::dangling_mut::<c_void>();
    let refused = [
        create(Some(&kernel), 2, 0),
        create(Some(&short), 0, 0),
        create(Some(&attributes(0x1)), 0, 0),
        create(Some(&with_name(OBJ_OPENLINK)), 0, 0),
        create(Some(&with_name(OBJ_EXCLUSIVE)), 0, 0),
    ];
    let expected = [
        STATUS_INVALID_PARAMETER,
        STATUS_INVALID_PARAMETER,
        STATUS_INVALID_PARAMETER,
        STATUS_INVALID_PARAMETER,
        STATUS_NOT_IMPLEMENTED,
    ];
    if refused
        .iter()
        .zip(expected)
        .any(|(got, status)| *got != (status, untouched))
    {
        return Err("an event that cannot be made was not refused, or a handle was written");
    }

    // A thread through its handle: not signalled until it has ended.
    fn sleeper(_: usize) {
        // SAFETY: no object is involved.
        unsafe { wait::wait(None, Some(-300_000)) };
    }
    let started = thread::create_referenced(sleeper, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    // SAFETY: a thread this test holds a reference to, which it gives
    // up once the handle holds the thread.
    let opened = unsafe {
        let opened = handle::open(started.cast(), SYNCHRONIZE);
        object::dereference(started.cast());
        opened.map_err(|_| "no memory for a handle")? as *mut c_void
    };
    let of_thread = [wait_on(opened, 0, Some(0)), wait_on(opened, 0, None)];
    let again = wait_on(opened, 0, Some(0));
    close(opened);
    if of_thread != [STATUS_TIMEOUT, 0] || again != 0 {
        return Err("a wait on a thread's handle did not last until the thread ended");
    }

    // The process never ends; null is no handle; and a wait by handle
    // is alertable when asked to be.
    let process = wait_on(-1i64 as *mut c_void, 0, Some(0));
    let nothing = wait_on(core::ptr::null_mut(), 0, Some(0));
    let (status, event) = create(Some(&kernel), 0, 0);
    if status != STATUS_SUCCESS {
        return Err("no memory for an event");
    }
    let alerts = [
        crate::ps::ZwAlertThread(-2i64 as *mut c_void),
        wait_on(event, 0, Some(0)),
        wait_on(event, 1, Some(0)),
        wait_on(event, 1, Some(0)),
    ];
    close(event);
    if process != STATUS_TIMEOUT || nothing != STATUS_INVALID_HANDLE {
        return Err("a wait on the process or on no handle did not say so");
    }
    if alerts != [0, STATUS_TIMEOUT, STATUS_ALERTED, STATUS_TIMEOUT] {
        return Err("an alertable wait by handle was not alerted, or another was");
    }
    Ok(16)
}

pub use crate::svc::zw::{ZwCreateEvent, ZwOpenEvent, ZwWaitForSingleObject};
