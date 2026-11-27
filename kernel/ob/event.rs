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
use super::object::{self, ObjectType};
use crate::ke::wait;
use core::ffi::c_void;
use nk_ntabi::io::KERNEL_MODE;
use nk_ntabi::ke::KEVENT;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::*;
use nk_ob::handles::{Attributes, Mode};

/// `SYNCHRONIZE`: the right to wait on an object.
const SYNCHRONIZE: u32 = 0x0010_0000;
/// `OBJ_INHERIT`.
const OBJ_INHERIT: u32 = 0x2;
/// `OBJ_PERMANENT`, `OBJ_EXCLUSIVE`: about an object's name.
const OBJ_PERMANENT: u32 = 0x10;
const OBJ_EXCLUSIVE: u32 = 0x20;
/// `OBJ_VALID_ATTRIBUTES` (`wdm.h`): every attribute there is.
const OBJ_VALID_ATTRIBUTES: u32 = 0x1FF2;

/// [`ZwCreateEvent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwcreateevent):
/// a new event (`event_type` 0 for a notification event, 1 for a
/// synchronization event) and a handle to it, granted the access asked
/// for: a kernel handle with `OBJ_KERNEL_HANDLE` or without, as every
/// handle made in the System process is on Windows.
///
/// Only events without a name are made. Object attributes that name
/// the event, or ask for it to be permanent or exclusive (which is
/// about names), are refused with `STATUS_NOT_IMPLEMENTED`; that is
/// the gap the ledger's "partial" stands for. A security descriptor in
/// the attributes is not looked at: nothing checks access to an
/// object.
///
/// # Safety
/// `event_handle` points to room for a handle; `object_attributes` is
/// null or points to an `OBJECT_ATTRIBUTES`.
pub unsafe extern "C" fn ZwCreateEvent(
    event_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    event_type: u32,
    initial_state: u8,
) -> NTSTATUS {
    if event_type > 1 {
        return STATUS_INVALID_PARAMETER;
    }
    let mut attributes = 0;
    if !object_attributes.is_null() {
        // SAFETY: per the contract; the driver's memory, read field by
        // field through its pointer.
        let (length, name, given) = unsafe {
            (
                (&raw const (*object_attributes).Length).read_unaligned(),
                (&raw const (*object_attributes).ObjectName).read_unaligned(),
                (&raw const (*object_attributes).Attributes).read_unaligned(),
            )
        };
        if length as usize != size_of::<OBJECT_ATTRIBUTES>() || given & !OBJ_VALID_ATTRIBUTES != 0 {
            return STATUS_INVALID_PARAMETER;
        }
        if !name.is_null() || given & (OBJ_PERMANENT | OBJ_EXCLUSIVE) != 0 {
            return STATUS_NOT_IMPLEMENTED;
        }
        attributes = given;
    }
    let Some(body) = object::create(&object::EVENT_TYPE, size_of::<KEVENT>()) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: fresh storage of an event's size; the creating reference
    // is given up once the handle, if there is one, holds the event.
    unsafe {
        wait::KeInitializeEvent(body.cast(), event_type, initial_state);
        let opened = handle::open_with(
            body,
            desired_access,
            Attributes {
                inherit: attributes & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            true,
        );
        object::dereference(body);
        match opened {
            Ok(opened) => {
                event_handle.write_unaligned(opened as *mut c_void);
                STATUS_SUCCESS
            }
            Err(status) => status,
        }
    }
}

/// [`ZwOpenEvent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-zwopenevent):
/// a handle, granted the access asked for, to the event the attributes
/// name. A name that leads to nothing is what the namespace says of it
/// (`STATUS_OBJECT_NAME_NOT_FOUND`, `STATUS_OBJECT_PATH_NOT_FOUND`); to
/// an object that is not an event, `STATUS_OBJECT_TYPE_MISMATCH`.
/// `mountmgr.sys` asks for an event the session manager makes on
/// Windows, which no one makes on NK: it is not found.
///
/// Partial: a name relative to a directory handle stops the system by
/// name.
///
/// # Safety
/// `event_handle` points to room for a handle; `object_attributes`
/// points to an `OBJECT_ATTRIBUTES` whose name is a counted string.
pub unsafe extern "C" fn ZwOpenEvent(
    event_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    if object_attributes.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract; the driver's memory, read field by field
    // through its pointer.
    let (length, root, name, given) = unsafe {
        (
            (&raw const (*object_attributes).Length).read_unaligned(),
            (&raw const (*object_attributes).RootDirectory).read_unaligned(),
            (&raw const (*object_attributes).ObjectName).read_unaligned(),
            (&raw const (*object_attributes).Attributes).read_unaligned(),
        )
    };
    if length as usize != size_of::<OBJECT_ATTRIBUTES>() || given & !OBJ_VALID_ATTRIBUTES != 0 {
        return STATUS_INVALID_PARAMETER;
    }
    if name.is_null() {
        return STATUS_OBJECT_NAME_INVALID;
    }
    if !root.is_null() {
        crate::kd::bugcheck(format_args!(
            "ZwOpenEvent: a name relative to a directory handle is not implemented"
        ));
    }
    // SAFETY: per the contract.
    let wide = unsafe { crate::rtl::copy_unicode(name) };
    let (body, rest) = match super::lookup(None, &wide) {
        Ok(found) => found,
        Err(status) => return status,
    };
    // SAFETY: the look-up's reference, given up once the handle, if
    // there is one, holds the event.
    unsafe {
        if !rest.is_empty() {
            object::dereference(body);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
        if !core::ptr::eq(object::type_of(body), &raw const object::EVENT_TYPE) {
            object::dereference(body);
            return STATUS_OBJECT_TYPE_MISMATCH;
        }
        let opened = handle::open_with(
            body,
            desired_access,
            Attributes {
                inherit: given & OBJ_INHERIT != 0,
                protect_from_close: false,
            },
            true,
        );
        object::dereference(body);
        match opened {
            Ok(opened) => {
                event_handle.write_unaligned(opened as *mut c_void);
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
pub unsafe extern "C" fn ZwWaitForSingleObject(
    handle: *mut c_void,
    alertable: u8,
    timeout: *const i64,
) -> NTSTATUS {
    let held = match handle::reference_for(handle as u64, None, SYNCHRONIZE, Mode::Kernel) {
        Ok((held, _)) => held,
        Err(status) => return status,
    };
    let body = held.body();
    // SAFETY: the object is referenced until the wait is over; its
    // type says its body is a dispatcher object; per the contract for
    // the timeout.
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
        let timeout = (!timeout.is_null()).then(|| timeout.read_unaligned());
        wait::wait_as(Some(body.cast()), timeout, KERNEL_MODE, alertable != 0) as NTSTATUS
    }
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

    // What is refused, and that a refusal writes no handle.
    let named: [u16; 3] = [0x5C, 0x4E, 0x4B];
    let name = nk_ntabi::io::UNICODE_STRING {
        Length: 6,
        MaximumLength: 6,
        Buffer: named.as_ptr().cast_mut(),
    };
    let with_name = OBJECT_ATTRIBUTES {
        ObjectName: &raw const name,
        ..attributes(OBJ_KERNEL_HANDLE)
    };
    let short = OBJECT_ATTRIBUTES {
        Length: 24,
        ..attributes(0)
    };
    let untouched = core::ptr::dangling_mut::<c_void>();
    let refused = [
        create(Some(&kernel), 2, 0),
        create(Some(&short), 0, 0),
        create(Some(&attributes(0x1)), 0, 0),
        create(Some(&with_name), 0, 0),
        create(Some(&attributes(OBJ_PERMANENT)), 0, 0),
    ];
    let expected = [
        STATUS_INVALID_PARAMETER,
        STATUS_INVALID_PARAMETER,
        STATUS_INVALID_PARAMETER,
        STATUS_NOT_IMPLEMENTED,
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
