//! System threads, as drivers create them.
//!
//! NK has no processes yet, so every thread is a system thread and the
//! process a driver names is not looked at.

#![allow(non_snake_case)]

use crate::ke::thread;
use crate::ob::{handle, object};
use alloc::boxed::Box;
use core::ffi::c_void;
use nk_ntabi::status::*;

/// `KSTART_ROUTINE`.
type StartRoutine = unsafe extern "C" fn(*mut c_void);

/// What a new system thread is to run.
struct Start {
    routine: StartRoutine,
    context: *mut c_void,
}

fn system_thread(start: usize) {
    // SAFETY: the box `PsCreateSystemThread` leaked for this thread.
    // Taken apart and freed before the routine runs: a routine usually
    // ends its thread itself and never returns here.
    let Start { routine, context } = *unsafe { Box::from_raw(start as *mut Start) };
    // SAFETY: the routine the driver gave, at PASSIVE_LEVEL in a thread
    // of its own, with the context it gave.
    unsafe { routine(context) };
    // A routine that returns has ended its thread.
}

/// [`PsCreateSystemThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pscreatesystemthread).
/// The handle is a kernel handle whatever the object attributes say:
/// there is no other kind. Access, attributes, process and client id
/// are not looked at.
///
/// # Safety
/// `thread_handle` points to room for a handle; `start_routine` may be
/// called with `start_context` in a new thread.
pub unsafe extern "C" fn PsCreateSystemThread(
    thread_handle: *mut *mut c_void,
    _desired_access: u32,
    _object_attributes: *mut c_void,
    _process_handle: *mut c_void,
    _client_id: *mut c_void,
    start_routine: Option<StartRoutine>,
    start_context: *mut c_void,
) -> NTSTATUS {
    let Some(routine) = start_routine else {
        return STATUS_INVALID_PARAMETER;
    };
    let start = Box::into_raw(Box::new(Start {
        routine,
        context: start_context,
    }));
    let created = thread::create_referenced(
        system_thread,
        start as usize,
        thread::NORMAL_PRIORITY,
        thread::ANYWHERE,
    );
    let Ok(new) = created else {
        // SAFETY: the thread was not created, so the box is still ours.
        drop(unsafe { Box::from_raw(start) });
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: per the contract; the reference `create_referenced` gave
    // is handed to the handle and then given up.
    unsafe {
        thread_handle.write_unaligned(handle::open(new.cast()) as *mut c_void);
        object::dereference(new.cast());
    }
    STATUS_SUCCESS
}

/// [`PsTerminateSystemThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-psterminatesystemthread):
/// end the calling thread.
pub extern "C" fn PsTerminateSystemThread(_exit_status: NTSTATUS) -> NTSTATUS {
    thread::exit()
}

/// [`ZwClose`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwclose).
pub extern "C" fn ZwClose(handle: *mut c_void) -> NTSTATUS {
    handle::close(handle as u64)
}

/// [`KeGetCurrentThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kegetcurrentthread).
/// In-line code on x86-64; a call on arm64.
pub extern "C" fn KeGetCurrentThread() -> *mut c_void {
    thread::current().cast()
}
