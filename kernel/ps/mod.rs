//! System threads, as drivers create them.
//!
//! Every thread belongs to the System process (`process`), so the
//! process a driver names is not looked at.

#![allow(non_snake_case)]

pub mod process;

use crate::ke::seh::{self, Guard, Unhandled};
use crate::ke::thread;
use crate::ob::{handle, object};
use alloc::boxed::Box;
use core::ffi::c_void;
use nk_ntabi::status::*;

/// `KSTART_ROUTINE`.
pub type StartRoutine = unsafe extern "C" fn(*mut c_void);

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
    // of its own, with the context it gave. It is the thread's first
    // driver frame: an exception it lets out is unhandled.
    unsafe {
        seh::call(
            routine as usize,
            [context.addr(), 0, 0, 0],
            &Guard::Base(Unhandled::SystemThread),
        )
    };
    // A routine that returns has ended its thread.
}

/// [`PsCreateSystemThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pscreatesystemthread).
/// The handle is a kernel handle whatever the object attributes say:
/// there is no other kind, and it is granted the access asked for.
/// Attributes, process and client id are not looked at.
///
/// # Safety
/// `thread_handle` points to room for a handle; `start_routine` may be
/// called with `start_context` in a new thread.
pub unsafe extern "C" fn PsCreateSystemThread(
    thread_handle: *mut *mut c_void,
    desired_access: u32,
    _object_attributes: *mut c_void,
    _process_handle: *mut c_void,
    _client_id: *mut c_void,
    start_routine: Option<StartRoutine>,
    start_context: *mut c_void,
) -> NTSTATUS {
    let Some(routine) = start_routine else {
        return STATUS_INVALID_PARAMETER;
    };
    // SAFETY: per the contract.
    unsafe {
        create_system_thread(routine, start_context, |thread| {
            match handle::open(thread, desired_access) {
                Ok(handle) => {
                    thread_handle.write_unaligned(handle as *mut c_void);
                    STATUS_SUCCESS
                }
                Err(status) => status,
            }
        })
    }
}

/// Create a system thread that runs `routine(context)`. `announce` is
/// given the thread object, to make the creator's handle to it and hand
/// the handle over, and says whether it could. The thread is started
/// after that, as Windows readies a new thread last: it finds its
/// handle where its creator wanted it, and a thread that could not be
/// given one never runs, so a failure is reported only for work that
/// was not done.
///
/// # Safety
/// `routine` may be called with `context` in a new thread.
pub unsafe fn create_system_thread(
    routine: StartRoutine,
    context: *mut c_void,
    announce: impl FnOnce(*mut u8) -> NTSTATUS,
) -> NTSTATUS {
    let start = Box::into_raw(Box::new(Start { routine, context }));
    let created = thread::create_unstarted(
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
    let status = announce(new.cast());
    // SAFETY: a thread from `create_unstarted`, started or taken back
    // once; one taken back never ran, so the box is still ours. Then
    // the reference `create_unstarted` gave.
    unsafe {
        if nt_success(status) {
            thread::begin(new);
        } else {
            thread::discard(new);
            drop(Box::from_raw(start));
        }
        object::dereference(new.cast());
    }
    status
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
