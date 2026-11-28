//! System threads, as drivers create them.
//!
//! Every thread belongs to the System process (`process`), so the
//! process a driver names is not looked at.

#![allow(non_snake_case)]

pub mod notify;
pub mod process;
pub mod silo;

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
pub extern "C" fn NtClose(handle: *mut c_void) -> NTSTATUS {
    handle::close(handle as u64)
}

/// `THREAD_ALERT`: the right to alert a thread.
const THREAD_ALERT: u32 = 0x4;

/// `ZwAlertThread` (`ntifs.h`):
/// alert the thread a handle names, in kernel mode, which is the mode
/// of a caller of the `Zw` routine (`ke::wait::alert`). The handle
/// must name a thread.
pub extern "C" fn NtAlertThread(thread_handle: *mut c_void) -> NTSTATUS {
    let found = handle::reference_for(
        thread_handle as u64,
        Some(&raw const object::THREAD_TYPE),
        THREAD_ALERT,
        nk_ob::handles::Mode::Kernel,
    );
    match found {
        Ok((thread, _)) => {
            // SAFETY: a thread, referenced by the look-up until the
            // alert is made.
            unsafe { crate::ke::wait::alert(thread.cast(), nk_ntabi::io::KERNEL_MODE) };
            STATUS_SUCCESS
        }
        Err(status) => status,
    }
}

/// `THREAD_SET_LIMITED_INFORMATION`: the right the priority classes
/// ask of the handle.
const THREAD_SET_LIMITED_INFORMATION: u32 = 0x400;
/// `THREAD_SET_THREAD_TOKEN`: the right the impersonation token class
/// asks of the thread's handle.
const THREAD_SET_THREAD_TOKEN: u32 = 0x80;

/// Run `set` on the thread `thread_handle` names, referenced meanwhile,
/// or say why the handle gave no thread.
fn with_thread(
    thread_handle: *mut c_void,
    access: u32,
    set: impl FnOnce(*mut thread::Thread) -> NTSTATUS,
) -> NTSTATUS {
    let found = handle::reference_for(
        thread_handle as u64,
        Some(&raw const object::THREAD_TYPE),
        access,
        nk_ob::handles::Mode::Kernel,
    );
    match found {
        Ok((body, _)) => set(body.cast()),
        Err(status) => status,
    }
}

/// [`ZwSetInformationThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-zwsetinformationthread):
/// set something about the thread a handle names, by information
/// class. Each class checks in the order Windows 10 does, so that a
/// call wrong in two ways fails the way it fails there.
///
/// | Class | Sets | Checks, in order |
/// | --- | --- | --- |
/// | `ThreadPriority` | the thread's priority (`KeSetPriorityThread`) | the length is 4 (`STATUS_INFO_LENGTH_MISMATCH`); the priority is 1 to 31 (`STATUS_INVALID_PARAMETER`); the handle |
/// | `ThreadBasePriority` | the base priority, as a step from the process's, and the priority with it (`ke::thread::set_base_priority`) | the length is 4; the handle; the step is one there is (`STATUS_INVALID_PARAMETER`) |
///
/// | `ThreadImpersonationToken` | the token the thread impersonates, or none for a null handle (`se::impersonate`) | the length is a handle's; the thread's handle; the token's handle; the token is an impersonation token (`STATUS_BAD_TOKEN_TYPE`) |
///
/// A class Windows never sets is `STATUS_INVALID_INFO_CLASS`
/// (`nk_ps::info::can_be_set`). The classes Windows sets and NK does
/// not are `STATUS_NOT_IMPLEMENTED`: the ledger's "partial". The
/// caller is kernel mode, so no privilege is asked for a real-time
/// priority and the handle's access is not checked.
///
/// # Safety
/// `information` points to `length` readable bytes.
pub unsafe extern "C" fn NtSetInformationThread(
    thread_handle: *mut c_void,
    class: u32,
    information: *const c_void,
    length: u32,
) -> NTSTATUS {
    use nk_ps::info;
    let mode = crate::svc::capture::mode();
    // A class whose information is one 32-bit number.
    let number = || -> Result<Option<i32>, NTSTATUS> {
        if length != 4 {
            return Ok(None);
        }
        // SAFETY: per the contract; fault-protected for `UserMode`.
        unsafe { crate::svc::capture::read(information.cast::<i32>(), mode) }.map(Some)
    };
    match class {
        info::THREAD_PRIORITY => {
            let Some(priority) = (match number() {
                Ok(v) => v,
                Err(status) => return status,
            }) else {
                return STATUS_INFO_LENGTH_MISMATCH;
            };
            if !info::priority_allowed(priority) {
                return STATUS_INVALID_PARAMETER;
            }
            with_thread(thread_handle, THREAD_SET_LIMITED_INFORMATION, |thread| {
                // SAFETY: a thread, referenced by the look-up.
                unsafe { thread::set_priority(thread, priority as u8) };
                STATUS_SUCCESS
            })
        }
        info::THREAD_BASE_PRIORITY => {
            let Some(increment) = (match number() {
                Ok(v) => v,
                Err(status) => return status,
            }) else {
                return STATUS_INFO_LENGTH_MISMATCH;
            };
            with_thread(thread_handle, THREAD_SET_LIMITED_INFORMATION, |thread| {
                if !info::base_increment_allowed(increment) {
                    return STATUS_INVALID_PARAMETER;
                }
                // SAFETY: a thread, referenced by the look-up; its
                // process is the System process, whose base is 8.
                unsafe { thread::set_base_priority(thread, increment) };
                STATUS_SUCCESS
            })
        }
        info::THREAD_IMPERSONATION_TOKEN => {
            if length as usize != size_of::<*mut c_void>() {
                return STATUS_INFO_LENGTH_MISMATCH;
            }
            // SAFETY: per the contract; fault-protected for `UserMode`.
            let token =
                match unsafe { crate::svc::capture::read(information.cast::<*mut c_void>(), mode) }
                {
                    Ok(t) => t,
                    Err(status) => return status,
                };
            with_thread(thread_handle, THREAD_SET_THREAD_TOKEN, |thread| {
                // SAFETY: a thread, referenced by the look-up.
                unsafe { crate::se::impersonate::set_thread_impersonation_token(thread, token) }
            })
        }
        class if !info::can_be_set(class) => STATUS_INVALID_INFO_CLASS,
        _ => STATUS_NOT_IMPLEMENTED,
    }
}

/// What `ZwSetInformationThread` does to a thread's priorities and
/// what it refuses, the thread being another one that waits. Returns
/// the calls made.
pub fn thread_information_test() -> Result<u32, &'static str> {
    use crate::ke::wait;
    use core::sync::atomic::{AtomicBool, Ordering};
    use nk_ntabi::thread::{BASE_PRIORITY, PRIORITY, SATURATION};
    static DONE: AtomicBool = AtomicBool::new(false);
    fn idles(_: usize) {
        while !DONE.load(Ordering::Acquire) {
            // SAFETY: no object is involved.
            unsafe { wait::wait(None, Some(-10_000)) };
        }
    }
    DONE.store(false, Ordering::Release);
    let other = thread::create_referenced(idles, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)
        .map_err(|_| "no memory for a thread")?;
    // SAFETY: a thread this test holds a reference to until the end.
    let Ok(opened) = (unsafe { handle::open(other.cast(), 0x001F_FFFF) }) else {
        DONE.store(true, Ordering::Release);
        // SAFETY: the reference taken above.
        unsafe { object::dereference(other.cast()) };
        return Err("no memory for a handle");
    };
    let opened = opened as *mut c_void;
    let set = |to: *mut c_void, class: u32, value: i32, length: u32| {
        // SAFETY: the value is a local of four bytes; no call reads
        // more.
        unsafe { ZwSetInformationThread(to, class, (&raw const value).cast(), length) }
    };
    // SAFETY: the referenced thread.
    let priority = |new: i32| unsafe { thread::KeSetPriorityThread(other.cast(), new) };
    let kept = || {
        // SAFETY: the referenced thread's block; single bytes.
        unsafe {
            (
                thread::object_field::<u8>(other, PRIORITY).read(),
                thread::object_field::<u8>(other, BASE_PRIORITY).read(),
                thread::object_field::<i8>(other, SATURATION).read(),
            )
        }
    };
    use nk_ps::info::{THREAD_BASE_PRIORITY as BASE, THREAD_PRIORITY as SET};
    let normal = i32::from(thread::NORMAL_PRIORITY);
    // The priority, set through the handle, is what KeSetPriorityThread
    // then finds; the base priority is not touched by either.
    let through_handle = (
        priority(normal + 1),
        set(opened, SET, normal + 2, 4),
        priority(normal + 1),
        kept(),
    );
    // Refused, in the order Windows refuses: a bad priority before a
    // bad handle, a bad length before both.
    let refused = [
        set(opened, SET, 0, 4),
        set(opened, SET, 32, 4),
        set(opened, SET, normal, 2),
        set(core::ptr::null_mut(), SET, 0, 4),
        set(core::ptr::null_mut(), SET, normal, 2),
        set(core::ptr::null_mut(), SET, normal, 4),
        set(core::ptr::null_mut(), BASE, 3, 4),
        set(opened, BASE, 3, 4),
        set(opened, BASE, 1, 8),
        set(opened, 0x7FFF, normal, 4),
        set(opened, 6, normal, 4),
        set(opened, 4, normal, 4),
        set(-1i64 as *mut c_void, SET, normal, 4),
    ];
    let untouched = kept();
    // One step up: the base is 9 and the priority, which was set one
    // above the old base, stays one above the new.
    let stepped = (set(opened, BASE, 1, 4), kept(), priority(normal));
    // Back to no step from under the base: counted from the base.
    let back = (set(opened, BASE, 0, 4), kept());
    // The time-critical and idle steps pin the thread.
    let pinned = (
        set(opened, BASE, 16, 4),
        kept(),
        set(opened, BASE, -16, 4),
        kept(),
        set(opened, BASE, 0, 4),
        kept(),
    );
    DONE.store(true, Ordering::Release);
    // SAFETY: the thread, referenced until here; the wait is for its
    // end.
    unsafe {
        wait::wait(Some(other.cast()), None);
        object::dereference(other.cast());
    }
    handle::close(opened as u64);
    let n = thread::NORMAL_PRIORITY;
    if through_handle != (normal, STATUS_SUCCESS, normal + 2, (n + 1, n, 0)) {
        return Err("a priority set through a handle is not the thread's priority");
    }
    let expected = [
        STATUS_INVALID_PARAMETER,
        STATUS_INVALID_PARAMETER,
        STATUS_INFO_LENGTH_MISMATCH,
        STATUS_INVALID_PARAMETER,
        STATUS_INFO_LENGTH_MISMATCH,
        STATUS_INVALID_HANDLE,
        STATUS_INVALID_HANDLE,
        STATUS_INVALID_PARAMETER,
        STATUS_INFO_LENGTH_MISMATCH,
        STATUS_INVALID_INFO_CLASS,
        STATUS_INVALID_INFO_CLASS,
        STATUS_NOT_IMPLEMENTED,
        STATUS_OBJECT_TYPE_MISMATCH,
    ];
    if refused != expected || untouched != (n + 1, n, 0) {
        return Err("a call that sets nothing did not fail as it fails on Windows");
    }
    if stepped != (STATUS_SUCCESS, (n + 2, n + 1, 0), normal + 2) {
        return Err("a step of the base priority did not move the base and the priority by one");
    }
    if back != (STATUS_SUCCESS, (n, n, 0)) {
        return Err("a base priority set back did not bring the thread back to it");
    }
    let (high, low) = ((15, 15, 1), (1, 1, -1));
    if pinned
        != (
            STATUS_SUCCESS,
            high,
            STATUS_SUCCESS,
            low,
            STATUS_SUCCESS,
            (n, n, 0),
        )
    {
        return Err("the time-critical and idle steps did not pin the thread at 15 and 1");
    }
    Ok(27)
}

/// [`KeGetCurrentThread`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kegetcurrentthread).
/// In-line code on x86-64; a call on arm64.
pub extern "C" fn KeGetCurrentThread() -> *mut c_void {
    thread::current().cast()
}

/// `ETHREAD.CrossThreadFlags` of `thread`, changed by atomic operations
/// only, as Windows changes them.
///
/// # Safety
/// `thread` is a live thread.
unsafe fn cross_thread_flags<'a>(thread: *mut thread::Thread) -> &'a core::sync::atomic::AtomicU32 {
    // SAFETY: per the contract: an aligned 32-bit field of its block.
    unsafe {
        core::sync::atomic::AtomicU32::from_ptr(thread::object_field(
            thread,
            nk_ntabi::thread::CROSS_THREAD_FLAGS,
        ))
    }
}

/// `PsGetThreadHardErrorsAreDisabled` (`ntifs.h`): whether `thread`
/// asked for no hard-error message.
///
/// # Safety
/// `thread` is a live thread.
pub unsafe extern "C" fn PsGetThreadHardErrorsAreDisabled(thread: *mut thread::Thread) -> u8 {
    use core::sync::atomic::Ordering;
    // SAFETY: per the contract.
    let flags = unsafe { cross_thread_flags(thread) }.load(Ordering::Relaxed);
    u8::from(flags & nk_ntabi::thread::HARD_ERRORS_ARE_DISABLED != 0)
}

/// `PsSetThreadHardErrorsAreDisabled` (`ntifs.h`): set or clear the
/// flag `PsGetThreadHardErrorsAreDisabled` reads.
///
/// # Safety
/// `thread` is a live thread.
pub unsafe extern "C" fn PsSetThreadHardErrorsAreDisabled(
    thread: *mut thread::Thread,
    disabled: u8,
) {
    use core::sync::atomic::Ordering;
    use nk_ntabi::thread::HARD_ERRORS_ARE_DISABLED;
    // SAFETY: per the contract.
    let flags = unsafe { cross_thread_flags(thread) };
    if disabled != 0 {
        flags.fetch_or(HARD_ERRORS_ARE_DISABLED, Ordering::Relaxed);
    } else {
        flags.fetch_and(!HARD_ERRORS_ARE_DISABLED, Ordering::Relaxed);
    }
}

/// [`IoSetThreadHardErrorMode`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-iosetthreadharderrormode):
/// whether the calling thread's hard errors are shown from now on;
/// returns whether they were. NK shows none in any case: the flag is
/// kept for whoever reads it.
pub extern "C" fn IoSetThreadHardErrorMode(enable: u8) -> u8 {
    let current = thread::current();
    // SAFETY: the calling thread is live.
    unsafe {
        let was = PsGetThreadHardErrorsAreDisabled(current) == 0;
        PsSetThreadHardErrorsAreDisabled(current, u8::from(enable == 0));
        u8::from(was)
    }
}

/// `PsGetHostSilo` (`ntddk.h`): the host silo, which NK's silo routines
/// name by null (`silo`).
pub extern "C" fn PsGetHostSilo() -> *mut c_void {
    core::ptr::null_mut()
}

pub use crate::svc::zw::{ZwAlertThread, ZwClose, ZwSetInformationThread};
