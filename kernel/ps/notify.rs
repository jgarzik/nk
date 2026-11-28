//! Process, thread, and image-load notify routines: drivers register callbacks
//! in Windows' 64-entry tables and NK dispatches them at `PASSIVE_LEVEL` on
//! user process creation/exit, thread creation/exit, and image mapping.

#![allow(non_snake_case)]

use crate::ke::spinlock::{Rank, SpinLock};
use core::ffi::c_void;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::status::*;
use nk_ntabi::user::{IMAGE_INFO, PS_CREATE_NOTIFY_INFO};

/// How many routines may be registered per table: Windows' table size.
const SLOTS: usize = 64;

/// Process-notify registration flags.
const REMOVE: u32 = 1;
const EX: u32 = 2;
const SUBSYSTEMS: u32 = 4;

#[derive(Clone, Copy, PartialEq, Eq)]
struct Entry {
    routine: usize,
    flags: u32,
}

struct NotifyTables {
    process: [Option<Entry>; SLOTS],
    thread: [Option<usize>; SLOTS],
    image: [Option<usize>; SLOTS],
}

static TABLES: SpinLock<NotifyTables> = SpinLock::new(
    Rank::ProcessNotify,
    NotifyTables {
        process: [None; SLOTS],
        thread: [None; SLOTS],
        image: [None; SLOTS],
    },
);

/// `MmVerifyCallbackFunctionCheckFlags`: whether `routine` is code of a
/// loaded image, and, for an `Ex` registration, one linked with `/INTEGRITYCHECK`.
fn verify(routine: usize, flags: u32) -> bool {
    let Some(module) = crate::ldr::module_containing(routine as u64) else {
        return false;
    };
    if flags & EX == 0 {
        return true;
    }
    // SAFETY: the image is loaded for as long as its routine is being registered.
    let image = unsafe { crate::ldr::view(&module) };
    nk_pe::image_headers(image)
        .is_ok_and(|h| h.dll_characteristics & nk_pe::DLLCHARACTERISTICS_FORCE_INTEGRITY != 0)
}

fn set_process(routine: usize, flags: u32) -> NTSTATUS {
    if flags & REMOVE != 0 {
        let wanted = Some(Entry {
            routine,
            flags: flags & !REMOVE,
        });
        let mut tables = TABLES.lock();
        return match tables.process.iter_mut().find(|slot| **slot == wanted) {
            Some(slot) => {
                *slot = None;
                STATUS_SUCCESS
            }
            None => STATUS_PROCEDURE_NOT_FOUND,
        };
    }
    if !verify(routine, flags) {
        return STATUS_ACCESS_DENIED;
    }
    let mut tables = TABLES.lock();
    match tables.process.iter_mut().find(|slot| slot.is_none()) {
        Some(slot) => {
            *slot = Some(Entry { routine, flags });
            STATUS_SUCCESS
        }
        None => STATUS_INVALID_PARAMETER,
    }
}

/// [`PsSetCreateProcessNotifyRoutine`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine).
pub extern "C" fn PsSetCreateProcessNotifyRoutine(routine: *mut c_void, remove: u8) -> NTSTATUS {
    set_process(routine.addr(), if remove != 0 { REMOVE } else { 0 })
}

/// [`PsSetCreateProcessNotifyRoutineEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex).
pub extern "C" fn PsSetCreateProcessNotifyRoutineEx(routine: *mut c_void, remove: u8) -> NTSTATUS {
    set_process(routine.addr(), EX | if remove != 0 { REMOVE } else { 0 })
}

const NOTIFY_SUBSYSTEMS: u32 = 0;

/// [`PsSetCreateProcessNotifyRoutineEx2`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex2).
pub extern "C" fn PsSetCreateProcessNotifyRoutineEx2(
    notify_type: u32,
    routine: *mut c_void,
    remove: u8,
) -> NTSTATUS {
    if notify_type != NOTIFY_SUBSYSTEMS {
        return STATUS_INVALID_PARAMETER;
    }
    let remove = if remove != 0 { REMOVE } else { 0 };
    set_process(routine.addr(), EX | SUBSYSTEMS | remove)
}

/// [`PsSetCreateThreadNotifyRoutine`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutine).
pub extern "C" fn PsSetCreateThreadNotifyRoutine(routine: *mut c_void) -> NTSTATUS {
    let mut tables = TABLES.lock();
    match tables.thread.iter_mut().find(|slot| slot.is_none()) {
        Some(slot) => {
            *slot = Some(routine.addr());
            STATUS_SUCCESS
        }
        None => STATUS_INSUFFICIENT_RESOURCES,
    }
}

/// [`PsRemoveCreateThreadNotifyRoutine`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psremovecreatethreadnotifyroutine).
pub extern "C" fn PsRemoveCreateThreadNotifyRoutine(routine: *mut c_void) -> NTSTATUS {
    let wanted = Some(routine.addr());
    let mut tables = TABLES.lock();
    match tables.thread.iter_mut().find(|slot| **slot == wanted) {
        Some(slot) => {
            *slot = None;
            STATUS_SUCCESS
        }
        None => STATUS_PROCEDURE_NOT_FOUND,
    }
}

/// [`PsSetLoadImageNotifyRoutine`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine).
pub extern "C" fn PsSetLoadImageNotifyRoutine(routine: *mut c_void) -> NTSTATUS {
    let mut tables = TABLES.lock();
    match tables.image.iter_mut().find(|slot| slot.is_none()) {
        Some(slot) => {
            *slot = Some(routine.addr());
            STATUS_SUCCESS
        }
        None => STATUS_INSUFFICIENT_RESOURCES,
    }
}

/// [`PsRemoveLoadImageNotifyRoutine`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psremoveloadimagenotifyroutine).
pub extern "C" fn PsRemoveLoadImageNotifyRoutine(routine: *mut c_void) -> NTSTATUS {
    let wanted = Some(routine.addr());
    let mut tables = TABLES.lock();
    match tables.image.iter_mut().find(|slot| **slot == wanted) {
        Some(slot) => {
            *slot = None;
            STATUS_SUCCESS
        }
        None => STATUS_PROCEDURE_NOT_FOUND,
    }
}

/// Dispatch registered process-creation or process-exit notify routines at `PASSIVE_LEVEL`.
///
/// For creation (`create_info.is_some()`), an `Ex` callback may fail creation by
/// setting `CreationStatus` to an error NTSTATUS; that status is returned.
///
/// # Safety
/// `process` is a live `EPROCESS`; `create_info` (if `Some`) is valid for the call.
#[allow(dead_code)]
pub unsafe fn dispatch_process(
    process: *mut c_void,
    parent_pid: u64,
    pid: u64,
    create_info: Option<&mut PS_CREATE_NOTIFY_INFO>,
) -> NTSTATUS {
    let snapshot = { TABLES.lock().process };
    let creating = create_info.is_some();
    let info_ptr = match create_info {
        Some(info) => core::ptr::from_mut(info),
        None => core::ptr::null_mut(),
    };
    for entry in snapshot.into_iter().flatten() {
        if entry.flags & EX != 0 {
            // SAFETY: registered via `PsSetCreateProcessNotifyRoutineEx*`.
            let cb: unsafe extern "C" fn(*mut c_void, *mut c_void, *mut PS_CREATE_NOTIFY_INFO) =
                unsafe { core::mem::transmute(entry.routine) };
            // SAFETY: `process` and `info_ptr` are valid per the contract.
            unsafe {
                cb(
                    process,
                    core::ptr::with_exposed_provenance_mut(pid as usize),
                    info_ptr,
                );
            }
            if !info_ptr.is_null() {
                // SAFETY: `info_ptr` came from a valid `&mut PS_CREATE_NOTIFY_INFO`.
                let st = unsafe { (*info_ptr).CreationStatus };
                if !nt_success(st) {
                    return st;
                }
            }
        } else {
            // SAFETY: registered via `PsSetCreateProcessNotifyRoutine`.
            let cb: unsafe extern "C" fn(*mut c_void, *mut c_void, u8) =
                unsafe { core::mem::transmute(entry.routine) };
            // SAFETY: per the contract.
            unsafe {
                cb(
                    core::ptr::with_exposed_provenance_mut(parent_pid as usize),
                    core::ptr::with_exposed_provenance_mut(pid as usize),
                    u8::from(creating),
                );
            }
        }
    }
    STATUS_SUCCESS
}

/// Dispatch registered thread-creation or thread-exit notify routines at `PASSIVE_LEVEL`.
#[allow(dead_code)]
pub fn dispatch_thread(pid: u64, tid: u64, create: bool) {
    let snapshot = { TABLES.lock().thread };
    for routine in snapshot.into_iter().flatten() {
        // SAFETY: registered via `PsSetCreateThreadNotifyRoutine`.
        let cb: unsafe extern "C" fn(*mut c_void, *mut c_void, u8) =
            unsafe { core::mem::transmute(routine) };
        // SAFETY: passing scalar PID/TID/bool values.
        unsafe {
            cb(
                core::ptr::with_exposed_provenance_mut(pid as usize),
                core::ptr::with_exposed_provenance_mut(tid as usize),
                u8::from(create),
            );
        }
    }
}

/// Dispatch registered load-image notify routines at `PASSIVE_LEVEL`.
///
/// # Safety
/// `full_image_name` (if non-null) and `image_info` are valid for the call.
#[allow(dead_code)]
pub unsafe fn dispatch_image(
    full_image_name: *const UNICODE_STRING,
    pid: u64,
    image_info: *const IMAGE_INFO,
) {
    let snapshot = { TABLES.lock().image };
    for routine in snapshot.into_iter().flatten() {
        // SAFETY: registered via `PsSetLoadImageNotifyRoutine`.
        let cb: unsafe extern "C" fn(*const UNICODE_STRING, *mut c_void, *const IMAGE_INFO) =
            unsafe { core::mem::transmute(routine) };
        // SAFETY: per the contract.
        unsafe {
            cb(
                full_image_name,
                core::ptr::with_exposed_provenance_mut(pid as usize),
                image_info,
            );
        }
    }
}
