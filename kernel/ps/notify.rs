//! Process-creation notify routines: drivers register them, as on
//! Windows, in a table of 64 (`PspCreateProcessNotifyRoutine`).
//!
//! NK creates no process but the system process yet, so nothing calls
//! a registered routine; registering and removing behave as on Windows.

use crate::ke::spinlock::{Rank, SpinLock};
use core::ffi::c_void;
use nk_ntabi::status::*;

/// How many routines may be registered: Windows' table.
const SLOTS: usize = 64;

/// The kinds of registration, the pinned kernel's flags: taking one back,
/// the `Ex` form (with `PS_CREATE_NOTIFY_INFO`), and a notification for
/// processes of every subsystem (`PsSetCreateProcessNotifyRoutineEx2`'s
/// `PsCreateProcessNotifySubsystems`).
const REMOVE: u32 = 1;
const EX: u32 = 2;
const SUBSYSTEMS: u32 = 4;

/// A registration: the routine and its kind.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Entry {
    routine: usize,
    flags: u32,
}

static TABLE: SpinLock<[Option<Entry>; SLOTS]> = SpinLock::new(Rank::ProcessNotify, [None; SLOTS]);

/// `MmVerifyCallbackFunctionCheckFlags`: whether `routine` is code of a
/// loaded image, and, for an `Ex` registration, one linked to have its
/// signature checked (`/INTEGRITYCHECK`), as Windows requires of those.
fn verify(routine: usize, flags: u32) -> bool {
    let Some(module) = crate::ldr::module_containing(routine as u64) else {
        return false;
    };
    if flags & EX == 0 {
        return true;
    }
    // SAFETY: the image is loaded for as long as its routine is being
    // registered by it.
    let image = unsafe { crate::ldr::view(&module) };
    nk_pe::image_headers(image)
        .is_ok_and(|h| h.dll_characteristics & nk_pe::DLLCHARACTERISTICS_FORCE_INTEGRITY != 0)
}

/// `PspSetCreateProcessNotifyRoutine`: register `routine` with `flags`,
/// or take back the registration of the same routine and kind.
fn set(routine: usize, flags: u32) -> NTSTATUS {
    if flags & REMOVE != 0 {
        let wanted = Some(Entry {
            routine,
            flags: flags & !REMOVE,
        });
        let mut table = TABLE.lock();
        return match table.iter_mut().find(|slot| **slot == wanted) {
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
    let mut table = TABLE.lock();
    match table.iter_mut().find(|slot| slot.is_none()) {
        Some(slot) => {
            *slot = Some(Entry { routine, flags });
            STATUS_SUCCESS
        }
        None => STATUS_INVALID_PARAMETER,
    }
}

/// [`PsSetCreateProcessNotifyRoutine`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine):
/// register `routine`, of any loaded image, or with `remove` take it
/// back (`STATUS_PROCEDURE_NOT_FOUND` if it is not registered). With 64
/// routines registered, `STATUS_INVALID_PARAMETER`.
pub extern "C" fn PsSetCreateProcessNotifyRoutine(routine: *mut c_void, remove: u8) -> NTSTATUS {
    set(routine.addr(), if remove != 0 { REMOVE } else { 0 })
}

/// `PsCreateProcessNotifySubsystems`, the one type of
/// `PsSetCreateProcessNotifyRoutineEx2`.
const NOTIFY_SUBSYSTEMS: u32 = 0;

/// [`PsSetCreateProcessNotifyRoutineEx2`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex2):
/// as the `Ex` form, for processes of every subsystem: the routine's
/// image must be linked with `/INTEGRITYCHECK` (`STATUS_ACCESS_DENIED`
/// otherwise). A type other than `PsCreateProcessNotifySubsystems` is
/// `STATUS_INVALID_PARAMETER`.
pub extern "C" fn PsSetCreateProcessNotifyRoutineEx2(
    notify_type: u32,
    routine: *mut c_void,
    remove: u8,
) -> NTSTATUS {
    if notify_type != NOTIFY_SUBSYSTEMS {
        return STATUS_INVALID_PARAMETER;
    }
    let remove = if remove != 0 { REMOVE } else { 0 };
    set(routine.addr(), EX | SUBSYSTEMS | remove)
}
