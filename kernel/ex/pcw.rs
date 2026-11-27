//! Performance counters (`Pcw*`): the kernel passes each call to
//! `pcw.sys`, through the extension host it creates for it (id 1,
//! `ExpPcwExtensionHost`; `ex::extension`). Until that driver has
//! registered, each call fails with the status the pinned kernel's
//! `ExpPcwDisabledStatus` gives: `STATUS_NOT_IMPLEMENTED` if the `pcw`
//! service is to start (or has no key, `Start` read as 0), success with
//! nothing registered if it is not.
//!
//! When `pcw.sys` registers, Windows' kernel registers counter sets of
//! its own with it (synchronization, processors, thermal zones, event
//! tracing, file-system disk I/O: `ExpPcwHostCallback`). NK registers
//! none (`doc/design/absent.md`).

#![allow(non_snake_case)]

use super::extension::{self, PCW};
use crate::ke::seh::{self, Guard};
use core::ffi::c_void;
use core::sync::atomic::{AtomicU8, Ordering};
use nk_ntabi::status::*;

/// What the registry said, once read: 0 not yet, 1 `pcw` not to start,
/// 2 to start. Windows reads it once (`ExpPcwEnableState`).
static STATE: AtomicU8 = AtomicU8::new(0);

/// The routines of `pcw.sys`'s table, by place.
const REGISTER: usize = 0;
const ADD_INSTANCE: usize = 4;

/// `ExpPcwHostCallback`: what the kernel does as `pcw.sys` registers
/// (event 1) or goes. NK registers no counter sets of its own.
pub fn host_notification(_event: u32) {}

/// `ExpPcwDisabledStatus`.
fn disabled_status() -> NTSTATUS {
    let mut state = STATE.load(Ordering::Relaxed);
    if state == 0 {
        let start =
            match crate::cm::read("Machine\\System\\CurrentControlSet\\Services\\pcw", "Start") {
                Ok((_, data)) => data
                    .first_chunk::<4>()
                    .map_or(0, |b| u32::from_le_bytes(*b)),
                Err(_) => 0,
            };
        state = if start != 0 { 1 } else { 2 };
        STATE.store(state, Ordering::Relaxed);
    }
    if state == 2 {
        STATUS_NOT_IMPLEMENTED
    } else {
        STATUS_SUCCESS
    }
}

/// Give back the host's table if an exception unwinds a call made with
/// it.
///
/// # Safety
/// Called once, by the unwind, for a call made under [`extension::table`].
unsafe fn release_on_unwind(_context: *mut c_void) {
    extension::release(&PCW);
}

/// Call routine `index` of `pcw.sys`'s table with `args`, under the
/// host's protection: what it returned, or `None` with no table.
///
/// # Safety
/// `args` are what that routine takes.
unsafe fn forward(index: usize, args: [usize; 4]) -> Option<NTSTATUS> {
    let table = extension::table(&PCW)?;
    let guard = Guard::Undo {
        undo: release_on_unwind,
        context: core::ptr::null_mut(),
    };
    // SAFETY: the registered table holds the host's five routines; per
    // the contract for the arguments.
    let status = unsafe { seh::call(table.add(index).read_unaligned() as usize, args, &guard) };
    extension::release(&PCW);
    Some(status as NTSTATUS)
}

/// [`PcwRegister`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pcwregister):
/// `pcw.sys` registers the counter set; without it, nothing is
/// registered (`*registration` is null), with the status above.
///
/// # Safety
/// `registration` is writable and `info` a registration's description.
pub unsafe extern "C" fn PcwRegister(
    registration: *mut *mut c_void,
    info: *const c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    if let Some(status) = unsafe { forward(REGISTER, [registration.addr(), info.addr(), 0, 0]) } {
        return status;
    }
    // SAFETY: per the contract.
    unsafe { registration.write_unaligned(core::ptr::null_mut()) };
    disabled_status()
}

/// `pcw.sys`'s `PcwAddInstance`, called with its five arguments.
struct AddInstance {
    routine: usize,
    args: [usize; 5],
    status: NTSTATUS,
}

/// Call the routine of an [`AddInstance`], from inside the guarded call
/// that carries it.
///
/// # Safety
/// `call` is the record [`PcwAddInstance`] passes.
unsafe extern "C" fn add_instance(call: *mut AddInstance) {
    type Routine = unsafe extern "C" fn(usize, usize, usize, usize, usize) -> NTSTATUS;
    // SAFETY: the record of the call below; its routine is `pcw.sys`'s
    // `PcwAddInstance`, which takes five arguments of these widths.
    unsafe {
        let routine: Routine = core::mem::transmute((*call).routine);
        let [a, b, c, d, e] = (*call).args;
        (*call).status = routine(a, b, c, d, e);
    }
}

/// [`PcwAddInstance`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pcwaddinstance):
/// `pcw.sys` adds the instance; without it, the status above.
///
/// # Safety
/// The arguments are what the routine takes.
pub unsafe extern "C" fn PcwAddInstance(
    buffer: *mut c_void,
    name: *const c_void,
    id: u32,
    count: u32,
    data: *const c_void,
) -> NTSTATUS {
    let Some(table) = extension::table(&PCW) else {
        return disabled_status();
    };
    let mut call = AddInstance {
        // SAFETY: the registered table holds the host's five routines.
        routine: unsafe { table.add(ADD_INSTANCE).read_unaligned() } as usize,
        args: [
            buffer.addr(),
            name.addr(),
            id as usize,
            count as usize,
            data.addr(),
        ],
        status: STATUS_SUCCESS,
    };
    let guard = Guard::Undo {
        undo: release_on_unwind,
        context: core::ptr::null_mut(),
    };
    // SAFETY: `add_instance` takes the record, which lives until the
    // call is over.
    unsafe {
        seh::call(
            add_instance as *const () as usize,
            [(&raw mut call).addr(), 0, 0, 0],
            &guard,
        )
    };
    extension::release(&PCW);
    call.status
}
