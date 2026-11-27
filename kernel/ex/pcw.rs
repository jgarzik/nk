//! Performance counters (`Pcw*`): on Windows the kernel passes each
//! call to `pcw.sys`, through the extension host it creates for it
//! (id 1, `ExpPcwExtensionHost`). Until that driver has registered,
//! each call fails with the status the pinned kernel's
//! `ExpPcwDisabledStatus` gives, and NK hosts no `pcw.sys`, so that is
//! every call's answer: `STATUS_NOT_IMPLEMENTED` if the `pcw` service
//! is to start (or has no key, `Start` read as 0), success with nothing
//! registered if it is not.

#![allow(non_snake_case)]

use core::ffi::c_void;
use core::sync::atomic::{AtomicU8, Ordering};
use nk_ntabi::status::*;

/// What the registry said, once read: 0 not yet, 1 `pcw` not to start,
/// 2 to start. Windows reads it once (`ExpPcwEnableState`).
static STATE: AtomicU8 = AtomicU8::new(0);

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

/// [`PcwRegister`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pcwregister):
/// no counter set is registered (`*registration` is null), with the
/// status above.
///
/// # Safety
/// `registration` is writable.
pub unsafe extern "C" fn PcwRegister(
    registration: *mut *mut c_void,
    _info: *const c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { registration.write_unaligned(core::ptr::null_mut()) };
    disabled_status()
}

/// [`PcwAddInstance`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pcwaddinstance):
/// the status above; nothing is added.
pub extern "C" fn PcwAddInstance(
    _buffer: *mut c_void,
    _name: *const c_void,
    _id: u32,
    _count: u32,
    _data: *const c_void,
) -> NTSTATUS {
    disabled_status()
}
