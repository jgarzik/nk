//! Plug and Play notifications: a driver registers a callback for a
//! category of events (`IoRegisterPlugPlayNotification`) and is called
//! when one happens.
//!
//! The events NK produces are the arrival and the removal of a device
//! interface (`super::interface`). A registration for a hardware
//! profile change or for a target device's removal is kept and never
//! called: NK has one hardware profile and removes no device on
//! request.
//!
//! A callback is called at `PASSIVE_LEVEL` with no lock held, on the
//! thread that changed the interface's state (Windows queues the event
//! for a worker of its own). While it runs, the registration counts as
//! in use, and taking it back waits for that to end.

#![allow(non_snake_case)]

use crate::ke::seh::{self, Guard};
use crate::ke::{Rank, SpinLock};
use crate::mm::pool;
use crate::ob::object;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_ntabi::io::{DRIVER_OBJECT, UNICODE_STRING};
use nk_ntabi::pnp::*;
use nk_ntabi::status::*;

/// One registration. Its address is the handle the driver holds.
struct Registration {
    category: u32,
    /// For interface changes: the class.
    class: [u8; 16],
    driver: usize,
    callback: usize,
    context: usize,
    /// Callbacks in progress, and the thread of the last one to begin.
    calls: u32,
    caller: usize,
    /// Taken back: no further callback begins.
    gone: bool,
}

#[expect(
    clippy::vec_box,
    reason = "a registration's address is the handle a driver holds"
)]
static REGISTRATIONS: SpinLock<Vec<alloc::boxed::Box<Registration>>> =
    SpinLock::new(Rank::DeviceTree, Vec::new());

/// Call `callback(structure, context)` for the registration `handle`,
/// if it is still registered.
fn call(handle: usize, structure: *mut c_void) {
    let target = {
        let mut registrations = REGISTRATIONS.lock();
        registrations
            .iter_mut()
            .find(|r| core::ptr::from_ref::<Registration>(r) as usize == handle && !r.gone)
            .map(|r| {
                r.calls += 1;
                r.caller = crate::ke::pcr::current_thread() as usize;
                (r.callback, r.context)
            })
    };
    let Some((callback, context)) = target else {
        return;
    };
    // SAFETY: a driver's notification callback, registered for this
    // category, called at `PASSIVE_LEVEL` with the structure of that
    // category and the driver's context. Nothing is owed if it is
    // unwound but the count of calls, which is left raised: the
    // registration then cannot be taken back, as an entry Windows'
    // callback never returned from cannot.
    unsafe { seh::call(callback, [structure.addr(), context, 0, 0], &Guard::Nothing) };
    let mut registrations = REGISTRATIONS.lock();
    if let Some(at) = registrations
        .iter()
        .position(|r| core::ptr::from_ref::<Registration>(r) as usize == handle)
    {
        registrations[at].calls -= 1;
        // Taken back from inside its own callback: it goes now.
        if registrations[at].gone && registrations[at].calls == 0 {
            registrations.swap_remove(at);
            registrations.shrink_to_fit();
        }
    }
}

/// Tell `handles` that the interface `link` of `class` arrived or
/// went.
fn tell(handles: &[usize], class: &[u8; 16], link: &str, arrived: bool) {
    if handles.is_empty() {
        return;
    }
    crate::ke::irql::expect_passive("a Plug and Play notification");
    // The structure and the name are the callbacks' to read during the
    // call: in the pool, reached by pointer only.
    let mut name: Vec<u16> = link.encode_utf16().chain([0]).collect();
    let bytes = size_of::<DEVICE_INTERFACE_CHANGE_NOTIFICATION>() + size_of::<UNICODE_STRING>();
    let block = pool::alloc_zeroed(bytes, super::TAG);
    if block.is_null() {
        return;
    }
    let structure = block.cast::<DEVICE_INTERFACE_CHANGE_NOTIFICATION>();
    // SAFETY: a fresh zeroed block with room for the structure and the
    // counted string behind it; `name` outlives the calls.
    unsafe {
        let string = structure.add(1).cast::<UNICODE_STRING>();
        string.write(UNICODE_STRING {
            Length: ((name.len() - 1) * 2) as u16,
            MaximumLength: (name.len() * 2) as u16,
            Buffer: name.as_mut_ptr(),
        });
        structure.write(DEVICE_INTERFACE_CHANGE_NOTIFICATION {
            Version: 1,
            Size: size_of::<DEVICE_INTERFACE_CHANGE_NOTIFICATION>() as u16,
            Event: if arrived {
                GUID_DEVICE_INTERFACE_ARRIVAL
            } else {
                GUID_DEVICE_INTERFACE_REMOVAL
            },
            InterfaceClassGuid: *class,
            SymbolicLinkName: string,
        });
    }
    for handle in handles {
        call(*handle, structure.cast());
    }
    let _ = pool::free(block);
}

/// The interface `link` of `class` was enabled or disabled: tell every
/// registration for the class.
pub fn interface_changed(class: &[u8; 16], link: &str, arrived: bool) {
    let handles: Vec<usize> = REGISTRATIONS
        .lock()
        .iter()
        .filter(|r| {
            r.category == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE && r.class == *class && !r.gone
        })
        .map(|r| core::ptr::from_ref::<Registration>(r) as usize)
        .collect();
    tell(&handles, class, link, arrived);
}

/// [`IoRegisterPlugPlayNotification`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioregisterplugplaynotification):
/// have `callback` called with `context` for events of `category`. The
/// registration holds a reference to `driver` until it is taken back.
///
/// For interface changes, `data` is the class's GUID, and with
/// `PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES` the
/// callback is called, before this returns, for each interface of the
/// class that is enabled now. Registrations of the other two
/// categories are kept and never called (see the top of this file).
///
/// # Safety
/// `driver` is a live driver object; `callback` is a notification
/// callback of that driver; for interface changes `data` points to a
/// GUID; `handle` is writable.
pub unsafe extern "C" fn IoRegisterPlugPlayNotification(
    category: u32,
    flags: u32,
    data: *const c_void,
    driver: *mut DRIVER_OBJECT,
    callback: usize,
    context: usize,
    handle: *mut *mut c_void,
) -> NTSTATUS {
    crate::ke::irql::expect_passive("IoRegisterPlugPlayNotification");
    let class = match category {
        EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE => {
            if data.is_null() {
                return STATUS_INVALID_PARAMETER;
            }
            // SAFETY: per the contract.
            unsafe { data.cast::<[u8; 16]>().read_unaligned() }
        }
        EVENT_CATEGORY_HARDWARE_PROFILE_CHANGE | EVENT_CATEGORY_TARGET_DEVICE_CHANGE => [0; 16],
        _ => return STATUS_INVALID_DEVICE_REQUEST,
    };
    if driver.is_null() || callback == 0 || handle.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    let registration = alloc::boxed::Box::new(Registration {
        category,
        class,
        driver: driver as usize,
        callback,
        context,
        calls: 0,
        caller: 0,
        gone: false,
    });
    let own = core::ptr::from_ref::<Registration>(&registration) as usize;
    {
        let mut registrations = REGISTRATIONS.lock();
        if registrations.try_reserve_exact(1).is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        registrations.push(registration);
    }
    // SAFETY: per the contract: the registration's reference, and the
    // caller's place for the handle.
    unsafe {
        object::reference(driver.cast());
        handle.write_unaligned(own as *mut c_void);
    }
    if category == EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE
        && flags & PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES != 0
    {
        for link in super::interface::enabled_of(&class) {
            tell(&[own], &class, &link, true);
        }
    }
    STATUS_SUCCESS
}

/// [`IoUnregisterPlugPlayNotificationEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iounregisterplugplaynotificationex):
/// take a registration back. No callback begins after this is called;
/// one in progress on another thread is waited for. Called from inside
/// the registration's own callback, it does not wait for itself.
///
/// # Safety
/// `handle` came from `IoRegisterPlugPlayNotification` and has not
/// been taken back.
pub unsafe extern "C" fn IoUnregisterPlugPlayNotificationEx(handle: *mut c_void) -> NTSTATUS {
    let own = handle as usize;
    let me = crate::ke::pcr::current_thread() as usize;
    let driver = loop {
        {
            let mut registrations = REGISTRATIONS.lock();
            let Some(at) = registrations
                .iter()
                .position(|r| core::ptr::from_ref::<Registration>(r) as usize == own)
            else {
                return STATUS_INVALID_PARAMETER;
            };
            let found = &mut registrations[at];
            found.gone = true;
            if found.calls == 0 || (found.calls == 1 && found.caller == me) {
                let driver = found.driver;
                // A callback taking itself back leaves the entry for
                // `call` to free when the callback returns.
                if found.calls == 0 {
                    registrations.swap_remove(at);
                    registrations.shrink_to_fit();
                }
                break driver;
            }
        }
        // A callback is running on another thread: let it finish.
        crate::ke::time::stall(100);
    };
    // SAFETY: the registration's reference to its driver object.
    unsafe { object::dereference(driver as *mut u8) };
    STATUS_SUCCESS
}

/// [`IoUnregisterPlugPlayNotification`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iounregisterplugplaynotification):
/// as `IoUnregisterPlugPlayNotificationEx`.
///
/// # Safety
/// As `IoUnregisterPlugPlayNotificationEx`.
pub unsafe extern "C" fn IoUnregisterPlugPlayNotification(handle: *mut c_void) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe { IoUnregisterPlugPlayNotificationEx(handle) }
}
