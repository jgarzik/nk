//! Extension hosts: places in the kernel where a driver plugs in a
//! table of routines for the kernel to call (`ExRegisterExtension`).
//!
//! Windows' kernel creates sixteen hosts at boot (`ExRegisterHost`),
//! each named by an id and a version and expecting a number of
//! routines. NK has the three its drivers register with, made as
//! Windows makes them: `pcw.sys`'s performance counters (id 1), which
//! the kernel's `Pcw*` routines call; `ksecdd.sys`'s authorization
//! routines (id 2) and `cng.sys`'s cryptography (id 3), which nothing on
//! NK calls yet. A registration with a host Windows has and NK does not
//! stops the system naming it; with a host Windows does not have
//! either, it fails as on Windows.
//!
//! As on Windows, a host's table is reached under run-down protection
//! ([`table`]): protection that is run down until a table is registered,
//! and run down again, waiting for those inside, when it is taken back.

#![allow(non_snake_case)]

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};
use nk_ntabi::status::*;

/// One host.
pub struct Host {
    id: u16,
    version: u16,
    functions: u16,
    /// The table registered, or null.
    table: AtomicPtr<c_void>,
    /// Whoever is using the table holds this.
    rundown: AtomicUsize,
    /// Told of a registration before (0) and after (1) it is made, and
    /// of an unregistration before (2) and after (3).
    notify: Option<fn(u32)>,
}

impl Host {
    const fn new(id: u16, version: u16, functions: u16, notify: Option<fn(u32)>) -> Self {
        Self {
            id,
            version,
            functions,
            table: AtomicPtr::new(core::ptr::null_mut()),
            // Run down: no table to use yet.
            rundown: AtomicUsize::new(nk_ex::rundown::ACTIVE),
            notify,
        }
    }
}

/// `pcw.sys`'s host.
pub static PCW: Host = Host::new(1, 1, 5, Some(super::pcw::host_notification));
/// `ksecdd.sys`'s and `cng.sys`'s.
static AUTHORIZATION: Host = Host::new(2, 1, 6, None);
static CRYPTOGRAPHY: Host = Host::new(3, 1, 0x24, None);

/// The hosts NK creates (`ExpInitSystemPhase1`,
/// `SepInitializeAuthorizationCallbacks`).
static HOSTS: [&Host; 3] = [&PCW, &AUTHORIZATION, &CRYPTOGRAPHY];

/// `(id, version)` of every host the pinned kernel creates
/// (`ExRegisterHost`'s sixteen callers).
const WINDOWS_HOSTS: [(u16, u16); 16] = [
    (1, 1),
    (2, 1),
    (3, 1),
    (4, 1),
    (5, 13),
    (6, 11),
    (7, 1),
    (8, 17),
    (9, 1),
    (10, 2),
    (11, 1),
    (12, 1),
    (13, 2),
    (14, 1),
    (15, 3),
    (16, 3),
];

/// The version of `EX_EXTENSION_REGISTRATION` callers pass, in the high
/// half of the version argument.
const REGISTRATION_VERSION: u32 = 0x1_0000;

/// `EX_EXTENSION_REGISTRATION`, as the drivers build it.
#[repr(C)]
struct Registration {
    id: u16,
    version: u16,
    functions: u16,
    table: *const *const c_void,
    host_interface: *mut *mut c_void,
    driver: *mut c_void,
}

/// The table registered with `host`, under run-down protection that the
/// caller gives back with [`release`]; `None` with no table
/// (`ExGetExtensionTable`).
pub fn table(host: &Host) -> Option<*const *const c_void> {
    // SAFETY: the host's protection, which lives for ever.
    if unsafe { super::rundown::ExAcquireRundownProtection(host.rundown.as_ptr()) } == 0 {
        return None;
    }
    Some(host.table.load(Ordering::Acquire).cast_const().cast())
}

/// Give back the protection [`table`] took (`ExReleaseExtensionTable`).
pub fn release(host: &Host) {
    // SAFETY: the caller holds the protection.
    unsafe { super::rundown::ExReleaseRundownProtection(host.rundown.as_ptr()) };
}

/// `ExRegisterExtension` (exported, not documented): plug the
/// registration's table of routines into the host it names, and give
/// the caller the host, as its handle, and the host's interface (none
/// for NK's hosts). As the pinned kernel checks: a registration version
/// other than 1, or a table missing where routines are counted, is
/// `STATUS_INVALID_PARAMETER`; no such host, `STATUS_NOT_FOUND`; fewer
/// routines than the host takes, `STATUS_INVALID_PARAMETER`; a null
/// routine, `STATUS_ACCESS_DENIED`; a host with a table already,
/// `STATUS_OBJECT_NAME_COLLISION`.
///
/// # Safety
/// `extension` is writable; `registration` points to a registration
/// whose table holds its count of routines.
pub unsafe extern "C" fn ExRegisterExtension(
    extension: *mut *const Host,
    version: u32,
    registration: *const c_void,
) -> NTSTATUS {
    let registration = registration.cast::<Registration>();
    // SAFETY: per the contract.
    let (id, host_version, functions, table, host_interface) = unsafe {
        (
            (&raw const (*registration).id).read_unaligned(),
            (&raw const (*registration).version).read_unaligned(),
            (&raw const (*registration).functions).read_unaligned(),
            (&raw const (*registration).table).read_unaligned(),
            (&raw const (*registration).host_interface).read_unaligned(),
        )
    };
    if version & 0xFFFF_0000 != REGISTRATION_VERSION || (table.is_null() && functions != 0) {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(host) = HOSTS
        .iter()
        .find(|h| h.id == id && h.version == host_version)
    else {
        if WINDOWS_HOSTS.contains(&(id, host_version)) {
            crate::kd::bugcheck(format_args!(
                "ExRegisterExtension: NK does not implement extension host {id} version {host_version}"
            ));
        }
        return STATUS_NOT_FOUND;
    };
    if functions < host.functions {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract, the table holds `functions` routines.
    if (0..usize::from(functions)).any(|i| unsafe { table.add(i).read_unaligned() }.is_null()) {
        return STATUS_ACCESS_DENIED;
    }
    if host
        .table
        .compare_exchange(
            core::ptr::null_mut(),
            table.cast_mut().cast(),
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        return STATUS_OBJECT_NAME_COLLISION;
    }
    if let Some(notify) = host.notify {
        notify(0);
    }
    // The table may be used from now on.
    // SAFETY: the host's protection, run down while it had no table.
    unsafe { super::rundown::ExInitializeRundownProtection(host.rundown.as_ptr()) };
    if let Some(notify) = host.notify {
        notify(1);
    }
    // SAFETY: per the contract.
    unsafe {
        if !host_interface.is_null() {
            // NK's hosts have no interface of their own.
            host_interface.write_unaligned(core::ptr::null_mut());
        }
        extension.write_unaligned(*host);
    }
    STATUS_SUCCESS
}

/// `ExUnregisterExtension` (exported, not documented): take the table
/// back from the host `extension`, the handle `ExRegisterExtension`
/// gave, once nobody is using it.
///
/// # Safety
/// `extension` is a handle `ExRegisterExtension` gave.
pub unsafe extern "C" fn ExUnregisterExtension(extension: *const Host) {
    // SAFETY: per the contract, one of the static hosts.
    let host = unsafe { &*extension };
    if let Some(notify) = host.notify {
        notify(2);
    }
    // SAFETY: the host's protection, which lives for ever.
    unsafe { super::rundown::ExWaitForRundownProtectionRelease(host.rundown.as_ptr()) };
    host.table.store(core::ptr::null_mut(), Ordering::Release);
    if let Some(notify) = host.notify {
        notify(3);
    }
}
