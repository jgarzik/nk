//! Extension hosts: places in the kernel where a driver plugs in a
//! table of routines for the kernel to call (`ExRegisterExtension`).
//!
//! Windows' kernel creates sixteen hosts at boot (`ExRegisterHost`),
//! each named by an id and a version and expecting a number of
//! routines. NK has the two its drivers register with: `ksecdd.sys`'s
//! authorization routines (id 2) and `cng.sys`'s cryptography (id 3),
//! both created as Windows creates them, with no interface of their own
//! to hand back and no notification routine. NK calls neither table
//! yet. A registration with a host Windows has and NK does not stops
//! the system naming it; with a host Windows does not have either, it
//! fails as on Windows.

#![allow(non_snake_case)]

use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use nk_ntabi::status::*;

/// One host.
pub struct Host {
    id: u16,
    version: u16,
    functions: u16,
    /// The table registered, or null.
    table: AtomicPtr<c_void>,
}

impl Host {
    const fn new(id: u16, version: u16, functions: u16) -> Self {
        Self {
            id,
            version,
            functions,
            table: AtomicPtr::new(core::ptr::null_mut()),
        }
    }
}

/// The hosts NK creates (`SepInitializeAuthorizationCallbacks`).
static HOSTS: [Host; 2] = [Host::new(2, 1, 6), Host::new(3, 1, 0x24)];

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

/// `EX_EXTENSION_REGISTRATION`, as `cng.sys` and `ksecdd.sys` build it.
#[repr(C)]
struct Registration {
    id: u16,
    version: u16,
    functions: u16,
    table: *const *const c_void,
    host_interface: *mut *mut c_void,
    driver: *mut c_void,
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
    // SAFETY: per the contract.
    unsafe {
        if !host_interface.is_null() {
            // NK's hosts have no interface of their own.
            host_interface.write_unaligned(core::ptr::null_mut());
        }
        extension.write_unaligned(host);
    }
    STATUS_SUCCESS
}

/// `ExUnregisterExtension` (exported, not documented): take the table
/// back from the host `extension`, the handle `ExRegisterExtension`
/// gave. Nothing on NK calls a host's table, so there is no call under
/// way to wait for.
///
/// # Safety
/// `extension` is a handle `ExRegisterExtension` gave.
pub unsafe extern "C" fn ExUnregisterExtension(extension: *const Host) {
    // SAFETY: per the contract, one of the static hosts.
    unsafe {
        (*extension)
            .table
            .store(core::ptr::null_mut(), Ordering::Release)
    };
}
