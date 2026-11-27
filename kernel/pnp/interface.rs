//! Device interfaces: a device's driver says "this device is one of
//! class G" (`IoRegisterDeviceInterface`) and turns that on
//! (`IoSetDeviceInterfaceState`); who wants devices of class G finds
//! them by a symbolic link whose name says device and class, and can
//! be told when one arrives (`super::notify`).
//!
//! The link's name and the registry record are Windows'
//! (`Control\DeviceClasses\{class}\##?#<device>#{class}`); the names
//! are built in `nk_pnp::interface`.

#![allow(non_snake_case)]

use super::node::{self, State};
use super::notify;
use crate::cm;
use crate::ke::{Rank, SpinLock};
use crate::mm::pool;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use nk_ntabi::io::{DEVICE_OBJECT, UNICODE_STRING};
use nk_ntabi::status::*;
use nk_pnp::{ids, interface as names};

const CLASSES: &str = "Machine\\System\\CurrentControlSet\\Control\\DeviceClasses";

const REG_SZ: u32 = 1;
const REG_DWORD: u32 = 4;

/// One registered interface.
struct Interface {
    /// The link's name, `\??\...`.
    link: String,
    class: [u8; 16],
    pdo: usize,
    /// The link exists.
    enabled: bool,
    /// Asked to be enabled before the device was started: enabled when
    /// it starts, as on Windows.
    waiting: bool,
}

static INTERFACES: SpinLock<Vec<Interface>> = SpinLock::new(Rank::DeviceTree, Vec::new());

/// The registry key of the interface `link`, and of its one instance
/// (the reference string's, `#` for none).
fn keys(class: &[u8; 16], link: &str) -> (String, String) {
    let device = format!(
        "{CLASSES}\\{}\\{}",
        ids::guid_text(class),
        names::registry_name(link)
    );
    let instance = format!("{device}\\{}", names::reference_key(link));
    (device, instance)
}

/// [`IoRegisterDeviceInterface`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioregisterdeviceinterface):
/// register the device whose physical device object is `device` as
/// one of the interface class `class`, and hand out the name of the
/// symbolic link that will stand for it, in pool memory the caller
/// frees (`RtlFreeUnicodeString`). The interface is not enabled.
/// Registered already, the same name is handed out with
/// `STATUS_OBJECT_NAME_EXISTS`.
///
/// # Safety
/// `device` is a live device object; `class` points to a GUID;
/// `reference` is null or a counted string; `link_name` is writable.
pub unsafe extern "C" fn IoRegisterDeviceInterface(
    device: *mut DEVICE_OBJECT,
    class: *const [u8; 16],
    reference: *const UNICODE_STRING,
    link_name: *mut UNICODE_STRING,
) -> NTSTATUS {
    // SAFETY: per the contract.
    let (class, reference) = unsafe {
        crate::io::device::check(device, "IoRegisterDeviceInterface");
        link_name.write_unaligned(UNICODE_STRING {
            Length: 0,
            MaximumLength: 0,
            Buffer: core::ptr::null_mut(),
        });
        let reference = crate::rtl::copy_unicode(reference);
        (class.read_unaligned(), String::from_utf16_lossy(&reference))
    };
    let Some(found) = node::get(device as usize) else {
        return STATUS_INVALID_DEVICE_REQUEST;
    };
    let Some(link) = names::link_name(&found.instance, &class, &reference) else {
        return STATUS_INVALID_DEVICE_REQUEST;
    };
    let known = {
        let mut interfaces = INTERFACES.lock();
        let known = interfaces.iter().any(|known| known.link == link);
        if !known {
            if interfaces.try_reserve_exact(1).is_err() {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            interfaces.push(Interface {
                link: link.clone(),
                class,
                pdo: device as usize,
                enabled: false,
                waiting: false,
            });
        }
        known
    };
    if !known {
        let (device_key, instance_key) = keys(&class, &link);
        let written = cm::write_path(
            &device_key,
            &[("DeviceInstance", REG_SZ, &ids::sz(&found.instance))],
        )
        .and_then(|()| {
            cm::write_path(
                &instance_key,
                &[("SymbolicLink", REG_SZ, &ids::sz(&names::user_name(&link)))],
            )
        });
        if written.is_err() {
            forget(&link);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }
    // The name, zero-terminated, in a block of the caller's.
    let units: Vec<u16> = link.encode_utf16().chain([0]).collect();
    let bytes = units.len() * 2;
    let block = pool::alloc(bytes, super::TAG);
    if block.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: a fresh block of that many bytes; `link_name` is the
    // caller's.
    unsafe {
        block.copy_from_nonoverlapping(units.as_ptr().cast(), bytes);
        link_name.write_unaligned(UNICODE_STRING {
            Length: (bytes - 2) as u16,
            MaximumLength: bytes as u16,
            Buffer: block.cast(),
        });
    }
    if known {
        STATUS_OBJECT_NAME_EXISTS
    } else {
        STATUS_SUCCESS
    }
}

/// Take the interface `link` out of the list and the registry.
fn forget(link: &str) {
    let gone = {
        let mut interfaces = INTERFACES.lock();
        let at = interfaces.iter().position(|known| known.link == link);
        let gone = at.map(|at| interfaces.swap_remove(at));
        interfaces.shrink_to_fit();
        gone
    };
    if let Some(gone) = gone {
        let (device_key, _) = keys(&gone.class, link);
        let _ = cm::delete_tree(&device_key);
    }
}

/// Make or remove the link of an interface and say so in the registry
/// and to whoever asked to be told.
fn switch(link: &str, class: &[u8; 16], pdo: usize, on: bool) -> NTSTATUS {
    let wide: Vec<u16> = link.encode_utf16().collect();
    let (_, instance_key) = keys(class, link);
    let control = format!("{instance_key}\\Control");
    if on {
        // SAFETY: the interface's device, which the tree holds.
        let Some(target) = (unsafe { super::export::device_name(pdo as *mut DEVICE_OBJECT) })
        else {
            // A device without a name cannot be linked to.
            return STATUS_INVALID_DEVICE_REQUEST;
        };
        let target: Vec<u16> = target.encode_utf16().collect();
        let status = crate::ob::insert_link(&wide, &target);
        if !nt_success(status) {
            return status;
        }
        let _ = cm::write_path(&control, &[("Linked", REG_DWORD, &1u32.to_le_bytes())]);
    } else {
        let status = crate::ob::remove_link(&wide);
        if !nt_success(status) {
            return status;
        }
        let _ = cm::write_path(&control, &[("Linked", REG_DWORD, &0u32.to_le_bytes())]);
    }
    notify::interface_changed(class, link, on);
    STATUS_SUCCESS
}

/// [`IoSetDeviceInterfaceState`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iosetdeviceinterfacestate):
/// enable or disable the interface whose link is named `link_name`.
/// Enabling makes the link and tells whoever registered for the
/// class's arrivals; if the device is not started yet, that happens
/// when it starts, and the call succeeds now, as on Windows.
///
/// Enabling answers:
/// - `STATUS_OBJECT_NAME_NOT_FOUND`: no such interface is registered.
/// - `STATUS_OBJECT_NAME_EXISTS`: enabled already.
///
/// Disabling answers `STATUS_SUCCESS` whatever came of it, as the
/// pinned kernel's routine turns any failure of a disable into success:
/// `partmgr.sys` disables an interface it never enabled on each disk it
/// starts, and fails the start on an error.
///
/// # Safety
/// `link_name` points to a counted string.
pub unsafe extern "C" fn IoSetDeviceInterfaceState(
    link_name: *const UNICODE_STRING,
    enable: u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    let status = unsafe { set_state(link_name, enable != 0) };
    if enable == 0 { STATUS_SUCCESS } else { status }
}

/// What [`IoSetDeviceInterfaceState`] does, with the status of it.
///
/// # Safety
/// `link_name` points to a counted string.
unsafe fn set_state(link_name: *const UNICODE_STRING, on: bool) -> NTSTATUS {
    crate::ke::irql::expect_passive("IoSetDeviceInterfaceState");
    // SAFETY: per the contract.
    let link = String::from_utf16_lossy(&unsafe { crate::rtl::copy_unicode(link_name) });
    // Whether the interface's device is started is the tree's to say,
    // under its own lock: asked before this list's lock is taken.
    let device = INTERFACES
        .lock()
        .iter()
        .find(|known| known.link.eq_ignore_ascii_case(&link))
        .map(|known| known.pdo);
    let started = device
        .and_then(|pdo| node::with(pdo, |node| node.state == State::Started))
        .unwrap_or(false);
    let (class, pdo) = {
        let mut interfaces = INTERFACES.lock();
        let Some(known) = interfaces
            .iter_mut()
            .find(|known| known.link.eq_ignore_ascii_case(&link))
        else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        if on && (known.enabled || known.waiting) {
            return STATUS_OBJECT_NAME_EXISTS;
        }
        if !on && !known.enabled {
            let waited = core::mem::replace(&mut known.waiting, false);
            return if waited {
                STATUS_SUCCESS
            } else {
                STATUS_OBJECT_NAME_NOT_FOUND
            };
        }
        if on && !started {
            known.waiting = true;
            return STATUS_SUCCESS;
        }
        known.enabled = on;
        (known.class, known.pdo)
    };
    let link = canonical(&link).unwrap_or(link);
    let status = switch(&link, &class, pdo, on);
    if !nt_success(status) {
        // Nothing was switched: the interface is as it was.
        let mut interfaces = INTERFACES.lock();
        if let Some(known) = interfaces.iter_mut().find(|known| known.link == link) {
            known.enabled = !on;
        }
    }
    status
}

/// The name an interface was registered under, for a name that may
/// differ from it in letter case.
fn canonical(link: &str) -> Option<String> {
    INTERFACES
        .lock()
        .iter()
        .find(|known| known.link.eq_ignore_ascii_case(link))
        .map(|known| known.link.clone())
}

/// The device `pdo` has started: the interfaces its drivers enabled
/// before that are enabled now.
pub fn device_started(pdo: usize) {
    let waiting: Vec<(String, [u8; 16])> = {
        let mut interfaces = INTERFACES.lock();
        interfaces
            .iter_mut()
            .filter(|known| known.pdo == pdo && known.waiting)
            .map(|known| {
                known.waiting = false;
                known.enabled = true;
                (known.link.clone(), known.class)
            })
            .collect()
    };
    for (link, class) in waiting {
        if !nt_success(switch(&link, &class, pdo, true)) {
            let mut interfaces = INTERFACES.lock();
            if let Some(known) = interfaces.iter_mut().find(|known| known.link == link) {
                known.enabled = false;
            }
        }
    }
}

/// The device `pdo` is not started any more, or is gone (`forgotten`):
/// its interfaces are disabled, and for a device that is gone taken
/// off the list with their records.
pub fn device_stopped(pdo: usize, forgotten: bool) {
    let own: Vec<(String, [u8; 16], bool)> = {
        let mut interfaces = INTERFACES.lock();
        interfaces
            .iter_mut()
            .filter(|known| known.pdo == pdo)
            .map(|known| {
                known.waiting = false;
                let enabled = core::mem::replace(&mut known.enabled, false);
                (known.link.clone(), known.class, enabled)
            })
            .collect()
    };
    for (link, class, enabled) in own {
        if enabled {
            switch(&link, &class, pdo, false);
        }
        if forgotten {
            forget(&link);
        }
    }
}

/// The links of the enabled interfaces of the class `class`, for a
/// registration that asks to be told of those that exist already.
pub fn enabled_of(class: &[u8; 16]) -> Vec<String> {
    INTERFACES
        .lock()
        .iter()
        .filter(|known| known.enabled && known.class == *class)
        .map(|known| known.link.clone())
        .collect()
}

/// [`IoSetDeviceInterfacePropertyData`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iosetdeviceinterfacepropertydata):
/// give the registered interface whose link is `link_name` the
/// property `key`, of type `kind`, or with `DEVPROP_TYPE_EMPTY` (0)
/// take it away. The property is kept with the interface's record,
/// under `Properties\{category}\NNNN` of its reference string's key
/// (where exactly Windows keeps an interface's properties NK has not
/// read; nothing reads them back but
/// `IoGetDeviceInterfacePropertyData`, which no driver NK runs
/// imports).
///
/// INFERRED: `STATUS_OBJECT_NAME_NOT_FOUND` for a link that names no
/// registered interface, and `STATUS_INVALID_PARAMETER` for a locale
/// other than neutral.
///
/// # Safety
/// `link_name` points to a counted string; `key` to a `DEVPROPKEY`;
/// `data` is readable for `size` bytes.
pub unsafe extern "C" fn IoSetDeviceInterfacePropertyData(
    link_name: *const UNICODE_STRING,
    key: *const nk_ntabi::pnp::DEVPROPKEY,
    lcid: u32,
    _flags: u32,
    kind: u32,
    size: u32,
    data: *const u8,
) -> NTSTATUS {
    if lcid != 0 || key.is_null() || (size != 0 && data.is_null()) {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract; a driver may pack the key.
    let (link, fmtid, pid, value) = unsafe {
        let mut value = alloc::vec![0u8; size as usize];
        data.copy_to_nonoverlapping(value.as_mut_ptr(), value.len());
        (
            String::from_utf16_lossy(&crate::rtl::copy_unicode(link_name)),
            (&raw const (*key).fmtid).read_unaligned(),
            (&raw const (*key).pid).read_unaligned(),
            value,
        )
    };
    let known = INTERFACES
        .lock()
        .iter()
        .find(|known| known.link.eq_ignore_ascii_case(&link))
        .map(|known| (known.link.clone(), known.class));
    let Some((link, class)) = known else {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    };
    let (_, instance_key) = keys(&class, &link);
    let path = format!(
        "{instance_key}\\Properties\\{}\\{pid:04X}",
        ids::guid_text(&fmtid)
    );
    let done = if kind == 0 {
        cm::delete_tree(&path)
    } else {
        let stored = super::registry::DEVPROP_REGISTRY_TYPE | (kind & 0xFFFF);
        cm::write_path(&path, &[("", stored, &value)])
    };
    match done {
        Ok(()) => STATUS_SUCCESS,
        Err(status) => status,
    }
}
