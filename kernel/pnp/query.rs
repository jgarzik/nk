//! The questions the Plug and Play manager asks a device stack, and
//! the reading of the answers.
//!
//! An answer that is more than a status is memory the driver allocated
//! from the pool and handed over in `IoStatus.Information`: the manager
//! copies it and frees the block, as on Windows. The copy is as long as
//! the pool says the block is, and everything is read out of the copy:
//! what an answer says of its own length (a list's size field, a
//! string's terminator, a count) is believed only as far as the block
//! reaches. An answer that is not the start of a pool block is not
//! read at all.

use crate::io::stack::{send_synchronous, send_synchronous_from};
use crate::mm::pool;
use alloc::string::String;
use alloc::vec::Vec;
use nk_ntabi::io::{DEVICE_OBJECT, IRP_MJ_PNP};
use nk_ntabi::pnp::*;
use nk_ntabi::status::*;
use nk_pnp::resources::{Requirements, ResourceList};

/// The longest answer, in bytes, the manager copies: far beyond what
/// any device answers.
const LONGEST: usize = 1 << 20;

/// The locale device text is asked for in: US English, the system
/// default of the reference Windows.
const LOCALE: u32 = 0x409;

/// Send a Plug and Play request to the stack of `device`.
///
/// # Safety
/// `device` is a live device object; `parameters` names nothing that
/// goes away during the call. `PASSIVE_LEVEL`.
pub unsafe fn pnp(
    device: *mut DEVICE_OBJECT,
    minor: u8,
    parameters: [u64; 4],
) -> (NTSTATUS, usize) {
    // SAFETY: per the contract.
    unsafe { send_synchronous(device, IRP_MJ_PNP, minor, parameters) }
}

/// A copy of the pool block at `address`, as long as the block is.
/// `None` if `address` is not the start of a live pool block, or the
/// block is longer than any answer.
///
/// # Safety
/// If `address` is a pool block, nothing frees it during the call.
pub unsafe fn block(address: usize) -> Option<Vec<u8>> {
    let (size, _) = pool::info(address as *const u8)?;
    if size > LONGEST {
        return None;
    }
    let mut bytes = alloc::vec![0u8; size];
    // SAFETY: a live pool block of `size` bytes, per the pool and the
    // contract; the copy is NK's own memory.
    unsafe { (address as *const u8).copy_to_nonoverlapping(bytes.as_mut_ptr(), size) };
    Some(bytes)
}

/// Copy the block a driver handed over, and free it: it is the
/// manager's. What is not a pool block is left alone.
///
/// # Safety
/// `address` is what a driver put in `IoStatus.Information` for a
/// request whose answer is a pool block the receiver frees.
unsafe fn take(address: usize) -> Option<Vec<u8>> {
    // SAFETY: per the contract.
    let bytes = unsafe { block(address) }?;
    let _ = pool::free(address as *mut u8);
    Some(bytes)
}

/// The string, or for `multi` the list of strings, `bytes` begin with.
/// `None` if the bytes end before the string does.
fn text_of(bytes: &[u8], multi: bool) -> Option<Vec<u16>> {
    let mut found = Vec::new();
    for unit in bytes.as_chunks::<2>().0 {
        let unit = u16::from_le_bytes(*unit);
        if unit == 0 && (!multi || found.last().is_none_or(|last| *last == 0)) {
            return Some(found);
        }
        found.push(unit);
    }
    None
}

/// What the stack of `device` answers `IRP_MN_QUERY_ID` for `kind`
/// with: one identifier, or for the hardware and the compatible
/// identifiers a list of them. `Ok(empty)` if no driver answers.
///
/// # Safety
/// As [`pnp`].
pub unsafe fn id(device: *mut DEVICE_OBJECT, kind: u32) -> Result<Vec<String>, NTSTATUS> {
    // SAFETY: per the contract; a successful answer is a string from
    // the pool, the manager's to free.
    unsafe {
        let (status, information) = pnp(device, IRP_MN_QUERY_ID, query_id_parameters(kind));
        if !nt_success(status) || information == 0 {
            return if status == STATUS_NOT_SUPPORTED || nt_success(status) {
                Ok(Vec::new())
            } else {
                Err(status)
            };
        }
        let multi = matches!(kind, BUS_QUERY_HARDWARE_IDS | BUS_QUERY_COMPATIBLE_IDS);
        let found = take(information)
            .and_then(|bytes| text_of(&bytes, multi))
            .ok_or(STATUS_PNP_INVALID_ID)?;
        Ok(if multi {
            nk_pnp::ids::multi_sz(&found)
        } else {
            alloc::vec![String::from_utf16_lossy(&found)]
        })
    }
}

/// What the stack answers `IRP_MN_QUERY_DEVICE_TEXT` with, if anything.
///
/// # Safety
/// As [`pnp`].
pub unsafe fn text(device: *mut DEVICE_OBJECT, kind: u32) -> Option<String> {
    // SAFETY: as in `id`.
    unsafe {
        let parameters = query_device_text_parameters(kind, LOCALE);
        let (status, information) = pnp(device, IRP_MN_QUERY_DEVICE_TEXT, parameters);
        if !nt_success(status) || information == 0 {
            return None;
        }
        let found = text_of(&take(information)?, false)?;
        Some(String::from_utf16_lossy(&found))
    }
}

/// The capabilities the stack of `device` states: its flags, `Address`
/// and `UINumber`. The structure starts out as Windows sends it:
/// version 1, address and number all ones.
///
/// # Safety
/// As [`pnp`].
pub unsafe fn capabilities(device: *mut DEVICE_OBJECT) -> Result<(u32, u32, u32), NTSTATUS> {
    // An all-zero structure is a valid value. It is the drivers' to
    // write: reached by pointer only.
    let block = pool::alloc_zeroed(size_of::<DEVICE_CAPABILITIES>(), super::TAG)
        .cast::<DEVICE_CAPABILITIES>();
    if block.is_null() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: a fresh block of that size, freed below; the request has
    // completed when `pnp` returns.
    unsafe {
        (&raw mut (*block).Size).write(size_of::<DEVICE_CAPABILITIES>() as u16);
        (&raw mut (*block).Version).write(1);
        (&raw mut (*block).Address).write(u32::MAX);
        (&raw mut (*block).UINumber).write(u32::MAX);
        let parameters = device_capabilities_parameters(block as u64);
        let (status, _) = pnp(device, IRP_MN_QUERY_CAPABILITIES, parameters);
        let answer = (
            (&raw const (*block).Flags).read(),
            (&raw const (*block).Address).read(),
            (&raw const (*block).UINumber).read(),
        );
        let _ = pool::free(block.cast());
        if nt_success(status) || status == STATUS_NOT_SUPPORTED {
            Ok(answer)
        } else {
            Err(status)
        }
    }
}

/// What the stack answers `IRP_MN_QUERY_BUS_INFORMATION` with: a
/// `PNP_BUS_INFORMATION` (the bus type's GUID, the legacy bus type,
/// the bus number).
///
/// # Safety
/// As [`pnp`].
pub unsafe fn bus_information(device: *mut DEVICE_OBJECT) -> Option<super::node::BusInformation> {
    // SAFETY: a successful answer is a structure from the pool.
    unsafe {
        let (status, information) = pnp(device, IRP_MN_QUERY_BUS_INFORMATION, [0; 4]);
        if !nt_success(status) || information == 0 {
            return None;
        }
        let bytes = take(information)?;
        let bytes = bytes.get(..24)?;
        Some(super::node::BusInformation {
            bus_type: bytes[..16].try_into().ok()?,
            legacy_bus_type: u32::from_le_bytes(bytes[16..20].try_into().ok()?),
            bus_number: u32::from_le_bytes(bytes[20..].try_into().ok()?),
        })
    }
}

/// The bytes of the `CM_RESOURCE_LIST` the pool block at `address`
/// begins with; `None` if it is not a pool block or holds no whole
/// list.
///
/// # Safety
/// As [`block`].
pub unsafe fn resource_list_at(address: usize) -> Option<Vec<u8>> {
    // SAFETY: per the contract.
    let bytes = unsafe { block(address) }?;
    ResourceList::parse(&bytes).map(|(_, used)| bytes[..used].to_vec())
}

/// What the stack answers `IRP_MN_QUERY_RESOURCE_REQUIREMENTS` with,
/// as bytes; empty if it has no requirements, or answered with what
/// is not a list.
///
/// # Safety
/// As [`pnp`].
pub unsafe fn requirements(device: *mut DEVICE_OBJECT) -> Vec<u8> {
    // SAFETY: a successful answer is a list from the pool.
    unsafe {
        let (status, information) = pnp(device, IRP_MN_QUERY_RESOURCE_REQUIREMENTS, [0; 4]);
        if !nt_success(status) || information == 0 {
            return Vec::new();
        }
        take(information)
            .and_then(|bytes| Requirements::in_block(&bytes).map(<[u8]>::to_vec))
            .unwrap_or_default()
    }
}

/// What the stack answers `IRP_MN_QUERY_RESOURCES` with (the device's
/// boot configuration), as bytes; empty if it has none.
///
/// # Safety
/// As [`pnp`].
pub unsafe fn resources(device: *mut DEVICE_OBJECT) -> Vec<u8> {
    // SAFETY: a successful answer is a list from the pool.
    unsafe {
        let (status, information) = pnp(device, IRP_MN_QUERY_RESOURCES, [0; 4]);
        if !nt_success(status) || information == 0 {
            return Vec::new();
        }
        take(information)
            .and_then(|bytes| ResourceList::parse(&bytes).map(|(_, used)| bytes[..used].to_vec()))
            .unwrap_or_default()
    }
}

/// Have the stack filter `list`, the device's requirements
/// (`IRP_MN_FILTER_RESOURCE_REQUIREMENTS`), and return the list as the
/// drivers left it; empty for none. The request is sent as Windows
/// sends it (`IopFilterResourceRequirementsCall`): with a list, it
/// starts out successful and holding the list; without one, as not
/// supported and holding nothing. A driver that changes the list frees
/// the one it was given and hands over its own.
///
/// # Safety
/// As [`pnp`].
pub unsafe fn filtered(device: *mut DEVICE_OBJECT, list: &[u8]) -> Result<Vec<u8>, NTSTATUS> {
    let sent = if list.is_empty() {
        core::ptr::null_mut()
    } else {
        let sent = pool::alloc(list.len(), super::TAG);
        if sent.is_null() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        // SAFETY: a fresh block of the list's length.
        unsafe { sent.copy_from_nonoverlapping(list.as_ptr(), list.len()) };
        sent
    };
    let start = (!sent.is_null()).then_some((STATUS_SUCCESS, sent as usize));
    // SAFETY: per the contract. What comes back in `Information` is
    // the list now in force, from the pool: the one sent, or a
    // driver's that replaced it (which freed the one sent).
    unsafe {
        let (status, information) = send_synchronous_from(
            device,
            IRP_MJ_PNP,
            IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
            filter_resource_requirements_parameters(sent as u64),
            start,
        );
        if information == 0 {
            // No list is left: the device requires nothing.
            return if nt_success(status) || status == STATUS_NOT_SUPPORTED {
                Ok(Vec::new())
            } else {
                Err(status)
            };
        }
        let bytes = take(information);
        if !nt_success(status) && status != STATUS_NOT_SUPPORTED {
            return Err(status);
        }
        bytes
            .and_then(|bytes| Requirements::in_block(&bytes).map(<[u8]>::to_vec))
            .ok_or(STATUS_INVALID_PARAMETER)
    }
}

/// The devices the stack of `device` reports for `relation`, each
/// referenced for the caller, as the driver that answered referenced
/// them. `Ok(None)` if no driver answers.
///
/// # Safety
/// As [`pnp`].
pub unsafe fn relations(
    device: *mut DEVICE_OBJECT,
    relation: u32,
) -> Result<Option<Vec<usize>>, NTSTATUS> {
    // SAFETY: a successful answer is a `DEVICE_RELATIONS` from the
    // pool.
    unsafe {
        let parameters = query_device_relations_parameters(relation);
        let (status, information) = pnp(device, IRP_MN_QUERY_DEVICE_RELATIONS, parameters);
        if status == STATUS_NOT_SUPPORTED {
            return Ok(None);
        }
        if !nt_success(status) {
            return Err(status);
        }
        if information == 0 {
            return Ok(Some(Vec::new()));
        }
        let bytes = take(information).ok_or(STATUS_INVALID_PARAMETER)?;
        // The count, padded to a pointer, then that many pointers: as
        // many as the block holds.
        let count = bytes
            .get(..4)
            .map(|count| u32::from_le_bytes(count.try_into().unwrap()) as usize)
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let objects = bytes.get(8..).unwrap_or(&[]).as_chunks::<8>().0;
        if count > objects.len() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        Ok(Some(
            objects[..count]
                .iter()
                .map(|object| usize::from_le_bytes(*object))
                .collect(),
        ))
    }
}

/// `PNP_DEVICE_STATE` bits.
pub const PNP_DEVICE_DISABLED: u32 = 0x1;
pub const PNP_DEVICE_FAILED: u32 = 0x4;
pub const PNP_DEVICE_REMOVED: u32 = 0x8;

/// What the stack answers `IRP_MN_QUERY_PNP_DEVICE_STATE` with: the
/// `PNP_DEVICE_STATE` bits, zero if no driver answers.
///
/// # Safety
/// As [`pnp`].
pub unsafe fn device_state(device: *mut DEVICE_OBJECT) -> u32 {
    // SAFETY: per the contract.
    let (status, information) = unsafe { pnp(device, IRP_MN_QUERY_PNP_DEVICE_STATE, [0; 4]) };
    if nt_success(status) {
        information as u32
    } else {
        0
    }
}
