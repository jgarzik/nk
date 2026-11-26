//! The questions the Plug and Play manager asks a device stack, and
//! the reading of the answers.
//!
//! An answer that is more than a status is memory the driver allocated
//! from the pool and handed over in `IoStatus.Information`: the manager
//! copies what it needs and frees the block, as on Windows. What a
//! driver hands over is read through raw pointers, unit by unit, up to
//! a bound: nothing here trusts a length it has not checked.

use crate::io::stack::{send_synchronous, send_synchronous_from};
use crate::mm::pool;
use alloc::string::String;
use alloc::vec::Vec;
use nk_ntabi::io::{DEVICE_OBJECT, IRP_MJ_PNP};
use nk_ntabi::pnp::*;
use nk_ntabi::status::*;
use nk_pnp::resources::{Requirements, ResourceList};

/// The longest answer, in bytes, the manager reads of a string or a
/// list a driver hands it: far beyond what any device answers.
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

/// Free what a driver handed over.
fn release(block: usize) {
    if block != 0 {
        let _ = pool::free(block as *mut u8);
    }
}

/// The UTF-16 units at `address`, up to and without the zero that ends
/// them; for a list of strings (`multi`), up to the empty string that
/// ends the list, the zeros between them kept.
///
/// # Safety
/// `address` is a zero-terminated string (or list of them) in readable
/// memory.
unsafe fn units(address: usize, multi: bool) -> Vec<u16> {
    let mut found = Vec::new();
    let text = address as *const u16;
    for at in 0..LONGEST / 2 {
        // SAFETY: per the contract, nothing past the terminator is
        // read. A driver may pack the string.
        let unit = unsafe { text.add(at).read_unaligned() };
        if unit == 0 && (!multi || found.last().is_none_or(|last| *last == 0)) {
            break;
        }
        found.push(unit);
    }
    found
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
        let found = units(information, multi);
        release(information);
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
        let found = units(information, false);
        release(information);
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
    // SAFETY: a successful answer is 24 bytes from the pool.
    unsafe {
        let (status, information) = pnp(device, IRP_MN_QUERY_BUS_INFORMATION, [0; 4]);
        if !nt_success(status) || information == 0 {
            return None;
        }
        let bytes = (information as *const [u8; 24]).read_unaligned();
        release(information);
        Some(super::node::BusInformation {
            bus_type: bytes[..16].try_into().unwrap(),
            legacy_bus_type: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            bus_number: u32::from_le_bytes(bytes[20..].try_into().unwrap()),
        })
    }
}

/// Copy `length` bytes from `address`.
///
/// # Safety
/// The bytes are readable.
unsafe fn copy(address: usize, length: usize) -> Vec<u8> {
    let mut bytes = alloc::vec![0u8; length];
    // SAFETY: per the contract; the copy is NK's own memory.
    unsafe { (address as *const u8).copy_to_nonoverlapping(bytes.as_mut_ptr(), length) };
    bytes
}

/// The bytes of the `IO_RESOURCE_REQUIREMENTS_LIST` at `address`, as
/// long as the list says it is; `None` if what it says cannot be.
///
/// # Safety
/// `address` is a requirements list in readable memory.
pub unsafe fn requirements_at(address: usize) -> Option<Vec<u8>> {
    // SAFETY: per the contract: the list is as long as its first field
    // says.
    unsafe {
        let stated = (address as *const [u8; 4]).read_unaligned();
        let size = Requirements::stated_size(stated).filter(|size| *size <= LONGEST)?;
        let bytes = copy(address, size);
        Requirements::parse(&bytes).map(|_| bytes)
    }
}

/// The bytes of the `CM_RESOURCE_LIST` at `address`. A resource list
/// does not state its length: it is walked, descriptor by descriptor.
///
/// # Safety
/// `address` is a resource list in readable memory.
pub unsafe fn resource_list_at(address: usize) -> Option<Vec<u8>> {
    // Read as much as the list is found to need, a step at a time: the
    // count, then each bus's header, then its descriptors.
    let mut have = 4;
    loop {
        // SAFETY: per the contract, `have` bytes of the list are there:
        // each step asks only for what the bytes before it promise.
        let bytes = unsafe { copy(address, have) };
        match ResourceList::needed(&bytes, LONGEST) {
            Some(need) if need > have => have = need,
            Some(_) => return ResourceList::parse(&bytes).map(|(_, used)| bytes[..used].to_vec()),
            None => return None,
        }
    }
}

/// What the stack answers `IRP_MN_QUERY_RESOURCE_REQUIREMENTS` with,
/// as bytes; empty if it has no requirements.
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
        let bytes = requirements_at(information).unwrap_or_default();
        release(information);
        bytes
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
        let bytes = resource_list_at(information).unwrap_or_default();
        release(information);
        bytes
    }
}

/// Have the stack filter `list`, the device's requirements
/// (`IRP_MN_FILTER_RESOURCE_REQUIREMENTS`), and return the list as the
/// drivers left it. The request starts out successful and holding the
/// list, as Windows sends it; a driver that changes the list frees the
/// one it was given and hands over its own.
///
/// # Safety
/// As [`pnp`].
pub unsafe fn filtered(device: *mut DEVICE_OBJECT, list: &[u8]) -> Result<Vec<u8>, NTSTATUS> {
    let block = pool::alloc(list.len(), super::TAG);
    if block.is_null() {
        return Err(STATUS_INSUFFICIENT_RESOURCES);
    }
    // SAFETY: a fresh block of the list's length; what comes back in
    // `Information` is the list now in force, from the pool: the one
    // sent, or a driver's that replaced it (which freed the one sent).
    unsafe {
        block.copy_from_nonoverlapping(list.as_ptr(), list.len());
        let (status, information) = send_synchronous_from(
            device,
            IRP_MJ_PNP,
            IRP_MN_FILTER_RESOURCE_REQUIREMENTS,
            filter_resource_requirements_parameters(block as u64),
            Some((STATUS_SUCCESS, block as usize)),
        );
        if !nt_success(status) && status != STATUS_NOT_SUPPORTED {
            release(information);
            return Err(status);
        }
        if information == 0 {
            // No list is left: the device requires nothing.
            return Ok(Vec::new());
        }
        let bytes = requirements_at(information);
        release(information);
        bytes.ok_or(STATUS_INVALID_PARAMETER)
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
    // pool, its count followed by that many pointers.
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
        let relations = information as *const DEVICE_RELATIONS;
        let count = (&raw const (*relations).Count).read_unaligned() as usize;
        let objects = (&raw const (*relations).Objects).cast::<usize>();
        let found = (0..count.min(LONGEST / 8))
            .map(|at| objects.add(at).read_unaligned())
            .collect();
        release(information);
        Ok(Some(found))
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
