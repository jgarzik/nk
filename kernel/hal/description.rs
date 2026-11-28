//! `\Registry\Machine\Hardware\Description\System`: the
//! firmware's description of the machine, which Windows' loader and
//! kernel put in the registry at every boot and nothing keeps on disk.
//! NK writes the keys Microsoft's drivers read (`nk_hal::description`
//! has the formats):
//!
//! - `MultifunctionAdapter\<n>` with `Identifier` "ACPI BIOS": the root
//!   ACPI table's address and the firmware's memory map. `acpi.sys`
//!   stops the system when it starts a device without it.
//! - `MultifunctionAdapter\<n>` with `Identifier` "PCI": a bus with
//!   nothing more said about it, as on the reference Windows, where the
//!   loader has no PCI BIOS to ask.
//!
//! Drivers find a key by its `Identifier`, not its number. Windows has
//! an "ISA" key before these two; NK describes no ISA bus.

use super::platform;
use crate::cm;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_hal::description::{self, Range};
use nk_ntabi::status::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_NOT_FOUND};

const SYSTEM: &str = "Machine\\Hardware\\Description\\System";
const REG_SZ: u32 = 1;
const REG_BINARY: u32 = 3;
const REG_FULL_RESOURCE_DESCRIPTOR: u32 = 9;

fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// The "ACPI BIOS" key's `Configuration Data` for this machine.
fn acpi_bios() -> Option<Vec<u8>> {
    let info = platform::boot_info()?;
    let root = platform::acpi_root()?;
    // SAFETY: the loader left the memory map in reserved memory that
    // the direct map covers and nothing writes.
    let map = unsafe {
        core::slice::from_raw_parts(
            crate::mm::phys_to_virt(info.mmap_phys),
            info.mmap_len as usize,
        )
    };
    let regions = || nk_bootinfo::regions(map, info.mmap_desc_size as usize);
    let mut ranges = Vec::new();
    ranges.try_reserve_exact(regions().count()).ok()?;
    ranges.extend(regions().map(|region| Range {
        base: region.phys,
        length: region.pages * crate::mm::PAGE_SIZE as u64,
        kind: description::e820_kind(region.kind),
    }));
    let size = description::acpi_bios(root, ranges.iter().copied(), &mut []);
    let mut data = Vec::new();
    data.try_reserve_exact(size).ok()?;
    data.resize(size, 0);
    description::acpi_bios(root, ranges.iter().copied(), &mut data);
    Some(data)
}

/// Write the description into the registry. After the registry is
/// built and before any driver starts.
pub fn publish() -> Result<(), &'static str> {
    const FAILED: &str = "the machine's description could not be written to the registry";
    let adapter = |number: u32, identifier: &str, configuration: &[u8]| {
        cm::write_path(
            &alloc::format!("{SYSTEM}\\MultifunctionAdapter\\{number}"),
            &[
                (
                    "Component Information",
                    REG_BINARY,
                    &description::COMPONENT_INFORMATION,
                ),
                ("Identifier", REG_SZ, &wide(identifier)),
                (
                    "Configuration Data",
                    REG_FULL_RESOURCE_DESCRIPTOR,
                    configuration,
                ),
            ],
        )
        .map_err(|_| FAILED)
    };
    let acpi = acpi_bios().ok_or(FAILED)?;
    adapter(0, "ACPI BIOS", &acpi)?;
    adapter(
        1,
        "PCI",
        &description::empty_bus(description::INTERFACE_PCI_BUS),
    )
}

/// [`IoQueryDeviceDescription`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioquerydevicedescription):
/// search `\Registry\Machine\Hardware\Description\System` for legacy
/// firmware-described buses, controllers and peripherals. On ACPI/UEFI
/// machines NK publishes only the `ACPI BIOS` and empty `PCI` adapters and
/// no legacy ISA/ARC controller nodes, so any controller/peripheral query
/// finds no matching entry (`STATUS_OBJECT_NAME_NOT_FOUND`), as on UEFI
/// Windows.
///
/// # Safety
/// Pointers are null or valid per Microsoft's `IoQueryDeviceDescription` contract.
#[allow(non_snake_case, clippy::too_many_arguments)]
pub unsafe extern "C" fn IoQueryDeviceDescription(
    _bus_type: *const u32,
    _bus_number: *const u32,
    _controller_type: *const u32,
    _controller_number: *const u32,
    _peripheral_type: *const u32,
    _peripheral_number: *const u32,
    callout_routine: *const c_void,
    _context: *mut c_void,
) -> NTSTATUS {
    crate::ke::irql::expect_passive("IoQueryDeviceDescription");
    if callout_routine.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    STATUS_OBJECT_NAME_NOT_FOUND
}

/// For the self-tests: the keys are there and say what the machine is.
pub fn test() -> Result<(), &'static str> {
    let key = |number: u32| alloc::format!("{SYSTEM}\\MultifunctionAdapter\\{number}");
    let (kind, identifier) = cm::read(&key(0), "Identifier").map_err(|_| "no ACPI BIOS key")?;
    if kind != REG_SZ || identifier != wide("ACPI BIOS") {
        return Err("the first adapter is not the ACPI BIOS");
    }
    let (kind, data) = cm::read(&key(0), "Configuration Data").map_err(|_| "no data")?;
    let word = |at: usize| {
        data.get(at..at + 8)
            .and_then(|b| b.try_into().ok())
            .map(u64::from_le_bytes)
    };
    let (Some(root), Some(count)) = (word(36), word(44)) else {
        return Err("the ACPI BIOS data is too short for its node");
    };
    if kind != REG_FULL_RESOURCE_DESCRIPTOR
        || Some(root) != platform::acpi_root()
        || count == 0
        || data.len() != 52 + count as usize * 24
    {
        return Err("the ACPI BIOS data does not name the root table and the memory map");
    }
    // Every range is whole pages and of a kind an E820 map has.
    let whole = (0..count as usize).all(|n| {
        let at = 52 + n * 24;
        let (Some(base), Some(length), Some(kind)) = (word(at), word(at + 8), word(at + 16)) else {
            return false;
        };
        base % 4096 == 0 && length % 4096 == 0 && length != 0 && (1..=7).contains(&(kind as u32))
    });
    if !whole {
        return Err("a range of the memory map is malformed");
    }
    let (_, identifier) = cm::read(&key(1), "Identifier").map_err(|_| "no PCI key")?;
    let (_, data) = cm::read(&key(1), "Configuration Data").map_err(|_| "no PCI data")?;
    if identifier != wide("PCI") || data != description::empty_bus(5) {
        return Err("the PCI key does not describe an undescribed PCI bus");
    }
    Ok(())
}
