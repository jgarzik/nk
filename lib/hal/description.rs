//! The firmware's description of the machine as Windows' loader leaves
//! it in the registry, under `HARDWARE\Description\System`: what
//! `acpi.sys` and `pci.sys` read there.
//!
//! The "ACPI BIOS" key's `Configuration Data` is a
//! `CM_FULL_RESOURCE_DESCRIPTOR` with one device-specific partial
//! descriptor, followed by an `ACPI_BIOS_MULTI_NODE`: the physical
//! address of the root table (the XSDT where there is one), a count, and
//! that many memory ranges in the form of the BIOS's E820 map.
//! `acpi.sys` stops the system (`ACPI_BIOS_ERROR`, 0x11) without it.

/// The kinds of memory an E820 entry names.
pub const E820_RAM: u32 = 1;
pub const E820_RESERVED: u32 = 2;
pub const E820_ACPI_RECLAIM: u32 = 3;
pub const E820_ACPI_NVS: u32 = 4;
pub const E820_UNUSABLE: u32 = 5;
pub const E820_PERSISTENT: u32 = 7;

/// A range of the memory map: base, length in bytes, E820 kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub base: u64,
    pub length: u64,
    pub kind: u32,
}

/// The E820 kind of a UEFI memory descriptor's type, as a loader turns
/// the firmware's map into the BIOS's: what the operating system may use
/// is RAM (loader and boot-services memory included, free once boot
/// services have ended), ACPI's two kinds keep their own, persistent
/// and unusable memory theirs, and the rest (reserved, runtime
/// services, memory-mapped I/O, firmware's own) is reserved.
pub const fn e820_kind(efi_type: u32) -> u32 {
    match efi_type {
        1..=4 | 7 => E820_RAM,
        9 => E820_ACPI_RECLAIM,
        10 => E820_ACPI_NVS,
        8 => E820_UNUSABLE,
        14 => E820_PERSISTENT,
        _ => E820_RESERVED,
    }
}

/// `InterfaceType` values of a resource descriptor.
pub const INTERFACE_INTERNAL: u32 = 0;
pub const INTERFACE_PCI_BUS: u32 = 5;
/// `CmResourceTypeDeviceSpecific`.
const DEVICE_SPECIFIC: u8 = 5;
/// The full descriptor's header (interface, bus, version, revision,
/// count) and one partial descriptor: where the node starts.
const NODE: usize = 16 + 20;
/// The node's own header: the root table's address and the count.
const NODE_HEADER: usize = 16;
/// One memory range of the node.
const ENTRY: usize = 24;

/// Write the "ACPI BIOS" `Configuration Data` for the root table at
/// `root` and the memory `ranges` into `out`, if it has room, and
/// return the number of bytes the data takes.
pub fn acpi_bios(root: u64, ranges: impl Iterator<Item = Range> + Clone, out: &mut [u8]) -> usize {
    let count = ranges.clone().count();
    let node = NODE_HEADER + count * ENTRY;
    let size = NODE + node;
    let Some(out) = out.get_mut(..size) else {
        return size;
    };
    out.fill(0);
    out[0..4].copy_from_slice(&INTERFACE_INTERNAL.to_le_bytes());
    // Bus 0, version 0, revision 0; one partial descriptor.
    out[12..16].copy_from_slice(&1u32.to_le_bytes());
    out[16] = DEVICE_SPECIFIC;
    out[20..24].copy_from_slice(&(node as u32).to_le_bytes());
    out[NODE..NODE + 8].copy_from_slice(&root.to_le_bytes());
    out[NODE + 8..NODE + 16].copy_from_slice(&(count as u64).to_le_bytes());
    for (entry, range) in out[NODE + NODE_HEADER..]
        .as_chunks_mut::<ENTRY>()
        .0
        .iter_mut()
        .zip(ranges)
    {
        entry[0..8].copy_from_slice(&range.base.to_le_bytes());
        entry[8..16].copy_from_slice(&range.length.to_le_bytes());
        entry[16..20].copy_from_slice(&range.kind.to_le_bytes());
    }
    size
}

/// The `Configuration Data` of a bus Windows' loader found nothing to
/// say about: a full descriptor for `interface`, bus 0, with no partial
/// descriptors. The "PCI" key's is this.
pub const fn empty_bus(interface: u32) -> [u8; 16] {
    let i = interface.to_le_bytes();
    [i[0], i[1], i[2], i[3], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
}

/// `Component Information` of a `MultifunctionAdapter` key: flags,
/// version and key 0, every processor in the affinity mask.
pub const COMPONENT_INFORMATION: [u8; 16] =
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF];

#[cfg(test)]
mod tests {
    use super::*;

    /// The layout the reference Windows has: the node starts at byte
    /// 36, its size is in the partial descriptor, entries are 24 bytes.
    #[test]
    fn the_acpi_bios_data_is_laid_out_as_windows_lays_it_out() {
        let ranges = [
            Range {
                base: 0,
                length: 0x1000,
                kind: E820_RAM,
            },
            Range {
                base: 0x80_0000,
                length: 0x8000,
                kind: E820_ACPI_NVS,
            },
        ];
        assert_eq!(
            acpi_bios(0x7FB7_D0E8, ranges.iter().copied(), &mut []),
            36 + 16 + 48
        );
        let mut out = [0xAAu8; 120];
        let size = acpi_bios(0x7FB7_D0E8, ranges.iter().copied(), &mut out);
        assert_eq!(size, 100);
        let u32_at = |o: usize| u32::from_le_bytes(out[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(out[o..o + 8].try_into().unwrap());
        assert_eq!((u32_at(0), u32_at(4), u32_at(8), u32_at(12)), (0, 0, 0, 1));
        assert_eq!((out[16], out[17], u32_at(20)), (5, 0, 64));
        assert_eq!((u32_at(24), u32_at(28), u32_at(32)), (0, 0, 0));
        assert_eq!((u64_at(36), u64_at(44)), (0x7FB7_D0E8, 2));
        assert_eq!(
            (u64_at(52), u64_at(60), u32_at(68), u32_at(72)),
            (0, 0x1000, 1, 0)
        );
        assert_eq!((u64_at(76), u64_at(84), u32_at(92)), (0x80_0000, 0x8000, 4));
        // Nothing beyond the data is written.
        assert!(out[100..].iter().all(|&b| b == 0xAA));
        // The reference machine's data: 144 ranges in 3508 bytes.
        let many = (0..144).map(|n| Range {
            base: n * 0x1000,
            length: 0x1000,
            kind: 1,
        });
        assert_eq!(acpi_bios(1, many, &mut []), 3508);
    }

    #[test]
    fn firmware_memory_types_become_e820_kinds() {
        assert_eq!(e820_kind(7), E820_RAM); // conventional
        assert_eq!(e820_kind(3), E820_RAM); // boot services code
        assert_eq!(e820_kind(9), E820_ACPI_RECLAIM);
        assert_eq!(e820_kind(10), E820_ACPI_NVS);
        assert_eq!(e820_kind(5), E820_RESERVED); // runtime services code
        assert_eq!(e820_kind(11), E820_RESERVED); // memory-mapped I/O
        assert_eq!(e820_kind(0), E820_RESERVED);
        assert_eq!(empty_bus(INTERFACE_PCI_BUS)[..4], [5, 0, 0, 0]);
    }
}
