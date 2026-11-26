//! Device identifiers: the strings a bus driver answers
//! `IRP_MN_QUERY_ID` with, and the instance path the Plug and Play
//! manager builds from them (`<device id>\<instance id>`, the name of
//! the device's key under `Enum`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

/// The strings of a `REG_MULTI_SZ`: each ends at a zero, the list at an
/// empty string or at the end of `units`.
pub fn multi_sz(units: &[u16]) -> Vec<String> {
    units
        .split(|&c| c == 0)
        .take_while(|s| !s.is_empty())
        .map(String::from_utf16_lossy)
        .collect()
}

/// `strings` as a `REG_MULTI_SZ`: each followed by a zero, and one more
/// zero at the end. No strings is two zeros, as Windows writes it.
pub fn to_multi_sz<S: AsRef<str>>(strings: &[S]) -> Vec<u16> {
    let mut units: Vec<u16> = strings
        .iter()
        .flat_map(|s| s.as_ref().encode_utf16().chain([0]))
        .collect();
    if units.is_empty() {
        units.push(0);
    }
    units.push(0);
    units
}

/// `text` as a zero-terminated string's bytes, the data of a `REG_SZ`.
pub fn sz(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// The text of a `REG_SZ`'s data: up to its first zero.
pub fn from_sz(data: &[u8]) -> String {
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

/// The strings of a `REG_MULTI_SZ`'s data.
pub fn from_multi_sz(data: &[u8]) -> Vec<String> {
    let units: Vec<u16> = data
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    multi_sz(&units)
}

/// Whether `c` may stand in a device identifier. Windows replaces the
/// others (a space and everything below it, everything above `0x7F`,
/// and the comma) with an underscore before it uses an identifier as
/// part of a key's name.
const fn legal(c: char) -> bool {
    c > ' ' && (c as u32) <= 0x7F && c != ','
}

/// An identifier with every character that may not stand in one
/// replaced by an underscore.
pub fn fixed_up(id: &str) -> String {
    id.chars().map(|c| if legal(c) { c } else { '_' }).collect()
}

/// The number Windows makes of a parent's instance path for the
/// identifiers of its children: each upper-cased character folded in
/// (`37 * hash + c`), the result multiplied by 314159269, its sign
/// dropped, and reduced modulo 1000000007.
pub fn parent_hash(parent_instance_path: &str) -> u32 {
    let mut hash: u32 = 0;
    for c in parent_instance_path.encode_utf16() {
        let upper = if (u16::from(b'a')..=u16::from(b'z')).contains(&c) {
            c - 32
        } else {
            c
        };
        hash = hash.wrapping_mul(37).wrapping_add(u32::from(upper));
    }
    let scrambled = hash.wrapping_mul(314_159_269) as i32;
    scrambled.unsigned_abs() % 1_000_000_007
}

/// The prefix that makes the instance identifiers of a device's
/// children unique in the machine (`ParentIdPrefix`): the device's
/// depth in the tree, the hash of its instance path, and a counter that
/// tells apart devices at the same depth whose paths hash alike.
pub fn parent_id_prefix(level: u32, hash: u32, number: u32) -> String {
    format!("{level:x}&{hash:x}&{number:x}")
}

/// The name of the value under `Enum` that counts the prefixes given
/// out for one depth and hash.
pub fn next_parent_id_value(level: u32, hash: u32) -> String {
    format!("NextParentID.{hash:x}.{level:x}")
}

/// A device's instance path. `device` is what the bus answered for
/// `BusQueryDeviceID`, `instance` for `BusQueryInstanceID` (it may have
/// answered nothing). A bus that says the instance identifier is unique
/// in the machine (`DEVICE_CAPABILITIES.UniqueID`) has it used as it
/// is; otherwise the parent's prefix goes in front of it.
pub fn instance_path(
    device: &str,
    instance: Option<&str>,
    unique: bool,
    parent_prefix: &str,
) -> String {
    let device = fixed_up(device);
    let instance = instance.map(fixed_up);
    match instance {
        Some(instance) if unique => format!("{device}\\{instance}"),
        Some(instance) => format!("{device}\\{parent_prefix}&{instance}"),
        None => format!("{device}\\{parent_prefix}"),
    }
}

/// `DEVICE_CAPABILITIES` flags as the `Capabilities` value of a
/// device's key holds them (`CM_DEVCAP_*`): the bits from
/// `LockSupported` to `SurpriseRemovalOK` moved down by two, then
/// `HardwareDisabled` and `NonDynamic`.
pub const fn registry_capabilities(flags: u32) -> u32 {
    ((flags >> 2) & 0xFF) | (((flags >> 14) & 3) << 8)
}

/// A GUID as Windows writes a device class in the registry: braces,
/// lower-case digits.
pub fn guid_text(guid: &[u8; 16]) -> String {
    let d1 = u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]]);
    let d2 = u16::from_le_bytes([guid[4], guid[5]]);
    let d3 = u16::from_le_bytes([guid[6], guid[7]]);
    format!(
        "{{{d1:08x}-{d2:04x}-{d3:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}}}",
        guid[8], guid[9], guid[10], guid[11], guid[12], guid[13], guid[14], guid[15]
    )
}

/// The GUID a text like `{4d36e967-e325-11ce-bfc1-08002be10318}`
/// names, in either letter case; `None` if it is not one.
pub fn guid_from_text(text: &str) -> Option<[u8; 16]> {
    let inner = text.strip_prefix('{')?.strip_suffix('}')?;
    let parts: Vec<&str> = inner.split('-').collect();
    let lengths = [8, 4, 4, 4, 12];
    if parts.len() != 5 || parts.iter().zip(lengths).any(|(p, n)| p.len() != n) {
        return None;
    }
    let number = |text: &str| u64::from_str_radix(text, 16).ok();
    let mut guid = [0u8; 16];
    guid[..4].copy_from_slice(&(number(parts[0])? as u32).to_le_bytes());
    guid[4..6].copy_from_slice(&(number(parts[1])? as u16).to_le_bytes());
    guid[6..8].copy_from_slice(&(number(parts[2])? as u16).to_le_bytes());
    guid[8..10].copy_from_slice(&(number(parts[3])? as u16).to_be_bytes());
    guid[10..].copy_from_slice(&number(parts[4])?.to_be_bytes()[2..]);
    Some(guid)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn multi_sz_splits_and_joins() {
        let units = wide("ACPI_HAL\\PNP0C08\0*PNP0C08\0\0junk");
        assert_eq!(multi_sz(&units), ["ACPI_HAL\\PNP0C08", "*PNP0C08"]);
        assert_eq!(multi_sz(&wide("one")), ["one"]);
        assert!(multi_sz(&[0, 0]).is_empty());
        assert_eq!(to_multi_sz(&["a", "bc"]), wide("a\0bc\0\0"));
        assert_eq!(to_multi_sz::<&str>(&[]), [0, 0]);
    }

    #[test]
    fn registry_strings() {
        assert_eq!(sz("ab"), [b'a', 0, b'b', 0, 0, 0]);
        assert_eq!(from_sz(&sz("ACPI")), "ACPI");
        assert_eq!(from_sz(&[b'x', 0, 0, 0, b'y', 0]), "x");
        assert_eq!(from_sz(&[b'x', 0, b'y']), "x");
        let data: Vec<u8> = to_multi_sz(&["p", "q"])
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert_eq!(from_multi_sz(&data), ["p", "q"]);
    }

    #[test]
    fn illegal_characters_become_underscores() {
        assert_eq!(fixed_up("SCSI\\Disk QEMU,x\u{e9}"), "SCSI\\Disk_QEMU_x_");
        assert_eq!(fixed_up("PCI\\VEN_8086&DEV_2922"), "PCI\\VEN_8086&DEV_2922");
    }

    /// The prefixes the reference Windows gave the devices of the path
    /// to the disk (`ParentIdPrefix` in each one's key).
    #[test]
    fn parent_prefixes_are_windows() {
        let acpi = "ACPI_HAL\\PNP0C08\\0";
        assert_eq!(parent_hash(acpi), 0x0dab_a3ff);
        assert_eq!(parent_id_prefix(2, parent_hash(acpi), 0), "2&daba3ff&0");
        let root = "ACPI\\PNP0A08\\0";
        assert_eq!(parent_id_prefix(3, parent_hash(root), 0), "3&11583659&0");
        let ahci = "PCI\\VEN_8086&DEV_2922&SUBSYS_11001AF4&REV_02\\3&11583659&0&FA";
        assert_eq!(parent_id_prefix(4, parent_hash(ahci), 0), "4&35424867&0");
        // Letter case does not change the hash.
        assert_eq!(parent_hash("acpi\\pnp0a08\\0"), parent_hash(root));
        assert_eq!(
            next_parent_id_value(3, 0x1158_3659),
            "NextParentID.11583659.3"
        );
    }

    #[test]
    fn instance_paths() {
        assert_eq!(
            instance_path("ACPI\\PNP0A08", Some("0"), true, "2&daba3ff&0"),
            "ACPI\\PNP0A08\\0"
        );
        assert_eq!(
            instance_path(
                "PCI\\VEN_8086&DEV_2922&SUBSYS_11001AF4&REV_02",
                Some("FA"),
                false,
                "3&11583659&0"
            ),
            "PCI\\VEN_8086&DEV_2922&SUBSYS_11001AF4&REV_02\\3&11583659&0&FA"
        );
        assert_eq!(
            instance_path(
                "SCSI\\Disk&Ven_QEMU&Prod_HARDDISK",
                Some("000000"),
                false,
                "4&35424867&0"
            ),
            "SCSI\\Disk&Ven_QEMU&Prod_HARDDISK\\4&35424867&0&000000"
        );
        assert_eq!(
            instance_path("BUS\\DEV", None, false, "1&2&3"),
            "BUS\\DEV\\1&2&3"
        );
    }

    /// The `Capabilities` values of the reference Windows' keys.
    #[test]
    fn capabilities_as_the_registry_holds_them() {
        // UniqueID | SilentInstall: the HAL's ACPI device, 0x30.
        assert_eq!(registry_capabilities(1 << 6 | 1 << 7), 0x30);
        // SilentInstall | RawDeviceOK: the disk, 0x60.
        assert_eq!(registry_capabilities(1 << 7 | 1 << 8), 0x60);
        // The power bits are not capabilities of this kind.
        assert_eq!(registry_capabilities(0b11 | 1 << 10), 0);
        assert_eq!(registry_capabilities(1 << 14 | 1 << 15), 0x300);
    }

    #[test]
    fn guids() {
        let text = "{4d36e967-e325-11ce-bfc1-08002be10318}";
        let guid = guid_from_text(text).unwrap();
        assert_eq!(
            guid,
            [
                0x67, 0xe9, 0x36, 0x4d, 0x25, 0xe3, 0xce, 0x11, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1,
                0x03, 0x18
            ]
        );
        assert_eq!(guid_text(&guid), text);
        assert_eq!(guid_from_text(&text.to_uppercase()), Some(guid));
        for bad in [
            "4d36e967-e325-11ce-bfc1-08002be10318",
            "{4d36e967-e325-11ce-bfc1}",
            "{4d36e967-e325-11ce-bfc1-08002be1031}",
            "{4d36e96z-e325-11ce-bfc1-08002be10318}",
        ] {
            assert_eq!(guid_from_text(bad), None, "{bad}");
        }
    }
}
