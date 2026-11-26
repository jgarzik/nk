//! Which driver-database record a device's identifiers match.
//!
//! Windows' driver database (`DriverDatabase` in the registry) names,
//! per device identifier, the INF files that list it
//! (`DeviceIds\<id>`), and per INF the driver package that is active.
//! A package describes each identifier it serves
//! (`Descriptors\<id>`: which configuration) and each configuration
//! (`Configurations\<name>`: the service, the identifiers it must not
//! be used for, what goes into the device's key).
//!
//! A device answers a list of hardware identifiers and a list of
//! compatible ones, each from the most specific to the least. The
//! match is the first identifier, hardware ones before compatible
//! ones, that the database has a usable record for.

use alloc::string::String;

/// Where in a device's lists the matching identifier stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    /// The identifier that matched, as the device spelled it.
    pub id: String,
    /// Whether it is one of the compatible identifiers.
    pub compatible: bool,
    /// Its place in its list, from zero.
    pub index: usize,
}

/// The first of `hardware`, then of `compatible`, for which `usable`
/// says the database has a record that may be used.
pub fn select<S: AsRef<str>>(
    hardware: &[S],
    compatible: &[S],
    mut usable: impl FnMut(&str) -> bool,
) -> Option<Match> {
    let lists = [(hardware, false), (compatible, true)];
    for (list, compatible) in lists {
        for (index, id) in list.iter().enumerate() {
            if usable(id.as_ref()) {
                return Some(Match {
                    id: id.as_ref().into(),
                    compatible,
                    index,
                });
            }
        }
    }
    None
}

/// Whether two identifiers are the same: letter case does not count.
pub fn same_id(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Whether a configuration's `ExcludeIds` rule it out for a device:
/// one of them is among the device's identifiers.
pub fn excluded<S: AsRef<str>, T: AsRef<str>>(
    exclude: &[S],
    hardware: &[T],
    compatible: &[T],
) -> bool {
    exclude.iter().any(|excluded| {
        hardware
            .iter()
            .chain(compatible)
            .any(|id| same_id(excluded.as_ref(), id.as_ref()))
    })
}

/// The device class a driver package installs its devices in: the
/// GUID in a package's `Version` value, behind the eight bytes it
/// starts with.
pub fn package_class(version: &[u8]) -> Option<[u8; 16]> {
    version.get(8..24)?.try_into().ok()
}

/// The service a `Service` value names. Windows keeps the driver
/// object's path there for a device whose driver has no service key
/// (`\Driver\ACPI_HAL`): the name is then what follows `\Driver\`.
pub fn service_name(value: &str) -> &str {
    let prefix = "\\Driver\\";
    match value.get(..prefix.len()) {
        Some(start) if start.eq_ignore_ascii_case(prefix) => &value[prefix.len()..],
        _ => value,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AHCI_HARDWARE: [&str; 4] = [
        "PCI\\VEN_8086&DEV_2922&SUBSYS_11001AF4&REV_02",
        "PCI\\VEN_8086&DEV_2922&SUBSYS_11001AF4",
        "PCI\\VEN_8086&DEV_2922&CC_010601",
        "PCI\\VEN_8086&DEV_2922&CC_0106",
    ];
    const AHCI_COMPATIBLE: [&str; 7] = [
        "PCI\\VEN_8086&DEV_2922&REV_02",
        "PCI\\VEN_8086&DEV_2922",
        "PCI\\VEN_8086&CC_010601",
        "PCI\\VEN_8086&CC_0106",
        "PCI\\VEN_8086",
        "PCI\\CC_010601",
        "PCI\\CC_0106",
    ];

    /// The reference machine's AHCI controller matches `mshdc.inf` by
    /// its sixth compatible identifier.
    #[test]
    fn the_first_usable_identifier_wins() {
        let database = ["pci\\cc_010601", "PCI\\CC_0106"];
        let found = select(&AHCI_HARDWARE, &AHCI_COMPATIBLE, |id| {
            database.iter().any(|known| same_id(known, id))
        });
        assert_eq!(
            found,
            Some(Match {
                id: "PCI\\CC_010601".into(),
                compatible: true,
                index: 5
            })
        );
    }

    #[test]
    fn hardware_identifiers_come_first() {
        let found = select(&["A", "B"], &["B", "C"], |id| id != "A");
        assert_eq!(
            found,
            Some(Match {
                id: "B".into(),
                compatible: false,
                index: 1
            })
        );
        assert_eq!(select(&["A"], &["B"], |_| false), None);
        assert_eq!(select::<&str>(&[], &[], |_| true), None);
    }

    #[test]
    fn exclusion() {
        let exclude = ["GenSFloppy", "SCSI\\DiskMATSHITALS-120/240"];
        assert!(excluded(&exclude, &["x", "gensfloppy"], &[]));
        assert!(excluded(
            &exclude,
            &["x"],
            &["SCSI\\DISKMATSHITALS-120/240"]
        ));
        assert!(!excluded(&exclude, &["GenDisk"], &["SCSI\\Disk"]));
        assert!(!excluded::<&str, &str>(&[], &["GenDisk"], &[]));
    }

    #[test]
    fn class_of_a_package() {
        // disk.inf's `Version` on the reference Windows.
        let version = [
            0xff, 0xff, 0x09, 0x00, 0, 0, 0, 0, 0x67, 0xe9, 0x36, 0x4d, 0x25, 0xe3, 0xce, 0x11,
            0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18, 0x00, 0x80,
        ];
        let class = package_class(&version).unwrap();
        assert_eq!(
            crate::ids::guid_text(&class),
            "{4d36e967-e325-11ce-bfc1-08002be10318}"
        );
        assert_eq!(package_class(&version[..23]), None);
    }

    #[test]
    fn service_names() {
        assert_eq!(service_name("ACPI"), "ACPI");
        assert_eq!(service_name("\\Driver\\ACPI_HAL"), "ACPI_HAL");
        assert_eq!(service_name("\\driver\\x"), "x");
        assert_eq!(service_name("\\Dri"), "\\Dri");
    }
}
