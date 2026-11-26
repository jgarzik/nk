//! The names of a device interface: the symbolic link that stands for
//! one device as a member of one interface class, and the registry
//! keys that record it under `Control\DeviceClasses`.
//!
//! The link of the reference machine's disk as a disk
//! (`GUID_DEVINTERFACE_DISK`):
//! `\??\SCSI#Disk&Ven_QEMU&Prod_HARDDISK#4&35424867&0&000000#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}`:
//! the instance path with `#` for each backslash, `#`, and the class.
//! A reference string, which tells apart several interfaces of one
//! class on one device, follows behind a backslash.

use alloc::format;
use alloc::string::String;

/// What the link's name starts with in the kernel, and for user mode.
const KERNEL_PREFIX: &str = "\\??\\";
const USER_PREFIX: &str = "\\\\?\\";

/// The name of the symbolic link for the device `instance` as a member
/// of `class`, with the reference string `reference` (empty for none).
/// `None` for a device without an instance path, or a reference string
/// with a path separator in it, which Windows does not take.
pub fn link_name(instance: &str, class: &[u8; 16], reference: &str) -> Option<String> {
    if instance.is_empty() || reference.contains(['\\', '/']) {
        return None;
    }
    let device = instance.replace('\\', "#");
    let class = crate::ids::guid_text(class);
    Some(if reference.is_empty() {
        format!("{KERNEL_PREFIX}{device}#{class}")
    } else {
        format!("{KERNEL_PREFIX}{device}#{class}\\{reference}")
    })
}

/// The link's name without its prefix, split into the device-and-class
/// part and the reference string (empty for none).
fn parts(link: &str) -> (&str, &str) {
    let rest = link.strip_prefix(KERNEL_PREFIX).unwrap_or(link);
    rest.split_once('\\').unwrap_or((rest, ""))
}

/// The name of the interface's key under its class: `##?#`, then
/// device and class.
pub fn registry_name(link: &str) -> String {
    format!("##?#{}", parts(link).0)
}

/// The name of the subkey for the link's reference string: `#`, then
/// the string.
pub fn reference_key(link: &str) -> String {
    format!("#{}", parts(link).1)
}

/// The link's name as user mode spells it (`\\?\...`), which is what
/// the registry records.
pub fn user_name(link: &str) -> String {
    let rest = link.strip_prefix(KERNEL_PREFIX).unwrap_or(link);
    format!("{USER_PREFIX}{rest}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const DISK: &str = "SCSI\\Disk&Ven_QEMU&Prod_HARDDISK\\4&35424867&0&000000";

    fn disk_class() -> [u8; 16] {
        crate::ids::guid_from_text("{53f56307-b6bf-11d0-94f2-00a0c91efb8b}").unwrap()
    }

    #[test]
    fn the_link_names_device_and_class() {
        let link = link_name(DISK, &disk_class(), "").unwrap();
        assert_eq!(
            link,
            "\\??\\SCSI#Disk&Ven_QEMU&Prod_HARDDISK#4&35424867&0&000000#\
             {53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
        );
        assert_eq!(
            registry_name(&link),
            "##?#SCSI#Disk&Ven_QEMU&Prod_HARDDISK#4&35424867&0&000000#\
             {53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
        );
        assert_eq!(reference_key(&link), "#");
        assert_eq!(
            user_name(&link),
            "\\\\?\\SCSI#Disk&Ven_QEMU&Prod_HARDDISK#4&35424867&0&000000#\
             {53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
        );
    }

    #[test]
    fn a_reference_string_follows_the_class() {
        let link = link_name("ROOT\\X\\0000", &disk_class(), "Port1").unwrap();
        assert!(link.ends_with("#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}\\Port1"));
        assert_eq!(
            registry_name(&link),
            "##?#ROOT#X#0000#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"
        );
        assert_eq!(reference_key(&link), "#Port1");
        assert!(user_name(&link).ends_with("\\Port1"));
    }

    #[test]
    fn names_that_are_not_taken() {
        assert_eq!(link_name("", &disk_class(), ""), None);
        assert_eq!(link_name(DISK, &disk_class(), "a\\b"), None);
        assert_eq!(link_name(DISK, &disk_class(), "a/b"), None);
        // A name without the kernel's prefix is taken as it is.
        assert_eq!(registry_name("A#B"), "##?#A#B");
        assert_eq!(user_name("A#B"), "\\\\?\\A#B");
    }
}
