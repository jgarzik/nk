//! State names of the Windows Notification Facility, as far as NK needs
//! them to say that a state does not exist.
//!
//! A state name is 64 bits, kept exclusive-ored with a constant; among
//! its fields is its lifetime. Windows finds a state by its name among
//! the instances that exist, and for a well-known or permanent name it
//! has not seen yet looks the name up in the registry, where the names
//! of this kind are listed, and makes the instance. A name found in
//! neither place is `STATUS_OBJECT_NAME_NOT_FOUND`
//! (`NtQueryWnfStateData`, `ExpWnfSubscribeWnfStateChange`,
//! `ExpWnfLookupNameInstance`, `ExpWnfLookupPermanentName` of the
//! pinned kernel). NK has no instances; a name is unknown unless its
//! registry lists it.

/// What a state name is exclusive-ored with.
const STATE_KEY: u64 = 0x41C6_4E6D_A3BC_0074;

/// `WNF_STATE_NAME_LIFETIME`.
pub const WELL_KNOWN: u32 = 0;
pub const PERMANENT: u32 = 1;
pub const PERSISTENT: u32 = 2;
pub const TEMPORARY: u32 = 3;

/// The lifetime of a state name: bits 4 and 5 of its plain form.
pub fn lifetime(state_name: u64) -> u32 {
    (((state_name ^ STATE_KEY) >> 4) & 3) as u32
}

/// Whether a name of this lifetime is one the registry of the SYSTEM
/// hive lists (`Control\Notifications`): the well-known and the
/// permanent. Persistent names are listed in the SOFTWARE hive, which
/// NK does not have, and temporary ones nowhere.
pub fn listed_in_system_hive(lifetime: u32) -> bool {
    lifetime == WELL_KNOWN || lifetime == PERMANENT
}

/// The name of the registry value that lists a state name: its sixteen
/// hexadecimal digits, upper case.
pub fn value_name(state_name: u64) -> [u8; 16] {
    let mut name = [0u8; 16];
    for (i, digit) in name.iter_mut().enumerate() {
        let nibble = (state_name >> (60 - 4 * i)) & 0xF;
        *digit = b"0123456789ABCDEF"[nibble as usize];
    }
    name
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lifetime_is_in_the_plain_name() {
        // WNF_SHEL_APPLICATION_STARTED, a well-known name.
        assert_eq!(lifetime(0x0D83_063E_A3BE_0075), WELL_KNOWN);
        for wanted in [WELL_KNOWN, PERMANENT, PERSISTENT, TEMPORARY] {
            let plain = u64::from(wanted) << 4 | 1;
            assert_eq!(lifetime(plain ^ STATE_KEY), wanted);
        }
    }

    #[test]
    fn which_names_the_system_hive_lists() {
        assert!(listed_in_system_hive(WELL_KNOWN));
        assert!(listed_in_system_hive(PERMANENT));
        assert!(!listed_in_system_hive(PERSISTENT));
        assert!(!listed_in_system_hive(TEMPORARY));
    }

    #[test]
    fn a_name_is_listed_by_its_digits() {
        assert_eq!(&value_name(0x0D83_063E_A3BE_0075), b"0D83063EA3BE0075");
        assert_eq!(&value_name(0xABCD_EF01_2345_6789), b"ABCDEF0123456789");
    }
}
