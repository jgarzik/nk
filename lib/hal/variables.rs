//! Firmware environment variables: what Windows makes of UEFI's
//! variable services
//! ([UEFI specification, Variable Services](https://uefi.org/specs/UEFI/2.10/08_Services_Runtime_Services.html#variable-services)).
//!
//! The firmware is behind a trait, so the rules are tested on the
//! host: the status a firmware status becomes, and the buffer
//! `HalEnumerateEnvironmentVariablesEx` fills, both as the pinned
//! kernel has them (`HalEfiToNtStatusMappings`,
//! `HalpEnumerateEnvironmentVariablesWithFilter`).

use nk_ntabi::status::*;

/// UEFI statuses the rules look at: an error has the top bit set.
pub const EFI_SUCCESS: u64 = 0;
const EFI_ERROR: u64 = 1 << 63;
pub const EFI_BUFFER_TOO_SMALL: u64 = EFI_ERROR | 5;
pub const EFI_NOT_FOUND: u64 = EFI_ERROR | 14;

/// Variable attributes: kept across a restart, visible to boot
/// services, visible at run time, and "append to what is there".
pub const VARIABLE_NON_VOLATILE: u32 = 0x1;
pub const VARIABLE_BOOTSERVICE_ACCESS: u32 = 0x2;
pub const VARIABLE_RUNTIME_ACCESS: u32 = 0x4;
pub const VARIABLE_APPEND_WRITE: u32 = 0x40;

/// How many 16-bit units the HAL's buffer for a variable's name
/// holds, terminator included: Windows passes firmware no longer
/// name, and stops enumerating at a longer one.
pub const NAME_UNITS: usize = 256;

/// The status Windows gives for a firmware status: the pinned
/// kernel's table. One that is not in it is `STATUS_UNSUCCESSFUL`.
pub const fn nt_status(efi: u64) -> NTSTATUS {
    const fn status(value: u32) -> NTSTATUS {
        value as NTSTATUS
    }
    if efi & EFI_ERROR == 0 {
        // Success, and the four warnings.
        return match efi {
            0 => STATUS_SUCCESS,
            1 => status(0xC00A_0022),
            2 => status(0xC000_0121),
            4 => status(0xC000_0023),
            _ => STATUS_UNSUCCESSFUL,
        };
    }
    match efi & !EFI_ERROR {
        1 => status(0xC000_026C),
        2 => STATUS_INVALID_PARAMETER,
        3 => STATUS_NOT_SUPPORTED,
        4 => status(0xC000_0206),
        5 => STATUS_BUFFER_TOO_SMALL,
        6 | 19 => STATUS_DEVICE_NOT_READY,
        7 | 10 | 16 => status(0xC000_0185),
        8 => status(0xC000_00A2),
        9 => status(0xC000_0454),
        11 => status(0xC000_007F),
        12 => status(0xC000_0178),
        13 => status(0x8000_001C),
        14 => STATUS_VARIABLE_NOT_FOUND,
        15 | 26 => STATUS_ACCESS_DENIED,
        17 => status(0xC000_0088),
        18 => status(0xC000_00B5),
        20 => status(0x8000_0011),
        21 => status(0xC000_0240),
        22..=24 => status(0xC000_0186),
        25 => STATUS_REVISION_MISMATCH,
        27 => status(0xC000_003F),
        _ => STATUS_UNSUCCESSFUL,
    }
}

/// The two variable services an enumeration uses.
pub trait Variables {
    /// `GetNextVariableName`: `name` and `guid` hold the last variable
    /// found (an empty name to begin) and are given the next. Returns
    /// the firmware's status and the size of the name in bytes, its
    /// terminator included.
    fn next(&mut self, name: &mut [u16; NAME_UNITS], guid: &mut [u8; 16]) -> (u64, usize);

    /// `GetVariable` into `value`; an empty `value` asks for the size
    /// alone. Returns the firmware's status, the size of the value
    /// (the size needed, for `EFI_BUFFER_TOO_SMALL`), and the
    /// attributes if the firmware gave them.
    fn get(
        &mut self,
        name: &[u16; NAME_UNITS],
        guid: &[u8; 16],
        value: &mut [u8],
    ) -> (u64, usize, Option<u32>);
}

/// `VARIABLE_NAME` (class 1): `NextEntryOffset`, the vendor GUID, the
/// name. `VARIABLE_NAME_AND_VALUE` (class 2): `NextEntryOffset`,
/// `ValueOffset`, `ValueLength`, `Attributes`, the GUID, the name, and
/// the value at the next multiple of four.
pub const CLASS_NAMES: u32 = 1;
pub const CLASS_VALUES: u32 = 2;
const NAME_HEADER: usize = 0x14;
const VALUE_HEADER: usize = 0x20;

fn put_u32(buffer: &mut [u8], at: usize, value: usize) {
    buffer[at..at + 4].copy_from_slice(&(value as u32).to_le_bytes());
}

/// Fill `buffer` with every variable, as
/// `HalEnumerateEnvironmentVariablesEx` does for information class
/// `class`: one entry after another, each at a multiple of four and
/// leading to the next by its first field, the last with zero there.
/// Returns the status and the length: the bytes used, or with
/// `STATUS_BUFFER_TOO_SMALL` the bytes a buffer needs. A buffer that
/// is too small holds the entries that fitted whole.
///
/// `class` is 1 or 2 and the caller's buffer starts at a multiple of
/// four; the caller has checked both.
pub fn enumerate(firmware: &mut impl Variables, class: u32, buffer: &mut [u8]) -> (NTSTATUS, u32) {
    let header = if class == CLASS_NAMES {
        NAME_HEADER
    } else {
        VALUE_HEADER
    };
    let mut remaining = buffer.len();
    let mut fits = remaining != 0;
    let mut cursor = 0usize;
    let mut last: Option<usize> = None;
    let mut status = STATUS_SUCCESS;
    let mut name = [0u16; NAME_UNITS];
    let mut guid = [0u8; 16];
    loop {
        let (found, name_size) = firmware.next(&mut name, &mut guid);
        if found != EFI_SUCCESS {
            if found != EFI_NOT_FOUND {
                status = STATUS_UNSUCCESSFUL;
            }
            break;
        }
        let name_size = name_size.min(NAME_UNITS * 2);
        let aligned = cursor.next_multiple_of(4);
        if aligned != cursor {
            let pad = aligned - cursor;
            cursor = aligned;
            if remaining < pad {
                fits = false;
                remaining = 0;
                status = STATUS_BUFFER_TOO_SMALL;
            } else {
                remaining -= pad;
            }
        }
        let mut need = header + name_size;
        if class != CLASS_NAMES {
            need = need.next_multiple_of(4);
        }
        let left = if remaining < need {
            status = STATUS_BUFFER_TOO_SMALL;
            fits = false;
            0
        } else {
            remaining - need
        };
        let name_bytes = name.iter().flat_map(|unit| unit.to_le_bytes());
        if class == CLASS_NAMES {
            if fits {
                buffer[cursor + 4..cursor + NAME_HEADER].copy_from_slice(&guid);
                for (to, from) in buffer[cursor + NAME_HEADER..cursor + NAME_HEADER + name_size]
                    .iter_mut()
                    .zip(name_bytes)
                {
                    *to = from;
                }
                if let Some(last) = last {
                    put_u32(buffer, last, cursor - last);
                }
                last = Some(cursor);
            }
            remaining = left;
            cursor += need;
            continue;
        }
        let value_at = cursor + need;
        if fits {
            buffer[cursor + 0x10..cursor + VALUE_HEADER].copy_from_slice(&guid);
            for (to, from) in buffer[cursor + VALUE_HEADER..cursor + VALUE_HEADER + name_size]
                .iter_mut()
                .zip(name_bytes)
            {
                *to = from;
            }
            put_u32(buffer, cursor + 4, need);
        }
        let room: &mut [u8] = if fits {
            &mut buffer[value_at..value_at + left]
        } else {
            &mut []
        };
        let (got, size, attributes) = firmware.get(&name, &guid, room);
        if let (true, Some(attributes)) = (fits, attributes) {
            put_u32(buffer, cursor + 0xC, attributes as usize);
        }
        if got == EFI_SUCCESS {
            remaining = left;
            if fits {
                put_u32(buffer, cursor + 8, size);
                remaining -= size.min(remaining);
                if let Some(last) = last {
                    put_u32(buffer, last, cursor - last);
                }
                last = Some(cursor);
            }
        } else if got == EFI_BUFFER_TOO_SMALL {
            remaining = 0;
            fits = false;
            status = STATUS_BUFFER_TOO_SMALL;
        } else {
            status = STATUS_UNSUCCESSFUL;
            break;
        }
        cursor = value_at + size;
    }
    if let Some(last) = last {
        put_u32(buffer, last, 0);
    }
    (status, cursor as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A firmware of a few variables, in order.
    struct Store {
        variables: Vec<(&'static str, u8, u32, Vec<u8>)>,
        /// What `GetNextVariableName` answers past the end.
        end: u64,
        /// A variable whose value cannot be read.
        broken: Option<&'static str>,
    }

    fn units(name: &str) -> Vec<u16> {
        name.encode_utf16().chain([0]).collect()
    }

    fn text(name: &[u16]) -> String {
        let end = name.iter().position(|&c| c == 0).unwrap_or(name.len());
        String::from_utf16(&name[..end]).unwrap()
    }

    impl Variables for Store {
        fn next(&mut self, name: &mut [u16; NAME_UNITS], guid: &mut [u8; 16]) -> (u64, usize) {
            let current = text(name);
            let index = if current.is_empty() {
                0
            } else {
                match self
                    .variables
                    .iter()
                    .position(|v| v.0 == current && [v.1; 16] == *guid)
                {
                    Some(at) => at + 1,
                    None => return (EFI_ERROR | 2, 0),
                }
            };
            let Some(variable) = self.variables.get(index) else {
                return (self.end, 0);
            };
            let next = units(variable.0);
            name[..next.len()].copy_from_slice(&next);
            *guid = [variable.1; 16];
            (EFI_SUCCESS, next.len() * 2)
        }

        fn get(
            &mut self,
            name: &[u16; NAME_UNITS],
            guid: &[u8; 16],
            value: &mut [u8],
        ) -> (u64, usize, Option<u32>) {
            let name = text(name);
            if self.broken == Some(name.as_str()) {
                return (EFI_ERROR | 7, 0, None);
            }
            let Some(variable) = self
                .variables
                .iter()
                .find(|v| v.0 == name && [v.1; 16] == *guid)
            else {
                return (EFI_NOT_FOUND, 0, None);
            };
            if value.len() < variable.3.len() {
                return (EFI_BUFFER_TOO_SMALL, variable.3.len(), Some(variable.2));
            }
            value[..variable.3.len()].copy_from_slice(&variable.3);
            (EFI_SUCCESS, variable.3.len(), Some(variable.2))
        }
    }

    fn store() -> Store {
        Store {
            variables: vec![
                ("Boot0000", 0xA1, 7, vec![1, 2, 3, 4, 5]),
                ("Lang", 0xB2, 3, vec![]),
                ("Timeout", 0xA1, 7, vec![9, 8]),
            ],
            end: EFI_NOT_FOUND,
            broken: None,
        }
    }

    fn u32_at(buffer: &[u8], at: usize) -> usize {
        u32::from_le_bytes(buffer[at..at + 4].try_into().unwrap()) as usize
    }

    /// The entries of a class 1 buffer: GUID byte and name.
    fn names(buffer: &[u8]) -> Vec<(u8, String)> {
        let mut out = Vec::new();
        let mut at = 0;
        loop {
            let next = u32_at(buffer, at);
            let end = if next == 0 { buffer.len() } else { at + next };
            let name: Vec<u16> = buffer[at + NAME_HEADER..end]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_le_bytes(*c))
                .collect();
            out.push((buffer[at + 4], text(&name)));
            if next == 0 {
                return out;
            }
            at += next;
        }
    }

    #[test]
    fn firmware_statuses_become_windows_statuses() {
        assert_eq!(nt_status(EFI_SUCCESS), STATUS_SUCCESS);
        assert_eq!(nt_status(1) as u32, 0xC00A_0022);
        assert_eq!(nt_status(2) as u32, 0xC000_0121);
        assert_eq!(nt_status(4), STATUS_BUFFER_TOO_SMALL);
        assert_eq!(nt_status(EFI_ERROR | 1) as u32, 0xC000_026C);
        assert_eq!(nt_status(EFI_ERROR | 2), STATUS_INVALID_PARAMETER);
        assert_eq!(nt_status(EFI_ERROR | 3), STATUS_NOT_SUPPORTED);
        assert_eq!(nt_status(EFI_ERROR | 4) as u32, 0xC000_0206);
        assert_eq!(nt_status(EFI_BUFFER_TOO_SMALL), STATUS_BUFFER_TOO_SMALL);
        assert_eq!(nt_status(EFI_ERROR | 6), STATUS_DEVICE_NOT_READY);
        assert_eq!(nt_status(EFI_ERROR | 7) as u32, 0xC000_0185);
        assert_eq!(nt_status(EFI_ERROR | 8) as u32, 0xC000_00A2);
        assert_eq!(nt_status(EFI_ERROR | 9) as u32, 0xC000_0454);
        assert_eq!(nt_status(EFI_ERROR | 11) as u32, 0xC000_007F);
        assert_eq!(nt_status(EFI_ERROR | 12) as u32, 0xC000_0178);
        assert_eq!(nt_status(EFI_ERROR | 13) as u32, 0x8000_001C);
        assert_eq!(nt_status(EFI_NOT_FOUND), STATUS_VARIABLE_NOT_FOUND);
        assert_eq!(nt_status(EFI_ERROR | 15), STATUS_ACCESS_DENIED);
        assert_eq!(nt_status(EFI_ERROR | 17) as u32, 0xC000_0088);
        assert_eq!(nt_status(EFI_ERROR | 18) as u32, 0xC000_00B5);
        assert_eq!(nt_status(EFI_ERROR | 20) as u32, 0x8000_0011);
        assert_eq!(nt_status(EFI_ERROR | 21) as u32, 0xC000_0240);
        assert_eq!(nt_status(EFI_ERROR | 22) as u32, 0xC000_0186);
        assert_eq!(nt_status(EFI_ERROR | 25), STATUS_REVISION_MISMATCH);
        assert_eq!(nt_status(EFI_ERROR | 26), STATUS_ACCESS_DENIED);
        assert_eq!(nt_status(EFI_ERROR | 27) as u32, 0xC000_003F);
        // Not in the table: an error past its end, a warning past its
        // end, a status with stray bits.
        assert_eq!(nt_status(EFI_ERROR | 28), STATUS_UNSUCCESSFUL);
        assert_eq!(nt_status(EFI_ERROR), STATUS_UNSUCCESSFUL);
        assert_eq!(nt_status(3), STATUS_UNSUCCESSFUL);
        assert_eq!(nt_status(5), STATUS_UNSUCCESSFUL);
    }

    #[test]
    fn names_are_listed_one_entry_after_another() {
        // 0x14 + 18, pad to 0x28; 0x14 + 10 = 0x1E, pad 2; 0x14 + 16.
        let needed = 0x28 + 0x20 + 0x24;
        let mut buffer = vec![0xEE; needed];
        assert_eq!(
            enumerate(&mut store(), CLASS_NAMES, &mut buffer),
            (STATUS_SUCCESS, needed as u32)
        );
        assert_eq!(
            names(&buffer),
            [
                (0xA1, "Boot0000".into()),
                (0xB2, "Lang".into()),
                (0xA1, "Timeout".into())
            ]
        );
        // Entries start at multiples of four; the padding between is
        // the caller's.
        assert_eq!((u32_at(&buffer, 0), u32_at(&buffer, 0x28)), (0x28, 0x20));
        assert_eq!(&buffer[0x26..0x28], [0xEE; 2]);

        // Too small by one byte: what fitted whole, and the size.
        let mut short = vec![0xEE; needed - 1];
        assert_eq!(
            enumerate(&mut store(), CLASS_NAMES, &mut short),
            (STATUS_BUFFER_TOO_SMALL, needed as u32)
        );
        assert_eq!(
            names(&short),
            [(0xA1, "Boot0000".into()), (0xB2, "Lang".into())]
        );
        assert_eq!(&short[0x48..], vec![0xEE; needed - 1 - 0x48]);
        // Room for the first entry and one byte of its alignment padding,
        // not the full padding before the second entry.
        let mut pad_short = vec![0xEE; 0x27];
        assert_eq!(
            enumerate(&mut store(), CLASS_NAMES, &mut pad_short),
            (STATUS_BUFFER_TOO_SMALL, needed as u32)
        );
        assert_eq!(names(&pad_short[..0x26]), [(0xA1, "Boot0000".into())]);
        // No buffer at all asks for the size.
        assert_eq!(
            enumerate(&mut store(), CLASS_NAMES, &mut []),
            (STATUS_BUFFER_TOO_SMALL, needed as u32)
        );
        // No variables: nothing is needed and nothing written.
        let mut empty = Store {
            variables: vec![],
            ..store()
        };
        let mut untouched = [0xEE; 8];
        assert_eq!(
            enumerate(&mut empty, CLASS_NAMES, &mut untouched),
            (STATUS_SUCCESS, 0)
        );
        assert_eq!(untouched, [0xEE; 8]);
    }

    #[test]
    fn values_follow_their_names() {
        // Entry: 0x20 + name, padded to four, then the value.
        // Boot0000: 0x20 + 18 -> 0x34, value 5 -> 0x39, next at 0x3C.
        // Lang: 0x20 + 10 -> 0x2C, value 0 -> next at 0x68.
        // Timeout: 0x20 + 16 = 0x30, value 2.
        let needed = 0x3C + 0x2C + 0x30 + 2;
        let mut buffer = vec![0xEE; needed];
        assert_eq!(
            enumerate(&mut store(), CLASS_VALUES, &mut buffer),
            (STATUS_SUCCESS, needed as u32)
        );
        let entry = |at: usize| {
            (
                u32_at(&buffer, at),
                u32_at(&buffer, at + 4),
                u32_at(&buffer, at + 8),
                u32_at(&buffer, at + 0xC),
                buffer[at + 0x10],
            )
        };
        assert_eq!(entry(0), (0x3C, 0x34, 5, 7, 0xA1));
        assert_eq!(&buffer[0x34..0x39], [1, 2, 3, 4, 5]);
        assert_eq!(entry(0x3C), (0x2C, 0x2C, 0, 3, 0xB2));
        assert_eq!(entry(0x68), (0, 0x30, 2, 7, 0xA1));
        assert_eq!(&buffer[0x98..0x9A], [9, 8]);

        // Room for the first name but not its value: nothing fits, and
        // the size is still worked out.
        let mut short = vec![0xEE; 0x36];
        assert_eq!(
            enumerate(&mut store(), CLASS_VALUES, &mut short),
            (STATUS_BUFFER_TOO_SMALL, needed as u32)
        );
        // Room for the first entry alone.
        let mut one = vec![0xEE; 0x3C + 0x10];
        assert_eq!(
            enumerate(&mut store(), CLASS_VALUES, &mut one),
            (STATUS_BUFFER_TOO_SMALL, needed as u32)
        );
        assert_eq!((u32_at(&one, 0), u32_at(&one, 8)), (0, 5));
        assert_eq!(&one[0x34..0x39], [1, 2, 3, 4, 5]);
    }

    #[test]
    fn a_firmware_that_fails_ends_the_enumeration() {
        // The list ends with an error that is not "no more".
        let mut failing = Store {
            end: EFI_ERROR | 7,
            ..store()
        };
        let mut buffer = vec![0; 0x200];
        assert_eq!(
            enumerate(&mut failing, CLASS_NAMES, &mut buffer).0,
            STATUS_UNSUCCESSFUL
        );
        assert_eq!(names(&buffer).len(), 3);
        // A value that cannot be read: what came before it stands.
        let mut broken = Store {
            broken: Some("Lang"),
            ..store()
        };
        let (status, length) = enumerate(&mut broken, CLASS_VALUES, &mut buffer);
        assert_eq!((status, length), (STATUS_UNSUCCESSFUL, 0x3C));
        assert_eq!(u32_at(&buffer, 0), 0);
    }
}
