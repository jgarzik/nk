//! `RtlGetPersistedStateLocation`: where a component keeps state that
//! must outlive a boot, after the state-separation redirection map.

use core::sync::atomic::{AtomicBool, Ordering};
use nk_ntabi::status::*;

/// The redirection maps, by location type: registry keys, files.
const MAPS: [&str; 2] = [
    "Machine\\System\\CurrentControlSet\\Control\\StateSeparation\\RedirectionMap\\Keys",
    "Machine\\System\\CurrentControlSet\\Control\\StateSeparation\\RedirectionMap\\Files",
];

/// The value a map's entry gives its target in, when the caller names
/// none.
const TARGET: &str = "TargetNtPath";

/// Set once a map has been found absent: Windows looks no more after
/// that, for either type.
static NO_MAP: AtomicBool = AtomicBool::new(false);

/// The NUL-terminated string at `s`, without its NUL.
///
/// # Safety
/// `s` is a readable NUL-terminated string.
unsafe fn wide(s: *const u16) -> alloc::vec::Vec<u16> {
    let mut out = alloc::vec::Vec::new();
    // SAFETY: per the contract, every unit up to the NUL is readable.
    unsafe {
        let mut at = s;
        while at.read_unaligned() != 0 {
            out.push(at.read_unaligned());
            at = at.add(1);
        }
    }
    out
}

/// Copy `units` and a NUL into `target` if `length` bytes hold them;
/// say how many bytes that takes.
///
/// # Safety
/// `target` is writable for `length` bytes; `needed` is null or
/// writable.
unsafe fn give(units: &[u16], target: *mut u16, length: u32, needed: *mut u32) -> NTSTATUS {
    let bytes = (units.len() as u32 + 1) * 2;
    // SAFETY: per the contract.
    unsafe {
        if !needed.is_null() {
            needed.write_unaligned(bytes);
        }
        if bytes > length {
            return STATUS_BUFFER_OVERFLOW;
        }
        for (i, &unit) in units.iter().chain(&[0]).enumerate() {
            target.add(i).write_unaligned(unit);
        }
    }
    STATUS_SUCCESS
}

/// `RtlGetPersistedStateLocation` (`wdm.h`; [Microsoft's
/// page](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetpersistedstatelocation)):
/// the path where the component `source_id` keeps its state of the kind
/// `location_type` (0 a registry key, 1 a file). Where the redirection
/// map of that kind names the component, the map's target (the value
/// `custom_value`, else `TargetNtPath`, of the component's entry, a
/// `REG_SZ`); where the map does not exist, or has no entry for it,
/// `default_path`, or `STATUS_OBJECT_NAME_NOT_FOUND` without one. A
/// buffer too small is `STATUS_BUFFER_OVERFLOW` with the length
/// needed, as the pinned kernel answers.
///
/// # Safety
/// `source_id`, and `custom_value` and `default_path` where not null,
/// are NUL-terminated strings; `target_path` is writable for
/// `buffer_length_in` bytes; `buffer_length_out` is null or writable.
pub unsafe extern "system" fn RtlGetPersistedStateLocation(
    source_id: *const u16,
    custom_value: *const u16,
    default_path: *const u16,
    location_type: u32,
    target_path: *mut u16,
    buffer_length_in: u32,
    buffer_length_out: *mut u32,
) -> NTSTATUS {
    let Some(map) = MAPS.get(location_type as usize) else {
        return STATUS_INVALID_PARAMETER_3;
    };
    if !NO_MAP.load(Ordering::Relaxed) {
        if crate::cm::exists(map) {
            // SAFETY: per the contract.
            let (source, value) = unsafe {
                let value = if custom_value.is_null() {
                    TARGET.encode_utf16().collect()
                } else {
                    wide(custom_value)
                };
                (wide(source_id), value)
            };
            let entry = alloc::format!(
                "{map}\\{}",
                alloc::string::String::from_utf16_lossy(&source)
            );
            let value = alloc::string::String::from_utf16_lossy(&value);
            match crate::cm::read(&entry, &value) {
                Ok((REG_SZ, data)) => {
                    let mut units: alloc::vec::Vec<u16> = data
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|c| u16::from_le_bytes(*c))
                        .collect();
                    if units.last() == Some(&0) {
                        units.pop();
                    }
                    // SAFETY: per the contract.
                    return unsafe {
                        give(&units, target_path, buffer_length_in, buffer_length_out)
                    };
                }
                Ok(_) => return STATUS_OBJECT_TYPE_MISMATCH,
                // No entry for the component: its default.
                Err(STATUS_OBJECT_NAME_NOT_FOUND) if !crate::cm::exists(&entry) => {}
                Err(status) => return status,
            }
        } else {
            NO_MAP.store(true, Ordering::Relaxed);
        }
    }
    if default_path.is_null() {
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    // SAFETY: per the contract.
    unsafe {
        let units = wide(default_path);
        give(&units, target_path, buffer_length_in, buffer_length_out)
    }
}

/// `REG_SZ`.
const REG_SZ: u32 = 1;
