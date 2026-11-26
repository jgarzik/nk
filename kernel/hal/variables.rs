//! Firmware environment variables, through UEFI's variable services:
//! `NtGetEnvironmentVariableEx`, `NtQueryEnvironmentVariableInfoEx`,
//! `HalEnumerateEnvironmentVariablesEx`, `HalSetEnvironmentVariableEx`.
//! `pshed.dll` keeps hardware error records there.
//!
//! Each is what the pinned kernel's HAL makes of the firmware service
//! (`nk_hal::variables` has the status mapping and the enumeration
//! buffer). The firmware is called as for a shutdown
//! (`hal::firmware_call`), with the caller's own buffers: firmware
//! runs in the kernel's address space. UEFI's runtime services are
//! not to be entered twice at once, so one lock is held across each
//! call; Windows keeps to the boot processor instead.
//!
//! On Windows the two `Nt` routines are for kernel-mode callers only
//! (`STATUS_PRIVILEGE_NOT_HELD` for any other): NK's exports have no
//! other callers.

#![allow(non_snake_case)]

use super::{EFI_RUNTIME, firmware_call};
use crate::ke::{Rank, SpinLock};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::Ordering;
use nk_hal::variables::{self as rules, NAME_UNITS, Variables};
use nk_ntabi::status::*;

/// Held across each call into the firmware's variable services.
static FIRMWARE: SpinLock<()> = SpinLock::new(Rank::FirmwareVariables, ());

/// Offsets in `EFI_RUNTIME_SERVICES`: its header's revision and size,
/// and the four services.
const REVISION: u64 = 8;
const HEADER_SIZE: u64 = 12;
const GET_VARIABLE: u64 = 0x48;
const GET_NEXT_VARIABLE_NAME: u64 = 0x50;
const SET_VARIABLE: u64 = 0x58;
const QUERY_VARIABLE_INFO: u64 = 0x80;
/// The first revision of the table that has `QueryVariableInfo`: 2.0.
const REVISION_2_0: u32 = 0x0002_0000;

type Guid = [u8; 16];
type GetVariable =
    unsafe extern "efiapi" fn(*const u16, *const Guid, *mut u32, *mut usize, *mut c_void) -> u64;
type GetNextVariableName = unsafe extern "efiapi" fn(*mut usize, *mut u16, *mut Guid) -> u64;
type SetVariable =
    unsafe extern "efiapi" fn(*const u16, *const Guid, u32, usize, *const c_void) -> u64;
type QueryVariableInfo = unsafe extern "efiapi" fn(u32, *mut u64, *mut u64, *mut u64) -> u64;

/// The address of the service at `offset` of the firmware's runtime
/// services table, if there is a table and it has the service.
fn service(offset: u64) -> Option<usize> {
    let table = EFI_RUNTIME.load(Ordering::Relaxed);
    if table == 0 {
        return None;
    }
    // SAFETY: firmware's runtime services table, identity mapped and
    // valid for the life of the system; its header says how far it
    // goes.
    unsafe {
        let size = u64::from(((table + HEADER_SIZE) as *const u32).read());
        let revision = ((table + REVISION) as *const u32).read();
        if offset + 8 > size || (offset == QUERY_VARIABLE_INFO && revision < REVISION_2_0) {
            return None;
        }
        let address = ((table + offset) as *const usize).read();
        (address != 0).then_some(address)
    }
}

/// Whether the machine has UEFI runtime services at all: without,
/// every routine here is `STATUS_NOT_IMPLEMENTED`, as on a machine
/// Windows did not start from UEFI.
fn has_firmware() -> bool {
    EFI_RUNTIME.load(Ordering::Relaxed) != 0
}

/// Call a variable service: one call at a time.
fn call<R>(service: impl FnOnce() -> R) -> R {
    let _one_at_a_time = FIRMWARE.lock();
    firmware_call(service)
}

/// The name at `name`, as the HAL passes it to firmware: copied, and
/// terminated. A name that does not fit the HAL's buffer reaches
/// firmware empty, as the pinned kernel's bounded copy leaves it.
///
/// # Safety
/// `name` points to 16-bit units that end with a zero.
unsafe fn name_of(name: *const u16) -> [u16; NAME_UNITS] {
    let mut copy = [0u16; NAME_UNITS];
    for (index, slot) in copy.iter_mut().enumerate() {
        // SAFETY: per the contract, every unit up to the zero is
        // readable.
        let unit = unsafe { name.add(index).read_unaligned() };
        if unit == 0 {
            return copy;
        }
        *slot = unit;
    }
    [0; NAME_UNITS]
}

/// `GetVariable`: the firmware's status as Windows', and the size and
/// attributes it left.
///
/// # Safety
/// `value` is writable for `size` bytes.
unsafe fn get(
    name: &[u16; NAME_UNITS],
    guid: &Guid,
    value: *mut c_void,
    mut size: usize,
) -> (u64, usize, Option<u32>) {
    let Some(address) = service(GET_VARIABLE) else {
        return (u64::MAX, size, None);
    };
    const UNWRITTEN: u32 = 0xDEAD_BEEF;
    let mut attributes = UNWRITTEN;
    // SAFETY: the firmware's own routine, of that signature; the
    // pointers are to locals and, per the contract, the caller's
    // buffer.
    let status = call(|| unsafe {
        let get: GetVariable = core::mem::transmute(address);
        get(
            name.as_ptr(),
            guid,
            &raw mut attributes,
            &raw mut size,
            value,
        )
    });
    (
        status,
        size,
        (attributes != UNWRITTEN).then_some(attributes),
    )
}

/// `SetVariable`.
///
/// # Safety
/// `value` is readable for `size` bytes.
unsafe fn set(
    name: &[u16; NAME_UNITS],
    guid: &Guid,
    attributes: u32,
    size: usize,
    value: *const c_void,
) -> NTSTATUS {
    let Some(address) = service(SET_VARIABLE) else {
        return STATUS_NOT_IMPLEMENTED;
    };
    // SAFETY: the firmware's own routine, of that signature; per the
    // contract for the value.
    rules::nt_status(call(|| unsafe {
        let set: SetVariable = core::mem::transmute(address);
        set(name.as_ptr(), guid, attributes, size, value)
    }))
}

/// `NtGetEnvironmentVariableEx`: read the firmware variable `name` of
/// vendor `vendor_guid` into `value`. `value_length` is the buffer's
/// size and is given the variable's (with `STATUS_BUFFER_TOO_SMALL`,
/// the size needed); `attributes`, if asked for, the variable's.
/// A variable that is not there is `STATUS_VARIABLE_NOT_FOUND`; every
/// other firmware status has the pinned kernel's translation.
///
/// When firmware does not say the attributes, they are written as
/// `0xDEADBEEF`, as the pinned kernel's `IoGetEnvironmentVariableEx`
/// leaves them.
///
/// # Safety
/// `name` is a terminated string; `vendor_guid` is readable;
/// `value_length` is readable and writable, and `value` writable for
/// as many bytes as it says; `attributes` is null or writable.
pub unsafe extern "C" fn NtGetEnvironmentVariableEx(
    name: *const u16,
    vendor_guid: *const Guid,
    value: *mut c_void,
    value_length: *mut u32,
    attributes: *mut u32,
) -> NTSTATUS {
    if !has_firmware() {
        return STATUS_NOT_IMPLEMENTED;
    }
    // SAFETY: per the contract.
    unsafe {
        let name = name_of(name);
        let guid = vendor_guid.read_unaligned();
        let room = value_length.read_unaligned() as usize;
        let (status, size, found) = get(&name, &guid, value, room);
        value_length.write_unaligned(size as u32);
        if !attributes.is_null() {
            attributes.write_unaligned(found.unwrap_or(0xDEAD_BEEF));
        }
        if status == u64::MAX {
            return STATUS_NOT_IMPLEMENTED;
        }
        rules::nt_status(status)
    }
}

/// `NtQueryEnvironmentVariableInfoEx`: how much room the firmware has
/// for variables of the given attributes (`QueryVariableInfo`): in
/// all, left, and for one variable. The attributes must say
/// non-volatile (`STATUS_INVALID_PARAMETER`); Windows adds the two
/// access bits. Firmware older than UEFI 2.0 has no such service:
/// `STATUS_NOT_IMPLEMENTED`.
///
/// # Safety
/// The three pointers are writable.
pub unsafe extern "C" fn NtQueryEnvironmentVariableInfoEx(
    attributes: u32,
    maximum_storage: *mut u64,
    remaining_storage: *mut u64,
    maximum_variable_size: *mut u64,
) -> NTSTATUS {
    if !has_firmware() {
        return STATUS_NOT_IMPLEMENTED;
    }
    if attributes & rules::VARIABLE_NON_VOLATILE == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let Some(address) = service(QUERY_VARIABLE_INFO) else {
        return STATUS_NOT_IMPLEMENTED;
    };
    let attributes =
        attributes | rules::VARIABLE_BOOTSERVICE_ACCESS | rules::VARIABLE_RUNTIME_ACCESS;
    // SAFETY: the firmware's own routine, of that signature; per the
    // contract for the three pointers.
    rules::nt_status(call(|| unsafe {
        let query: QueryVariableInfo = core::mem::transmute(address);
        query(
            attributes,
            maximum_storage,
            remaining_storage,
            maximum_variable_size,
        )
    }))
}

/// The firmware, for an enumeration.
struct Firmware {
    next: usize,
}

impl Variables for Firmware {
    fn next(&mut self, name: &mut [u16; NAME_UNITS], guid: &mut Guid) -> (u64, usize) {
        let mut size = NAME_UNITS * 2;
        // SAFETY: the firmware's own routine, of that signature; the
        // name's buffer is as large as `size` says.
        let status = call(|| unsafe {
            let next: GetNextVariableName = core::mem::transmute(self.next);
            next(&raw mut size, name.as_mut_ptr(), guid)
        });
        (status, size)
    }

    fn get(
        &mut self,
        name: &[u16; NAME_UNITS],
        guid: &Guid,
        value: &mut [u8],
    ) -> (u64, usize, Option<u32>) {
        let to = if value.is_empty() {
            core::ptr::null_mut()
        } else {
            value.as_mut_ptr().cast()
        };
        // SAFETY: the kernel's own buffer, of that length.
        unsafe { get(name, guid, to, value.len()) }
    }
}

/// `HalEnumerateEnvironmentVariablesEx`: every firmware variable, as
/// a list of `VARIABLE_NAME` (class 1) or `VARIABLE_NAME_AND_VALUE`
/// (class 2) in `buffer`, which must start at a multiple of four.
/// `buffer_length` is the buffer's size and is given the bytes used,
/// or with `STATUS_BUFFER_TOO_SMALL` the bytes needed. The layout and
/// the statuses are the pinned kernel's (`nk_hal::variables`).
///
/// The list is built in memory of the kernel's and copied out, so the
/// bytes between entries keep the caller's values, as on Windows.
/// Without memory for that copy the call fails with
/// `STATUS_INSUFFICIENT_RESOURCES`, which is NK's own.
///
/// # Safety
/// `buffer_length` is readable and writable, and `buffer` readable
/// and writable for as many bytes as it says.
pub unsafe extern "C" fn HalEnumerateEnvironmentVariablesEx(
    information_class: u32,
    buffer: *mut u8,
    buffer_length: *mut u32,
) -> NTSTATUS {
    let (Some(next), Some(_)) = (service(GET_NEXT_VARIABLE_NAME), service(GET_VARIABLE)) else {
        return STATUS_NOT_IMPLEMENTED;
    };
    if !matches!(information_class, rules::CLASS_NAMES | rules::CLASS_VALUES)
        || !buffer.addr().is_multiple_of(4)
    {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract; the caller's memory is copied in and
    // out, and no reference to it is ever made.
    unsafe {
        let length = buffer_length.read_unaligned() as usize;
        let mut copy: Vec<u8> = Vec::new();
        if copy.try_reserve_exact(length).is_err() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if length != 0 {
            core::ptr::copy_nonoverlapping(buffer.cast_const(), copy.as_mut_ptr(), length);
            copy.set_len(length);
        }
        let (status, used) = rules::enumerate(&mut Firmware { next }, information_class, &mut copy);
        if length != 0 {
            core::ptr::copy_nonoverlapping(copy.as_ptr(), buffer, length);
        }
        buffer_length.write_unaligned(used);
        status
    }
}

/// `HalSetEnvironmentVariableEx`: write the firmware variable `name`
/// of vendor `vendor_guid`, or with no value delete it. The attributes
/// must say non-volatile (`STATUS_INVALID_PARAMETER`); Windows adds
/// the two access bits. As the pinned kernel does it: unless the
/// value is to be appended, the variable is deleted first; then, if
/// there is a value, it is written, and the status is that write's.
/// With no value the status is the deletion's
/// (`STATUS_VARIABLE_NOT_FOUND` if there was none), or
/// `STATUS_INVALID_PARAMETER` if appending was asked for.
///
/// # Safety
/// `name` is a terminated string; `vendor_guid` is readable; `value`
/// is readable for `value_length` bytes.
pub unsafe extern "C" fn HalSetEnvironmentVariableEx(
    name: *const u16,
    vendor_guid: *const Guid,
    value: *const c_void,
    value_length: u32,
    attributes: u32,
) -> NTSTATUS {
    if !has_firmware() {
        return STATUS_NOT_IMPLEMENTED;
    }
    if attributes & rules::VARIABLE_NON_VOLATILE == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let attributes =
        attributes | rules::VARIABLE_BOOTSERVICE_ACCESS | rules::VARIABLE_RUNTIME_ACCESS;
    // SAFETY: per the contract.
    unsafe {
        let name = name_of(name);
        let guid = vendor_guid.read_unaligned();
        let mut status = if attributes & rules::VARIABLE_APPEND_WRITE == 0 {
            set(&name, &guid, 0, 0, core::ptr::null())
        } else {
            STATUS_INVALID_PARAMETER
        };
        if value_length != 0 {
            status = set(&name, &guid, attributes, value_length as usize, value);
        }
        status
    }
}

// ---- tests --------------------------------------------------------------

/// A variable of the test's own is written, read, found in both
/// kinds of enumeration and deleted, through the four exports, on the
/// machine's real firmware. Returns the calls made.
pub fn test() -> Result<u32, &'static str> {
    static GUID: Guid = *b"NK-test-variable";
    const VALUE: [u8; 5] = [0x4E, 0x4B, 1, 2, 3];
    const ALL: u32 = 7;
    let name: Vec<u16> = "NkSelfTest".encode_utf16().chain([0]).collect();
    let read = |room: u32| {
        let mut value = [0xEEu8; 16];
        let (mut length, mut attributes) = (room, 0x5A5A);
        // SAFETY: locals that outlive the call; `room` is no more than
        // the buffer.
        let status = unsafe {
            NtGetEnvironmentVariableEx(
                name.as_ptr(),
                &raw const GUID,
                value.as_mut_ptr().cast(),
                &raw mut length,
                &raw mut attributes,
            )
        };
        (status, length, attributes, value)
    };
    let write = |value: &[u8], attributes: u32| {
        // SAFETY: locals that outlive the call.
        unsafe {
            HalSetEnvironmentVariableEx(
                name.as_ptr(),
                &raw const GUID,
                value.as_ptr().cast(),
                value.len() as u32,
                attributes,
            )
        }
    };
    // The list of class `class` in a buffer of `words` 32-bit words
    // (so aligned): the status, the length, and the list.
    let list = |class: u32, words: usize| -> Option<(NTSTATUS, u32, Vec<u32>)> {
        let mut buffer: Vec<u32> = Vec::new();
        buffer.try_reserve_exact(words).ok()?;
        buffer.resize(words, 0xEEEE_EEEE);
        let mut length = (words * 4) as u32;
        // SAFETY: a buffer of that many bytes, and a local.
        let status = unsafe {
            HalEnumerateEnvironmentVariablesEx(class, buffer.as_mut_ptr().cast(), &raw mut length)
        };
        Some((status, length, buffer))
    };
    // Where the test's variable is in a list: the offset of its entry.
    let find = |class: u32, list: &[u32]| -> Option<usize> {
        let bytes: Vec<u8> = list.iter().flat_map(|word| word.to_le_bytes()).collect();
        let header = if class == 1 { 0x14 } else { 0x20 };
        let wanted: Vec<u8> = name.iter().flat_map(|unit| unit.to_le_bytes()).collect();
        let mut at = 0;
        loop {
            let entry = bytes.get(at..)?;
            let next = u32::from_le_bytes(entry.get(..4)?.try_into().ok()?) as usize;
            if entry.get(header - 16..header)? == GUID
                && entry.get(header..header + wanted.len())? == wanted
            {
                return Some(at);
            }
            if next == 0 {
                return None;
            }
            at += next;
        }
    };

    // What cannot be asked.
    let (mut total, mut left, mut one) = (0u64, 0u64, 0u64);
    // SAFETY: three locals.
    let (info, refused) = unsafe {
        (
            NtQueryEnvironmentVariableInfoEx(1, &raw mut total, &raw mut left, &raw mut one),
            NtQueryEnvironmentVariableInfoEx(6, &raw mut total, &raw mut left, &raw mut one),
        )
    };
    if info != STATUS_SUCCESS || total == 0 || left > total || one == 0 {
        return Err("the firmware's room for variables was not reported");
    }
    if refused != STATUS_INVALID_PARAMETER || write(&VALUE, 6) != STATUS_INVALID_PARAMETER {
        return Err("a variable that is not non-volatile was not refused");
    }
    let mut misaligned = [0u32; 8];
    let mut length = 16u32;
    // SAFETY: locals; the buffer's address is off by one on purpose,
    // and is refused before it is used.
    let bad = unsafe {
        [
            HalEnumerateEnvironmentVariablesEx(3, misaligned.as_mut_ptr().cast(), &raw mut length),
            HalEnumerateEnvironmentVariablesEx(0, misaligned.as_mut_ptr().cast(), &raw mut length),
            HalEnumerateEnvironmentVariablesEx(
                1,
                misaligned.as_mut_ptr().cast::<u8>().add(1),
                &raw mut length,
            ),
        ]
    };
    if bad != [STATUS_INVALID_PARAMETER; 3] || length != 16 {
        return Err("an enumeration of no known kind, or into a misaligned buffer, was made");
    }

    // Not there yet (a run that died may have left it: delete first).
    let _ = write(&[], 1);
    if read(16) != (STATUS_VARIABLE_NOT_FOUND, 16, 0xDEAD_BEEF, [0xEE; 16])
        || write(&[], 1) != STATUS_VARIABLE_NOT_FOUND
    {
        return Err("a variable that is not there was found, or deleted");
    }
    if write(&VALUE, 1) != STATUS_SUCCESS {
        return Err("a variable could not be written");
    }
    let verdict = (|| {
        let (status, length, attributes, value) = read(16);
        if (status, length, attributes) != (STATUS_SUCCESS, 5, ALL) || value[..5] != VALUE {
            return Err("a variable written was not read back with its attributes");
        }
        let (status, length, _, value) = read(2);
        if (status, length) != (STATUS_BUFFER_TOO_SMALL, 5) || value != [0xEE; 16] {
            return Err("a buffer too small for a variable was not told the size needed");
        }
        for class in [1, 2] {
            let (status, needed, _) = list(class, 0).ok_or("no memory")?;
            if status != STATUS_BUFFER_TOO_SMALL || needed == 0 {
                return Err("an enumeration into no buffer did not say the size needed");
            }
            let words = (needed as usize).div_ceil(4) + 16;
            let (status, used, entries) = list(class, words).ok_or("no memory")?;
            if status != STATUS_SUCCESS || used != needed {
                return Err("an enumeration did not fill a buffer of the size it asked for");
            }
            let at = find(class, &entries).ok_or("the variable written is not in the list")?;
            if class == 2 {
                let entry = &entries[at / 4..];
                let (offset, length, attributes) = (entry[1] as usize, entry[2], entry[3]);
                let bytes: Vec<u8> = entry.iter().flat_map(|word| word.to_le_bytes()).collect();
                if (length, attributes) != (5, ALL) || bytes.get(offset..offset + 5) != Some(&VALUE)
                {
                    return Err("the list does not hold the variable's value and attributes");
                }
            }
            // One byte short: the size again, and not our business
            // what fitted.
            let (status, again, _) = list(class, (needed as usize - 1) / 4).ok_or("no memory")?;
            if status != STATUS_BUFFER_TOO_SMALL || again != needed {
                return Err("a buffer too small for the list was not told the size needed");
            }
        }
        // Written again, it is replaced.
        if write(&[9], 1) != STATUS_SUCCESS || read(16).1 != 1 {
            return Err("a variable written again was not replaced");
        }
        Ok(())
    })();
    let deleted = write(&[], 1);
    verdict?;
    if deleted != STATUS_SUCCESS || read(16).0 != STATUS_VARIABLE_NOT_FOUND {
        return Err("a variable was not deleted");
    }
    let (status, _, entries) = list(1, 4096).ok_or("no memory")?;
    if nt_success(status) && find(1, &entries).is_some() {
        return Err("a deleted variable is still in the list");
    }
    Ok(24)
}
