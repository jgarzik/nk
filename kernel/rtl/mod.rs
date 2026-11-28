//! Runtime-library exports. The logic is in `lib/rtl`.

#![allow(non_snake_case)]

pub mod avl;
pub mod bitmap;
pub mod counted;
pub mod crt;
pub mod feature;
pub mod gen83;
pub mod image;
pub mod name;
pub mod nls;
pub mod oem;
pub mod once;
pub mod persist;
pub mod prefix;
pub mod print;
pub mod range;
pub mod resource;
pub mod splay;
pub mod string;

use nk_ntabi::io::{RTL_OSVERSIONINFOEXW, UNICODE_STRING};
use nk_ntabi::status::{
    NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_REVISION_MISMATCH, STATUS_SUCCESS,
};

/// Copy a driver's counted string out of its memory.
///
/// # Safety
/// `us` must be null or point to a `UNICODE_STRING` whose buffer holds
/// `Length` bytes.
pub unsafe fn copy_unicode(us: *const UNICODE_STRING) -> alloc::vec::Vec<u16> {
    let mut out = alloc::vec::Vec::new();
    if us.is_null() {
        return out;
    }
    // SAFETY: per the contract, the header is readable and the buffer
    // holds `Length / 2` units. Drivers may pack strings, so read unaligned.
    unsafe {
        let (buf, len) = ((*us).Buffer, usize::from((*us).Length) / 2);
        if !buf.is_null() {
            out.extend((0..len).map(|i| buf.add(i).read_unaligned()));
        }
    }
    out
}

/// [`RtlCheckPortableOperatingSystem`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlcheckportableoperatingsystem):
/// whether the system started as a portable (Windows To Go) workspace,
/// which the control set's `PortableOperatingSystem` value says. Without
/// it, not.
///
/// # Safety
/// `portable` is writable.
pub unsafe extern "system" fn RtlCheckPortableOperatingSystem(portable: *mut u8) -> NTSTATUS {
    let set = matches!(
        crate::cm::read(
            "Machine\\System\\CurrentControlSet\\Control",
            "PortableOperatingSystem"
        ),
        Ok((_, data)) if data.iter().any(|&b| b != 0)
    );
    // SAFETY: per the contract.
    unsafe { portable.write(u8::from(set)) };
    STATUS_SUCCESS
}

/// `RtlInitUnicodeString`: point `destination` at the NUL-terminated
/// string `source` without copying it.
///
/// # Safety
/// `destination` must be writable; `source` must be null or NUL terminated.
pub unsafe extern "C" fn RtlInitUnicodeString(
    destination: *mut UNICODE_STRING,
    source: *const u16,
) {
    let mut chars = 0;
    if !source.is_null() {
        // The scan stops at the longest length the function can report.
        while chars < nk_rtl::MAX_INIT_LENGTH / 2 {
            // SAFETY: the caller guarantees a terminator, and every unit
            // before it is readable.
            if unsafe { source.add(chars).read_unaligned() } == 0 {
                break;
            }
            chars += 1;
        }
    }
    let (length, maximum) = if source.is_null() {
        (0, 0)
    } else {
        nk_rtl::init_unicode_lengths(chars)
    };
    // SAFETY: the caller guarantees `destination` is writable.
    unsafe {
        destination.write_unaligned(UNICODE_STRING {
            Length: length,
            MaximumLength: maximum,
            Buffer: source.cast_mut(),
        });
    }
}

/// The Windows version NK presents: 10.0, build 19045, the build its
/// reference machine runs.
pub const VERSION: (u32, u32, u32) = (10, 0, 19045);

/// [`RtlGetVersion`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetversion).
/// Fills in as much of the structure as its size field says is there.
///
/// # Safety
/// `info` points to an `RTL_OSVERSIONINFOW` or `RTL_OSVERSIONINFOEXW`
/// whose size field says which.
pub unsafe extern "C" fn RtlGetVersion(info: *mut RTL_OSVERSIONINFOEXW) -> NTSTATUS {
    /// `VER_PLATFORM_WIN32_NT`.
    const PLATFORM_NT: u32 = 2;
    /// `VER_NT_WORKSTATION`.
    const WORKSTATION: u8 = 1;
    // SAFETY: per the contract.
    unsafe {
        let size = (&raw const (*info).dwOSVersionInfoSize).read();
        (&raw mut (*info).dwMajorVersion).write(VERSION.0);
        (&raw mut (*info).dwMinorVersion).write(VERSION.1);
        (&raw mut (*info).dwBuildNumber).write(VERSION.2);
        (&raw mut (*info).dwPlatformId).write(PLATFORM_NT);
        // No service pack: an empty string.
        (&raw mut (*info).szCSDVersion).cast::<u16>().write(0);
        if size as usize == size_of::<RTL_OSVERSIONINFOEXW>() {
            (&raw mut (*info).wServicePackMajor).write(0);
            (&raw mut (*info).wServicePackMinor).write(0);
            (&raw mut (*info).wSuiteMask).write(0);
            (&raw mut (*info).wProductType).write(WORKSTATION);
            (&raw mut (*info).wReserved).write(0);
        }
    }
    STATUS_SUCCESS
}

/// [`RtlNtStatusToDosErrorNoTeb`](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-rtlntstatustodoserror):
/// the Windows error code for `status`, by the pinned kernel's table
/// (`nk_rtl::doserror`).
pub extern "C" fn RtlNtStatusToDosErrorNoTeb(status: NTSTATUS) -> u32 {
    nk_rtl::doserror::dos_error(status as u32)
}

/// [`RtlNtStatusToDosError`](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-rtlntstatustodoserror):
/// the same. Windows also keeps `status` as the last status in the
/// calling thread's TEB; NK's threads have no TEB, as Windows' system
/// threads have none, and for those Windows keeps nothing either.
pub extern "C" fn RtlNtStatusToDosError(status: NTSTATUS) -> u32 {
    RtlNtStatusToDosErrorNoTeb(status)
}

/// [`RtlIsStateSeparationEnabled`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlisstateseparationenabled):
/// whether OS state separation is enabled. False on NK (and standard
/// Windows 10 desktop installations).
pub extern "C" fn RtlIsStateSeparationEnabled() -> u8 {
    0
}

/// [`RtlGetActiveConsoleId`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlgetactiveconsoleid):
/// session id of the active console session. NK has only session 0.
pub extern "C" fn RtlGetActiveConsoleId() -> u32 {
    0
}

/// [`RtlIsNtDdiVersionAvailable`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlisntddiversionavailable):
/// whether the OS supports at least the given `NTDDI_*` version.
/// Windows 10 2004–22H2 (build 19041–19045) is `NTDDI_WIN10_VB` (`0x0A00_0008`).
pub extern "C" fn RtlIsNtDdiVersionAvailable(version: u32) -> u8 {
    const NTDDI_WIN10_VB: u32 = 0x0A00_0008;
    u8::from(version <= NTDDI_WIN10_VB)
}

/// [`VerSetConditionMask`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-versetconditionmask):
/// record comparison operator `condition` (1..=7) for each version field bit
/// set in `type_mask`.
pub extern "C" fn VerSetConditionMask(
    mut condition_mask: u64,
    type_mask: u32,
    condition: u8,
) -> u64 {
    let op = u64::from(condition & 0x7);
    if type_mask == 0 {
        return condition_mask;
    }
    for bit in 0..8u32 {
        if type_mask & (1 << bit) != 0 {
            let shift = bit * 3;
            condition_mask = (condition_mask & !(0x7u64 << shift)) | (op << shift);
        }
    }
    condition_mask
}

/// Compare `actual` against `asked` under Windows' `VER_*` condition code.
fn version_matches(actual: u32, asked: u32, condition: u8) -> bool {
    match condition {
        1 => actual == asked, // VER_EQUAL
        2 => actual > asked,  // VER_GREATER
        3 => actual >= asked, // VER_GREATER_EQUAL
        4 => actual < asked,  // VER_LESS
        5 => actual <= asked, // VER_LESS_EQUAL
        _ => false,
    }
}

/// [`RtlVerifyVersionInfo`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlverifyversioninfo):
/// compare `version_info` against NK's reported Windows 10.0.19045 Workstation
/// version using the operators encoded in `condition_mask`.
///
/// # Safety
/// `version_info` points to a readable `RTL_OSVERSIONINFOEXW`.
pub unsafe extern "C" fn RtlVerifyVersionInfo(
    version_info: *const RTL_OSVERSIONINFOEXW,
    type_mask: u32,
    condition_mask: u64,
) -> NTSTATUS {
    if version_info.is_null() || type_mask == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: checked non-null; per the contract.
    let info = unsafe { version_info.read_unaligned() };
    let cond = |bit: u32| ((condition_mask >> (bit * 3)) & 0x7) as u8;
    // Hierarchical comparison for major/minor/build/SP per Microsoft docs:
    // if major/minor/SP are compared with >= or <=, a strictly greater/lesser
    // higher component satisfies lower components automatically.
    const VER_MINORVERSION: u32 = 0x01;
    const VER_MAJORVERSION: u32 = 0x02;
    const VER_BUILDNUMBER: u32 = 0x04;
    const VER_PLATFORMID: u32 = 0x08;
    const VER_SERVICEPACKMINOR: u32 = 0x10;
    const VER_SERVICEPACKMAJOR: u32 = 0x20;
    const VER_SUITENAME: u32 = 0x40;
    const VER_PRODUCT_TYPE: u32 = 0x80;

    // NK reports Windows 10.0.19045, Platform 2 (NT), SP 0.0, ProductType 1 (Workstation).
    let actual_major = 10u32;
    let actual_minor = 0u32;
    let actual_build = 19045u32;
    let actual_platform = 2u32;
    let actual_sp_major = 0u32;
    let actual_sp_minor = 0u32;
    let actual_suite = 0u32;
    let actual_product = 1u32;

    if type_mask & VER_PLATFORMID != 0
        && !version_matches(actual_platform, info.dwPlatformId, cond(3))
    {
        return STATUS_REVISION_MISMATCH;
    }
    if type_mask & VER_PRODUCT_TYPE != 0
        && !version_matches(actual_product, u32::from(info.wProductType), cond(7))
    {
        return STATUS_REVISION_MISMATCH;
    }
    if type_mask & VER_SUITENAME != 0 {
        let asked = u32::from(info.wSuiteMask);
        let ok = match cond(6) {
            6 => (actual_suite & asked) == asked, // VER_AND
            7 => (actual_suite & asked) != 0,     // VER_OR
            other => version_matches(actual_suite, asked, other),
        };
        if !ok {
            return STATUS_REVISION_MISMATCH;
        }
    }
    // Version tuple comparison (major, minor, sp_major, sp_minor, build).
    let mut decided = false;
    for (mask, bit, actual, asked) in [
        (VER_MAJORVERSION, 1, actual_major, info.dwMajorVersion),
        (VER_MINORVERSION, 0, actual_minor, info.dwMinorVersion),
        (
            VER_SERVICEPACKMAJOR,
            5,
            actual_sp_major,
            u32::from(info.wServicePackMajor),
        ),
        (
            VER_SERVICEPACKMINOR,
            4,
            actual_sp_minor,
            u32::from(info.wServicePackMinor),
        ),
        (VER_BUILDNUMBER, 2, actual_build, info.dwBuildNumber),
    ] {
        if type_mask & mask == 0 || decided {
            continue;
        }
        let op = cond(bit);
        if !version_matches(actual, asked, op) {
            return STATUS_REVISION_MISMATCH;
        }
        if actual != asked && matches!(op, 2..=5) {
            decided = true;
        }
    }
    STATUS_SUCCESS
}

/// The room `RtlDeriveCapabilitySidsFromName` clears in its callers'
/// buffers: a SID of nine and of ten sub-authorities.
const GROUP_SID_ROOM: usize = 0x2C;
const CAPABILITY_SID_ROOM: usize = 0x30;

/// `RtlDeriveCapabilitySidsFromName` (exported, not documented): the
/// group SID and the capability SID of the capability named `name`
/// (`nk_se::capability`), written into the caller's buffers. A missing
/// argument is a fast fail, as on Windows.
///
/// # Safety
/// `name` is a counted string; the buffers are writable for a SID of
/// nine and of ten sub-authorities.
pub unsafe extern "C" fn RtlDeriveCapabilitySidsFromName(
    name: *const UNICODE_STRING,
    group_sid: *mut u8,
    capability_sid: *mut u8,
) -> NTSTATUS {
    if name.is_null() || group_sid.is_null() || capability_sid.is_null() {
        crate::kd::bugcheck(format_args!(
            "0x00000139 KERNEL_SECURITY_CHECK_FAILURE: RtlDeriveCapabilitySidsFromName was given no buffer (parameter 1 0x0000000000000005)"
        ));
    }
    // SAFETY: per the contract.
    let upper: alloc::vec::Vec<u16> = unsafe { copy_unicode(name) }
        .into_iter()
        .map(nk_rtl::upcase::upcase_char)
        .collect();
    let (group, capability) = nk_se::capability::derive(&upper);
    // SAFETY: per the contract; each SID fits the room it is given.
    unsafe {
        group_sid.write_bytes(0, GROUP_SID_ROOM);
        capability_sid.write_bytes(0, CAPABILITY_SID_ROOM);
        group_sid.copy_from_nonoverlapping(group.as_ptr(), group.len());
        capability_sid.copy_from_nonoverlapping(capability.as_ptr(), capability.len());
    }
    STATUS_SUCCESS
}
