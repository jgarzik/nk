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
use nk_ntabi::status::{NTSTATUS, STATUS_SUCCESS};

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
