//! Runtime-library structures a driver can see.

use core::mem::{offset_of, size_of};

/// [`STRING`](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-string),
/// under its other names `ANSI_STRING` and `OEM_STRING`: a counted
/// string of bytes. Lengths are in bytes; a terminator is not required.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u8,
}

pub type ANSI_STRING = STRING;

/// [`GUID`](https://learn.microsoft.com/en-us/windows/win32/api/guiddef/ns-guiddef-guid).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GUID {
    pub Data1: u32,
    pub Data2: u16,
    pub Data3: u16,
    pub Data4: [u8; 8],
}

const _: () = {
    assert!(size_of::<GUID>() == 0x10);
    assert!(offset_of!(GUID, Data2) == 4);
    assert!(offset_of!(GUID, Data3) == 6);
    assert!(offset_of!(GUID, Data4) == 8);
    assert!(size_of::<STRING>() == 0x10);
    assert!(offset_of!(STRING, MaximumLength) == 2);
    assert!(offset_of!(STRING, Buffer) == 8);
};
