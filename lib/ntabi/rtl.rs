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

const _: () = {
    assert!(size_of::<STRING>() == 0x10);
    assert!(offset_of!(STRING, MaximumLength) == 2);
    assert!(offset_of!(STRING, Buffer) == 8);
};
