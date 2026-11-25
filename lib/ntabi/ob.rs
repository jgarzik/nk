//! Object-manager facts a binary can see: the header in front of every
//! object the object manager allocates, and what a kernel handle looks
//! like.

use core::ffi::c_void;

/// `OBJECT_HEADER`, up to where the object itself (`Body`) begins. The
/// x86-64 layout is checked against the public symbols of the pinned
/// kernel build (`pdb.rs`).
#[repr(C)]
pub struct OBJECT_HEADER {
    pub PointerCount: i64,
    pub HandleCount: i64,
    pub Lock: usize,
    pub TypeIndex: u8,
    pub TraceFlags: u8,
    pub InfoMask: u8,
    pub Flags: u8,
    pub Reserved: u32,
    pub ObjectCreateInfo: *mut c_void,
    pub SecurityDescriptor: *mut c_void,
}

/// [`OBJECT_ATTRIBUTES`](https://learn.microsoft.com/en-us/windows/win32/api/ntdef/ns-ntdef-_object_attributes):
/// how a caller names the object it wants opened or created.
#[repr(C)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: *mut c_void,
    pub ObjectName: *const crate::io::UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: *mut c_void,
    pub SecurityQualityOfService: *mut c_void,
}

const _: () = {
    assert!(core::mem::size_of::<OBJECT_ATTRIBUTES>() == 48);
    assert!(core::mem::offset_of!(OBJECT_ATTRIBUTES, RootDirectory) == 8);
    assert!(core::mem::offset_of!(OBJECT_ATTRIBUTES, ObjectName) == 16);
    assert!(core::mem::offset_of!(OBJECT_ATTRIBUTES, Attributes) == 24);
};

/// Where the object begins, from the start of its header.
pub const OBJECT_BODY: usize = 0x30;

const _: () = assert!(core::mem::size_of::<OBJECT_HEADER>() == OBJECT_BODY);

/// The bits every kernel handle has set. A driver may test them
/// (`ObIsKernelHandle`), so they are as on Windows.
pub const KERNEL_HANDLE: u64 = 0xFFFF_FFFF_8000_0000;

/// The handle for entry `index` of the kernel handle table. Handles are
/// multiples of four, and none is zero.
pub const fn kernel_handle(index: usize) -> u64 {
    KERNEL_HANDLE | (index as u64 + 1) << 2
}

/// The table entry `handle` names, if it is a kernel handle. The low two
/// bits of a handle are ignored, as on Windows.
pub const fn kernel_handle_index(handle: u64) -> Option<usize> {
    if handle & KERNEL_HANDLE != KERNEL_HANDLE {
        return None;
    }
    match (handle & !KERNEL_HANDLE) >> 2 {
        0 => None,
        n => Some(n as usize - 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_handles_round_trip() {
        assert_eq!(kernel_handle(0), 0xFFFF_FFFF_8000_0004);
        assert_eq!(kernel_handle(1), 0xFFFF_FFFF_8000_0008);
        for index in [0, 1, 2, 1000, 0x1F_FFFF] {
            assert_eq!(kernel_handle_index(kernel_handle(index)), Some(index));
            // The low bits carry nothing.
            assert_eq!(kernel_handle_index(kernel_handle(index) | 3), Some(index));
        }
    }

    #[test]
    fn what_is_not_a_kernel_handle() {
        assert_eq!(kernel_handle_index(0), None);
        assert_eq!(kernel_handle_index(4), None, "a user handle");
        assert_eq!(
            kernel_handle_index(KERNEL_HANDLE),
            None,
            "entry zero does not exist"
        );
        assert_eq!(kernel_handle_index(KERNEL_HANDLE | 3), None);
        assert_eq!(
            kernel_handle_index(0x0000_0000_8000_0004),
            None,
            "not sign-extended"
        );
        assert_eq!(kernel_handle_index(u64::MAX), Some(0x1FFF_FFFE));
    }
}
