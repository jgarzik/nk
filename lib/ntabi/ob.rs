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

/// `OBJECT_HEADER.Flags`: the object is permanent (`OBJ_PERMANENT`): it
/// keeps its name when its last handle closes. `ObMakeTemporaryObject`
/// clears the bit.
pub const OB_FLAG_PERMANENT_OBJECT: u8 = 0x10;

/// `OBJECT_HEADER.InfoMask`: an `OBJECT_HEADER_NAME_INFO` precedes the
/// header. Each bit of the mask stands for one optional header in front
/// of the fixed one; NK makes only this one, which then sits directly
/// before the header.
pub const OB_INFOMASK_NAME: u8 = 0x02;

/// `OBJECT_HEADER_NAME_INFO`: where a named object is in the namespace.
/// Private to Windows; read by `ObQueryNameString` and by Microsoft's
/// own binaries. The x86-64 layout is checked against the kernel's
/// symbols.
#[repr(C)]
pub struct OBJECT_HEADER_NAME_INFO {
    /// The directory object holding the name; null once the object has
    /// lost its name.
    pub Directory: *mut c_void,
    /// The name within that directory: the path's last component.
    pub Name: crate::io::UNICODE_STRING,
    pub ReferenceCount: i32,
    pub Reserved: u32,
}

/// Size of `OBJECT_DIRECTORY`, a directory object's body.
pub const OBJECT_DIRECTORY_SIZE: usize = 0x158;

/// `OBJECT_SYMBOLIC_LINK`: a symbolic-link object's body.
#[repr(C)]
pub struct OBJECT_SYMBOLIC_LINK {
    pub CreationTime: i64,
    /// Where the link leads. (A union with a callback and its context,
    /// for links the kernel resolves in code.)
    pub LinkTarget: crate::io::UNICODE_STRING,
    pub DosDeviceDriveIndex: u32,
    pub Flags: u32,
    pub AccessMask: u32,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<OBJECT_HEADER_NAME_INFO>() == 0x20);
    assert!(offset_of!(OBJECT_HEADER_NAME_INFO, Name) == 0x08);
    assert!(offset_of!(OBJECT_HEADER_NAME_INFO, ReferenceCount) == 0x18);
    assert!(size_of::<OBJECT_SYMBOLIC_LINK>() == 0x28);
    assert!(offset_of!(OBJECT_SYMBOLIC_LINK, LinkTarget) == 0x08);
    assert!(offset_of!(OBJECT_SYMBOLIC_LINK, DosDeviceDriveIndex) == 0x18);
    assert!(offset_of!(OBJECT_SYMBOLIC_LINK, AccessMask) == 0x20);
    // A name-info header in front keeps the header 16-byte aligned.
    assert!(size_of::<OBJECT_HEADER_NAME_INFO>() % 16 == 0);
};

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

/// `GENERIC_MAPPING`: the specific rights each generic right stands for.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GENERIC_MAPPING {
    pub GenericRead: u32,
    pub GenericWrite: u32,
    pub GenericExecute: u32,
    pub GenericAll: u32,
}

/// What an object's type does with a body nothing refers to any more.
pub type OB_DELETE_METHOD = unsafe extern "C" fn(object: *mut c_void);

/// What an object's type does when a handle to an object is closed:
/// the process whose handle it was, the object, and how many handles
/// that process and the whole system had to it before this one went.
pub type OB_CLOSE_METHOD = unsafe extern "C" fn(
    process: *mut c_void,
    object: *mut c_void,
    process_handle_count: usize,
    system_handle_count: usize,
);

/// `OBJECT_TYPE_INITIALIZER`: what a type is made from, kept inside it.
/// Private to Windows, but handed to `ObCreateObjectType` and read back
/// by Microsoft's own drivers, so it has Windows' layout (x86-64: checked
/// against the kernel's symbols; arm64: the same, by NK's choice).
#[repr(C)]
pub struct OBJECT_TYPE_INITIALIZER {
    pub Length: u16,
    pub ObjectTypeFlags: u16,
    pub ObjectTypeCode: u32,
    pub InvalidAttributes: u32,
    pub GenericMapping: GENERIC_MAPPING,
    pub ValidAccessMask: u32,
    pub RetainAccess: u32,
    pub PoolType: i32,
    pub DefaultPagedPoolCharge: u32,
    pub DefaultNonPagedPoolCharge: u32,
    pub DumpProcedure: *mut c_void,
    pub OpenProcedure: *mut c_void,
    pub CloseProcedure: Option<OB_CLOSE_METHOD>,
    pub DeleteProcedure: Option<OB_DELETE_METHOD>,
    pub ParseProcedure: *mut c_void,
    pub SecurityProcedure: *mut c_void,
    pub QueryNameProcedure: *mut c_void,
    pub OkayToCloseProcedure: *mut c_void,
    pub WaitObjectFlagMask: u32,
    pub WaitObjectFlagOffset: u16,
    pub WaitObjectPointerOffset: u16,
}

/// `OBJECT_TYPE`: a kind of object. A driver holds its address (the
/// value of `*ExEventObjectType`).
#[repr(C)]
pub struct OBJECT_TYPE {
    pub TypeList: crate::ke::LIST_ENTRY,
    pub Name: crate::io::UNICODE_STRING,
    pub DefaultObject: *mut c_void,
    pub Index: u8,
    pub TotalNumberOfObjects: u32,
    pub TotalNumberOfHandles: u32,
    pub HighWaterNumberOfObjects: u32,
    pub HighWaterNumberOfHandles: u32,
    pub TypeInfo: OBJECT_TYPE_INITIALIZER,
    pub TypeLock: usize,
    pub Key: u32,
    pub CallbackList: crate::ke::LIST_ENTRY,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<OBJECT_TYPE_INITIALIZER>() == 0x78);
    assert!(offset_of!(OBJECT_TYPE_INITIALIZER, GenericMapping) == 0xC);
    assert!(offset_of!(OBJECT_TYPE_INITIALIZER, ValidAccessMask) == 0x1C);
    assert!(offset_of!(OBJECT_TYPE_INITIALIZER, PoolType) == 0x24);
    assert!(offset_of!(OBJECT_TYPE_INITIALIZER, OpenProcedure) == 0x38);
    assert!(offset_of!(OBJECT_TYPE_INITIALIZER, DeleteProcedure) == 0x48);
    assert!(offset_of!(OBJECT_TYPE_INITIALIZER, ParseProcedure) == 0x50);
    assert!(offset_of!(OBJECT_TYPE_INITIALIZER, OkayToCloseProcedure) == 0x68);
    assert!(size_of::<OBJECT_TYPE>() == 0xD8);
    assert!(offset_of!(OBJECT_TYPE, Name) == 0x10);
    assert!(offset_of!(OBJECT_TYPE, Index) == 0x28);
    assert!(offset_of!(OBJECT_TYPE, TypeInfo) == 0x40);
    assert!(offset_of!(OBJECT_TYPE, CallbackList) == 0xC8);
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

/// The handle by which the System process itself names entry `index`
/// of its table: the kernel handle without the kernel bits. The
/// kernel's handle table is that process's own, as on Windows, so both
/// handles name one entry.
pub const fn process_handle(index: usize) -> u64 {
    (index as u64 + 1) << 2
}

/// The table entry `handle` names for a caller in the System process.
/// A kernel handle is one only for kernel mode: for user mode it is a
/// number like any other, too large to be an entry. Anything else is a
/// handle of the process's own. The low two bits are ignored.
pub const fn handle_index(handle: u64, kernel_mode: bool) -> Option<usize> {
    if handle & KERNEL_HANDLE == KERNEL_HANDLE {
        return if kernel_mode {
            kernel_handle_index(handle)
        } else {
            None
        };
    }
    match handle >> 2 {
        0 => None,
        n => Some((n - 1) as usize),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_process_handle_names_the_entry_its_kernel_handle_names() {
        for index in [0, 1, 2, 1000] {
            let (kernel, own) = (kernel_handle(index), process_handle(index));
            assert_eq!(own, kernel & !KERNEL_HANDLE);
            assert!((own as i64) > 0 && own % 4 == 0);
            assert_eq!(handle_index(kernel, true), Some(index));
            assert_eq!(handle_index(own, true), Some(index));
            assert_eq!(handle_index(own | 3, false), Some(index));
            assert_eq!(
                handle_index(kernel, false),
                None,
                "no handle at all for user mode"
            );
        }
        assert_eq!(handle_index(0, true), None);
        assert_eq!(handle_index(3, false), None);
        // Not sign-extended: a process handle far past any table.
        assert_eq!(handle_index(0x0000_0000_8000_0004, true), Some(0x2000_0000));
    }

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
