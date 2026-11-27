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

/// [`TIME_FIELDS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_time_fields).
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct TIME_FIELDS {
    pub Year: i16,
    pub Month: i16,
    pub Day: i16,
    pub Hour: i16,
    pub Minute: i16,
    pub Second: i16,
    pub Milliseconds: i16,
    pub Weekday: i16,
}

/// [`RTL_BITMAP`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitializebitmap):
/// the header of a bitmap. The buffer is the caller's, a whole number
/// of `ULONG`s.
#[repr(C)]
pub struct RTL_BITMAP {
    /// In bits.
    pub SizeOfBitMap: u32,
    pub Buffer: *mut u32,
}

/// `RTL_RANGE_LIST` (`ntddk.h` of the Windows 2000 DDK): the header of
/// a range list. The entries its list holds are the kernel's.
#[repr(C)]
pub struct RTL_RANGE_LIST {
    pub ListHead: crate::ke::LIST_ENTRY,
    pub Flags: u32,
    /// How many ranges the list holds.
    pub Count: u32,
    /// Changes whenever the list does; an iterator is good for one
    /// value of it.
    pub Stamp: u32,
}

/// `RTL_RANGE`: one range of a list, as the iterator hands it out.
#[repr(C)]
pub struct RTL_RANGE {
    pub Start: u64,
    /// The last address of the range.
    pub End: u64,
    pub UserData: *mut core::ffi::c_void,
    pub Owner: *mut core::ffi::c_void,
    pub Attributes: u8,
    /// `RTL_RANGE_SHARED`, `RTL_RANGE_CONFLICT`.
    pub Flags: u8,
}

/// `RTL_RANGE_LIST_ITERATOR`: a place in a range list.
#[repr(C)]
pub struct RTL_RANGE_LIST_ITERATOR {
    pub RangeListHead: *mut crate::ke::LIST_ENTRY,
    pub MergedHead: *mut crate::ke::LIST_ENTRY,
    pub Current: *mut core::ffi::c_void,
    pub Stamp: u32,
}

/// [`RTL_SPLAY_LINKS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_rtl_splay_links):
/// a node's place in a binary tree. A root is its own parent.
#[repr(C)]
pub struct RTL_SPLAY_LINKS {
    pub Parent: *mut RTL_SPLAY_LINKS,
    pub LeftChild: *mut RTL_SPLAY_LINKS,
    pub RightChild: *mut RTL_SPLAY_LINKS,
}

/// `RTL_BALANCED_LINKS` (`ntddk.h`): a node's place in an
/// [AVL table](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinitializegenerictableavl).
/// The caller's element follows it in the same allocation.
#[repr(C)]
pub struct RTL_BALANCED_LINKS {
    pub Parent: *mut RTL_BALANCED_LINKS,
    pub LeftChild: *mut RTL_BALANCED_LINKS,
    pub RightChild: *mut RTL_BALANCED_LINKS,
    /// The height of the right subtree less that of the left: -1, 0, 1.
    pub Balance: i8,
    pub Reserved: [u8; 3],
}

/// `RTL_AVL_TABLE` (`ntddk.h`): the header of an AVL table, which the
/// driver owns. `BalancedRoot` is the tree's sentinel: its own parent,
/// with the root as its right child.
#[repr(C)]
pub struct RTL_AVL_TABLE {
    pub BalancedRoot: RTL_BALANCED_LINKS,
    pub OrderedPointer: *mut core::ffi::c_void,
    pub WhichOrderedElement: u32,
    pub NumberGenericTableElements: u32,
    pub DepthOfTree: u32,
    pub RestartKey: *mut RTL_BALANCED_LINKS,
    pub DeleteCount: u32,
    pub CompareRoutine: Option<AvlCompare>,
    pub AllocateRoutine: Option<AvlAllocate>,
    pub FreeRoutine: Option<AvlFree>,
    pub TableContext: *mut core::ffi::c_void,
}

/// `RTL_AVL_COMPARE_ROUTINE`: `GenericLessThan` (0), `GenericGreaterThan`
/// (1) or `GenericEqual` (2), of the first element against the second.
pub type AvlCompare = unsafe extern "system" fn(
    *mut RTL_AVL_TABLE,
    *mut core::ffi::c_void,
    *mut core::ffi::c_void,
) -> u32;
/// `RTL_AVL_ALLOCATE_ROUTINE`.
pub type AvlAllocate = unsafe extern "system" fn(*mut RTL_AVL_TABLE, u32) -> *mut core::ffi::c_void;
/// `RTL_AVL_FREE_ROUTINE`.
pub type AvlFree = unsafe extern "system" fn(*mut RTL_AVL_TABLE, *mut core::ffi::c_void);

/// `RTL_GENERIC_COMPARE_RESULTS`.
pub const GENERIC_LESS_THAN: u32 = 0;
pub const GENERIC_GREATER_THAN: u32 = 1;
pub const GENERIC_EQUAL: u32 = 2;

/// `UNICODE_PREFIX_TABLE_ENTRY` (`ntifs.h`): one name of a
/// [prefix table](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinsertunicodeprefix).
/// The driver allocates it; the prefix routines fill it in.
#[repr(C)]
pub struct UNICODE_PREFIX_TABLE_ENTRY {
    pub NodeTypeCode: i16,
    /// The number of components in the name.
    pub NameLength: i16,
    pub NextPrefixTree: *mut UNICODE_PREFIX_TABLE_ENTRY,
    pub CaseMatch: *mut UNICODE_PREFIX_TABLE_ENTRY,
    pub Links: RTL_SPLAY_LINKS,
    /// The caller's name: pointed to, not copied.
    pub Prefix: *mut crate::io::UNICODE_STRING,
}

/// `UNICODE_PREFIX_TABLE` (`ntifs.h`). Its first three fields are an
/// entry's: the list of trees ends at the table.
#[repr(C)]
pub struct UNICODE_PREFIX_TABLE {
    pub NodeTypeCode: i16,
    pub NameLength: i16,
    pub NextPrefixTree: *mut UNICODE_PREFIX_TABLE_ENTRY,
    pub LastNextEntry: *mut UNICODE_PREFIX_TABLE_ENTRY,
}

const _: () = {
    assert!(size_of::<TIME_FIELDS>() == 0x10);
    assert!(offset_of!(TIME_FIELDS, Weekday) == 0xE);
    assert!(size_of::<RTL_RANGE_LIST>() == 0x20);
    assert!(offset_of!(RTL_RANGE_LIST, Flags) == 0x10);
    assert!(offset_of!(RTL_RANGE_LIST, Count) == 0x14);
    assert!(offset_of!(RTL_RANGE_LIST, Stamp) == 0x18);
    assert!(size_of::<RTL_RANGE>() == 0x28);
    assert!(offset_of!(RTL_RANGE, End) == 8);
    assert!(offset_of!(RTL_RANGE, UserData) == 0x10);
    assert!(offset_of!(RTL_RANGE, Owner) == 0x18);
    assert!(offset_of!(RTL_RANGE, Attributes) == 0x20);
    assert!(offset_of!(RTL_RANGE, Flags) == 0x21);
    assert!(size_of::<RTL_RANGE_LIST_ITERATOR>() == 0x20);
    assert!(offset_of!(RTL_RANGE_LIST_ITERATOR, MergedHead) == 8);
    assert!(offset_of!(RTL_RANGE_LIST_ITERATOR, Current) == 0x10);
    assert!(offset_of!(RTL_RANGE_LIST_ITERATOR, Stamp) == 0x18);
    assert!(size_of::<RTL_BITMAP>() == 0x10);
    assert!(offset_of!(RTL_BITMAP, Buffer) == 8);
    assert!(size_of::<RTL_SPLAY_LINKS>() == 0x18);
    assert!(size_of::<RTL_BALANCED_LINKS>() == 0x20);
    assert!(offset_of!(RTL_BALANCED_LINKS, Balance) == 0x18);
    assert!(size_of::<RTL_AVL_TABLE>() == 0x68);
    assert!(offset_of!(RTL_AVL_TABLE, OrderedPointer) == 0x20);
    assert!(offset_of!(RTL_AVL_TABLE, WhichOrderedElement) == 0x28);
    assert!(offset_of!(RTL_AVL_TABLE, NumberGenericTableElements) == 0x2C);
    assert!(offset_of!(RTL_AVL_TABLE, DepthOfTree) == 0x30);
    assert!(offset_of!(RTL_AVL_TABLE, RestartKey) == 0x38);
    assert!(offset_of!(RTL_AVL_TABLE, DeleteCount) == 0x40);
    assert!(offset_of!(RTL_AVL_TABLE, CompareRoutine) == 0x48);
    assert!(offset_of!(RTL_AVL_TABLE, AllocateRoutine) == 0x50);
    assert!(offset_of!(RTL_AVL_TABLE, FreeRoutine) == 0x58);
    assert!(offset_of!(RTL_AVL_TABLE, TableContext) == 0x60);
    assert!(offset_of!(RTL_SPLAY_LINKS, LeftChild) == 8);
    assert!(offset_of!(RTL_SPLAY_LINKS, RightChild) == 0x10);
    assert!(size_of::<UNICODE_PREFIX_TABLE_ENTRY>() == 0x38);
    assert!(offset_of!(UNICODE_PREFIX_TABLE_ENTRY, NameLength) == 2);
    assert!(offset_of!(UNICODE_PREFIX_TABLE_ENTRY, NextPrefixTree) == 8);
    assert!(offset_of!(UNICODE_PREFIX_TABLE_ENTRY, CaseMatch) == 0x10);
    assert!(offset_of!(UNICODE_PREFIX_TABLE_ENTRY, Links) == 0x18);
    assert!(offset_of!(UNICODE_PREFIX_TABLE_ENTRY, Prefix) == 0x30);
    assert!(size_of::<UNICODE_PREFIX_TABLE>() == 0x18);
    // The table doubles as the entry that ends the list of trees.
    assert!(
        offset_of!(UNICODE_PREFIX_TABLE, NodeTypeCode)
            == offset_of!(UNICODE_PREFIX_TABLE_ENTRY, NodeTypeCode)
    );
    assert!(
        offset_of!(UNICODE_PREFIX_TABLE, NameLength)
            == offset_of!(UNICODE_PREFIX_TABLE_ENTRY, NameLength)
    );
    assert!(
        offset_of!(UNICODE_PREFIX_TABLE, NextPrefixTree)
            == offset_of!(UNICODE_PREFIX_TABLE_ENTRY, NextPrefixTree)
    );
    assert!(offset_of!(UNICODE_PREFIX_TABLE, LastNextEntry) == 0x10);
    assert!(size_of::<GUID>() == 0x10);
    assert!(offset_of!(GUID, Data2) == 4);
    assert!(offset_of!(GUID, Data3) == 6);
    assert!(offset_of!(GUID, Data4) == 8);
    assert!(size_of::<STRING>() == 0x10);
    assert!(offset_of!(STRING, MaximumLength) == 2);
    assert!(offset_of!(STRING, Buffer) == 8);
};
