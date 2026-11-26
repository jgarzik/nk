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

/// [`RTL_SPLAY_LINKS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_rtl_splay_links):
/// a node's place in a binary tree. A root is its own parent.
#[repr(C)]
pub struct RTL_SPLAY_LINKS {
    pub Parent: *mut RTL_SPLAY_LINKS,
    pub LeftChild: *mut RTL_SPLAY_LINKS,
    pub RightChild: *mut RTL_SPLAY_LINKS,
}

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
    assert!(size_of::<RTL_SPLAY_LINKS>() == 0x18);
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
