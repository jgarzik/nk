//! The Unicode prefix table. The table, its entries and the names they
//! point to are the driver's memory, laid out as `ntifs.h` declares
//! them; the algorithm is `nk_rtl::prefix`, which is handed the
//! driver's fields to read and write through raw pointers ([`Driver`]).
//! Nothing is kept here, and the caller serialises the calls on one
//! table, as on Windows.

#![allow(non_snake_case)]

use super::string::Wide;
use core::mem::offset_of;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::rtl::{RTL_SPLAY_LINKS, UNICODE_PREFIX_TABLE, UNICODE_PREFIX_TABLE_ENTRY};
use nk_rtl::prefix::{self, Nodes, Text};

impl Text for Wide {
    fn length(&self) -> usize {
        self.len()
    }
    fn unit(&self, at: usize) -> u16 {
        Wide::unit(*self, at)
    }
}

type Entry = *mut UNICODE_PREFIX_TABLE_ENTRY;

/// A driver's table. A node is the address of the table or of an
/// entry: the table's first three fields lie where an entry's do
/// (`nk_ntabi::rtl` asserts it) and are reached as an entry's.
struct Driver(*mut UNICODE_PREFIX_TABLE);

impl Driver {
    /// # Safety
    /// `table` is a prefix table, and it and every entry linked into
    /// it, with the name each points to, are valid while the result is
    /// used; so is any entry handed to the algorithm with it.
    unsafe fn of(table: *mut UNICODE_PREFIX_TABLE) -> Self {
        Self(table)
    }
}

/// The entry a link points into, if any: links point at `Links`.
fn linked(links: *mut RTL_SPLAY_LINKS) -> Option<Entry> {
    (!links.is_null()).then(|| {
        links
            .wrapping_byte_sub(offset_of!(UNICODE_PREFIX_TABLE_ENTRY, Links))
            .cast()
    })
}

/// The link that points at `entry`; null for none.
fn link(entry: Option<Entry>) -> *mut RTL_SPLAY_LINKS {
    entry.map_or(core::ptr::null_mut(), |entry| {
        entry
            .wrapping_byte_add(offset_of!(UNICODE_PREFIX_TABLE_ENTRY, Links))
            .cast()
    })
}

/// Read or write one field of a driver's entry. The entries are the
/// driver's memory: no reference is formed, and a driver may pack them,
/// so nothing assumes alignment.
macro_rules! field {
    ($node:expr, $($field:ident).+) => {
        // SAFETY: the contract of `Driver::of`, or of the export using
        // the field itself.
        unsafe { (&raw const (*$node).$($field).+).read_unaligned() }
    };
    ($node:expr, $($field:ident).+ = $value:expr) => {
        // SAFETY: as above.
        unsafe { (&raw mut (*$node).$($field).+).write_unaligned($value) }
    };
}

impl Nodes for Driver {
    type Node = Entry;
    type Name = Wide;

    fn table(&self) -> Entry {
        self.0.cast()
    }
    fn kind(&self, node: Entry) -> i16 {
        field!(node, NodeTypeCode)
    }
    fn set_kind(&mut self, node: Entry, kind: i16) {
        field!(node, NodeTypeCode = kind);
    }
    fn name_length(&self, node: Entry) -> i16 {
        field!(node, NameLength)
    }
    fn set_name_length(&mut self, node: Entry, length: i16) {
        field!(node, NameLength = length);
    }
    fn next_tree(&self, node: Entry) -> Option<Entry> {
        let next = field!(node, NextPrefixTree);
        (!next.is_null()).then_some(next)
    }
    fn set_next_tree(&mut self, node: Entry, next: Option<Entry>) {
        field!(node, NextPrefixTree = next.unwrap_or(core::ptr::null_mut()));
    }
    fn case_match(&self, entry: Entry) -> Entry {
        field!(entry, CaseMatch)
    }
    fn set_case_match(&mut self, entry: Entry, next: Entry) {
        field!(entry, CaseMatch = next);
    }
    fn parent(&self, entry: Entry) -> Entry {
        // A sound entry's parent link is never null: a root's is its
        // own.
        linked(field!(entry, Links.Parent)).unwrap_or(entry)
    }
    fn set_parent(&mut self, entry: Entry, parent: Entry) {
        field!(entry, Links.Parent = link(Some(parent)));
    }
    fn left(&self, entry: Entry) -> Option<Entry> {
        linked(field!(entry, Links.LeftChild))
    }
    fn set_left(&mut self, entry: Entry, child: Option<Entry>) {
        field!(entry, Links.LeftChild = link(child));
    }
    fn right(&self, entry: Entry) -> Option<Entry> {
        linked(field!(entry, Links.RightChild))
    }
    fn set_right(&mut self, entry: Entry, child: Option<Entry>) {
        field!(entry, Links.RightChild = link(child));
    }
    fn name(&self, entry: Entry) -> Wide {
        let name = field!(entry, Prefix);
        // SAFETY: an entry in a table points to the name it was
        // inserted under, which its owner keeps valid while it is in.
        unsafe { Wide::of(name) }
    }
    fn forget_enumeration(&mut self) {
        field!(self.0, LastNextEntry = core::ptr::null_mut());
    }
}

/// [`RtlInitializeUnicodePrefix`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitializeunicodeprefix):
/// make `table` an empty table.
///
/// # Safety
/// `table` is writable for a `UNICODE_PREFIX_TABLE`.
pub unsafe extern "C" fn RtlInitializeUnicodePrefix(table: *mut UNICODE_PREFIX_TABLE) {
    // SAFETY: per the contract; an empty table links no entry.
    prefix::initialize(&mut unsafe { Driver::of(table) });
}

/// [`RtlInsertUnicodePrefix`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinsertunicodeprefix):
/// put `entry` in the table under the name `name`, which the entry
/// points to from now on. False if that name is in the table already.
///
/// # Safety
/// `table` is an initialised table whose entries, and their names, are
/// valid; `entry` is writable and not in a table; `name` and `entry`
/// stay valid until the entry is removed.
pub unsafe extern "C" fn RtlInsertUnicodePrefix(
    table: *mut UNICODE_PREFIX_TABLE,
    name: *const UNICODE_STRING,
    entry: *mut UNICODE_PREFIX_TABLE_ENTRY,
) -> u8 {
    field!(entry, Prefix = name.cast_mut());
    // SAFETY: per the contract.
    u8::from(prefix::insert(&mut unsafe { Driver::of(table) }, entry))
}

/// [`RtlFindUnicodePrefix`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlfindunicodeprefix):
/// the entry whose name is the longest prefix of `full_name` on a
/// component boundary, or null. Characters before
/// `case_insensitive_index` must match exactly, later ones without
/// regard to case.
///
/// # Safety
/// `table` is an initialised table whose entries, and their names, are
/// valid; `full_name` points to a counted string.
pub unsafe extern "C" fn RtlFindUnicodePrefix(
    table: *mut UNICODE_PREFIX_TABLE,
    full_name: *const UNICODE_STRING,
    case_insensitive_index: u32,
) -> *mut UNICODE_PREFIX_TABLE_ENTRY {
    // SAFETY: per the contract.
    let (mut table, full_name) = unsafe { (Driver::of(table), Wide::of(full_name)) };
    prefix::find(&mut table, &full_name, case_insensitive_index as usize)
        .unwrap_or(core::ptr::null_mut())
}

/// [`RtlRemoveUnicodePrefix`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlremoveunicodeprefix):
/// take `entry` out of the table.
///
/// # Safety
/// `table` is an initialised table whose entries, and their names, are
/// valid, and `entry` is one of them.
pub unsafe extern "C" fn RtlRemoveUnicodePrefix(
    table: *mut UNICODE_PREFIX_TABLE,
    entry: *mut UNICODE_PREFIX_TABLE_ENTRY,
) {
    // SAFETY: per the contract.
    prefix::remove(&mut unsafe { Driver::of(table) }, entry);
}
