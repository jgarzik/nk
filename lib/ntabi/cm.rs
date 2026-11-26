//! Registry facts a binary can see: the query table of
//! `RtlQueryRegistryValues` and what its `RelativeTo` argument means.
//!
//! The information structures of `ZwQueryKey` and its relatives are not
//! here: they are variable-length byte layouts, which `nk_cm` writes.

use crate::status::NTSTATUS;
use core::ffi::c_void;

/// [`RTL_QUERY_REGISTRY_ROUTINE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-rtl_query_registry_routine):
/// a driver's routine, called with a value's name, type, data and
/// length, the caller's context and the entry's.
pub type RTL_QUERY_REGISTRY_ROUTINE = unsafe extern "C" fn(
    ValueName: *mut u16,
    ValueType: u32,
    ValueData: *mut c_void,
    ValueLength: u32,
    Context: *mut c_void,
    EntryContext: *mut c_void,
) -> NTSTATUS;

/// [`RTL_QUERY_REGISTRY_TABLE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_rtl_query_registry_table):
/// one entry of a query table. The table ends at an entry whose
/// `QueryRoutine` and `Name` are both null.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RTL_QUERY_REGISTRY_TABLE {
    pub QueryRoutine: Option<RTL_QUERY_REGISTRY_ROUTINE>,
    pub Flags: u32,
    pub Name: *mut u16,
    pub EntryContext: *mut c_void,
    pub DefaultType: u32,
    pub DefaultData: *mut c_void,
    pub DefaultLength: u32,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<RTL_QUERY_REGISTRY_TABLE>() == 0x38);
    assert!(offset_of!(RTL_QUERY_REGISTRY_TABLE, QueryRoutine) == 0x00);
    assert!(offset_of!(RTL_QUERY_REGISTRY_TABLE, Flags) == 0x08);
    assert!(offset_of!(RTL_QUERY_REGISTRY_TABLE, Name) == 0x10);
    assert!(offset_of!(RTL_QUERY_REGISTRY_TABLE, EntryContext) == 0x18);
    assert!(offset_of!(RTL_QUERY_REGISTRY_TABLE, DefaultType) == 0x20);
    assert!(offset_of!(RTL_QUERY_REGISTRY_TABLE, DefaultData) == 0x28);
    assert!(offset_of!(RTL_QUERY_REGISTRY_TABLE, DefaultLength) == 0x30);
};

/// `RelativeTo`: what the path of a query is relative to.
pub const RTL_REGISTRY_ABSOLUTE: u32 = 0;
pub const RTL_REGISTRY_SERVICES: u32 = 1;
pub const RTL_REGISTRY_CONTROL: u32 = 2;
pub const RTL_REGISTRY_WINDOWS_NT: u32 = 3;
pub const RTL_REGISTRY_DEVICEMAP: u32 = 4;
pub const RTL_REGISTRY_USER: u32 = 5;
/// The path is not a path but a key handle.
pub const RTL_REGISTRY_HANDLE: u32 = 0x4000_0000;
/// The key is optional.
pub const RTL_REGISTRY_OPTIONAL: u32 = 0x8000_0000;

/// Value types.
pub const REG_NONE: u32 = 0;
pub const REG_SZ: u32 = 1;
pub const REG_EXPAND_SZ: u32 = 2;
pub const REG_MULTI_SZ: u32 = 7;
