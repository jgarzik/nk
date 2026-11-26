//! What a trace provider hands the kernel: event descriptors, and the
//! WMI structures of `wmistr.h`. Layouts are the WDK's (`evntprov.h`,
//! `wmistr.h`).

use core::ffi::c_void;

/// `GUID`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GUID {
    pub Data1: u32,
    pub Data2: u16,
    pub Data3: u16,
    pub Data4: [u8; 8],
}

/// `REGHANDLE`: what `EtwRegister` gives a provider to write with.
pub type REGHANDLE = u64;

/// [`EVENT_DESCRIPTOR`](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_descriptor).
#[repr(C)]
pub struct EVENT_DESCRIPTOR {
    pub Id: u16,
    pub Version: u8,
    pub Channel: u8,
    pub Level: u8,
    pub Opcode: u8,
    pub Task: u16,
    pub Keyword: u64,
}

/// [`EVENT_DATA_DESCRIPTOR`](https://learn.microsoft.com/en-us/windows/win32/api/evntprov/ns-evntprov-event_data_descriptor):
/// one piece of an event's data.
#[repr(C)]
pub struct EVENT_DATA_DESCRIPTOR {
    pub Ptr: u64,
    pub Size: u32,
    pub Reserved: u32,
}

/// `PETWENABLECALLBACK`: source, control code, level, the two keyword
/// masks, filter data, the provider's context.
pub type ETW_ENABLE_CALLBACK =
    unsafe extern "C" fn(*const GUID, u32, u8, u64, u64, *mut c_void, *mut c_void);

/// The enable callback of a classic provider
/// (`EtwRegisterClassicProvider`): the provider's GUID, a control code,
/// the enabling session's handle with level and flags, the provider's
/// context.
pub type ETW_CLASSIC_CALLBACK = unsafe extern "C" fn(*const GUID, u8, *mut c_void, *mut c_void);

/// `EVENT_INFO_CLASS`: what `EtwSetInformation` sets. The two a
/// kernel-mode provider may set.
pub const EVENT_PROVIDER_SET_TRAITS: u32 = 2;
pub const EVENT_PROVIDER_USE_DESCRIPTOR_TYPE: u32 = 3;

/// [`WNODE_HEADER`](https://learn.microsoft.com/en-us/windows/win32/etw/wnode-header):
/// what every block of WMI data begins with, an event a driver fires
/// included.
#[repr(C)]
pub struct WNODE_HEADER {
    pub BufferSize: u32,
    pub ProviderId: u32,
    /// For a trace: the handle of the session, with level and flags.
    pub HistoricalContext: u64,
    pub TimeStamp: i64,
    pub Guid: GUID,
    pub ClientContext: u32,
    pub Flags: u32,
}

/// `WNODE_HEADER.Flags`: the block is a trace event for a session; it
/// is to be logged as well as delivered.
pub const WNODE_FLAG_TRACED_GUID: u32 = 0x0002_0000;
pub const WNODE_FLAG_LOG_WNODE: u32 = 0x0004_0000;

/// [`WMIREGGUIDW`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wmistr/ns-wmistr-wmiregguidw):
/// one data block of a driver's registration. The last field is a
/// union: here the physical device object the block's instances are
/// named after.
#[repr(C)]
pub struct WMIREGGUIDW {
    pub Guid: GUID,
    pub Flags: u32,
    pub InstanceCount: u32,
    pub Pdo: *mut c_void,
}

/// [`WMIREGINFOW`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wmistr/ns-wmistr-wmireginfow):
/// a driver's answer to a registration request. `GuidCount` entries
/// begin at `WmiRegGuid`.
#[repr(C)]
pub struct WMIREGINFOW {
    pub BufferSize: u32,
    pub NextWmiRegInfo: u32,
    pub RegistryPath: u32,
    pub MofResourceName: u32,
    pub GuidCount: u32,
    pub WmiRegGuid: [WMIREGGUIDW; 0],
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<WNODE_HEADER>() == 0x30);
    assert!(offset_of!(WNODE_HEADER, HistoricalContext) == 0x08);
    assert!(offset_of!(WNODE_HEADER, Guid) == 0x18);
    assert!(offset_of!(WNODE_HEADER, Flags) == 0x2C);
    assert!(size_of::<WMIREGGUIDW>() == 0x20);
    assert!(offset_of!(WMIREGGUIDW, Flags) == 0x10);
    assert!(offset_of!(WMIREGGUIDW, Pdo) == 0x18);
    assert!(offset_of!(WMIREGINFOW, GuidCount) == 0x10);
    assert!(offset_of!(WMIREGINFOW, WmiRegGuid) == 0x18);
    assert!(size_of::<GUID>() == 16);
    assert!(size_of::<EVENT_DESCRIPTOR>() == 16);
    assert!(offset_of!(EVENT_DESCRIPTOR, Task) == 6);
    assert!(offset_of!(EVENT_DESCRIPTOR, Keyword) == 8);
    assert!(size_of::<EVENT_DATA_DESCRIPTOR>() == 16);
    assert!(offset_of!(EVENT_DATA_DESCRIPTOR, Size) == 8);
};
