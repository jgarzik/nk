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

/// `EVENT_INFO_CLASS`: what `EtwSetInformation` sets. The two a
/// kernel-mode provider may set.
pub const EVENT_PROVIDER_SET_TRAITS: u32 = 2;
pub const EVENT_PROVIDER_USE_DESCRIPTOR_TYPE: u32 = 3;

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<GUID>() == 16);
    assert!(size_of::<EVENT_DESCRIPTOR>() == 16);
    assert!(offset_of!(EVENT_DESCRIPTOR, Task) == 6);
    assert!(offset_of!(EVENT_DESCRIPTOR, Keyword) == 8);
    assert!(size_of::<EVENT_DATA_DESCRIPTOR>() == 16);
    assert!(offset_of!(EVENT_DATA_DESCRIPTOR, Size) == 8);
};
