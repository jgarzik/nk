//! What `ZwQuerySystemInformation` and `RtlQueryModuleInformation` fill
//! in. The kernel-mode headers of the WDK declare none of these; the
//! layouts are the public ones of `winternl.h` and of the auxiliary
//! kernel library (`aux_klib.h`), and what the pinned kernel's code
//! writes.

use core::ffi::c_void;

/// `SYSTEM_INFORMATION_CLASS`: the classes NK answers.
pub const SYSTEM_BASIC_INFORMATION_CLASS: u32 = 0;
pub const SYSTEM_MODULE_INFORMATION_CLASS: u32 = 11;
pub const SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS: u32 = 35;
pub const SYSTEM_ISOLATED_USER_MODE_INFORMATION_CLASS: u32 = 165;

/// `SYSTEM_BASIC_INFORMATION`.
#[repr(C)]
pub struct SYSTEM_BASIC_INFORMATION {
    pub Reserved: u32,
    pub TimerResolution: u32,
    pub PageSize: u32,
    pub NumberOfPhysicalPages: u32,
    pub LowestPhysicalPageNumber: u32,
    pub HighestPhysicalPageNumber: u32,
    pub AllocationGranularity: u32,
    pub MinimumUserModeAddress: usize,
    pub MaximumUserModeAddress: usize,
    pub ActiveProcessorsAffinityMask: usize,
    pub NumberOfProcessors: i8,
}

/// `SYSTEM_KERNEL_DEBUGGER_INFORMATION`.
#[repr(C)]
pub struct SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    pub KernelDebuggerEnabled: u8,
    pub KernelDebuggerNotPresent: u8,
}

/// The size of `SYSTEM_ISOLATED_USER_MODE_INFORMATION`: bits about the
/// secure kernel, then spare bytes.
pub const SYSTEM_ISOLATED_USER_MODE_INFORMATION_SIZE: usize = 0x10;

/// The length of a module's path in the two structures below.
pub const MODULE_PATH_LENGTH: usize = 256;

/// `RTL_PROCESS_MODULE_INFORMATION`: one loaded image, as class 11
/// reports it. The array of them follows a count
/// ([`RTL_PROCESS_MODULES_HEADER`] bytes in).
#[repr(C)]
pub struct RTL_PROCESS_MODULE_INFORMATION {
    pub Section: *mut c_void,
    pub MappedBase: *mut c_void,
    pub ImageBase: *mut c_void,
    pub ImageSize: u32,
    pub Flags: u32,
    pub LoadOrderIndex: u16,
    pub InitOrderIndex: u16,
    pub LoadCount: u16,
    pub OffsetToFileName: u16,
    pub FullPathName: [u8; MODULE_PATH_LENGTH],
}

/// Where the modules begin in `RTL_PROCESS_MODULES`: after the count
/// and its padding.
pub const RTL_PROCESS_MODULES_HEADER: usize = 8;

/// `AUX_MODULE_EXTENDED_INFO`: one loaded image, as
/// `RtlQueryModuleInformation` reports it. `AUX_MODULE_BASIC_INFO` is
/// its first field alone.
#[repr(C)]
pub struct AUX_MODULE_EXTENDED_INFO {
    pub ImageBase: *mut c_void,
    pub ImageSize: u32,
    pub FileNameOffset: u16,
    pub FullPathName: [u8; MODULE_PATH_LENGTH],
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<SYSTEM_BASIC_INFORMATION>() == 0x40);
    assert!(offset_of!(SYSTEM_BASIC_INFORMATION, AllocationGranularity) == 0x18);
    assert!(offset_of!(SYSTEM_BASIC_INFORMATION, MinimumUserModeAddress) == 0x20);
    assert!(offset_of!(SYSTEM_BASIC_INFORMATION, NumberOfProcessors) == 0x38);
    assert!(size_of::<SYSTEM_KERNEL_DEBUGGER_INFORMATION>() == 2);
    assert!(size_of::<RTL_PROCESS_MODULE_INFORMATION>() == 0x128);
    assert!(offset_of!(RTL_PROCESS_MODULE_INFORMATION, ImageBase) == 0x10);
    assert!(offset_of!(RTL_PROCESS_MODULE_INFORMATION, ImageSize) == 0x18);
    assert!(offset_of!(RTL_PROCESS_MODULE_INFORMATION, LoadOrderIndex) == 0x20);
    assert!(offset_of!(RTL_PROCESS_MODULE_INFORMATION, OffsetToFileName) == 0x26);
    assert!(offset_of!(RTL_PROCESS_MODULE_INFORMATION, FullPathName) == 0x28);
    assert!(size_of::<AUX_MODULE_EXTENDED_INFO>() == 0x110);
    assert!(offset_of!(AUX_MODULE_EXTENDED_INFO, ImageSize) == 0x08);
    assert!(offset_of!(AUX_MODULE_EXTENDED_INFO, FileNameOffset) == 0x0C);
    assert!(offset_of!(AUX_MODULE_EXTENDED_INFO, FullPathName) == 0x0E);
};
