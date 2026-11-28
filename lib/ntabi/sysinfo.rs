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

/// `SystemRegisterFirmwareTableInformationHandler`, which
/// `ZwSetSystemInformation` takes.
pub const SYSTEM_REGISTER_FIRMWARE_TABLE_INFORMATION_HANDLER_CLASS: u32 = 75;

/// `SYSTEM_FIRMWARE_TABLE_HANDLER`: a driver registers (`Register`
/// non-zero) or takes back the routine that serves the firmware tables
/// of one provider, named by a four-character signature. The layout is
/// the one `acpi.sys` builds and the pinned kernel's
/// `ExpRegisterFirmwareTableInformationHandler` reads.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SYSTEM_FIRMWARE_TABLE_HANDLER {
    pub ProviderSignature: u32,
    pub Register: u8,
    pub FirmwareTableHandler: *mut c_void,
    pub DriverObject: *mut c_void,
}

const _: () = {
    use core::mem::offset_of;
    assert!(size_of::<SYSTEM_FIRMWARE_TABLE_HANDLER>() == 0x18);
    assert!(offset_of!(SYSTEM_FIRMWARE_TABLE_HANDLER, Register) == 0x04);
    assert!(offset_of!(SYSTEM_FIRMWARE_TABLE_HANDLER, FirmwareTableHandler) == 0x08);
    assert!(offset_of!(SYSTEM_FIRMWARE_TABLE_HANDLER, DriverObject) == 0x10);
};

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

/// `SYSTEM_INFORMATION_CLASS`: the classes of
/// `NtQuerySystemInformationEx` NK answers.
pub const SYSTEM_LOGICAL_PROCESSOR_AND_GROUP_INFORMATION_CLASS: u32 = 107;
pub const SYSTEM_INTERRUPT_STEERING_INFORMATION_CLASS: u32 = 180;

/// `LOGICAL_PROCESSOR_RELATIONSHIP`: the relationships NK states.
pub const RELATION_PROCESSOR_CORE: u32 = 0;
pub const RELATION_NUMA_NODE: u32 = 1;
pub const RELATION_CACHE: u32 = 2;
pub const RELATION_PROCESSOR_PACKAGE: u32 = 3;
pub const RELATION_GROUP: u32 = 4;
pub const RELATION_ALL: u32 = 0xFFFF;

/// `SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX` for a core or a package:
/// the header and a `PROCESSOR_RELATIONSHIP` of one group.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PROCESSOR_RELATIONSHIP_ENTRY {
    pub Relationship: u32,
    pub Size: u32,
    pub Flags: u8,
    pub EfficiencyClass: u8,
    pub Reserved: [u8; 20],
    pub GroupCount: u16,
    pub GroupMask: crate::interrupt::GROUP_AFFINITY,
}

/// [`SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-system_logical_processor_information_ex)
/// for a NUMA node: the header and a `NUMA_NODE_RELATIONSHIP`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NUMA_NODE_RELATIONSHIP_ENTRY {
    pub Relationship: u32,
    pub Size: u32,
    pub NodeNumber: u32,
    pub Reserved: [u8; 20],
    pub GroupMask: crate::interrupt::GROUP_AFFINITY,
}

/// `SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX` for the processor groups:
/// the header and a `GROUP_RELATIONSHIP` of one `PROCESSOR_GROUP_INFO`.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct GROUP_RELATIONSHIP_ENTRY {
    pub Relationship: u32,
    pub Size: u32,
    pub MaximumGroupCount: u16,
    pub ActiveGroupCount: u16,
    pub Reserved: [u8; 20],
    pub MaximumProcessorCount: u8,
    pub ActiveProcessorCount: u8,
    pub Reserved2: [u8; 38],
    pub ActiveProcessorMask: usize,
}

/// `SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT`: the question of
/// class 180. The answer is a `u32` of flags, the lowest "enabled".
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT {
    pub Gsiv: u32,
    pub ControllerInterrupt: u8,
    pub EdgeInterrupt: u8,
    pub IsPrimaryInterrupt: u8,
    pub TargetAffinity: crate::interrupt::GROUP_AFFINITY,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<PROCESSOR_RELATIONSHIP_ENTRY>() == 0x30);
    assert!(offset_of!(PROCESSOR_RELATIONSHIP_ENTRY, Flags) == 0x08);
    assert!(offset_of!(PROCESSOR_RELATIONSHIP_ENTRY, EfficiencyClass) == 0x09);
    assert!(offset_of!(PROCESSOR_RELATIONSHIP_ENTRY, GroupCount) == 0x1E);
    assert!(offset_of!(PROCESSOR_RELATIONSHIP_ENTRY, GroupMask) == 0x20);
    assert!(size_of::<NUMA_NODE_RELATIONSHIP_ENTRY>() == 0x30);
    assert!(offset_of!(NUMA_NODE_RELATIONSHIP_ENTRY, NodeNumber) == 0x08);
    assert!(offset_of!(NUMA_NODE_RELATIONSHIP_ENTRY, GroupMask) == 0x20);
    assert!(size_of::<GROUP_RELATIONSHIP_ENTRY>() == 0x50);
    assert!(offset_of!(GROUP_RELATIONSHIP_ENTRY, MaximumProcessorCount) == 0x20);
    assert!(offset_of!(GROUP_RELATIONSHIP_ENTRY, ActiveProcessorMask) == 0x48);
    assert!(size_of::<SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT>() == 0x18);
    assert!(offset_of!(SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT, TargetAffinity) == 0x08);
};

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

/// `SystemEntropyInterruptTimingInformation`, which
/// `ZwSetSystemInformation` takes: a driver's routine for the times of
/// interrupts ([`SYSTEM_ENTROPY_TIMING_INFORMATION`]).
pub const SYSTEM_ENTROPY_INTERRUPT_TIMING_INFORMATION_CLASS: u32 = 0x83;

/// What class 0x83 takes, as `cng.sys` builds it and the pinned
/// kernel's `NtSetSystemInformation` reads it: the routine given each
/// full half of a processor's timing buffer, the routine run once for
/// each processor's state when it registers, and their context.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SYSTEM_ENTROPY_TIMING_INFORMATION {
    pub EntropyRoutine: *mut c_void,
    pub InitializationRoutine: *mut c_void,
    pub InitializationContext: *mut c_void,
}

const _: () = assert!(size_of::<SYSTEM_ENTROPY_TIMING_INFORMATION>() == 0x18);

/// `SystemBootEntropyInformation`: the entropy the loader gathered, for
/// `cng.sys`. Answered once, in kernel mode, into a buffer of exactly
/// [`SYSTEM_BOOT_ENTROPY_INFORMATION_SIZE`] bytes.
pub const SYSTEM_BOOT_ENTROPY_INFORMATION_CLASS: u32 = 0x75;

/// What class 0x75 returns: the head of [`BOOT_ENTROPY_LDR_RESULT`], up
/// to and including `SeedBytesForCng`. The pinned kernel's
/// `ExpQuerySystemInformation` asks for this length exactly, and
/// `cng.sys`'s `GetBootEntropy` passes it.
pub const SYSTEM_BOOT_ENTROPY_INFORMATION_SIZE: usize =
    core::mem::offset_of!(BOOT_ENTROPY_LDR_RESULT, RngBytesForNtoskrnl);

/// `BOOT_ENTROPY_SOURCE_ID`: each source of boot entropy, which is also
/// its record's place in [`BOOT_ENTROPY_LDR_RESULT::EntropySourceResult`]
/// plus one. Values from the pinned kernel's symbols.
pub const BOOT_ENTROPY_SOURCE_NONE: u32 = 0;
pub const BOOT_ENTROPY_SOURCE_SEEDFILE: u32 = 1;
pub const BOOT_ENTROPY_SOURCE_EXTERNAL: u32 = 2;
pub const BOOT_ENTROPY_SOURCE_TPM: u32 = 3;
pub const BOOT_ENTROPY_SOURCE_RDRAND: u32 = 4;
pub const BOOT_ENTROPY_SOURCE_TIME: u32 = 5;
pub const BOOT_ENTROPY_SOURCE_ACPI_OEM0: u32 = 6;
pub const BOOT_ENTROPY_SOURCE_UEFI: u32 = 7;
pub const BOOT_ENTROPY_SOURCE_CNG: u32 = 8;
pub const BOOT_ENTROPY_SOURCE_TCB_TPM: u32 = 9;
pub const BOOT_ENTROPY_SOURCE_TCB_RDRAND: u32 = 10;
/// `BootMaxEntropySources`: the number of records.
pub const BOOT_MAX_ENTROPY_SOURCES: usize = 10;

/// `BOOT_ENTROPY_SOURCE_RESULT_CODE`: what became of a source.
pub const BOOT_ENTROPY_SOURCE_STRUCTURE_UNINITIALIZED: u32 = 0;
pub const BOOT_ENTROPY_SOURCE_DISABLED_BY_POLICY: u32 = 1;
pub const BOOT_ENTROPY_SOURCE_NOT_PRESENT: u32 = 2;
pub const BOOT_ENTROPY_SOURCE_ERROR: u32 = 3;
pub const BOOT_ENTROPY_SOURCE_SUCCESS: u32 = 4;

/// The most entropy one source's record holds.
pub const BOOT_ENTROPY_SOURCE_DATA_SIZE: usize = 64;

/// `BOOT_ENTROPY_SOURCE_LDR_RESULT`: one source's record.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BOOT_ENTROPY_SOURCE_LDR_RESULT {
    /// `BOOT_ENTROPY_SOURCE_*`.
    pub SourceId: u32,
    pub Policy: u64,
    /// `BOOT_ENTROPY_SOURCE_*` result code.
    pub ResultCode: u32,
    pub ResultStatus: i32,
    pub Time: u64,
    pub EntropyLength: u32,
    pub EntropyData: [u8; BOOT_ENTROPY_SOURCE_DATA_SIZE],
}

/// `BOOT_ENTROPY_LDR_RESULT`: what Windows' loader hands the kernel of
/// the entropy it gathered (the loader block extension's
/// `BootEntropyResult`). NK's loader hands over the same block
/// (`nk-bootinfo`); the kernel copies its head out for class 0x75.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BOOT_ENTROPY_LDR_RESULT {
    pub maxEntropySources: u32,
    pub EntropySourceResult: [BOOT_ENTROPY_SOURCE_LDR_RESULT; BOOT_MAX_ENTROPY_SOURCES],
    pub SeedBytesForCng: [u8; 48],
    pub RngBytesForNtoskrnl: [u8; 1024],
    pub KdEntropy: [u8; 32],
}

const _: () = {
    use core::mem::offset_of;
    assert!(size_of::<BOOT_ENTROPY_SOURCE_LDR_RESULT>() == 104);
    assert!(offset_of!(BOOT_ENTROPY_SOURCE_LDR_RESULT, Policy) == 8);
    assert!(offset_of!(BOOT_ENTROPY_SOURCE_LDR_RESULT, ResultCode) == 16);
    assert!(offset_of!(BOOT_ENTROPY_SOURCE_LDR_RESULT, ResultStatus) == 20);
    assert!(offset_of!(BOOT_ENTROPY_SOURCE_LDR_RESULT, Time) == 24);
    assert!(offset_of!(BOOT_ENTROPY_SOURCE_LDR_RESULT, EntropyLength) == 32);
    assert!(offset_of!(BOOT_ENTROPY_SOURCE_LDR_RESULT, EntropyData) == 36);
    assert!(size_of::<BOOT_ENTROPY_LDR_RESULT>() == 2152);
    assert!(offset_of!(BOOT_ENTROPY_LDR_RESULT, EntropySourceResult) == 8);
    assert!(offset_of!(BOOT_ENTROPY_LDR_RESULT, SeedBytesForCng) == 0x418);
    assert!(offset_of!(BOOT_ENTROPY_LDR_RESULT, RngBytesForNtoskrnl) == 0x448);
    assert!(offset_of!(BOOT_ENTROPY_LDR_RESULT, KdEntropy) == 0x848);
    assert!(SYSTEM_BOOT_ENTROPY_INFORMATION_SIZE == 0x448);
};

impl BOOT_ENTROPY_LDR_RESULT {
    /// A block of no sources and no bytes.
    pub const fn zeroed() -> Self {
        const NONE: BOOT_ENTROPY_SOURCE_LDR_RESULT = BOOT_ENTROPY_SOURCE_LDR_RESULT {
            SourceId: 0,
            Policy: 0,
            ResultCode: 0,
            ResultStatus: 0,
            Time: 0,
            EntropyLength: 0,
            EntropyData: [0; BOOT_ENTROPY_SOURCE_DATA_SIZE],
        };
        Self {
            maxEntropySources: 0,
            EntropySourceResult: [NONE; BOOT_MAX_ENTROPY_SOURCES],
            SeedBytesForCng: [0; 48],
            RngBytesForNtoskrnl: [0; 1024],
            KdEntropy: [0; 32],
        }
    }
}
