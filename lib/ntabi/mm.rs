//! Virtual memory and section ABI types (`winnt.h` / `ntifs.h`).

/// `MEMORY_BASIC_INFORMATION` (`winnt.h`, 48 bytes on 64-bit Windows).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MEMORY_BASIC_INFORMATION {
    pub BaseAddress: u64,
    pub AllocationBase: u64,
    pub AllocationProtect: u32,
    pub PartitionId: u16,
    pub _pad0: u16,
    pub RegionSize: u64,
    pub State: u32,
    pub Protect: u32,
    pub Type: u32,
    pub _pad1: u32,
}

/// `MEMORY_REGION_INFORMATION` (`ntifs.h`, 48 bytes on 64-bit Windows 10 19045).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MEMORY_REGION_INFORMATION {
    pub AllocationBase: u64,
    pub AllocationProtect: u32,
    pub RegionType: u32,
    pub RegionSize: u64,
    pub CommitSize: u64,
    pub PartitionId: u64,
    pub NodePreference: u64,
}

/// `MEM_ADDRESS_REQUIREMENTS` (`winnt.h`, 24 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MEM_ADDRESS_REQUIREMENTS {
    pub LowestStartingAddress: u64,
    pub HighestEndingAddress: u64,
    pub Alignment: u64,
}

/// `MEM_EXTENDED_PARAMETER` (`winnt.h`, 16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MEM_EXTENDED_PARAMETER {
    pub Type: u64,
    pub Value: u64,
}

/// `MEM_EXTENDED_PARAMETER_TYPE` values.
pub const MEM_EXTENDED_PARAMETER_ADDRESS_REQUIREMENTS: u64 = 1;

/// `MEMORY_RANGE_ENTRY` (`winnt.h`, 16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MEMORY_RANGE_ENTRY {
    pub VirtualAddress: u64,
    pub NumberOfBytes: u64,
}

/// `MEMORY_INFORMATION_CLASS` values handled by `NtQueryVirtualMemory`.
pub const MEMORY_BASIC_INFORMATION_CLASS: u32 = 0;
pub const MEMORY_MAPPED_FILENAME_INFORMATION_CLASS: u32 = 2;
pub const MEMORY_REGION_INFORMATION_CLASS: u32 = 6;

/// `VIRTUAL_MEMORY_INFORMATION_CLASS` values handled by `NtSetInformationVirtualMemory`.
pub const VM_PREFETCH_INFORMATION: u32 = 0;
pub const VM_CFG_CALL_TARGET_INFORMATION: u32 = 2;

/// Section allocation attributes (`SEC_*`, `winnt.h`).
pub const SEC_FILE: u32 = 0x0080_0000;
pub const SEC_IMAGE: u32 = 0x0100_0000;
pub const SEC_PROTECTED_IMAGE: u32 = 0x0200_0000;
pub const SEC_RESERVE: u32 = 0x0400_0000;
pub const SEC_COMMIT: u32 = 0x0800_0000;
pub const SEC_NOCACHE: u32 = 0x1000_0000;
pub const SEC_IMAGE_NO_EXECUTE: u32 = SEC_IMAGE | SEC_NOCACHE;

/// Section access rights (`SECTION_*`, `winnt.h`).
pub const SECTION_QUERY: u32 = 0x0001;
pub const SECTION_MAP_WRITE: u32 = 0x0002;
pub const SECTION_MAP_READ: u32 = 0x0004;
pub const SECTION_MAP_EXECUTE: u32 = 0x0008;
pub const SECTION_EXTEND_SIZE: u32 = 0x0010;
pub const SECTION_ALL_ACCESS: u32 = 0x000F_001F;

/// `SECTION_INHERIT` values for `NtMapViewOfSection`.
pub const VIEW_SHARE: u32 = 1;
pub const VIEW_UNMAP: u32 = 2;

/// `SECTION_INFORMATION_CLASS` values for `NtQuerySection`.
pub const SECTION_BASIC_INFORMATION_CLASS: u32 = 0;
pub const SECTION_IMAGE_INFORMATION_CLASS: u32 = 1;

/// `SECTION_BASIC_INFORMATION` (`ntifs.h`, 24 bytes on 64-bit Windows).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SECTION_BASIC_INFORMATION {
    pub BaseAddress: u64,
    pub AllocationAttributes: u32,
    pub _pad0: u32,
    pub MaximumSize: i64,
}

/// `SECTION_IMAGE_INFORMATION` (`ntkrnlmp.x64.pdb`, 64 bytes on 64-bit Windows).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SECTION_IMAGE_INFORMATION {
    pub TransferAddress: u64,
    pub ZeroBits: u32,
    pub _pad0: u32,
    pub MaximumStackSize: u64,
    pub CommittedStackSize: u64,
    pub SubSystemType: u32,
    pub SubSystemMinorVersion: u16,
    pub SubSystemMajorVersion: u16,
    pub MajorOperatingSystemVersion: u16,
    pub MinorOperatingSystemVersion: u16,
    pub ImageCharacteristics: u16,
    pub DllCharacteristics: u16,
    pub Machine: u16,
    pub ImageContainsCode: u8,
    pub ImageFlags: u8,
    pub LoaderFlags: u32,
    pub ImageFileSize: u32,
    pub CheckSum: u32,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<MEMORY_BASIC_INFORMATION>() == 48);
    assert!(offset_of!(MEMORY_BASIC_INFORMATION, AllocationBase) == 8);
    assert!(offset_of!(MEMORY_BASIC_INFORMATION, AllocationProtect) == 16);
    assert!(offset_of!(MEMORY_BASIC_INFORMATION, PartitionId) == 20);
    assert!(offset_of!(MEMORY_BASIC_INFORMATION, RegionSize) == 24);
    assert!(offset_of!(MEMORY_BASIC_INFORMATION, State) == 32);
    assert!(offset_of!(MEMORY_BASIC_INFORMATION, Protect) == 36);
    assert!(offset_of!(MEMORY_BASIC_INFORMATION, Type) == 40);
    assert!(size_of::<MEMORY_REGION_INFORMATION>() == 48);
    assert!(size_of::<MEM_ADDRESS_REQUIREMENTS>() == 24);
    assert!(size_of::<MEM_EXTENDED_PARAMETER>() == 16);
    assert!(size_of::<MEMORY_RANGE_ENTRY>() == 16);
    assert!(size_of::<SECTION_BASIC_INFORMATION>() == 24);
    assert!(offset_of!(SECTION_BASIC_INFORMATION, AllocationAttributes) == 8);
    assert!(offset_of!(SECTION_BASIC_INFORMATION, MaximumSize) == 16);
    assert!(size_of::<SECTION_IMAGE_INFORMATION>() == 64);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, TransferAddress) == 0);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, ZeroBits) == 8);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, MaximumStackSize) == 16);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, CommittedStackSize) == 24);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, SubSystemType) == 32);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, SubSystemMinorVersion) == 36);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, SubSystemMajorVersion) == 38);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, ImageCharacteristics) == 44);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, DllCharacteristics) == 46);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, Machine) == 48);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, ImageContainsCode) == 50);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, ImageFlags) == 51);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, LoaderFlags) == 52);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, ImageFileSize) == 56);
    assert!(offset_of!(SECTION_IMAGE_INFORMATION, CheckSum) == 60);
};
