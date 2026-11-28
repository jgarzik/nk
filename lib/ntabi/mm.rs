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
};
