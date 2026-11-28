//! Exports implemented in `kernel/mm`.

use super::super::{Export, NT, State};
use crate::mm;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(
        Implemented,
        mm::contig::MmAllocateContiguousMemorySpecifyCache
    ),
    export!(Implemented, mm::contig::MmAllocateContiguousNodeMemory),
    export!(Implemented, mm::contig::MmFreeContiguousMemory),
    export!(Implemented, mm::contig::MmFreeContiguousMemorySpecifyCache),
    export!(Implemented, mm::flush::MmCanFileBeTruncated),
    export!(Implemented, mm::flush::MmDoesFileHaveUserWritableReferences),
    export!(Implemented, mm::flush::MmFlushImageSection),
    export!(Implemented, mm::flush::MmMdlPageContentsState),
    export!(Implemented, mm::flush::MmQuerySystemSize),
    export!(Implemented, mm::io::MmGetPhysicalAddress),
    export!(Implemented, mm::io::MmGetVirtualForPhysical),
    export!(Implemented, mm::io::MmMapIoSpaceEx),
    export!(Implemented, mm::io::MmUnmapIoSpace),
    export!(Partial, mm::pool::ExAllocatePool2),
    export!(Implemented, mm::pool::ExAllocatePoolWithQuotaTag),
    export!(Implemented, mm::pool::ExAllocatePoolWithTag),
    export!(Implemented, mm::pool::ExAllocatePoolWithTagPriority),
    export!(Implemented, mm::pool::ExFreePool),
    export!(Implemented, mm::pool::ExFreePoolWithTag),
    export_variable!(
        Implemented,
        "MmUserProbeAddress",
        mm::user::MmUserProbeAddress
    ),
    export_variable!(
        Implemented,
        "MmHighestUserAddress",
        mm::user::MmHighestUserAddress
    ),
    export_variable!(Implemented, "MmBadPointer", mm::user::MmBadPointer),
    export!(Implemented, mm::pool::ExAllocatePool),
    export!(Partial, mm::cache::MmPrefetchPages),
];
