//! Exports implemented in `kernel/cc`.

use super::super::{Export, NT, State};
use crate::arch;
use crate::cc;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export_entry!(
        Implemented,
        "CcInitializeCacheMap",
        arch::seh::nk_entry_CcInitializeCacheMap
    ),
    export!(Implemented, cc::map::CcUninitializeCacheMap),
    export_entry!(Partial, "CcMapData", arch::seh::nk_entry_CcMapData),
    export_entry!(Partial, "CcPinRead", arch::seh::nk_entry_CcPinRead),
    export_entry!(
        Partial,
        "CcPinMappedData",
        arch::seh::nk_entry_CcPinMappedData
    ),
    export_entry!(
        Partial,
        "CcPreparePinWrite",
        arch::seh::nk_entry_CcPreparePinWrite
    ),
    export!(Implemented, cc::pin::CcSetDirtyPinnedData),
    export!(Implemented, cc::pin::CcUnpinData),
    export!(Implemented, cc::pin::CcRepinBcb),
    export!(Implemented, cc::pin::CcUnpinRepinnedBcb),
    export!(Implemented, cc::pin::CcGetFileObjectFromBcb),
    export_entry!(
        Implemented,
        "CcCopyReadEx",
        arch::seh::nk_entry_CcCopyReadEx
    ),
    export_entry!(Implemented, "CcCopyWrite", arch::seh::nk_entry_CcCopyWrite),
    export_entry!(
        Implemented,
        "CcCopyWriteEx",
        arch::seh::nk_entry_CcCopyWriteEx
    ),
    export_entry!(Implemented, "CcMdlRead", arch::seh::nk_entry_CcMdlRead),
    export!(Implemented, cc::mdl::CcMdlReadComplete),
    export_entry!(
        Implemented,
        "CcPrepareMdlWrite",
        arch::seh::nk_entry_CcPrepareMdlWrite
    ),
    export_entry!(
        Implemented,
        "CcMdlWriteComplete",
        arch::seh::nk_entry_CcMdlWriteComplete
    ),
    export!(Implemented, cc::mdl::CcMdlWriteAbort),
    export!(Implemented, cc::flush::CcFlushCache),
    export!(Implemented, cc::flush::CcIsThereDirtyData),
    export!(Partial, cc::size::CcPurgeCacheSection),
    export!(Implemented, cc::size::CcCoherencyFlushAndPurgeCache),
    export_entry!(
        Implemented,
        "CcSetFileSizes",
        arch::seh::nk_entry_CcSetFileSizes
    ),
    export!(Implemented, cc::size::CcSetFileSizesEx),
    export_entry!(Partial, "CcZeroData", arch::seh::nk_entry_CcZeroData),
    export!(Implemented, cc::size::CcSetReadAheadGranularity),
    export!(Implemented, cc::size::CcSetAdditionalCacheAttributes),
    export!(Implemented, cc::size::CcSetAdditionalCacheAttributesEx),
    export!(Partial, cc::throttle::CcCanIWrite),
    export!(Implemented, cc::throttle::CcDeferWrite),
    export!(Implemented, cc::lazy::CcWaitForCurrentLazyWriterActivity),
];
