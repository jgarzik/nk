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
    export!(Partial, cc::map::CcUninitializeCacheMap),
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
    export!(Partial, cc::pin::CcSetDirtyPinnedData),
    export!(Implemented, cc::pin::CcUnpinData),
    export!(Implemented, cc::pin::CcRepinBcb),
    export!(Implemented, cc::pin::CcUnpinRepinnedBcb),
    export!(Implemented, cc::pin::CcGetFileObjectFromBcb),
];
