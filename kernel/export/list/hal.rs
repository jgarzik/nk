//! Exports implemented in `kernel/hal`.

use super::super::{Export, NT, State};
use crate::hal;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export_variable!(Partial, "HalDispatchTable", hal::dispatch::HalDispatchTable),
    export_variable!(
        Partial,
        "HalPrivateDispatchTable",
        hal::dispatch::HalPrivateDispatchTable
    ),
    export!(Implemented, hal::pci::HalGetBusDataByOffset),
    export!(Implemented, hal::dma::HalTranslateBusAddress),
    export!(Partial, hal::dma::IoGetDmaAdapter),
    export!(Implemented, hal::pci::HalSetBusDataByOffset),
    export!(Partial, hal::target::HalGetInterruptTargetInformation),
    export!(Implemented, hal::query::HalConvertDeviceIdtToIrql),
    export!(Implemented, hal::query::HalGetMemoryCachingRequirements),
    export!(Implemented, hal::query::HalGetMessageRoutingInfo),
    export!(Implemented, hal::query::HalGetProcessorIdByNtNumber),
];
