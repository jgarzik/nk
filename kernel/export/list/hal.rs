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
];
