//! Exports implemented in `kernel/hal`.

use super::super::{Export, NT, State};
use crate::hal;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Implemented, hal::pci::HalGetBusDataByOffset),
    export!(Implemented, hal::pci::HalSetBusDataByOffset),
];
