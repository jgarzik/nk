//! Exports implemented in `kernel/whea`.

use super::super::{Export, NT, State};
use crate::whea;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Implemented, whea::WheaAddErrorSourceDeviceDriverV1),
    export!(Implemented, whea::WheaGetErrorSource),
    export!(Partial, whea::WheaRemoveErrorSource),
];
