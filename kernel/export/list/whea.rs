//! Exports implemented in `kernel/whea`.

use super::super::{Export, NT, State};
use crate::whea;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Implemented, whea::WheaAddErrorSource),
    export!(Implemented, whea::WheaAddErrorSourceDeviceDriverV1),
    export!(Partial, whea::WheaConfigureErrorSource),
    export!(Implemented, whea::WheaGetErrorSource),
    export!(Implemented, whea::WheaInitializeRecordHeader),
    export!(Partial, whea::WheaLogInternalEvent),
    export!(Partial, whea::WheaRemoveErrorSource),
    export!(Partial, whea::WheaReportFatalHwErrorDeviceDriverEx),
    export!(Partial, whea::WheaReportHwError),
    export!(Partial, whea::WheaReportHwErrorDeviceDriverEx),
    export!(Implemented, whea::WheaUnconfigureErrorSource),
];
