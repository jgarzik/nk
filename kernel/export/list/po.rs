//! Exports implemented in `kernel/po`.

use super::super::{Export, NT, State};
use crate::po;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Implemented, po::absent::PoSetHiberRange),
    export!(Implemented, po::absent::PoShutdownBugCheck),
    export!(Implemented, po::request::PoDirectedDripsSetDeviceFlags),
    export!(Implemented, po::request::PoGetSystemWake),
    export!(Implemented, po::request::PoQueryWatchdogTime),
    export!(Partial, po::request::PoRequestPowerIrp),
    export!(Implemented, po::request::PoSetPowerState),
    export!(Implemented, po::request::PoSetSystemWake),
    export!(Implemented, po::setting::PoRegisterCoalescingCallback),
    export!(Partial, po::setting::PoRegisterPowerSettingCallback),
    export!(Implemented, po::setting::PoUnregisterCoalescingCallback),
    export!(Implemented, po::setting::PoUnregisterPowerSettingCallback),
    export!(Partial, po::ZwPowerInformation),
];
