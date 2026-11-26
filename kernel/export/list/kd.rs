//! Exports implemented in `kernel/kd`.

use super::super::{Export, NT, State};
use crate::kd::{debugger, variables};

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Implemented, debugger::KdAcquireDebuggerLock),
    export!(Implemented, debugger::KdDeregisterPowerHandler),
    export!(Implemented, debugger::KdDisableDebugger),
    export!(Implemented, debugger::KdEnableDebugger),
    export!(Implemented, debugger::KdPowerTransitionEx),
    export!(Implemented, debugger::KdRegisterPowerHandler),
    export!(Implemented, debugger::KdReleaseDebuggerLock),
    export_variable!(Implemented, "InitSafeBootMode", variables::InitSafeBootMode),
    export_variable!(Implemented, "KdComPortInUse", variables::KdComPortInUse),
    export_variable!(
        Implemented,
        "KdDebuggerEnabled",
        variables::KdDebuggerEnabled
    ),
    export_variable!(
        Implemented,
        "KdDebuggerNotPresent",
        variables::KdDebuggerNotPresent
    ),
    export_variable!(Implemented, "KdHvComPortInUse", variables::KdHvComPortInUse),
    export_variable!(
        Implemented,
        "Mm64BitPhysicalAddress",
        variables::Mm64BitPhysicalAddress
    ),
];
