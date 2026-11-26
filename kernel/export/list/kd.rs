//! Exports implemented in `kernel/kd`.

use super::super::{Export, NT, State};
use crate::kd::variables;

pub(in crate::export) static EXPORTS: &[Export] = &[
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
