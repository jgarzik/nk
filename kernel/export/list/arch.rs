//! Exports implemented entered through an assembly stub of the architecture.

use super::super::{Export, NT, State};
use crate::arch;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export_entry!(Implemented, "__chkstk", arch::nk_chkstk),
    export_entry!(
        Partial,
        "MmProbeAndLockPages",
        arch::seh::nk_entry_MmProbeAndLockPages
    ),
    export_entry!(
        Implemented,
        "ProbeForRead",
        arch::seh::nk_entry_ProbeForRead
    ),
    export_entry!(
        Implemented,
        "ExRaiseStatus",
        arch::seh::nk_entry_ExRaiseStatus
    ),
    export_entry!(
        Implemented,
        "ExRaiseAccessViolation",
        arch::seh::nk_entry_ExRaiseAccessViolation
    ),
    export_entry!(
        Implemented,
        "ExRaiseDatatypeMisalignment",
        arch::seh::nk_entry_ExRaiseDatatypeMisalignment
    ),
    export_entry!(
        Implemented,
        "ProbeForWrite",
        arch::seh::nk_entry_ProbeForWrite
    ),
];
