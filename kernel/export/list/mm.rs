//! Exports implemented in `kernel/mm`.

use super::super::{Export, NT, State};
use crate::mm;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Implemented, mm::pool::ExAllocatePoolWithQuotaTag),
    export!(Implemented, mm::pool::ExAllocatePoolWithTag),
    export!(Implemented, mm::pool::ExAllocatePoolWithTagPriority),
    export!(Implemented, mm::pool::ExFreePool),
    export!(Implemented, mm::pool::ExFreePoolWithTag),
    export_variable!(
        Implemented,
        "MmUserProbeAddress",
        mm::user::MmUserProbeAddress
    ),
];
