//! Exports implemented in `kernel/ldr`.

use super::super::{Export, NT, State};
use crate::ldr;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Implemented, ldr::MmLockPagableDataSection),
    export!(Implemented, ldr::MmLockPagableSectionByHandle),
    export!(Implemented, ldr::MmPageEntireDriver),
    export!(Implemented, ldr::MmResetDriverPaging),
    export!(Implemented, ldr::MmUnlockPagableImageSection),
];
