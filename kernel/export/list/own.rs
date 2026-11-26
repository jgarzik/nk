//! Exports implemented by this module itself.

use super::super::MmGetSystemRoutineAddress;
use super::super::{Export, NT, State};

pub(in crate::export) static EXPORTS: &[Export] =
    &[export!(Implemented, MmGetSystemRoutineAddress)];
