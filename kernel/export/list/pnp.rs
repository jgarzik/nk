//! Exports implemented in `kernel/pnp`.

use super::super::{Export, NT, State};
use crate::pnp;

pub(in crate::export) static EXPORTS: &[Export] = &[export!(
    Implemented,
    pnp::export::IoInvalidateDeviceRelations
)];
