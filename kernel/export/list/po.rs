//! Exports implemented in `kernel/po`.

use super::super::{Export, NT, State};
use crate::po;

pub(in crate::export) static EXPORTS: &[Export] = &[export!(Partial, po::ZwPowerInformation)];
