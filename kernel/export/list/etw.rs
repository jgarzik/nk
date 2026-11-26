//! Exports implemented in `kernel/etw`.

use super::super::{Export, NT, State};
use crate::etw;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Implemented, etw::EtwRegister),
    export!(Implemented, etw::EtwRegisterClassicProvider),
    export!(Implemented, etw::EtwSetInformation),
    export!(Implemented, etw::EtwUnregister),
    export!(Implemented, etw::EtwWriteTransfer),
    export!(Implemented, etw::WmiQueryTraceInformation),
    export!(Implemented, etw::WmiTraceMessage),
];
