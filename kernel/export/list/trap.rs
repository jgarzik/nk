//! Exports implemented that only stop the system (`export::trap`).

use super::super::trap;
use super::super::{Export, NT, State};

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Traps, trap::ZwAlpcCancelMessage),
    export!(Traps, trap::ZwAlpcConnectPort),
    export!(Traps, trap::ZwAlpcConnectPortEx),
    export!(Traps, trap::ZwAlpcCreatePortSection),
    export!(Traps, trap::ZwAlpcCreateResourceReserve),
    export!(Traps, trap::ZwAlpcCreateSectionView),
    export!(Traps, trap::ZwAlpcCreateSecurityContext),
    export!(Traps, trap::ZwAlpcDeletePortSection),
    export!(Traps, trap::ZwAlpcDeleteSectionView),
    export!(Traps, trap::ZwAlpcDeleteSecurityContext),
    export!(Traps, trap::ZwAlpcDisconnectPort),
    export!(Traps, trap::ZwAlpcQueryInformation),
    export!(Traps, trap::ZwAlpcQueryInformationMessage),
    export!(Traps, trap::ZwAlpcSendWaitReceivePort),
    export!(Traps, trap::ZwAlpcSetInformation),
    export!(Traps, trap::IoSetIoCompletionEx),
    export!(Traps, trap::ZwCreateIoCompletion),
    export!(Traps, trap::ZwRemoveIoCompletionEx),
];
