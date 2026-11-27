//! Routines Microsoft's volume drivers (`partmgr.sys`, `volmgr.sys`,
//! `mountmgr.sys`) import that NK does not implement: each stops the
//! system, naming itself, if called. A name leaves this list in the
//! commit that implements the routine.

#![allow(non_snake_case, non_upper_case_globals)]

use super::super::{Export, NT, State};

trap_list!(
    PsGetCurrentThreadTeb,
    PsGetProcessCreateTimeQuadPart,
    PsGetProcessSecurityPort,
    PsGetSiloIdentifier,
    PsGetThreadProcess,
    PsImpersonateClient,
    PsIsCurrentThreadInServerSilo,
    PsIsProtectedProcess,
    PsLookupProcessByProcessId,
    PsRevertToSelf,
    PsSetCreateProcessNotifyRoutine,
    PsSetCreateProcessNotifyRoutineEx2,
    PsUpdateComponentPower,
);
