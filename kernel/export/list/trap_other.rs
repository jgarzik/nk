//! Routines Microsoft's storage stack imports that NK does not
//! implement: each stops the system, naming itself, if called. A name
//! leaves this list in the commit that implements the routine.

#![allow(non_snake_case, non_upper_case_globals)]

use super::super::{Export, NT, State};

trap_list!(
    DbgCommandString,
    DbgPrintEx,
    DbgPrompt,
    DbgSetDebugFilterState,
    EmClientQueryRuleState,
    EmClientRuleEvaluate,
    EmProviderDeregister,
    EmProviderRegister,
    FsRtlIsSystemPagingFile,
    HeadlessDispatch,
    HviGetHypervisorFeatures,
    HviIsAnyHypervisorPresent,
    ObReferenceObjectByPointer,
    VfFailDeviceNode,
    VfFailSystemBIOS,
    VfIsVerificationEnabled,
    VslGetSecurePciDeviceAlternateFunctionNumberForVtl0Dma,
    VslGetSecurePciEnabled,
    VslQuerySecureDevice,
    __chkstk,
    _strnicmp,
    _strtoui64,
    _strupr,
    _vsnprintf,
    isspace,
    rand,
    strchr,
    strncpy_s,
    strnlen,
    strstr,
    strtok_s,
    vDbgPrintExWithPrefix,
);
