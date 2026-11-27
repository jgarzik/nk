//! Routines Microsoft's volume drivers (`partmgr.sys`, `volmgr.sys`,
//! `mountmgr.sys`) import that NK does not implement: each stops the
//! system, naming itself, if called. A name leaves this list in the
//! commit that implements the routine.

#![allow(non_snake_case, non_upper_case_globals)]

use super::super::{Export, NT, State};

trap_list!(
    RtlAddProcessTrustLabelAce,
    RtlAppendUnicodeToString,
    RtlCreateSystemVolumeInformationFolder,
    RtlDelete,
    RtlDowncaseUnicodeString,
    RtlEqualString,
    RtlFindClearBits,
    RtlFreeOemString,
    RtlGenerate8dot3Name,
    RtlGetEnabledExtendedFeatures,
    RtlGetPersistedStateLocation,
    RtlMapSecurityErrorToNtStatus,
    RtlNtStatusToDosError,
    RtlNtStatusToDosErrorNoTeb,
    RtlOemStringToCountedUnicodeString,
    RtlOemStringToUnicodeString,
    RtlOemToUnicodeN,
    RtlSetSaclSecurityDescriptor,
    RtlSplay,
    RtlTimeFieldsToTime,
    RtlUnicodeStringToCountedOemString,
    RtlUpcaseUnicodeStringToCountedOemString,
    RtlUpperString,
    RtlxOemStringToUnicodeSize,
    _purecall,
);
