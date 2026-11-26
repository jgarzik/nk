//! Routines Microsoft's storage stack imports that NK does not
//! implement: each stops the system, naming itself, if called. A name
//! leaves this list in the commit that implements the routine.

#![allow(non_snake_case, non_upper_case_globals)]

use super::super::{Export, NT, State};

trap_list!(
    RtlAddRange,
    RtlCheckRegistryKey,
    RtlCmDecodeMemIoResource,
    RtlCmEncodeMemIoResource,
    RtlCopyRangeList,
    RtlCreateRegistryKey,
    RtlDeleteOwnersRanges,
    RtlDeleteRange,
    RtlDeleteRegistryValue,
    RtlFindClosestEncodableLength,
    RtlFindMessage,
    RtlFindRange,
    RtlFreeRangeList,
    RtlGetFirstRange,
    RtlGetNextRange,
    RtlInitializeRangeList,
    RtlInvertRangeList,
    RtlInvertRangeListEx,
    RtlIoDecodeMemIoResource,
    RtlIoEncodeMemIoResource,
    RtlIsRangeAvailable,
    RtlNotifyFeatureUsage,
    RtlPcToFileName,
    RtlQueryFeatureConfiguration,
    RtlQueryFeatureConfigurationChangeStamp,
    RtlRegisterFeatureConfigurationChangeNotification,
    RtlRunOnceExecuteOnce,
    RtlUnregisterFeatureConfigurationChangeNotification,
    RtlWriteRegistryValue,
);
