//! Routines Microsoft's binaries import that NK does not
//! implement: each stops the system, naming itself, if called. A name
//! leaves this list in the commit that implements the routine.

#![allow(non_snake_case, non_upper_case_globals)]

use super::super::{Export, NT, State};

trap_list!(
    IoAdjustStackSizeForRedirection,
    IoAssignResources,
    IoCancelFileOpen,
    IoCreateFile,
    IoCsqInitializeEx,
    IoCsqInsertIrpEx,
    IoDuplicateDependency,
    IoGetFsZeroingOffset,
    IoQueryFullDriverPath,
    IoRaiseHardError,
    IoRaiseInformationalHardError,
    IoReadPartitionTableEx,
    IoRequestDeviceEject,
    IoRequestDeviceEjectEx,
    IoRequestDeviceRemovalForReset,
    IoRetrievePriorityInfo,
    IoSetFsTrackOffsetState,
    IoSetFsZeroingOffset,
    IoTestDependency,
    IoVerifyVolume,
    IoVolumeDeviceToDosName,
    IoWMIExecuteMethod,
    IoWMIQueryAllData,
);
