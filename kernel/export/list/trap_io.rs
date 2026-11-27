//! Routines Microsoft's binaries import that NK does not
//! implement: each stops the system, naming itself, if called. A name
//! leaves this list in the commit that implements the routine.

#![allow(non_snake_case, non_upper_case_globals)]

use super::super::{Export, NT, State};

trap_list!(
    IoAdjustStackSizeForRedirection,
    IoAllocateMiniCompletionPacket,
    IoAssignResources,
    IoCancelFileOpen,
    IoCreateFile,
    IoDuplicateDependency,
    IoQueryFullDriverPath,
    IoRaiseHardError,
    IoRaiseInformationalHardError,
    IoReadPartitionTableEx,
    IoRequestDeviceEject,
    IoRequestDeviceEjectEx,
    IoRequestDeviceRemovalForReset,
    IoSetFsTrackOffsetState,
    IoTestDependency,
    IoVerifyVolume,
    IoVolumeDeviceToDosName,
    IoWMIExecuteMethod,
    IoWMIQueryAllData,
);
