//! Routines Microsoft's binaries import that NK does not
//! implement: each stops the system, naming itself, if called. A name
//! leaves this list in the commit that implements the routine.

#![allow(non_snake_case, non_upper_case_globals)]

use super::super::{Export, NT, State};

trap_list!(
    IoAcquireVpbSpinLock,
    IoAdjustStackSizeForRedirection,
    IoAssignResources,
    IoCancelFileOpen,
    IoCheckShareAccess,
    IoCreateFile,
    IoCreateStreamFileObject,
    IoCsqInitializeEx,
    IoCsqInsertIrpEx,
    IoDuplicateDependency,
    IoGetDeviceToVerify,
    IoGetFsZeroingOffset,
    IoGetRelatedDeviceObject,
    IoGetTopLevelIrp,
    IoIsOperationSynchronous,
    IoIsSystemThread,
    IoMakeAssociatedIrp,
    IoQueryFullDriverPath,
    IoRaiseHardError,
    IoRaiseInformationalHardError,
    IoReadPartitionTableEx,
    IoRegisterFileSystem,
    IoReleaseVpbSpinLock,
    IoRemoveShareAccess,
    IoRequestDeviceEject,
    IoRequestDeviceEjectEx,
    IoRequestDeviceRemovalForReset,
    IoRetrievePriorityInfo,
    IoSetDeviceToVerify,
    IoSetFsTrackOffsetState,
    IoSetFsZeroingOffset,
    IoSetShareAccess,
    IoSetTopLevelIrp,
    IoTestDependency,
    IoUnregisterFileSystem,
    IoUpdateShareAccess,
    IoVerifyVolume,
    IoVolumeDeviceToDosName,
    IoVolumeDeviceToGuid,
    IoVolumeDeviceToGuidPath,
    IoWMIExecuteMethod,
    IoWMIQueryAllData,
);
