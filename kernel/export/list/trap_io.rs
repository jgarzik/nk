//! Routines Microsoft's storage stack imports that NK does not
//! implement: each stops the system, naming itself, if called. A name
//! leaves this list in the commit that implements the routine.

#![allow(non_snake_case, non_upper_case_globals)]

use super::super::{Export, NT, State};

trap_list!(
    IoAssignResources,
    IoClearActivityIdThread,
    IoDuplicateDependency,
    IoGetActivityIdIrp,
    IoGetActivityIdThread,
    IoGetAdapterCryptoEngineExtension,
    IoGetConfigurationInformation,
    IoGetGenericIrpExtension,
    IoGetIoAttributionHandle,
    IoGetIoPriorityHint,
    IoGetPagingIoPriority,
    IoGetRequestorProcessId,
    IoGetStackLimits,
    IoIs32bitProcess,
    IoIsActivityTracingEnabled,
    IoPropagateActivityIdToThread,
    IoPropagateIrpExtension,
    IoPropagateIrpExtensionEx,
    IoQueryFullDriverPath,
    IoReadPartitionTableEx,
    IoRecordIoAttribution,
    IoReportTargetDeviceChangeAsynchronous,
    IoRequestDeviceEject,
    IoRequestDeviceEjectEx,
    IoRequestDeviceRemovalForReset,
    IoReserveDependency,
    IoResolveDependency,
    IoSetActivityIdIrp,
    IoSetDependency,
    IoSetDeviceInterfacePropertyData,
    IoSetGenericIrpExtension,
    IoSetHardErrorOrVerifyDevice,
    IoTestDependency,
    IoWMIExecuteMethod,
    IoWMIOpenBlock,
    IoWMIQueryAllData,
);
