//! Routines Microsoft's storage stack imports that NK does not
//! implement: each stops the system, naming itself, if called. A name
//! leaves this list in the commit that implements the routine.

#![allow(non_snake_case, non_upper_case_globals)]

use super::super::{Export, NT, State};

trap_list!(
    IoAssignResources,
    IoDuplicateDependency,
    IoGetConfigurationInformation,
    IoQueryFullDriverPath,
    IoReadPartitionTableEx,
    IoRegisterDeviceInterface,
    IoRegisterPlugPlayNotification,
    IoReportTargetDeviceChangeAsynchronous,
    IoRequestDeviceEject,
    IoRequestDeviceEjectEx,
    IoRequestDeviceRemovalForReset,
    IoReserveDependency,
    IoResolveDependency,
    IoSetDependency,
    IoSetDeviceInterfacePropertyData,
    IoSetDeviceInterfaceState,
    IoTestDependency,
    IoUnregisterPlugPlayNotification,
    IoUnregisterPlugPlayNotificationEx,
    IoWMIExecuteMethod,
    IoWMIQueryAllData,
);
