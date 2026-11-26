//! Routines Microsoft's storage stack imports that NK does not
//! implement: each stops the system, naming itself, if called. A name
//! leaves this list in the commit that implements the routine.

#![allow(non_snake_case, non_upper_case_globals)]

use super::super::{Export, NT, State};

trap_list!(
    PoCreateThermalRequest,
    PoDeleteThermalRequest,
    PoDirectedDripsSetDeviceFlags,
    PoFxActivateComponent,
    PoFxCompleteDevicePowerNotRequired,
    PoFxCompleteDirectedPowerDown,
    PoFxCompleteIdleCondition,
    PoFxCompleteIdleState,
    PoFxIdleComponent,
    PoFxIssueComponentPerfStateChange,
    PoFxNotifySurprisePowerOn,
    PoFxPowerControl,
    PoFxPowerOnCrashdumpDevice,
    PoFxRegisterComponentPerfStates,
    PoFxRegisterCrashdumpDevice,
    PoFxRegisterDevice,
    PoFxRegisterDripsWatchdogCallback,
    PoFxReportDevicePoweredOn,
    PoFxSetComponentLatency,
    PoFxSetComponentResidency,
    PoFxSetDeviceIdleTimeout,
    PoFxStartDevicePowerManagement,
    PoFxUnregisterDevice,
    PoGetSystemWake,
    PoGetThermalRequestSupport,
    PoQueryWatchdogTime,
    PoRegisterCoalescingCallback,
    PoRegisterPowerSettingCallback,
    PoRequestPowerIrp,
    PoSetHiberRange,
    PoSetPowerState,
    PoSetSystemWake,
    PoSetThermalActiveCooling,
    PoSetThermalPassiveCooling,
    PoShutdownBugCheck,
    PoUnregisterCoalescingCallback,
    PoUnregisterPowerSettingCallback,
);
