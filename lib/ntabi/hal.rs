//! The HAL's dispatch tables: two exported variables, each a version
//! number and then routine pointers, which Microsoft's drivers call
//! through and store their own routines into.
//!
//! `HalDispatchTable` is
//! [`HAL_DISPATCH`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-halexaminembr)
//! of `ntddk.h`. `HalPrivateDispatchTable` (`HAL_PRIVATE_DISPATCH`) is
//! in no header; its slots are named by the pinned kernel's public
//! symbols, against which the list below is checked.
//!
//! Each list is a macro that hands its slot names, in order, to the
//! macro it is given: the kernel builds the tables from the same lists.

/// `HAL_DISPATCH_VERSION` of the pinned build.
pub const HAL_DISPATCH_VERSION: u32 = 4;
/// The version the pinned build's `HalPrivateDispatchTable` starts with.
pub const HAL_PRIVATE_DISPATCH_VERSION: u32 = 0x33;

/// Offset of the first slot: the version and its padding come before.
pub const FIRST_SLOT: usize = 8;

/// The slots of `HalDispatchTable`, in order.
#[macro_export]
macro_rules! hal_dispatch_slots {
    ($with:ident) => {
        $with! {
            HalQuerySystemInformation, HalSetSystemInformation,
            HalQueryBusSlots, Spare1, HalExamineMBR,
            HalIoReadPartitionTable, HalIoSetPartitionInformation,
            HalIoWritePartitionTable, HalReferenceHandlerForBus,
            HalReferenceBusHandler, HalDereferenceBusHandler,
            HalInitPnpDriver, HalInitPowerManagement, HalGetDmaAdapter,
            HalGetInterruptTranslator, HalStartMirroring, HalEndMirroring,
            HalMirrorPhysicalMemory, HalEndOfBoot, HalMirrorVerify,
            HalGetCachedAcpiTable, HalSetPciErrorHandlerCallback,
        }
    };
}

/// The slots of `HalPrivateDispatchTable`, in order.
#[macro_export]
macro_rules! hal_private_dispatch_slots {
    ($with:ident) => {
        $with! {
            HalHandlerForBus, HalHandlerForConfigSpace,
            HalLocateHiberRanges, HalRegisterBusHandler, HalSetWakeEnable,
            HalSetWakeAlarm, HalPciTranslateBusAddress,
            HalPciAssignSlotResources, HalHaltSystem,
            HalFindBusAddressTranslation, HalResetDisplay,
            HalAllocateMapRegisters, KdSetupPciDeviceForDebugging,
            KdReleasePciDeviceForDebugging, KdGetAcpiTablePhase0,
            KdCheckPowerButton, HalVectorToIDTEntry, KdMapPhysicalMemory64,
            KdUnmapVirtualAddress, KdGetPciDataByOffset,
            KdSetPciDataByOffset, HalGetInterruptVectorOverride,
            HalGetVectorInputOverride, HalLoadMicrocode, HalUnloadMicrocode,
            HalPostMicrocodeUpdate, HalAllocateMessageTargetOverride,
            HalFreeMessageTargetOverride, HalDpReplaceBegin,
            HalDpReplaceTarget, HalDpReplaceControl, HalDpReplaceEnd,
            HalPrepareForBugcheck, HalQueryWakeTime,
            HalReportIdleStateUsage, HalTscSynchronization,
            HalWheaInitProcessorGenericSection, HalStopLegacyUsbInterrupts,
            HalReadWheaPhysicalMemory, HalWriteWheaPhysicalMemory,
            HalDpMaskLevelTriggeredInterrupts,
            HalDpUnmaskLevelTriggeredInterrupts,
            HalDpGetInterruptReplayState, HalDpReplayInterrupts,
            HalQueryIoPortAccessSupported,
            KdSetupIntegratedDeviceForDebugging,
            KdReleaseIntegratedDeviceForDebugging,
            HalGetEnlightenmentInformation, HalAllocateEarlyPages,
            HalMapEarlyPages, Dummy1, Dummy2, HalNotifyProcessorFreeze,
            HalPrepareProcessorForIdle, HalRegisterLogRoutine,
            HalResumeProcessorFromIdle, Dummy, HalVectorToIDTEntryEx,
            HalSecondaryInterruptQueryPrimaryInformation, HalMaskInterrupt,
            HalUnmaskInterrupt, HalIsInterruptTypeSecondary,
            HalAllocateGsivForSecondaryInterrupt, HalAddInterruptRemapping,
            HalRemoveInterruptRemapping, HalSaveAndDisableHvEnlightenment,
            HalRestoreHvEnlightenment, HalFlushIoBuffersExternalCache,
            HalFlushExternalCache, HalPciEarlyRestore, HalGetProcessorId,
            HalAllocatePmcCounterSet, HalCollectPmcCounters,
            HalFreePmcCounterSet, HalProcessorHalt,
            HalTimerQueryCycleCounter, Dummy3, HalPciMarkHiberPhase,
            HalQueryProcessorRestartEntryPoint, HalRequestInterrupt,
            HalEnumerateUnmaskedInterrupts,
            HalFlushAndInvalidatePageExternalCache,
            KdEnumerateDebuggingDevices, HalFlushIoRectangleExternalCache,
            HalPowerEarlyRestore, HalQueryCapsuleCapabilities,
            HalUpdateCapsule, HalPciMultiStageResumeCapable,
            HalDmaFreeCrashDumpRegisters, HalAcpiAoacCapable,
            HalInterruptSetDestination, HalGetClockConfiguration,
            HalClockTimerActivate, HalClockTimerInitialize,
            HalClockTimerStop, HalClockTimerArm,
            HalTimerOnlyClockInterruptPending, HalAcpiGetMultiNode,
            HalPowerSetRebootHandler, HalIommuRegisterDispatchTable,
            HalTimerWatchdogStart, HalTimerWatchdogResetCountdown,
            HalTimerWatchdogStop, HalTimerWatchdogGeneratedLastReset,
            HalTimerWatchdogTriggerSystemReset,
            HalInterruptVectorDataToGsiv,
            HalInterruptGetHighestPriorityInterrupt, HalProcessorOn,
            HalProcessorOff, HalProcessorFreeze,
            HalDmaLinkDeviceObjectByToken, HalDmaCheckAdapterToken, Dummy4,
            HalTimerConvertPerformanceCounterToAuxiliaryCounter,
            HalTimerConvertAuxiliaryCounterToPerformanceCounter,
            HalTimerQueryAuxiliaryCounterFrequency,
            HalConnectThermalInterrupt, HalIsEFIRuntimeActive,
            HalTimerQueryAndResetRtcErrors, HalAcpiLateRestore,
            KdWatchdogDelayExpiration, HalGetProcessorStats,
            HalTimerWatchdogQueryDueTime, HalConnectSyntheticInterrupt,
            HalPreprocessNmi, HalEnumerateEnvironmentVariablesWithFilter,
            HalCaptureLastBranchRecordStack, HalClearLastBranchRecordStack,
            HalConfigureLastBranchRecord, HalGetLastBranchInformation,
            HalResumeLastBranchRecord, HalStartLastBranchRecord,
            HalStopLastBranchRecord, HalIommuBlockDevice,
            HalIommuUnblockDevice, HalGetIommuInterface,
            HalRequestGenericErrorRecovery,
            HalTimerQueryHostPerformanceCounter,
            HalTopologyQueryProcessorRelationships,
            HalInitPlatformDebugTriggers, HalRunPlatformDebugTriggers,
            HalTimerGetReferencePage, HalGetHiddenProcessorPowerInterface,
            HalGetHiddenProcessorPackageId,
            HalGetHiddenPackageProcessorCount,
            HalGetHiddenProcessorApicIdByIndex,
            HalRegisterHiddenProcessorIdleState, HalIommuReportIommuFault,
            HalIommuDmaRemappingCapable,
        }
    };
}

/// The slots of the table the HAL gives `acpi.sys` in exchange for the
/// driver's own (`HalInitPowerManagement`): a `PM_DISPATCH_TABLE`,
/// signature and version and then routines. It is in no header; the
/// names are those of the routines the pinned kernel's table holds.
#[macro_export]
macro_rules! hal_acpi_dispatch_slots {
    ($with:ident) => {
        $with! {
            HalAcpiTimerInit, HalAcpiMachineStateInit, HalAcpiQueryFlags,
            HalInterruptIsPicStateIntact, HalInterruptRestoreAllControllerState,
            HalPciInterfaceReadConfig, HalPciInterfaceWriteConfig, HalInterruptGetApicVersion,
            HalSetMaxLegacyPciBusNumber, HalInterruptIsGsiValid, HalAcpiGetTable,
            HalAcpiGetRsdp, HalAcpiGetFacsMapping, HalAcpiGetAllTables,
            HalAcpiPmRegisterAvailable, HalAcpiPmRegisterRead, HalAcpiPmRegisterWrite,
            HalAcpiAccessSecureAddress,
        }
    };
}

macro_rules! names {
    ($($name:ident),* $(,)?) => {
        &[$(stringify!($name)),*]
    };
}

/// The slot names of `HalDispatchTable`.
pub const HAL_DISPATCH_SLOTS: &[&str] = hal_dispatch_slots!(names);
/// The slot names of `HalPrivateDispatchTable`.
pub const HAL_PRIVATE_DISPATCH_SLOTS: &[&str] = hal_private_dispatch_slots!(names);

/// The slot names of the HAL's ACPI table.
pub const HAL_ACPI_DISPATCH_SLOTS: &[&str] = hal_acpi_dispatch_slots!(names);
/// What the HAL's ACPI table starts with: the signature `HAL ` in its
/// low half, the version, 4, in its high half.
pub const HAL_ACPI_DISPATCH_HEADER: u64 = 0x0000_0004_4841_4C20;

/// The offset of the slot called `name` in a table with `slots`.
pub const fn slot_offset(slots: &[&str], name: &str) -> Option<usize> {
    let mut i = 0;
    while i < slots.len() {
        if same(slots[i].as_bytes(), name.as_bytes()) {
            return Some(FIRST_SLOT + i * 8);
        }
        i += 1;
    }
    None
}

const fn same(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

// `HAL_DISPATCH` version 4 ends with `HalSetPciErrorHandlerCallback`;
// the private table is 1200 bytes in the pinned build.
const _: () = assert!(FIRST_SLOT + HAL_DISPATCH_SLOTS.len() * 8 == 0xb8);
const _: () = assert!(FIRST_SLOT + HAL_PRIVATE_DISPATCH_SLOTS.len() * 8 == 1200);
const _: () = assert!(matches!(
    slot_offset(HAL_DISPATCH_SLOTS, "HalInitPowerManagement"),
    Some(0x68)
));
const _: () = assert!(FIRST_SLOT + HAL_ACPI_DISPATCH_SLOTS.len() * 8 == 0x98);
const _: () = assert!(matches!(
    slot_offset(HAL_ACPI_DISPATCH_SLOTS, "HalAcpiPmRegisterRead"),
    Some(0x80)
));
const _: () = assert!(matches!(
    slot_offset(HAL_ACPI_DISPATCH_SLOTS, "HalAcpiGetTable"),
    Some(0x58)
));
const _: () = assert!(matches!(
    slot_offset(HAL_DISPATCH_SLOTS, "HalGetCachedAcpiTable"),
    Some(0xa8)
));
