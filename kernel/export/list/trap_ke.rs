//! Routines Microsoft's storage stack imports that NK does not
//! implement: each stops the system, naming itself, if called. A name
//! leaves this list in the commit that implements the routine.

#![allow(non_snake_case, non_upper_case_globals)]

use super::super::{Export, NT, State};

trap_list!(
    KeAcquireGuardedMutex,
    KeAcquireInStackQueuedSpinLockAtDpcLevel,
    KeAcquireInStackQueuedSpinLockForDpc,
    KeBugCheck,
    KeCancelTimer2,
    KeClearEvent,
    KeExpandKernelStackAndCalloutEx,
    KeFlushIoBuffers,
    KeFlushQueuedDpcs,
    KeFlushWriteBuffer,
    KeGetCurrentNodeNumber,
    KeGetCurrentProcessorNumberEx,
    KeGetEffectiveIrql,
    KeGetProcessorIndexFromNumber,
    KeGetProcessorNumberFromIndex,
    KeGetRecommendedSharedDataAlignment,
    KeInitializeGuardedMutex,
    KeInitializeThreadedDpc,
    KeInitializeTimer2,
    KeIpiGenericCall,
    KeProcessorGroupAffinity,
    KeQueryActiveGroupCount,
    KeQueryGroupAffinity,
    KeQueryHighestNodeNumber,
    KeQueryInterruptTimePrecise,
    KeQueryLogicalProcessorRelationship,
    KeQueryMaximumGroupCount,
    KeQueryMaximumProcessorCountEx,
    KeQueryNodeActiveAffinity,
    KeQueryUnbiasedInterruptTime,
    KeQueryUnbiasedInterruptTimePrecise,
    KeRegisterProcessorChangeCallback,
    KeReleaseGuardedMutex,
    KeReleaseInStackQueuedSpinLockForDpc,
    KeReleaseInStackQueuedSpinLockFromDpcLevel,
    KeReportCacheIncoherentDevice,
    KeRevertToUserGroupAffinityThread,
    KeSetCoalescableTimer,
    KeSetImportanceDpc,
    KeSetSystemGroupAffinityThread,
    KeSetTargetProcessorDpcEx,
    KeSetTimer2,
    KeStartDynamicProcessor,
);
