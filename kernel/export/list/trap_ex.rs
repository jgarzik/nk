//! Routines Microsoft's storage stack imports that NK does not
//! implement: each stops the system, naming itself, if called. A name
//! leaves this list in the commit that implements the routine.

#![allow(non_snake_case, non_upper_case_globals)]

use super::super::{Export, NT, State};

trap_list!(
    ExAcquireRundownProtection,
    ExAcquireRundownProtectionCacheAware,
    ExAcquireSpinLockExclusive,
    ExAcquireSpinLockExclusiveAtDpcLevel,
    ExAcquireSpinLockShared,
    ExAcquireSpinLockSharedAtDpcLevel,
    ExAllocateCacheAwareRundownProtection,
    ExAllocatePool,
    ExAllocateTimerInternal2,
    ExCreateCallback,
    ExFreeCacheAwareRundownProtection,
    ExInitializeRundownProtection,
    ExInitializeRundownProtectionCacheAware,
    ExInterlockedInsertHeadList,
    ExInterlockedInsertTailList,
    ExInterlockedPopEntryList,
    ExInterlockedPushEntryList,
    ExInterlockedRemoveHeadList,
    ExIsSoftBoot,
    ExNotifyCallback,
    ExQueryTimerResolution,
    ExReInitializeRundownProtectionCacheAware,
    ExRegisterCallback,
    ExReleaseRundownProtection,
    ExReleaseRundownProtectionCacheAware,
    ExReleaseSpinLockExclusive,
    ExReleaseSpinLockExclusiveFromDpcLevel,
    ExReleaseSpinLockShared,
    ExReleaseSpinLockSharedFromDpcLevel,
    ExSizeOfRundownProtectionCacheAware,
    ExSubscribeWnfStateChange,
    ExTryQueueWorkItem,
    ExUnregisterCallback,
    ExUnsubscribeWnfStateChange,
    ExWaitForRundownProtectionRelease,
    ExWaitForRundownProtectionReleaseCacheAware,
    FirstEntrySList,
);
