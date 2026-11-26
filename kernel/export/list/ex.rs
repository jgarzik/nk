//! Exports implemented in `kernel/ex`.

use super::super::{Export, NT, State};
use crate::ex;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Implemented, ex::absent::HeadlessDispatch),
    export!(Implemented, ex::absent::HviGetHypervisorFeatures),
    export!(Implemented, ex::absent::HviIsAnyHypervisorPresent),
    export!(Implemented, ex::absent::VfFailDeviceNode),
    export!(Implemented, ex::absent::VfFailSystemBIOS),
    export!(Implemented, ex::absent::VfIsVerificationEnabled),
    export!(
        Implemented,
        ex::vsl::VslGetSecurePciDeviceAlternateFunctionNumberForVtl0Dma
    ),
    export!(Implemented, ex::vsl::VslQuerySecureDevice),
    export!(Partial, ex::em::EmClientQueryRuleState),
    export!(Partial, ex::em::EmClientRuleEvaluate),
    export!(Implemented, ex::em::EmProviderDeregister),
    export!(Implemented, ex::em::EmProviderRegister),
    export!(Implemented, ex::sysinfo::MmIsDriverVerifying),
    export!(Implemented, ex::sysinfo::RtlQueryModuleInformation),
    export!(Implemented, ex::pushlock::ExAcquirePushLockExclusiveEx),
    export!(Implemented, ex::pushlock::ExAcquirePushLockSharedEx),
    export!(Implemented, ex::resource::ExAcquireResourceExclusiveLite),
    export!(Implemented, ex::resource::ExAcquireResourceSharedLite),
    export!(Implemented, ex::resource::ExAcquireSharedStarveExclusive),
    export!(Implemented, ex::resource::ExAcquireSharedWaitForExclusive),
    export!(Partial, ex::timer::ExAllocateTimer),
    export!(Implemented, ex::timer::ExCancelTimer),
    export!(Implemented, ex::resource::ExConvertExclusiveToSharedLite),
    export!(Implemented, ex::lookaside::ExDeleteNPagedLookasideList),
    export!(Implemented, ex::lookaside::ExDeletePagedLookasideList),
    export!(Implemented, ex::resource::ExDeleteResourceLite),
    export!(Implemented, ex::timer::ExDeleteTimer),
    export!(Implemented, ex::resource::ExGetExclusiveWaiterCount),
    export!(Implemented, ex::resource::ExGetSharedWaiterCount),
    export!(Implemented, ex::lookaside::ExInitializeNPagedLookasideList),
    export!(Implemented, ex::lookaside::ExInitializePagedLookasideList),
    export!(Implemented, ex::resource::ExInitializeResourceLite),
    export!(Implemented, ex::resource::ExIsResourceAcquiredExclusiveLite),
    export!(Implemented, ex::resource::ExIsResourceAcquiredSharedLite),
    export!(Implemented, ex::slist::ExQueryDepthSList),
    export!(Implemented, ex::work::ExQueueWorkItem),
    export!(Implemented, ex::resource::ExReinitializeResourceLite),
    export!(Implemented, ex::pushlock::ExReleasePushLockEx),
    export!(Implemented, ex::pushlock::ExReleasePushLockExclusiveEx),
    export!(Implemented, ex::pushlock::ExReleasePushLockSharedEx),
    export!(Implemented, ex::resource::ExReleaseResourceForThreadLite),
    export!(Implemented, ex::resource::ExReleaseResourceLite),
    export!(Partial, ex::timer::ExSetTimer),
    export!(Implemented, ex::pushlock::ExTryAcquirePushLockExclusiveEx),
    export!(Implemented, ex::uuid::ExUuidCreate),
    export!(Implemented, ex::slist::ExpInterlockedFlushSList),
    export!(Implemented, ex::slist::ExpInterlockedPopEntrySList),
    export!(Implemented, ex::slist::ExpInterlockedPushEntrySList),
    export!(Implemented, ex::slist::InitializeSListHead),
    export!(Implemented, ex::work::IoAllocateWorkItem),
    export!(Implemented, ex::work::IoFreeWorkItem),
    export!(Implemented, ex::work::IoQueueWorkItem),
    export!(Implemented, ex::work::IoInitializeWorkItem),
    export!(Implemented, ex::work::IoQueueWorkItemEx),
    export!(Implemented, ex::work::IoSizeofWorkItem),
    export!(Implemented, ex::work::IoUninitializeWorkItem),
    export!(Implemented, ex::sysinfo::DbgkWerCaptureLiveKernelDump),
    export!(Partial, ex::sysinfo::NtQuerySystemInformation),
    export!(Implemented, ex::sysinfo::PsGetVersion),
    export_entry!(
        Partial,
        "ZwQuerySystemInformation",
        ex::sysinfo::NtQuerySystemInformation
    ),
    export!(Partial, ex::sysinfo_ex::NtQuerySystemInformationEx),
    export_entry!(
        Partial,
        "ZwQuerySystemInformationEx",
        ex::sysinfo_ex::NtQuerySystemInformationEx
    ),
    export!(Implemented, ex::license::ZwQueryLicenseValue),
    export!(Implemented, ex::shim::KseRegisterShim),
    export!(Implemented, ex::vsl::VslGetSecurePciEnabled),
    export!(Implemented, ex::rundown::ExInitializeRundownProtection),
    export!(Implemented, ex::rundown::ExAcquireRundownProtection),
    export!(Implemented, ex::rundown::ExReleaseRundownProtection),
    export!(Implemented, ex::rundown::ExWaitForRundownProtectionRelease),
    export!(
        Implemented,
        ex::rundown::ExAllocateCacheAwareRundownProtection
    ),
    export!(Implemented, ex::rundown::ExFreeCacheAwareRundownProtection),
    export!(
        Implemented,
        ex::rundown::ExSizeOfRundownProtectionCacheAware
    ),
    export!(
        Implemented,
        ex::rundown::ExInitializeRundownProtectionCacheAware
    ),
    export!(
        Implemented,
        ex::rundown::ExReInitializeRundownProtectionCacheAware
    ),
    export!(
        Implemented,
        ex::rundown::ExAcquireRundownProtectionCacheAware
    ),
    export!(
        Implemented,
        ex::rundown::ExReleaseRundownProtectionCacheAware
    ),
    export!(
        Implemented,
        ex::rundown::ExWaitForRundownProtectionReleaseCacheAware
    ),
    export!(Implemented, ex::spinlock::ExAcquireSpinLockExclusive),
    export!(Implemented, ex::spinlock::ExAcquireSpinLockShared),
    export!(
        Implemented,
        ex::spinlock::ExAcquireSpinLockExclusiveAtDpcLevel
    ),
    export!(Implemented, ex::spinlock::ExAcquireSpinLockSharedAtDpcLevel),
    export!(Implemented, ex::spinlock::ExReleaseSpinLockExclusive),
    export!(Implemented, ex::spinlock::ExReleaseSpinLockShared),
    export!(
        Implemented,
        ex::spinlock::ExReleaseSpinLockExclusiveFromDpcLevel
    ),
    export!(
        Implemented,
        ex::spinlock::ExReleaseSpinLockSharedFromDpcLevel
    ),
    export!(Implemented, ex::spinlock::ExInterlockedInsertHeadList),
    export!(Implemented, ex::spinlock::ExInterlockedInsertTailList),
    export!(Implemented, ex::spinlock::ExInterlockedRemoveHeadList),
    export!(Implemented, ex::spinlock::ExInterlockedPopEntryList),
    export!(Implemented, ex::spinlock::ExInterlockedPushEntryList),
    export!(Implemented, ex::slist::FirstEntrySList),
    export!(Implemented, ex::work::ExTryQueueWorkItem),
    export!(Implemented, ex::sysinfo::MmIsVerifierEnabled),
    export!(Implemented, ex::sysinfo::MmAddVerifierThunks),
    export!(Implemented, ex::sysinfo::ExIsSoftBoot),
    export!(Implemented, ex::sysinfo::MmIsAddressValid),
];
