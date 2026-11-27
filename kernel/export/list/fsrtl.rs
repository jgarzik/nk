//! Exports implemented in `kernel/fsrtl`.

use super::super::{Export, NT, State};
use crate::arch;
use crate::fsrtl;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Implemented, fsrtl::FsRtlIsSystemPagingFile),
    export!(Partial, fsrtl::FsRtlGetVirtualDiskNestingLevel),
    export!(Implemented, fsrtl::FsRtlTeardownPerStreamContexts),
    export!(
        Implemented,
        fsrtl::filter::FsRtlRegisterFileSystemFilterCallbacks
    ),
    export_entry!(
        Implemented,
        "FsRtlInitializeLargeMcb",
        arch::seh::nk_entry_FsRtlInitializeLargeMcb
    ),
    export!(Implemented, fsrtl::mcb::FsRtlUninitializeLargeMcb),
    export!(Implemented, fsrtl::mcb::FsRtlResetLargeMcb),
    export_entry!(
        Implemented,
        "FsRtlAddLargeMcbEntry",
        arch::seh::nk_entry_FsRtlAddLargeMcbEntry
    ),
    export_entry!(
        Implemented,
        "FsRtlRemoveLargeMcbEntry",
        arch::seh::nk_entry_FsRtlRemoveLargeMcbEntry
    ),
    export_entry!(
        Implemented,
        "FsRtlTruncateLargeMcb",
        arch::seh::nk_entry_FsRtlTruncateLargeMcb
    ),
    export!(Implemented, fsrtl::mcb::FsRtlLookupLargeMcbEntry),
    export!(
        Implemented,
        fsrtl::mcb::FsRtlLookupLastLargeMcbEntryAndIndex
    ),
    export!(Implemented, fsrtl::mcb::FsRtlGetNextLargeMcbEntry),
    export!(Implemented, fsrtl::mcb::FsRtlNumberOfRunsInLargeMcb),
    export!(Implemented, fsrtl::name::FsRtlDissectName),
    export!(Implemented, fsrtl::name::FsRtlAreNamesEqual),
    export!(Implemented, fsrtl::name::FsRtlDoesNameContainWildCards),
    export!(Partial, fsrtl::name::FsRtlIsFatDbcsLegal),
    export!(Implemented, fsrtl::name::FsRtlIsDbcsInExpression),
    export!(Implemented, fsrtl::lock::FsRtlInitializeFileLock),
    export!(Partial, fsrtl::lock::FsRtlUninitializeFileLock),
    export!(Partial, fsrtl::lock::FsRtlCheckLockForReadAccess),
    export!(Partial, fsrtl::lock::FsRtlCheckLockForWriteAccess),
    export!(Partial, fsrtl::lock::FsRtlCheckLockForOplockRequest),
    export!(Partial, fsrtl::lock::FsRtlFastCheckLockForRead),
    export!(Partial, fsrtl::lock::FsRtlFastCheckLockForWrite),
    export!(Partial, fsrtl::lock::FsRtlAreThereWaitingFileLocks),
    export!(Partial, fsrtl::lock::FsRtlFastUnlockSingle),
    export!(Partial, fsrtl::lock::FsRtlFastUnlockAll),
    export!(Partial, fsrtl::lock::FsRtlFastUnlockAllByKey),
    export!(Implemented, fsrtl::oplock::FsRtlInitializeOplock),
    export!(Partial, fsrtl::oplock::FsRtlUninitializeOplock),
    export!(Partial, fsrtl::oplock::FsRtlCheckOplock),
    export!(Partial, fsrtl::oplock::FsRtlCheckOplockEx),
    export!(Partial, fsrtl::oplock::FsRtlOplockBreakH),
    export!(Partial, fsrtl::oplock::FsRtlOplockIsFastIoPossible),
    export!(Partial, fsrtl::oplock::FsRtlCurrentBatchOplock),
    export!(Partial, fsrtl::oplock::FsRtlCurrentOplockH),
    export!(Implemented, fsrtl::oplock::FsRtlOplockIsSharedRequest),
    export!(Implemented, fsrtl::notify::FsRtlNotifyInitializeSync),
    export!(Implemented, fsrtl::notify::FsRtlNotifyUninitializeSync),
    export!(Partial, fsrtl::notify::FsRtlNotifyFullReportChange),
    export!(Partial, fsrtl::notify::FsRtlNotifyCleanup),
    export!(Implemented, fsrtl::tunnel::FsRtlInitializeTunnelCache),
    export!(Implemented, fsrtl::tunnel::FsRtlDeleteTunnelCache),
    export!(Implemented, fsrtl::tunnel::FsRtlAddToTunnelCache),
    export!(Implemented, fsrtl::tunnel::FsRtlFindInTunnelCache),
    export!(Implemented, fsrtl::tunnel::FsRtlDeleteKeyFromTunnelCache),
    export!(Partial, fsrtl::volume::FsRtlNotifyVolumeEvent),
    export!(Partial, fsrtl::device::FsRtlVolumeDeviceToCorrelationId),
    export!(Implemented, fsrtl::device::FsRtlGetEcpListFromIrp),
    export!(
        Implemented,
        fsrtl::device::FsRtlAreVolumeStartupApplicationsComplete
    ),
    export!(Implemented, fsrtl::device::FsRtlUpdateDiskCounters),
    export!(Implemented, fsrtl::status::FsRtlIsNtstatusExpected),
    export!(Implemented, fsrtl::status::FsRtlNormalizeNtstatus),
    export!(Implemented, fsrtl::status::FsRtlIsTotalDeviceFailure),
];
