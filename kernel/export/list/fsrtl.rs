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
];
