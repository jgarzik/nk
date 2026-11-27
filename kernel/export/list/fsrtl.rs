//! Exports implemented in `kernel/fsrtl`.

use super::super::{Export, NT, State};
use crate::fsrtl;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Implemented, fsrtl::FsRtlIsSystemPagingFile),
    export!(Partial, fsrtl::FsRtlGetVirtualDiskNestingLevel),
    export!(Implemented, fsrtl::FsRtlTeardownPerStreamContexts),
    export!(
        Implemented,
        fsrtl::filter::FsRtlRegisterFileSystemFilterCallbacks
    ),
];
