//! Exports implemented in `kernel/io`.

use super::super::{Export, NT, State};
use crate::io;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Partial, io::mdl::IoAllocateMdl),
    export!(Implemented, io::device::IoCreateDevice),
    export!(Implemented, io::symlink::IoCreateSymbolicLink),
    export!(Implemented, io::device::IoDeleteDevice),
    export!(Implemented, io::symlink::IoDeleteSymbolicLink),
    export!(Implemented, io::remlock::IoAcquireRemoveLockEx),
    export!(Implemented, io::wmi::IoWMIDeviceObjectToProviderId),
    export!(Partial, io::wmi::IoWMIRegistrationControl),
    export!(Implemented, io::wmi::IoWMIWriteEvent),
    export!(Implemented, io::irp::IoAllocateIrp),
    export!(Implemented, io::irp::IoFreeIrp),
    export!(Implemented, io::mdl::IoFreeMdl),
    export!(Implemented, io::file::IoGetDeviceObjectPointer),
    export!(Implemented, io::irp::IoGetRequestorProcess),
    export!(Implemented, io::remlock::IoInitializeRemoveLockEx),
    export!(Implemented, io::remlock::IoReleaseRemoveLockAndWaitEx),
    export!(Implemented, io::remlock::IoReleaseRemoveLockEx),
    export!(Implemented, io::irp::IoReleaseCancelSpinLock),
    export!(Implemented, io::irp::IofCallDriver),
    export!(Implemented, io::irp::IofCompleteRequest),
    export!(Partial, io::mdl::MmMapLockedPagesSpecifyCache),
    export!(Implemented, io::mdl::MmUnlockPages),
    export!(Implemented, io::fsrtl::FsRtlTeardownPerStreamContexts),
    export!(Implemented, io::csq::IoCsqInitialize),
    export!(Implemented, io::csq::IoCsqInsertIrp),
    export!(Implemented, io::csq::IoCsqRemoveNextIrp),
    export!(Implemented, io::csq::IoIsWdmVersionAvailable),
];
