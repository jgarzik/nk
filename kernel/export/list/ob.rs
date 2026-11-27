//! Exports implemented in `kernel/ob`.

use super::super::{Export, NT, State};
use crate::ob;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export_variable!(
        Implemented,
        "ExEventObjectType",
        ob::object::ExEventObjectType
    ),
    export!(Implemented, ob::object::IoGetFileObjectGenericMapping),
    export!(Implemented, ob::security::ObDereferenceSecurityDescriptor),
    export!(Implemented, ob::security::ObLogSecurityDescriptor),
    export!(Implemented, ob::handle::ObReferenceObjectByHandle),
    export!(Implemented, ob::handle::ObReferenceObjectByHandleWithTag),
    export!(Implemented, ob::security::ObReferenceSecurityDescriptor),
    export!(Implemented, ob::object::ObfDereferenceObject),
    export!(Implemented, ob::object::ObfDereferenceObjectWithTag),
    export!(Implemented, ob::object::ObfReferenceObject),
    export!(Implemented, ob::object::ObfReferenceObjectWithTag),
    export_variable!(Implemented, "PsJobType", ob::object::PsJobType),
    export_variable!(Implemented, "PsThreadType", ob::object::PsThreadType),
    export_variable!(Implemented, "PsProcessType", ob::object::PsProcessType),
    export!(Partial, ob::event::ZwCreateEvent),
    export!(Partial, ob::event::ZwOpenEvent),
    export_variable!(
        Implemented,
        "IoDeviceObjectType",
        ob::object::IoDeviceObjectType
    ),
    export!(Implemented, ob::handle::ObOpenObjectByPointer),
    export_variable!(
        Implemented,
        "IoFileObjectType",
        ob::object::IoFileObjectType
    ),
    export!(Implemented, ob::object::ObReferenceObjectByPointer),
    export!(Partial, ob::event::ZwWaitForSingleObject),
    export!(Partial, ob::directory::ZwCreateDirectoryObject),
    export!(Partial, ob::directory::ZwMakeTemporaryObject),
];
