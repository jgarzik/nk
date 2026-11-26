//! Exports implemented in `kernel/pnp`.

use super::super::{Export, NT, State};
use crate::pnp;

pub(in crate::export) static EXPORTS: &[Export] = &[
    export!(Implemented, pnp::export::IoGetConfigurationInformation),
    export!(Implemented, pnp::export::IoGetDeviceNumaNode),
    export!(Implemented, pnp::export::IoGetDeviceProperty),
    export!(Partial, pnp::export::IoGetDevicePropertyData),
    export!(Implemented, pnp::export::IoInvalidateDeviceRelations),
    export!(Implemented, pnp::export::IoInvalidateDeviceState),
    export!(Implemented, pnp::export::IoOpenDeviceRegistryKey),
    export!(Implemented, pnp::interface::IoRegisterDeviceInterface),
    export!(Partial, pnp::depend::IoReserveDependency),
    export!(Partial, pnp::depend::IoResolveDependency),
    export!(Partial, pnp::depend::IoSetDependency),
    export!(Partial, pnp::notify::IoRegisterPlugPlayNotification),
    export!(
        Implemented,
        pnp::interface::IoSetDeviceInterfacePropertyData
    ),
    export!(Implemented, pnp::interface::IoSetDeviceInterfaceState),
    export!(Implemented, pnp::notify::IoUnregisterPlugPlayNotification),
    export!(Implemented, pnp::notify::IoUnregisterPlugPlayNotificationEx),
    export!(Implemented, pnp::export::IoSetDevicePropertyData),
];
