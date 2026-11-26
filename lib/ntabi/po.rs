//! The runtime power framework's structures: what a driver hands
//! [`PoFxRegisterDevice`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-pofxregisterdevice).
//!
//! Layouts are the WDK's (`wdm.h`); the pinned kernel's
//! `PoFxRegisterDevice` reads the fields at these offsets.

use crate::ex::GUID;
use core::ffi::c_void;

/// `PO_FX_VERSION_V1`, `_V2`, `_V3`: the first field of a
/// `PO_FX_DEVICE`, which says which of the three layouts follows.
pub const PO_FX_VERSION_V1: u32 = 1;
pub const PO_FX_VERSION_V2: u32 = 2;
pub const PO_FX_VERSION_V3: u32 = 3;

/// The callbacks every version of `PO_FX_DEVICE` carries, in the order
/// they lie in the structure:
/// [`ComponentActiveConditionCallback`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-po_fx_component_active_condition_callback),
/// `ComponentIdleConditionCallback`, `ComponentIdleStateCallback`,
/// `DevicePowerRequiredCallback`, `DevicePowerNotRequiredCallback`,
/// `PowerControlCallback`. Each is null or a routine.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PO_FX_CALLBACKS {
    pub ComponentActiveConditionCallback: *mut c_void,
    pub ComponentIdleConditionCallback: *mut c_void,
    pub ComponentIdleStateCallback: *mut c_void,
    pub DevicePowerRequiredCallback: *mut c_void,
    pub DevicePowerNotRequiredCallback: *mut c_void,
    pub PowerControlCallback: *mut c_void,
}

/// `PO_FX_COMPONENT_ACTIVE_CONDITION_CALLBACK` and
/// `PO_FX_COMPONENT_IDLE_CONDITION_CALLBACK`: the device's context and
/// the component's index.
pub type PO_FX_COMPONENT_CONDITION_CALLBACK = unsafe extern "C" fn(*mut c_void, u32);

/// [`PO_FX_DEVICE_V1`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_po_fx_device_v1),
/// up to its components: `ComponentCount` `PO_FX_COMPONENT_V1` follow.
#[repr(C)]
pub struct PO_FX_DEVICE_V1 {
    pub Version: u32,
    pub ComponentCount: u32,
    pub Callbacks: PO_FX_CALLBACKS,
    pub DeviceContext: *mut c_void,
}

/// [`PO_FX_DEVICE_V2`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_po_fx_device_v2),
/// up to its components: `ComponentCount` `PO_FX_COMPONENT_V2` follow.
#[repr(C)]
pub struct PO_FX_DEVICE_V2 {
    pub Version: u32,
    pub Flags: u64,
    pub Callbacks: PO_FX_CALLBACKS,
    pub DeviceContext: *mut c_void,
    pub ComponentCount: u32,
}

/// [`PO_FX_DEVICE_V3`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_po_fx_device_v3),
/// up to its components: `ComponentCount` `PO_FX_COMPONENT_V2` follow.
#[repr(C)]
pub struct PO_FX_DEVICE_V3 {
    pub Version: u32,
    pub Flags: u64,
    pub Callbacks: PO_FX_CALLBACKS,
    pub DirectedPowerUpCallback: *mut c_void,
    pub DirectedPowerDownCallback: *mut c_void,
    pub DirectedFxTimeoutInSeconds: u32,
    pub DeviceContext: *mut c_void,
    pub ComponentCount: u32,
}

/// Where the components of each version start.
pub const PO_FX_DEVICE_V1_COMPONENTS: usize = 0x40;
pub const PO_FX_DEVICE_V2_COMPONENTS: usize = 0x50;
pub const PO_FX_DEVICE_V3_COMPONENTS: usize = 0x68;

/// [`PO_FX_COMPONENT_IDLE_STATE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_po_fx_component_idle_state):
/// one F-state of a component.
#[repr(C)]
pub struct PO_FX_COMPONENT_IDLE_STATE {
    pub TransitionLatency: u64,
    pub ResidencyRequirement: u64,
    pub NominalPower: u32,
}

/// [`PO_FX_COMPONENT_V1`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_po_fx_component_v1).
#[repr(C)]
pub struct PO_FX_COMPONENT_V1 {
    pub Id: GUID,
    pub IdleStateCount: u32,
    pub DeepestWakeableIdleState: u32,
    pub IdleStates: *mut PO_FX_COMPONENT_IDLE_STATE,
}

/// [`PO_FX_COMPONENT_V2`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_po_fx_component_v2).
#[repr(C)]
pub struct PO_FX_COMPONENT_V2 {
    pub Id: GUID,
    pub Flags: u64,
    pub DeepestWakeableIdleState: u32,
    pub IdleStateCount: u32,
    pub IdleStates: *mut PO_FX_COMPONENT_IDLE_STATE,
    pub ProviderCount: u32,
    pub Providers: *mut u32,
}

const _: () = {
    use core::mem::offset_of;
    assert!(size_of::<PO_FX_CALLBACKS>() == 0x30);
    assert!(offset_of!(PO_FX_DEVICE_V1, ComponentCount) == 0x04);
    assert!(offset_of!(PO_FX_DEVICE_V1, Callbacks) == 0x08);
    assert!(offset_of!(PO_FX_DEVICE_V1, DeviceContext) == 0x38);
    assert!(size_of::<PO_FX_DEVICE_V1>() == PO_FX_DEVICE_V1_COMPONENTS);
    assert!(offset_of!(PO_FX_DEVICE_V2, Flags) == 0x08);
    assert!(offset_of!(PO_FX_DEVICE_V2, Callbacks) == 0x10);
    assert!(offset_of!(PO_FX_DEVICE_V2, DeviceContext) == 0x40);
    assert!(offset_of!(PO_FX_DEVICE_V2, ComponentCount) == 0x48);
    assert!(size_of::<PO_FX_DEVICE_V2>() == PO_FX_DEVICE_V2_COMPONENTS);
    assert!(offset_of!(PO_FX_DEVICE_V3, Callbacks) == 0x10);
    assert!(offset_of!(PO_FX_DEVICE_V3, DirectedPowerUpCallback) == 0x40);
    assert!(offset_of!(PO_FX_DEVICE_V3, DirectedPowerDownCallback) == 0x48);
    assert!(offset_of!(PO_FX_DEVICE_V3, DirectedFxTimeoutInSeconds) == 0x50);
    assert!(offset_of!(PO_FX_DEVICE_V3, DeviceContext) == 0x58);
    assert!(offset_of!(PO_FX_DEVICE_V3, ComponentCount) == 0x60);
    assert!(size_of::<PO_FX_DEVICE_V3>() == PO_FX_DEVICE_V3_COMPONENTS);
    assert!(size_of::<PO_FX_COMPONENT_IDLE_STATE>() == 0x18);
    assert!(size_of::<PO_FX_COMPONENT_V1>() == 0x20);
    assert!(offset_of!(PO_FX_COMPONENT_V1, IdleStateCount) == 0x10);
    assert!(offset_of!(PO_FX_COMPONENT_V1, DeepestWakeableIdleState) == 0x14);
    assert!(size_of::<PO_FX_COMPONENT_V2>() == 0x38);
    assert!(offset_of!(PO_FX_COMPONENT_V2, DeepestWakeableIdleState) == 0x18);
    assert!(offset_of!(PO_FX_COMPONENT_V2, IdleStateCount) == 0x1C);
    assert!(offset_of!(PO_FX_COMPONENT_V2, ProviderCount) == 0x28);
    assert!(offset_of!(PO_FX_COMPONENT_V2, Providers) == 0x30);
};
