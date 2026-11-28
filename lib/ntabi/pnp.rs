//! Plug and Play and power requests: the minor function codes of
//! `IRP_MJ_PNP` and `IRP_MJ_POWER`, what each keeps in its stack
//! location's `Parameters`, and the structures those point to.
//!
//! The definitions are the WDK's (`wdm.h`); x86-64 and arm64 share
//! them. Microsoft documents each request under
//! [Plug and Play minor IRPs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/plug-and-play-minor-irps)
//! and
//! [power management minor IRPs](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/power-management-minor-irps).
//!
//! `Parameters` is four 8-byte slots (`io::IO_STACK_LOCATION`); the
//! functions here encode each request's members into them and say
//! where the members are. The parameter structures are anonymous in
//! the kernel's symbols, so their offsets are the header's, stated in
//! the tests below.

use crate::io::{DEVICE_OBJECT, PVOID, UNICODE_STRING};
use core::ffi::c_void;

/// Minor functions of `IRP_MJ_PNP`.
pub const IRP_MN_START_DEVICE: u8 = 0x00;
pub const IRP_MN_QUERY_REMOVE_DEVICE: u8 = 0x01;
pub const IRP_MN_REMOVE_DEVICE: u8 = 0x02;
pub const IRP_MN_CANCEL_REMOVE_DEVICE: u8 = 0x03;
pub const IRP_MN_STOP_DEVICE: u8 = 0x04;
pub const IRP_MN_QUERY_STOP_DEVICE: u8 = 0x05;
pub const IRP_MN_CANCEL_STOP_DEVICE: u8 = 0x06;
pub const IRP_MN_QUERY_DEVICE_RELATIONS: u8 = 0x07;
pub const IRP_MN_QUERY_INTERFACE: u8 = 0x08;
pub const IRP_MN_QUERY_CAPABILITIES: u8 = 0x09;
pub const IRP_MN_QUERY_RESOURCES: u8 = 0x0A;
pub const IRP_MN_QUERY_RESOURCE_REQUIREMENTS: u8 = 0x0B;
pub const IRP_MN_QUERY_DEVICE_TEXT: u8 = 0x0C;
pub const IRP_MN_FILTER_RESOURCE_REQUIREMENTS: u8 = 0x0D;
pub const IRP_MN_READ_CONFIG: u8 = 0x0F;
pub const IRP_MN_WRITE_CONFIG: u8 = 0x10;
pub const IRP_MN_EJECT: u8 = 0x11;
pub const IRP_MN_SET_LOCK: u8 = 0x12;
pub const IRP_MN_QUERY_ID: u8 = 0x13;
pub const IRP_MN_QUERY_PNP_DEVICE_STATE: u8 = 0x14;
pub const IRP_MN_QUERY_BUS_INFORMATION: u8 = 0x15;
pub const IRP_MN_DEVICE_USAGE_NOTIFICATION: u8 = 0x16;
pub const IRP_MN_SURPRISE_REMOVAL: u8 = 0x17;
pub const IRP_MN_DEVICE_ENUMERATED: u8 = 0x19;

/// Minor functions of `IRP_MJ_POWER`.
pub const IRP_MN_WAIT_WAKE: u8 = 0x00;
pub const IRP_MN_POWER_SEQUENCE: u8 = 0x01;
pub const IRP_MN_SET_POWER: u8 = 0x02;
pub const IRP_MN_QUERY_POWER: u8 = 0x03;

/// `DEVICE_RELATION_TYPE`: which relations `IRP_MN_QUERY_DEVICE_RELATIONS`
/// asks for.
pub const BUS_RELATIONS: u32 = 0;
pub const EJECTION_RELATIONS: u32 = 1;
pub const POWER_RELATIONS: u32 = 2;
pub const REMOVAL_RELATIONS: u32 = 3;
pub const TARGET_DEVICE_RELATION: u32 = 4;
pub const SINGLE_BUS_RELATIONS: u32 = 5;
pub const TRANSPORT_RELATIONS: u32 = 6;

/// `BUS_QUERY_ID_TYPE`: which identifier `IRP_MN_QUERY_ID` asks for.
pub const BUS_QUERY_DEVICE_ID: u32 = 0;
pub const BUS_QUERY_HARDWARE_IDS: u32 = 1;
pub const BUS_QUERY_COMPATIBLE_IDS: u32 = 2;
pub const BUS_QUERY_INSTANCE_ID: u32 = 3;
pub const BUS_QUERY_DEVICE_SERIAL_NUMBER: u32 = 4;
pub const BUS_QUERY_CONTAINER_ID: u32 = 5;

/// `DEVICE_TEXT_TYPE`: which text `IRP_MN_QUERY_DEVICE_TEXT` asks for.
pub const DEVICE_TEXT_DESCRIPTION: u32 = 0;
pub const DEVICE_TEXT_LOCATION_INFORMATION: u32 = 1;

/// `DEVICE_USAGE_NOTIFICATION_TYPE`: the special file
/// `IRP_MN_DEVICE_USAGE_NOTIFICATION` is about.
pub const DEVICE_USAGE_TYPE_UNDEFINED: u32 = 0;
pub const DEVICE_USAGE_TYPE_PAGING: u32 = 1;
pub const DEVICE_USAGE_TYPE_HIBERNATION: u32 = 2;
pub const DEVICE_USAGE_TYPE_DUMP_FILE: u32 = 3;
pub const DEVICE_USAGE_TYPE_BOOT: u32 = 4;
pub const DEVICE_USAGE_TYPE_POST_DISPLAY: u32 = 5;
pub const DEVICE_USAGE_TYPE_GUEST_ASSIGNED: u32 = 6;

/// `IRP_MN_READ_CONFIG` and `IRP_MN_WRITE_CONFIG`: which configuration
/// space (`PCI_WHICHSPACE_*`).
pub const PCI_WHICHSPACE_CONFIG: u32 = 0;
pub const PCI_WHICHSPACE_ROM: u32 = 0x5269_6350;

/// `POWER_STATE_TYPE`: whether a power request is about the system's
/// state or the device's.
pub const POWER_STATE_TYPE_SYSTEM: u32 = 0;
pub const POWER_STATE_TYPE_DEVICE: u32 = 1;

/// `SYSTEM_POWER_STATE`.
pub const POWER_SYSTEM_UNSPECIFIED: u32 = 0;
pub const POWER_SYSTEM_WORKING: u32 = 1;
pub const POWER_SYSTEM_SLEEPING1: u32 = 2;
pub const POWER_SYSTEM_SLEEPING2: u32 = 3;
pub const POWER_SYSTEM_SLEEPING3: u32 = 4;
pub const POWER_SYSTEM_HIBERNATE: u32 = 5;
pub const POWER_SYSTEM_SHUTDOWN: u32 = 6;
pub const POWER_SYSTEM_MAXIMUM: u32 = 7;

/// `DEVICE_POWER_STATE`.
pub const POWER_DEVICE_UNSPECIFIED: u32 = 0;
pub const POWER_DEVICE_D0: u32 = 1;
pub const POWER_DEVICE_D1: u32 = 2;
pub const POWER_DEVICE_D2: u32 = 3;
pub const POWER_DEVICE_D3: u32 = 4;
pub const POWER_DEVICE_MAXIMUM: u32 = 5;

/// `POWER_ACTION`: why the system's power state changes.
pub const POWER_ACTION_NONE: u32 = 0;
pub const POWER_ACTION_RESERVED: u32 = 1;
pub const POWER_ACTION_SLEEP: u32 = 2;
pub const POWER_ACTION_HIBERNATE: u32 = 3;
pub const POWER_ACTION_SHUTDOWN: u32 = 4;
pub const POWER_ACTION_SHUTDOWN_RESET: u32 = 5;
pub const POWER_ACTION_SHUTDOWN_OFF: u32 = 6;
pub const POWER_ACTION_WARM_EJECT: u32 = 7;
pub const POWER_ACTION_DISPLAY_OFF: u32 = 8;

/// `Parameters.StartDevice`: AllocatedResources,
/// AllocatedResourcesTranslated (two `CM_RESOURCE_LIST` pointers).
pub const fn start_device_parameters(raw: u64, translated: u64) -> [u64; 4] {
    [raw, translated, 0, 0]
}

/// `Parameters.QueryDeviceRelations`: Type (`DEVICE_RELATION_TYPE`).
pub const fn query_device_relations_parameters(relation: u32) -> [u64; 4] {
    [relation as u64, 0, 0, 0]
}

/// `Parameters.QueryInterface`: InterfaceType (a GUID's address), Size
/// and Version (16 bits each, sharing a slot), Interface (where the
/// `INTERFACE` is to be written), InterfaceSpecificData.
pub const fn query_interface_parameters(
    interface_type: u64,
    size: u16,
    version: u16,
    interface: u64,
    specific_data: u64,
) -> [u64; 4] {
    [
        interface_type,
        size as u64 | (version as u64) << 16,
        interface,
        specific_data,
    ]
}

/// `Parameters.DeviceCapabilities`: Capabilities (a
/// `DEVICE_CAPABILITIES` to fill in).
pub const fn device_capabilities_parameters(capabilities: u64) -> [u64; 4] {
    [capabilities, 0, 0, 0]
}

/// `Parameters.FilterResourceRequirements`: IoResourceRequirementList.
pub const fn filter_resource_requirements_parameters(list: u64) -> [u64; 4] {
    [list, 0, 0, 0]
}

/// `Parameters.ReadWriteConfig`: WhichSpace, Buffer, Offset, Length,
/// each in a slot of its own.
pub const fn read_write_config_parameters(
    which_space: u32,
    buffer: u64,
    offset: u32,
    length: u32,
) -> [u64; 4] {
    [which_space as u64, buffer, offset as u64, length as u64]
}

/// `Parameters.SetLock`: Lock (a `BOOLEAN`).
pub const fn set_lock_parameters(lock: bool) -> [u64; 4] {
    [lock as u64, 0, 0, 0]
}

/// `Parameters.QueryId`: IdType (`BUS_QUERY_ID_TYPE`).
pub const fn query_id_parameters(id_type: u32) -> [u64; 4] {
    [id_type as u64, 0, 0, 0]
}

/// `Parameters.QueryDeviceText`: DeviceTextType, LocaleId.
pub const fn query_device_text_parameters(text_type: u32, locale: u32) -> [u64; 4] {
    [text_type as u64, locale as u64, 0, 0]
}

/// `Parameters.UsageNotification`: InPath (a `BOOLEAN`), Type
/// (`DEVICE_USAGE_NOTIFICATION_TYPE`).
pub const fn usage_notification_parameters(in_path: bool, usage: u32) -> [u64; 4] {
    [in_path as u64, usage as u64, 0, 0]
}

/// `Parameters.WaitWake`: PowerState (the lowest `SYSTEM_POWER_STATE`
/// the device can wake the system from).
pub const fn wait_wake_parameters(system_state: u32) -> [u64; 4] {
    [system_state as u64, 0, 0, 0]
}

/// `Parameters.PowerSequence`: PowerSequence (a `POWER_SEQUENCE` to
/// fill in).
pub const fn power_sequence_parameters(sequence: u64) -> [u64; 4] {
    [sequence, 0, 0, 0]
}

/// `Parameters.Power`: SystemContext, Type (`POWER_STATE_TYPE`), State
/// (a `POWER_STATE`), ShutdownType (`POWER_ACTION`), each in a slot of
/// its own.
pub const fn power_parameters(
    system_context: u32,
    state_type: u32,
    state: u32,
    shutdown_type: u32,
) -> [u64; 4] {
    [
        system_context as u64,
        state_type as u64,
        state as u64,
        shutdown_type as u64,
    ]
}

/// [`DEVICE_RELATIONS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_device_relations):
/// what a driver answers `IRP_MN_QUERY_DEVICE_RELATIONS` with, in
/// paged pool: a count, and that many referenced device objects.
#[repr(C)]
pub struct DEVICE_RELATIONS {
    pub Count: u32,
    pub Objects: [*mut DEVICE_OBJECT; 1],
}

/// How many bytes a `DEVICE_RELATIONS` with `count` objects takes.
pub const fn device_relations_size(count: usize) -> usize {
    core::mem::offset_of!(DEVICE_RELATIONS, Objects) + count * size_of::<*mut DEVICE_OBJECT>()
}

/// `POWER_STATE`: a system power state or a device power state, by the
/// request it travels in.
#[repr(C)]
#[derive(Clone, Copy)]
pub union POWER_STATE {
    pub SystemState: u32,
    pub DeviceState: u32,
}

/// [`REQUEST_POWER_COMPLETE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nc-wdm-request_power_complete):
/// the completion function a driver gives `PoRequestPowerIrp`: the
/// device it named, the minor function, the `POWER_STATE` (one 32-bit
/// value), its context, the request's status block.
pub type REQUEST_POWER_COMPLETE = unsafe extern "C" fn(
    *mut DEVICE_OBJECT,
    u8,
    u32,
    *mut core::ffi::c_void,
    *mut crate::io::IO_STATUS_BLOCK,
);

/// `POWER_SEQUENCE`: how often the device has left each low-power
/// state.
#[repr(C)]
pub struct POWER_SEQUENCE {
    pub SequenceD1: u32,
    pub SequenceD2: u32,
    pub SequenceD3: u32,
}

/// `DEVICE_CAPABILITIES.Flags`: the bit fields that follow `Version`,
/// first bit lowest.
pub const DEVICE_CAPABILITY_DEVICE_D1: u32 = 1 << 0;
pub const DEVICE_CAPABILITY_DEVICE_D2: u32 = 1 << 1;
pub const DEVICE_CAPABILITY_LOCK_SUPPORTED: u32 = 1 << 2;
pub const DEVICE_CAPABILITY_EJECT_SUPPORTED: u32 = 1 << 3;
pub const DEVICE_CAPABILITY_REMOVABLE: u32 = 1 << 4;
pub const DEVICE_CAPABILITY_DOCK_DEVICE: u32 = 1 << 5;
pub const DEVICE_CAPABILITY_UNIQUE_ID: u32 = 1 << 6;
pub const DEVICE_CAPABILITY_SILENT_INSTALL: u32 = 1 << 7;
pub const DEVICE_CAPABILITY_RAW_DEVICE_OK: u32 = 1 << 8;
pub const DEVICE_CAPABILITY_SURPRISE_REMOVAL_OK: u32 = 1 << 9;
pub const DEVICE_CAPABILITY_WAKE_FROM_D0: u32 = 1 << 10;
pub const DEVICE_CAPABILITY_WAKE_FROM_D1: u32 = 1 << 11;
pub const DEVICE_CAPABILITY_WAKE_FROM_D2: u32 = 1 << 12;
pub const DEVICE_CAPABILITY_WAKE_FROM_D3: u32 = 1 << 13;
pub const DEVICE_CAPABILITY_HARDWARE_DISABLED: u32 = 1 << 14;
pub const DEVICE_CAPABILITY_NON_DYNAMIC: u32 = 1 << 15;
pub const DEVICE_CAPABILITY_WARM_EJECT_SUPPORTED: u32 = 1 << 16;
pub const DEVICE_CAPABILITY_NO_DISPLAY_IN_UI: u32 = 1 << 17;

/// [`DEVICE_CAPABILITIES`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_device_capabilities):
/// what the drivers of a stack fill in for `IRP_MN_QUERY_CAPABILITIES`.
/// Whoever sends the request sets `Size`, `Version` (1), and `Address`
/// and `UINumber` to all ones.
#[repr(C)]
pub struct DEVICE_CAPABILITIES {
    pub Size: u16,
    pub Version: u16,
    /// The `DEVICE_CAPABILITY_*` bits.
    pub Flags: u32,
    pub Address: u32,
    pub UINumber: u32,
    /// The device power state for each system power state.
    pub DeviceState: [u32; POWER_SYSTEM_MAXIMUM as usize],
    pub SystemWake: u32,
    pub DeviceWake: u32,
    pub D1Latency: u32,
    pub D2Latency: u32,
    pub D3Latency: u32,
}

/// [`INTERFACE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_interface):
/// the head of every interface a driver hands out for
/// `IRP_MN_QUERY_INTERFACE`; the interface's own routines follow it.
#[repr(C)]
pub struct INTERFACE {
    pub Size: u16,
    pub Version: u16,
    pub Context: PVOID,
    pub InterfaceReference: Option<unsafe extern "C" fn(*mut c_void)>,
    pub InterfaceDereference: Option<unsafe extern "C" fn(*mut c_void)>,
}

/// [`BUS_INTERFACE_STANDARD`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_bus_interface_standard):
/// what a bus driver hands out for `GUID_BUS_INTERFACE_STANDARD`: the
/// routines through which a device's drivers reach its bus. The
/// routines' types are the header's (`TRANSLATE_BUS_ADDRESS`,
/// `GET_DMA_ADAPTER`, `GET_SET_DEVICE_DATA`).
#[repr(C)]
pub struct BUS_INTERFACE_STANDARD {
    pub Header: INTERFACE,
    pub TranslateBusAddress: PVOID,
    pub GetDmaAdapter: PVOID,
    pub SetBusData: PVOID,
    pub GetBusData: PVOID,
}

const _: () = {
    assert!(size_of::<BUS_INTERFACE_STANDARD>() == 0x40);
    assert!(core::mem::offset_of!(BUS_INTERFACE_STANDARD, TranslateBusAddress) == 0x20);
    assert!(core::mem::offset_of!(BUS_INTERFACE_STANDARD, GetDmaAdapter) == 0x28);
    assert!(core::mem::offset_of!(BUS_INTERFACE_STANDARD, SetBusData) == 0x30);
    assert!(core::mem::offset_of!(BUS_INTERFACE_STANDARD, GetBusData) == 0x38);
};

/// `CM_PARTIAL_RESOURCE_DESCRIPTOR.Type` and
/// `IO_RESOURCE_DESCRIPTOR.Type` (`CmResourceType*`).
pub const CM_RESOURCE_TYPE_NULL: u8 = 0;
pub const CM_RESOURCE_TYPE_PORT: u8 = 1;
pub const CM_RESOURCE_TYPE_INTERRUPT: u8 = 2;
pub const CM_RESOURCE_TYPE_MEMORY: u8 = 3;
pub const CM_RESOURCE_TYPE_DMA: u8 = 4;
pub const CM_RESOURCE_TYPE_DEVICE_SPECIFIC: u8 = 5;
pub const CM_RESOURCE_TYPE_BUS_NUMBER: u8 = 6;
pub const CM_RESOURCE_TYPE_MEMORY_LARGE: u8 = 7;
pub const CM_RESOURCE_TYPE_CONFIG_DATA: u8 = 128;
pub const CM_RESOURCE_TYPE_DEVICE_PRIVATE: u8 = 129;

/// `ShareDisposition` (`CM_SHARE_DISPOSITION`).
pub const CM_RESOURCE_SHARE_UNDETERMINED: u8 = 0;
pub const CM_RESOURCE_SHARE_DEVICE_EXCLUSIVE: u8 = 1;
pub const CM_RESOURCE_SHARE_DRIVER_EXCLUSIVE: u8 = 2;
pub const CM_RESOURCE_SHARE_SHARED: u8 = 3;

/// [`CM_PARTIAL_RESOURCE_DESCRIPTOR`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_partial_resource_descriptor):
/// one resource a device was given. The header packs it to four bytes:
/// the union `u` starts at offset 4, and a 64-bit address in it is not
/// 8-byte aligned. It is kept as four 32-bit words, read by the
/// functions below.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CM_PARTIAL_RESOURCE_DESCRIPTOR {
    pub Type: u8,
    pub ShareDisposition: u8,
    pub Flags: u16,
    pub u: [u32; 4],
}

/// `u.Generic`, `u.Port`, `u.Memory`: Start (a `PHYSICAL_ADDRESS`),
/// Length.
pub const fn cm_range(start: u64, length: u32) -> [u32; 4] {
    [start as u32, (start >> 32) as u32, length, 0]
}

/// The start of a range resource (`u.Generic.Start`).
pub const fn cm_range_start(u: [u32; 4]) -> u64 {
    u[0] as u64 | (u[1] as u64) << 32
}

/// The length of a range resource (`u.Generic.Length`).
pub const fn cm_range_length(u: [u32; 4]) -> u32 {
    u[2]
}

/// `u.Interrupt`: Level and Group (16 bits each), Vector, Affinity (a
/// `KAFFINITY`).
pub const fn cm_interrupt(level: u16, group: u16, vector: u32, affinity: u64) -> [u32; 4] {
    [
        level as u32 | (group as u32) << 16,
        vector,
        affinity as u32,
        (affinity >> 32) as u32,
    ]
}

/// `CM_PARTIAL_RESOURCE_LIST`: a count and that many descriptors.
#[repr(C)]
pub struct CM_PARTIAL_RESOURCE_LIST {
    pub Version: u16,
    pub Revision: u16,
    pub Count: u32,
    pub PartialDescriptors: [CM_PARTIAL_RESOURCE_DESCRIPTOR; 1],
}

/// `CM_FULL_RESOURCE_DESCRIPTOR`: the resources of one device on one
/// bus.
#[repr(C)]
pub struct CM_FULL_RESOURCE_DESCRIPTOR {
    /// `INTERFACE_TYPE`.
    pub InterfaceType: u32,
    pub BusNumber: u32,
    pub PartialResourceList: CM_PARTIAL_RESOURCE_LIST,
}

/// [`CM_RESOURCE_LIST`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_cm_resource_list):
/// what `IRP_MN_START_DEVICE` hands a driver: a count of full
/// descriptors, each as long as its own count of partial descriptors
/// makes it.
#[repr(C)]
pub struct CM_RESOURCE_LIST {
    pub Count: u32,
    pub List: [CM_FULL_RESOURCE_DESCRIPTOR; 1],
}

/// How many bytes a `CM_RESOURCE_LIST` of one full descriptor with
/// `partial` partial descriptors takes: what a device on one bus is
/// started with.
pub const fn cm_resource_list_size(partial: usize) -> usize {
    core::mem::offset_of!(CM_RESOURCE_LIST, List)
        + core::mem::offset_of!(CM_FULL_RESOURCE_DESCRIPTOR, PartialResourceList)
        + core::mem::offset_of!(CM_PARTIAL_RESOURCE_LIST, PartialDescriptors)
        + partial * size_of::<CM_PARTIAL_RESOURCE_DESCRIPTOR>()
}

/// `IO_RESOURCE_DESCRIPTOR.Option`.
pub const IO_RESOURCE_PREFERRED: u8 = 0x01;
pub const IO_RESOURCE_DEFAULT: u8 = 0x02;
pub const IO_RESOURCE_ALTERNATIVE: u8 = 0x08;

/// [`IO_RESOURCE_DESCRIPTOR`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_resource_descriptor):
/// one resource a device needs, as a range of what would do. The union
/// `u` is kept as three 64-bit words; a range (`u.Generic`, `u.Port`,
/// `u.Memory`) is Length and Alignment in the first, then
/// MinimumAddress and MaximumAddress.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IO_RESOURCE_DESCRIPTOR {
    pub Option: u8,
    pub Type: u8,
    pub ShareDisposition: u8,
    pub Spare1: u8,
    pub Flags: u16,
    pub Spare2: u16,
    pub u: [u64; 3],
}

/// `u.Generic` of an `IO_RESOURCE_DESCRIPTOR`: Length, Alignment,
/// MinimumAddress, MaximumAddress.
pub const fn io_range(length: u32, alignment: u32, minimum: u64, maximum: u64) -> [u64; 3] {
    [length as u64 | (alignment as u64) << 32, minimum, maximum]
}

/// `IO_RESOURCE_LIST`: one alternative: a count and that many
/// descriptors.
#[repr(C)]
pub struct IO_RESOURCE_LIST {
    pub Version: u16,
    pub Revision: u16,
    pub Count: u32,
    pub Descriptors: [IO_RESOURCE_DESCRIPTOR; 1],
}

/// [`IO_RESOURCE_REQUIREMENTS_LIST`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_resource_requirements_list):
/// what a device needs, as alternative lists; `ListSize` is the bytes
/// of the whole.
#[repr(C)]
pub struct IO_RESOURCE_REQUIREMENTS_LIST {
    pub ListSize: u32,
    /// `INTERFACE_TYPE`.
    pub InterfaceType: u32,
    pub BusNumber: u32,
    pub SlotNumber: u32,
    pub Reserved: [u32; 3],
    pub AlternativeLists: u32,
    pub List: [IO_RESOURCE_LIST; 1],
}

const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(size_of::<DEVICE_RELATIONS>() == 0x10);
    assert!(offset_of!(DEVICE_RELATIONS, Objects) == 0x08);
    assert!(size_of::<POWER_STATE>() == 4);
    assert!(size_of::<POWER_SEQUENCE>() == 12);
    assert!(size_of::<DEVICE_CAPABILITIES>() == 0x40);
    assert!(offset_of!(DEVICE_CAPABILITIES, Version) == 0x02);
    assert!(offset_of!(DEVICE_CAPABILITIES, Flags) == 0x04);
    assert!(offset_of!(DEVICE_CAPABILITIES, Address) == 0x08);
    assert!(offset_of!(DEVICE_CAPABILITIES, UINumber) == 0x0C);
    assert!(offset_of!(DEVICE_CAPABILITIES, DeviceState) == 0x10);
    assert!(offset_of!(DEVICE_CAPABILITIES, SystemWake) == 0x2C);
    assert!(offset_of!(DEVICE_CAPABILITIES, DeviceWake) == 0x30);
    assert!(offset_of!(DEVICE_CAPABILITIES, D1Latency) == 0x34);
    assert!(offset_of!(DEVICE_CAPABILITIES, D3Latency) == 0x3C);
    assert!(size_of::<INTERFACE>() == 0x20);
    assert!(offset_of!(INTERFACE, Context) == 0x08);
    assert!(offset_of!(INTERFACE, InterfaceReference) == 0x10);
    assert!(offset_of!(INTERFACE, InterfaceDereference) == 0x18);
    assert!(size_of::<CM_PARTIAL_RESOURCE_DESCRIPTOR>() == 20);
    assert!(align_of::<CM_PARTIAL_RESOURCE_DESCRIPTOR>() == 4);
    assert!(offset_of!(CM_PARTIAL_RESOURCE_DESCRIPTOR, Flags) == 2);
    assert!(offset_of!(CM_PARTIAL_RESOURCE_DESCRIPTOR, u) == 4);
    assert!(size_of::<CM_PARTIAL_RESOURCE_LIST>() == 28);
    assert!(offset_of!(CM_PARTIAL_RESOURCE_LIST, Count) == 4);
    assert!(offset_of!(CM_PARTIAL_RESOURCE_LIST, PartialDescriptors) == 8);
    assert!(size_of::<CM_FULL_RESOURCE_DESCRIPTOR>() == 36);
    assert!(offset_of!(CM_FULL_RESOURCE_DESCRIPTOR, PartialResourceList) == 8);
    assert!(size_of::<CM_RESOURCE_LIST>() == 40);
    assert!(offset_of!(CM_RESOURCE_LIST, List) == 4);
    assert!(size_of::<IO_RESOURCE_DESCRIPTOR>() == 32);
    assert!(offset_of!(IO_RESOURCE_DESCRIPTOR, Flags) == 4);
    assert!(offset_of!(IO_RESOURCE_DESCRIPTOR, u) == 8);
    assert!(size_of::<IO_RESOURCE_LIST>() == 40);
    assert!(offset_of!(IO_RESOURCE_LIST, Descriptors) == 8);
    assert!(size_of::<IO_RESOURCE_REQUIREMENTS_LIST>() == 72);
    assert!(offset_of!(IO_RESOURCE_REQUIREMENTS_LIST, AlternativeLists) == 28);
    assert!(offset_of!(IO_RESOURCE_REQUIREMENTS_LIST, List) == 32);
};

/// `DEVICE_NODE` (private): what Windows keeps of a device, which a
/// physical device object's `DeviceObjectExtension->DeviceNode` points
/// to. Microsoft's drivers read the front of it: `partmgr.sys` follows
/// `Parent` to the parent's `PhysicalDeviceObject`. NK keeps the tree's
/// links and the device in it; the rest is zero.
#[repr(C)]
pub struct DEVICE_NODE {
    pub Sibling: *mut DEVICE_NODE,
    pub Child: *mut DEVICE_NODE,
    pub Parent: *mut DEVICE_NODE,
    pub LastChild: *mut DEVICE_NODE,
    pub PhysicalDeviceObject: *mut DEVICE_OBJECT,
    pub Rest: [u8; 0x310 - 0x28],
}

const _: () = {
    assert!(size_of::<DEVICE_NODE>() == 0x310);
    assert!(core::mem::offset_of!(DEVICE_NODE, Parent) == 0x10);
    assert!(core::mem::offset_of!(DEVICE_NODE, PhysicalDeviceObject) == 0x20);
};

/// [`DEVPROPKEY`](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/devpropkey):
/// the name of a device property: its category, a GUID, and its number
/// in the category.
#[repr(C)]
pub struct DEVPROPKEY {
    pub fmtid: [u8; 16],
    pub pid: u32,
}

const _: () = {
    assert!(size_of::<DEVPROPKEY>() == 20);
    assert!(core::mem::offset_of!(DEVPROPKEY, pid) == 16);
};

/// `IO_NOTIFICATION_EVENT_CATEGORY`.
pub const EVENT_CATEGORY_HARDWARE_PROFILE_CHANGE: u32 = 0;
pub const EVENT_CATEGORY_DEVICE_INTERFACE_CHANGE: u32 = 2;
pub const EVENT_CATEGORY_TARGET_DEVICE_CHANGE: u32 = 3;

/// [`TARGET_DEVICE_CUSTOM_NOTIFICATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_target_device_custom_notification):
/// a custom event a driver reports for a device. `Size` covers the
/// header and the data after it; the kernel fills `FileObject` in for
/// each registration it tells.
#[repr(C)]
pub struct TARGET_DEVICE_CUSTOM_NOTIFICATION {
    pub Version: u16,
    pub Size: u16,
    pub Event: [u8; 16],
    pub FileObject: *mut crate::io::FILE_OBJECT,
    /// Where in `CustomDataBuffer` a name starts, or -1 for none.
    pub NameBufferOffset: i32,
    pub CustomDataBuffer: [u8; 1],
}

/// The bytes of a [`TARGET_DEVICE_CUSTOM_NOTIFICATION`] before its data.
pub const TARGET_DEVICE_CUSTOM_HEADER: usize = 0x24;

/// [`TARGET_DEVICE_REMOVAL_NOTIFICATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_target_device_removal_notification):
/// delivered to `EVENT_CATEGORY_TARGET_DEVICE_CHANGE` registrations on device removal.
#[repr(C)]
pub struct TARGET_DEVICE_REMOVAL_NOTIFICATION {
    pub Version: u16,
    pub Size: u16,
    pub Event: [u8; 16],
    pub FileObject: *mut crate::io::FILE_OBJECT,
}

const _: () = {
    assert!(size_of::<TARGET_DEVICE_REMOVAL_NOTIFICATION>() == 0x20);
    assert!(core::mem::offset_of!(TARGET_DEVICE_REMOVAL_NOTIFICATION, Event) == 4);
    assert!(core::mem::offset_of!(TARGET_DEVICE_REMOVAL_NOTIFICATION, FileObject) == 0x18);
};

/// The predefined target-device events, which a driver may not report:
/// `GUID_TARGET_DEVICE_QUERY_REMOVE` (`{cb3a4009-46f0-11d0-b08f-00609713053f}`),
/// `..._REMOVE_CANCELLED` (`...400a...`) and `..._REMOVE_COMPLETE`
/// (`...400b...`).
pub const GUID_TARGET_DEVICE_QUERY_REMOVE: [u8; 16] = [
    0x09, 0x40, 0x3A, 0xCB, 0xF0, 0x46, 0xD0, 0x11, 0xB0, 0x8F, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3F,
];
pub const GUID_TARGET_DEVICE_REMOVE_CANCELLED: [u8; 16] = [
    0x0A, 0x40, 0x3A, 0xCB, 0xF0, 0x46, 0xD0, 0x11, 0xB0, 0x8F, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3F,
];
pub const GUID_TARGET_DEVICE_REMOVE_COMPLETE: [u8; 16] = [
    0x0B, 0x40, 0x3A, 0xCB, 0xF0, 0x46, 0xD0, 0x11, 0xB0, 0x8F, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3F,
];

const _: () = {
    assert!(core::mem::offset_of!(TARGET_DEVICE_CUSTOM_NOTIFICATION, Event) == 4);
    assert!(core::mem::offset_of!(TARGET_DEVICE_CUSTOM_NOTIFICATION, FileObject) == 0x18);
    assert!(core::mem::offset_of!(TARGET_DEVICE_CUSTOM_NOTIFICATION, NameBufferOffset) == 0x20);
    assert!(
        core::mem::offset_of!(TARGET_DEVICE_CUSTOM_NOTIFICATION, CustomDataBuffer)
            == TARGET_DEVICE_CUSTOM_HEADER
    );
};

/// `PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES`.
pub const PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES: u32 = 1;

/// `GUID_DEVICE_INTERFACE_ARRIVAL`, `GUID_DEVICE_INTERFACE_REMOVAL`
/// (`{cb3a4004-46f0-11d0-b08f-00609713053f}` and `...4005...`).
pub const GUID_DEVICE_INTERFACE_ARRIVAL: [u8; 16] = [
    0x04, 0x40, 0x3a, 0xcb, 0xf0, 0x46, 0xd0, 0x11, 0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f,
];
pub const GUID_DEVICE_INTERFACE_REMOVAL: [u8; 16] = [
    0x05, 0x40, 0x3a, 0xcb, 0xf0, 0x46, 0xd0, 0x11, 0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f,
];

/// [`DEVICE_INTERFACE_CHANGE_NOTIFICATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_device_interface_change_notification):
/// what a callback registered for interface changes is handed.
#[repr(C)]
pub struct DEVICE_INTERFACE_CHANGE_NOTIFICATION {
    pub Version: u16,
    pub Size: u16,
    pub Event: [u8; 16],
    pub InterfaceClassGuid: [u8; 16],
    pub SymbolicLinkName: *mut UNICODE_STRING,
}

const _: () = {
    assert!(size_of::<DEVICE_INTERFACE_CHANGE_NOTIFICATION>() == 48);
    assert!(core::mem::offset_of!(DEVICE_INTERFACE_CHANGE_NOTIFICATION, Event) == 4);
    assert!(core::mem::offset_of!(DEVICE_INTERFACE_CHANGE_NOTIFICATION, SymbolicLinkName) == 40);
};

/// [`CONFIGURATION_INFORMATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_configuration_information):
/// the system's counts of devices of the old kinds, which the drivers
/// of such devices read and write in place
/// (`IoGetConfigurationInformation`). `Version` is the structure's
/// size, as the pinned kernel's own copy starts out.
#[repr(C)]
pub struct CONFIGURATION_INFORMATION {
    pub DiskCount: u32,
    pub FloppyCount: u32,
    pub CdRomCount: u32,
    pub TapeCount: u32,
    pub ScsiPortCount: u32,
    pub SerialCount: u32,
    pub ParallelCount: u32,
    pub AtDiskPrimaryAddressClaimed: u8,
    pub AtDiskSecondaryAddressClaimed: u8,
    pub Version: u32,
    pub MediumChangerCount: u32,
}

const _: () = {
    assert!(size_of::<CONFIGURATION_INFORMATION>() == 0x28);
    assert!(core::mem::offset_of!(CONFIGURATION_INFORMATION, AtDiskPrimaryAddressClaimed) == 0x1C);
    assert!(core::mem::offset_of!(CONFIGURATION_INFORMATION, Version) == 0x20);
    assert!(core::mem::offset_of!(CONFIGURATION_INFORMATION, MediumChangerCount) == 0x24);
};

#[cfg(test)]
mod tests {
    use super::*;

    /// The members of each request's parameters at the offsets `wdm.h`
    /// gives them on 64-bit Windows: a member the header marks
    /// `POINTER_ALIGNMENT` starts a slot.
    #[test]
    fn parameters_are_where_the_header_puts_them() {
        assert_eq!(
            start_device_parameters(0x1000, 0x2000),
            [0x1000, 0x2000, 0, 0]
        );
        assert_eq!(
            query_device_relations_parameters(TARGET_DEVICE_RELATION),
            [4, 0, 0, 0]
        );
        // Size at +8, Version at +10, Interface at +16, the specific
        // data at +24.
        assert_eq!(
            query_interface_parameters(0x1000, 0x40, 2, 0x2000, 0x3000),
            [0x1000, 0x0002_0040, 0x2000, 0x3000]
        );
        assert_eq!(device_capabilities_parameters(0x1000), [0x1000, 0, 0, 0]);
        assert_eq!(
            filter_resource_requirements_parameters(0x1000),
            [0x1000, 0, 0, 0]
        );
        // WhichSpace +0, Buffer +8, Offset +16, Length +24.
        assert_eq!(
            read_write_config_parameters(PCI_WHICHSPACE_CONFIG, 0x1000, 0x3C, 4),
            [0, 0x1000, 0x3C, 4]
        );
        assert_eq!(set_lock_parameters(true), [1, 0, 0, 0]);
        assert_eq!(query_id_parameters(BUS_QUERY_HARDWARE_IDS), [1, 0, 0, 0]);
        // DeviceTextType +0, LocaleId +8.
        assert_eq!(
            query_device_text_parameters(DEVICE_TEXT_LOCATION_INFORMATION, 0x409),
            [1, 0x409, 0, 0]
        );
        // InPath +0, Type +8.
        assert_eq!(
            usage_notification_parameters(true, DEVICE_USAGE_TYPE_PAGING),
            [1, 1, 0, 0]
        );
        assert_eq!(wait_wake_parameters(POWER_SYSTEM_SLEEPING3), [4, 0, 0, 0]);
        assert_eq!(power_sequence_parameters(0x1000), [0x1000, 0, 0, 0]);
        // SystemContext +0, Type +8, State +16, ShutdownType +24.
        assert_eq!(
            power_parameters(
                7,
                POWER_STATE_TYPE_DEVICE,
                POWER_DEVICE_D3,
                POWER_ACTION_SHUTDOWN
            ),
            [7, 1, 4, 4]
        );
    }

    #[test]
    fn resources_are_read_where_the_packed_header_puts_them() {
        // A memory range above 4 GiB: Start at +4 of the descriptor,
        // Length at +12.
        let u = cm_range(0x1_F000_0000, 0x2000);
        assert_eq!(u, [0xF000_0000, 1, 0x2000, 0]);
        assert_eq!(cm_range_start(u), 0x1_F000_0000);
        assert_eq!(cm_range_length(u), 0x2000);
        // Level +4, Group +6, Vector +8, Affinity +12.
        assert_eq!(
            cm_interrupt(9, 1, 0x39, 0x1_0000_0003),
            [0x0001_0009, 0x39, 3, 1]
        );
        assert_eq!(PCI_WHICHSPACE_ROM.to_le_bytes(), *b"PciR");
        // Length +8 of the descriptor, Alignment +12, the addresses
        // +16 and +24.
        assert_eq!(
            io_range(0x100, 0x10, 0xD000, 0xDFFF),
            [0x0000_0010_0000_0100, 0xD000, 0xDFFF]
        );
    }

    #[test]
    fn lists_are_as_long_as_their_counts() {
        assert_eq!(device_relations_size(0), 8);
        assert_eq!(device_relations_size(1), size_of::<DEVICE_RELATIONS>());
        assert_eq!(device_relations_size(3), 32);
        // One descriptor is what the structure itself holds.
        assert_eq!(cm_resource_list_size(1), size_of::<CM_RESOURCE_LIST>());
        assert_eq!(cm_resource_list_size(0), 20);
        assert_eq!(cm_resource_list_size(4), 20 + 4 * 20);
        // The capability bits, as the kernel's symbols number them.
        assert_eq!(DEVICE_CAPABILITY_REMOVABLE, 0x10);
        assert_eq!(DEVICE_CAPABILITY_RAW_DEVICE_OK, 0x100);
        assert_eq!(DEVICE_CAPABILITY_SURPRISE_REMOVAL_OK, 0x200);
        assert_eq!(DEVICE_CAPABILITY_NO_DISPLAY_IN_UI, 0x2_0000);
    }
}
