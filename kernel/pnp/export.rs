//! What drivers call on the Plug and Play manager.

#![allow(non_snake_case)]

use super::node::{self, Node};
use super::{engine, registry};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use nk_ntabi::io::{DEVICE_OBJECT, UNICODE_STRING};
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::pnp::{
    BUS_RELATIONS, CONFIGURATION_INFORMATION, DEVICE_CAPABILITY_REMOVABLE, DEVPROPKEY,
};
use nk_ntabi::status::*;
use nk_pnp::ids;

/// [`IoInvalidateDeviceRelations`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioinvalidatedevicerelations):
/// the relations of `device`, a physical device object, have changed.
/// For `BusRelations` the device is asked for its children again, by a
/// worker thread, some time after this returns; callable at
/// `DISPATCH_LEVEL`. A device that is not started when its turn comes
/// is not asked: it is asked when it starts.
///
/// The other relation types change nothing NK keeps: ejection, power
/// and removal relations are asked for when a device is ejected,
/// powered or removed, none of which NK does.
///
/// # Safety
/// `device` is a live device object.
pub unsafe extern "C" fn IoInvalidateDeviceRelations(device: *mut DEVICE_OBJECT, relation: u32) {
    // SAFETY: per the contract.
    unsafe {
        crate::io::device::check(device, "IoInvalidateDeviceRelations");
        if relation == BUS_RELATIONS {
            engine::enumerate_later(device);
        }
    }
}

/// The node of `device`, which must be a physical device object the
/// manager knows: Windows refuses any other device
/// (`STATUS_INVALID_DEVICE_REQUEST`).
fn node_of(device: *mut DEVICE_OBJECT) -> Result<Node, NTSTATUS> {
    node::get(device as usize).ok_or(STATUS_INVALID_DEVICE_REQUEST)
}

/// `DEVICE_REGISTRY_PROPERTY`.
const DEVICE_DESCRIPTION: u32 = 0;
const HARDWARE_ID: u32 = 1;
const COMPATIBLE_IDS: u32 = 2;
const BOOT_CONFIGURATION: u32 = 3;
const CLASS_NAME: u32 = 5;
const CLASS_GUID: u32 = 6;
const DRIVER_KEY_NAME: u32 = 7;
const MANUFACTURER: u32 = 8;
const FRIENDLY_NAME: u32 = 9;
const LOCATION_INFORMATION: u32 = 10;
const PHYSICAL_DEVICE_OBJECT_NAME: u32 = 11;
const BUS_TYPE_GUID: u32 = 12;
const LEGACY_BUS_TYPE: u32 = 13;
const BUS_NUMBER: u32 = 14;
const ENUMERATOR_NAME: u32 = 15;
const ADDRESS: u32 = 16;
const UI_NUMBER: u32 = 17;
const INSTALL_STATE: u32 = 18;
const REMOVAL_POLICY: u32 = 19;
const RESOURCE_REQUIREMENTS: u32 = 20;
const ALLOCATED_RESOURCES: u32 = 21;
const CONTAINER_ID: u32 = 22;

/// `InstallStateInstalled`, `InstallStateFailedInstall`.
const INSTALL_STATE_INSTALLED: u32 = 0;
const INSTALL_STATE_FAILED: u32 = 2;
/// `RemovalPolicyExpectNoRemoval`, `RemovalPolicyExpectSurpriseRemoval`.
const EXPECT_NO_REMOVAL: u32 = 1;
const EXPECT_SURPRISE_REMOVAL: u32 = 3;

fn wide_bytes(text: &str) -> Vec<u8> {
    ids::sz(text)
}

/// The value of a property of the device `found`, as the bytes
/// `IoGetDeviceProperty` hands out. `None`: the device has no such
/// property.
fn property(found: &Node, device: *mut DEVICE_OBJECT, which: u32) -> Option<Vec<u8>> {
    let key = registry::enum_key(&found.instance);
    // A string of the device's key. Device installation writes a
    // description and a manufacturer as `@inf,%token%;text`.
    // INFERRED: that Windows hands out the text behind the `;`; taken
    // from what its drivers print, not read in its code.
    let string = |name: &str| {
        registry::string(&key, name).map(|text| {
            let plain = match text.split_once(';') {
                Some((indirect, plain)) if indirect.starts_with('@') => plain,
                _ => &text,
            };
            wide_bytes(plain)
        })
    };
    let raw = |name: &str| crate::cm::read(&key, name).ok().map(|(_, data)| data);
    let filled = |bytes: &Vec<u8>| (!bytes.is_empty()).then(|| bytes.clone());
    match which {
        DEVICE_DESCRIPTION => string("DeviceDesc"),
        HARDWARE_ID => raw("HardwareID"),
        COMPATIBLE_IDS => raw("CompatibleIDs"),
        BOOT_CONFIGURATION => filled(&found.boot),
        CLASS_NAME => found
            .class
            .as_deref()
            .and_then(|class| registry::string(&registry::class_key(class), "Class"))
            .map(|name| wide_bytes(&name)),
        CLASS_GUID => string("ClassGUID"),
        DRIVER_KEY_NAME => string("Driver"),
        MANUFACTURER => string("Mfg"),
        FRIENDLY_NAME => string("FriendlyName"),
        LOCATION_INFORMATION => string("LocationInformation"),
        PHYSICAL_DEVICE_OBJECT_NAME => {
            // A device without a name has an empty one, as on Windows.
            // SAFETY: a live device object.
            let name = unsafe { device_name(device) };
            Some(name.map(|name| wide_bytes(&name)).unwrap_or_default())
        }
        BUS_TYPE_GUID => found.bus.map(|bus| bus.bus_type.to_vec()),
        LEGACY_BUS_TYPE => found
            .bus
            .map(|bus| bus.legacy_bus_type.to_le_bytes().to_vec()),
        BUS_NUMBER => found.bus.map(|bus| bus.bus_number.to_le_bytes().to_vec()),
        ENUMERATOR_NAME => found.instance.split('\\').next().map(wide_bytes),
        ADDRESS => (found.address != u32::MAX).then(|| found.address.to_le_bytes().to_vec()),
        UI_NUMBER => (found.ui_number != u32::MAX).then(|| found.ui_number.to_le_bytes().to_vec()),
        INSTALL_STATE => {
            let installed = found.service.is_some() || found.class.is_some();
            let state = if installed {
                INSTALL_STATE_INSTALLED
            } else {
                INSTALL_STATE_FAILED
            };
            Some(state.to_le_bytes().to_vec())
        }
        REMOVAL_POLICY => {
            let removable = found.capabilities & DEVICE_CAPABILITY_REMOVABLE != 0;
            let policy = if removable {
                EXPECT_SURPRISE_REMOVAL
            } else {
                EXPECT_NO_REMOVAL
            };
            Some(policy.to_le_bytes().to_vec())
        }
        RESOURCE_REQUIREMENTS => filled(&found.requirements),
        ALLOCATED_RESOURCES => filled(&found.raw),
        CONTAINER_ID => string("ContainerID"),
        _ => None,
    }
}

/// [`IoGetDeviceProperty`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetdeviceproperty):
/// a property of the device whose physical device object is `device`.
/// `result_length` gets the property's size; a buffer too small for it
/// gets nothing (`STATUS_BUFFER_TOO_SMALL`).
///
/// - `STATUS_INVALID_DEVICE_REQUEST`: `device` is not a physical device
///   object the manager has a node for.
/// - `STATUS_INVALID_PARAMETER_2`: no such property, or the translated
///   boot configuration (`DevicePropertyBootConfigurationTranslated`),
///   which NK does not keep.
/// - `STATUS_OBJECT_NAME_NOT_FOUND`: the device has no value for it.
///
/// # Safety
/// `device` is a live device object; `buffer` is writable for
/// `buffer_length` bytes; `result_length` is writable.
pub unsafe extern "C" fn IoGetDeviceProperty(
    device: *mut DEVICE_OBJECT,
    which: u32,
    buffer_length: u32,
    buffer: *mut u8,
    result_length: *mut u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        crate::io::device::check(device, "IoGetDeviceProperty");
        result_length.write_unaligned(0);
        let found = match node_of(device) {
            Ok(found) => found,
            Err(status) => return status,
        };
        if which > CONTAINER_ID || which == 4 {
            return STATUS_INVALID_PARAMETER_2;
        }
        let Some(value) = property(&found, device, which) else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        result_length.write_unaligned(value.len() as u32);
        if value.len() > buffer_length as usize {
            return STATUS_BUFFER_TOO_SMALL;
        }
        buffer.copy_from_nonoverlapping(value.as_ptr(), value.len());
    }
    STATUS_SUCCESS
}

/// `PLUGPLAY_REGKEY_DEVICE`, `PLUGPLAY_REGKEY_DRIVER`,
/// `PLUGPLAY_REGKEY_CURRENT_HWPROFILE`.
const REGKEY_DEVICE: u32 = 1;
const REGKEY_DRIVER: u32 = 2;
const REGKEY_CURRENT_HWPROFILE: u32 = 4;

/// [`IoOpenDeviceRegistryKey`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioopendeviceregistrykey):
/// a handle to a key of the device whose physical device object is
/// `device`: its `Device Parameters` key (`PLUGPLAY_REGKEY_DEVICE`),
/// made if it is not there, or its driver key under its class
/// (`PLUGPLAY_REGKEY_DRIVER`), which a device that was never installed
/// does not have (`STATUS_OBJECT_NAME_NOT_FOUND`).
///
/// NK has one hardware profile: with
/// `PLUGPLAY_REGKEY_CURRENT_HWPROFILE` the request stops the system
/// rather than open a key Windows would not.
///
/// # Safety
/// `device` is a live device object; `handle` is writable.
pub unsafe extern "C" fn IoOpenDeviceRegistryKey(
    device: *mut DEVICE_OBJECT,
    key_type: u32,
    desired_access: u32,
    handle: *mut *mut core::ffi::c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        crate::io::device::check(device, "IoOpenDeviceRegistryKey");
        handle.write_unaligned(core::ptr::null_mut());
    }
    let found = match node_of(device) {
        Ok(found) => found,
        Err(status) => return status,
    };
    let control_set = "\\Registry\\Machine\\System\\CurrentControlSet";
    let path = match key_type {
        REGKEY_DEVICE => format!("{control_set}\\Enum\\{}\\Device Parameters", found.instance),
        REGKEY_DRIVER => {
            let key = registry::enum_key(&found.instance);
            match registry::string(&key, "Driver") {
                Some(driver) => format!("{control_set}\\Control\\Class\\{driver}"),
                None => return STATUS_OBJECT_NAME_NOT_FOUND,
            }
        }
        _ if key_type & REGKEY_CURRENT_HWPROFILE != 0 => crate::kd::bugcheck(format_args!(
            "IoOpenDeviceRegistryKey: NK has no hardware profiles (key type {key_type:#x} for {})",
            found.instance
        )),
        _ => return STATUS_INVALID_PARAMETER,
    };
    let mut name: Vec<u16> = path.encode_utf16().collect();
    let name = UNICODE_STRING {
        Length: (name.len() * 2) as u16,
        MaximumLength: (name.len() * 2) as u16,
        Buffer: name.as_mut_ptr(),
    };
    /// `OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE`.
    const ATTRIBUTES: u32 = 0x40 | 0x200;
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: core::ptr::null_mut(),
        ObjectName: &raw const name,
        Attributes: ATTRIBUTES,
        SecurityDescriptor: core::ptr::null_mut(),
        SecurityQualityOfService: core::ptr::null_mut(),
    };
    // SAFETY: the attributes and the name they point to live to the end
    // of the call; `handle` is the caller's.
    unsafe {
        if key_type == REGKEY_DEVICE {
            crate::cm::ZwCreateKey(
                handle,
                desired_access,
                &raw const attributes,
                0,
                core::ptr::null(),
                0,
                core::ptr::null_mut(),
            )
        } else {
            crate::cm::ZwOpenKey(handle, desired_access, &raw const attributes)
        }
    }
}

/// [`IoInvalidateDeviceState`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioinvalidatedevicestate):
/// the state of the device whose physical device object is `device`
/// has changed. A started device is sent
/// `IRP_MN_QUERY_PNP_DEVICE_STATE` again, by a worker thread, and one
/// its drivers then call failed, disabled or removed is taken down;
/// for a device that is not started nothing is done, as on Windows.
///
/// Of the other state bits, NK acts on none: it does not rebalance
/// resources (`PNP_RESOURCE_REQUIREMENTS_CHANGED`) and has no user
/// interface to hide a device from.
///
/// Windows stops the system for a device that is not a physical
/// device object (`PNP_DETECTED_FATAL_ERROR`); so does NK.
///
/// # Safety
/// `device` is a live device object.
pub unsafe extern "C" fn IoInvalidateDeviceState(device: *mut DEVICE_OBJECT) {
    // SAFETY: per the contract.
    unsafe {
        crate::io::device::check(device, "IoInvalidateDeviceState");
        if node::get(device as usize).is_none() {
            crate::kd::bugcheck(format_args!(
                "0x000000CA PNP_DETECTED_FATAL_ERROR: IoInvalidateDeviceState for {device:p}, \
                 which is not a physical device object"
            ));
        }
        engine::requery_later(device);
    }
}

/// [`IoGetDeviceNumaNode`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetdevicenumanode):
/// the NUMA node of the device whose physical device object is
/// `device`. NK records no node for a device, and Windows' answer for
/// such a device is node 0 on a machine with one node and
/// `STATUS_NOT_FOUND` on any other.
///
/// # Safety
/// `device` is null or a live device object; `node_number` is writable.
pub unsafe extern "C" fn IoGetDeviceNumaNode(
    device: *mut DEVICE_OBJECT,
    node_number: *mut u16,
) -> NTSTATUS {
    if device.is_null() || node::get(device as usize).is_none() {
        return STATUS_INVALID_PARAMETER;
    }
    if crate::ke::smp::KeQueryHighestNodeNumber() != 0 {
        return STATUS_NOT_FOUND;
    }
    // SAFETY: per the contract.
    unsafe { node_number.write_unaligned(0) };
    STATUS_SUCCESS
}

/// `DEVPROP_TYPE_EMPTY`: no value; setting it deletes the property.
const DEVPROP_TYPE_EMPTY: u32 = 0;
/// What a property's registry value carries its type in front of.
const DEVPROP_REGISTRY_TYPE: u32 = 0xFFFF_0000;

/// The key a device's property is kept in, as Windows keeps it:
/// `Properties\{category}\NNNN` under the device's key, the value
/// without a name, its registry type the property's type behind
/// `0xFFFF`.
///
/// # Safety
/// `key` points to a `DEVPROPKEY`.
unsafe fn property_key(found: &Node, key: *const DEVPROPKEY) -> String {
    // SAFETY: per the contract; a driver may pack the key.
    let (fmtid, pid) = unsafe {
        (
            (&raw const (*key).fmtid).read_unaligned(),
            (&raw const (*key).pid).read_unaligned(),
        )
    };
    format!(
        "{}\\Properties\\{}\\{pid:04X}",
        registry::enum_key(&found.instance),
        ids::guid_text(&fmtid)
    )
}

/// [`IoSetDevicePropertyData`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iosetdevicepropertydata):
/// give the device whose physical device object is `device` the
/// property `key`, of type `kind`, or with `DEVPROP_TYPE_EMPTY` take
/// it away. The property is kept in the device's key; NK's registry is
/// never written out, so `PLUGPLAY_PROPERTY_PERSISTENT` changes
/// nothing.
///
/// The properties Windows computes from what it knows of a device (the
/// `DEVPKEY_Device_*` set) are not special here: one a driver sets is
/// kept like any other.
///
/// INFERRED: `STATUS_INVALID_DEVICE_REQUEST` for a device that is not
/// a physical device object, and `STATUS_INVALID_PARAMETER` for a
/// locale other than neutral, which the pinned kernel sends down an
/// error path NK did not follow to its status.
///
/// # Safety
/// `device` is a live device object; `key` points to a `DEVPROPKEY`;
/// `data` is readable for `size` bytes.
pub unsafe extern "C" fn IoSetDevicePropertyData(
    device: *mut DEVICE_OBJECT,
    key: *const DEVPROPKEY,
    lcid: u32,
    _flags: u32,
    kind: u32,
    size: u32,
    data: *const u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        crate::io::device::check(device, "IoSetDevicePropertyData");
        let found = match node_of(device) {
            Ok(found) => found,
            Err(status) => return status,
        };
        if lcid != 0 || key.is_null() || (size != 0 && data.is_null()) {
            return STATUS_INVALID_PARAMETER;
        }
        let path = property_key(&found, key);
        if kind == DEVPROP_TYPE_EMPTY {
            return match crate::cm::delete_tree(&path) {
                Ok(()) => STATUS_SUCCESS,
                Err(status) => status,
            };
        }
        let mut value = alloc::vec![0u8; size as usize];
        data.copy_to_nonoverlapping(value.as_mut_ptr(), value.len());
        match crate::cm::write_path(
            &path,
            &[("", DEVPROP_REGISTRY_TYPE | (kind & 0xFFFF), &value)],
        ) {
            Ok(()) => STATUS_SUCCESS,
            Err(status) => status,
        }
    }
}

/// [`IoGetDevicePropertyData`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetdevicepropertydata):
/// the property `key` of the device whose physical device object is
/// `device`: its type, its size, and, if `size` bytes are room enough,
/// its value (else `STATUS_BUFFER_TOO_SMALL`). A property the device
/// was not given is not found (`STATUS_OBJECT_NAME_NOT_FOUND`, as the
/// pinned kernel answers).
///
/// Only properties that were set are found: NK computes none of the
/// properties Windows derives from what it knows of a device.
///
/// # Safety
/// `device` is a live device object; `key` points to a `DEVPROPKEY`;
/// `data` is writable for `size` bytes; `required_size` and `kind`
/// are writable or null.
pub unsafe extern "C" fn IoGetDevicePropertyData(
    device: *mut DEVICE_OBJECT,
    key: *const DEVPROPKEY,
    lcid: u32,
    _flags: u32,
    size: u32,
    data: *mut u8,
    required_size: *mut u32,
    kind: *mut u32,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        crate::io::device::check(device, "IoGetDevicePropertyData");
        let report = |length: u32, found: u32| {
            if !required_size.is_null() {
                required_size.write_unaligned(length);
            }
            if !kind.is_null() {
                kind.write_unaligned(found);
            }
        };
        report(0, DEVPROP_TYPE_EMPTY);
        let found = match node_of(device) {
            Ok(found) => found,
            Err(status) => return status,
        };
        if lcid != 0 || key.is_null() {
            return STATUS_INVALID_PARAMETER;
        }
        let Ok((stored, value)) = crate::cm::read(&property_key(&found, key), "") else {
            return STATUS_OBJECT_NAME_NOT_FOUND;
        };
        report(value.len() as u32, stored & 0xFFFF);
        if value.len() > size as usize {
            return STATUS_BUFFER_TOO_SMALL;
        }
        data.copy_from_nonoverlapping(value.as_ptr(), value.len());
    }
    STATUS_SUCCESS
}

/// The name of the device `device` in the object namespace, if it has
/// one.
///
/// # Safety
/// `device` is a live device object.
pub unsafe fn device_name(device: *mut DEVICE_OBJECT) -> Option<String> {
    // SAFETY: per the contract; a named object's name is a counted
    // string that stays while the object does.
    let name = unsafe {
        let info = crate::ob::object::name_info(device.cast());
        if info.is_null() {
            return None;
        }
        crate::rtl::copy_unicode(&raw const (*info).Name)
    };
    (!name.is_empty()).then(|| format!("\\Device\\{}", String::from_utf16_lossy(&name)))
}

/// The system's `CONFIGURATION_INFORMATION`: drivers' to read and
/// write through the pointer `IoGetConfigurationInformation` hands
/// out, so NK reaches it by pointer only.
struct Configuration(core::cell::UnsafeCell<CONFIGURATION_INFORMATION>);

// SAFETY: the structure is the drivers' memory; NK neither reads nor
// writes it after handing its address out.
unsafe impl Sync for Configuration {}

static CONFIGURATION: Configuration =
    Configuration(core::cell::UnsafeCell::new(CONFIGURATION_INFORMATION {
        DiskCount: 0,
        FloppyCount: 0,
        CdRomCount: 0,
        TapeCount: 0,
        ScsiPortCount: 0,
        SerialCount: 0,
        ParallelCount: 0,
        AtDiskPrimaryAddressClaimed: 0,
        AtDiskSecondaryAddressClaimed: 0,
        Version: size_of::<CONFIGURATION_INFORMATION>() as u32,
        MediumChangerCount: 0,
    }));

/// [`IoGetConfigurationInformation`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-iogetconfigurationinformation):
/// the one `CONFIGURATION_INFORMATION` of the system, which class and
/// port drivers count their devices in. All counts start at zero.
pub extern "C" fn IoGetConfigurationInformation() -> *mut CONFIGURATION_INFORMATION {
    CONFIGURATION.0.get()
}
