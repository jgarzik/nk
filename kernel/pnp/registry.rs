//! The registry the Plug and Play manager keeps: each device's key
//! under `Enum`, the driver database it finds a device's driver in,
//! the class keys, and each service's `Enum` subkey.
//!
//! Windows installs a device from its INF once (user mode does, with
//! the driver database's records of that INF) and at every later boot
//! finds what installation left in the device's key. NK's registry
//! starts without the keys of enumerated devices, so NK applies the
//! driver database's record when it first sees a device and writes the
//! values installation writes (`install`). `doc/design/pnp.md`.

use super::node::Node;
use crate::cm;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use nk_pnp::{database, ids};

const CONTROL_SET: &str = "Machine\\System\\CurrentControlSet";
/// The driver database: a hive of its own on Windows, reached as this
/// key.
const DATABASE: &str = "Machine\\System\\DriverDatabase";

pub const REG_SZ: u32 = 1;
pub const REG_DWORD: u32 = 4;
pub const REG_MULTI_SZ: u32 = 7;
pub const REG_RESOURCE_LIST: u32 = 8;
pub const REG_RESOURCE_REQUIREMENTS_LIST: u32 = 10;

/// The container every device that cannot be removed from the machine
/// is in: the machine itself.
const SYSTEM_CONTAINER: &str = "{00000000-0000-0000-ffff-ffffffffffff}";

/// The key of the device whose instance path is `instance`.
pub fn enum_key(instance: &str) -> String {
    format!("{CONTROL_SET}\\Enum\\{instance}")
}

/// The key of the device class `class`.
pub fn class_key(class: &str) -> String {
    format!("{CONTROL_SET}\\Control\\Class\\{class}")
}

/// The key of the service `service`.
pub fn service_key(service: &str) -> String {
    format!("{CONTROL_SET}\\Services\\{service}")
}

/// The text of the string value `name` of the key at `path`.
pub fn string(path: &str, name: &str) -> Option<String> {
    match cm::read(path, name) {
        Ok((REG_SZ | 2, data)) => Some(ids::from_sz(&data)),
        _ => None,
    }
}

/// The strings of the multi-string value `name` of the key at `path`;
/// a plain string counts as a list of one.
pub fn strings(path: &str, name: &str) -> Vec<String> {
    match cm::read(path, name) {
        Ok((REG_MULTI_SZ, data)) => ids::from_multi_sz(&data),
        Ok((REG_SZ, data)) => alloc::vec![ids::from_sz(&data)],
        _ => Vec::new(),
    }
}

/// The number the value `name` of the key at `path` holds.
pub fn dword(path: &str, name: &str) -> Option<u32> {
    match cm::read(path, name) {
        Ok((REG_DWORD, data)) => Some(u32::from_le_bytes(data.get(..4)?.try_into().ok()?)),
        _ => None,
    }
}

fn multi(strings: &[String]) -> Vec<u8> {
    ids::to_multi_sz(strings)
        .into_iter()
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// The prefix the children of the device `parent` (at `level`) carry
/// in their instance identifiers: the one in its key, or a new one,
/// which is then written there (`ParentIdPrefix`) and counted under
/// `Enum` (`NextParentID.<hash>.<level>`), as Windows does.
pub fn parent_prefix(parent: &str, level: u32) -> Result<String, i32> {
    let key = enum_key(parent);
    if let Some(prefix) = string(&key, "ParentIdPrefix") {
        return Ok(prefix);
    }
    let hash = ids::parent_hash(parent);
    let counter = ids::next_parent_id_value(level, hash);
    let enumeration = format!("{CONTROL_SET}\\Enum");
    let number = dword(&enumeration, &counter).unwrap_or(0);
    let prefix = ids::parent_id_prefix(level, hash, number);
    cm::write_path(
        &enumeration,
        &[(&counter, REG_DWORD, &(number + 1).to_le_bytes())],
    )?;
    cm::write_path(&key, &[("ParentIdPrefix", REG_SZ, &ids::sz(&prefix))])?;
    Ok(prefix)
}

/// Write what enumeration learned of a device into its key, creating
/// the key and the subkeys every device has.
pub fn write_identity(node: &Node) -> Result<(), i32> {
    let key = enum_key(&node.instance);
    let capabilities = ids::registry_capabilities(node.capabilities).to_le_bytes();
    let hardware = multi(&node.hardware_ids);
    let compatible = multi(&node.compatible_ids);
    let container = ids::sz(SYSTEM_CONTAINER);
    let mut values: Vec<(&str, u32, &[u8])> = Vec::new();
    values.push(("Capabilities", REG_DWORD, &capabilities));
    // A device that cannot be removed is in the machine's container.
    // (One that can gets a container of its own on Windows, made from
    // its identifiers: NK writes none.)
    if node.capabilities & nk_ntabi::pnp::DEVICE_CAPABILITY_REMOVABLE == 0 {
        values.push(("ContainerID", REG_SZ, &container));
    }
    if !node.hardware_ids.is_empty() {
        values.push(("HardwareID", REG_MULTI_SZ, &hardware));
    }
    if !node.compatible_ids.is_empty() {
        values.push(("CompatibleIDs", REG_MULTI_SZ, &compatible));
    }
    let location = node.location.as_deref().map(ids::sz);
    if let Some(location) = &location {
        values.push(("LocationInformation", REG_SZ, location));
    }
    let number = node.ui_number.to_le_bytes();
    if node.ui_number != u32::MAX {
        values.push(("UINumber", REG_DWORD, &number));
    }
    let address = node.address.to_le_bytes();
    if node.address != u32::MAX {
        values.push(("Address", REG_DWORD, &address));
    }
    // Until the device is installed, its description is the bus's.
    let description = node.description.as_deref().map(ids::sz);
    if let (Some(description), None) = (&description, string(&key, "DeviceDesc")) {
        values.push(("DeviceDesc", REG_SZ, description));
    }
    cm::write_path(&key, &values)?;
    for subkey in ["LogConf", "Control", "Device Parameters", "Properties"] {
        cm::write_path(&format!("{key}\\{subkey}"), &[])?;
    }
    let configuration = format!("{key}\\LogConf");
    if !node.boot.is_empty() {
        cm::write_path(
            &configuration,
            &[("BootConfig", REG_RESOURCE_LIST, &node.boot)],
        )?;
    }
    if !node.requirements.is_empty() {
        cm::write_path(
            &configuration,
            &[(
                "BasicConfigVector",
                REG_RESOURCE_REQUIREMENTS_LIST,
                &node.requirements,
            )],
        )?;
    }
    Ok(())
}

/// What the driver database says of a device.
#[derive(Debug, Clone)]
pub struct Record {
    /// The identifier that matched.
    pub id: String,
    pub inf: String,
    /// The configuration (the INF's install section).
    pub section: String,
    /// The key of that configuration.
    configuration: String,
    pub service: Option<String>,
    pub class: Option<String>,
    provider: Option<String>,
    description: Option<String>,
    manufacturer: Option<String>,
}

/// The record of the identifier `id`, if the database has one that may
/// be used for a device with these identifiers.
fn record(id: &str, hardware: &[String], compatible: &[String]) -> Option<Record> {
    // Which INF lists the identifier: the names of the key's values.
    let inf = cm::values(&format!("{DATABASE}\\DeviceIds\\{id}"))
        .into_iter()
        .map(|(name, _, _)| name)
        .find(|name| !name.is_empty())?;
    let package_name = string(&format!("{DATABASE}\\DriverInfFiles\\{inf}"), "Active")?;
    let package = format!("{DATABASE}\\DriverPackages\\{package_name}");
    let descriptor = format!("{package}\\Descriptors\\{id}");
    let section = string(&descriptor, "Configuration")?;
    let configuration = format!("{package}\\Configurations\\{section}");
    if !cm::exists(&configuration) {
        return None;
    }
    let exclude = strings(&configuration, "ExcludeIds");
    if database::excluded(&exclude, hardware, compatible) {
        return None;
    }
    let class = cm::read(&package, "Version")
        .ok()
        .and_then(|(_, version)| database::package_class(&version))
        .map(|guid| ids::guid_text(&guid));
    Some(Record {
        id: id.into(),
        inf,
        section,
        service: string(&configuration, "Service"),
        class,
        provider: string(&package, "Provider"),
        description: string(&descriptor, "Description"),
        manufacturer: string(&descriptor, "Manufacturer"),
        configuration,
    })
}

/// The driver database's record for a device with these identifiers:
/// that of its first hardware identifier that has one, else of its
/// first compatible identifier that has one.
pub fn find_driver(hardware: &[String], compatible: &[String]) -> Option<Record> {
    let matched = database::select(hardware, compatible, |id| {
        record(id, hardware, compatible).is_some()
    })?;
    record(&matched.id, hardware, compatible)
}

/// The driver key a newly installed device of `class` gets: the first
/// four-digit subkey of the class key that is not there.
fn new_driver_key(class: &str) -> Option<String> {
    let key = class_key(class);
    (0..10_000)
        .map(|number| format!("{number:04}"))
        .find(|number| !cm::exists(&format!("{key}\\{number}")))
        .map(|number| format!("{class}\\{number}"))
}

/// Install the device `node` from `record`: write into its key what
/// Windows' device installation writes (the service, the class, the
/// driver key, the description and the manufacturer as the INF names
/// them), make the driver key, and copy the configuration's device
/// settings into `Device Parameters`.
///
/// The text Windows puts behind the `;` of `DeviceDesc` and `Mfg` is
/// the INF's string, which the driver database does not hold: NK puts
/// the bus's description there, or nothing.
pub fn install(node: &Node, record: &Record) -> Result<(), i32> {
    let key = enum_key(&node.instance);
    let indirect = |token: &Option<String>, text: &str| {
        token
            .as_ref()
            .map(|token| ids::sz(&format!("@{},{token};{text}", record.inf)))
    };
    let description = indirect(
        &record.description,
        node.description.as_deref().unwrap_or(""),
    );
    let manufacturer = indirect(&record.manufacturer, "");
    let service = record.service.as_deref().map(ids::sz);
    let class = record.class.as_deref().map(ids::sz);
    let driver_key = record.class.as_deref().and_then(new_driver_key);
    let driver = driver_key.as_deref().map(ids::sz);
    let upper_filters = cm::read(&record.configuration, "UpperFilters").ok();
    let lower_filters = cm::read(&record.configuration, "LowerFilters").ok();
    let mut values: Vec<(&str, u32, &[u8])> = Vec::new();
    values.push(("ConfigFlags", REG_DWORD, &[0; 4]));
    for (name, data) in [
        ("Service", &service),
        ("ClassGUID", &class),
        ("Driver", &driver),
        ("DeviceDesc", &description),
        ("Mfg", &manufacturer),
    ] {
        if let Some(data) = data {
            values.push((name, REG_SZ, data));
        }
    }
    if let Some((kind, data)) = &upper_filters {
        values.push(("UpperFilters", *kind, data));
    }
    if let Some((kind, data)) = &lower_filters {
        values.push(("LowerFilters", *kind, data));
    }
    cm::write_path(&key, &values)?;
    if let Some(driver_key) = &driver_key {
        let inf = ids::sz(&record.inf);
        let section = ids::sz(&record.section);
        let id = ids::sz(&record.id.to_ascii_lowercase());
        let provider = record.provider.as_deref().map(ids::sz);
        let mut values: Vec<(&str, u32, &[u8])> = alloc::vec![
            ("InfPath", REG_SZ, &inf[..]),
            ("InfSection", REG_SZ, &section[..]),
            ("MatchingDeviceId", REG_SZ, &id[..]),
        ];
        if let Some(provider) = &provider {
            values.push(("ProviderName", REG_SZ, provider));
        }
        if let Some(description) = &description {
            values.push(("DriverDesc", REG_SZ, description));
        }
        cm::write_path(
            &format!("{CONTROL_SET}\\Control\\Class\\{driver_key}"),
            &values,
        )?;
    }
    let settings = format!("{}\\Device", record.configuration);
    if cm::exists(&settings) {
        cm::copy_tree(&settings, &format!("{key}\\Device Parameters"))?;
    }
    Ok(())
}

/// Record in the key of `service` that it serves the device
/// `instance`: the `Enum` subkey's `Count`, `NextInstance` and one
/// numbered value per device, as Windows keeps them.
pub fn service_serves(service: &str, instance: &str) -> Result<(), i32> {
    let key = format!("{}\\Enum", service_key(service));
    let count = dword(&key, "Count").unwrap_or(0);
    let listed = (0..count).any(|n| {
        string(&key, &format!("{n}")).is_some_and(|known| known.eq_ignore_ascii_case(instance))
    });
    if listed {
        return Ok(());
    }
    let next = (count + 1).to_le_bytes();
    cm::write_path(
        &key,
        &[
            (&format!("{count}"), REG_SZ, &ids::sz(instance)),
            ("Count", REG_DWORD, &next),
            ("NextInstance", REG_DWORD, &next),
        ],
    )
}

/// Take the device `instance` out of the list `service_serves` keeps.
pub fn service_stopped_serving(service: &str, instance: &str) {
    let key = format!("{}\\Enum", service_key(service));
    let count = dword(&key, "Count").unwrap_or(0);
    let mut kept: Vec<String> = (0..count)
        .filter_map(|n| string(&key, &format!("{n}")))
        .collect();
    kept.retain(|known| !known.eq_ignore_ascii_case(instance));
    for n in 0..count {
        cm::delete_value(&key, &format!("{n}"));
    }
    let now = (kept.len() as u32).to_le_bytes();
    let _ = cm::write_path(
        &key,
        &[
            ("Count", REG_DWORD, &now),
            ("NextInstance", REG_DWORD, &now),
        ],
    );
    for (n, known) in kept.iter().enumerate() {
        let _ = cm::write_path(&key, &[(&format!("{n}"), REG_SZ, &ids::sz(known))]);
    }
}

/// Write what a started device was given into its `Control` key:
/// the requirements as its drivers filtered them and the raw resources
/// assigned.
pub fn write_allocation(instance: &str, filtered: &[u8], raw: &[u8]) -> Result<(), i32> {
    let key = format!("{}\\Control", enum_key(instance));
    let mut values: Vec<(&str, u32, &[u8])> = Vec::new();
    if !filtered.is_empty() {
        values.push((
            "FilteredConfigVector",
            REG_RESOURCE_REQUIREMENTS_LIST,
            filtered,
        ));
    }
    if !raw.is_empty() {
        values.push(("AllocConfig", REG_RESOURCE_LIST, raw));
    }
    cm::write_path(&key, &values)
}

/// Forget what `write_allocation` wrote: the device is not started.
pub fn clear_allocation(instance: &str) {
    let key = format!("{}\\Control", enum_key(instance));
    cm::delete_value(&key, "FilteredConfigVector");
    cm::delete_value(&key, "AllocConfig");
}

/// The key a property of the device `instance` is kept in, as Windows
/// keeps it: `Properties\{category}\NNNN` under the device's key.
pub fn property_key(instance: &str, category: &[u8; 16], number: u32) -> String {
    format!(
        "{}\\Properties\\{}\\{number:04X}",
        enum_key(instance),
        ids::guid_text(category)
    )
}

/// What a property's registry value carries its type behind, and
/// `DEVPROP_TYPE_BINARY`.
pub const DEVPROP_REGISTRY_TYPE: u32 = 0xFFFF_0000;
const DEVPROP_TYPE_BINARY: u32 = 0x1003;

fn connection_key(instance: &str) -> String {
    use nk_pnp::connection::{CONNECTION_DATA_CATEGORY, CONNECTION_DATA_NUMBER};
    property_key(instance, &CONNECTION_DATA_CATEGORY, CONNECTION_DATA_NUMBER)
}

/// Give the device its interrupt connection data, as the property a
/// bus driver reads it by (`IoGetDevicePropertyData`).
pub fn write_connection(instance: &str, data: &[u8]) -> Result<(), i32> {
    cm::write_path(
        &connection_key(instance),
        &[("", DEVPROP_REGISTRY_TYPE | DEVPROP_TYPE_BINARY, data)],
    )
}

/// Take the device's interrupt connection data away.
pub fn clear_connection(instance: &str) {
    let _ = cm::delete_tree(&connection_key(instance));
}
