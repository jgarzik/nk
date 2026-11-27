//! A bus driver of the test's own for the machine's AHCI controller:
//! what `pci.sys` is to that one device, and nothing more.
//!
//! The driver reports a device of its own under the root (as the HAL
//! reports its device), and on it enumerates one child: the function
//! of PCI bus 0 whose class code is that of an AHCI controller. The
//! child's physical device object answers what `pci.sys`'s answers for
//! that function (`PciDevice_*` in the pinned `pci.sys`): its
//! identifiers, text, capabilities and bus, its requirements and boot
//! configuration read from its configuration space, the bus interface
//! and configuration requests, and at its start it programs the
//! address registers, the command register and the message capability.
//! A request `pci.sys` knows and this driver does not is completed as
//! `pci.sys` completes one it does not support: unchanged.
//!
//! `stordirect.rs` brings Microsoft's storage stack up on it.

use crate::hal::pci::{self, Function};
use crate::io::{device, driver, irp};
use crate::pnp::root::{complete, complete_unchanged, pool_string, relations_of};
use crate::pnp::{self, registry};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicUsize, Ordering};
use nk_ntabi::dma::{DEVICE_DESCRIPTION, DMA_ADAPTER};
use nk_ntabi::io::*;
use nk_ntabi::pnp::*;
use nk_ntabi::status::*;
use nk_pnp::ids;
use nk_pnp::resources::*;

/// The bus driver's service: its device is `ROOT\NkAhciBus\0000`.
pub const BUS: &str = "NkAhciBus";

/// The class code of an AHCI controller: mass storage, serial ATA,
/// AHCI.
const AHCI_CLASS: [u8; 3] = [0x01, 0x06, 0x01];

/// `PCIBus`, the `INTERFACE_TYPE`.
const PCI_BUS: u32 = 5;

/// `GUID_BUS_TYPE_PCI` and `GUID_BUS_INTERFACE_STANDARD`.
const GUID_BUS_TYPE_PCI: &str = "{c8ebdfb0-b510-11d0-80e5-00a0c92542e3}";
const GUID_BUS_INTERFACE_STANDARD: &str = "{496b8280-6f25-11d0-beaf-08002be2092f}";

/// Registers of a function's configuration space.
const COMMAND: u32 = 0x04;
const STATUS: u32 = 0x06;
const BAR0: u32 = 0x10;
const CAPABILITIES: u32 = 0x34;
const INTERRUPT_LINE: u32 = 0x3C;
/// Command bits: decode I/O ports, decode memory, master the bus.
const COMMAND_IO: u16 = 1;
const COMMAND_MEMORY: u16 = 2;
const COMMAND_MASTER: u16 = 4;
/// Status bit: the function has a list of capabilities.
const STATUS_CAPABILITIES: u16 = 0x10;
/// The identifier of the message-signalled interrupt capability, and
/// bits of its control register: enabled, and the address is 64 bits.
const CAPABILITY_MSI: u8 = 0x05;
const MSI_ENABLE: u16 = 1;
const MSI_64BIT: u16 = 0x80;
const MSI_MULTIPLE_ENABLE: u16 = 0x70;

/// `CM_RESOURCE_PORT_IO | CM_RESOURCE_PORT_16_BIT_DECODE |
/// CM_RESOURCE_PORT_POSITIVE_DECODE | CM_RESOURCE_PORT_BAR`, and
/// `CM_RESOURCE_MEMORY_BAR`: the flags `pci.sys` gives the ranges of a
/// function's address registers.
const PORT_FLAGS: u16 = 0x131;
const MEMORY_FLAGS: u16 = 0x80;
const SHARE_DEVICE_EXCLUSIVE: u8 = 1;

/// The bus's devices: the one it reported and serves, its own on top
/// of that, and the child.
static REPORTED: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());
static FUNCTION_DEVICE: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());
static CHILD: AtomicPtr<DEVICE_OBJECT> = AtomicPtr::new(core::ptr::null_mut());
static DRIVER: AtomicPtr<DRIVER_OBJECT> = AtomicPtr::new(core::ptr::null_mut());
/// Whether the controller is on the bus, whether its device refuses a
/// start, and the number the next device made for it is named by.
static PRESENT: AtomicBool = AtomicBool::new(false);
static REFUSE_START: AtomicBool = AtomicBool::new(false);
static SEQUENCE: AtomicU32 = AtomicU32::new(0);
/// The child's place on the bus: device and function number, packed as
/// [`pack`] packs them.
static PLACE: AtomicU32 = AtomicU32::new(0);
/// References to the bus interface handed out and not given back.
static INTERFACE_REFERENCES: AtomicUsize = AtomicUsize::new(0);

fn pack(function: Function) -> u32 {
    u32::from(function.device) << 8 | u32::from(function.function)
}

/// The child's function.
fn place() -> Function {
    let packed = PLACE.load(Ordering::Acquire);
    Function {
        segment: 0,
        bus: 0,
        device: (packed >> 8) as u8,
        function: packed as u8,
    }
}

fn read8(function: Function, offset: u32) -> u8 {
    let mut value = [0xFF; 1];
    pci::read(function, offset, &mut value);
    value[0]
}

fn read16(function: Function, offset: u32) -> u16 {
    let mut value = [0xFF; 2];
    pci::read(function, offset, &mut value);
    u16::from_le_bytes(value)
}

fn read32(function: Function, offset: u32) -> u32 {
    let mut value = [0xFF; 4];
    pci::read(function, offset, &mut value);
    u32::from_le_bytes(value)
}

fn write16(function: Function, offset: u32, value: u16) {
    pci::write(function, offset, &value.to_le_bytes());
}

fn write32(function: Function, offset: u32, value: u32) {
    pci::write(function, offset, &value.to_le_bytes());
}

/// The AHCI controller of PCI bus 0, if the machine has one there.
pub fn find() -> Option<Function> {
    (0..32u8)
        .flat_map(|device| (0..8u8).map(move |function| (device, function)))
        .map(|(device, function)| Function {
            segment: 0,
            bus: 0,
            device,
            function,
        })
        .find(|function| {
            let mut header = [0xFFu8; 16];
            let present = pci::read(*function, 0, &mut header) == 16
                && nk_hal::pci::present(
                    function.function,
                    u16::from_le_bytes([header[0], header[1]]),
                    read8(function.first(), nk_hal::pci::HEADER_TYPE),
                );
            // A general device's header, with the controller's class.
            present
                && [header[11], header[10], header[9]] == AHCI_CLASS
                && read8(*function, nk_hal::pci::HEADER_TYPE) & 0x7F == 0
        })
}

/// What `pci.sys` calls a function, part by part.
struct Identity {
    vendor: u16,
    device: u16,
    /// The subsystem's identifier and its vendor's, as one number.
    subsystem: u32,
    revision: u8,
    class: [u8; 3],
}

fn identity(function: Function) -> Identity {
    Identity {
        vendor: read16(function, 0x00),
        device: read16(function, 0x02),
        subsystem: u32::from(read16(function, 0x2E)) << 16 | u32::from(read16(function, 0x2C)),
        revision: read8(function, 0x08),
        class: [
            read8(function, 0x0B),
            read8(function, 0x0A),
            read8(function, 0x09),
        ],
    }
}

impl Identity {
    /// The device identifier: also the first hardware identifier.
    fn device_id(&self) -> String {
        format!(
            "PCI\\VEN_{:04X}&DEV_{:04X}&SUBSYS_{:08X}&REV_{:02X}",
            self.vendor, self.device, self.subsystem, self.revision
        )
    }

    fn hardware_ids(&self) -> Vec<String> {
        let Identity {
            vendor,
            device,
            subsystem,
            class: [base, sub, interface],
            ..
        } = *self;
        alloc::vec![
            self.device_id(),
            format!("PCI\\VEN_{vendor:04X}&DEV_{device:04X}&SUBSYS_{subsystem:08X}"),
            format!("PCI\\VEN_{vendor:04X}&DEV_{device:04X}&CC_{base:02X}{sub:02X}{interface:02X}"),
            format!("PCI\\VEN_{vendor:04X}&DEV_{device:04X}&CC_{base:02X}{sub:02X}"),
        ]
    }

    fn compatible_ids(&self) -> Vec<String> {
        let Identity {
            vendor,
            device,
            revision,
            class: [base, sub, interface],
            ..
        } = *self;
        alloc::vec![
            format!("PCI\\VEN_{vendor:04X}&DEV_{device:04X}&REV_{revision:02X}"),
            format!("PCI\\VEN_{vendor:04X}&DEV_{device:04X}"),
            format!("PCI\\VEN_{vendor:04X}&CC_{base:02X}{sub:02X}{interface:02X}"),
            format!("PCI\\VEN_{vendor:04X}&CC_{base:02X}{sub:02X}"),
            format!("PCI\\VEN_{vendor:04X}"),
            format!("PCI\\CC_{base:02X}{sub:02X}{interface:02X}"),
            format!("PCI\\CC_{base:02X}{sub:02X}"),
        ]
    }
}

/// The instance path the child gets: its device identifier, and its
/// parent's prefix before `pci.sys`'s instance identifier, the device
/// and function number in two hexadecimal digits.
pub fn instance_id(function: Function) -> String {
    format!("{:02X}", function.device << 3 | function.function)
}

/// The device identifier of the controller at `function`.
pub fn device_id(function: Function) -> String {
    identity(function).device_id()
}

/// One address register that decodes something.
#[derive(Clone, Copy)]
struct Bar {
    index: u32,
    port: bool,
    base: u64,
    length: u64,
}

/// The function's address registers, sized as `pci.sys` sizes them:
/// with the decodes off, each register is written all ones, read, and
/// put back. `None` for a register of a kind this driver does not
/// describe (64-bit memory).
fn bars(function: Function) -> Option<Vec<Bar>> {
    let command = read16(function, COMMAND);
    write16(function, COMMAND, command & !(COMMAND_IO | COMMAND_MEMORY));
    let mut found = Some(Vec::new());
    for index in 0..6u32 {
        let register = BAR0 + index * 4;
        let old = read32(function, register);
        write32(function, register, u32::MAX);
        let mask = read32(function, register);
        write32(function, register, old);
        let port = old & 1 != 0;
        let fixed = if port { 0x3 } else { 0xF };
        if mask & !fixed == 0 {
            continue;
        }
        if !port && old & 0x6 != 0 {
            found = None;
            break;
        }
        // An I/O register may leave its upper half unimplemented.
        let decoded = if port && mask >> 16 == 0 {
            mask | 0xFFFF_0000
        } else {
            mask
        };
        if let Some(list) = &mut found {
            list.push(Bar {
                index,
                port,
                base: u64::from(old & !fixed),
                length: u64::from(!(decoded & !fixed)) + 1,
            });
        }
    }
    write16(function, COMMAND, command);
    found
}

/// Where the function's message capability is, if it has one.
fn msi_capability(function: Function) -> Option<u32> {
    if read16(function, STATUS) & STATUS_CAPABILITIES == 0 {
        return None;
    }
    let mut at = u32::from(read8(function, CAPABILITIES) & 0xFC);
    // A list longer than the space is a loop.
    for _ in 0..48 {
        if at < 0x40 {
            return None;
        }
        if read8(function, at) == CAPABILITY_MSI {
            return Some(at);
        }
        at = u32::from(read8(function, at + 1) & 0xFC);
    }
    None
}

/// What the function's message capability holds: whether messages are
/// enabled, how many (as the power of two the register states), and
/// the address and data of the first. `None` without the capability.
pub fn message_programmed(function: Function) -> Option<(bool, u32, u64, u16)> {
    let capability = msi_capability(function)?;
    let control = read16(function, capability + 2);
    let low = u64::from(read32(function, capability + 4));
    let (high, data) = if control & MSI_64BIT != 0 {
        (
            u64::from(read32(function, capability + 8)),
            read16(function, capability + 12),
        )
    } else {
        (0, read16(function, capability + 8))
    };
    Some((
        control & MSI_ENABLE != 0,
        1 << ((control & MSI_MULTIPLE_ENABLE) >> 4),
        high << 32 | low,
        data,
    ))
}

/// The function's interrupt line as firmware left it, if it has a pin
/// and a line.
fn line(function: Function) -> Option<u32> {
    let [line, pin] = read16(function, INTERRUPT_LINE).to_le_bytes();
    (pin != 0 && line != 0xFF).then_some(u32::from(line))
}

/// Whether the device's key says its driver handles messages:
/// `Device Parameters\Interrupt Management\
/// MessageSignaledInterruptProperties`, value `MSISupported`, which
/// the device's installation puts there and `pci.sys` reads
/// (`PciGetMessageCount`) when it builds the requirements.
fn messages_wanted(pdo: *mut DEVICE_OBJECT) -> bool {
    let Some(instance) = pnp::node::with(pdo as usize, |node| node.instance.clone()) else {
        return false;
    };
    let key = format!(
        "{}\\Device Parameters\\Interrupt Management\\MessageSignaledInterruptProperties",
        registry::enum_key(&instance)
    );
    registry::dword(&key, "MSISupported") == Some(1)
}

/// The device-private descriptor `pci.sys` puts behind the range of
/// the address register `index`.
fn private(index: u32) -> IoDescriptor {
    let mut descriptor = IoDescriptor::interrupt(0, 0, 0, 1, index);
    descriptor.kind = TYPE_DEVICE_PRIVATE;
    descriptor
}

/// What the function requires, as `pci.sys` states it: for each
/// address register its range where firmware put it and, as the
/// alternative, anywhere below 4 GiB, with a device-private descriptor
/// naming the register; then the interrupt: one message if the
/// function can send one and its key says its driver wants them, with
/// any line as the alternative, else its line.
fn requirements(function: Function, pdo: *mut DEVICE_OBJECT) -> Option<Requirements> {
    let mut descriptors = Vec::new();
    for bar in bars(function)? {
        let (kind, flags) = if bar.port {
            (TYPE_PORT, PORT_FLAGS)
        } else {
            (TYPE_MEMORY, MEMORY_FLAGS)
        };
        if bar.base != 0 {
            descriptors.push(IoDescriptor::range(
                OPTION_PREFERRED,
                kind,
                SHARE_DEVICE_EXCLUSIVE,
                flags,
                Wanted {
                    length: bar.length,
                    alignment: 1,
                    minimum: bar.base,
                    maximum: bar.base + bar.length - 1,
                },
            ));
        }
        descriptors.push(IoDescriptor::range(
            if bar.base != 0 { OPTION_ALTERNATIVE } else { 0 },
            kind,
            SHARE_DEVICE_EXCLUSIVE,
            flags,
            Wanted {
                length: bar.length,
                alignment: bar.length,
                minimum: 0,
                maximum: 0xFFFF_FFFF,
            },
        ));
        descriptors.push(private(bar.index));
    }
    let message = msi_capability(function).is_some() && messages_wanted(pdo);
    if message {
        descriptors.push(IoDescriptor::interrupt(
            OPTION_PREFERRED,
            SHARE_DEVICE_EXCLUSIVE,
            INTERRUPT_LATCHED | INTERRUPT_MESSAGE,
            MESSAGE_TOKEN,
            MESSAGE_TOKEN,
        ));
    }
    if line(function).is_some() {
        descriptors.push(IoDescriptor::interrupt(
            if message { OPTION_ALTERNATIVE } else { 0 },
            SHARE_SHARED,
            0,
            0,
            u32::MAX,
        ));
    }
    Some(Requirements {
        interface: PCI_BUS,
        bus: u32::from(function.bus),
        slot: nk_hal::pci::slot_number(function.device, function.function),
        lists: alloc::vec![IoList {
            version: 1,
            revision: 1,
            descriptors,
        }],
    })
}

/// What firmware configured: each address register's range, and the
/// interrupt line.
fn boot_configuration(function: Function) -> Option<ResourceList> {
    let mut partials = Vec::new();
    for bar in bars(function)? {
        if bar.base == 0 {
            continue;
        }
        let (kind, flags) = if bar.port {
            (TYPE_PORT, PORT_FLAGS)
        } else {
            (TYPE_MEMORY, MEMORY_FLAGS)
        };
        partials.push(Partial::range(
            kind,
            SHARE_DEVICE_EXCLUSIVE,
            flags,
            bar.base,
            bar.length,
        ));
    }
    if let Some(line) = line(function) {
        partials.push(Partial::interrupt(
            SHARE_SHARED,
            0,
            line as u16,
            0,
            line,
            0xFFFF_FFFF,
        ));
    }
    Some(ResourceList::of(PCI_BUS, u32::from(function.bus), partials))
}

/// A copy of `bytes` in a pool block the receiver frees; zero without
/// memory.
fn pool_copy(bytes: &[u8]) -> usize {
    let block = crate::mm::pool::alloc(bytes.len(), pnp::TAG);
    if !block.is_null() {
        // SAFETY: a fresh block of that many bytes.
        unsafe { block.copy_from_nonoverlapping(bytes.as_ptr(), bytes.len()) };
    }
    block as usize
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

fn multi(strings: &[String]) -> Vec<u16> {
    let strings: Vec<&str> = strings.iter().map(String::as_str).collect();
    ids::to_multi_sz(&strings)
}

/// Complete `request` with a block the receiver frees, or for want of
/// memory.
///
/// # Safety
/// `request` is an IRP its caller owns.
unsafe fn answer(request: *mut IRP, block: usize) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        match block {
            0 => complete(request, STATUS_INSUFFICIENT_RESOURCES, 0),
            block => complete(request, STATUS_SUCCESS, block),
        }
    }
}

/// [`BUS_INTERFACE_STANDARD`]'s routines, as `pci.sys` has them
/// (`PciBusInterface_*`).
///
/// # Safety
/// Called by a driver through the interface, with the routine's
/// arguments.
unsafe extern "C" fn interface_reference(_: *mut c_void) {
    INTERFACE_REFERENCES.fetch_add(1, Ordering::AcqRel);
}

/// # Safety
/// As [`interface_reference`].
unsafe extern "C" fn interface_dereference(_: *mut c_void) {
    INTERFACE_REFERENCES.fetch_sub(1, Ordering::AcqRel);
}

/// `HalTranslateBusAddress` for the PCI bus the function is on.
///
/// # Safety
/// As [`interface_reference`].
unsafe extern "C" fn translate_bus_address(
    _: *mut c_void,
    bus_address: i64,
    _length: u32,
    address_space: *mut u32,
    translated_address: *mut i64,
) -> u8 {
    // SAFETY: the caller's pointers, per the routine's contract.
    unsafe {
        crate::hal::dma::HalTranslateBusAddress(
            PCI_BUS,
            u32::from(place().bus),
            bus_address,
            address_space,
            translated_address,
        )
    }
}

/// `IoGetDmaAdapter` on the bus's own device, with the function's bus
/// number in a description that names the PCI bus.
///
/// # Safety
/// As [`interface_reference`].
unsafe extern "C" fn get_dma_adapter(
    _: *mut c_void,
    description: *mut DEVICE_DESCRIPTION,
    number_of_map_registers: *mut u32,
) -> *mut DMA_ADAPTER {
    // SAFETY: the caller's description and count, per the routine's
    // contract.
    unsafe {
        if (&raw const (*description).InterfaceType).read() == PCI_BUS {
            (&raw mut (*description).BusNumber).write(u32::from(place().bus));
        }
        crate::hal::dma::IoGetDmaAdapter(
            REPORTED.load(Ordering::Acquire),
            description,
            number_of_map_registers,
        )
    }
}

/// Read or write the function's configuration space; the count of
/// bytes moved. As in `pci.sys` (`PciReadDeviceSpace`), every space
/// but the expansion ROM's is the configuration space: Storport names
/// it by the bus data type, 4, where the interface's header says 0.
/// The ROM is not read: this controller has none.
///
/// # Safety
/// `buffer` is valid for `length` bytes, of writes if `!write`.
unsafe fn bus_data(space: u32, buffer: *mut u8, offset: u32, length: u32, write: bool) -> u32 {
    if space == PCI_WHICHSPACE_ROM || buffer.is_null() || offset.checked_add(length).is_none() {
        return 0;
    }
    // SAFETY: per the contract; the buffer is the driver's memory, and
    // is copied through a buffer of NK's own.
    unsafe {
        let mut own = alloc::vec![0u8; length as usize];
        if write {
            buffer.copy_to_nonoverlapping(own.as_mut_ptr(), own.len());
            pci::write(place(), offset, &own) as u32
        } else {
            let moved = pci::read(place(), offset, &mut own);
            buffer.copy_from_nonoverlapping(own.as_ptr(), moved);
            moved as u32
        }
    }
}

/// # Safety
/// As [`interface_reference`].
unsafe extern "C" fn set_bus_data(
    _: *mut c_void,
    space: u32,
    buffer: *mut u8,
    offset: u32,
    length: u32,
) -> u32 {
    // SAFETY: the caller's buffer, per the routine's contract.
    unsafe { bus_data(space, buffer, offset, length, true) }
}

/// # Safety
/// As [`interface_reference`].
unsafe extern "C" fn get_bus_data(
    _: *mut c_void,
    space: u32,
    buffer: *mut u8,
    offset: u32,
    length: u32,
) -> u32 {
    // SAFETY: the caller's buffer, per the routine's contract.
    unsafe { bus_data(space, buffer, offset, length, false) }
}

/// `IRP_MN_QUERY_INTERFACE`: the bus interface, for a caller whose
/// structure has room for it (`PciBusInterface_Constructor`); any
/// other is not supported, as `PciDevice_QueryInterface` answers for
/// an interface it has no entry for.
///
/// # Safety
/// `request` is a query for an interface at the child's location.
unsafe fn query_interface(request: *mut IRP, parameters: [u64; 4]) -> NTSTATUS {
    // SAFETY: per the contract: a GUID, and a structure of the size the
    // request states.
    unsafe {
        let guid = (parameters[0] as *const [u8; 16]).read_unaligned();
        let size = parameters[1] as u16;
        let version = (parameters[1] >> 16) as u16;
        let interface = parameters[2] as *mut BUS_INTERFACE_STANDARD;
        let standard = ids::guid_from_text(GUID_BUS_INTERFACE_STANDARD) == Some(guid);
        if !standard
            || version != 1
            || usize::from(size) < size_of::<BUS_INTERFACE_STANDARD>()
            || interface.is_null()
        {
            kprintln!(
                "ahcibus: interface {} (size {size:#x}, version {version}) is not supported",
                ids::guid_text(&guid)
            );
            return complete_unchanged(request);
        }
        interface.write_unaligned(BUS_INTERFACE_STANDARD {
            Header: INTERFACE {
                Size: size_of::<BUS_INTERFACE_STANDARD>() as u16,
                Version: 1,
                Context: CHILD.load(Ordering::Acquire).cast(),
                InterfaceReference: Some(interface_reference),
                InterfaceDereference: Some(interface_dereference),
            },
            TranslateBusAddress: translate_bus_address as PVOID,
            GetDmaAdapter: get_dma_adapter as PVOID,
            SetBusData: set_bus_data as PVOID,
            GetBusData: get_bus_data as PVOID,
        });
        interface_reference(core::ptr::null_mut());
        complete(request, STATUS_SUCCESS, (*request).IoStatus.Information)
    }
}

/// Program the function with what it was given, as `pci.sys` does at a
/// device's start: each address register with its range's start, the
/// command register's decodes for the kinds of range it has and bus
/// mastering, and the message capability with the address and data the
/// HAL gives for the vector the interrupt was translated to.
///
/// # Safety
/// `parameters` are those of a start request.
unsafe fn start(parameters: [u64; 4]) -> NTSTATUS {
    let function = place();
    // SAFETY: per the contract: two resource lists, or null.
    let lists = unsafe {
        [parameters[0], parameters[1]].map(|list| {
            (list != 0)
                .then(|| pnp::query::resource_list_at(list as usize))
                .flatten()
                .and_then(|bytes| ResourceList::parse(&bytes))
                .map(|(list, _)| list)
        })
    };
    let [Some(raw), Some(translated)] = lists else {
        return STATUS_INVALID_PARAMETER;
    };
    let mut command = read16(function, COMMAND) & !(COMMAND_IO | COMMAND_MEMORY | COMMAND_MASTER);
    write16(function, COMMAND, command);
    // A range's register is named by the device-private descriptor
    // behind it.
    let partials: Vec<&Partial> = raw.partials().collect();
    for (at, partial) in partials.iter().enumerate() {
        let Some((start, _)) = partial.as_range() else {
            continue;
        };
        let index = partials
            .get(at + 1)
            .filter(|next| next.kind == TYPE_DEVICE_PRIVATE)
            .map(|next| u32::from_le_bytes(next.data[4..8].try_into().unwrap_or_default()));
        let (Some(index @ 0..6), Ok(start)) = (index, u32::try_from(start)) else {
            return STATUS_INVALID_PARAMETER;
        };
        let register = BAR0 + index * 4;
        let kept = read32(function, register) & if partial.kind == TYPE_PORT { 0x3 } else { 0xF };
        write32(function, register, start | kept);
        command |= if partial.kind == TYPE_PORT {
            COMMAND_IO
        } else {
            COMMAND_MEMORY
        };
    }
    let message = translated
        .partials()
        .find(|partial| partial.kind == TYPE_INTERRUPT && partial.is_message())
        .and_then(Partial::as_interrupt);
    if let Some(capability) = msi_capability(function) {
        let control = read16(function, capability + 2) & !(MSI_ENABLE | MSI_MULTIPLE_ENABLE);
        write16(function, capability + 2, control);
        if let Some((_, _, vector, _)) = message {
            let Some(to) = crate::hal::interrupt::message(vector) else {
                return STATUS_INVALID_PARAMETER;
            };
            write32(function, capability + 4, to.address as u32);
            if control & MSI_64BIT != 0 {
                write32(function, capability + 8, (to.address >> 32) as u32);
                write16(function, capability + 12, to.data as u16);
            } else {
                write16(function, capability + 8, to.data as u16);
            }
            write16(function, capability + 2, control | MSI_ENABLE);
        }
    } else if message.is_some() {
        return STATUS_INVALID_PARAMETER;
    }
    write16(function, COMMAND, command | COMMAND_MASTER);
    STATUS_SUCCESS
}

/// Take the function off the bus again: no messages, no mastering.
/// Its decodes stay as they are, firmware having had them on.
fn stop() {
    let function = place();
    if let Some(capability) = msi_capability(function) {
        let control = read16(function, capability + 2);
        write16(function, capability + 2, control & !MSI_ENABLE);
    }
    write16(
        function,
        COMMAND,
        read16(function, COMMAND) & !COMMAND_MASTER,
    );
}

/// The child's answers to Plug and Play requests.
///
/// # Safety
/// `request` is a Plug and Play IRP at the child's location.
unsafe fn child_pnp(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    let function = place();
    // SAFETY: per the contract.
    unsafe {
        let location = (*request).CurrentStackLocation;
        let parameters = (*location).Parameters;
        let minor = (*location).MinorFunction;
        match minor {
            IRP_MN_QUERY_ID => {
                let who = identity(function);
                let text = match parameters[0] as u32 {
                    BUS_QUERY_DEVICE_ID => wide(&who.device_id()),
                    BUS_QUERY_INSTANCE_ID => wide(&instance_id(function)),
                    BUS_QUERY_HARDWARE_IDS => multi(&who.hardware_ids()),
                    BUS_QUERY_COMPATIBLE_IDS => multi(&who.compatible_ids()),
                    _ => return complete_unchanged(request),
                };
                answer(request, pool_string(&text))
            }
            IRP_MN_QUERY_DEVICE_TEXT => {
                let text = match parameters[0] as u32 {
                    // The entry of `pci.sys`'s message table for the
                    // class code.
                    DEVICE_TEXT_DESCRIPTION => wide("Serial ATA Controller"),
                    DEVICE_TEXT_LOCATION_INFORMATION => wide(&format!(
                        "@System32\\drivers\\pci.sys,#65536;PCI bus %1, device %2, function %3;({},{},{})",
                        function.bus, function.device, function.function
                    )),
                    _ => return complete_unchanged(request),
                };
                answer(request, pool_string(&text))
            }
            IRP_MN_QUERY_CAPABILITIES => {
                // `PciDevice_QueryCapabilities` for a function that is
                // no bridge and has no power management capability:
                // its address, no flag, and full power only while the
                // system works.
                let capabilities = parameters[0] as *mut DEVICE_CAPABILITIES;
                let address = u32::from(function.device) << 16 | u32::from(function.function);
                (&raw mut (*capabilities).Address).write_unaligned(address);
                let flags = &raw mut (*capabilities).Flags;
                flags.write_unaligned(
                    flags.read_unaligned()
                        & !(DEVICE_CAPABILITY_UNIQUE_ID | DEVICE_CAPABILITY_RAW_DEVICE_OK),
                );
                let mut states = [POWER_DEVICE_D3; POWER_SYSTEM_MAXIMUM as usize];
                states[POWER_SYSTEM_UNSPECIFIED as usize] = POWER_DEVICE_UNSPECIFIED;
                states[POWER_SYSTEM_WORKING as usize] = POWER_DEVICE_D0;
                (&raw mut (*capabilities).DeviceState).write_unaligned(states);
                complete(request, STATUS_SUCCESS, (*request).IoStatus.Information)
            }
            IRP_MN_QUERY_BUS_INFORMATION => {
                let mut information = [0u8; 24];
                let Some(guid) = ids::guid_from_text(GUID_BUS_TYPE_PCI) else {
                    return complete_unchanged(request);
                };
                information[..16].copy_from_slice(&guid);
                information[16..20].copy_from_slice(&PCI_BUS.to_le_bytes());
                information[20..].copy_from_slice(&u32::from(function.bus).to_le_bytes());
                answer(request, pool_copy(&information))
            }
            IRP_MN_QUERY_RESOURCE_REQUIREMENTS => match requirements(function, device) {
                Some(list) => answer(request, pool_copy(&list.to_bytes())),
                None => complete_unchanged(request),
            },
            IRP_MN_QUERY_RESOURCES => match boot_configuration(function) {
                Some(list) => answer(request, pool_copy(&list.to_bytes())),
                None => complete_unchanged(request),
            },
            IRP_MN_QUERY_DEVICE_RELATIONS if parameters[0] as u32 == TARGET_DEVICE_RELATION => {
                answer(request, relations_of(&[device as usize]))
            }
            IRP_MN_QUERY_INTERFACE => query_interface(request, parameters),
            IRP_MN_READ_CONFIG | IRP_MN_WRITE_CONFIG => {
                let moved = bus_data(
                    parameters[0] as u32,
                    parameters[1] as *mut u8,
                    parameters[2] as u32,
                    parameters[3] as u32,
                    minor == IRP_MN_WRITE_CONFIG,
                );
                complete(request, STATUS_SUCCESS, moved as usize)
            }
            IRP_MN_START_DEVICE => {
                let status = if REFUSE_START.load(Ordering::Acquire) {
                    STATUS_DEVICE_NOT_READY
                } else {
                    start(parameters)
                };
                complete(request, status, 0)
            }
            IRP_MN_STOP_DEVICE | IRP_MN_SURPRISE_REMOVAL => {
                stop();
                complete(request, STATUS_SUCCESS, 0)
            }
            IRP_MN_REMOVE_DEVICE => {
                stop();
                // A device whose function left the bus goes for good.
                let gone = !PRESENT.load(Ordering::Acquire);
                let status = complete(request, STATUS_SUCCESS, 0);
                if gone {
                    CHILD.store(core::ptr::null_mut(), Ordering::Release);
                    device::IoDeleteDevice(device);
                }
                status
            }
            // Nothing of a device's requirements is the bus's to
            // change once they are stated.
            IRP_MN_FILTER_RESOURCE_REQUIREMENTS => complete_unchanged(request),
            IRP_MN_QUERY_STOP_DEVICE
            | IRP_MN_CANCEL_STOP_DEVICE
            | IRP_MN_QUERY_REMOVE_DEVICE
            | IRP_MN_CANCEL_REMOVE_DEVICE
            | IRP_MN_DEVICE_ENUMERATED => complete(request, STATUS_SUCCESS, 0),
            // `PciDevice_QueryDeviceState` adds nothing for a function
            // that is no bridge, and succeeds.
            IRP_MN_QUERY_PNP_DEVICE_STATE => {
                complete(request, STATUS_SUCCESS, (*request).IoStatus.Information)
            }
            // The other relations are not a function's to state.
            IRP_MN_QUERY_DEVICE_RELATIONS => complete_unchanged(request),
            _ => {
                kprintln!(
                    "ahcibus: request {minor:#04x} ({:#x}) is not supported",
                    parameters[0]
                );
                complete_unchanged(request)
            }
        }
    }
}

/// The driver's dispatch routine for Plug and Play requests.
///
/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn dispatch_pnp(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    // SAFETY: a live request at the location of a device of the bus's.
    unsafe {
        if device == CHILD.load(Ordering::Acquire) {
            return child_pnp(device, request);
        }
        // The bus's own device, on the device it reported: it has the
        // one child, and everything else is the device below's.
        let location = (*request).CurrentStackLocation;
        if (*location).MinorFunction == IRP_MN_QUERY_DEVICE_RELATIONS
            && (*location).Parameters[0] as u32 == BUS_RELATIONS
        {
            let child = CHILD.load(Ordering::Acquire) as usize;
            let children = if PRESENT.load(Ordering::Acquire) {
                &[child][..]
            } else {
                &[]
            };
            match relations_of(children) {
                0 => return complete(request, STATUS_INSUFFICIENT_RESOURCES, 0),
                list => {
                    (*request).IoStatus.Status = STATUS_SUCCESS;
                    (*request).IoStatus.Information = list;
                }
            }
        }
        (*request).CurrentLocation += 1;
        (*request).CurrentStackLocation = (*request).CurrentStackLocation.add(1);
        irp::IofCallDriver(REPORTED.load(Ordering::Acquire), request)
    }
}

/// The driver's dispatch routine for power requests: the child is at
/// full power and stays there, so a request for its state is granted
/// as it comes; the bus's own device passes requests down.
///
/// # Safety
/// Called as a dispatch routine.
unsafe extern "C" fn dispatch_power(device: *mut DEVICE_OBJECT, request: *mut IRP) -> NTSTATUS {
    irp::PoStartNextPowerIrp(request);
    // SAFETY: a live request at the location of a device of the bus's.
    unsafe {
        if device == CHILD.load(Ordering::Acquire) {
            let minor = (*(*request).CurrentStackLocation).MinorFunction;
            return match minor {
                IRP_MN_SET_POWER | IRP_MN_QUERY_POWER => complete(request, STATUS_SUCCESS, 0),
                _ => complete_unchanged(request),
            };
        }
        (*request).CurrentLocation += 1;
        (*request).CurrentStackLocation = (*request).CurrentStackLocation.add(1);
        irp::PoCallDriver(REPORTED.load(Ordering::Acquire), request)
    }
}

/// Make a device of the driver's, called `name` if it has one.
fn make(driver: *mut DRIVER_OBJECT, name: Option<&str>) -> Option<*mut DEVICE_OBJECT> {
    /// `FILE_DEVICE_UNKNOWN`, and for a child `FILE_DEVICE_SECURE_OPEN
    /// | FILE_AUTOGENERATED_DEVICE_NAME`'s first, which `pci.sys` gives
    /// its devices.
    const UNKNOWN: u32 = 0x22;
    const SECURE_OPEN: u32 = 0x100;
    let mut units: Vec<u16> = name.unwrap_or("").encode_utf16().collect();
    let counted = UNICODE_STRING {
        Length: (units.len() * 2) as u16,
        MaximumLength: (units.len() * 2) as u16,
        Buffer: units.as_mut_ptr(),
    };
    let mut made = core::ptr::null_mut();
    // SAFETY: a driver object of the test's; the name is a counted
    // string or null; `made` is writable.
    let status = unsafe {
        device::IoCreateDevice(
            driver,
            0,
            if name.is_some() {
                &raw const counted
            } else {
                core::ptr::null()
            },
            UNKNOWN,
            if name.is_some() { SECURE_OPEN } else { 0 },
            0,
            &raw mut made,
        )
    };
    nt_success(status).then_some(made)
}

/// The bus: its driver and its devices, there while this is.
pub struct Bus {
    function: Function,
}

impl Bus {
    /// Make the bus driver, report its device, and have the manager
    /// ask it for its child: the controller at `function`.
    pub fn new(function: Function) -> Result<Self, &'static str> {
        if !DRIVER.load(Ordering::Acquire).is_null() {
            return Err("the bus is there already");
        }
        PLACE.store(pack(function), Ordering::Release);
        let made = driver::builtin(BUS, |object| {
            // SAFETY: the driver object being set up.
            unsafe {
                (*object).MajorFunction[usize::from(IRP_MJ_PNP)] = Some(dispatch_pnp);
                (*object).MajorFunction[usize::from(IRP_MJ_POWER)] = Some(dispatch_power);
            }
        })
        .map_err(|_| "the bus's driver object could not be made")?;
        DRIVER.store(made, Ordering::Release);
        let bus = Bus { function };
        let reported = pnp::report_detected_device(BUS, Some("Internal"))
            .map_err(|_| "the bus's device could not be reported")?;
        REPORTED.store(reported, Ordering::Release);
        let own = make(made, None).ok_or("the bus's own device could not be made")?;
        FUNCTION_DEVICE.store(own, Ordering::Release);
        // SAFETY: devices just made: the bus driver attaches to the
        // device it reported, as a driver's `AddDevice` would.
        unsafe {
            if device::IoAttachDeviceToDeviceStack(own, reported).is_null() {
                return Err("the bus's device could not be attached");
            }
            (*own).Flags &= !DO_DEVICE_INITIALIZING;
        }
        Ok(bus)
    }

    /// The controller appears on the bus: a new device is made for it,
    /// and the manager is told the bus's children changed. With
    /// `refuse_start` the device refuses to be started: the test's
    /// way of failing a start below Storport.
    pub fn plug(&self, refuse_start: bool) -> Result<(), &'static str> {
        if !CHILD.load(Ordering::Acquire).is_null() {
            return Err("the controller's device is there already");
        }
        // The name is the kind `pci.sys` gives its devices: a number
        // no other of its devices had.
        let number = SEQUENCE.fetch_add(1, Ordering::AcqRel);
        let child = make(
            DRIVER.load(Ordering::Acquire),
            Some(&format!("\\Device\\NTPNP_PCI{number:04}")),
        )
        .ok_or("the child could not be made")?;
        // SAFETY: the device just made.
        unsafe { (*child).Flags &= !DO_DEVICE_INITIALIZING };
        REFUSE_START.store(refuse_start, Ordering::Release);
        CHILD.store(child, Ordering::Release);
        PRESENT.store(true, Ordering::Release);
        self.changed();
        Ok(())
    }

    /// The controller goes from the bus: the manager is told, and the
    /// device is deleted when the manager removes it.
    pub fn unplug(&self) {
        PRESENT.store(false, Ordering::Release);
        self.changed();
    }

    /// Tell the manager the bus's children changed.
    fn changed(&self) {
        // SAFETY: the device the bus reported.
        unsafe {
            pnp::export::IoInvalidateDeviceRelations(
                REPORTED.load(Ordering::Acquire),
                BUS_RELATIONS,
            );
        }
    }

    /// The child's physical device object; null while the controller
    /// is off the bus.
    pub fn child(&self) -> *mut DEVICE_OBJECT {
        CHILD.load(Ordering::Acquire)
    }

    /// The controller's place on the PCI bus.
    pub fn function(&self) -> Function {
        self.function
    }
}

impl Drop for Bus {
    fn drop(&mut self) {
        if !REPORTED.load(Ordering::Acquire).is_null() {
            self.unplug();
            pnp::settle();
        }
        // SAFETY: devices of the bus's: its own is detached and deleted
        // before the device it reported is taken back, which takes the
        // child out of the tree; the child is then the bus's to delete.
        unsafe {
            let own = FUNCTION_DEVICE.swap(core::ptr::null_mut(), Ordering::AcqRel);
            let reported = REPORTED.swap(core::ptr::null_mut(), Ordering::AcqRel);
            if !own.is_null() {
                if !reported.is_null() {
                    device::IoDetachDevice(reported);
                }
                device::IoDeleteDevice(own);
            }
            if !reported.is_null() {
                pnp::remove_reported_device(reported);
            }
            let child = CHILD.swap(core::ptr::null_mut(), Ordering::AcqRel);
            if !child.is_null() {
                device::IoDeleteDevice(child);
            }
        }
        let made = DRIVER.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !made.is_null() {
            driver::remove_builtin(made);
        }
        let _ = crate::cm::delete_tree(&registry::enum_key(&format!("ROOT\\{BUS}")));
    }
}
