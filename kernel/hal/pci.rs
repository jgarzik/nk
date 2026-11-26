//! PCI configuration space.
//!
//! A function's configuration registers are reached through memory where
//! the ACPI MCFG table describes them (ECAM: 4096 bytes per function),
//! and otherwise, on an architecture that has them, through the two
//! configuration ports (256 bytes per function, segment 0 only). The
//! arithmetic is `nk_hal::pci`.
//!
//! Every access is made under one lock, held at `HIGH_LEVEL`, as Windows
//! serialises configuration access: the ports are an address register
//! and a data register, and a request that spans several registers is
//! not interleaved with another. So the routines here are callable at
//! any IRQL.
//!
//! [`read`] and [`write`] are the kernel's own interface; the bus-data
//! exports and, later, the HAL's private dispatch routines stand on
//! them.

#![allow(non_snake_case)]

use super::platform::{self, MAX_ECAM};
use crate::arch;
use crate::ke::{Rank, SpinLock};
use crate::mm;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};
pub use nk_hal::pci::Function;
use nk_hal::pci::{self, Piece};

/// Where each stretch of memory-mapped configuration space is mapped, by
/// its place in the platform description; 0 for one that is not.
static MAPPED: [AtomicU64; MAX_ECAM] = [const { AtomicU64::new(0) }; MAX_ECAM];

/// Serialises every configuration access.
static CONFIG: SpinLock<()> = SpinLock::new(Rank::PciConfig, ());

/// Map the configuration space the MCFG describes. A stretch that cannot
/// be mapped is reported and left out: its buses are then reached
/// through the ports, or not at all.
pub fn init() {
    for (index, entry) in platform::get().ecam() {
        let (base, bytes) = entry.span();
        match mm::map::map_device_for_good(base, bytes) {
            Some(va) => {
                MAPPED[index].store(va, Ordering::Release);
                kprintln!(
                    "hal: PCI segment {} buses {:#x}-{:#x}: configuration space at {base:#x}",
                    entry.segment,
                    entry.start_bus,
                    entry.end_bus
                );
            }
            None => kprintln!("hal: cannot map PCI configuration space at {base:#x}"),
        }
    }
}

/// The HAL's ACPI table, `HalPciInterfaceReadConfig`: `acpi.sys` reads
/// `length` bytes of a function's configuration space from `offset`,
/// for firmware's AML and for the bus interface it gives `pci.sys` for
/// a root bus. `bus` and `slot` name the function
/// (`Function::from_interface`). Returns `length`, as Windows' routine
/// does whatever it read; what NK cannot reach reads as all ones, as
/// the bus answers for a function that is not there.
///
/// # Safety
/// `buffer` is writable for `length` bytes.
pub unsafe extern "C" fn HalPciInterfaceReadConfig(
    _context: *mut c_void,
    bus: u32,
    slot: u32,
    buffer: *mut u8,
    offset: u32,
    length: u32,
) -> u32 {
    let function = Function::from_interface(bus, slot);
    let read = mechanism(function).map_or(0, |m| {
        let within = pci::within(offset, length, m.space());
        // SAFETY: `within` is at most `length` and ends in the space.
        unsafe { copy_out(m, function, offset, within, buffer) };
        within
    });
    // SAFETY: the rest of the caller's buffer.
    unsafe {
        buffer
            .add(read as usize)
            .write_bytes(0xFF, (length - read) as usize);
    }
    length
}

/// The HAL's ACPI table, `HalPciInterfaceWriteConfig`: the write that
/// goes with [`HalPciInterfaceReadConfig`]. Returns `length`; what NK
/// cannot reach is not written.
///
/// # Safety
/// `buffer` is readable for `length` bytes.
pub unsafe extern "C" fn HalPciInterfaceWriteConfig(
    _context: *mut c_void,
    bus: u32,
    slot: u32,
    buffer: *const u8,
    offset: u32,
    length: u32,
) -> u32 {
    let function = Function::from_interface(bus, slot);
    if let Some(m) = mechanism(function) {
        let within = pci::within(offset, length, m.space());
        // SAFETY: `within` is at most `length` and ends in the space.
        unsafe { copy_in(m, function, offset, within, buffer) };
    }
    length
}

/// The HAL's ACPI table, `HalSetMaxLegacyPciBusNumber`: `acpi.sys`
/// tells the HAL of a bus number firmware uses. Windows' HAL keeps the
/// highest and answers its bus-data exports only up to it. NK's
/// (`hal::bus`) answer for every bus a configuration mechanism reaches,
/// so there is no maximum to raise.
pub extern "C" fn HalSetMaxLegacyPciBusNumber(_bus: u32) {}

/// Put the routines of this file in their slots.
pub fn provide() {
    use super::dispatch::{HalAcpiDispatchTable, acpi_slot};
    HalAcpiDispatchTable.provide(
        acpi_slot("HalPciInterfaceReadConfig"),
        HalPciInterfaceReadConfig as *const (),
    );
    HalAcpiDispatchTable.provide(
        acpi_slot("HalPciInterfaceWriteConfig"),
        HalPciInterfaceWriteConfig as *const (),
    );
    HalAcpiDispatchTable.provide(
        acpi_slot("HalSetMaxLegacyPciBusNumber"),
        HalSetMaxLegacyPciBusNumber as *const (),
    );
}

/// For the self-tests: the host bridge's first registers read as
/// `acpi.sys` reads them, through the slot at Windows' offset, and a
/// function no mechanism reaches.
pub fn interface_test() -> Result<(), &'static str> {
    type Read = unsafe extern "C" fn(*mut c_void, u32, u32, *mut u8, u32, u32) -> u32;
    let slot = |offset: usize| {
        // SAFETY: the table is pointers after its header.
        unsafe {
            super::dispatch::HalAcpiDispatchTable
                .address()
                .cast::<u8>()
                .add(offset)
                .cast::<*const ()>()
                .read()
        }
    };
    // SAFETY: the slot holds `HalPciInterfaceReadConfig`, of this type.
    let read_config: Read = unsafe { core::mem::transmute(slot(0x30)) };
    let bridge = Function {
        segment: 0,
        bus: 0,
        device: 0,
        function: 0,
    };
    let mut own = [0u8; 8];
    if read(bridge, 0, &mut own) != own.len() {
        return Err("the host bridge's registers were not read");
    }
    let mut through = [0u8; 8];
    // SAFETY: a local of the length given.
    let length = unsafe { read_config(core::ptr::null_mut(), 0, 0, through.as_mut_ptr(), 0, 8) };
    if length != 8 || through != own {
        return Err("the interface did not read what the HAL's own access reads");
    }
    // A segment no mechanism reaches reads as all ones, in full.
    let mut absent = [0u8; 4];
    // SAFETY: as above.
    let length = unsafe {
        read_config(
            core::ptr::null_mut(),
            0xFFFF << 8,
            0,
            absent.as_mut_ptr(),
            0,
            4,
        )
    };
    if length != 4 || absent != [0xFF; 4] {
        return Err("a function that cannot be reached did not read as all ones");
    }
    // A write of the vendor identifier, which is read-only, is taken
    // and changes nothing.
    type Write = unsafe extern "C" fn(*mut c_void, u32, u32, *const u8, u32, u32) -> u32;
    // SAFETY: the slot holds `HalPciInterfaceWriteConfig`, of this type.
    let write_config: Write = unsafe { core::mem::transmute(slot(0x38)) };
    // SAFETY: two bytes of a local.
    let length = unsafe { write_config(core::ptr::null_mut(), 0, 0, own.as_ptr(), 0, 2) };
    let mut after = [0u8; 8];
    read(bridge, 0, &mut after);
    if length != 2 || after != own {
        return Err("a write through the interface was not carried out as the HAL's own");
    }
    // SAFETY: the slot holds `HalSetMaxLegacyPciBusNumber`.
    let set_max: extern "C" fn(u32) = unsafe { core::mem::transmute(slot(0x48)) };
    set_max(0xFF);
    Ok(())
}

/// How one function's registers are reached.
#[derive(Clone, Copy)]
enum Mechanism {
    /// Its 4096 bytes are at this address.
    Memory(u64),
    /// Through the configuration ports.
    Ports(arch::PciPorts),
}

impl Mechanism {
    /// Bytes of configuration space the mechanism reaches.
    fn space(self) -> u32 {
        match self {
            Mechanism::Memory(_) => pci::ECAM_SPACE,
            Mechanism::Ports(_) => pci::PORT_SPACE,
        }
    }

    /// Read one register of `function`. The caller holds the lock and
    /// `piece` lies in the mechanism's space.
    fn get(self, function: Function, piece: Piece) -> u32 {
        match self {
            Mechanism::Memory(base) => {
                let register = (base + u64::from(piece.offset)) as *const u8;
                // SAFETY: the register lies in the function's page of
                // configuration space, mapped as device memory by `init`
                // and aligned to its width; device registers are read
                // with volatile accesses.
                unsafe {
                    match piece.width {
                        1 => u32::from(register.read_volatile()),
                        2 => u32::from(register.cast::<u16>().read_volatile()),
                        _ => register.cast::<u32>().read_volatile(),
                    }
                }
            }
            Mechanism::Ports(ports) => {
                let Function {
                    bus,
                    device,
                    function,
                    ..
                } = function;
                match pci::port_address(bus, device, function, piece.offset) {
                    Some(address) => ports.read(address, piece.offset & 3, piece.width),
                    None => u32::MAX,
                }
            }
        }
    }

    /// Write one register of `function`; as [`get`](Self::get).
    fn put(self, function: Function, piece: Piece, value: u32) {
        match self {
            Mechanism::Memory(base) => {
                let register = (base + u64::from(piece.offset)) as *mut u8;
                // SAFETY: as in `get`.
                unsafe {
                    match piece.width {
                        1 => register.write_volatile(value as u8),
                        2 => register.cast::<u16>().write_volatile(value as u16),
                        _ => register.cast::<u32>().write_volatile(value),
                    }
                }
            }
            Mechanism::Ports(ports) => {
                let Function {
                    bus,
                    device,
                    function,
                    ..
                } = function;
                if let Some(address) = pci::port_address(bus, device, function, piece.offset) {
                    ports.write(address, piece.offset & 3, piece.width, value);
                }
            }
        }
    }
}

/// The mechanism through memory for `function`, if the MCFG covers its
/// bus.
fn memory(function: Function) -> Option<Mechanism> {
    platform::get().ecam().find_map(|(index, entry)| {
        if !entry.covers(function.segment, function.bus) {
            return None;
        }
        let offset = entry.function_offset(function.bus, function.device, function.function)?;
        match MAPPED[index].load(Ordering::Acquire) {
            0 => None,
            va => Some(Mechanism::Memory(va + offset)),
        }
    })
}

/// The mechanism through the ports for `function`: segment 0 of an
/// architecture that has them.
fn ports(function: Function) -> Option<Mechanism> {
    let in_range = function.segment == 0 && function.device < 32 && function.function < 8;
    arch::PCI_PORTS.filter(|_| in_range).map(Mechanism::Ports)
}

/// How `function` is reached: through memory if the MCFG covers its bus,
/// else through the ports; `None` for a bus neither reaches.
fn mechanism(function: Function) -> Option<Mechanism> {
    memory(function).or_else(|| ports(function))
}

/// Bytes of configuration space `function` has, as far as NK can reach
/// them: 4096 through memory, 256 through the ports, 0 for a bus that
/// does not exist. Says nothing about whether a device is there.
pub fn space(function: Function) -> u32 {
    mechanism(function).map_or(0, Mechanism::space)
}

/// Copy `len` bytes of `function`'s configuration space, from `offset`,
/// to `to`, register by register.
///
/// # Safety
/// `to` is valid for `len` bytes of writes, and `offset + len` lies in
/// the mechanism's space.
unsafe fn copy_out(m: Mechanism, function: Function, offset: u32, len: u32, to: *mut u8) {
    let _held = CONFIG.lock();
    for piece in pci::pieces(offset, len) {
        let value = m.get(function, piece).to_le_bytes();
        // SAFETY: the piece lies in the `len` bytes per the contract.
        unsafe {
            to.add((piece.offset - offset) as usize)
                .copy_from_nonoverlapping(value.as_ptr(), usize::from(piece.width));
        }
    }
}

/// Copy `len` bytes from `from` to `function`'s configuration space at
/// `offset`, register by register.
///
/// # Safety
/// `from` is valid for `len` bytes of reads, and `offset + len` lies in
/// the mechanism's space.
unsafe fn copy_in(m: Mechanism, function: Function, offset: u32, len: u32, from: *const u8) {
    let _held = CONFIG.lock();
    for piece in pci::pieces(offset, len) {
        let mut value = [0u8; 4];
        // SAFETY: the piece lies in the `len` bytes per the contract.
        unsafe {
            from.add((piece.offset - offset) as usize)
                .copy_to_nonoverlapping(value.as_mut_ptr(), usize::from(piece.width));
        }
        m.put(function, piece, u32::from_le_bytes(value));
    }
}

/// Read `buffer.len()` bytes of `function`'s configuration space from
/// `offset`. Returns how many were read: fewer than asked where the
/// space ends, none for a bus that does not exist. A function that is
/// not there reads as all ones, as the bus itself answers.
pub fn read(function: Function, offset: u32, buffer: &mut [u8]) -> usize {
    let Some(m) = mechanism(function) else {
        return 0;
    };
    let len = pci::within(offset, buffer.len() as u32, m.space());
    // SAFETY: `len` is at most the buffer's length and ends in the space.
    unsafe { copy_out(m, function, offset, len, buffer.as_mut_ptr()) };
    len as usize
}

/// Write `data` to `function`'s configuration space at `offset`. Returns
/// how many bytes were written, as [`read`] counts them.
pub fn write(function: Function, offset: u32, data: &[u8]) -> usize {
    let Some(m) = mechanism(function) else {
        return 0;
    };
    let len = pci::within(offset, data.len() as u32, m.space());
    // SAFETY: `len` is at most the data's length and ends in the space.
    unsafe { copy_in(m, function, offset, len, data.as_ptr()) };
    len as usize
}

/// Whether a function is at `function`, by `m`: its vendor register
/// answers, and for a function other than 0 its device says it has
/// several.
fn present(m: Mechanism, function: Function) -> bool {
    let mut vendor = [0xFF; 2];
    let mut header_type = [0u8; 1];
    // SAFETY: two bytes and one byte, in the first 256 of the space.
    unsafe {
        copy_out(m, function, 0, 2, vendor.as_mut_ptr());
        if function.function != 0 {
            copy_out(
                m,
                function.first(),
                pci::HEADER_TYPE,
                1,
                header_type.as_mut_ptr(),
            );
        }
    }
    pci::present(
        function.function,
        u16::from_le_bytes(vendor),
        header_type[0],
    )
}

/// The function a bus-data routine's arguments name, and how it is
/// reached; `None` for another kind of bus data or a bus that does not
/// exist.
fn named(bus_data_type: u32, bus_number: u32, slot_number: u32) -> Option<(Mechanism, Function)> {
    if bus_data_type != pci::PCI_CONFIGURATION {
        return None;
    }
    let (segment, bus) = pci::bus_number(bus_number);
    let (device, function) = pci::slot(slot_number);
    let function = Function {
        segment,
        bus,
        device,
        function,
    };
    Some((mechanism(function)?, function))
}

/// [`HalGetBusDataByOffset`](https://learn.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff546599(v=vs.85)):
/// read a function's PCI configuration space. Returns the bytes read; 0
/// for a bus that does not exist or bus data that is not
/// `PCIConfiguration`; for a slot with no function, the bytes of the
/// vendor register the request covers, set to `PCI_INVALID_VENDORID`
/// (2 for a read of the header).
///
/// # Safety
/// `buffer` is valid for `length` bytes of writes.
pub unsafe extern "C" fn HalGetBusDataByOffset(
    bus_data_type: u32,
    bus_number: u32,
    slot_number: u32,
    buffer: *mut c_void,
    offset: u32,
    length: u32,
) -> u32 {
    let Some((m, function)) = named(bus_data_type, bus_number, slot_number) else {
        return 0;
    };
    if !present(m, function) {
        let len = pci::absent_read(offset, length);
        // SAFETY: `len` is at most `length`.
        unsafe { buffer.cast::<u8>().write_bytes(0xFF, len as usize) };
        return len;
    }
    let len = pci::within(offset, length, m.space());
    // SAFETY: per the contract; `len` is at most `length`.
    unsafe { copy_out(m, function, offset, len, buffer.cast()) };
    len
}

/// [`HalSetBusDataByOffset`](https://learn.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff546628(v=vs.85)):
/// write a function's PCI configuration space. Returns the bytes
/// written: 0 for a bus that does not exist, bus data that is not
/// `PCIConfiguration`, or a slot with no function.
///
/// # Safety
/// `buffer` is valid for `length` bytes of reads.
pub unsafe extern "C" fn HalSetBusDataByOffset(
    bus_data_type: u32,
    bus_number: u32,
    slot_number: u32,
    buffer: *mut c_void,
    offset: u32,
    length: u32,
) -> u32 {
    let Some((m, function)) = named(bus_data_type, bus_number, slot_number) else {
        return 0;
    };
    if !present(m, function) {
        return 0;
    }
    let len = pci::within(offset, length, m.space());
    // SAFETY: per the contract; `len` is at most `length`.
    unsafe { copy_in(m, function, offset, len, buffer.cast_const().cast()) };
    len
}

/// The first 64 bytes of `function`, read through memory and through
/// the ports: `None` unless both mechanisms reach it.
pub fn both_mechanisms(function: Function) -> Option<([u8; 64], [u8; 64])> {
    let (by_memory, by_ports) = (memory(function)?, ports(function)?);
    let (mut a, mut b) = ([0u8; 64], [0u8; 64]);
    // SAFETY: 64 bytes each, in the first 256 of the space.
    unsafe {
        copy_out(by_memory, function, 0, 64, a.as_mut_ptr());
        copy_out(by_ports, function, 0, 64, b.as_mut_ptr());
    }
    Some((a, b))
}
