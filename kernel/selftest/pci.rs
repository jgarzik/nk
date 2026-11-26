//! Tests of PCI configuration access, made as a driver makes it: through
//! the bus-data exports.

use crate::hal::pci::{self, Function, HalGetBusDataByOffset, HalSetBusDataByOffset};
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_hal::pci::{PCI_CONFIGURATION, slot_number};

pub static GROUP: Group = Group {
    names: &[
        "hal.pci.bridge",
        "hal.pci.ahci",
        "hal.pci.write",
        "hal.pci.contract",
        "hal.pci.ports",
    ],
    run,
    manual: false,
};

const INTERRUPT_LINE: u32 = 0x3C;

/// `HalGetBusDataByOffset` for a function of bus 0.
fn get(device: u8, function: u8, offset: u32, buffer: &mut [u8]) -> u32 {
    // SAFETY: the buffer is valid for its length.
    unsafe {
        HalGetBusDataByOffset(
            PCI_CONFIGURATION,
            0,
            slot_number(device, function),
            buffer.as_mut_ptr().cast(),
            offset,
            buffer.len() as u32,
        )
    }
}

/// `HalSetBusDataByOffset` for a function of bus 0.
fn set(device: u8, function: u8, offset: u32, data: &[u8]) -> u32 {
    // SAFETY: the data is valid for its length.
    unsafe {
        HalSetBusDataByOffset(
            PCI_CONFIGURATION,
            0,
            slot_number(device, function),
            data.as_ptr().cast_mut().cast(),
            offset,
            data.len() as u32,
        )
    }
}

/// Vendor, device, and class code (base, sub-class, interface) of a
/// header.
fn identity(header: &[u8; 64]) -> (u16, u16, [u8; 3]) {
    (
        u16::from_le_bytes([header[0], header[1]]),
        u16::from_le_bytes([header[2], header[3]]),
        [header[11], header[10], header[9]],
    )
}

/// Every function of bus 0 that is there, with its header.
fn functions() -> impl Iterator<Item = (u8, u8, [u8; 64])> {
    (0..32u8)
        .flat_map(|device| (0..8u8).map(move |function| (device, function)))
        .filter_map(|(device, function)| {
            let mut header = [0u8; 64];
            (get(device, function, 0, &mut header) == 64).then_some((device, function, header))
        })
}

/// The host bridge is function 0 of device 0 of bus 0.
fn bridge() -> Result<(u16, u16), &'static str> {
    let mut header = [0u8; 64];
    if get(0, 0, 0, &mut header) != 64 {
        return Err("no function at 00:00.0");
    }
    let (vendor, device, class) = identity(&header);
    if class[..2] != [0x06, 0x00] {
        return Err("the function at 00:00.0 is not a host bridge");
    }
    Ok((vendor, device))
}

/// Writing the bridge's interrupt-line register, which is storage and
/// nothing else, changes what it reads, by the exports and by the
/// kernel's own interface alike; the register is put back.
fn write() -> Result<(), &'static str> {
    let host = Function {
        segment: 0,
        bus: 0,
        device: 0,
        function: 0,
    };
    let mut old = [0u8; 1];
    if get(0, 0, INTERRUPT_LINE, &mut old) != 1 {
        return Err("cannot read the interrupt-line register");
    }
    let new = [old[0] ^ 0x5A];
    let written = set(0, 0, INTERRUPT_LINE, &new);
    let mut seen = [0u8; 1];
    let read = get(0, 0, INTERRUPT_LINE, &mut seen);
    let mut inside = [0u8; 4];
    let inside_read = pci::read(host, INTERRUPT_LINE, &mut inside);
    let restored = pci::write(host, INTERRUPT_LINE, &old);
    let mut after = [0u8; 1];
    get(0, 0, INTERRUPT_LINE, &mut after);
    if written != 1 || read != 1 || seen != new {
        return Err("a byte written is not the byte read back");
    }
    if inside_read != 4 || inside[0] != new[0] {
        return Err("the kernel's own read disagrees with the export's");
    }
    if restored != 1 || after != old {
        return Err("the register was not put back");
    }
    Ok(())
}

/// What the routines answer where there is nothing: an empty slot, a
/// bus that does not exist, bus data of another kind, the end of the
/// configuration space.
fn contract() -> Result<(u8, u8), &'static str> {
    let empty = (0..32u8)
        .flat_map(|device| (0..8u8).map(move |function| (device, function)))
        .find(|&(device, function)| {
            let mut vendor = [0u8; 2];
            get(device, function, 0, &mut vendor);
            vendor == [0xFF; 2]
        })
        .ok_or("every slot of bus 0 holds a function")?;
    let (device, function) = empty;
    let mut header = [0xA5u8; 64];
    if get(device, function, 0, &mut header) != 2 {
        return Err("a read of an empty slot's header did not return 2");
    }
    if header[..2] != [0xFF; 2] || header[2..].iter().any(|&b| b != 0xA5) {
        return Err("an empty slot's read wrote other than the invalid vendor id");
    }
    let mut word = [0xA5u8; 4];
    if get(device, function, 0x40, &mut word) != 0 || word != [0xA5; 4] {
        return Err("a read past an empty slot's vendor id returned bytes");
    }
    if set(device, function, INTERRUPT_LINE, &[0]) != 0 {
        return Err("a write to an empty slot was counted");
    }
    // SAFETY: the buffers are valid for their lengths.
    let (other_data, other_bus) = unsafe {
        (
            // `Cmos`, bus data NK has none of.
            HalGetBusDataByOffset(0, 0, 0, word.as_mut_ptr().cast(), 0, 4),
            // Bus 0 of a segment the machine does not have.
            HalGetBusDataByOffset(
                PCI_CONFIGURATION,
                0x1234 << 8,
                0,
                word.as_mut_ptr().cast(),
                0,
                4,
            ),
        )
    };
    if other_data != 0 || other_bus != 0 || word != [0xA5; 4] {
        return Err("bus data that does not exist was read");
    }
    // The end of the space: whatever lies before it, and nothing after.
    let host = Function {
        segment: 0,
        bus: 0,
        device: 0,
        function: 0,
    };
    let space = pci::space(host);
    let mut tail = [0u8; 8];
    if get(0, 0, space - 4, &mut tail) != 4 || get(0, 0, space, &mut tail) != 0 {
        return Err("a read across the end of configuration space was not cut short");
    }
    Ok(empty)
}

fn run(r: &mut Report, _: &BootInfo) {
    match bridge() {
        Ok((vendor, device)) => r.ok_with(
            "hal.pci.bridge",
            format_args!("host bridge {vendor:04x}:{device:04x}"),
        ),
        Err(why) => r.fail("hal.pci.bridge", format_args!("{why}")),
    }
    // Mass storage, serial ATA, AHCI.
    match functions().find(|(_, _, header)| identity(header).2 == [0x01, 0x06, 0x01]) {
        Some((device, function, header)) => {
            let (vendor, id, _) = identity(&header);
            r.ok_with(
                "hal.pci.ahci",
                format_args!("AHCI controller {vendor:04x}:{id:04x} at 00:{device:02x}.{function}"),
            );
        }
        None => r.skip(
            "hal.pci.ahci",
            format_args!("no AHCI controller on bus 0 of this machine"),
        ),
    }
    r.check("hal.pci.write", write);
    match contract() {
        Ok((device, function)) => r.ok_with(
            "hal.pci.contract",
            format_args!("empty slot 00:{device:02x}.{function}"),
        ),
        Err(why) => r.fail("hal.pci.contract", format_args!("{why}")),
    }
    let host = Function {
        segment: 0,
        bus: 0,
        device: 0,
        function: 0,
    };
    match pci::both_mechanisms(host) {
        Some((by_memory, by_ports)) if by_memory == by_ports => r.ok_with(
            "hal.pci.ports",
            format_args!("ports and memory agree on 64 bytes"),
        ),
        Some(_) => r.fail(
            "hal.pci.ports",
            format_args!("the configuration ports and memory read differently"),
        ),
        None => r.skip(
            "hal.pci.ports",
            format_args!("the bridge is not reachable both through memory and through ports"),
        ),
    }
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
