//! PCI configuration ports: arm64 has no I/O ports, so there are none,
//! and configuration space is reached through memory alone.

/// The configuration ports, of which there are none: a type with no
/// values.
#[derive(Clone, Copy)]
pub enum PciPorts {}

pub const PCI_PORTS: Option<PciPorts> = None;

impl PciPorts {
    pub fn read(self, _address: u32, _lane: u32, _width: u8) -> u32 {
        match self {}
    }

    pub fn write(self, _address: u32, _lane: u32, _width: u8, _value: u32) {
        match self {}
    }
}
