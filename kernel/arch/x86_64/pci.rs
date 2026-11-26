//! The PCI configuration ports: configuration mechanism #1 of the
//! [PCI Local Bus Specification](https://pcisig.com/specifications). An
//! address written to port `0xCF8` selects a 32-bit register of one
//! function; ports `0xCFC` to `0xCFF` are then its four bytes.

use core::arch::asm;

const ADDRESS: u16 = 0xCF8;
const DATA: u16 = 0xCFC;

/// The configuration ports. The caller serialises their use: the address
/// register is shared by every access.
#[derive(Clone, Copy)]
pub struct PciPorts;

/// Every PC has them.
pub const PCI_PORTS: Option<PciPorts> = Some(PciPorts);

impl PciPorts {
    /// Read `width` bytes (1, 2 or 4) from byte `lane` of the register
    /// `address` selects.
    pub fn read(self, address: u32, lane: u32, width: u8) -> u32 {
        let port = DATA + lane as u16;
        // SAFETY: the configuration ports of a PC; port access touches
        // no memory.
        unsafe {
            asm!("out dx, eax", in("dx") ADDRESS, in("eax") address, options(nomem, nostack));
            match width {
                1 => {
                    let value: u8;
                    asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack));
                    u32::from(value)
                }
                2 => {
                    let value: u16;
                    asm!("in ax, dx", in("dx") port, out("ax") value, options(nomem, nostack));
                    u32::from(value)
                }
                _ => {
                    let value: u32;
                    asm!("in eax, dx", in("dx") port, out("eax") value, options(nomem, nostack));
                    value
                }
            }
        }
    }

    /// Write `width` bytes of `value` to byte `lane` of the register
    /// `address` selects.
    pub fn write(self, address: u32, lane: u32, width: u8, value: u32) {
        let port = DATA + lane as u16;
        // SAFETY: as in `read`.
        unsafe {
            asm!("out dx, eax", in("dx") ADDRESS, in("eax") address, options(nomem, nostack));
            match width {
                1 => {
                    asm!("out dx, al", in("dx") port, in("al") value as u8, options(nomem, nostack));
                }
                2 => {
                    asm!("out dx, ax", in("dx") port, in("ax") value as u16, options(nomem, nostack));
                }
                _ => asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack)),
            }
        }
    }
}
