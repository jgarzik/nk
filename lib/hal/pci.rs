//! PCI configuration space: how a function is named, how a request for
//! some of its bytes is cut into register accesses, and what the bus-data
//! routines answer.
//!
//! [`HalGetBusDataByOffset`](https://learn.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff546599(v=vs.85))
//! names a function by a bus number and a `PCI_SLOT_NUMBER`.

/// One function of one device: where configuration space is addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Function {
    /// PCI segment group.
    pub segment: u16,
    pub bus: u8,
    /// 0 to 31.
    pub device: u8,
    /// 0 to 7.
    pub function: u8,
}

impl Function {
    /// Function 0 of the same device, which says whether the device has
    /// other functions.
    pub const fn first(self) -> Self {
        Self {
            function: 0,
            ..self
        }
    }
}

/// `BUS_DATA_TYPE` `PCIConfiguration`.
pub const PCI_CONFIGURATION: u32 = 4;
/// `PCI_INVALID_VENDORID`: what the vendor register reads where there is
/// no function.
pub const INVALID_VENDOR: u16 = 0xFFFF;
/// Offset of the header-type register, and its multi-function bit.
pub const HEADER_TYPE: u32 = 0x0E;
pub const MULTI_FUNCTION: u8 = 0x80;

/// Bytes of configuration space reachable through the configuration
/// ports, and through memory (ECAM).
pub const PORT_SPACE: u32 = 0x100;
pub const ECAM_SPACE: u32 = 0x1000;

/// The device and function a `PCI_SLOT_NUMBER` names: device in bits 0-4,
/// function in bits 5-7. The other bits are reserved and not looked at.
pub const fn slot(slot_number: u32) -> (u8, u8) {
    ((slot_number & 0x1F) as u8, (slot_number >> 5 & 7) as u8)
}

/// The `PCI_SLOT_NUMBER` of a device and function.
pub const fn slot_number(device: u8, function: u8) -> u32 {
    (device as u32 & 0x1F) | (function as u32 & 7) << 5
}

/// The segment group and bus a bus-data routine's `BusNumber` names: the
/// bus in the low eight bits and the segment in the sixteen above them.
/// That is NK's reading for machines with more than one segment; with
/// one, `BusNumber` is the bus, as documented.
pub const fn bus_number(bus_number: u32) -> (u16, u8) {
    ((bus_number >> 8) as u16, bus_number as u8)
}

/// What is written to port `0xCF8` to select the 32-bit register holding
/// `offset` of a function, for an access through port `0xCFC`
/// (configuration mechanism #1). `None` for an offset the mechanism
/// cannot reach or a device or function number out of range.
pub const fn port_address(bus: u8, device: u8, function: u8, offset: u32) -> Option<u32> {
    if device >= 32 || function >= 8 || offset >= PORT_SPACE {
        return None;
    }
    Some(
        1 << 31
            | (bus as u32) << 16
            | (device as u32) << 11
            | (function as u32) << 8
            | offset & 0xFC,
    )
}

/// One register access: `width` bytes (1, 2 or 4) at `offset`, which is a
/// multiple of `width`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Piece {
    pub offset: u32,
    pub width: u8,
}

/// Cut `len` bytes at `offset` into register accesses, each as wide as
/// its alignment and what is left allow: configuration registers are
/// read and written whole where the request covers them whole, and never
/// across a 32-bit boundary.
pub fn pieces(offset: u32, len: u32) -> impl Iterator<Item = Piece> {
    let (mut at, end) = (offset, offset.saturating_add(len));
    core::iter::from_fn(move || {
        if at >= end {
            return None;
        }
        let width = [4u32, 2, 1]
            .into_iter()
            .find(|w| at.is_multiple_of(*w) && end - at >= *w)?;
        let piece = Piece {
            offset: at,
            width: width as u8,
        };
        at += width;
        Some(piece)
    })
}

/// How many of the `length` bytes asked for at `offset` lie in a
/// configuration space of `space` bytes.
pub const fn within(offset: u32, length: u32, space: u32) -> u32 {
    if offset >= space {
        0
    } else if length > space - offset {
        space - offset
    } else {
        length
    }
}

/// How many bytes a read of `length` bytes at `offset` returns where no
/// function answers: those of the vendor register, which reads
/// [`INVALID_VENDOR`], that the request covers. A read of the header from
/// its start so returns 2, the documented answer for an empty slot.
pub const fn absent_read(offset: u32, length: u32) -> u32 {
    within(offset, length, 2)
}

/// Whether a function is there, given the vendor register it reads and,
/// for a function other than 0, the header type of function 0: a device
/// that does not say it has several functions has only function 0, even
/// if it answers for the others.
pub const fn present(function: u8, vendor: u16, first_header_type: u8) -> bool {
    vendor != INVALID_VENDOR && (function == 0 || first_header_type & MULTI_FUNCTION != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_slot_number_holds_device_and_function() {
        assert_eq!(slot(0), (0, 0));
        // 00:1f.2
        assert_eq!(slot(0x5F), (0x1F, 2));
        assert_eq!(slot_number(0x1F, 2), 0x5F);
        assert_eq!(slot(0xFF), (31, 7));
        // Reserved bits are not looked at.
        assert_eq!(slot(0xFFFF_FF00 | 0x23), (3, 1));
        for device in 0..32 {
            for function in 0..8 {
                assert_eq!(slot(slot_number(device, function)), (device, function));
            }
        }
    }

    #[test]
    fn a_bus_number_holds_the_segment_above_the_bus() {
        assert_eq!(bus_number(0), (0, 0));
        assert_eq!(bus_number(0xFF), (0, 0xFF));
        assert_eq!(bus_number(0x0123), (1, 0x23));
        assert_eq!(bus_number(0x00FF_FFFF), (0xFFFF, 0xFF));
    }

    #[test]
    fn the_port_address_selects_a_32_bit_register() {
        assert_eq!(port_address(0, 0, 0, 0), Some(0x8000_0000));
        // 00:1f.2, the interrupt line register: its dword is 0x3C.
        assert_eq!(port_address(0, 0x1F, 2, 0x3C), Some(0x8000_FA3C));
        assert_eq!(port_address(0, 0x1F, 2, 0x3D), Some(0x8000_FA3C));
        assert_eq!(port_address(0, 0x1F, 2, 0x3F), Some(0x8000_FA3C));
        assert_eq!(port_address(0xFF, 31, 7, 0xFF), Some(0x80FF_FFFC));
        assert_eq!(port_address(0, 0, 0, 0x100), None);
        assert_eq!(port_address(0, 32, 0, 0), None);
        assert_eq!(port_address(0, 0, 8, 0), None);
    }

    fn cut(offset: u32, len: u32) -> Vec<(u32, u8)> {
        pieces(offset, len).map(|p| (p.offset, p.width)).collect()
    }

    #[test]
    fn a_request_is_cut_into_whole_registers() {
        assert_eq!(cut(0, 4), [(0, 4)]);
        assert_eq!(cut(0, 2), [(0, 2)]);
        assert_eq!(cut(0x3C, 1), [(0x3C, 1)]);
        assert_eq!(cut(0, 8), [(0, 4), (4, 4)]);
        // Unaligned ends: bytes and words up to the boundary, then whole.
        assert_eq!(cut(1, 7), [(1, 1), (2, 2), (4, 4)]);
        assert_eq!(cut(3, 6), [(3, 1), (4, 4), (8, 1)]);
        assert_eq!(cut(2, 5), [(2, 2), (4, 2), (6, 1)]);
        assert_eq!(cut(5, 2), [(5, 1), (6, 1)]);
        assert_eq!(cut(7, 0), []);
        // Every byte once, in order, never across a dword.
        for offset in 0..9 {
            for len in 0..13 {
                let mut at = offset;
                for (o, w) in cut(offset, len) {
                    assert_eq!(o, at);
                    assert_eq!(o % u32::from(w), 0);
                    assert_eq!(o / 4, (o + u32::from(w) - 1) / 4);
                    at += u32::from(w);
                }
                assert_eq!(at, offset + len);
            }
        }
        // A length that would overflow ends at the top, without a panic.
        assert_eq!(pieces(u32::MAX - 1, 8).count(), 1);
    }

    #[test]
    fn a_request_is_held_to_the_configuration_space() {
        assert_eq!(within(0, 256, PORT_SPACE), 256);
        assert_eq!(within(0, 4096, PORT_SPACE), 256);
        assert_eq!(within(0xFC, 8, PORT_SPACE), 4);
        assert_eq!(within(0x100, 4, PORT_SPACE), 0);
        assert_eq!(within(0x100, 4, ECAM_SPACE), 4);
        assert_eq!(within(0xFFF, 4, ECAM_SPACE), 1);
        assert_eq!(within(u32::MAX, u32::MAX, ECAM_SPACE), 0);
        assert_eq!(within(8, 0, ECAM_SPACE), 0);
    }

    #[test]
    fn an_empty_slot_reads_as_the_invalid_vendor() {
        assert_eq!(absent_read(0, 256), 2);
        assert_eq!(absent_read(0, 2), 2);
        assert_eq!(absent_read(0, 1), 1);
        assert_eq!(absent_read(1, 4), 1);
        assert_eq!(absent_read(2, 4), 0);
        assert_eq!(absent_read(0x40, 4), 0);
    }

    #[test]
    fn a_function_is_there_if_it_answers_and_its_device_admits_it() {
        assert!(present(0, 0x8086, 0));
        assert!(!present(0, INVALID_VENDOR, 0));
        assert!(present(2, 0x8086, 0x80));
        assert!(!present(2, 0x8086, 0x00), "a single-function device");
        assert!(!present(2, INVALID_VENDOR, 0x80));
        let f = Function {
            segment: 1,
            bus: 2,
            device: 3,
            function: 4,
        };
        assert_eq!(f.first().function, 0);
        assert_eq!(
            (f.first().segment, f.first().bus, f.first().device),
            (1, 2, 3)
        );
    }
}
