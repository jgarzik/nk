//! A device's interrupt connection data: the property
//! (`INTERRUPT_CONNECTION_DATA_PKEY`) in which Windows tells a bus
//! driver how each interrupt of a device it started is delivered.
//! `pci.sys` reads it when it starts a device with message-signalled
//! interrupts and programs the address and data of each message from
//! it.
//!
//! The value is an `INTERRUPT_CONNECTION_DATA`: a count and that many
//! `INTERRUPT_VECTOR_DATA`, one per interrupt descriptor of the
//! device's resource list, in the list's order. The layout is the
//! pinned kernel's symbols'.
//!
//! A message is stated the way `pci.sys` insists on
//! (`PciProcessInterruptDescriptor` refuses any other type for a
//! message descriptor): as a message request, which the bus driver
//! hands to the HAL (`HalGetMessageRoutingInfo`) together with the
//! entry's remapping information and gets back as an address and data.
//! NK remaps nothing, so the remapping information holds the message
//! itself, which is what the HAL then answers.

use alloc::vec::Vec;

/// The property's category and number.
pub const CONNECTION_DATA_CATEGORY: [u8; 16] = [
    0x09, 0x0f, 0xe2, 0xf0, 0x7a, 0xd9, 0xa9, 0x49, 0x80, 0x46, 0xbb, 0x6e, 0x22, 0xe6, 0xbb, 0x2e,
];
pub const CONNECTION_DATA_NUMBER: u32 = 2;

/// `INTERRUPT_CONNECTION_TYPE`: a line of an interrupt controller, and
/// a message a device was asked for.
const TYPE_CONTROLLER_INPUT: u32 = 0;
const TYPE_MESSAGE_REQUEST: u32 = 3;

/// `KINTERRUPT_POLARITY`, `KINTERRUPT_MODE`.
const POLARITY_ACTIVE_HIGH: u32 = 1;
const POLARITY_ACTIVE_LOW: u32 = 2;
const MODE_LEVEL_SENSITIVE: u32 = 0;
const MODE_LATCHED: u32 = 1;
/// `HAL_APIC_DESTINATION_MODE`: physical.
const DESTINATION_PHYSICAL: u32 = 1;

/// The size of one `INTERRUPT_VECTOR_DATA`, and where its members are.
const VECTOR_DATA: usize = 88;
const HEADER: usize = 8;

/// How one interrupt of a device is delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivery {
    pub vector: u32,
    pub irql: u8,
    /// The processors it may arrive on, of group 0.
    pub affinity: u64,
    pub source: Source,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// A line: its global system interrupt, and how it signals.
    Line { gsi: u32, edge: bool, low: bool },
    /// A message: what the device writes, and where.
    Message { address: u64, data: u32 },
}

/// The property's value for a device whose interrupts are delivered as
/// `deliveries` say.
pub fn connection_data(deliveries: &[Delivery]) -> Vec<u8> {
    let mut data = alloc::vec![0u8; HEADER + deliveries.len() * VECTOR_DATA];
    data[..4].copy_from_slice(&(deliveries.len() as u32).to_le_bytes());
    for (at, delivery) in deliveries.iter().enumerate() {
        let entry = &mut data[HEADER + at * VECTOR_DATA..][..VECTOR_DATA];
        let put = |entry: &mut [u8], offset: usize, value: u32| {
            entry[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        };
        let (kind, polarity, mode) = match delivery.source {
            Source::Line { edge, low, .. } => (
                TYPE_CONTROLLER_INPUT,
                if low {
                    POLARITY_ACTIVE_LOW
                } else {
                    POLARITY_ACTIVE_HIGH
                },
                if edge {
                    MODE_LATCHED
                } else {
                    MODE_LEVEL_SENSITIVE
                },
            ),
            // A message is a rising edge.
            Source::Message { .. } => (TYPE_MESSAGE_REQUEST, POLARITY_ACTIVE_HIGH, MODE_LATCHED),
        };
        put(entry, 0, kind);
        put(entry, 4, delivery.vector);
        entry[8] = delivery.irql;
        put(entry, 12, polarity);
        put(entry, 16, mode);
        // `TargetProcessors`: a mask and group 0.
        entry[24..32].copy_from_slice(&delivery.affinity.to_le_bytes());
        match delivery.source {
            // `ControllerInput.Gsiv`.
            Source::Line { gsi, .. } => put(entry, 56, gsi),
            Source::Message { address, data } => {
                // `IntRemapInfo`: no remapping table entry, and the
                // message as it goes on the bus: address high, address
                // low, data.
                put(entry, 44, (address >> 32) as u32);
                put(entry, 48, address as u32);
                put(entry, 52, data & 0xFFFF);
                // `MessageRequest.DestinationMode`: the processor is
                // named by its own identifier.
                put(entry, 72, DESTINATION_PHYSICAL);
            }
        }
    }
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32_at(data: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
    }

    /// One message, as the reference machine's AHCI controller has:
    /// the structure is 96 bytes; `pci.sys` finds the type at 8, the
    /// vector at 12, the processors at 32, the remapping information
    /// at 48 and the destination mode at 80, and hands the last four
    /// to the HAL, which reads the message's address and data out of
    /// the remapping information.
    #[test]
    fn one_message() {
        let data = connection_data(&[Delivery {
            vector: 0x60,
            irql: 6,
            affinity: 0xF,
            source: Source::Message {
                address: 0xFEE0_1000,
                data: 0x60,
            },
        }]);
        assert_eq!(data.len(), 96);
        assert_eq!(u32_at(&data, 0), 1);
        assert_eq!(u32_at(&data, 8), 3);
        assert_eq!(u32_at(&data, 12), 0x60);
        assert_eq!(data[16], 6);
        assert_eq!((u32_at(&data, 20), u32_at(&data, 24)), (1, 1));
        assert_eq!(&data[32..40], &0xFu64.to_le_bytes());
        assert_eq!(u32_at(&data, 48), 0);
        assert_eq!((u32_at(&data, 52), u32_at(&data, 56)), (0, 0xFEE0_1000));
        assert_eq!(u32_at(&data, 60), 0x60);
        assert_eq!(u32_at(&data, 80), 1);
    }

    #[test]
    fn lines_and_several_interrupts() {
        let line = |gsi, edge, low| Delivery {
            vector: 0x51,
            irql: 5,
            affinity: 1,
            source: Source::Line { gsi, edge, low },
        };
        let data = connection_data(&[line(10, false, true), line(1, true, false)]);
        assert_eq!(data.len(), 8 + 2 * 88);
        assert_eq!(u32_at(&data, 0), 2);
        // The first: a controller input, active low, level.
        assert_eq!(
            (u32_at(&data, 8), u32_at(&data, 20), u32_at(&data, 24)),
            (0, 2, 0)
        );
        assert_eq!(u32_at(&data, 8 + 56), 10);
        // The second: active high, latched.
        let second = 8 + 88;
        assert_eq!(
            (u32_at(&data, second + 12), u32_at(&data, second + 16)),
            (1, 1)
        );
        assert_eq!(u32_at(&data, second + 56), 1);
        assert_eq!(connection_data(&[]), [0; 8]);
    }

    #[test]
    fn the_property_is_windows() {
        assert_eq!(
            crate::ids::guid_text(&CONNECTION_DATA_CATEGORY),
            "{f0e20f09-d97a-49a9-8046-bb6e22e6bb2e}"
        );
        assert_eq!(CONNECTION_DATA_NUMBER, 2);
    }
}
