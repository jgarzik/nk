//! Resource lists and resource requirements lists, as bytes and as
//! values.
//!
//! A `CM_RESOURCE_LIST` says what a device has; an
//! `IO_RESOURCE_REQUIREMENTS_LIST` what it could do with. Both are
//! variable in length and come from drivers and from the registry, so
//! they are read here from bytes, with every length checked, and
//! written back to bytes.
//! [Microsoft's description of the two](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/hardware-resources).

use alloc::vec::Vec;

pub const TYPE_NULL: u8 = 0;
pub const TYPE_PORT: u8 = 1;
pub const TYPE_INTERRUPT: u8 = 2;
pub const TYPE_MEMORY: u8 = 3;
pub const TYPE_DMA: u8 = 4;
pub const TYPE_DEVICE_SPECIFIC: u8 = 5;
pub const TYPE_BUS_NUMBER: u8 = 6;
pub const TYPE_MEMORY_LARGE: u8 = 7;
pub const TYPE_CONFIG_DATA: u8 = 128;
pub const TYPE_DEVICE_PRIVATE: u8 = 129;

/// `CmResourceShareShared`.
pub const SHARE_SHARED: u8 = 3;

/// `CM_RESOURCE_INTERRUPT_LATCHED`.
pub const INTERRUPT_LATCHED: u16 = 1;
/// `CM_RESOURCE_INTERRUPT_MESSAGE`.
pub const INTERRUPT_MESSAGE: u16 = 2;
/// `CM_RESOURCE_INTERRUPT_MESSAGE_TOKEN`: the vector a raw message
/// interrupt carries.
pub const MESSAGE_TOKEN: u32 = 0xFFFF_FFFE;

/// `CM_RESOURCE_MEMORY_LARGE_40`, `_48`, `_64`: how a large memory
/// range's length is scaled.
pub const MEMORY_LARGE_40: u16 = 0x0200;
pub const MEMORY_LARGE_48: u16 = 0x0400;
pub const MEMORY_LARGE_64: u16 = 0x0800;

/// `IO_RESOURCE_PREFERRED`, `IO_RESOURCE_ALTERNATIVE`.
pub const OPTION_PREFERRED: u8 = 1;
pub const OPTION_ALTERNATIVE: u8 = 8;

/// The sizes of the fixed parts.
const PARTIAL: usize = 20;
const FULL_HEADER: usize = 16;
const IO_DESCRIPTOR: usize = 32;
const IO_LIST_HEADER: usize = 8;
const REQUIREMENTS_HEADER: usize = 32;

/// More descriptors than any list has: a count above it is garbage.
const MAX_DESCRIPTORS: usize = 0x1_0000;

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

/// The shift a large memory range's length is stored with.
const fn large_shift(flags: u16) -> u32 {
    if flags & MEMORY_LARGE_40 != 0 {
        8
    } else if flags & MEMORY_LARGE_48 != 0 {
        16
    } else if flags & MEMORY_LARGE_64 != 0 {
        32
    } else {
        0
    }
}

/// One `CM_PARTIAL_RESOURCE_DESCRIPTOR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Partial {
    pub kind: u8,
    pub share: u8,
    pub flags: u16,
    /// The union, as stored.
    pub data: [u8; 16],
    /// What follows a device-specific descriptor: its data.
    pub extra: Vec<u8>,
}

impl Partial {
    /// A descriptor of `kind` with an all-zero union.
    pub fn new(kind: u8, share: u8, flags: u16) -> Self {
        Self {
            kind,
            share,
            flags,
            data: [0; 16],
            extra: Vec::new(),
        }
    }

    /// A port, memory or bus-number range, `length` units from
    /// `start`. A large memory range's length is stored scaled, as its
    /// flags say.
    pub fn range(kind: u8, share: u8, flags: u16, start: u64, length: u64) -> Self {
        let mut partial = Self::new(kind, share, flags);
        if kind == TYPE_BUS_NUMBER {
            partial.data[..4].copy_from_slice(&(start as u32).to_le_bytes());
            partial.data[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        } else {
            let stored = if kind == TYPE_MEMORY_LARGE {
                length >> large_shift(flags)
            } else {
                length
            };
            partial.data[..8].copy_from_slice(&start.to_le_bytes());
            partial.data[8..12].copy_from_slice(&(stored as u32).to_le_bytes());
        }
        partial
    }

    /// An interrupt: for a line or a translated interrupt, `level` and
    /// `vector`; `group` is the processor group.
    pub fn interrupt(
        share: u8,
        flags: u16,
        level: u16,
        group: u16,
        vector: u32,
        affinity: u64,
    ) -> Self {
        let mut partial = Self::new(TYPE_INTERRUPT, share, flags);
        partial.data[..2].copy_from_slice(&level.to_le_bytes());
        partial.data[2..4].copy_from_slice(&group.to_le_bytes());
        partial.data[4..8].copy_from_slice(&vector.to_le_bytes());
        partial.data[8..].copy_from_slice(&affinity.to_le_bytes());
        partial
    }

    /// A raw message-signalled interrupt of `count` messages: the
    /// token for a vector, the count where a line has its level's upper
    /// half.
    pub fn raw_messages(share: u8, flags: u16, count: u16, affinity: u64) -> Self {
        Self::interrupt(share, flags, 0, count, MESSAGE_TOKEN, affinity)
    }

    /// Where a port, memory or bus-number range starts and how long it
    /// is; `None` for other kinds.
    pub fn as_range(&self) -> Option<(u64, u64)> {
        let u32_of = |at: usize| u32::from_le_bytes(self.data[at..at + 4].try_into().unwrap());
        match self.kind {
            TYPE_PORT | TYPE_MEMORY | TYPE_MEMORY_LARGE => {
                let start = u64::from_le_bytes(self.data[..8].try_into().unwrap());
                let shift = if self.kind == TYPE_MEMORY_LARGE {
                    large_shift(self.flags)
                } else {
                    0
                };
                Some((start, u64::from(u32_of(8)) << shift))
            }
            TYPE_BUS_NUMBER => Some((u64::from(u32_of(0)), u64::from(u32_of(4)))),
            _ => None,
        }
    }

    /// An interrupt's `(level, group, vector, affinity)`; for a raw
    /// message interrupt the second is the message count.
    pub fn as_interrupt(&self) -> Option<(u16, u16, u32, u64)> {
        (self.kind == TYPE_INTERRUPT).then(|| {
            (
                u16::from_le_bytes(self.data[..2].try_into().unwrap()),
                u16::from_le_bytes(self.data[2..4].try_into().unwrap()),
                u32::from_le_bytes(self.data[4..8].try_into().unwrap()),
                u64::from_le_bytes(self.data[8..].try_into().unwrap()),
            )
        })
    }

    /// Whether this is a message-signalled interrupt.
    pub fn is_message(&self) -> bool {
        self.kind == TYPE_INTERRUPT && self.flags & INTERRUPT_MESSAGE != 0
    }
}

/// One `CM_FULL_RESOURCE_DESCRIPTOR`: the resources on one bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Full {
    pub interface: u32,
    pub bus: u32,
    pub version: u16,
    pub revision: u16,
    pub partial: Vec<Partial>,
}

/// A `CM_RESOURCE_LIST`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResourceList {
    pub full: Vec<Full>,
}

impl ResourceList {
    /// A list of one full descriptor, as the Plug and Play manager
    /// builds a device's.
    pub fn of(interface: u32, bus: u32, partial: Vec<Partial>) -> Self {
        Self {
            full: alloc::vec![Full {
                interface,
                bus,
                version: 1,
                revision: 1,
                partial,
            }],
        }
    }

    /// The list `bytes` starts with, and how many bytes it is long.
    /// `None` if the bytes end before the list does or a count is
    /// beyond belief.
    pub fn parse(bytes: &[u8]) -> Option<(Self, usize)> {
        let count = u32_at(bytes, 0)? as usize;
        if count > MAX_DESCRIPTORS {
            return None;
        }
        let mut at = 4;
        let mut full = Vec::new();
        for _ in 0..count {
            let partials = u32_at(bytes, at + 12)? as usize;
            if partials > MAX_DESCRIPTORS {
                return None;
            }
            let mut one = Full {
                interface: u32_at(bytes, at)?,
                bus: u32_at(bytes, at + 4)?,
                version: u16_at(bytes, at + 8)?,
                revision: u16_at(bytes, at + 10)?,
                partial: Vec::new(),
            };
            at += FULL_HEADER;
            for _ in 0..partials {
                let fixed = bytes.get(at..at + PARTIAL)?;
                let mut partial = Partial::new(fixed[0], fixed[1], u16_at(fixed, 2)?);
                partial.data.copy_from_slice(&fixed[4..]);
                at += PARTIAL;
                if partial.kind == TYPE_DEVICE_SPECIFIC {
                    let size = u32_at(&partial.data, 0)? as usize;
                    partial.extra = bytes.get(at..at.checked_add(size)?)?.to_vec();
                    at += size;
                }
                one.partial.push(partial);
            }
            full.push(one);
        }
        Some((Self { full }, at))
    }

    /// The list as bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(self.full.len() as u32).to_le_bytes());
        for full in &self.full {
            bytes.extend_from_slice(&full.interface.to_le_bytes());
            bytes.extend_from_slice(&full.bus.to_le_bytes());
            bytes.extend_from_slice(&full.version.to_le_bytes());
            bytes.extend_from_slice(&full.revision.to_le_bytes());
            bytes.extend_from_slice(&(full.partial.len() as u32).to_le_bytes());
            for partial in &full.partial {
                bytes.push(partial.kind);
                bytes.push(partial.share);
                bytes.extend_from_slice(&partial.flags.to_le_bytes());
                bytes.extend_from_slice(&partial.data);
                bytes.extend_from_slice(&partial.extra);
            }
        }
        bytes
    }

    /// Every partial descriptor of the list, bus after bus.
    pub fn partials(&self) -> impl Iterator<Item = &Partial> {
        self.full.iter().flat_map(|full| full.partial.iter())
    }
}

/// One `IO_RESOURCE_DESCRIPTOR`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoDescriptor {
    pub option: u8,
    pub kind: u8,
    pub share: u8,
    pub flags: u16,
    /// The union, as stored.
    pub data: [u8; 24],
}

impl IoDescriptor {
    /// A port or memory range, as `wanted` describes it. The length
    /// and the alignment are 32 bits wide in a descriptor.
    pub fn range(option: u8, kind: u8, share: u8, flags: u16, wanted: Wanted) -> Self {
        let mut data = [0; 24];
        data[..4].copy_from_slice(&(wanted.length as u32).to_le_bytes());
        data[4..8].copy_from_slice(&(wanted.alignment as u32).to_le_bytes());
        data[8..16].copy_from_slice(&wanted.minimum.to_le_bytes());
        data[16..].copy_from_slice(&wanted.maximum.to_le_bytes());
        Self {
            option,
            kind,
            share,
            flags,
            data,
        }
    }

    /// An interrupt: any one vector (for a line, its number) from
    /// `minimum` to `maximum` inclusive.
    pub fn interrupt(option: u8, share: u8, flags: u16, minimum: u32, maximum: u32) -> Self {
        let mut data = [0; 24];
        data[..4].copy_from_slice(&minimum.to_le_bytes());
        data[4..8].copy_from_slice(&maximum.to_le_bytes());
        Self {
            option,
            kind: TYPE_INTERRUPT,
            share,
            flags,
            data,
        }
    }

    fn u32_of(&self, at: usize) -> u32 {
        u32::from_le_bytes(self.data[at..at + 4].try_into().unwrap())
    }

    fn u64_of(&self, at: usize) -> u64 {
        u64::from_le_bytes(self.data[at..at + 8].try_into().unwrap())
    }

    /// Whether this is another choice for the requirement the
    /// descriptor before it states.
    pub fn is_alternative(&self) -> bool {
        self.option & OPTION_ALTERNATIVE != 0
    }

    /// What the descriptor asks for, in one shape for every kind that
    /// is a range of numbers; `None` for the kinds that are not.
    pub fn wanted(&self) -> Option<Wanted> {
        match self.kind {
            TYPE_PORT | TYPE_MEMORY => Some(Wanted {
                length: u64::from(self.u32_of(0)),
                alignment: u64::from(self.u32_of(4)).max(1),
                minimum: self.u64_of(8),
                maximum: self.u64_of(16),
            }),
            TYPE_MEMORY_LARGE => {
                let shift = large_shift(self.flags);
                Some(Wanted {
                    length: u64::from(self.u32_of(0)) << shift,
                    alignment: (u64::from(self.u32_of(4)) << shift).max(1),
                    minimum: self.u64_of(8),
                    maximum: self.u64_of(16),
                })
            }
            TYPE_INTERRUPT => Some(Wanted {
                length: 1,
                alignment: 1,
                minimum: u64::from(self.u32_of(0)),
                maximum: u64::from(self.u32_of(4)),
            }),
            TYPE_BUS_NUMBER => Some(Wanted {
                length: u64::from(self.u32_of(0)),
                alignment: 1,
                minimum: u64::from(self.u32_of(4)),
                maximum: u64::from(self.u32_of(8)),
            }),
            _ => None,
        }
    }
}

/// A requirement that is a range of numbers: `length` of them in a
/// row, the first a multiple of `alignment`, all from `minimum` to
/// `maximum` inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Wanted {
    pub length: u64,
    pub alignment: u64,
    pub minimum: u64,
    pub maximum: u64,
}

/// One `IO_RESOURCE_LIST`: one way of satisfying the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IoList {
    pub version: u16,
    pub revision: u16,
    pub descriptors: Vec<IoDescriptor>,
}

/// An `IO_RESOURCE_REQUIREMENTS_LIST`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirements {
    pub interface: u32,
    pub bus: u32,
    pub slot: u32,
    pub lists: Vec<IoList>,
}

impl Requirements {
    /// The bytes of the list that the memory block `block` begins
    /// with: as many as the list's own `ListSize` field states, if the
    /// block has that many and they hold a whole list. A driver hands
    /// the Plug and Play manager such a block; what the list says of
    /// its own length is believed only as far as the block reaches.
    pub fn in_block(block: &[u8]) -> Option<&[u8]> {
        let stated = u32_at(block, 0)? as usize;
        let list = block.get(..stated)?;
        Self::parse(list).map(|_| list)
    }

    /// The requirements list in `bytes`. `None` if the bytes end before
    /// the list does or a count is beyond belief.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        let lists = u32_at(bytes, 28)? as usize;
        if lists > MAX_DESCRIPTORS {
            return None;
        }
        let mut result = Self {
            interface: u32_at(bytes, 4)?,
            bus: u32_at(bytes, 8)?,
            slot: u32_at(bytes, 12)?,
            lists: Vec::new(),
        };
        let mut at = REQUIREMENTS_HEADER;
        for _ in 0..lists {
            let count = u32_at(bytes, at + 4)? as usize;
            if count > MAX_DESCRIPTORS {
                return None;
            }
            let mut list = IoList {
                version: u16_at(bytes, at)?,
                revision: u16_at(bytes, at + 2)?,
                descriptors: Vec::new(),
            };
            at += IO_LIST_HEADER;
            for _ in 0..count {
                let fixed = bytes.get(at..at + IO_DESCRIPTOR)?;
                list.descriptors.push(IoDescriptor {
                    option: fixed[0],
                    kind: fixed[1],
                    share: fixed[2],
                    flags: u16_at(fixed, 4)?,
                    data: fixed[8..].try_into().ok()?,
                });
                at += IO_DESCRIPTOR;
            }
            result.lists.push(list);
        }
        Some(result)
    }

    /// The list as bytes, its size field included.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = alloc::vec![0u8; REQUIREMENTS_HEADER];
        bytes[4..8].copy_from_slice(&self.interface.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.bus.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.slot.to_le_bytes());
        bytes[28..32].copy_from_slice(&(self.lists.len() as u32).to_le_bytes());
        for list in &self.lists {
            bytes.extend_from_slice(&list.version.to_le_bytes());
            bytes.extend_from_slice(&list.revision.to_le_bytes());
            bytes.extend_from_slice(&(list.descriptors.len() as u32).to_le_bytes());
            for descriptor in &list.descriptors {
                bytes.extend_from_slice(&[descriptor.option, descriptor.kind, descriptor.share, 0]);
                bytes.extend_from_slice(&descriptor.flags.to_le_bytes());
                bytes.extend_from_slice(&[0, 0]);
                bytes.extend_from_slice(&descriptor.data);
            }
        }
        let size = bytes.len() as u32;
        bytes[..4].copy_from_slice(&size.to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    /// The AHCI controller's raw resources on the reference Windows
    /// (`RESOURCEMAP\PnP Manager\PnpManager`, `\Device\NTPNP_PCI0003.Raw`).
    fn ahci_raw() -> ResourceList {
        let mut bar4 = Partial::new(TYPE_DEVICE_PRIVATE, 0, 0);
        bar4.data[..8].copy_from_slice(&hex("0100000004000000"));
        let mut bar5 = Partial::new(TYPE_DEVICE_PRIVATE, 0, 0);
        bar5.data[..8].copy_from_slice(&hex("0100000005000000"));
        ResourceList::of(
            5,
            0,
            vec![
                Partial::range(TYPE_PORT, 1, 0x131, 0x6040, 0x20),
                bar4,
                Partial::range(TYPE_MEMORY, 1, 0x80, 0x8101_0000, 0x1000),
                bar5,
                Partial::raw_messages(1, 3, 1, 0),
            ],
        )
    }

    #[test]
    fn a_resource_list_survives_bytes() {
        let list = ahci_raw();
        let bytes = list.to_bytes();
        // What Windows recorded: 120 bytes.
        assert_eq!(bytes.len(), 120);
        assert_eq!(ResourceList::parse(&bytes), Some((list.clone(), 120)));
        // Bytes behind the list are not part of it.
        let mut longer = bytes.clone();
        longer.extend_from_slice(&[0xAA; 7]);
        assert_eq!(ResourceList::parse(&longer), Some((list, 120)));
        for cut in 0..bytes.len() {
            assert_eq!(ResourceList::parse(&bytes[..cut]), None, "cut at {cut}");
        }
    }

    #[test]
    fn the_message_interrupt_is_as_windows_recorded_it() {
        let list = ahci_raw();
        let interrupt = list.partials().last().unwrap();
        assert!(interrupt.is_message());
        // "level=0x10000 vector=0xfffffffe": the count is the upper
        // half of what a line calls its level.
        assert_eq!(interrupt.as_interrupt(), Some((0, 1, MESSAGE_TOKEN, 0)));
        assert_eq!(&interrupt.data[..8], &hex("00000100feffffff")[..]);
        assert_eq!(interrupt.as_range(), None);
    }

    #[test]
    fn ranges_of_every_kind() {
        let port = Partial::range(TYPE_PORT, 1, 1, 0x6040, 0x20);
        assert_eq!(port.as_range(), Some((0x6040, 0x20)));
        assert_eq!(port.as_interrupt(), None);
        assert!(!port.is_message());
        let bus = Partial::range(TYPE_BUS_NUMBER, 1, 0, 0, 256);
        assert_eq!(bus.as_range(), Some((0, 256)));
        // The reference machine's 64-bit window: 0x180000000 for
        // 0x800000000 bytes, its length stored in units of 256 bytes.
        let large = Partial::range(
            TYPE_MEMORY_LARGE,
            1,
            MEMORY_LARGE_40,
            0x1_8000_0000,
            0x8_0000_0000,
        );
        assert_eq!(&large.data[8..12], &0x0800_0000u32.to_le_bytes());
        assert_eq!(large.as_range(), Some((0x1_8000_0000, 0x8_0000_0000)));
        for (flags, shift) in [(MEMORY_LARGE_48, 16), (MEMORY_LARGE_64, 32), (0, 0)] {
            let length = 3u64 << shift;
            let partial = Partial::range(TYPE_MEMORY_LARGE, 1, flags, 0, length);
            assert_eq!(partial.as_range(), Some((0, length)));
        }
        let line = Partial::interrupt(3, 0, 10, 0, 10, 0xFFFF_FFFF);
        assert_eq!(line.as_interrupt(), Some((10, 0, 10, 0xFFFF_FFFF)));
    }

    #[test]
    fn device_specific_data_follows_its_descriptor() {
        let mut specific = Partial::new(TYPE_DEVICE_SPECIFIC, 0, 0);
        specific.data[..4].copy_from_slice(&3u32.to_le_bytes());
        specific.extra = vec![1, 2, 3];
        let list = ResourceList::of(0, 0, vec![specific, Partial::range(TYPE_PORT, 1, 1, 8, 2)]);
        let bytes = list.to_bytes();
        assert_eq!(bytes.len(), 4 + 16 + 20 + 3 + 20);
        assert_eq!(ResourceList::parse(&bytes), Some((list, bytes.len())));
        // Data said to be longer than the bytes there are.
        let mut lying = bytes.clone();
        lying[4 + 16 + 4..4 + 16 + 8].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        assert_eq!(ResourceList::parse(&lying), None);
    }

    #[test]
    fn counts_beyond_belief_are_refused() {
        let mut bytes = ahci_raw().to_bytes();
        bytes[..4].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        assert_eq!(ResourceList::parse(&bytes), None);
        let mut bytes = ahci_raw().to_bytes();
        bytes[16..20].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        assert_eq!(ResourceList::parse(&bytes), None);
        assert_eq!(
            ResourceList::parse(&[0, 0, 0, 0]),
            Some((ResourceList::default(), 4))
        );
    }

    /// The AHCI controller's requirements on the reference Windows
    /// (`LogConf\BasicConfigVector`): a port and a memory range, each
    /// preferred where firmware put it, and a message interrupt with
    /// the line as its alternative.
    fn ahci_requirements() -> Requirements {
        Requirements {
            interface: 5,
            bus: 0,
            slot: 0x5F,
            lists: vec![IoList {
                version: 1,
                revision: 1,
                descriptors: vec![
                    IoDescriptor::range(
                        1,
                        TYPE_PORT,
                        1,
                        0x131,
                        Wanted {
                            length: 0x20,
                            alignment: 0x20,
                            minimum: 0x6040,
                            maximum: 0x605F,
                        },
                    ),
                    IoDescriptor::range(
                        8,
                        TYPE_PORT,
                        1,
                        0x131,
                        Wanted {
                            length: 0x20,
                            alignment: 0x20,
                            minimum: 0,
                            maximum: 0xFFFF_FFFF,
                        },
                    ),
                    IoDescriptor::range(
                        1,
                        TYPE_MEMORY,
                        1,
                        0x80,
                        Wanted {
                            length: 0x1000,
                            alignment: 0x1000,
                            minimum: 0x8101_0000,
                            maximum: 0x8101_0FFF,
                        },
                    ),
                    IoDescriptor::range(
                        8,
                        TYPE_MEMORY,
                        1,
                        0x80,
                        Wanted {
                            length: 0x1000,
                            alignment: 0x1000,
                            minimum: 0,
                            maximum: 0xFFFF_FFFF,
                        },
                    ),
                    IoDescriptor::interrupt(1, 1, 3, MESSAGE_TOKEN, MESSAGE_TOKEN),
                    IoDescriptor::interrupt(8, 3, 0, 0, 0xFFFF_FFFF),
                ],
            }],
        }
    }

    #[test]
    fn a_requirements_list_survives_bytes() {
        let list = ahci_requirements();
        let bytes = list.to_bytes();
        assert_eq!(bytes.len(), 32 + 8 + 6 * 32);
        assert_eq!(Requirements::parse(&bytes), Some(list));
        for cut in 0..bytes.len() {
            assert_eq!(Requirements::parse(&bytes[..cut]), None, "cut at {cut}");
        }
    }

    /// A list is taken out of the block a driver handed over only as
    /// far as the block reaches, whatever the list says of itself.
    #[test]
    fn a_list_does_not_reach_beyond_its_block() {
        let bytes = ahci_requirements().to_bytes();
        let mut block = bytes.clone();
        block.extend_from_slice(&[0xEE; 40]);
        assert_eq!(Requirements::in_block(&block), Some(&bytes[..]));
        assert_eq!(Requirements::in_block(&bytes), Some(&bytes[..]));
        // A size beyond the block.
        let mut lying = block.clone();
        lying[..4].copy_from_slice(&(block.len() as u32 + 1).to_le_bytes());
        assert_eq!(Requirements::in_block(&lying), None);
        lying[..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(Requirements::in_block(&lying), None);
        // A size too small for the descriptors the list counts.
        let mut short = block.clone();
        short[..4].copy_from_slice(&(bytes.len() as u32 - 1).to_le_bytes());
        assert_eq!(Requirements::in_block(&short), None);
        assert_eq!(Requirements::in_block(&[]), None);
        assert_eq!(Requirements::in_block(&[0; 16]), None);
    }

    #[test]
    fn requirement_counts_beyond_belief_are_refused() {
        let mut bytes = ahci_requirements().to_bytes();
        bytes[28..32].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        assert_eq!(Requirements::parse(&bytes), None);
        let mut bytes = ahci_requirements().to_bytes();
        bytes[36..40].copy_from_slice(&0x7FFF_FFFFu32.to_le_bytes());
        assert_eq!(Requirements::parse(&bytes), None);
    }

    #[test]
    fn what_a_descriptor_wants() {
        let list = ahci_requirements();
        let descriptors = &list.lists[0].descriptors;
        assert_eq!(
            descriptors[0].wanted(),
            Some(Wanted {
                length: 0x20,
                alignment: 0x20,
                minimum: 0x6040,
                maximum: 0x605F
            })
        );
        assert!(!descriptors[0].is_alternative());
        assert!(descriptors[1].is_alternative());
        assert_eq!(
            descriptors[4].wanted(),
            Some(Wanted {
                length: 1,
                alignment: 1,
                minimum: u64::from(MESSAGE_TOKEN),
                maximum: u64::from(MESSAGE_TOKEN)
            })
        );
        let mut bus = IoDescriptor::interrupt(0, 1, 0, 0, 0);
        bus.kind = TYPE_BUS_NUMBER;
        bus.data[..4].copy_from_slice(&0x100u32.to_le_bytes());
        bus.data[4..8].copy_from_slice(&0u32.to_le_bytes());
        bus.data[8..12].copy_from_slice(&0xFFu32.to_le_bytes());
        assert_eq!(
            bus.wanted(),
            Some(Wanted {
                length: 0x100,
                alignment: 1,
                minimum: 0,
                maximum: 0xFF
            })
        );
        let large = IoDescriptor::range(
            0,
            TYPE_MEMORY_LARGE,
            1,
            MEMORY_LARGE_40,
            Wanted {
                length: 0x10,
                alignment: 0,
                minimum: 0,
                maximum: u64::MAX,
            },
        );
        assert_eq!(large.wanted().unwrap().length, 0x1000);
        assert_eq!(large.wanted().unwrap().alignment, 1);
        let mut private = IoDescriptor::interrupt(0, 0, 0, 0, 0);
        private.kind = TYPE_DEVICE_PRIVATE;
        assert_eq!(private.wanted(), None);
    }
}
