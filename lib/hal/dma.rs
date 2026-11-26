//! DMA arithmetic: what a device description asks for, how a buffer
//! falls into pages, and how pieces of it join into runs of bus
//! addresses.
//!
//! There is no I/O memory management unit on the machines NK runs on: a
//! bus address is a physical address. A device that cannot drive every
//! address bit cannot reach memory above what it drives; a transfer to
//! or from such memory goes through a page the device can reach (a
//! bounce page, which Windows counts in "map registers").

pub const PAGE: u64 = 4096;

/// What a `DEVICE_DESCRIPTION` says, as far as NK reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Description {
    pub version: u32,
    pub master: bool,
    pub scatter_gather: bool,
    pub dma32: bool,
    pub dma64: bool,
    pub maximum_length: u32,
    /// Version 3's `DmaAddressWidth`.
    pub address_width: u32,
}

/// What an adapter made for a description is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Address bits the device drives: 24 to 64.
    pub width: u8,
    /// Pages one transfer may span, plus one: what Windows reports as
    /// the number of map registers.
    pub map_registers: u32,
}

impl Limits {
    /// The highest physical address the device reaches.
    pub const fn highest(&self) -> u64 {
        if self.width >= 64 {
            u64::MAX
        } else {
            (1 << self.width) - 1
        }
    }
}

/// The limits of the adapter a description asks for. `None` for a
/// description NK makes no adapter for: a version above 3, a device
/// that is not a bus master (it needs a system DMA controller, and NK
/// drives none), or an address width that is no width.
///
/// A version 3 description may state the width outright; otherwise the
/// two flags do: 64 bits, else 32, else the 24 of an ISA device.
pub const fn limits(d: &Description) -> Option<Limits> {
    if d.version > 3 || !d.master {
        return None;
    }
    let width = if d.version == 3 && d.address_width != 0 {
        if d.address_width < 24 || d.address_width > 64 {
            return None;
        }
        d.address_width as u8
    } else if d.dma64 {
        64
    } else if d.dma32 {
        32
    } else {
        24
    };
    Some(Limits {
        width,
        map_registers: (d.maximum_length as u64).div_ceil(PAGE) as u32 + 1,
    })
}

/// One piece of a buffer that lies within one page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Piece {
    /// Which page of the buffer's span, from 0.
    pub page: usize,
    /// Where in that page the piece begins.
    pub offset: u32,
    pub length: u32,
}

/// Cut `length` bytes that begin `offset` bytes into a page into the
/// pieces that lie in each page.
pub fn pieces(offset: u32, length: u32) -> impl Iterator<Item = Piece> {
    let (mut at, end) = (u64::from(offset), u64::from(offset) + u64::from(length));
    core::iter::from_fn(move || {
        if at >= end {
            return None;
        }
        let stop = ((at / PAGE + 1) * PAGE).min(end);
        let piece = Piece {
            page: (at / PAGE) as usize,
            offset: (at % PAGE) as u32,
            length: (stop - at) as u32,
        };
        at = stop;
        Some(piece)
    })
}

/// How many pages `length` bytes span that begin `offset` bytes into a
/// page.
pub const fn span(offset: u32, length: u32) -> u32 {
    if length == 0 {
        return 0;
    }
    ((offset as u64 % PAGE + length as u64).div_ceil(PAGE)) as u32
}

/// Whether a device that reaches up to `highest` can reach all of the
/// `length` bytes at physical address `address`.
pub const fn reachable(address: u64, length: u32, highest: u64) -> bool {
    length == 0
        || match address.checked_add(length as u64 - 1) {
            Some(last) => last <= highest,
            None => false,
        }
}

/// One run of bus addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub address: u64,
    pub length: u32,
}

/// Joins pieces given in order into runs: a piece that begins where the
/// last one ended extends it, unless told to stand alone.
#[derive(Debug, Default)]
pub struct Runs {
    last: Option<Run>,
    /// Whether `last` may be extended.
    open: bool,
}

impl Runs {
    pub const fn new() -> Self {
        Self {
            last: None,
            open: false,
        }
    }

    /// Add a piece. `alone`: the piece is its own run whatever is next
    /// to it (a bounce page is not part of its neighbours' memory).
    /// Returns the run this completes, if the piece began a new one.
    pub fn add(&mut self, address: u64, length: u32, alone: bool) -> Option<Run> {
        if let Some(last) = &mut self.last
            && self.open
            && !alone
            && last.address.checked_add(u64::from(last.length)) == Some(address)
            && last.length.checked_add(length).is_some()
        {
            last.length += length;
            return None;
        }
        self.open = !alone;
        self.last.replace(Run { address, length })
    }

    /// The last run, when every piece has been added.
    pub fn finish(self) -> Option<Run> {
        self.last
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn description() -> Description {
        Description {
            version: 2,
            master: true,
            scatter_gather: true,
            dma32: true,
            dma64: false,
            maximum_length: 0x1_0000,
            address_width: 0,
        }
    }

    #[test]
    fn an_adapter_s_width_comes_from_the_flags_or_the_stated_width() {
        let width = |d: Description| limits(&d).map(|l| l.width);
        assert_eq!(width(description()), Some(32));
        assert_eq!(
            width(Description {
                dma64: true,
                ..description()
            }),
            Some(64)
        );
        assert_eq!(
            width(Description {
                dma32: false,
                ..description()
            }),
            Some(24)
        );
        // A stated width is version 3's alone.
        let stated = Description {
            address_width: 40,
            ..description()
        };
        assert_eq!(width(stated), Some(32));
        let v3 = Description {
            version: 3,
            ..stated
        };
        assert_eq!(width(v3), Some(40));
        assert_eq!(
            width(Description {
                address_width: 0,
                ..v3
            }),
            Some(32)
        );
        for bad in [1, 23, 65, 200] {
            assert_eq!(
                width(Description {
                    address_width: bad,
                    ..v3
                }),
                None
            );
        }
        // Versions 0 to 3; bus masters only.
        for version in 0..=3 {
            assert!(
                limits(&Description {
                    version,
                    ..description()
                })
                .is_some()
            );
        }
        assert_eq!(
            width(Description {
                version: 4,
                ..description()
            }),
            None
        );
        assert_eq!(
            width(Description {
                master: false,
                ..description()
            }),
            None
        );
    }

    #[test]
    fn an_adapter_reaches_what_its_width_allows() {
        let highest = |width| {
            Limits {
                width,
                map_registers: 1,
            }
            .highest()
        };
        assert_eq!(highest(24), 0xFF_FFFF);
        assert_eq!(highest(32), 0xFFFF_FFFF);
        assert_eq!(highest(40), 0xFF_FFFF_FFFF);
        assert_eq!(highest(64), u64::MAX);
        assert!(reachable(0xFFFF_F000, 0x1000, 0xFFFF_FFFF));
        assert!(!reachable(0xFFFF_F000, 0x1001, 0xFFFF_FFFF));
        assert!(!reachable(0x1_0000_0000, 1, 0xFFFF_FFFF));
        assert!(reachable(0x1_0000_0000, 0, 0xFFFF_FFFF));
        assert!(reachable(u64::MAX, 1, u64::MAX));
        assert!(!reachable(u64::MAX, 2, u64::MAX));
    }

    #[test]
    fn map_registers_are_the_pages_of_the_longest_transfer_and_one() {
        let registers = |maximum_length| {
            limits(&Description {
                maximum_length,
                ..description()
            })
            .unwrap()
            .map_registers
        };
        assert_eq!(registers(0x1_0000), 17);
        assert_eq!(registers(0x1_0001), 18);
        assert_eq!(registers(1), 2);
        assert_eq!(registers(0), 1);
        assert_eq!(registers(u32::MAX), 0x10_0001);
    }

    #[test]
    fn a_buffer_falls_into_the_pieces_of_its_pages() {
        let cut = |offset, length| -> Vec<(usize, u32, u32)> {
            pieces(offset, length)
                .map(|p| (p.page, p.offset, p.length))
                .collect()
        };
        assert_eq!(cut(0, 0x1000), [(0, 0, 0x1000)]);
        assert_eq!(cut(0x10, 0x20), [(0, 0x10, 0x20)]);
        assert_eq!(
            cut(0xF00, 0x1200),
            [(0, 0xF00, 0x100), (1, 0, 0x1000), (2, 0, 0x100)]
        );
        assert_eq!(cut(0xFFF, 2), [(0, 0xFFF, 1), (1, 0, 1)]);
        assert_eq!(cut(5, 0), []);
        // An offset past the first page names a later page.
        assert_eq!(cut(0x2010, 0x10), [(2, 0x10, 0x10)]);
        assert_eq!(span(0, 0x1000), 1);
        assert_eq!(span(0xF00, 0x1200), 3);
        assert_eq!(span(0xFFF, 2), 2);
        assert_eq!(span(5, 0), 0);
        assert_eq!(span(0, u32::MAX), 0x10_0000);
        for (offset, length) in [(0, 1), (0xFFF, 0x3001), (0x800, 0x800), (1, 0x1FFF)] {
            let all: Vec<_> = pieces(offset, length).collect();
            assert_eq!(all.len() as u32, span(offset, length));
            assert_eq!(all.iter().map(|p| p.length).sum::<u32>(), length);
        }
    }

    #[test]
    fn adjacent_pieces_join_into_one_run() {
        let join = |pieces: &[(u64, u32, bool)]| -> Vec<(u64, u32)> {
            let mut runs = Runs::new();
            let mut out = Vec::new();
            for &(address, length, alone) in pieces {
                out.extend(runs.add(address, length, alone));
            }
            out.extend(runs.finish());
            out.iter().map(|r| (r.address, r.length)).collect()
        };
        // Three pages in a row are one run; a gap starts another.
        assert_eq!(
            join(&[
                (0x1F00, 0x100, false),
                (0x2000, 0x1000, false),
                (0x3000, 0x80, false),
                (0x9000, 0x1000, false),
            ]),
            [(0x1F00, 0x1180), (0x9000, 0x1000)]
        );
        // A piece that stands alone joins neither neighbour, even when
        // its address happens to follow or precede theirs.
        assert_eq!(
            join(&[
                (0x1000, 0x1000, false),
                (0x2000, 0x1000, true),
                (0x3000, 0x1000, false),
                (0x4000, 0x1000, false),
            ]),
            [(0x1000, 0x1000), (0x2000, 0x1000), (0x3000, 0x2000)]
        );
        assert_eq!(join(&[]), []);
        assert_eq!(join(&[(0x5000, 7, false)]), [(0x5000, 7)]);
        // A run's length stays within 32 bits, and its end within 64.
        assert_eq!(
            join(&[(0, u32::MAX, false), (u64::from(u32::MAX), 1, false)]),
            [(0, u32::MAX), (u64::from(u32::MAX), 1)]
        );
        assert_eq!(
            join(&[(u64::MAX - 1, 2, false), (0, 1, false)]),
            [(u64::MAX - 1, 2), (0, 1)]
        );
    }
}
