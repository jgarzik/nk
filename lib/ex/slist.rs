//! The sequenced singly linked list (`SLIST_HEADER`): a lock-free stack
//! whose head is 16 bytes in the driver's memory.
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/singly-and-doubly-linked-lists>
//!
//! # The header
//!
//! Two quadwords, as `wdm.h` declares `HeaderX64`: in the first, the
//! depth (16 bits) and a sequence number (48 bits); in the second, four
//! reserved bits and the address of the first entry without its low four
//! bits, which are zero because entries are 16-byte aligned. The arm64
//! declaration has the same fields at the same bits, so one format
//! serves both. An empty, initialised header is all zero
//! (`InitializeSListHead`). NK keeps the reserved bits zero.
//!
//! # The transitions
//!
//! Each function maps the header as read to the header to store. The
//! kernel stores it with a 16-byte compare-and-swap and starts over if
//! the header changed meanwhile:
//!
//! - push: [`push`] gives the new header and what to write into the new
//!   entry's `Next` before the swap;
//! - pop: [`first`] gives the entry to take; the kernel reads its `Next`
//!   and [`pop`] gives the new header;
//! - flush: [`first`] gives the chain to hand back and [`flush`] the
//!   empty header; the depth of the old header is how many entries the
//!   chain has, which is what deleting a lookaside list has to free;
//! - `ExQueryDepthSList` is [`depth`].
//!
//! # The sequence number
//!
//! It goes up on every push and stays on a pop or a flush, which is what
//! Windows' x64 routines are seen to do. That is enough to make a stale
//! swap fail: a pop that read the first entry and its `Next`, then lost
//! the processor while others popped that entry and pushed it back,
//! finds a different sequence number. Two headers are equal only if no
//! push came between them, and then the list is the same too.

/// Entries are aligned to this, on both architectures.
pub const ENTRY_ALIGN: u64 = 16;

/// `SLIST_HEADER` as its two quadwords, `Alignment` and `Region`.
#[repr(C, align(16))]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct Header {
    pub alignment: u64,
    pub region: u64,
}

/// What a header holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fields {
    /// How many entries the list has.
    pub depth: u16,
    /// 48 bits.
    pub sequence: u64,
    /// The address of the first entry; zero when the list is empty.
    pub next: u64,
}

pub const fn pack(fields: Fields) -> Header {
    Header {
        // The shift drops what does not fit in the sequence's 48 bits.
        alignment: fields.depth as u64 | fields.sequence << 16,
        region: fields.next & !(ENTRY_ALIGN - 1),
    }
}

pub const fn unpack(header: Header) -> Fields {
    Fields {
        depth: header.alignment as u16,
        sequence: header.alignment >> 16,
        next: header.region & !(ENTRY_ALIGN - 1),
    }
}

/// How many entries the list has (`ExQueryDepthSList`).
pub const fn depth(header: Header) -> u16 {
    unpack(header).depth
}

/// The address of the first entry, if the list has any.
pub const fn first(header: Header) -> Option<u64> {
    match unpack(header).next {
        0 => None,
        entry => Some(entry),
    }
}

/// An entry that is not 16-byte aligned cannot be named by a header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Misaligned;

/// Put the entry at `entry` first. Returns the new header and the
/// address to store in the entry's `Next` before swapping the header in.
pub const fn push(header: Header, entry: u64) -> Result<(Header, u64), Misaligned> {
    if entry % ENTRY_ALIGN != 0 {
        return Err(Misaligned);
    }
    let old = unpack(header);
    let new = Fields {
        depth: old.depth.wrapping_add(1),
        sequence: old.sequence + 1,
        next: entry,
    };
    Ok((pack(new), old.next))
}

/// Take the first entry off a list that has one. `next` is what the
/// kernel read from that entry's `Next`.
pub const fn pop(header: Header, next: u64) -> Header {
    let old = unpack(header);
    pack(Fields {
        depth: old.depth.wrapping_sub(1),
        sequence: old.sequence,
        next,
    })
}

/// Take every entry off the list.
pub const fn flush(header: Header) -> Header {
    pack(Fields {
        depth: 0,
        sequence: unpack(header).sequence,
        next: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const SEQUENCE_MASK: u64 = (1 << 48) - 1;

    #[test]
    fn the_header_is_sixteen_aligned_bytes() {
        assert_eq!((size_of::<Header>(), align_of::<Header>()), (16, 16));
        assert_eq!(core::mem::offset_of!(Header, region), 8);
        assert_eq!(Header::default(), pack(unpack(Header::default())));
        assert_eq!(
            (depth(Header::default()), first(Header::default())),
            (0, None)
        );
    }

    #[test]
    fn fields_sit_where_the_declaration_puts_them() {
        let header = pack(Fields {
            depth: 0x1234,
            sequence: 0xABCD_EF01_2345,
            next: 0xFFFF_8000_1234_5670,
        });
        assert_eq!(header.alignment, 0xABCD_EF01_2345_1234);
        assert_eq!(header.region, 0xFFFF_8000_1234_5670);
    }

    #[test]
    fn fields_survive_packing_at_their_limits() {
        for depth in [0, 1, 0x7FFF, 0xFFFF] {
            for sequence in [0, 1, SEQUENCE_MASK - 1, SEQUENCE_MASK] {
                for next in [0, 0x10, 0x7FFF_FFFF_FFF0, 0xFFFF_FFFF_FFFF_FFF0] {
                    let fields = Fields {
                        depth,
                        sequence,
                        next,
                    };
                    let header = pack(fields);
                    assert_eq!(unpack(header), fields);
                    assert_eq!(self::depth(header), depth);
                    assert_eq!(first(header), (next != 0).then_some(next));
                    // Reserved bits stay clear.
                    assert_eq!(header.region & 0xF, 0);
                }
            }
        }
        // What does not fit is cut off, not spilled into a neighbour.
        let header = pack(Fields {
            depth: 0,
            sequence: u64::MAX,
            next: 0x1F,
        });
        assert_eq!(
            unpack(header),
            Fields {
                depth: 0,
                sequence: SEQUENCE_MASK,
                next: 0x10
            }
        );
    }

    #[test]
    fn the_counters_wrap_in_place() {
        let full = pack(Fields {
            depth: 0xFFFF,
            sequence: SEQUENCE_MASK,
            next: 0x100,
        });
        let (header, next) = push(full, 0x200).unwrap();
        assert_eq!(next, 0x100);
        assert_eq!(
            unpack(header),
            Fields {
                depth: 0,
                sequence: 0,
                next: 0x200
            }
        );
    }

    #[test]
    fn a_misaligned_entry_is_refused() {
        for entry in [1, 8, 0x1008, 0xFFFF_FFFF_FFFF_FFFF] {
            assert_eq!(push(Header::default(), entry), Err(Misaligned));
        }
    }

    #[derive(Clone, Copy, Debug)]
    enum Op {
        Push(u64),
        Pop,
        Flush,
    }

    /// A list as the kernel would run it, single-handed: the header, and
    /// the `Next` field of each entry by address.
    #[derive(Default)]
    struct List {
        header: Header,
        memory: HashMap<u64, u64>,
    }

    impl List {
        fn push(&mut self, entry: u64) {
            let (header, next) = push(self.header, entry).unwrap();
            self.memory.insert(entry, next);
            self.header = header;
        }

        fn pop(&mut self) -> Option<u64> {
            let entry = first(self.header)?;
            self.header = pop(self.header, self.memory[&entry]);
            Some(entry)
        }

        fn flush(&mut self) -> Vec<u64> {
            let chain = self.entries();
            self.header = flush(self.header);
            chain
        }

        /// The entries, first to last, by following the links.
        fn entries(&self) -> Vec<u64> {
            let mut entries = Vec::new();
            let mut at = first(self.header);
            while let Some(entry) = at {
                entries.push(entry);
                at = Some(self.memory[&entry]).filter(|&next| next != 0);
            }
            entries
        }
    }

    /// Every sequence of `length` operations over three entries.
    fn sequences(length: usize) -> Vec<Vec<Op>> {
        let ops = [
            Op::Push(0x100),
            Op::Push(0x200),
            Op::Push(0x300),
            Op::Pop,
            Op::Flush,
        ];
        let mut all = vec![Vec::new()];
        for _ in 0..length {
            all = all
                .into_iter()
                .flat_map(|s| ops.iter().map(move |&op| [s.clone(), vec![op]].concat()))
                .collect();
        }
        all
    }

    #[test]
    fn every_short_run_matches_a_vec_and_never_repeats_a_header_for_another_list() {
        let mut runs = 0;
        for ops in sequences(7) {
            let mut list = List::default();
            let mut model: Vec<u64> = Vec::new();
            let mut pushes = 0;
            // Each header seen, with the list it stood for.
            let mut seen: HashMap<Header, Vec<u64>> = HashMap::new();
            seen.insert(list.header, Vec::new());
            for op in ops {
                match op {
                    // An entry is on at most one list at a time.
                    Op::Push(entry) if model.contains(&entry) => continue,
                    Op::Push(entry) => {
                        list.push(entry);
                        model.insert(0, entry);
                        pushes += 1;
                    }
                    Op::Pop => {
                        let expect = (!model.is_empty()).then(|| model.remove(0));
                        assert_eq!(list.pop(), expect);
                    }
                    Op::Flush => assert_eq!(list.flush(), core::mem::take(&mut model)),
                }
                assert_eq!(list.entries(), model);
                assert_eq!(usize::from(depth(list.header)), model.len());
                assert_eq!(first(list.header), model.first().copied());
                // Pushes move the sequence number; nothing else does.
                assert_eq!(unpack(list.header).sequence, pushes);
                // The same header again means the same list again: a
                // swap against a stale header cannot succeed.
                let stood_for = seen.entry(list.header).or_insert_with(|| model.clone());
                assert_eq!(*stood_for, model);
                runs += 1;
            }
        }
        assert!(runs > 100_000, "{runs}");
    }

    #[test]
    fn popping_and_pushing_the_same_entry_back_changes_the_header() {
        // The classic: [A, B], and a pop that has read A and A's Next
        // (B) is overtaken by pop A, pop B, push A.
        let (a, b) = (0x100, 0x200);
        let mut list = List::default();
        list.push(b);
        list.push(a);
        let stale = list.header;
        let stale_swap = pop(stale, list.memory[&a]);
        assert_eq!(first(stale_swap), Some(b));
        assert_eq!(list.pop(), Some(a));
        assert_eq!(list.pop(), Some(b));
        list.push(a);
        // A is first again, but the overtaken pop's compare fails: it
        // would have put B, long gone, back on the list.
        assert_eq!(first(list.header), first(stale));
        assert_ne!(list.header, stale);
        assert_ne!(unpack(list.header).sequence, unpack(stale).sequence);
    }
}
