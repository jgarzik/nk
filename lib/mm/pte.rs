//! Software page-table entries: what an entry holds while it maps
//! nothing, and what a prototype PTE holds.
//!
//! NK keeps Windows' x64 encodings (`_MMPTE`), which no driver sees but
//! which are a compact and proven design. Bit 0 clear means "not valid"
//! to both processors NK runs on, so the same formats serve arm64; a
//! valid entry in a page table is the processor's own
//! (`pt::Arch::leaf`). A prototype PTE is never walked by a processor,
//! so its valid form is NK's: bit 0 set and the frame number.
//!
//! - prototype pointer (a page table's entry for a page of a section
//!   view): bit 10 set, bits 16-63 the address of the prototype PTE;
//! - transition (a prototype PTE whose frame is on a list or under
//!   I/O): bit 11 set, bit 10 clear, bits 12-47 the frame number;
//! - subsection (a prototype PTE whose page is in the file only): bit 10
//!   set, bits 16-63 the address of its subsection;
//! - protection, in the invalid forms: bits 5-9.

/// Windows' protection code for read-write pages (`MM_READWRITE`).
pub const MM_READWRITE: u64 = 4;

const VALID: u64 = 1;
const PROTOTYPE: u64 = 1 << 10;
const TRANSITION: u64 = 1 << 11;
const PFN_MASK: u64 = 0x0000_FFFF_FFFF_F000;

/// The 48 bits of a canonical address kept in bits 16-63.
fn pack(address: u64) -> u64 {
    address << 16
}

/// A canonical address again, its bit 47 extended.
fn unpack(entry: u64) -> u64 {
    ((entry as i64) >> 16) as u64
}

/// A page table's entry for a page of a view, pointing at the
/// prototype PTE at `proto`.
pub fn prototype_pointer(proto: u64) -> u64 {
    pack(proto) | PROTOTYPE
}

/// The prototype PTE a page table's invalid entry points at, if it is a
/// prototype pointer.
pub fn prototype_target(entry: u64) -> Option<u64> {
    (entry & VALID == 0 && entry & PROTOTYPE != 0).then(|| unpack(entry))
}

/// What a prototype PTE says of its page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    /// In memory and mapped: the frame number.
    Valid(u64),
    /// In memory, on a list or under I/O: the frame number.
    Transition(u64),
    /// In the file only: the address of the subsection.
    Subsection(u64),
    /// Not a page of any section.
    Zero,
}

impl Proto {
    pub fn encode(self) -> u64 {
        match self {
            Self::Valid(pfn) => pfn << 12 | VALID,
            Self::Transition(pfn) => pfn << 12 & PFN_MASK | TRANSITION | MM_READWRITE << 5,
            Self::Subsection(address) => pack(address) | PROTOTYPE | MM_READWRITE << 5,
            Self::Zero => 0,
        }
    }

    pub fn decode(entry: u64) -> Self {
        if entry & VALID != 0 {
            Self::Valid((entry & PFN_MASK) >> 12)
        } else if entry & PROTOTYPE != 0 {
            Self::Subsection(unpack(entry))
        } else if entry & TRANSITION != 0 {
            Self::Transition((entry & PFN_MASK) >> 12)
        } else {
            Self::Zero
        }
    }
}

/// How a memory access is made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    Read,
    Write,
    Execute,
}

/// What a page-table entry of a system-cache view holds, as a fault
/// sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewEntry {
    /// Nothing is mapped.
    Empty,
    /// A prototype pointer: the page is to be resolved.
    Prototype,
    /// A valid entry, which allows writes or not.
    Valid { writable: bool },
}

/// What becomes of a fault on a system-cache view's page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewFault {
    /// Resolve the page from its prototype PTE.
    Resolve,
    /// The entry already allows the access (another processor made it
    /// valid meanwhile): run the access again.
    Again,
    /// Not the memory manager's to resolve: an access violation, or the
    /// kernel's rule for a fault on a kernel address.
    Refuse,
}

/// `MmAccessFault`'s first questions for a system-cache view: user mode
/// may not touch system addresses at all; view pages hold data, never
/// code; a valid entry is resolved again only for an access it allows,
/// so a protection fault is never taken for a page to bring in.
pub fn view_fault(entry: ViewEntry, access: Access, user_mode: bool) -> ViewFault {
    if user_mode || access == Access::Execute {
        return ViewFault::Refuse;
    }
    match entry {
        ViewEntry::Empty => ViewFault::Refuse,
        ViewEntry::Prototype => ViewFault::Resolve,
        ViewEntry::Valid { writable } if writable || access == Access::Read => ViewFault::Again,
        ViewEntry::Valid { .. } => ViewFault::Refuse,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_view_fault_resolves_only_what_it_may() {
        use super::{Access::*, ViewEntry::*, ViewFault::*, view_fault};
        assert_eq!(view_fault(Prototype, Read, false), Resolve);
        assert_eq!(view_fault(Prototype, Write, false), Resolve);
        assert_eq!(view_fault(Prototype, Execute, false), Refuse);
        assert_eq!(view_fault(Prototype, Read, true), Refuse);
        assert_eq!(view_fault(Empty, Read, false), Refuse);
        assert_eq!(view_fault(Valid { writable: true }, Write, false), Again);
        assert_eq!(view_fault(Valid { writable: false }, Read, false), Again);
        // A protection fault is no page to bring in, again and again.
        assert_eq!(view_fault(Valid { writable: false }, Write, false), Refuse);
        assert_eq!(view_fault(Valid { writable: true }, Execute, false), Refuse);
        assert_eq!(view_fault(Valid { writable: true }, Read, true), Refuse);
    }

    use super::*;

    #[test]
    fn every_format_round_trips() {
        for p in [
            Proto::Valid(0x12_3456),
            Proto::Transition(0xF_FFFF_FFFF),
            Proto::Subsection(0xFFFF_9100_0000_1238),
            Proto::Subsection(0x0000_7FFF_0000_0040),
            Proto::Zero,
        ] {
            assert_eq!(Proto::decode(p.encode()), p);
        }
    }

    #[test]
    fn the_encodings_are_windows() {
        let s = Proto::Subsection(0xFFFF_9100_0000_1238).encode();
        assert_eq!(s & 1, 0);
        assert_eq!(s & 1 << 10, 1 << 10);
        assert_eq!(s >> 16, 0xFFFF_9100_0000_1238 & 0xFFFF_FFFF_FFFF);
        assert_eq!(s >> 5 & 0x1F, MM_READWRITE);
        let t = Proto::Transition(0x1234).encode();
        assert_eq!(t & (1 | 1 << 10 | 1 << 11), 1 << 11);
        assert_eq!(t >> 12 & 0xF_FFFF_FFFF, 0x1234);
    }

    #[test]
    fn a_prototype_pointer_names_its_prototype_pte() {
        let proto = 0xFFFF_9100_0000_2000;
        let e = prototype_pointer(proto);
        assert_eq!(e & 1, 0);
        assert_eq!(prototype_target(e), Some(proto));
        assert_eq!(prototype_target(0), None);
        assert_eq!(
            prototype_target(e | 1),
            None,
            "a valid entry points at no prototype"
        );
    }
}
