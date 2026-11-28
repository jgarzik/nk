//! A file's buffer control blocks (BCBs): the ranges pinned through it,
//! kept sorted by offset as `CcFindBcb` and `CcAllocateInitializeBcb`
//! keep them; the BCB that covers a range; the dirty runs the lazy
//! writer and flushes take; and the three kinds of handle a file system
//! is given for a mapped or pinned range.
//!
//! BCBs may overlap: a pin of a range no BCB wholly covers gets a BCB of
//! its own, as on Windows.

/// `NodeTypeCode` of a BCB.
pub const BCB_NODE: u16 = 0x2FD;
/// `NodeTypeCode` of an OBCB: the BCBs of a pin that spans views.
pub const OBCB_NODE: u16 = 0x2FA;

/// What a handle from `CcMapData`, `CcPinRead` or `CcPreparePinWrite`
/// is, by `CcUnpinData`'s tests: bit 0 set is a mapping (a VACB's
/// address plus one); otherwise the node type it points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Handle {
    /// A mapping: the VACB's address.
    Mapped(usize),
    Bcb,
    Obcb,
    /// Neither: a file system's bug.
    Invalid(u16),
}

/// The kind of `handle`; `node_type` reads the node type at an address
/// (only called for a pointer with bit 0 clear).
pub fn handle_kind(handle: usize, node_type: impl FnOnce(usize) -> u16) -> Handle {
    if handle & 1 != 0 {
        return Handle::Mapped(handle - 1);
    }
    match node_type(handle) {
        BCB_NODE => Handle::Bcb,
        OBCB_NODE => Handle::Obcb,
        other => Handle::Invalid(other),
    }
}

/// A BCB as the list sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub offset: u64,
    pub beyond: u64,
    pub dirty: bool,
}

/// Where `[offset, beyond)` stands in `list` (sorted by offset): the
/// index of the first BCB that wholly covers it, or the index a new BCB
/// for it goes at.
pub fn find(list: &[Entry], offset: u64, beyond: u64) -> Result<usize, usize> {
    let at = list.partition_point(|e| e.offset <= offset);
    list[..at]
        .iter()
        .rposition(|e| e.beyond >= beyond)
        .ok_or(at)
}

/// The next dirty run at or after `from`: the first dirty BCB that
/// starts there or later, and the dirty BCBs that overlap or adjoin
/// what is gathered, while the run stays within `most` bytes. Returns
/// the run's start, its end, and the indexes of its BCBs.
pub fn dirty_run(
    list: &[Entry],
    from: u64,
    most: u64,
) -> Option<(u64, u64, alloc::vec::Vec<usize>)> {
    let first = list.iter().position(|e| e.dirty && e.offset >= from)?;
    let (start, mut end) = (list[first].offset, list[first].beyond);
    let mut members = alloc::vec![first];
    for (i, e) in list.iter().enumerate().skip(first + 1) {
        if e.offset > end {
            break;
        }
        if e.dirty && e.beyond.max(end) - start <= most {
            end = end.max(e.beyond);
            members.push(i);
        }
    }
    Some((start, end, members))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(offset: u64, beyond: u64, dirty: bool) -> Entry {
        Entry {
            offset,
            beyond,
            dirty,
        }
    }

    #[test]
    fn handles_are_told_apart() {
        assert_eq!(
            handle_kind(0x1001, |_| unreachable!()),
            Handle::Mapped(0x1000)
        );
        assert_eq!(handle_kind(0x2000, |_| BCB_NODE), Handle::Bcb);
        assert_eq!(handle_kind(0x2000, |_| OBCB_NODE), Handle::Obcb);
        assert_eq!(handle_kind(0x2000, |_| 0x705), Handle::Invalid(0x705));
    }

    #[test]
    fn the_covering_bcb_is_found_or_a_place_given() {
        let list = [
            e(0, 0x200, false),
            e(0x1000, 0x2000, false),
            e(0x1800, 0x1A00, false),
        ];
        assert_eq!(find(&list, 0x100, 0x200), Ok(0));
        assert_eq!(
            find(&list, 0x1800, 0x1900),
            Ok(2),
            "the latest-starting cover"
        );
        assert_eq!(find(&list, 0x1900, 0x1C00), Ok(1));
        assert_eq!(
            find(&list, 0x1900, 0x2100),
            Err(3),
            "overlapping is not covering"
        );
        assert_eq!(find(&list, 0x400, 0x600), Err(1));
        assert_eq!(find(&[], 0, 1), Err(0));
    }

    #[test]
    fn dirty_runs_gather_overlapping_and_adjoining_bcbs() {
        let list = [
            e(0, 0x200, false),
            e(0x1000, 0x1200, true),
            e(0x1200, 0x1400, true),
            e(0x1300, 0x1600, false),
            e(0x1500, 0x1800, true),
            e(0x4000, 0x4200, true),
        ];
        assert_eq!(
            dirty_run(&list, 0, 0x10000),
            Some((0x1000, 0x1400, vec![1, 2]))
        );
        assert_eq!(
            dirty_run(&list, 0, 0x200),
            Some((0x1000, 0x1200, vec![1])),
            "capped"
        );
        assert_eq!(
            dirty_run(&list, 0x1001, 0x10000),
            Some((0x1200, 0x1400, vec![2]))
        );
        assert_eq!(
            dirty_run(&list, 0x1201, 0x10000),
            Some((0x1500, 0x1800, vec![4])),
            "not across a clean gap"
        );
        assert_eq!(dirty_run(&list, 0x4001, 0x10000), None);
    }
}
