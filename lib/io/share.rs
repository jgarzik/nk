//! Share access, as the pinned kernel's `IoCheckLinkShareAccess` keeps
//! it for `IoCheckShareAccess`, `IoSetShareAccess`,
//! `IoUpdateShareAccess` and `IoRemoveShareAccess`: what an open asks
//! for and lets others have, against the counts of the opens before it
//! ([`IoCheckShareAccess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocheckshareaccess)).

/// The counts a file system keeps per file (`SHARE_ACCESS`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub open: u32,
    pub readers: u32,
    pub writers: u32,
    pub deleters: u32,
    pub shared_read: u32,
    pub shared_write: u32,
    pub shared_delete: u32,
}

/// What one open asks for and shares: the `FILE_OBJECT` fields
/// `ReadAccess` .. `SharedDelete`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Open {
    pub read: bool,
    pub write: bool,
    pub delete: bool,
    pub shared_read: bool,
    pub shared_write: bool,
    pub shared_delete: bool,
}

impl Open {
    /// From an open's granted access and share mode.
    pub fn new(access: u32, share: u32) -> Self {
        Self {
            // FILE_READ_DATA | FILE_EXECUTE
            read: access & 0x21 != 0,
            // FILE_WRITE_DATA | FILE_APPEND_DATA
            write: access & 0x6 != 0,
            // DELETE
            delete: access & 0x1_0000 != 0,
            shared_read: share & 1 != 0,
            shared_write: share & 2 != 0,
            shared_delete: share & 4 != 0,
        }
    }

    /// Whether the open has access that counts: an open for attributes
    /// alone neither conflicts nor is counted.
    pub fn counts(&self) -> bool {
        self.read || self.write || self.delete
    }
}

/// Whether `open` may join the opens counted in `counts`.
pub fn allowed(open: &Open, counts: &Counts) -> bool {
    !((open.read && counts.shared_read < counts.open)
        || (open.write && counts.shared_write < counts.open)
        || (open.delete && counts.shared_delete < counts.open)
        || (counts.readers != 0 && !open.shared_read)
        || (counts.writers != 0 && !open.shared_write)
        || (counts.deleters != 0 && !open.shared_delete))
}

/// Count `open` in `counts`.
pub fn add(open: &Open, counts: &mut Counts) {
    counts.open += 1;
    counts.readers += u32::from(open.read);
    counts.writers += u32::from(open.write);
    counts.deleters += u32::from(open.delete);
    counts.shared_read += u32::from(open.shared_read);
    counts.shared_write += u32::from(open.shared_write);
    counts.shared_delete += u32::from(open.shared_delete);
}

/// Take `open` out of `counts`.
pub fn remove(open: &Open, counts: &mut Counts) {
    counts.open = counts.open.wrapping_sub(1);
    counts.readers = counts.readers.wrapping_sub(u32::from(open.read));
    counts.writers = counts.writers.wrapping_sub(u32::from(open.write));
    counts.deleters = counts.deleters.wrapping_sub(u32::from(open.delete));
    counts.shared_read = counts.shared_read.wrapping_sub(u32::from(open.shared_read));
    counts.shared_write = counts
        .shared_write
        .wrapping_sub(u32::from(open.shared_write));
    counts.shared_delete = counts
        .shared_delete
        .wrapping_sub(u32::from(open.shared_delete));
}

#[cfg(test)]
mod tests {
    use super::*;

    const READ: u32 = 0x1;
    const WRITE: u32 = 0x2;
    const DELETE: u32 = 0x1_0000;

    fn counted(opens: &[Open]) -> Counts {
        let mut counts = Counts::default();
        for open in opens {
            add(open, &mut counts);
        }
        counts
    }

    #[test]
    fn readers_share_with_readers() {
        let first = Open::new(READ, 1);
        let counts = counted(&[first]);
        assert!(allowed(&Open::new(READ, 1), &counts));
        // A second reader that will not share reading is refused.
        assert!(!allowed(&Open::new(READ, 0), &counts));
        // A writer is refused: the reader shares no writing.
        assert!(!allowed(&Open::new(WRITE, 7), &counts));
    }

    #[test]
    fn attributes_alone_never_conflict() {
        let counts = counted(&[Open::new(READ | WRITE | DELETE, 0)]);
        let attributes = Open::new(0x80, 0);
        assert!(!attributes.counts());
        assert!(allowed(&Open::new(READ, 7), &Counts::default()));
        assert!(!allowed(&Open::new(READ, 7), &counts));
    }

    #[test]
    fn delete_needs_shared_delete() {
        let counts = counted(&[Open::new(READ, 1)]);
        assert!(!allowed(&Open::new(DELETE, 1), &counts));
        let counts = counted(&[Open::new(READ, 5)]);
        assert!(allowed(&Open::new(DELETE, 1), &counts));
    }

    #[test]
    fn remove_undoes_add() {
        let a = Open::new(READ | WRITE, 3);
        let b = Open::new(READ, 7);
        let mut counts = counted(&[a, b]);
        remove(&a, &mut counts);
        assert_eq!(counts, counted(&[b]));
    }
}
