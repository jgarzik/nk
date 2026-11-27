//! The page-frame-number database: one entry per physical frame, and the
//! lists of frames that hold a file's data but are mapped nowhere.
//!
//! The states are Windows' (`_MMLISTS`): zeroed, free, standby,
//! modified, modified-no-write, bad, active and transition. The free
//! and zeroed frames are the frame bitmap's (`frames`), which also
//! hands out the contiguous runs the pool and drivers need; NK zeroes a
//! frame when it hands it out, so "zeroed" is never a separate list.
//! Standby, modified, modified-no-write and bad are linked lists through
//! the entries themselves, as in Windows.
//!
//! An entry's counts follow Windows' rule: `share_count` is the number of
//! valid page-table entries that map the frame; `ref_count` is one for
//! "some valid entry maps it" plus one per I/O or lock in progress. A
//! frame goes onto a list only when `ref_count` reaches zero, and onto
//! the one its `MODIFIED` flag and its section's no-write setting name.
//!
//! The database is memory, reached through a slice, so the host tests
//! drive every transition.

/// No entry: the end of a list.
pub const NONE: u32 = u32::MAX;

/// Where a frame is: Windows' `_MMLISTS` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Location {
    Zeroed = 0,
    Free = 1,
    Standby = 2,
    Modified = 3,
    ModifiedNoWrite = 4,
    Bad = 5,
    Active = 6,
    Transition = 7,
}

impl Location {
    const ALL: [Self; 8] = [
        Self::Zeroed,
        Self::Free,
        Self::Standby,
        Self::Modified,
        Self::ModifiedNoWrite,
        Self::Bad,
        Self::Active,
        Self::Transition,
    ];

    /// The index of the linked list a frame in this state is on.
    fn list(self) -> Option<usize> {
        match self {
            Self::Standby => Some(0),
            Self::Modified => Some(1),
            Self::ModifiedNoWrite => Some(2),
            Self::Bad => Some(3),
            _ => None,
        }
    }
}

/// `Pfn.flags`.
pub mod flag {
    /// The frame's contents differ from the file's.
    pub const MODIFIED: u8 = 0x01;
    /// A read into the frame is in flight; collided faults wait for it.
    pub const READ_IN_PROGRESS: u8 = 0x02;
    /// A write of the frame is in flight.
    pub const WRITE_IN_PROGRESS: u8 = 0x04;
    /// The read into the frame failed.
    pub const IN_PAGE_ERROR: u8 = 0x08;
    /// The frame holds a page of a section, owned by a prototype PTE
    /// (`Pfn.pte`); else it is the kernel's (pool, stacks, tables).
    pub const PROTOTYPE: u8 = 0x10;
}

/// One frame's entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct Pfn {
    /// List links, while the frame is on a list.
    pub flink: u32,
    pub blink: u32,
    /// The address of the prototype PTE that owns the frame, for a page
    /// of a section; 0 for the kernel's frames.
    pub pte: u64,
    /// What the prototype PTE holds again once the frame leaves.
    pub original_pte: u64,
    /// The in-page or write block of the I/O in flight, while a flag
    /// says one is.
    pub io: u64,
    pub share_count: u32,
    pub ref_count: u16,
    location: u8,
    pub flags: u8,
}

impl Pfn {
    /// A frame the allocator holds.
    pub const FREE: Self = Self::at(Location::Free);
    /// A frame that is in use outside the database's knowledge: the
    /// kernel's, firmware's, the loader's.
    pub const IN_USE: Self = Self {
        ref_count: 1,
        ..Self::at(Location::Active)
    };

    const fn at(location: Location) -> Self {
        Self {
            flink: NONE,
            blink: NONE,
            pte: 0,
            original_pte: 0,
            io: 0,
            share_count: 0,
            ref_count: 0,
            location: location as u8,
            flags: 0,
        }
    }

    pub fn location(&self) -> Location {
        Location::ALL[usize::from(self.location & 7)]
    }

    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

#[derive(Debug, Clone, Copy)]
struct ListHead {
    first: u32,
    last: u32,
    count: u64,
}

const EMPTY: ListHead = ListHead {
    first: NONE,
    last: NONE,
    count: 0,
};

/// A transition the state of a frame does not allow: a kernel bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Illegal(pub &'static str);

/// The database: its entries, and the heads of its lists.
pub struct PfnDb<'a> {
    entries: &'a mut [Pfn],
    lists: [ListHead; 4],
}

impl<'a> PfnDb<'a> {
    /// The database over `entries`, each already holding [`Pfn::FREE`] or
    /// [`Pfn::IN_USE`]. Every list starts empty.
    pub fn new(entries: &'a mut [Pfn]) -> Self {
        Self {
            entries,
            lists: [EMPTY; 4],
        }
    }

    /// Frames the database covers.
    pub fn len(&self) -> u64 {
        self.entries.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn get(&self, pfn: u64) -> &Pfn {
        &self.entries[pfn as usize]
    }

    pub fn get_mut(&mut self, pfn: u64) -> &mut Pfn {
        &mut self.entries[pfn as usize]
    }

    /// How many frames are on the list of `location` (standby, modified,
    /// modified-no-write, bad); 0 for the other states.
    pub fn count(&self, location: Location) -> u64 {
        location.list().map_or(0, |l| self.lists[l].count)
    }

    /// The first frame on the list of `location`.
    pub fn first(&self, location: Location) -> Option<u64> {
        let list = self.lists[location.list()?];
        (list.first != NONE).then_some(u64::from(list.first))
    }

    /// The frame after `pfn` on its list.
    pub fn next(&self, pfn: u64) -> Option<u64> {
        let next = self.get(pfn).flink;
        (next != NONE).then_some(u64::from(next))
    }

    fn insert(&mut self, location: Location, pfn: u64, front: bool) {
        let l = location.list().expect("a list");
        let index = pfn as u32;
        let head = self.lists[l];
        {
            let e = self.get_mut(pfn);
            e.location = location as u8;
            (e.flink, e.blink) = if front {
                (head.first, NONE)
            } else {
                (NONE, head.last)
            };
        }
        let neighbour = if front { head.first } else { head.last };
        if neighbour == NONE {
            self.lists[l].first = index;
            self.lists[l].last = index;
        } else if front {
            self.get_mut(u64::from(neighbour)).blink = index;
            self.lists[l].first = index;
        } else {
            self.get_mut(u64::from(neighbour)).flink = index;
            self.lists[l].last = index;
        }
        self.lists[l].count += 1;
    }

    /// Take `pfn` off the list it is on, leaving it in transition.
    fn unlink(&mut self, pfn: u64) {
        let e = *self.get(pfn);
        let l = e.location().list().expect("a frame on a list");
        if e.blink == NONE {
            self.lists[l].first = e.flink;
        } else {
            self.get_mut(u64::from(e.blink)).flink = e.flink;
        }
        if e.flink == NONE {
            self.lists[l].last = e.blink;
        } else {
            self.get_mut(u64::from(e.flink)).blink = e.blink;
        }
        self.lists[l].count -= 1;
        let e = self.get_mut(pfn);
        (e.flink, e.blink) = (NONE, NONE);
        e.location = Location::Transition as u8;
    }

    /// A frame the allocator handed to the kernel: active, referenced,
    /// owned by no section.
    pub fn kernel_allocate(&mut self, pfn: u64) {
        *self.get_mut(pfn) = Pfn::IN_USE;
    }

    /// A frame the kernel gave back to the allocator.
    pub fn kernel_free(&mut self, pfn: u64) -> Result<(), Illegal> {
        let e = self.get(pfn);
        if e.has(flag::PROTOTYPE) || e.location() != Location::Active {
            return Err(Illegal("a frame freed as the kernel's is not the kernel's"));
        }
        *self.get_mut(pfn) = Pfn::FREE;
        Ok(())
    }

    /// A free frame becomes a page of a section, owned by the prototype
    /// PTE at `pte`, which held `original_pte`. With `reading`, a read
    /// into it starts: it is in transition, referenced by the I/O. Else
    /// it is mapped at once: active, with one valid mapping.
    pub fn allocate(&mut self, pfn: u64, pte: u64, original_pte: u64, reading: bool) {
        let e = self.get_mut(pfn);
        *e = Pfn {
            pte,
            original_pte,
            ref_count: 1,
            flags: flag::PROTOTYPE,
            ..Pfn::at(Location::Active)
        };
        if reading {
            e.location = Location::Transition as u8;
            e.flags |= flag::READ_IN_PROGRESS;
        } else {
            e.share_count = 1;
        }
    }

    /// One more valid mapping of a section's frame. A frame on a list
    /// leaves it (a soft fault); one held only by I/O becomes active.
    /// Returns whether it came off a list.
    pub fn share(&mut self, pfn: u64) -> Result<bool, Illegal> {
        let e = *self.get(pfn);
        if !e.has(flag::PROTOTYPE) {
            return Err(Illegal("a kernel frame is not shared"));
        }
        if e.has(flag::READ_IN_PROGRESS) {
            return Err(Illegal("a frame being read is mapped"));
        }
        let listed = e.location().list().is_some();
        if listed {
            self.unlink(pfn);
        }
        let e = self.get_mut(pfn);
        if e.share_count == 0 {
            e.ref_count += 1;
        }
        e.share_count += 1;
        e.location = Location::Active as u8;
        Ok(listed)
    }

    /// One valid mapping fewer. The last one drops the mapping's
    /// reference ([`Self::dereference`]); returns the list the frame went
    /// onto, if it did.
    pub fn unshare(
        &mut self,
        pfn: u64,
        no_write: bool,
        front: bool,
    ) -> Result<Option<Location>, Illegal> {
        let e = self.get_mut(pfn);
        if e.share_count == 0 {
            return Err(Illegal("a frame no valid entry maps is unshared"));
        }
        e.share_count -= 1;
        if e.share_count != 0 {
            return Ok(None);
        }
        self.dereference(pfn, no_write, front)
    }

    /// Hold a section's frame for I/O or a lock: it leaves any list.
    pub fn reference(&mut self, pfn: u64) -> Result<(), Illegal> {
        let e = *self.get(pfn);
        if !e.has(flag::PROTOTYPE) {
            return Err(Illegal("a kernel frame is not referenced"));
        }
        if e.location().list().is_some() {
            self.unlink(pfn);
        }
        let e = self.get_mut(pfn);
        e.ref_count = e
            .ref_count
            .checked_add(1)
            .ok_or(Illegal("a frame's reference count overflows"))?;
        Ok(())
    }

    /// Let go of a reference. When none is left and nothing maps the
    /// frame, it goes onto standby if clean, else onto modified, or
    /// modified-no-write when its section is written only by the cache
    /// manager (`no_write`); at the head with `front`. Returns the list.
    pub fn dereference(
        &mut self,
        pfn: u64,
        no_write: bool,
        front: bool,
    ) -> Result<Option<Location>, Illegal> {
        let e = self.get_mut(pfn);
        if e.ref_count == 0 {
            return Err(Illegal("an unreferenced frame is dereferenced"));
        }
        e.ref_count -= 1;
        if e.ref_count != 0 {
            return Ok(None);
        }
        if e.share_count != 0 {
            return Err(Illegal("a mapped frame lost its last reference"));
        }
        let to = match (e.has(flag::MODIFIED), no_write) {
            (false, _) => Location::Standby,
            (true, false) => Location::Modified,
            (true, true) => Location::ModifiedNoWrite,
        };
        self.insert(to, pfn, front);
        Ok(Some(to))
    }

    /// Move an unreferenced frame between standby, modified and
    /// modified-no-write as its flag and its section now say: after a
    /// write, or when the section stops being written by the writers.
    pub fn relist(&mut self, pfn: u64, no_write: bool) {
        let e = *self.get(pfn);
        if e.location().list().is_none() || e.location() == Location::Bad {
            return;
        }
        self.unlink(pfn);
        self.get_mut(pfn).ref_count = 1;
        let _ = self.dereference(pfn, no_write, false);
    }

    /// The read into `pfn` is over.
    pub fn read_done(&mut self, pfn: u64) {
        self.get_mut(pfn).flags &= !(flag::READ_IN_PROGRESS);
        self.get_mut(pfn).io = 0;
    }

    /// Take a section's frame away from it: it is on a list, or held
    /// only by the reference of a read that failed. Returns the
    /// prototype PTE's address and what it held before, for the caller
    /// to restore; the frame is free.
    pub fn release(&mut self, pfn: u64) -> Result<(u64, u64), Illegal> {
        let e = *self.get(pfn);
        if !e.has(flag::PROTOTYPE) {
            return Err(Illegal("a kernel frame is released from a section"));
        }
        if e.location().list().is_some() {
            self.unlink(pfn);
        } else if e.share_count != 0 || e.ref_count > 1 || !e.has(flag::IN_PAGE_ERROR) {
            return Err(Illegal("a frame in use is released"));
        }
        *self.get_mut(pfn) = Pfn::FREE;
        Ok((e.pte, e.original_pte))
    }

    /// The oldest standby frame, off its list, as [`Self::release`]
    /// gives it: the frame to reuse when the allocator has none free.
    pub fn reclaim(&mut self) -> Option<(u64, u64, u64)> {
        let pfn = self.first(Location::Standby)?;
        let (pte, original) = self.release(pfn).ok()?;
        Some((pfn, pte, original))
    }

    /// Check every invariant: each list's links and count, and that a
    /// listed frame is unreferenced and in its list's state; that a
    /// mapped frame is active; that a frame being read is in
    /// transition; that no clean frame is on modified nor dirty one on
    /// standby.
    pub fn check(&self) -> Result<(), Illegal> {
        for (l, location) in [
            Location::Standby,
            Location::Modified,
            Location::ModifiedNoWrite,
            Location::Bad,
        ]
        .into_iter()
        .enumerate()
        {
            let head = self.lists[l];
            let (mut at, mut previous, mut count) = (head.first, NONE, 0);
            while at != NONE {
                let e = self.get(u64::from(at));
                if e.location() != location || e.blink != previous {
                    return Err(Illegal("a list's links or states are wrong"));
                }
                if e.ref_count != 0 || e.share_count != 0 {
                    return Err(Illegal("a listed frame is in use"));
                }
                let dirty = e.has(flag::MODIFIED);
                if dirty == (location == Location::Standby) && location != Location::Bad {
                    return Err(Illegal(
                        "a frame is on the wrong list for its modified flag",
                    ));
                }
                count += 1;
                if count > head.count {
                    return Err(Illegal("a list is longer than its count"));
                }
                (previous, at) = (at, e.flink);
            }
            if previous != head.last || count != head.count {
                return Err(Illegal("a list's tail or count is wrong"));
            }
        }
        for e in self.entries.iter() {
            if e.share_count != 0 && e.location() != Location::Active {
                return Err(Illegal("a mapped frame is not active"));
            }
            if e.has(flag::READ_IN_PROGRESS) && e.location() != Location::Transition {
                return Err(Illegal("a frame being read is not in transition"));
            }
            if e.location().list().is_none() && (e.flink != NONE || e.blink != NONE) {
                return Err(Illegal("a frame on no list has links"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db(entries: &mut [Pfn]) -> PfnDb<'_> {
        entries.fill(Pfn::FREE);
        PfnDb::new(entries)
    }

    fn order(db: &PfnDb<'_>, location: Location) -> Vec<u64> {
        let mut v = Vec::new();
        let mut at = db.first(location);
        while let Some(pfn) = at {
            v.push(pfn);
            at = db.next(pfn);
        }
        v
    }

    #[test]
    fn a_mapped_page_goes_to_standby_when_its_last_mapping_goes() {
        let mut e = [Pfn::FREE; 8];
        let mut d = db(&mut e);
        d.allocate(3, 0x1000, 0x400, false);
        assert_eq!(d.get(3).location(), Location::Active);
        assert_eq!((d.get(3).share_count, d.get(3).ref_count), (1, 1));
        assert_eq!(d.share(3), Ok(false));
        assert_eq!(d.unshare(3, false, false), Ok(None));
        assert_eq!(d.unshare(3, false, false), Ok(Some(Location::Standby)));
        assert_eq!(d.count(Location::Standby), 1);
        d.check().unwrap();
        // A soft fault takes it back.
        assert_eq!(d.share(3), Ok(true));
        assert_eq!(d.count(Location::Standby), 0);
        assert_eq!(d.get(3).location(), Location::Active);
        d.check().unwrap();
    }

    #[test]
    fn a_dirty_page_goes_to_modified_or_modified_no_write() {
        let mut e = [Pfn::FREE; 8];
        let mut d = db(&mut e);
        d.allocate(1, 0x1000, 0x400, false);
        d.allocate(2, 0x1008, 0x400, false);
        d.get_mut(1).flags |= flag::MODIFIED;
        d.get_mut(2).flags |= flag::MODIFIED;
        assert_eq!(d.unshare(1, false, false), Ok(Some(Location::Modified)));
        assert_eq!(
            d.unshare(2, true, false),
            Ok(Some(Location::ModifiedNoWrite))
        );
        d.check().unwrap();
        // Written: clean, and standby.
        d.get_mut(1).flags &= !flag::MODIFIED;
        d.relist(1, false);
        assert_eq!(d.get(1).location(), Location::Standby);
        d.check().unwrap();
    }

    #[test]
    fn a_page_under_io_stays_off_the_lists_until_released() {
        let mut e = [Pfn::FREE; 8];
        let mut d = db(&mut e);
        d.allocate(4, 0x2000, 0x400, true);
        assert_eq!(d.get(4).location(), Location::Transition);
        assert!(d.get(4).has(flag::READ_IN_PROGRESS));
        assert_eq!(d.share(4), Err(Illegal("a frame being read is mapped")));
        d.check().unwrap();
        d.read_done(4);
        // Read ahead of need: nothing maps it, so standby.
        assert_eq!(d.dereference(4, false, false), Ok(Some(Location::Standby)));
        // Locked while unmapped: off standby, and back when unlocked.
        d.reference(4).unwrap();
        assert_eq!(d.count(Location::Standby), 0);
        assert_eq!(d.dereference(4, false, false), Ok(Some(Location::Standby)));
        d.check().unwrap();
    }

    #[test]
    fn standby_is_reused_oldest_first_and_front_goes_first() {
        let mut e = [Pfn::FREE; 8];
        let mut d = db(&mut e);
        for pfn in 1..=3 {
            d.allocate(pfn, 0x1000 + pfn * 8, 0x400 + pfn, false);
            d.unshare(pfn, false, false).unwrap();
        }
        d.allocate(5, 0x5000, 0x405, false);
        d.unshare(5, false, true).unwrap();
        assert_eq!(order(&d, Location::Standby), [5, 1, 2, 3]);
        assert_eq!(d.reclaim(), Some((5, 0x5000, 0x405)));
        assert_eq!(d.reclaim(), Some((1, 0x1008, 0x401)));
        assert_eq!(*d.get(1), Pfn::FREE);
        // From the middle.
        assert_eq!(d.release(3), Ok((0x1018, 0x403)));
        assert_eq!(order(&d, Location::Standby), [2]);
        d.check().unwrap();
        assert_eq!(d.reclaim(), Some((2, 0x1010, 0x402)));
        assert_eq!(d.reclaim(), None);
        d.check().unwrap();
    }

    #[test]
    fn illegal_transitions_are_refused() {
        let mut e = [Pfn::FREE; 8];
        let mut d = db(&mut e);
        d.kernel_allocate(6);
        assert!(d.share(6).is_err());
        assert!(d.reference(6).is_err());
        assert!(d.release(6).is_err());
        d.kernel_free(6).unwrap();
        d.allocate(2, 0x1000, 0x400, false);
        assert!(d.kernel_free(2).is_err());
        assert!(d.release(2).is_err(), "a mapped frame is in use");
        d.unshare(2, false, false).unwrap();
        assert!(d.unshare(2, false, false).is_err());
        assert!(d.dereference(2, false, false).is_err());
        d.check().unwrap();
    }

    #[test]
    fn a_failed_read_releases_its_frame() {
        let mut e = [Pfn::FREE; 4];
        let mut d = db(&mut e);
        d.allocate(1, 0x1000, 0x400, true);
        assert!(d.release(1).is_err(), "a read in flight is not released");
        d.get_mut(1).flags |= flag::IN_PAGE_ERROR;
        assert_eq!(d.release(1), Ok((0x1000, 0x400)));
        d.check().unwrap();
    }

    #[test]
    fn check_finds_a_broken_list() {
        let mut e = [Pfn::FREE; 4];
        let mut d = db(&mut e);
        d.allocate(1, 0x1000, 0x400, false);
        d.unshare(1, false, false).unwrap();
        d.get_mut(1).flags |= flag::MODIFIED;
        assert!(d.check().is_err());
        d.get_mut(1).flags &= !flag::MODIFIED;
        d.get_mut(1).ref_count = 1;
        assert!(d.check().is_err());
    }
}
