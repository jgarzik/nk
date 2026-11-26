//! Range lists: the rules of `RtlAddRange`, `RtlDeleteRange`,
//! `RtlFindRange`, `RtlIsRangeAvailable`, `RtlInvertRangeList` and their
//! kin, with which the bus drivers' arbiters keep account of the
//! address space they hand out. Microsoft documented them in the
//! Windows 2000 DDK and no longer does; the header that declares them
//! is `ntddk.h` of that kit.
//!
//! A range is `start..=end` with an owner, attributes and two flags:
//! *shared*, given when it is added, and *conflict*, which the list
//! keeps.
//!
//! # NK's list, and Windows'
//!
//! The list is written against a store of ranges kept in order
//! ([`Ranges`]): the kernel's is a chain of pool blocks, the host
//! tests' a vector.
//!
//! Windows keeps ranges that overlap inside a *merged* range, a private
//! container, and the ranges and containers of a list in order of
//! where they start. NK keeps no containers: one chain, in order of
//! start, a new range after those that start where it does. Read from
//! the kernel NK follows (10.0.19041), that is the order Windows' two
//! levels are walked in, since a container's ranges are kept the same
//! way and containers do not overlap. The rest of what a caller can
//! observe is read from there too:
//!
//! - A range has the conflict flag exactly when it overlaps another
//!   range and the two are not both shared. Windows sets it on both
//!   when one is added over the other, and works it out afresh for the
//!   ranges left in a container when one is deleted.
//! - An add that would conflict is refused unless it asks to be added
//!   anyway; two shared ranges never conflict.
//! - A search runs from the highest address down, and after a conflict
//!   tries next just below the range it met.
//! - A range in the way is passed over if it is shared and the caller
//!   said shared is fine, or has one of the attributes the caller
//!   named, or has no owner and the caller said so, or the caller's
//!   callback says to pass it over; the callback is asked last, and
//!   only about ranges still in the way.
//! - The inverse of a list is the gaps between its ranges over the
//!   whole 64 bits; the inverse of an empty list is one range.

/// `RTL_RANGE_LIST_ADD_IF_CONFLICT`: add the range though it conflicts.
pub const ADD_IF_CONFLICT: u32 = 1;
/// `RTL_RANGE_LIST_ADD_SHARED`: the range may share with shared ranges.
pub const ADD_SHARED: u32 = 2;
/// A flag of `RtlAddRange` that no header declares: the range's user
/// data is a pool block that starts with a count of the entries that
/// point to it.
pub const ADD_COUNTED: u32 = 0x10;
/// The flag a range added so carries, which no header declares either.
pub const COUNTED: u8 = 0x10;
/// `RTL_RANGE_SHARED`, of a range's flags.
pub const SHARED: u8 = 1;
/// `RTL_RANGE_CONFLICT`, of a range's flags.
pub const CONFLICT: u8 = 2;
/// `RTL_RANGE_LIST_SHARED_OK`: a search may land on shared ranges.
pub const SHARED_OK: u32 = 1;
/// `RTL_RANGE_LIST_NULL_CONFLICT_OK`: a search may land on ranges with
/// no owner.
pub const NULL_CONFLICT_OK: u32 = 2;

/// What the list reads of a range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub start: u64,
    /// The last address of the range, not the one after it.
    pub end: u64,
    pub attributes: u8,
    pub flags: u8,
    /// The owner, as a number: zero is no owner.
    pub owner: usize,
}

impl Range {
    fn shared(&self) -> bool {
        self.flags & SHARED != 0
    }

    fn overlaps(&self, other: &Range) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    fn conflicts(&self, other: &Range) -> bool {
        self.overlaps(other) && !(self.shared() && other.shared())
    }
}

/// The ranges of a list, in order.
pub trait Ranges {
    /// What names a range.
    type Id: Copy + PartialEq;

    fn first(&self) -> Option<Self::Id>;
    fn last(&self) -> Option<Self::Id>;
    fn next(&self, id: Self::Id) -> Option<Self::Id>;
    fn previous(&self, id: Self::Id) -> Option<Self::Id>;
    fn range(&self, id: Self::Id) -> Range;
    fn set_flags(&mut self, id: Self::Id, flags: u8);
    /// Put `new`, which is in no list, before `before`, or last.
    fn insert(&mut self, new: Self::Id, before: Option<Self::Id>);
    /// Take `id` out of the list.
    fn remove(&mut self, id: Self::Id);
}

/// The ranges from `from` on, forward.
fn forward<R: Ranges>(list: &R, from: Option<R::Id>) -> impl Iterator<Item = R::Id> + '_ {
    core::iter::successors(from, |&id| list.next(id))
}

/// The ranges of the list other than `this` that `range` conflicts
/// with. The list is in order of start, so none past the first that
/// starts after `range` ends.
fn conflicts<'a, R: Ranges>(
    list: &'a R,
    this: Option<R::Id>,
    range: Range,
) -> impl Iterator<Item = R::Id> + 'a {
    forward(list, list.first())
        .take_while(move |&id| list.range(id).start <= range.end)
        .filter(move |&id| Some(id) != this && list.range(id).conflicts(&range))
}

/// `STATUS_RANGE_LIST_CONFLICT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Conflict;

/// `RtlAddRange`, once the range has its block: put `new`, which is
/// filled in (its shared flag included) and in no list, in its place.
/// `Err` is `STATUS_RANGE_LIST_CONFLICT`: the range conflicts with one
/// in the list and `if_conflict` was not asked for; the list is as it
/// was.
pub fn add<R: Ranges>(list: &mut R, new: R::Id, if_conflict: bool) -> Result<(), Conflict> {
    let mut range = list.range(new);
    range.flags &= !CONFLICT;
    let mut first = conflicts(list, None, range).next();
    if first.is_some() && !if_conflict {
        return Err(Conflict);
    }
    if first.is_some() {
        range.flags |= CONFLICT;
    }
    list.set_flags(new, range.flags);
    while let Some(id) = first {
        let flags = list.range(id).flags;
        list.set_flags(id, flags | CONFLICT);
        // The ones marked no longer need marking; `conflicts` still
        // lists them, so go on from the one after.
        first = forward(list, list.next(id))
            .take_while(|&id| list.range(id).start <= range.end)
            .find(|&id| list.range(id).conflicts(&range));
    }
    let after = forward(list, list.first()).find(|&id| list.range(id).start > range.start);
    list.insert(new, after);
    Ok(())
}

/// `RtlDeleteRange`: the range that starts and ends there and has that
/// owner. None is `STATUS_RANGE_NOT_FOUND`.
pub fn find_exact<R: Ranges>(list: &R, start: u64, end: u64, owner: usize) -> Option<R::Id> {
    forward(list, list.first())
        .take_while(|&id| list.range(id).start <= start)
        .find(|&id| {
            let range = list.range(id);
            range.start == start && range.end == end && range.owner == owner
        })
}

/// `RtlDeleteOwnersRanges`: the first range of that owner.
pub fn owned_by<R: Ranges>(list: &R, owner: usize) -> Option<R::Id> {
    forward(list, list.first()).find(|&id| list.range(id).owner == owner)
}

/// Take `id` out of the list, and the conflict flag off the ranges that
/// conflicted with it alone. The caller frees it.
pub fn remove<R: Ranges>(list: &mut R, id: R::Id) {
    let gone = list.range(id);
    list.remove(id);
    let mut at = list.first();
    while let Some(other) = at {
        let range = list.range(other);
        if range.start > gone.end {
            break;
        }
        if range.overlaps(&gone) {
            let still = conflicts(list, Some(other), range).next().is_some();
            let flags = if still {
                range.flags | CONFLICT
            } else {
                range.flags & !CONFLICT
            };
            list.set_flags(other, flags);
        }
        at = list.next(other);
    }
}

/// What a search may land on.
#[derive(Debug, Clone, Copy)]
pub struct Tolerance {
    /// `RTL_RANGE_LIST_SHARED_OK` and `RTL_RANGE_LIST_NULL_CONFLICT_OK`.
    pub flags: u32,
    /// A range with any of these attributes is not in the way.
    pub attributes: u8,
}

/// The first range, from `from` on in the direction given, that keeps
/// `start..=end` from being available; `None` if it is available.
/// `passed_over` is the caller's callback: asked about a range that is
/// in the way by every other rule, it says whether to pass it over.
pub fn in_the_way<R: Ranges>(
    list: &R,
    from: Option<R::Id>,
    go_forward: bool,
    (start, end): (u64, u64),
    tolerance: Tolerance,
    passed_over: &mut dyn FnMut(R::Id) -> bool,
) -> Option<R::Id> {
    let mut at = from;
    while let Some(id) = at {
        let range = list.range(id);
        if go_forward && range.start > end {
            // In order of start: nothing further can overlap.
            return None;
        }
        let overlaps = range.start <= end && start <= range.end;
        let tolerated = (tolerance.flags & SHARED_OK != 0 && range.shared())
            || range.attributes & tolerance.attributes != 0
            || (tolerance.flags & NULL_CONFLICT_OK != 0 && range.owner == 0);
        if overlaps && !tolerated && !passed_over(id) {
            return Some(id);
        }
        at = if go_forward {
            list.next(id)
        } else {
            list.previous(id)
        };
    }
    None
}

/// Why `RtlFindRange` fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindError {
    /// `STATUS_INVALID_PARAMETER`: no range of that length and alignment
    /// lies between the bounds.
    InvalidParameter,
    /// `STATUS_UNSUCCESSFUL`: every place is taken.
    Unsuccessful,
}

/// `RtlFindRange`: the highest start of `length` free bytes within
/// `minimum..=maximum` that is a multiple of `alignment`.
///
/// An alignment of zero is `STATUS_INVALID_PARAMETER`, as the routine's
/// own check intends; Windows divides by it before the check is reached.
pub fn find<R: Ranges>(
    list: &R,
    (minimum, maximum): (u64, u64),
    length: u64,
    alignment: u64,
    tolerance: Tolerance,
    passed_over: &mut dyn FnMut(R::Id) -> bool,
) -> Result<u64, FindError> {
    if alignment == 0 || length == 0 || minimum > maximum || maximum - minimum < length - 1 {
        return Err(FindError::InvalidParameter);
    }
    let highest = maximum - (length - 1);
    let mut start = highest - highest % alignment;
    if minimum.checked_add(alignment).is_none() || start < minimum {
        return Err(FindError::InvalidParameter);
    }
    let mut from = list.last();
    loop {
        let wanted = (start, start + (length - 1));
        let Some(id) = in_the_way(list, from, false, wanted, tolerance, passed_over) else {
            return Ok(start);
        };
        // Next, the highest place that ends below the range in the way;
        // the ranges after it cannot reach down there.
        let below = list
            .range(id)
            .start
            .checked_sub(length)
            .ok_or(FindError::Unsuccessful)?;
        start = below - below % alignment;
        if start < minimum {
            return Err(FindError::Unsuccessful);
        }
        from = Some(id);
    }
}

/// `RtlInvertRangeList`: the ranges of the inverse of a list, which are
/// the gaps between its ranges from zero to the last address there is.
pub fn gaps<R: Ranges>(list: &R) -> impl Iterator<Item = (u64, u64)> + '_ {
    let mut at = list.first();
    let empty = at.is_none();
    // The first address not known to be covered; none once the last
    // address is.
    let mut uncovered = Some(0u64);
    let mut finished = false;
    core::iter::from_fn(move || {
        if finished {
            return None;
        }
        while let Some(id) = at {
            at = list.next(id);
            let range = list.range(id);
            let Some(from) = uncovered else { break };
            let after = range.end.checked_add(1);
            uncovered = after.map(|after| after.max(from));
            if range.start > from {
                return Some((from, range.start - 1));
            }
        }
        finished = true;
        match uncovered {
            // The inverse of nothing is everything.
            Some(0) if empty => Some((0, u64::MAX)),
            Some(from) if from != 0 => Some((from, u64::MAX)),
            _ => None,
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A list as a vector of ranges and the order they are in.
    #[derive(Default)]
    struct List {
        ranges: Vec<Range>,
        order: Vec<usize>,
    }

    impl List {
        fn place(&self, id: usize) -> usize {
            self.order.iter().position(|&at| at == id).unwrap()
        }

        /// `RtlAddRange`.
        fn add(
            &mut self,
            start: u64,
            end: u64,
            flags: u32,
            owner: usize,
        ) -> Result<usize, Conflict> {
            let id = self.ranges.len();
            self.ranges.push(Range {
                start,
                end,
                attributes: 0,
                flags: if flags & ADD_SHARED != 0 { SHARED } else { 0 },
                owner,
            });
            add(self, id, flags & ADD_IF_CONFLICT != 0).map(|()| id)
        }

        fn with_attributes(mut self, id: usize, attributes: u8) -> Self {
            self.ranges[id].attributes = attributes;
            self
        }

        /// The ranges in order: start, end, flags.
        fn listed(&self) -> Vec<(u64, u64, u8)> {
            self.order
                .iter()
                .map(|&id| {
                    let range = self.ranges[id];
                    (range.start, range.end, range.flags)
                })
                .collect()
        }

        /// The invariants: in order of start, and the conflict flag on
        /// exactly the ranges that conflict with another.
        fn check(&self) {
            for pair in self.order.windows(2) {
                assert!(self.ranges[pair[0]].start <= self.ranges[pair[1]].start);
            }
            for &id in &self.order {
                let range = self.ranges[id];
                let conflicting = self
                    .order
                    .iter()
                    .any(|&other| other != id && self.ranges[other].conflicts(&range));
                assert_eq!(range.flags & CONFLICT != 0, conflicting, "{range:?}");
            }
        }
    }

    impl Ranges for List {
        type Id = usize;
        fn first(&self) -> Option<usize> {
            self.order.first().copied()
        }
        fn last(&self) -> Option<usize> {
            self.order.last().copied()
        }
        fn next(&self, id: usize) -> Option<usize> {
            self.order.get(self.place(id) + 1).copied()
        }
        fn previous(&self, id: usize) -> Option<usize> {
            self.place(id).checked_sub(1).map(|place| self.order[place])
        }
        fn range(&self, id: usize) -> Range {
            self.ranges[id]
        }
        fn set_flags(&mut self, id: usize, flags: u8) {
            self.ranges[id].flags = flags;
        }
        fn insert(&mut self, new: usize, before: Option<usize>) {
            let place = before.map_or(self.order.len(), |before| self.place(before));
            self.order.insert(place, new);
        }
        fn remove(&mut self, id: usize) {
            let place = self.place(id);
            self.order.remove(place);
        }
    }

    const NONE: Tolerance = Tolerance {
        flags: 0,
        attributes: 0,
    };

    fn never(_: usize) -> bool {
        false
    }

    #[test]
    fn ranges_are_kept_in_order_of_start() {
        let mut list = List::default();
        for (start, end) in [(50, 59), (10, 19), (30, 39), (0, 5), (100, 100)] {
            list.add(start, end, 0, 1).unwrap();
        }
        assert_eq!(
            list.listed(),
            [
                (0, 5, 0),
                (10, 19, 0),
                (30, 39, 0),
                (50, 59, 0),
                (100, 100, 0)
            ]
        );
        list.check();
        // The whole of the address space is a range.
        let mut all = List::default();
        all.add(0, u64::MAX, 0, 1).unwrap();
        assert_eq!(all.listed(), [(0, u64::MAX, 0)]);
    }

    #[test]
    fn an_overlap_is_refused_unless_shared_or_asked_for() {
        let mut list = List::default();
        list.add(10, 19, 0, 1).unwrap();
        for (start, end) in [(10, 19), (0, 10), (19, 30), (12, 13), (0, 100)] {
            assert_eq!(list.add(start, end, 0, 2), Err(Conflict));
            // Shared does not help against a range that is not.
            assert_eq!(list.add(start, end, ADD_SHARED, 2), Err(Conflict));
        }
        assert_eq!(list.listed(), [(10, 19, 0)]);
        list.add(0, 9, 0, 2).unwrap();
        list.add(20, 29, 0, 2).unwrap();
        list.check();

        // Shared ranges overlap one another freely.
        let mut shared = List::default();
        shared.add(10, 19, ADD_SHARED, 1).unwrap();
        shared.add(15, 25, ADD_SHARED, 2).unwrap();
        shared.add(10, 19, ADD_SHARED, 3).unwrap();
        assert_eq!(shared.add(18, 18, 0, 4), Err(Conflict));
        assert_eq!(
            shared.listed(),
            [(10, 19, SHARED), (10, 19, SHARED), (15, 25, SHARED)]
        );
        shared.check();
    }

    #[test]
    fn a_conflict_added_anyway_is_flagged_on_both_sides() {
        let mut list = List::default();
        list.add(10, 19, 0, 1).unwrap();
        list.add(30, 39, ADD_SHARED, 1).unwrap();
        list.add(50, 59, 0, 1).unwrap();
        list.add(15, 35, ADD_IF_CONFLICT, 2).unwrap();
        assert_eq!(
            list.listed(),
            [
                (10, 19, CONFLICT),
                (15, 35, CONFLICT),
                (30, 39, SHARED | CONFLICT),
                (50, 59, 0)
            ]
        );
        list.check();
        // Asked for, but nothing in the way: no flag.
        list.add(70, 79, ADD_IF_CONFLICT, 2).unwrap();
        // Shared over shared is no conflict, even when asked for.
        list.add(32, 33, ADD_IF_CONFLICT | ADD_SHARED, 3).unwrap();
        assert_eq!(list.ranges[5].flags, SHARED | CONFLICT, "it meets 15..=35");
        list.add(75, 76, ADD_IF_CONFLICT | ADD_SHARED, 3).unwrap();
        list.check();
    }

    #[test]
    fn a_range_goes_after_those_that_start_where_it_does() {
        let mut list = List::default();
        let a = list.add(10, 19, ADD_SHARED, 1).unwrap();
        let b = list.add(10, 30, ADD_SHARED, 2).unwrap();
        let c = list.add(10, 12, ADD_SHARED, 3).unwrap();
        let d = list.add(5, 40, ADD_SHARED, 4).unwrap();
        assert_eq!(list.order, [d, a, b, c]);
    }

    #[test]
    fn deleting_wants_start_end_and_owner_and_clears_stale_conflicts() {
        let mut list = List::default();
        let a = list.add(10, 19, 0, 1).unwrap();
        let b = list.add(15, 25, ADD_IF_CONFLICT, 2).unwrap();
        let c = list.add(22, 30, ADD_IF_CONFLICT, 3).unwrap();
        list.check();
        assert_eq!(find_exact(&list, 10, 19, 1), Some(a));
        assert_eq!(find_exact(&list, 10, 19, 2), None);
        assert_eq!(find_exact(&list, 10, 18, 1), None);
        assert_eq!(find_exact(&list, 11, 19, 1), None);
        assert_eq!(find_exact(&list, 15, 25, 2), Some(b));
        assert_eq!(find_exact(&list, 99, 99, 1), None);
        // Without the middle one the outer two no longer conflict.
        remove(&mut list, b);
        assert_eq!(list.listed(), [(10, 19, 0), (22, 30, 0)]);
        list.check();
        // With it back, deleting an end leaves the other pair's flags.
        let b = list.add(15, 25, ADD_IF_CONFLICT, 2).unwrap();
        remove(&mut list, a);
        assert_eq!(list.listed(), [(15, 25, CONFLICT), (22, 30, CONFLICT)]);
        list.check();
        assert_eq!(owned_by(&list, 3), Some(c));
        assert_eq!(owned_by(&list, 2), Some(b));
        assert_eq!(owned_by(&list, 1), None);
    }

    #[test]
    fn two_ranges_with_the_same_bounds_and_owner_go_one_at_a_time() {
        let mut list = List::default();
        let a = list.add(10, 19, ADD_SHARED, 7).unwrap();
        let b = list.add(10, 19, ADD_SHARED, 7).unwrap();
        assert_eq!(find_exact(&list, 10, 19, 7), Some(a));
        remove(&mut list, a);
        assert_eq!(find_exact(&list, 10, 19, 7), Some(b));
        remove(&mut list, b);
        assert_eq!(find_exact(&list, 10, 19, 7), None);
        assert!(list.order.is_empty());
    }

    fn available(list: &List, start: u64, end: u64, tolerance: Tolerance) -> bool {
        in_the_way(
            list,
            list.first(),
            true,
            (start, end),
            tolerance,
            &mut never,
        )
        .is_none()
    }

    #[test]
    fn a_range_is_available_if_nothing_is_in_the_way() {
        let mut list = List::default();
        list.add(10, 19, 0, 1).unwrap();
        let shared = list.add(30, 39, ADD_SHARED, 1).unwrap();
        let unowned = list.add(50, 59, 0, 0).unwrap();
        let marked = list.add(70, 79, 0, 1).unwrap();
        let list = list.with_attributes(marked, 0x40);
        assert!(available(&List::default(), 0, u64::MAX, NONE));
        assert!(available(&list, 0, 9, NONE));
        assert!(available(&list, 20, 29, NONE));
        assert!(available(&list, 80, u64::MAX, NONE));
        for (start, end) in [
            (0, 10),
            (19, 20),
            (12, 13),
            (0, 100),
            (35, 35),
            (55, 60),
            (79, 79),
        ] {
            assert!(!available(&list, start, end, NONE), "{start}..={end}");
        }
        let tolerate = |flags, attributes| Tolerance { flags, attributes };
        assert!(available(&list, 20, 49, tolerate(SHARED_OK, 0)));
        assert!(!available(&list, 20, 50, tolerate(SHARED_OK, 0)));
        assert!(available(&list, 40, 69, tolerate(NULL_CONFLICT_OK, 0)));
        assert!(!available(&list, 39, 69, tolerate(NULL_CONFLICT_OK, 0)));
        assert!(available(&list, 60, 100, tolerate(0, 0x40)));
        assert!(available(&list, 60, 100, tolerate(0, 0xC0)));
        assert!(!available(&list, 60, 100, tolerate(0, 0x80)));
        assert!(available(
            &list,
            20,
            u64::MAX,
            tolerate(SHARED_OK | NULL_CONFLICT_OK, 0x40)
        ));
        // The callback is asked only about what is still in the way,
        // in order, and may pass a range over.
        let mut asked = Vec::new();
        let mut pass_shared = |id: usize| {
            asked.push(id);
            id == shared
        };
        let met = in_the_way(
            &list,
            list.first(),
            true,
            (20, 75),
            tolerate(0, 0x40),
            &mut pass_shared,
        );
        assert_eq!(met, Some(unowned));
        assert_eq!(asked, [shared, unowned]);
    }

    #[test]
    fn a_search_takes_the_highest_place_that_fits() {
        let mut list = List::default();
        list.add(0x1000, 0x1FFF, 0, 1).unwrap();
        list.add(0x3000, 0x3FFF, 0, 1).unwrap();
        list.add(0x8000, 0x8FFF, 0, 1).unwrap();
        let find_in =
            |bounds, length, alignment| find(&list, bounds, length, alignment, NONE, &mut never);
        // From the top.
        assert_eq!(find_in((0, 0xFFFF), 0x1000, 0x1000), Ok(0xF000));
        assert_eq!(find_in((0, 0xFFFF), 0x1000, 1), Ok(0xF000));
        assert_eq!(find_in((0, 0xFFFE), 0x1000, 1), Ok(0xEFFF));
        assert_eq!(find_in((0, 0xFFFE), 0x1000, 0x1000), Ok(0xE000));
        // Below a range in the way.
        assert_eq!(find_in((0, 0x8FFF), 0x1000, 0x1000), Ok(0x7000));
        assert_eq!(find_in((0, 0x8800), 0x800, 0x1000), Ok(0x7000));
        assert_eq!(find_in((0, 0x8800), 0x800, 1), Ok(0x7800));
        assert_eq!(find_in((0, 0x8FFF), 0x4000, 0x1000), Ok(0x4000));
        // Too large for the gap between two: on down.
        assert_eq!(
            find_in((0, 0x8FFF), 0x4001, 1),
            Err(FindError::Unsuccessful)
        );
        assert_eq!(find_in((0, 0x3FFF), 0x1000, 0x1000), Ok(0x2000));
        assert_eq!(
            find_in((0, 0x3FFF), 0x1001, 1),
            Err(FindError::Unsuccessful)
        );
        assert_eq!(find_in((0, 0x1FFF), 0x1000, 0x1000), Ok(0));
        assert_eq!(
            find_in((1, 0x1FFF), 0x1000, 1),
            Err(FindError::Unsuccessful)
        );
        assert_eq!(find_in((0, 0x1FFF), 0x800, 0x1000), Ok(0));
        // The minimum bounds it.
        assert_eq!(find_in((0x4000, 0x8FFF), 0x4000, 0x1000), Ok(0x4000));
        assert_eq!(
            find_in((0x4001, 0x8FFF), 0x3FFF, 0x1000),
            Err(FindError::Unsuccessful)
        );
        assert_eq!(find_in((0x4001, 0x8FFF), 0x3FFF, 1), Ok(0x4001));
        // The very top of the address space.
        assert_eq!(find_in((0, u64::MAX), 0x1000, 0x1000), Ok(u64::MAX - 0xFFF));
        assert_eq!(find_in((0, u64::MAX), 1, 1), Ok(u64::MAX));
        assert_eq!(
            find(
                &List::default(),
                (0, u64::MAX),
                u64::MAX,
                1,
                NONE,
                &mut never
            ),
            Ok(1)
        );
    }

    #[test]
    fn a_search_that_cannot_be_is_refused() {
        let list = List::default();
        let find_in =
            |bounds, length, alignment| find(&list, bounds, length, alignment, NONE, &mut never);
        let invalid = Err(FindError::InvalidParameter);
        assert_eq!(find_in((0, 0xFFFF), 0, 1), invalid);
        assert_eq!(find_in((0, 0xFFFF), 0x10, 0), invalid);
        assert_eq!(find_in((0x100, 0xFF), 1, 1), invalid);
        assert_eq!(find_in((0, 0xFF), 0x101, 1), invalid);
        assert_eq!(find_in((0, 0xFF), 0x100, 1), Ok(0));
        // The highest aligned place is below the minimum.
        assert_eq!(find_in((0x10, 0x1FF), 0x100, 0x1000), invalid);
        // The minimum and the alignment do not add up.
        assert_eq!(find_in((u64::MAX - 1, u64::MAX), 1, 2), invalid);
        assert_eq!(find_in((u64::MAX - 1, u64::MAX), 1, 1), Ok(u64::MAX));
    }

    #[test]
    fn a_search_agrees_with_trying_every_place() {
        struct Random(u64);
        impl Random {
            fn below(&mut self, bound: u64) -> u64 {
                self.0 = self
                    .0
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (self.0 >> 33) % bound
            }
        }
        let mut random = Random(9);
        for _ in 0..300 {
            let mut list = List::default();
            for _ in 0..random.below(8) {
                let start = random.below(120);
                let end = start + random.below(12);
                let flags = [0, ADD_SHARED, ADD_IF_CONFLICT, ADD_IF_CONFLICT | ADD_SHARED]
                    [random.below(4) as usize];
                let _ = list.add(start, end, flags, random.below(3) as usize);
                list.check();
            }
            while list.order.len() > 3 {
                let id = list.order[random.below(list.order.len() as u64) as usize];
                remove(&mut list, id);
                list.check();
            }
            for _ in 0..20 {
                let minimum = random.below(60);
                let maximum = minimum + random.below(90);
                let length = random.below(20) + 1;
                let alignment = [1, 2, 4, 8, 3][random.below(5) as usize];
                let tolerance = Tolerance {
                    flags: random.below(4) as u32,
                    attributes: 0,
                };
                let found = find(
                    &list,
                    (minimum, maximum),
                    length,
                    alignment,
                    tolerance,
                    &mut never,
                );
                let Ok(found) = found else {
                    // Refused, or nothing fits: no aligned place does.
                    let fits = (minimum..=maximum).any(|start| {
                        start % alignment == 0
                            && start + length - 1 <= maximum
                            && available(&list, start, start + length - 1, tolerance)
                    });
                    if found == Err(FindError::Unsuccessful) {
                        assert!(!fits);
                    }
                    continue;
                };
                let highest = (minimum..=maximum)
                    .rev()
                    .find(|&start| {
                        start % alignment == 0
                            && start + length - 1 <= maximum
                            && available(&list, start, start + length - 1, tolerance)
                    })
                    .unwrap();
                assert_eq!(found, highest);
            }
        }
    }

    #[test]
    fn the_inverse_is_the_gaps() {
        let inverse = |ranges: &[(u64, u64)]| {
            let mut list = List::default();
            for &(start, end) in ranges {
                list.add(start, end, ADD_IF_CONFLICT, 1).unwrap();
            }
            gaps(&list).collect::<Vec<_>>()
        };
        assert_eq!(inverse(&[]), [(0, u64::MAX)]);
        assert_eq!(inverse(&[(0, u64::MAX)]), []);
        assert_eq!(inverse(&[(10, 19)]), [(0, 9), (20, u64::MAX)]);
        assert_eq!(inverse(&[(0, 19)]), [(20, u64::MAX)]);
        assert_eq!(inverse(&[(10, u64::MAX)]), [(0, 9)]);
        assert_eq!(
            inverse(&[(10, 19), (30, 39)]),
            [(0, 9), (20, 29), (40, u64::MAX)]
        );
        // Adjacent and overlapping ranges leave no gap between them.
        assert_eq!(inverse(&[(10, 19), (20, 29)]), [(0, 9), (30, u64::MAX)]);
        assert_eq!(
            inverse(&[(10, 40), (15, 20), (35, 50), (60, 60)]),
            [(0, 9), (51, 59), (61, u64::MAX)]
        );
        // A range inside one that reaches the top does not reopen it.
        assert_eq!(inverse(&[(5, u64::MAX), (10, 20)]), [(0, 4)]);
        assert_eq!(
            inverse(&[(0, 0), (u64::MAX, u64::MAX)]),
            [(1, u64::MAX - 1)]
        );
    }
}
