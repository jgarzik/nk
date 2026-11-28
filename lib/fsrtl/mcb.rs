//! The mapping control block (`BASE_MCB`, inside `LARGE_MCB`): runs of a
//! file's virtual block numbers (VBNs) and the logical block numbers
//! (LBNs) of the volume where each run lies, or a hole.
//!
//! # As Windows keeps it
//!
//! The pinned kernel keeps an array of pairs, `{ NextVbn, Lbn }`, both
//! 32-bit: run `i` covers the VBNs from the previous pair's `NextVbn`
//! (0 for the first) up to its own, and starts at `Lbn`; an `Lbn` of
//! `0xFFFFFFFF` is a hole. The 64-bit numbers of the exports are cut to
//! their low 32 bits, as Windows cuts them. What the exports report is
//! fixed by the map itself, because Windows keeps it in one form:
//!
//! - runs are never empty;
//! - two neighbouring runs are never both holes, and never both mapped
//!   with the second continuing the first's LBNs: such runs are one;
//! - the map never ends in a hole: removing or truncating the last runs
//!   drops a hole left at the end.
//!
//! Every operation here takes the pairs and returns the new pairs in
//! that form; a range added over runs that map it differently is
//! refused and changes nothing.

use alloc::vec::Vec;

/// The `Lbn` of a hole.
pub const HOLE: u32 = u32::MAX;

/// One pair of the array, as Windows lays it out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct Pair {
    pub next_vbn: u32,
    pub lbn: u32,
}

/// A run: `count` VBNs from `vbn`, at `lbn` (or a hole).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Run {
    vbn: u32,
    count: u32,
    lbn: Option<u32>,
}

fn runs(pairs: &[Pair]) -> Vec<Run> {
    let mut start = 0;
    pairs
        .iter()
        .map(|p| {
            let run = Run {
                vbn: start,
                count: p.next_vbn.wrapping_sub(start),
                lbn: (p.lbn != HOLE).then_some(p.lbn),
            };
            start = p.next_vbn;
            run
        })
        .collect()
}

/// Whether `b` is the run that would follow `a` if they were one.
fn continues(a: &Run, b: &Run) -> bool {
    match (a.lbn, b.lbn) {
        (None, None) => true,
        (Some(x), Some(y)) => x.wrapping_add(a.count) == y,
        _ => false,
    }
}

/// The pairs of `runs`, which must lie end to end from VBN 0: empty
/// runs gone, runs that continue each other merged, a hole at the end
/// dropped.
fn pairs(runs: Vec<Run>) -> Vec<Pair> {
    let mut merged: Vec<Run> = Vec::with_capacity(runs.len());
    for run in runs.into_iter().filter(|r| r.count != 0) {
        match merged.last_mut() {
            Some(last) if continues(last, &run) => last.count += run.count,
            _ => merged.push(run),
        }
    }
    if merged.last().is_some_and(|r| r.lbn.is_none()) {
        merged.pop();
    }
    merged
        .iter()
        .map(|r| Pair {
            next_vbn: r.vbn + r.count,
            lbn: r.lbn.unwrap_or(HOLE),
        })
        .collect()
}

/// The pieces of `runs` before `vbn`, and from `vbn` on: a run that
/// spans it is cut in two.
fn split(runs: &[Run], vbn: u32) -> (Vec<Run>, Vec<Run>) {
    let (mut before, mut after) = (Vec::new(), Vec::new());
    for r in runs {
        if r.vbn + r.count <= vbn {
            before.push(*r);
        } else if r.vbn >= vbn {
            after.push(*r);
        } else {
            let head = vbn - r.vbn;
            before.push(Run { count: head, ..*r });
            after.push(Run {
                vbn,
                count: r.count - head,
                lbn: r.lbn.map(|l| l.wrapping_add(head)),
            });
        }
    }
    (before, after)
}

/// The end of the map: the VBN after its last run.
fn end(pairs: &[Pair]) -> u32 {
    pairs.last().map_or(0, |p| p.next_vbn)
}

/// What a look-up finds (`FsRtlLookupLargeMcbEntry`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    /// The LBN of the VBN asked about, `None` in a hole.
    pub lbn: Option<u32>,
    /// The VBNs from the one asked about to the end of its run.
    pub count_from_lbn: u32,
    /// The LBN the run starts at, `None` for a hole.
    pub starting_lbn: Option<u32>,
    /// The whole run's VBNs.
    pub count_from_starting_lbn: u32,
    /// The run's index.
    pub index: u32,
}

/// The run holding `vbn`, if the map reaches it.
pub fn lookup(pairs: &[Pair], vbn: u32) -> Option<Found> {
    let index = pairs.partition_point(|p| p.next_vbn <= vbn);
    let pair = pairs.get(index)?;
    let start = if index == 0 {
        0
    } else {
        pairs[index - 1].next_vbn
    };
    let starting_lbn = (pair.lbn != HOLE).then_some(pair.lbn);
    Some(Found {
        lbn: starting_lbn.map(|l| l.wrapping_add(vbn - start)),
        count_from_lbn: pair.next_vbn - vbn,
        starting_lbn,
        count_from_starting_lbn: pair.next_vbn - start,
        index: index as u32,
    })
}

/// The last VBN the map holds, its LBN (`None` in a hole: the map never
/// ends in one, so never), and its run's index
/// (`FsRtlLookupLastLargeMcbEntryAndIndex`).
pub fn last(pairs: &[Pair]) -> Option<(u32, Option<u32>, u32)> {
    let index = pairs.len().checked_sub(1)?;
    let found = lookup(pairs, pairs[index].next_vbn - 1)?;
    Some((pairs[index].next_vbn - 1, found.lbn, index as u32))
}

/// Run `index`: its first VBN, its LBN (`None` for a hole) and its
/// length (`FsRtlGetNextLargeMcbEntry`).
pub fn run(pairs: &[Pair], index: u32) -> Option<(u32, Option<u32>, u32)> {
    let r = runs(pairs).get(index as usize).copied()?;
    Some((r.vbn, r.lbn, r.count))
}

/// The map with `count` VBNs from `vbn` at the LBNs from `lbn` added
/// (`FsRtlAddLargeMcbEntry`); `None` if any of them is already mapped
/// elsewhere, or the range passes the last 32-bit VBN.
pub fn add(pairs: &[Pair], vbn: u32, lbn: u32, count: u32) -> Option<Vec<Pair>> {
    let stop = vbn.checked_add(count)?;
    lbn.checked_add(count)?;
    let mut all = runs(pairs);
    let end = end(pairs);
    if end < vbn {
        all.push(Run {
            vbn: end,
            count: vbn - end,
            lbn: None,
        });
    }
    let (before, rest) = split(&all, vbn);
    let (middle, after) = split(&rest, stop);
    for r in &middle {
        if let Some(l) = r.lbn
            && l != lbn.wrapping_add(r.vbn - vbn)
        {
            return None;
        }
    }
    let mut out = before;
    out.push(Run {
        vbn,
        count,
        lbn: Some(lbn),
    });
    out.extend(after);
    Some(pairs_from(out))
}

/// The map with `count` VBNs from `vbn` made a hole
/// (`FsRtlRemoveLargeMcbEntry`); what lies past the end stays absent.
pub fn remove(pairs: &[Pair], vbn: u32, count: u32) -> Vec<Pair> {
    let stop = vbn.saturating_add(count);
    let (before, rest) = split(&runs(pairs), vbn);
    let (middle, after) = split(&rest, stop);
    let mut out = before;
    out.extend(middle.iter().map(|r| Run { lbn: None, ..*r }));
    out.extend(after);
    pairs_from(out)
}

/// The map with every VBN from `vbn` on gone (`FsRtlTruncateLargeMcb`).
pub fn truncate(pairs: &[Pair], vbn: u32) -> Vec<Pair> {
    pairs_from(split(&runs(pairs), vbn).0)
}

/// [`pairs`] of runs that may be out of order where an addition put a
/// run among them: they are sorted first.
fn pairs_from(mut runs: Vec<Run>) -> Vec<Pair> {
    runs.sort_by_key(|r| r.vbn);
    pairs(runs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(next_vbn: u32, lbn: u32) -> Pair {
        Pair { next_vbn, lbn }
    }

    #[test]
    fn empty_finds_nothing() {
        assert_eq!(lookup(&[], 0), None);
        assert_eq!(last(&[]), None);
        assert_eq!(run(&[], 0), None);
    }

    #[test]
    fn first_run_at_zero() {
        let m = add(&[], 0, 100, 8).unwrap();
        assert_eq!(m, [p(8, 100)]);
        let f = lookup(&m, 3).unwrap();
        assert_eq!(f.lbn, Some(103));
        assert_eq!(f.count_from_lbn, 5);
        assert_eq!(f.starting_lbn, Some(100));
        assert_eq!(f.count_from_starting_lbn, 8);
        assert_eq!(f.index, 0);
        assert_eq!(lookup(&m, 8), None);
    }

    #[test]
    fn a_gap_becomes_a_hole() {
        let m = add(&[], 10, 50, 5).unwrap();
        assert_eq!(m, [p(10, HOLE), p(15, 50)]);
        let f = lookup(&m, 4).unwrap();
        assert_eq!(f.lbn, None);
        assert_eq!(f.starting_lbn, None);
        assert_eq!(f.count_from_lbn, 6);
        assert_eq!(run(&m, 0), Some((0, None, 10)));
        assert_eq!(run(&m, 1), Some((10, Some(50), 5)));
        assert_eq!(last(&m), Some((14, Some(54), 1)));
    }

    #[test]
    fn contiguous_runs_merge() {
        let m = add(&[], 0, 100, 4).unwrap();
        let m = add(&m, 4, 104, 4).unwrap();
        assert_eq!(m, [p(8, 100)]);
        let m = add(&m, 8, 200, 4).unwrap();
        assert_eq!(m, [p(8, 100), p(12, 200)]);
    }

    #[test]
    fn filling_a_hole_merges_both_sides() {
        let m = add(&[], 0, 100, 4).unwrap();
        let m = add(&m, 8, 108, 4).unwrap();
        assert_eq!(m, [p(4, 100), p(8, HOLE), p(12, 108)]);
        let m = add(&m, 4, 104, 4).unwrap();
        assert_eq!(m, [p(12, 100)]);
    }

    #[test]
    fn the_same_mapping_again_changes_nothing() {
        let m = add(&[], 0, 100, 8).unwrap();
        assert_eq!(add(&m, 2, 102, 3).unwrap(), m);
    }

    #[test]
    fn a_different_mapping_is_refused() {
        let m = add(&[], 0, 100, 8).unwrap();
        assert_eq!(add(&m, 2, 500, 1), None);
        // Partly over a hole, partly over a mapped run that disagrees.
        let m = add(&[], 4, 100, 4).unwrap();
        assert_eq!(add(&m, 2, 300, 4), None);
    }

    #[test]
    fn partly_over_a_hole_and_agreeing() {
        let m = add(&[], 4, 104, 4).unwrap();
        assert_eq!(add(&m, 2, 102, 4).unwrap(), [p(2, HOLE), p(8, 102)]);
    }

    #[test]
    fn remove_punches_a_hole() {
        let m = add(&[], 0, 100, 12).unwrap();
        let r = remove(&m, 4, 4);
        assert_eq!(r, [p(4, 100), p(8, HOLE), p(12, 108)]);
        assert_eq!(add(&r, 4, 104, 4).unwrap(), m);
    }

    #[test]
    fn remove_at_the_end_drops_the_hole() {
        let m = add(&[], 0, 100, 4).unwrap();
        let m = add(&m, 8, 200, 4).unwrap();
        assert_eq!(remove(&m, 8, 4), [p(4, 100)]);
        assert_eq!(remove(&m, 0, 12), []);
        assert_eq!(remove(&m, 2, 100), [p(2, 100)]);
    }

    #[test]
    fn remove_next_to_a_hole_merges_holes() {
        let m = add(&[], 4, 100, 4).unwrap();
        let m = add(&m, 8, 300, 4).unwrap();
        assert_eq!(remove(&m, 4, 4), [p(8, HOLE), p(12, 300)]);
    }

    #[test]
    fn truncate_cuts_and_drops_a_final_hole() {
        let m = add(&[], 0, 100, 4).unwrap();
        let m = add(&m, 8, 200, 4).unwrap();
        assert_eq!(truncate(&m, 10), [p(4, 100), p(8, HOLE), p(10, 200)]);
        assert_eq!(truncate(&m, 6), [p(4, 100)]);
        assert_eq!(truncate(&m, 0), []);
        assert_eq!(truncate(&m, 100), m);
    }

    #[test]
    fn runs_enumerate_every_pair() {
        let m = add(&[], 2, 10, 2).unwrap();
        let m = add(&m, 6, 30, 2).unwrap();
        let all: Vec<_> = (0..).map_while(|i| run(&m, i)).collect();
        assert_eq!(
            all,
            [
                (0, None, 2),
                (2, Some(10), 2),
                (4, None, 2),
                (6, Some(30), 2)
            ]
        );
        assert_eq!(all.len(), m.len());
    }

    #[test]
    fn ranges_past_32_bits_are_refused() {
        assert_eq!(add(&[], u32::MAX - 1, 0, 2), None);
        assert_eq!(add(&[], 0, u32::MAX - 1, 2), None);
        assert!(add(&[], u32::MAX - 2, 0, 2).is_some());
    }
}
