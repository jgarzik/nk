//! A model checker for the tests: every state a few actors can reach,
//! whatever order their steps come in.

use std::collections::HashSet;
use std::fmt::Debug;
use std::hash::Hash;

/// Walk every state reachable from `start`. `steps` gives the states one
/// step away (one per actor able to move) and checks its invariants as
/// it goes; `finished` says whether every actor has run its script out.
///
/// A state with no step that is not finished is a deadlock: somebody
/// sleeps and nobody is left to wake them. Returns how many distinct
/// states were seen and how many of them were finished.
pub fn explore<S: Clone + Eq + Hash + Debug>(
    start: S,
    steps: impl Fn(&S) -> Vec<S>,
    finished: impl Fn(&S) -> bool,
) -> (usize, usize) {
    let mut seen = HashSet::new();
    let mut todo = vec![start.clone()];
    seen.insert(start);
    let mut ends = 0;
    while let Some(state) = todo.pop() {
        let next = steps(&state);
        if next.is_empty() {
            assert!(finished(&state), "stuck with work left: {state:?}");
            ends += 1;
        }
        for s in next {
            if seen.insert(s.clone()) {
                todo.push(s);
            }
        }
    }
    (seen.len(), ends)
}
