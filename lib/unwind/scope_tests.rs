//! Tests of the scope-table search and of the dispatch decisions.

use crate::UnwindError;
use crate::dispatch::*;
use crate::scope::{Action, Phase, ScopeRecord, count, next, record};

fn table(records: &[[u32; 4]]) -> Vec<u8> {
    let mut t = (records.len() as u32).to_le_bytes().to_vec();
    t.extend(records.iter().flatten().flat_map(|w| w.to_le_bytes()));
    t
}

/// Every action for `pc`, as a handler would collect them: resume after
/// each record, stop at `Stop`.
fn actions(t: &[u8], pc: u32, phase: Phase) -> Vec<(u32, Action)> {
    let mut out = Vec::new();
    let mut from = 0;
    while let Some((index, action)) = next(t, pc, phase, from).unwrap() {
        out.push((index, action));
        if action == Action::Stop {
            break;
        }
        from = index + 1;
    }
    out
}

const F1: u32 = 0x900;
const H2: u32 = 0x910;
const T1: u32 = 0x300;
const T3: u32 = 0x320;

/// `__try { __try { __try {} __except(1) {} } __finally {} } __except(f) {}`
fn nested() -> Vec<u8> {
    table(&[
        [0x130, 0x140, 1, T3],
        [0x120, 0x180, H2, 0],
        [0x100, 0x200, F1, T1],
    ])
}

#[test]
fn records_are_read_and_bounded() {
    let t = nested();
    assert_eq!(count(&t), Ok(3));
    assert_eq!(
        record(&t, 1),
        Ok(ScopeRecord {
            begin: 0x120,
            end: 0x180,
            handler: H2,
            jump_target: 0
        })
    );
    assert_eq!(record(&t, 3), Err(UnwindError::BadScopeTable));
    // A count that runs past the bytes, and no count at all.
    assert_eq!(count(&t[..t.len() - 1]), Err(UnwindError::BadScopeTable));
    assert_eq!(count(&[1, 0]), Err(UnwindError::BadScopeTable));
    assert_eq!(
        count(&u32::MAX.to_le_bytes()),
        Err(UnwindError::BadScopeTable)
    );
    assert_eq!(
        next(&t[..20], 0x130, Phase::Search, 0),
        Err(UnwindError::BadScopeTable)
    );
    assert_eq!(next(&table(&[]), 0x130, Phase::Search, 0), Ok(None));
}

#[test]
fn search_yields_the_filters_inside_out() {
    let t = nested();
    let filter = Action::Filter {
        filter: F1,
        jump_target: T1,
    };
    let always = Action::ExecuteHandler { jump_target: T3 };
    assert_eq!(
        actions(&t, 0x135, Phase::Search),
        [(0, always), (2, filter)]
    );
    // Between the scopes only the outer filter applies; a __finally is
    // not consulted when searching.
    assert_eq!(actions(&t, 0x150, Phase::Search), [(2, filter)]);
    // A range holds its first byte and not its end.
    assert_eq!(actions(&t, 0x100, Phase::Search), [(2, filter)]);
    assert_eq!(actions(&t, 0x1FF, Phase::Search), [(2, filter)]);
    assert_eq!(actions(&t, 0x0FF, Phase::Search), []);
    assert_eq!(actions(&t, 0x200, Phase::Search), []);
    assert_eq!(actions(&t, 0x140, Phase::Search), [(2, filter)]);
    // Resuming past a record does not return to it.
    assert_eq!(next(&t, 0x135, Phase::Search, 1), Ok(Some((2, filter))));
    assert_eq!(next(&t, 0x135, Phase::Search, 3), Ok(None));
    assert_eq!(next(&t, 0x135, Phase::Search, 99), Ok(None));
}

#[test]
fn unwind_runs_finally_blocks_up_to_the_target() {
    let t = nested();
    let finally = Action::Finally { handler: H2 };
    // Not the target frame: every __finally around pc runs.
    assert_eq!(
        actions(&t, 0x135, Phase::Unwind { target: None }),
        [(1, finally)]
    );
    assert_eq!(actions(&t, 0x190, Phase::Unwind { target: None }), []);
    // To the innermost __except block: nothing is left.
    assert_eq!(
        actions(&t, 0x135, Phase::Unwind { target: Some(T3) }),
        [(0, Action::Stop)]
    );
    // To the outer __except block: the __finally between runs first.
    assert_eq!(
        actions(&t, 0x135, Phase::Unwind { target: Some(T1) }),
        [(1, finally), (2, Action::Stop)]
    );
    // A jump that stays inside the __finally's scope does not run it.
    assert_eq!(
        actions(
            &t,
            0x135,
            Phase::Unwind {
                target: Some(0x170)
            }
        ),
        [(1, Action::Stop)]
    );
    // A jump out of it, still inside the outer scope, does.
    assert_eq!(
        actions(
            &t,
            0x135,
            Phase::Unwind {
                target: Some(0x1F0)
            }
        ),
        [(1, finally), (2, Action::Stop)]
    );
    // A target elsewhere in the function leaves every scope.
    assert_eq!(
        actions(
            &t,
            0x135,
            Phase::Unwind {
                target: Some(0x400)
            }
        ),
        [(1, finally)]
    );
    // A collided unwind resumes after the __finally it already ran.
    assert_eq!(
        next(&t, 0x135, Phase::Unwind { target: Some(T1) }, 2),
        Ok(Some((2, Action::Stop)))
    );
    // A __finally record's zero jump target is not a target.
    assert_eq!(
        actions(&t, 0x150, Phase::Unwind { target: Some(0) }),
        [(1, finally)]
    );
}

/// One scope of a generated function.
#[derive(Clone, Copy)]
struct Scope {
    begin: u32,
    end: u32,
    handler: u32,
    jump_target: u32,
}

struct Rng(u64);

impl Rng {
    fn below(&mut self, n: u32) -> u32 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 20) as u32 % n
    }
}

/// Fill `begin..end` with nested scopes, inner scopes emitted before the
/// scope around them, as the compiler orders its table.
fn generate(rng: &mut Rng, begin: u32, end: u32, depth: u32, out: &mut Vec<Scope>) {
    let mut at = begin;
    while depth < 5 && at + 8 < end {
        let b = at + rng.below(8);
        let e = b + 4 + rng.below(end - b);
        if e > end {
            break;
        }
        let (inner_begin, inner_end) = (b + rng.below(2), e - rng.below(2));
        generate(rng, inner_begin, inner_end, depth + 1, out);
        let id = out.len() as u32;
        let (handler, jump_target) = match rng.below(3) {
            0 => (0x9000 + id, 0),
            1 => (1, 0x8000 + id),
            _ => (0x9000 + id, 0x8000 + id),
        };
        out.push(Scope {
            begin: b,
            end: e,
            handler,
            jump_target,
        });
        at = e + rng.below(4);
    }
}

/// What the handler must do, from the nesting alone: take the scopes
/// that contain `pc`, innermost (smallest) first.
fn model(scopes: &[Scope], pc: u32, phase: Phase) -> Vec<Action> {
    let mut around: Vec<&Scope> = scopes
        .iter()
        .filter(|s| s.begin <= pc && pc < s.end)
        .collect();
    around.sort_by_key(|s| s.end - s.begin);
    let mut out = Vec::new();
    for s in around {
        let (is_finally, jump_target) = (s.jump_target == 0, s.jump_target);
        match phase {
            Phase::Search if is_finally => {}
            Phase::Search if s.handler == 1 => out.push(Action::ExecuteHandler { jump_target }),
            Phase::Search => out.push(Action::Filter {
                filter: s.handler,
                jump_target,
            }),
            Phase::Unwind { target } => {
                let stays = target.is_some_and(|t| {
                    (s.begin <= t && t < s.end) || (!is_finally && t == jump_target)
                });
                if stays {
                    out.push(Action::Stop);
                    break;
                }
                if is_finally {
                    out.push(Action::Finally { handler: s.handler });
                }
            }
        }
    }
    out
}

#[test]
fn search_agrees_with_a_nested_range_model() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    let (mut checked, mut nonempty) = (0, 0);
    for _ in 0..60 {
        let mut scopes = Vec::new();
        generate(&mut rng, 0x100, 0x200, 0, &mut scopes);
        let rows: Vec<[u32; 4]> = scopes
            .iter()
            .map(|s| [s.begin, s.end, s.handler, s.jump_target])
            .collect();
        let t = table(&rows);
        for pc in 0xF8..0x208 {
            let mut phases = vec![Phase::Search, Phase::Unwind { target: None }];
            // Unwind to every __except block and to a few addresses in
            // and around the function.
            phases.extend(
                scopes
                    .iter()
                    .filter(|s| s.jump_target != 0)
                    .map(|s| Phase::Unwind {
                        target: Some(s.jump_target),
                    }),
            );
            phases.extend((0..4).map(|_| Phase::Unwind {
                target: Some(0xF8 + rng.below(0x110)),
            }));
            for phase in phases {
                let got: Vec<Action> = actions(&t, pc, phase).into_iter().map(|(_, a)| a).collect();
                let want = model(&scopes, pc, phase);
                assert_eq!(got, want, "pc {pc:#x} {phase:?} table {rows:x?}");
                checked += 1;
                nonempty += usize::from(!want.is_empty());
            }
        }
    }
    assert!(
        checked > 50_000 && nonempty > checked / 4,
        "{nonempty} of {checked}"
    );
}

#[test]
fn search_dispositions_map_to_the_next_step() {
    assert_eq!(
        after_search_handler(EXCEPTION_CONTINUE_EXECUTION, 0),
        Next::Resume
    );
    assert_eq!(
        after_search_handler(EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_NESTED_CALL),
        Next::Resume
    );
    assert_eq!(
        after_search_handler(EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_NONCONTINUABLE),
        Next::Raise(STATUS_NONCONTINUABLE_EXCEPTION)
    );
    assert_eq!(
        after_search_handler(EXCEPTION_CONTINUE_SEARCH, EXCEPTION_NONCONTINUABLE),
        Next::NextFrame
    );
    assert_eq!(
        after_search_handler(EXCEPTION_NESTED_EXCEPTION, 0),
        Next::Nested
    );
    assert_eq!(
        after_search_handler(EXCEPTION_COLLIDED_UNWIND_DISPOSITION, 0),
        Next::Collided
    );
    assert_eq!(
        after_search_handler(4, 0),
        Next::Raise(STATUS_INVALID_DISPOSITION)
    );
    assert_eq!(
        after_search_handler(u32::MAX, 0),
        Next::Raise(STATUS_INVALID_DISPOSITION)
    );
}

#[test]
fn unwind_dispositions_map_to_the_next_step() {
    assert_eq!(
        after_unwind_handler(EXCEPTION_CONTINUE_SEARCH),
        Next::NextFrame
    );
    assert_eq!(
        after_unwind_handler(EXCEPTION_COLLIDED_UNWIND_DISPOSITION),
        Next::Collided
    );
    for d in [EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_NESTED_EXCEPTION, 4] {
        assert_eq!(
            after_unwind_handler(d),
            Next::Raise(STATUS_INVALID_DISPOSITION)
        );
    }
}

#[test]
fn filter_values_map_by_sign() {
    assert_eq!(after_filter(-1), FilterResult::ContinueExecution);
    assert_eq!(after_filter(i32::MIN), FilterResult::ContinueExecution);
    assert_eq!(after_filter(0), FilterResult::ContinueSearch);
    assert_eq!(after_filter(1), FilterResult::ExecuteHandler);
    assert_eq!(after_filter(i32::MAX), FilterResult::ExecuteHandler);
}

#[test]
fn unwind_flags_name_the_phase_of_each_frame() {
    assert_eq!(
        (
            EXCEPTION_UNWINDING,
            EXCEPTION_EXIT_UNWIND,
            EXCEPTION_STACK_INVALID
        ),
        (2, 4, 8)
    );
    assert_eq!(
        (
            EXCEPTION_NESTED_CALL,
            EXCEPTION_TARGET_UNWIND,
            EXCEPTION_COLLIDED_UNWIND
        ),
        (0x10, 0x20, 0x40)
    );
    assert_eq!(EXCEPTION_UNWIND, 0x66);
    assert_eq!(
        (STATUS_UNWIND, STATUS_BAD_STACK),
        (0xC000_0027, 0xC000_0028)
    );
    assert_eq!(STATUS_INVALID_UNWIND_TARGET, 0xC000_0029);

    assert_eq!(unwind_flags(0, 0x1000, Some(0x2000)), EXCEPTION_UNWINDING);
    assert_eq!(
        unwind_flags(0, 0x2000, Some(0x2000)),
        EXCEPTION_UNWINDING | EXCEPTION_TARGET_UNWIND
    );
    assert_eq!(
        unwind_flags(0, 0x2000, None),
        EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND
    );
    // Only the target frame itself is the target, not the frames below it.
    assert_eq!(unwind_flags(0, 0x2000, Some(0x1000)), EXCEPTION_UNWINDING);
    // Other flags are kept; a stale target flag is not.
    assert_eq!(
        unwind_flags(
            EXCEPTION_NONCONTINUABLE | EXCEPTION_TARGET_UNWIND,
            0x1000,
            Some(0x2000)
        ),
        EXCEPTION_NONCONTINUABLE | EXCEPTION_UNWINDING
    );
}

#[test]
fn frames_are_checked_against_the_stack_and_the_target() {
    let (low, high) = (0x1000, 0x2000);
    assert_eq!(check_frame(0x1000, low, high, None), FrameCheck::Ok);
    assert_eq!(check_frame(0x1FF8, low, high, None), FrameCheck::Ok);
    assert_eq!(check_frame(0x0FF8, low, high, None), FrameCheck::BadStack);
    assert_eq!(check_frame(0x2000, low, high, None), FrameCheck::BadStack);
    assert_eq!(check_frame(0x1804, low, high, None), FrameCheck::BadStack);
    assert_eq!(check_frame(0x1800, low, high, Some(0x1800)), FrameCheck::Ok);
    assert_eq!(check_frame(0x1800, low, high, Some(0x1900)), FrameCheck::Ok);
    assert_eq!(
        check_frame(0x1800, low, high, Some(0x17F8)),
        FrameCheck::PastTarget
    );
    // A bad stack is reported before a missed target.
    assert_eq!(
        check_frame(0x3000, low, high, Some(0x1800)),
        FrameCheck::BadStack
    );
}
