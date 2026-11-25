//! The scope table of a C function with `__try`: the search at the heart
//! of `__C_specific_handler`.
//!
//! The table is the function's handler data: a 32-bit count, then one
//! record of four RVAs per `__try`, inner scopes before the scopes that
//! enclose them. The same layout serves both architectures. This module
//! only decides which records apply and what each asks for; calling the
//! filter or the `__finally` block is the kernel's business.

use crate::{UnwindError, u32_at};

/// Size of one scope record.
pub const RECORD_SIZE: usize = 16;

/// `HandlerAddress` of a `__except` whose filter is the constant
/// `EXCEPTION_EXECUTE_HANDLER`.
const FILTER_ALWAYS: u32 = 1;

/// One `__try`. All four are RVAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScopeRecord {
    /// The guarded range, `begin..end`.
    pub begin: u32,
    pub end: u32,
    /// The filter of a `__except`, or the `__finally` block.
    pub handler: u32,
    /// Where a `__except` block starts; zero marks a `__finally`.
    pub jump_target: u32,
}

/// Number of records in a scope table.
pub fn count(table: &[u8]) -> Result<u32, UnwindError> {
    let n = u32_at(table, 0).map_err(|_| UnwindError::BadScopeTable)?;
    let need = (n as usize)
        .checked_mul(RECORD_SIZE)
        .and_then(|b| b.checked_add(4));
    match need {
        Some(need) if need <= table.len() => Ok(n),
        _ => Err(UnwindError::BadScopeTable),
    }
}

/// The `index`th record of a scope table.
pub fn record(table: &[u8], index: u32) -> Result<ScopeRecord, UnwindError> {
    if index >= count(table)? {
        return Err(UnwindError::BadScopeTable);
    }
    let at = 4 + index as usize * RECORD_SIZE;
    let field = |i: usize| u32_at(table, at + 4 * i).map_err(|_| UnwindError::BadScopeTable);
    Ok(ScopeRecord {
        begin: field(0)?,
        end: field(1)?,
        handler: field(2)?,
        jump_target: field(3)?,
    })
}

/// Which pass over the stack is running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Looking for a handler: filters are consulted.
    Search,
    /// Unwinding: `__finally` blocks run. `target` is the RVA the unwind
    /// will resume at when this frame is its target
    /// (`EXCEPTION_TARGET_UNWIND`), `None` in every other frame.
    Unwind { target: Option<u32> },
}

/// What one scope record asks of the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Call the filter. Negative: resume the faulting code. Zero: go on
    /// to the next record. Positive: unwind to `jump_target`.
    Filter { filter: u32, jump_target: u32 },
    /// The filter is constant: unwind to `jump_target`.
    ExecuteHandler { jump_target: u32 },
    /// Run the `__finally` block at `handler`, as an abnormal
    /// termination.
    Finally { handler: u32 },
    /// The unwind's target is inside this scope or is its `__except`
    /// block: nothing further out is being left.
    Stop,
}

/// The next record at or after index `from` that applies to `pc`, with
/// its index. `None` when no further record does. A handler resumes the
/// search at `index + 1`, the value it keeps in
/// `DISPATCHER_CONTEXT.ScopeIndex` so that an unwind which collides with
/// it does not run a `__finally` twice.
pub fn next(
    table: &[u8],
    pc: u32,
    phase: Phase,
    from: u32,
) -> Result<Option<(u32, Action)>, UnwindError> {
    for index in from..count(table)? {
        let r = record(table, index)?;
        if pc < r.begin || pc >= r.end {
            continue;
        }
        let action = match phase {
            Phase::Search if r.jump_target == 0 => continue,
            Phase::Search if r.handler == FILTER_ALWAYS => Action::ExecuteHandler {
                jump_target: r.jump_target,
            },
            Phase::Search => Action::Filter {
                filter: r.handler,
                jump_target: r.jump_target,
            },
            Phase::Unwind { target: Some(t) }
                if (t >= r.begin && t < r.end) || (r.jump_target != 0 && t == r.jump_target) =>
            {
                Action::Stop
            }
            Phase::Unwind { .. } if r.jump_target != 0 => continue,
            Phase::Unwind { .. } => Action::Finally { handler: r.handler },
        };
        return Ok(Some((index, action)));
    }
    Ok(None)
}
