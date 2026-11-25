//! What the kernel exports to drivers.
//!
//! One table drives three things: the import binder resolves names against
//! it, the boot log prints it, and the compatibility ledger is generated
//! from that log. An import with no entry here rejects the driver.
//!
//! An entry's `State` is an honest claim about the function behind it; see
//! `ledger/README.md`. Exports exist because a real driver in the fixture
//! corpus imports them, not to fill out the Windows export list.

use crate::{io, ldr, rtl};

#[derive(Clone, Copy, PartialEq, Eq)]
#[expect(
    dead_code,
    reason = "the first partial and trapping exports arrive with the next driver"
)]
pub enum State {
    /// Does what the Windows routine does, for what the kernel supports.
    Implemented,
    /// Works for the subset the proof drivers use; gaps are documented at
    /// the function.
    Partial,
    /// Present so the driver loads; bugchecks by name if ever called.
    Traps,
}

impl State {
    fn name(self) -> &'static str {
        match self {
            State::Implemented => "implemented",
            State::Partial => "partial",
            State::Traps => "traps",
        }
    }
}

pub struct Export {
    module: &'static str,
    name: &'static str,
    addr: *const (),
    state: State,
}

// SAFETY: an `Export` is immutable and its pointer names a function.
unsafe impl Sync for Export {}

const NT: &str = "ntoskrnl.exe";

macro_rules! export {
    ($state:ident, $path:path) => {
        Export {
            module: NT,
            name: {
                // The symbol is the last path segment.
                let full = stringify!($path).as_bytes();
                let mut start = full.len();
                while start > 0 && full[start - 1] != b':' {
                    start -= 1;
                }
                // SAFETY: `full` is ASCII and `start` is a char boundary.
                unsafe { core::str::from_utf8_unchecked(full.split_at(start).1) }
            },
            addr: $path as *const (),
            state: State::$state,
        }
    };
}

static EXPORTS: &[Export] = &[
    export!(Implemented, io::device::IoCreateDevice),
    export!(Implemented, io::device::IoDeleteDevice),
    export!(Implemented, io::irp::IofCompleteRequest),
    export!(Implemented, ldr::MmPageEntireDriver),
    export!(Implemented, rtl::RtlInitUnicodeString),
];

/// The address a driver's import of `module!name` binds to.
pub fn resolve(module: &[u8], name: &[u8]) -> Option<u64> {
    EXPORTS
        .iter()
        .find(|e| e.module.as_bytes().eq_ignore_ascii_case(module) && e.name.as_bytes() == name)
        .map(|e| e.addr as u64)
}

/// Print the table for the ledger: `NK-EXPORT <module> <name> <state>`.
pub fn print_all() {
    for e in EXPORTS {
        kprintln!("NK-EXPORT {} {} {}", e.module, e.name, e.state.name());
    }
}
