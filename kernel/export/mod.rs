//! What the kernel exports to drivers.
//!
//! One table drives three things: the import binder resolves names against
//! it, the boot log prints it, and the compatibility ledger is generated
//! from that log. An import with no entry here rejects the driver.
//!
//! An entry's `State` is an honest claim about the function behind it; see
//! `ledger/README.md`. Exports exist because a real driver in the fixture
//! corpus imports them, not to fill out the Windows export list.

use crate::{io, ke, ldr, mm, rtl};

#[derive(Clone, Copy, PartialEq, Eq)]
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
    export!(Implemented, mm::pool::ExAllocatePoolWithTag),
    export!(Implemented, mm::pool::ExFreePoolWithTag),
    export!(Partial, io::mdl::IoAllocateMdl),
    export!(Implemented, io::device::IoCreateDevice),
    export!(Implemented, io::symlink::IoCreateSymbolicLink),
    export!(Implemented, io::device::IoDeleteDevice),
    export!(Implemented, io::symlink::IoDeleteSymbolicLink),
    export!(Implemented, io::mdl::IoFreeMdl),
    export!(Implemented, io::irp::IofCompleteRequest),
    export!(Partial, ke::kspin::KeAcquireInStackQueuedSpinLock),
    export!(Implemented, ke::kspin::KeAcquireSpinLockAtDpcLevel),
    export!(Implemented, ke::kspin::KeAcquireSpinLockRaiseToDpc),
    export!(Implemented, ke::kspin::KeGetCurrentIrql),
    export!(Implemented, ke::kspin::KeInitializeSpinLock),
    export!(Implemented, ke::timer::KeCancelTimer),
    export!(Implemented, ke::dpc::KeInitializeDpc),
    export!(Implemented, ke::timer::KeInitializeTimer),
    export!(Implemented, ke::dpc::KeInsertQueueDpc),
    export!(Implemented, ke::kspin::KeLowerIrql),
    export!(Implemented, ke::time::KeQueryPerformanceCounter),
    export!(Implemented, ke::time::KeQueryTimeIncrement),
    export!(Implemented, ke::kspin::KeReleaseInStackQueuedSpinLock),
    export!(Implemented, ke::kspin::KeReleaseSpinLock),
    export!(Implemented, ke::kspin::KeReleaseSpinLockFromDpcLevel),
    export!(Implemented, ke::timer::KeReadStateTimer),
    export!(Implemented, ke::dpc::KeRemoveQueueDpc),
    export!(Implemented, ke::timer::KeSetTimer),
    export!(Implemented, ke::timer::KeSetTimerEx),
    export!(Implemented, ke::time::KeStallExecutionProcessor),
    export!(Implemented, ke::kspin::KeTryToAcquireSpinLockAtDpcLevel),
    export!(Implemented, ke::kspin::KfLowerIrql),
    export!(Implemented, ke::kspin::KfRaiseIrql),
    export!(Partial, io::mdl::MmMapLockedPagesSpecifyCache),
    export!(Implemented, ldr::MmPageEntireDriver),
    export!(Partial, io::mdl::MmProbeAndLockPages),
    export!(Implemented, io::mdl::MmUnlockPages),
    export!(Partial, ke::seh::ProbeForRead),
    export!(Implemented, rtl::RtlInitUnicodeString),
    export!(Traps, ke::seh::__C_specific_handler),
];

/// The address a driver's import of `module!name` binds to.
///
/// `hal.dll` is another name for the kernel here. In the Windows build NK
/// follows, every export of `hal.dll` forwards to `ntoskrnl.exe`, and
/// which of the two a driver names for a routine differs by architecture.
pub fn resolve(module: &[u8], name: &[u8]) -> Option<u64> {
    let module: &[u8] = if module.eq_ignore_ascii_case(b"hal.dll") {
        NT.as_bytes()
    } else {
        module
    };
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
