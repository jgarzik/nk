//! What the kernel exports to drivers.
//!
//! One table drives three things: the import binder resolves names against
//! it, the boot log prints it, and the compatibility ledger is generated
//! from that log. An import with no entry here rejects the driver.
//!
//! An entry's `State` is an honest claim about the function behind it; see
//! `ledger/README.md`. Exports exist because a real driver in the fixture
//! corpus imports them, not to fill out the Windows export list.

use crate::{ex, io, ke, ldr, mm, ob, ps, rtl, se};

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

/// A variable, not a function: the import is bound to its address.
macro_rules! export_variable {
    ($state:ident, $name:literal, $variable:path) => {
        Export {
            module: NT,
            name: $name,
            addr: $variable.address(),
            state: State::$state,
        }
    };
}

/// A function entered through an assembly stub, exported under the
/// name drivers import, which is not the stub's.
macro_rules! export_entry {
    ($state:ident, $name:literal, $entry:path) => {
        Export {
            module: NT,
            name: $name,
            addr: $entry as *const (),
            state: State::$state,
        }
    };
}

static EXPORTS: &[Export] = &[
    export!(Implemented, mm::pool::ExAllocatePoolWithQuotaTag),
    export!(Implemented, mm::pool::ExAllocatePoolWithTag),
    export_variable!(
        Implemented,
        "ExEventObjectType",
        ob::object::ExEventObjectType
    ),
    export!(Implemented, mm::pool::ExFreePoolWithTag),
    export!(Partial, io::mdl::IoAllocateMdl),
    export!(Implemented, io::device::IoCreateDevice),
    export!(Implemented, io::symlink::IoCreateSymbolicLink),
    export!(Implemented, io::device::IoDeleteDevice),
    export!(Implemented, io::symlink::IoDeleteSymbolicLink),
    export!(Implemented, io::remlock::IoAcquireRemoveLockEx),
    export!(Implemented, io::mdl::IoFreeMdl),
    export!(Implemented, io::remlock::IoInitializeRemoveLockEx),
    export!(Implemented, io::remlock::IoReleaseRemoveLockAndWaitEx),
    export!(Implemented, io::remlock::IoReleaseRemoveLockEx),
    export!(Implemented, io::irp::IoReleaseCancelSpinLock),
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
    export!(Implemented, ke::wait::KeSetEvent),
    export!(Implemented, ke::dpc::KeRemoveQueueDpc),
    export!(Implemented, ke::timer::KeSetTimer),
    export!(Implemented, ke::timer::KeSetTimerEx),
    export!(Implemented, ke::time::KeStallExecutionProcessor),
    export!(Implemented, ke::kspin::KeTryToAcquireSpinLockAtDpcLevel),
    export!(Implemented, ke::kspin::KfLowerIrql),
    export!(Implemented, ke::kspin::KfRaiseIrql),
    export!(Implemented, MmGetSystemRoutineAddress),
    export!(Partial, io::mdl::MmMapLockedPagesSpecifyCache),
    export!(Implemented, ldr::MmPageEntireDriver),
    export!(Partial, io::mdl::MmProbeAndLockPages),
    export!(Implemented, io::mdl::MmUnlockPages),
    export!(Implemented, ob::handle::ObReferenceObjectByHandle),
    export!(Implemented, ob::object::ObfDereferenceObject),
    export!(Partial, ke::seh::ProbeForRead),
    export!(Implemented, rtl::RtlGetVersion),
    export!(Implemented, rtl::RtlInitUnicodeString),
    export!(Traps, ke::seh::__C_specific_handler),
    export!(Implemented, ke::mutex::ExAcquireFastMutex),
    export!(Implemented, ke::mutex::ExAcquireFastMutexUnsafe),
    export!(Implemented, ex::work::ExQueueWorkItem),
    export!(Implemented, ke::mutex::ExReleaseFastMutex),
    export!(Implemented, ke::mutex::ExReleaseFastMutexUnsafe),
    export!(Implemented, ke::mutex::ExTryToAcquireFastMutex),
    export!(Implemented, ex::work::IoAllocateWorkItem),
    export!(Implemented, ex::work::IoFreeWorkItem),
    export!(Implemented, ex::work::IoQueueWorkItem),
    export!(Implemented, ke::mutex::KeAreApcsDisabled),
    export!(Implemented, ke::wait::KeDelayExecutionThread),
    export!(Implemented, ke::mutex::KeEnterCriticalRegion),
    export!(Implemented, ps::KeGetCurrentThread),
    export!(Implemented, ke::wait::KeInitializeEvent),
    export!(Implemented, ke::mutex::KeInitializeMutex),
    export!(Implemented, ke::wait::KeInitializeSemaphore),
    export!(Implemented, ke::mutex::KeLeaveCriticalRegion),
    export!(Implemented, ke::wait::KeReadStateEvent),
    export!(Implemented, ke::mutex::KeReadStateMutex),
    export!(Implemented, ke::wait::KeReadStateSemaphore),
    export!(Implemented, ke::mutex::KeReleaseMutex),
    export!(Implemented, ke::wait::KeReleaseSemaphore),
    export!(Implemented, ke::wait::KeResetEvent),
    export!(Implemented, ke::wait::KeWaitForMultipleObjects),
    export!(Implemented, ke::wait::KeWaitForSingleObject),
    export!(Implemented, ps::PsCreateSystemThread),
    export!(Implemented, ps::PsTerminateSystemThread),
    export_variable!(Implemented, "PsThreadType", ob::object::PsThreadType),
    export!(Implemented, ps::ZwClose),
    export_entry!(Implemented, "DbgPrint", rtl::print::nk_variadic_DbgPrint),
    export!(Implemented, rtl::print::RtlFreeUnicodeString),
    export_entry!(
        Implemented,
        "_snwprintf",
        rtl::print::nk_variadic__snwprintf
    ),
    export!(Implemented, rtl::print::_wcsnicmp),
    export!(Implemented, rtl::print::wcschr),
    export!(Implemented, se::RtlAbsoluteToSelfRelativeSD),
    export!(Implemented, se::RtlAddAccessAllowedAce),
    export!(Implemented, se::RtlCreateSecurityDescriptor),
    export!(Implemented, se::RtlGetDaclSecurityDescriptor),
    export!(Implemented, se::RtlGetGroupSecurityDescriptor),
    export!(Implemented, se::RtlGetOwnerSecurityDescriptor),
    export!(Implemented, se::RtlGetSaclSecurityDescriptor),
    export!(Implemented, se::RtlLengthSecurityDescriptor),
    export!(Implemented, se::RtlLengthSid),
    export!(Implemented, se::RtlSetDaclSecurityDescriptor),
    export!(Implemented, se::SeCaptureSecurityDescriptor),
    export_variable!(Implemented, "SeExports", se::SeExports),
    export_variable!(
        Implemented,
        "IoDeviceObjectType",
        ob::object::IoDeviceObjectType
    ),
    export!(Implemented, ob::handle::ObOpenObjectByPointer),
    export!(Implemented, se::ZwSetSecurityObject),
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

/// [`MmGetSystemRoutineAddress`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmgetsystemroutineaddress):
/// the address of a routine the kernel or the HAL exports, by name, or
/// null if there is none of that name. It is how a driver asks whether a
/// routine exists before relying on it.
///
/// # Safety
/// `name` points to a valid counted string.
#[allow(non_snake_case)]
pub unsafe extern "C" fn MmGetSystemRoutineAddress(
    name: *const nk_ntabi::io::UNICODE_STRING,
) -> *mut core::ffi::c_void {
    // SAFETY: per the contract.
    let wide = unsafe { rtl::copy_unicode(name) };
    // Export names are ASCII; a name that is not cannot match one.
    let mut ascii = [0u8; 128];
    if wide.len() > ascii.len() || wide.iter().any(|&unit| unit > 0x7F) {
        return core::ptr::null_mut();
    }
    for (byte, &unit) in ascii.iter_mut().zip(&wide) {
        *byte = unit as u8;
    }
    resolve(NT.as_bytes(), &ascii[..wide.len()])
        .map_or(core::ptr::null_mut(), |addr| addr as *mut core::ffi::c_void)
}

/// Print the table for the ledger: `NK-EXPORT <module> <name> <state>`.
pub fn print_all() {
    for e in EXPORTS {
        kprintln!("NK-EXPORT {} {} {}", e.module, e.name, e.state.name());
    }
}
