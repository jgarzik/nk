//! What the kernel exports to drivers.
//!
//! One table drives three things: the import binder resolves names against
//! it, the boot log prints it, and the compatibility ledger is generated
//! from that log. An import with no entry here rejects the driver.
//!
//! An entry's `State` is an honest claim about the function behind it; see
//! `ledger/README.md`. Exports exist because a real driver in the fixture
//! corpus imports them, not to fill out the Windows export list.

use crate::{arch, cm, etw, ex, io, ke, ldr, mm, ob, ps, rtl, se};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Does what the Windows routine does, for what the kernel supports.
    Implemented,
    /// Works for the subset the proof drivers use; gaps are documented at
    /// the function.
    Partial,
    /// Present so the driver loads; bugchecks by name if ever called.
    #[allow(
        dead_code,
        reason = "the ledger's vocabulary; nothing is bound this way at present"
    )]
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
    export!(Implemented, mm::pool::ExAllocatePoolWithTagPriority),
    export!(Implemented, etw::EtwRegister),
    export!(Implemented, etw::EtwRegisterClassicProvider),
    export!(Implemented, etw::EtwSetInformation),
    export!(Implemented, etw::EtwUnregister),
    export!(Implemented, etw::EtwWriteTransfer),
    export!(Implemented, etw::WmiQueryTraceInformation),
    export!(Implemented, etw::WmiTraceMessage),
    export_variable!(
        Implemented,
        "ExEventObjectType",
        ob::object::ExEventObjectType
    ),
    export!(Implemented, mm::pool::ExFreePool),
    export!(Implemented, mm::pool::ExFreePoolWithTag),
    export!(Partial, io::mdl::IoAllocateMdl),
    export!(Implemented, io::device::IoCreateDevice),
    export!(Implemented, io::symlink::IoCreateSymbolicLink),
    export!(Implemented, io::device::IoDeleteDevice),
    export!(Implemented, io::symlink::IoDeleteSymbolicLink),
    export!(Implemented, io::remlock::IoAcquireRemoveLockEx),
    export!(Implemented, io::wmi::IoWMIDeviceObjectToProviderId),
    export!(Partial, io::wmi::IoWMIRegistrationControl),
    export!(Implemented, io::wmi::IoWMIWriteEvent),
    export!(Implemented, io::irp::IoAllocateIrp),
    export!(Implemented, io::irp::IoFreeIrp),
    export!(Implemented, io::mdl::IoFreeMdl),
    export!(Implemented, io::file::IoGetDeviceObjectPointer),
    export!(Implemented, io::remlock::IoInitializeRemoveLockEx),
    export!(Implemented, io::remlock::IoReleaseRemoveLockAndWaitEx),
    export!(Implemented, io::remlock::IoReleaseRemoveLockEx),
    export!(Implemented, io::irp::IoReleaseCancelSpinLock),
    export!(Implemented, io::irp::IofCallDriver),
    export!(Implemented, io::irp::IofCompleteRequest),
    export!(Partial, ke::kspin::KeAcquireInStackQueuedSpinLock),
    export!(Implemented, ke::kspin::KeAcquireSpinLockAtDpcLevel),
    export!(Implemented, ke::kspin::KeAcquireSpinLockRaiseToDpc),
    export!(Implemented, ke::bugcheck::KeBugCheckEx),
    export!(
        Implemented,
        ke::bugcheck::KeDeregisterBugCheckReasonCallback
    ),
    export!(Implemented, ke::kspin::KeGetCurrentIrql),
    export!(Implemented, ke::kspin::KeInitializeSpinLock),
    export!(Implemented, ke::timer::KeCancelTimer),
    export!(Implemented, ke::dpc::KeInitializeDpc),
    export!(Implemented, ke::timer::KeInitializeTimer),
    export!(Implemented, ke::dpc::KeInsertQueueDpc),
    export!(Implemented, ke::kspin::KeLowerIrql),
    export!(Implemented, ke::smp::KeQueryActiveProcessorCountEx),
    export!(Implemented, ke::time::KeQueryPerformanceCounter),
    export!(Implemented, ke::time::KeQueryTimeIncrement),
    export!(Implemented, ke::bugcheck::KeRegisterBugCheckReasonCallback),
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
    export_variable!(Implemented, "KiBugCheckData", ke::bugcheck::KiBugCheckData),
    export!(Implemented, MmGetSystemRoutineAddress),
    export!(Implemented, ex::sysinfo::MmIsDriverVerifying),
    export!(Partial, io::mdl::MmMapLockedPagesSpecifyCache),
    export!(Implemented, ldr::MmPageEntireDriver),
    export_entry!(
        Partial,
        "MmProbeAndLockPages",
        arch::seh::nk_entry_MmProbeAndLockPages
    ),
    export!(Implemented, io::mdl::MmUnlockPages),
    export!(Implemented, ob::security::ObDereferenceSecurityDescriptor),
    export!(Implemented, ob::security::ObLogSecurityDescriptor),
    export!(Implemented, ob::handle::ObReferenceObjectByHandle),
    export!(Implemented, ob::handle::ObReferenceObjectByHandleWithTag),
    export!(Implemented, ob::security::ObReferenceSecurityDescriptor),
    export!(Implemented, ob::object::ObfDereferenceObject),
    export!(Implemented, ob::object::ObfDereferenceObjectWithTag),
    export!(Implemented, ob::object::ObfReferenceObject),
    export!(Implemented, ob::object::ObfReferenceObjectWithTag),
    export_entry!(
        Implemented,
        "ProbeForRead",
        arch::seh::nk_entry_ProbeForRead
    ),
    export!(Implemented, rtl::RtlGetVersion),
    export!(Implemented, ex::sysinfo::RtlQueryModuleInformation),
    export!(Implemented, rtl::RtlInitUnicodeString),
    export!(Implemented, ke::seh::__C_specific_handler),
    export!(Implemented, ke::mutex::ExAcquireFastMutex),
    export!(Implemented, ke::mutex::ExAcquireFastMutexUnsafe),
    export!(Implemented, ex::pushlock::ExAcquirePushLockExclusiveEx),
    export!(Implemented, ex::pushlock::ExAcquirePushLockSharedEx),
    export!(Implemented, ex::resource::ExAcquireResourceExclusiveLite),
    export!(Implemented, ex::resource::ExAcquireResourceSharedLite),
    export!(Implemented, ex::resource::ExAcquireSharedStarveExclusive),
    export!(Implemented, ex::resource::ExAcquireSharedWaitForExclusive),
    export!(Partial, ex::timer::ExAllocateTimer),
    export!(Implemented, ex::timer::ExCancelTimer),
    export!(Implemented, ex::resource::ExConvertExclusiveToSharedLite),
    export!(Implemented, ex::lookaside::ExDeleteNPagedLookasideList),
    export!(Implemented, ex::lookaside::ExDeletePagedLookasideList),
    export!(Implemented, ex::resource::ExDeleteResourceLite),
    export!(Implemented, ex::timer::ExDeleteTimer),
    export!(Implemented, ex::resource::ExGetExclusiveWaiterCount),
    export!(Implemented, ex::resource::ExGetSharedWaiterCount),
    export!(Implemented, ex::lookaside::ExInitializeNPagedLookasideList),
    export!(Implemented, ex::lookaside::ExInitializePagedLookasideList),
    export!(Implemented, ex::resource::ExInitializeResourceLite),
    export!(Implemented, ex::resource::ExIsResourceAcquiredExclusiveLite),
    export!(Implemented, ex::resource::ExIsResourceAcquiredSharedLite),
    export!(Implemented, ex::slist::ExQueryDepthSList),
    export!(Implemented, ex::work::ExQueueWorkItem),
    export!(Implemented, ex::resource::ExReinitializeResourceLite),
    export!(Implemented, ex::pushlock::ExReleasePushLockEx),
    export!(Implemented, ex::pushlock::ExReleasePushLockExclusiveEx),
    export!(Implemented, ex::pushlock::ExReleasePushLockSharedEx),
    export!(Implemented, ex::resource::ExReleaseResourceForThreadLite),
    export!(Implemented, ex::resource::ExReleaseResourceLite),
    export!(Partial, ex::timer::ExSetTimer),
    export!(Implemented, ex::pushlock::ExTryAcquirePushLockExclusiveEx),
    export!(Implemented, ex::uuid::ExUuidCreate),
    export!(Implemented, ex::slist::ExpInterlockedFlushSList),
    export!(Implemented, ex::slist::ExpInterlockedPopEntrySList),
    export!(Implemented, ex::slist::ExpInterlockedPushEntrySList),
    export!(Implemented, ex::slist::InitializeSListHead),
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
    export!(Implemented, ps::process::IoGetCurrentProcess),
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
    export!(Implemented, ex::sysinfo::DbgkWerCaptureLiveKernelDump),
    export!(Partial, ex::sysinfo::NtQuerySystemInformation),
    export!(Implemented, ps::PsCreateSystemThread),
    export!(Implemented, ex::sysinfo::PsGetVersion),
    export!(Implemented, ps::silo::PsAllocSiloContextSlot),
    export!(Implemented, ps::silo::PsAttachSiloToCurrentThread),
    export!(Implemented, ps::process::PsChargeProcessPagedPoolQuota),
    export!(Implemented, ps::silo::PsCreateSiloContext),
    export!(Implemented, ps::process::PsDereferencePrimaryToken),
    export!(Implemented, ps::silo::PsDereferenceSiloContext),
    export!(Implemented, ps::silo::PsDetachSiloFromCurrentThread),
    export!(Implemented, ps::silo::PsFreeSiloContextSlot),
    export!(Implemented, ps::process::PsGetCurrentProcess),
    export!(Implemented, ps::process::PsGetCurrentProcessId),
    export!(Implemented, ps::silo::PsGetCurrentServerSilo),
    export!(Implemented, ps::silo::PsGetCurrentSilo),
    export!(Implemented, ps::process::PsGetCurrentThreadId),
    export!(Implemented, ps::silo::PsGetJobSilo),
    export!(Implemented, ps::silo::PsGetPermanentSiloContext),
    export!(Implemented, ps::process::PsGetProcessId),
    export!(Implemented, ps::process::PsGetProcessSessionId),
    export!(Implemented, ps::silo::PsGetSiloMonitorContextSlot),
    export!(Implemented, ps::process::PsGetThreadProcessId),
    export!(Implemented, ps::process::PsGetThreadSessionId),
    export_variable!(
        Implemented,
        "PsInitialSystemProcess",
        ps::process::PsInitialSystemProcess
    ),
    export!(Implemented, ps::silo::PsInsertPermanentSiloContext),
    export!(Implemented, ps::silo::PsIsHostSilo),
    export_variable!(Implemented, "PsJobType", ob::object::PsJobType),
    export!(Implemented, ps::process::PsReferencePrimaryToken),
    export!(Implemented, ps::silo::PsRegisterSiloMonitor),
    export!(Implemented, ps::process::PsReturnProcessPagedPoolQuota),
    export!(Implemented, ps::silo::PsStartSiloMonitor),
    export!(Implemented, ps::PsTerminateSystemThread),
    export_variable!(Implemented, "PsThreadType", ob::object::PsThreadType),
    export!(Implemented, ps::silo::PsUnregisterSiloMonitor),
    export!(Implemented, ps::ZwAlertThread),
    export!(Implemented, ps::ZwClose),
    export_entry!(
        Partial,
        "ZwQuerySystemInformation",
        ex::sysinfo::NtQuerySystemInformation
    ),
    export!(Partial, ob::event::ZwCreateEvent),
    export_entry!(Implemented, "DbgPrint", rtl::print::nk_variadic_DbgPrint),
    export!(Implemented, rtl::name::FsRtlIsNameInExpression),
    export_variable!(
        Implemented,
        "FsRtlLegalAnsiCharacterArray",
        rtl::name::FsRtlLegalAnsiCharacterArray
    ),
    export!(Implemented, rtl::string::RtlCompareMemory),
    export!(Implemented, rtl::prefix::RtlFindUnicodePrefix),
    export!(Implemented, rtl::string::RtlFreeAnsiString),
    export!(Implemented, rtl::print::RtlFreeUnicodeString),
    export!(Implemented, rtl::prefix::RtlInitializeUnicodePrefix),
    export!(Implemented, rtl::prefix::RtlInsertUnicodePrefix),
    export!(Implemented, rtl::string::RtlMultiByteToUnicodeN),
    export!(Implemented, rtl::string::RtlPrefixUnicodeString),
    export!(Implemented, rtl::prefix::RtlRemoveUnicodePrefix),
    export!(Implemented, rtl::string::RtlStringFromGUID),
    export!(Implemented, rtl::string::RtlUnicodeStringToAnsiString),
    export!(Implemented, rtl::string::RtlUnicodeToMultiByteN),
    export!(Implemented, rtl::string::RtlUpcaseUnicodeChar),
    export!(Implemented, rtl::string::RtlUpcaseUnicodeString),
    export_entry!(
        Implemented,
        "_snwprintf",
        rtl::print::nk_variadic__snwprintf
    ),
    export!(Implemented, rtl::crt::_stricmp),
    export!(Implemented, rtl::print::_vsnwprintf),
    export!(Implemented, rtl::crt::_wcsicmp),
    export!(Implemented, rtl::print::_wcsnicmp),
    export!(Implemented, rtl::crt::strncmp),
    export!(Implemented, rtl::crt::strrchr),
    export!(Implemented, rtl::print::wcschr),
    export!(Implemented, rtl::crt::wcsstr),
    export!(Implemented, se::RtlAbsoluteToSelfRelativeSD),
    export!(Implemented, se::RtlAddAccessAllowedAce),
    export!(Implemented, se::sid::RtlConvertSidToUnicodeString),
    export!(Implemented, se::sid::RtlCopySid),
    export!(Implemented, se::sid::RtlCreateAcl),
    export!(Implemented, se::RtlCreateSecurityDescriptor),
    export!(Implemented, se::sid::RtlEqualSid),
    export!(Implemented, se::sid::RtlGetAppContainerParent),
    export!(Implemented, se::sid::RtlGetAppContainerSidType),
    export!(Implemented, se::RtlGetDaclSecurityDescriptor),
    export!(Implemented, se::RtlGetGroupSecurityDescriptor),
    export!(Implemented, se::RtlGetOwnerSecurityDescriptor),
    export!(Implemented, se::RtlGetSaclSecurityDescriptor),
    export!(Implemented, se::sid::RtlInitializeSid),
    export!(Implemented, se::sid::RtlLengthRequiredSid),
    export!(Implemented, se::RtlLengthSecurityDescriptor),
    export!(Implemented, se::RtlLengthSid),
    export!(Implemented, se::RtlSetDaclSecurityDescriptor),
    export!(Implemented, se::RtlSetGroupSecurityDescriptor),
    export!(Implemented, se::RtlSetOwnerSecurityDescriptor),
    export!(Implemented, se::sid::RtlSubAuthorityCountSid),
    export!(Implemented, se::sid::RtlSubAuthoritySid),
    export!(Implemented, se::RtlValidSecurityDescriptor),
    export!(Implemented, se::sid::RtlValidSid),
    export!(Implemented, se::access::SeAccessCheck),
    export!(Implemented, se::access::SeAppendPrivileges),
    export!(Implemented, se::descriptor::SeAssignSecurity),
    export!(Implemented, se::SeCaptureSecurityDescriptor),
    export!(Implemented, se::token::SeCaptureSubjectContext),
    export!(Implemented, se::token::SeCreateAccessState),
    export!(Implemented, se::descriptor::SeDeassignSecurity),
    export!(Implemented, se::token::SeDeleteAccessState),
    export_variable!(Implemented, "SeExports", se::SeExports),
    export!(Implemented, se::access::SeFreePrivileges),
    export!(Implemented, se::token::SeLockSubjectContext),
    export!(Implemented, se::access::SePrivilegeCheck),
    export!(Implemented, se::token::SeQueryInformationToken),
    export!(Implemented, se::descriptor::SeQuerySecurityDescriptorInfo),
    export!(Implemented, se::token::SeReleaseSubjectContext),
    export!(Implemented, se::descriptor::SeSetSecurityDescriptorInfo),
    export!(Implemented, se::access::SeSinglePrivilegeCheck),
    export!(Implemented, se::token::SeTokenType),
    export!(Implemented, se::token::SeUnlockSubjectContext),
    export_variable!(
        Implemented,
        "IoDeviceObjectType",
        ob::object::IoDeviceObjectType
    ),
    export!(Implemented, ob::handle::ObOpenObjectByPointer),
    export!(Implemented, se::zwtoken::ZwDuplicateToken),
    export!(Implemented, se::zwtoken::ZwOpenProcessTokenEx),
    export!(Implemented, se::zwtoken::ZwQueryInformationToken),
    export!(Partial, ps::ZwSetInformationThread),
    export!(Implemented, se::ZwSetSecurityObject),
    export!(Implemented, cm::RtlQueryRegistryValues),
    export!(Implemented, cm::RtlQueryRegistryValuesEx),
    export!(Partial, ob::event::ZwWaitForSingleObject),
    export!(Implemented, cm::ZwCreateKey),
    export!(Implemented, cm::ZwDeleteKey),
    export!(Implemented, cm::ZwDeleteValueKey),
    export!(Implemented, cm::ZwEnumerateKey),
    export!(Implemented, cm::ZwEnumerateValueKey),
    export!(Implemented, cm::ZwOpenKey),
    export!(Implemented, cm::ZwQueryKey),
    export!(Implemented, cm::ZwQueryValueKey),
    export!(Implemented, cm::ZwSetValueKey),
    export!(Implemented, io::csq::IoCsqInitialize),
    export!(Implemented, io::csq::IoCsqInsertIrp),
    export!(Implemented, io::csq::IoCsqRemoveNextIrp),
    export!(Implemented, io::csq::IoIsWdmVersionAvailable),
    export!(Implemented, ke::thread::KeSetPriorityThread),
    export!(Implemented, ps::process::KeStackAttachProcess),
    export!(Implemented, ps::process::KeUnstackDetachProcess),
    export_entry!(
        Implemented,
        "ExRaiseStatus",
        arch::seh::nk_entry_ExRaiseStatus
    ),
    export_entry!(
        Implemented,
        "ExRaiseAccessViolation",
        arch::seh::nk_entry_ExRaiseAccessViolation
    ),
    export_entry!(
        Implemented,
        "ExRaiseDatatypeMisalignment",
        arch::seh::nk_entry_ExRaiseDatatypeMisalignment
    ),
    export_entry!(
        Implemented,
        "ProbeForWrite",
        arch::seh::nk_entry_ProbeForWrite
    ),
    export!(Implemented, ke::seh::_local_unwind),
    export_variable!(
        Implemented,
        "MmUserProbeAddress",
        mm::user::MmUserProbeAddress
    ),
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

/// Whether `module` is a name the kernel's own exports go by: an
/// import from any other module is from a driver that exports.
pub fn is_kernel(module: &[u8]) -> bool {
    [NT, "hal.dll"]
        .iter()
        .any(|name| name.as_bytes().eq_ignore_ascii_case(module))
}

/// [`MmGetSystemRoutineAddress`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmgetsystemroutineaddress):
/// the address of a routine the kernel or the HAL exports, by name, or
/// null if there is none of that name. It is how a driver asks whether a
/// routine exists before relying on it.
///
/// A name that is not found is printed, `NK-LOOKUP <name> absent`: the
/// driver takes another path without it and no import table shows the
/// name, so the ledger lists these from the boot log.
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
    let found = if wide.len() > ascii.len() || wide.iter().any(|&unit| unit > 0x7F) {
        None
    } else {
        for (byte, &unit) in ascii.iter_mut().zip(&wide) {
            *byte = unit as u8;
        }
        resolve(NT.as_bytes(), &ascii[..wide.len()])
    };
    match found {
        Some(addr) => addr as *mut core::ffi::c_void,
        None => {
            // One word, whatever the driver passed.
            let name: alloc::string::String = char::decode_utf16(wide.iter().copied())
                .map(|c| c.ok().filter(|c| c.is_ascii_graphic()).unwrap_or('?'))
                .collect();
            kprintln!("NK-LOOKUP {name} absent");
            ABSENT.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            core::ptr::null_mut()
        }
    }
}

/// Names asked for by `MmGetSystemRoutineAddress` and not found.
static ABSENT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// How many look-ups by name have found nothing, so far.
pub fn absent_lookups() -> usize {
    ABSENT.load(core::sync::atomic::Ordering::Relaxed)
}

/// Print the table for the ledger: `NK-EXPORT <module> <name> <state>`.
pub fn print_all() {
    for e in EXPORTS {
        kprintln!("NK-EXPORT {} {} {}", e.module, e.name, e.state.name());
    }
}
