//! Check these definitions against the WDK itself.
//!
//! The nk-fixtures repository builds a probe driver with Microsoft's WDK
//! and publishes the sizes and offsets the compiler produced, one fact per
//! line (`sizeof DEVICE_OBJECT 336`). This test states the same facts from
//! the Rust definitions and compares.
//!
//! The probe tables are fixtures: `target/fixtures/abi-probe.<arch>.txt`.
//! When a table has not been downloaded the test says so on stderr and
//! passes; it never counts an absent table as agreement.

use crate::ex::{
    ERESOURCE, GENERAL_LOOKASIDE, NPAGED_LOOKASIDE_LIST, OWNER_ENTRY, PAGED_LOOKASIDE_LIST,
    SLIST_ENTRY, SLIST_HEADER,
};
use crate::io::*;
use crate::ob::OBJECT_ATTRIBUTES;
use crate::pcr;
use crate::se::{SE_EXPORTS, SECURITY_DESCRIPTOR};
use core::mem::{offset_of, size_of};
use std::collections::BTreeMap;
use std::path::PathBuf;

/// NK's side: fact name (as the probe spells it) and value.
fn nk_facts() -> Vec<(&'static str, usize)> {
    macro_rules! sz {
        ($t:ty) => {
            (concat!("sizeof ", stringify!($t)), size_of::<$t>())
        };
    }
    // `off!(TYPE, RustField)` or `off!(TYPE, RustField, "Windows.Member")`
    // where the Rust field flattens a union or nested struct.
    macro_rules! off {
        ($t:ty, $f:ident) => {
            (
                concat!("offsetof ", stringify!($t), " ", stringify!($f)),
                offset_of!($t, $f),
            )
        };
        ($t:ty, $f:ident, $win:literal) => {
            (
                concat!("offsetof ", stringify!($t), " ", $win),
                offset_of!($t, $f),
            )
        };
    }
    vec![
        sz!(UNICODE_STRING),
        off!(UNICODE_STRING, MaximumLength),
        off!(UNICODE_STRING, Buffer),
        sz!(LIST_ENTRY),
        sz!(IO_STATUS_BLOCK),
        off!(IO_STATUS_BLOCK, Information),
        sz!(DISPATCHER_HEADER),
        off!(DISPATCHER_HEADER, SignalState),
        off!(DISPATCHER_HEADER, WaitListHead),
        sz!(KEVENT),
        sz!(KDEVICE_QUEUE),
        sz!(KDPC),
        sz!(WAIT_CONTEXT_BLOCK),
        sz!(DRIVER_EXTENSION),
        off!(DRIVER_EXTENSION, AddDevice),
        off!(DRIVER_EXTENSION, ServiceKeyName),
        sz!(DRIVER_OBJECT),
        off!(DRIVER_OBJECT, DeviceObject),
        off!(DRIVER_OBJECT, Flags),
        off!(DRIVER_OBJECT, DriverStart),
        off!(DRIVER_OBJECT, DriverSize),
        off!(DRIVER_OBJECT, DriverExtension),
        off!(DRIVER_OBJECT, DriverName),
        off!(DRIVER_OBJECT, FastIoDispatch),
        off!(DRIVER_OBJECT, DriverInit),
        off!(DRIVER_OBJECT, DriverStartIo),
        off!(DRIVER_OBJECT, DriverUnload),
        off!(DRIVER_OBJECT, MajorFunction),
        sz!(DEVICE_OBJECT),
        off!(DEVICE_OBJECT, ReferenceCount),
        off!(DEVICE_OBJECT, DriverObject),
        off!(DEVICE_OBJECT, NextDevice),
        off!(DEVICE_OBJECT, AttachedDevice),
        off!(DEVICE_OBJECT, CurrentIrp),
        off!(DEVICE_OBJECT, Flags),
        off!(DEVICE_OBJECT, Characteristics),
        off!(DEVICE_OBJECT, DeviceExtension),
        off!(DEVICE_OBJECT, DeviceType),
        off!(DEVICE_OBJECT, StackSize),
        off!(DEVICE_OBJECT, Queue),
        off!(DEVICE_OBJECT, AlignmentRequirement),
        off!(DEVICE_OBJECT, DeviceQueue),
        off!(DEVICE_OBJECT, Dpc),
        off!(DEVICE_OBJECT, ActiveThreadCount),
        off!(DEVICE_OBJECT, SecurityDescriptor),
        off!(DEVICE_OBJECT, DeviceLock),
        off!(DEVICE_OBJECT, SectorSize),
        off!(DEVICE_OBJECT, DeviceObjectExtension),
        off!(DEVICE_OBJECT, Reserved),
        sz!(FILE_OBJECT),
        off!(FILE_OBJECT, DeviceObject),
        off!(FILE_OBJECT, FsContext),
        off!(FILE_OBJECT, PrivateCacheMap),
        off!(FILE_OBJECT, FinalStatus),
        off!(FILE_OBJECT, RelatedFileObject),
        off!(FILE_OBJECT, Flags),
        off!(FILE_OBJECT, FileName),
        off!(FILE_OBJECT, CurrentByteOffset),
        off!(FILE_OBJECT, Lock),
        off!(FILE_OBJECT, Event),
        off!(FILE_OBJECT, CompletionContext),
        off!(FILE_OBJECT, IrpList),
        off!(FILE_OBJECT, FileObjectExtension),
        sz!(IRP),
        off!(IRP, MdlAddress),
        off!(IRP, Flags),
        off!(IRP, SystemBuffer, "AssociatedIrp"),
        off!(IRP, ThreadListEntry),
        off!(IRP, IoStatus),
        off!(IRP, RequestorMode),
        off!(IRP, PendingReturned),
        off!(IRP, StackCount),
        off!(IRP, CurrentLocation),
        off!(IRP, Cancel),
        off!(IRP, UserIosb),
        off!(IRP, UserEvent),
        off!(IRP, Overlay),
        off!(IRP, CancelRoutine),
        off!(IRP, UserBuffer),
        off!(IRP, DriverContext, "Tail"),
        off!(IRP, DriverContext, "Tail.Overlay.DriverContext"),
        off!(IRP, Thread, "Tail.Overlay.Thread"),
        off!(IRP, ListEntry, "Tail.Overlay.ListEntry"),
        off!(
            IRP,
            CurrentStackLocation,
            "Tail.Overlay.CurrentStackLocation"
        ),
        off!(IRP, OriginalFileObject, "Tail.Overlay.OriginalFileObject"),
        sz!(IO_STACK_LOCATION),
        off!(IO_STACK_LOCATION, Control),
        off!(IO_STACK_LOCATION, Parameters),
        off!(IO_STACK_LOCATION, DeviceObject),
        off!(IO_STACK_LOCATION, FileObject),
        off!(IO_STACK_LOCATION, CompletionRoutine),
        off!(IO_STACK_LOCATION, Context),
        sz!(IO_SECURITY_CONTEXT),
        off!(IO_SECURITY_CONTEXT, DesiredAccess),
        sz!(MDL),
        off!(MDL, Size),
        off!(MDL, MdlFlags),
        off!(MDL, Process),
        off!(MDL, MappedSystemVa),
        off!(MDL, StartVa),
        off!(MDL, ByteCount),
        off!(MDL, ByteOffset),
        // `Parameters` members, as the slot each lands in (8 bytes apart
        // from the start of the stack location's Parameters at +8).
        ("offsetof IO_STACK_LOCATION Parameters.Read.Length", 8),
        ("offsetof IO_STACK_LOCATION Parameters.Read.Key", 16),
        ("offsetof IO_STACK_LOCATION Parameters.Read.ByteOffset", 24),
        (
            "offsetof IO_STACK_LOCATION Parameters.DeviceIoControl.OutputBufferLength",
            8,
        ),
        (
            "offsetof IO_STACK_LOCATION Parameters.DeviceIoControl.InputBufferLength",
            16,
        ),
        (
            "offsetof IO_STACK_LOCATION Parameters.DeviceIoControl.IoControlCode",
            24,
        ),
        (
            "offsetof IO_STACK_LOCATION Parameters.DeviceIoControl.Type3InputBuffer",
            32,
        ),
        (
            "offsetof IO_STACK_LOCATION Parameters.Create.SecurityContext",
            8,
        ),
        ("offsetof IO_STACK_LOCATION Parameters.Create.Options", 16),
        ("const IRP_MJ_MAXIMUM_FUNCTION", IRP_MJ_MAXIMUM_FUNCTION),
        ("const DISPATCH_LEVEL", pcr::DISPATCH_LEVEL as usize),
        ("const HIGH_LEVEL", pcr::HIGH_LEVEL as usize),
        ("const PAGE_SIZE", 4096),
        (
            "const MEMORY_ALLOCATION_ALIGNMENT",
            core::mem::align_of::<DEVICE_OBJECT>(),
        ),
        ("const IO_TYPE_DEVICE", IO_TYPE_DEVICE as usize),
        ("const IO_TYPE_DRIVER", IO_TYPE_DRIVER as usize),
        ("const IO_TYPE_FILE", IO_TYPE_FILE as usize),
        ("const IO_TYPE_IRP", IO_TYPE_IRP as usize),
        // Security, named objects, cancel-safe queues.
        sz!(SECURITY_DESCRIPTOR),
        off!(SECURITY_DESCRIPTOR, Control),
        off!(SECURITY_DESCRIPTOR, Owner),
        off!(SECURITY_DESCRIPTOR, Group),
        off!(SECURITY_DESCRIPTOR, Sacl),
        off!(SECURITY_DESCRIPTOR, Dacl),
        // Not the size: the WDK's header has grown past what the
        // Windows 10 kernel publishes.
        off!(SE_EXPORTS, SeNullSid),
        off!(SE_EXPORTS, SeWorldSid),
        off!(SE_EXPORTS, SeLocalSystemSid),
        off!(SE_EXPORTS, SeAliasAdminsSid),
        off!(SE_EXPORTS, SeAnonymousLogonSid),
        off!(SE_EXPORTS, SeUndockPrivilege),
        off!(SE_EXPORTS, SeIUserSid),
        sz!(OBJECT_ATTRIBUTES),
        off!(OBJECT_ATTRIBUTES, ObjectName),
        off!(OBJECT_ATTRIBUTES, Attributes),
        off!(OBJECT_ATTRIBUTES, SecurityDescriptor),
        sz!(IO_CSQ),
        off!(IO_CSQ, CsqInsertIrp),
        off!(IO_CSQ, CsqRemoveIrp),
        off!(IO_CSQ, CsqPeekNextIrp),
        off!(IO_CSQ, CsqAcquireLock),
        off!(IO_CSQ, CsqReleaseLock),
        off!(IO_CSQ, CsqCompleteCanceledIrp),
        off!(IO_CSQ, ReservePointer),
        sz!(IO_CSQ_IRP_CONTEXT),
        off!(IO_CSQ_IRP_CONTEXT, Irp),
        off!(IO_CSQ_IRP_CONTEXT, Csq),
        sz!(SLIST_ENTRY),
        sz!(SLIST_HEADER),
        off!(SLIST_HEADER, Alignment),
        off!(SLIST_HEADER, Region),
        sz!(GENERAL_LOOKASIDE),
        off!(GENERAL_LOOKASIDE, ListHead),
        off!(GENERAL_LOOKASIDE, Depth),
        off!(GENERAL_LOOKASIDE, MaximumDepth),
        off!(GENERAL_LOOKASIDE, TotalAllocates),
        off!(GENERAL_LOOKASIDE, AllocateMisses),
        off!(GENERAL_LOOKASIDE, TotalFrees),
        off!(GENERAL_LOOKASIDE, FreeMisses),
        off!(GENERAL_LOOKASIDE, Type),
        off!(GENERAL_LOOKASIDE, Tag),
        off!(GENERAL_LOOKASIDE, Size),
        off!(GENERAL_LOOKASIDE, Allocate),
        off!(GENERAL_LOOKASIDE, Free),
        off!(GENERAL_LOOKASIDE, ListEntry),
        off!(GENERAL_LOOKASIDE, LastTotalAllocates),
        off!(GENERAL_LOOKASIDE, LastAllocateMisses),
        off!(GENERAL_LOOKASIDE, Future),
        sz!(PAGED_LOOKASIDE_LIST),
        off!(PAGED_LOOKASIDE_LIST, L),
        sz!(NPAGED_LOOKASIDE_LIST),
        off!(NPAGED_LOOKASIDE_LIST, L),
        sz!(OWNER_ENTRY),
        off!(OWNER_ENTRY, OwnerThread),
        off!(OWNER_ENTRY, Bits, "TableSize"),
        sz!(ERESOURCE),
        off!(ERESOURCE, SystemResourcesList),
        off!(ERESOURCE, OwnerTable),
        off!(ERESOURCE, ActiveCount),
        off!(ERESOURCE, Flag),
        off!(ERESOURCE, SharedWaiters),
        off!(ERESOURCE, ExclusiveWaiters),
        off!(ERESOURCE, OwnerEntry),
        off!(ERESOURCE, ActiveEntries),
        off!(ERESOURCE, ContentionCount),
        off!(ERESOURCE, NumberOfSharedWaiters),
        off!(ERESOURCE, NumberOfExclusiveWaiters),
        off!(ERESOURCE, Address),
        off!(ERESOURCE, SpinLock),
    ]
}

/// x86-64 only: the public part of the KPCR. The header's KPCR stops
/// short of the embedded KPRCB, so the probe cannot state where the PRCB
/// or the current-thread slot are; those stay documented, not probed.
fn nk_facts_x64() -> Vec<(&'static str, usize)> {
    vec![
        ("offsetof KPCR Self", pcr::X86_64.self_ptr),
        ("offsetof KPCR CurrentPrcb", pcr::X86_64.current_prcb),
    ]
}

/// The exception structures both architectures share.
fn seh_facts() -> Vec<(&'static str, usize)> {
    use crate::seh::*;
    vec![
        ("sizeof EXCEPTION_RECORD", size_of::<EXCEPTION_RECORD>()),
        (
            "offsetof EXCEPTION_RECORD ExceptionFlags",
            offset_of!(EXCEPTION_RECORD, ExceptionFlags),
        ),
        (
            "offsetof EXCEPTION_RECORD ExceptionRecord",
            offset_of!(EXCEPTION_RECORD, ExceptionRecord),
        ),
        (
            "offsetof EXCEPTION_RECORD ExceptionAddress",
            offset_of!(EXCEPTION_RECORD, ExceptionAddress),
        ),
        (
            "offsetof EXCEPTION_RECORD NumberParameters",
            offset_of!(EXCEPTION_RECORD, NumberParameters),
        ),
        (
            "offsetof EXCEPTION_RECORD ExceptionInformation",
            offset_of!(EXCEPTION_RECORD, ExceptionInformation),
        ),
        ("sizeof EXCEPTION_POINTERS", size_of::<EXCEPTION_POINTERS>()),
        (
            "offsetof EXCEPTION_POINTERS ContextRecord",
            offset_of!(EXCEPTION_POINTERS, ContextRecord),
        ),
        // A scope table is a count and then records of this size.
        ("offsetof SCOPE_TABLE ScopeRecord", size_of::<u32>()),
        (
            "offsetof SCOPE_TABLE ScopeRecord[0].EndAddress",
            4 + offset_of!(SCOPE_RECORD, EndAddress),
        ),
        (
            "offsetof SCOPE_TABLE ScopeRecord[0].HandlerAddress",
            4 + offset_of!(SCOPE_RECORD, HandlerAddress),
        ),
        (
            "offsetof SCOPE_TABLE ScopeRecord[0].JumpTarget",
            4 + offset_of!(SCOPE_RECORD, JumpTarget),
        ),
        (
            "offsetof SCOPE_TABLE ScopeRecord[1]",
            4 + size_of::<SCOPE_RECORD>(),
        ),
    ]
}

/// `("offsetof T Field", offset)` for each named field of one type.
macro_rules! fields {
    ($name:literal, $t:ty, [$($f:ident),* $(,)?]) => {
        vec![
            (concat!("sizeof ", $name), size_of::<$t>()),
            $((concat!("offsetof ", $name, " ", stringify!($f)), offset_of!($t, $f)),)*
        ]
    };
}

/// The exception structures as x86-64 has them.
fn seh_facts_x64() -> Vec<(&'static str, usize)> {
    use crate::seh::x64::*;
    let mut facts = fields!(
        "CONTEXT",
        CONTEXT,
        [
            ContextFlags,
            MxCsr,
            SegCs,
            SegSs,
            EFlags,
            Dr0,
            Dr7,
            Rax,
            Rcx,
            Rdx,
            Rbx,
            Rsp,
            Rbp,
            Rsi,
            Rdi,
            R8,
            R9,
            R10,
            R11,
            R12,
            R13,
            R14,
            R15,
            Rip,
            FltSave,
            VectorRegister,
            VectorControl,
            DebugControl,
            LastBranchToRip,
            LastExceptionFromRip,
        ]
    );
    facts.push(("offsetof CONTEXT P1Home", offset_of!(CONTEXT, PHome)));
    facts.push((
        "offsetof CONTEXT Xmm6",
        offset_of!(CONTEXT, FltSave) + offset_of!(XSAVE_FORMAT, XmmRegisters) + 6 * 16,
    ));
    facts.extend(fields!(
        "RUNTIME_FUNCTION",
        RUNTIME_FUNCTION,
        [BeginAddress, EndAddress, UnwindData]
    ));
    facts.extend(fields!(
        "DISPATCHER_CONTEXT",
        DISPATCHER_CONTEXT,
        [
            ControlPc,
            ImageBase,
            FunctionEntry,
            EstablisherFrame,
            TargetIp,
            ContextRecord,
            LanguageHandler,
            HandlerData,
            HistoryTable,
            ScopeIndex,
            Fill0,
        ]
    ));
    facts.push(("sizeof M128A", size_of::<crate::seh::M128A>()));
    facts
}

/// The exception structures as arm64 has them: the WDK's table is the
/// only authority for these.
fn seh_facts_arm64() -> Vec<(&'static str, usize)> {
    use crate::seh::arm64::*;
    let mut facts = fields!(
        "CONTEXT",
        CONTEXT,
        [
            ContextFlags,
            Cpsr,
            X,
            Fp,
            Lr,
            Sp,
            Pc,
            V,
            Fpcr,
            Fpsr,
            Bcr,
            Bvr,
            Wcr,
            Wvr,
        ]
    );
    facts.extend(fields!(
        "RUNTIME_FUNCTION",
        RUNTIME_FUNCTION,
        [BeginAddress, UnwindData]
    ));
    facts.extend(fields!(
        "DISPATCHER_CONTEXT",
        DISPATCHER_CONTEXT,
        [
            ControlPc,
            ImageBase,
            FunctionEntry,
            EstablisherFrame,
            TargetPc,
            ContextRecord,
            LanguageHandler,
            HandlerData,
            HistoryTable,
            ScopeIndex,
            ControlPcIsUnwound,
            NonVolatileRegisters,
        ]
    ));
    facts
}

fn table(arch: &str) -> Option<BTreeMap<String, usize>> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "target", "fixtures"]
        .iter()
        .collect();
    let text = std::fs::read_to_string(path.join(format!("abi-probe.{arch}.txt"))).ok()?;
    Some(
        text.lines()
            .filter_map(|l| l.rsplit_once(' '))
            .map(|(name, value)| (name.to_string(), value.parse().expect("probe value")))
            .collect(),
    )
}

/// The Rust definitions are 64-bit and shared by both architectures, so
/// they are checked against each architecture's table.
#[test]
fn layouts_match_the_wdk() {
    let x64 = [nk_facts_x64(), seh_facts(), seh_facts_x64()].concat();
    let arm64 = [seh_facts(), seh_facts_arm64()].concat();
    for (arch, extra) in [("x64", x64), ("arm64", arm64)] {
        let Some(wdk) = table(arch) else {
            eprintln!("SKIP: no WDK ABI table for {arch} (target/fixtures/abi-probe.{arch}.txt)");
            continue;
        };
        assert_eq!(
            wdk.get("NKABI-BEGIN v1"),
            Some(&8),
            "{arch}: not a 64-bit probe table"
        );
        let mut wrong = Vec::new();
        let mut checked = 0;
        for (name, value) in nk_facts().into_iter().chain(extra) {
            match wdk.get(name) {
                Some(&w) if w == value => checked += 1,
                Some(&w) => wrong.push(format!("{name}: NK {value:#x}, WDK {w:#x}")),
                None => wrong.push(format!("{name}: not in the WDK table")),
            }
        }
        assert!(
            wrong.is_empty(),
            "{arch}: layout mismatches:\n  {}",
            wrong.join("\n  ")
        );
        eprintln!(
            "{arch}: {checked} layout facts match the WDK probe ({} in its table)",
            wdk.len()
        );
    }
}
