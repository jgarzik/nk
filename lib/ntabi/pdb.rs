//! Check the private layouts against Microsoft's public symbols.
//!
//! Structures the WDK does not declare (the processor block, the thread
//! object) are still read in line by Microsoft's own drivers, so NK gives
//! them Windows' layout. The authority is the type information in the
//! public PDB of the pinned kernel build, a fixture:
//! `target/fixtures/ntkrnlmp.x64.pdb`. As with the WDK tables, an absent
//! fixture is reported on stderr and never counted as agreement.
//!
//! There is no arm64 counterpart: no Windows 10 arm64 kernel or symbol
//! file is available to NK. See `doc/ABI.md`.

use crate::pcr;
use nk_pdb::{Layout, Pdb, Types};
use std::path::PathBuf;

/// The kernel's type records, or `None` (with a note) without the fixture.
fn kernel_types() -> Option<Types> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "target", "fixtures"]
        .iter()
        .collect();
    let Ok(file) = std::fs::read(path.join("ntkrnlmp.x64.pdb")) else {
        eprintln!("SKIP: no kernel symbols (target/fixtures/ntkrnlmp.x64.pdb)");
        return None;
    };
    let pdb = Pdb::parse(&file).expect("the kernel PDB");
    Some(pdb.types().expect("the kernel PDB's types"))
}

fn offset(layout: &Layout, ty: &str, field: &str) -> usize {
    let member = layout
        .member(field)
        .unwrap_or_else(|| panic!("{ty} has no field {field}"));
    assert_eq!(member.bits, None, "{ty}.{field} is a bit field");
    member.offset as usize
}

#[test]
fn processor_block_matches_the_kernel() {
    let Some(types) = kernel_types() else { return };
    let kpcr = types.layout("_KPCR").expect("_KPCR");
    let kprcb = types.layout("_KPRCB").expect("_KPRCB");
    let l = pcr::X86_64;
    assert_eq!(l.self_ptr, offset(&kpcr, "_KPCR", "Self"));
    assert_eq!(l.current_prcb, offset(&kpcr, "_KPCR", "CurrentPrcb"));
    assert_eq!(l.prcb, offset(&kpcr, "_KPCR", "Prcb"));
    assert_eq!(
        l.current_thread,
        l.prcb + offset(&kprcb, "_KPRCB", "CurrentThread"),
        "what the WDK's inlined KeGetCurrentThread reads"
    );
    assert_eq!(l.number, l.prcb + offset(&kprcb, "_KPRCB", "Number"));
    assert_eq!(
        l.legacy_number,
        Some(l.prcb + offset(&kprcb, "_KPRCB", "LegacyNumber"))
    );
    // The control region ends with the processor block.
    assert_eq!(l.size, kpcr.size as usize);
    assert_eq!(kpcr.size as usize, l.prcb + kprcb.size as usize);
    eprintln!(
        "x64: processor block matches the kernel symbols (KPCR {:#x} bytes)",
        kpcr.size
    );
}

#[test]
fn queued_lock_handle_matches_the_kernel() {
    use crate::ke::{KLOCK_QUEUE_HANDLE, KSPIN_LOCK_QUEUE};
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let handle = types
        .layout("_KLOCK_QUEUE_HANDLE")
        .expect("_KLOCK_QUEUE_HANDLE");
    let queue = types
        .layout("_KSPIN_LOCK_QUEUE")
        .expect("_KSPIN_LOCK_QUEUE");
    assert_eq!(size_of::<KLOCK_QUEUE_HANDLE>(), handle.size as usize);
    assert_eq!(
        offset_of!(KLOCK_QUEUE_HANDLE, OldIrql),
        offset(&handle, "_KLOCK_QUEUE_HANDLE", "OldIrql")
    );
    assert_eq!(size_of::<KSPIN_LOCK_QUEUE>(), queue.size as usize);
    assert_eq!(
        offset_of!(KSPIN_LOCK_QUEUE, Lock),
        offset(&queue, "_KSPIN_LOCK_QUEUE", "Lock")
    );
}

#[test]
fn shared_data_page_matches_the_kernel() {
    use crate::ke::*;
    let Some(types) = kernel_types() else { return };
    let page = types
        .layout("_KUSER_SHARED_DATA")
        .expect("_KUSER_SHARED_DATA");
    let field = |name| offset(&page, "_KUSER_SHARED_DATA", name);
    assert_eq!(SHARED_TICK_MULTIPLIER, field("TickCountMultiplier"));
    assert_eq!(SHARED_INTERRUPT_TIME, field("InterruptTime"));
    assert_eq!(SHARED_SYSTEM_TIME, field("SystemTime"));
    assert_eq!(SHARED_TICK_COUNT, field("TickCount"));
    assert!(page.size <= 4096, "it must fit the one page NK maps");
    // Each time is low word, high word, high word again.
    let time = types.layout("_KSYSTEM_TIME").expect("_KSYSTEM_TIME");
    assert_eq!(
        (time.size, offset(&time, "_KSYSTEM_TIME", "High2Time")),
        (12, 8)
    );
}

#[test]
fn dpc_matches_the_kernel() {
    use crate::ke::KDPC;
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let dpc = types.layout("_KDPC").expect("_KDPC");
    let field = |name| offset(&dpc, "_KDPC", name);
    assert_eq!(size_of::<KDPC>(), dpc.size as usize);
    assert_eq!(offset_of!(KDPC, Type), field("Type"));
    assert_eq!(offset_of!(KDPC, Importance), field("Importance"));
    assert_eq!(offset_of!(KDPC, Number), field("Number"));
    assert_eq!(offset_of!(KDPC, DpcListEntry), field("DpcListEntry"));
    assert_eq!(
        offset_of!(KDPC, ProcessorHistory),
        field("ProcessorHistory")
    );
    assert_eq!(offset_of!(KDPC, DeferredRoutine), field("DeferredRoutine"));
    assert_eq!(offset_of!(KDPC, DeferredContext), field("DeferredContext"));
    assert_eq!(offset_of!(KDPC, SystemArgument1), field("SystemArgument1"));
    assert_eq!(offset_of!(KDPC, SystemArgument2), field("SystemArgument2"));
    assert_eq!(offset_of!(KDPC, DpcData), field("DpcData"));
}

#[test]
fn timer_matches_the_kernel() {
    use crate::ke::{DISPATCHER_HEADER, KTIMER, TIMER_INSERTED};
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let header = types
        .layout("_DISPATCHER_HEADER")
        .expect("_DISPATCHER_HEADER");
    let field = |name| offset(&header, "_DISPATCHER_HEADER", name);
    assert_eq!(size_of::<DISPATCHER_HEADER>(), header.size as usize);
    assert_eq!(offset_of!(DISPATCHER_HEADER, Type), field("Type"));
    assert_eq!(
        offset_of!(DISPATCHER_HEADER, TimerControlFlags),
        field("TimerControlFlags")
    );
    assert_eq!(offset_of!(DISPATCHER_HEADER, Hand), field("Hand"));
    assert_eq!(
        offset_of!(DISPATCHER_HEADER, TimerMiscFlags),
        field("TimerMiscFlags")
    );
    assert_eq!(
        offset_of!(DISPATCHER_HEADER, SignalState),
        field("SignalState")
    );
    assert_eq!(
        offset_of!(DISPATCHER_HEADER, WaitListHead),
        field("WaitListHead")
    );
    let inserted = header.member("Inserted").expect("Inserted");
    assert_eq!(
        (inserted.offset as usize, inserted.bits),
        (
            offset_of!(DISPATCHER_HEADER, TimerMiscFlags),
            Some((TIMER_INSERTED.trailing_zeros() as u8, 1))
        )
    );

    let timer = types.layout("_KTIMER").expect("_KTIMER");
    let field = |name| offset(&timer, "_KTIMER", name);
    assert_eq!(size_of::<KTIMER>(), timer.size as usize);
    assert_eq!(offset_of!(KTIMER, Header), field("Header"));
    assert_eq!(offset_of!(KTIMER, DueTime), field("DueTime"));
    assert_eq!(offset_of!(KTIMER, TimerListEntry), field("TimerListEntry"));
    assert_eq!(offset_of!(KTIMER, Dpc), field("Dpc"));
    assert_eq!(offset_of!(KTIMER, Processor), field("Processor"));
    assert_eq!(offset_of!(KTIMER, TimerType), field("TimerType"));
    assert_eq!(offset_of!(KTIMER, Period), field("Period"));
}

#[test]
fn thread_matches_the_kernel() {
    use crate::thread::*;
    let Some(types) = kernel_types() else { return };
    let kthread = types.layout("_KTHREAD").expect("_KTHREAD");
    let ethread = types.layout("_ETHREAD").expect("_ETHREAD");
    let field = |name| offset(&kthread, "_KTHREAD", name);
    assert_eq!(KTHREAD_SIZE, kthread.size as usize);
    assert_eq!(ETHREAD_SIZE, ethread.size as usize);
    assert_eq!(offset(&ethread, "_ETHREAD", "Tcb"), 0);
    assert_eq!(field("Header"), 0);
    assert_eq!(INITIAL_STACK, field("InitialStack"));
    assert_eq!(STACK_LIMIT, field("StackLimit"));
    assert_eq!(STACK_BASE, field("StackBase"));
    assert_eq!(KERNEL_STACK, field("KernelStack"));
    assert_eq!(RUNNING, field("Running"));
    assert_eq!(PRIORITY, field("Priority"));
    assert_eq!(WAIT_LIST_ENTRY, field("WaitListEntry"));
    assert_eq!(STATE, field("State"));
    assert_eq!(NEXT_PROCESSOR, field("NextProcessor"));
    assert_eq!(BASE_PRIORITY, field("BasePriority"));
    assert_eq!(AFFINITY, field("Affinity"));
    assert_eq!(KERNEL_APC_DISABLE, field("KernelApcDisable"));
    assert_eq!(KERNEL_APC_DISABLE, field("CombinedApcDisable"));
    assert_eq!(KERNEL_APC_DISABLE + 2, field("SpecialApcDisable"));
    assert_eq!(MUTANT_LIST_HEAD, field("MutantListHead"));
    assert_eq!(TIMER, field("Timer"));
    assert_eq!(WAIT_BLOCK, field("WaitBlock"));
    assert_eq!(WAIT_STATUS, field("WaitStatus"));
    // The fields NK keeps inside the wait blocks' spare room are where
    // the blocks' used fields are not.
    let block = core::mem::size_of::<crate::ke::KWAIT_BLOCK>();
    for inside in [STATE, field("WaitIrql")] {
        let at = (inside - WAIT_BLOCK) % block;
        assert!(
            (20..24).contains(&at) || at >= 40,
            "{inside:#x} overlaps a wait block field"
        );
    }
    assert_eq!(IDEAL_PROCESSOR, field("IdealProcessor"));
    let affinity = types.layout("_GROUP_AFFINITY").expect("_GROUP_AFFINITY");
    assert_eq!(offset(&affinity, "_GROUP_AFFINITY", "Mask"), 0);
    assert_eq!(START_ADDRESS, offset(&ethread, "_ETHREAD", "StartAddress"));
    assert_eq!(PROCESS, field("Process"));
    let apc_state = types.layout("_KAPC_STATE").expect("_KAPC_STATE");
    assert_eq!(
        APC_STATE_PROCESS,
        field("ApcState") + offset(&apc_state, "_KAPC_STATE", "Process")
    );
    assert_eq!(CID, offset(&ethread, "_ETHREAD", "Cid"));
    let cid = types.layout("_CLIENT_ID").expect("_CLIENT_ID");
    assert_eq!(offset(&cid, "_CLIENT_ID", "UniqueProcess"), 0);
    assert_eq!(offset(&cid, "_CLIENT_ID", "UniqueThread"), 8);
}

#[test]
fn process_matches_the_kernel() {
    use crate::process::*;
    let Some(types) = kernel_types() else { return };
    let eprocess = types.layout("_EPROCESS").expect("_EPROCESS");
    let kprocess = types.layout("_KPROCESS").expect("_KPROCESS");
    let field = |name| offset(&eprocess, "_EPROCESS", name);
    assert_eq!(EPROCESS_SIZE, eprocess.size as usize);
    assert_eq!(field("Pcb"), 0);
    assert_eq!(offset(&kprocess, "_KPROCESS", "Header"), 0);
    assert_eq!(UNIQUE_PROCESS_ID, field("UniqueProcessId"));
    assert_eq!(CREATE_TIME, field("CreateTime"));
    assert_eq!(IMAGE_FILE_NAME, field("ImageFileName"));
    assert_eq!(TOKEN, field("Token"));
    // The token pointer is a fast reference: one pointer-sized word
    // whose low four bits are a count.
    let fast = types.layout("_EX_FAST_REF").expect("_EX_FAST_REF");
    let count = fast.member("RefCnt").expect("_EX_FAST_REF.RefCnt");
    assert_eq!((fast.size, count.offset), (8, 0));
    assert_eq!(
        count.bits,
        Some((0, FAST_REF_COUNT_MASK.count_ones() as u8))
    );
}

#[test]
fn wait_objects_match_the_kernel() {
    use crate::ke::*;
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let block = types.layout("_KWAIT_BLOCK").expect("_KWAIT_BLOCK");
    let field = |name| offset(&block, "_KWAIT_BLOCK", name);
    assert_eq!(size_of::<KWAIT_BLOCK>(), block.size as usize);
    assert_eq!(
        offset_of!(KWAIT_BLOCK, WaitListEntry),
        field("WaitListEntry")
    );
    assert_eq!(offset_of!(KWAIT_BLOCK, WaitType), field("WaitType"));
    assert_eq!(offset_of!(KWAIT_BLOCK, BlockState), field("BlockState"));
    assert_eq!(offset_of!(KWAIT_BLOCK, WaitKey), field("WaitKey"));
    assert_eq!(offset_of!(KWAIT_BLOCK, SpareLong), field("SpareLong"));
    assert_eq!(offset_of!(KWAIT_BLOCK, Thread), field("Thread"));
    assert_eq!(offset_of!(KWAIT_BLOCK, Object), field("Object"));
    assert_eq!(offset_of!(KWAIT_BLOCK, SparePtr), field("SparePtr"));
    let semaphore = types.layout("_KSEMAPHORE").expect("_KSEMAPHORE");
    assert_eq!(size_of::<KSEMAPHORE>(), semaphore.size as usize);
    assert_eq!(
        offset_of!(KSEMAPHORE, Limit),
        offset(&semaphore, "_KSEMAPHORE", "Limit")
    );
    let event = types.layout("_KEVENT").expect("_KEVENT");
    assert_eq!(size_of::<KEVENT>(), event.size as usize);
    let header = types
        .layout("_DISPATCHER_HEADER")
        .expect("_DISPATCHER_HEADER");
    let expired = header.member("Expired").expect("Expired");
    assert_eq!(
        expired.bits,
        Some((TIMER_EXPIRED.trailing_zeros() as u8, 1))
    );
}

#[test]
fn object_header_matches_the_kernel() {
    use crate::ob::*;
    use core::mem::offset_of;
    let Some(types) = kernel_types() else { return };
    let header = types.layout("_OBJECT_HEADER").expect("_OBJECT_HEADER");
    let field = |name| offset(&header, "_OBJECT_HEADER", name);
    assert_eq!(OBJECT_BODY, field("Body"));
    assert_eq!(
        offset_of!(OBJECT_HEADER, PointerCount),
        field("PointerCount")
    );
    assert_eq!(offset_of!(OBJECT_HEADER, HandleCount), field("HandleCount"));
    assert_eq!(offset_of!(OBJECT_HEADER, Lock), field("Lock"));
    assert_eq!(offset_of!(OBJECT_HEADER, TypeIndex), field("TypeIndex"));
    assert_eq!(offset_of!(OBJECT_HEADER, Flags), field("Flags"));
    assert_eq!(
        offset_of!(OBJECT_HEADER, ObjectCreateInfo),
        field("ObjectCreateInfo")
    );
    assert_eq!(
        offset_of!(OBJECT_HEADER, SecurityDescriptor),
        field("SecurityDescriptor")
    );
    assert_eq!(offset_of!(OBJECT_HEADER, InfoMask), field("InfoMask"));
}

#[test]
fn named_objects_match_the_kernel() {
    use crate::ob::*;
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let info = types
        .layout("_OBJECT_HEADER_NAME_INFO")
        .expect("_OBJECT_HEADER_NAME_INFO");
    let field = |name| offset(&info, "_OBJECT_HEADER_NAME_INFO", name);
    assert_eq!(size_of::<OBJECT_HEADER_NAME_INFO>(), info.size as usize);
    assert_eq!(
        offset_of!(OBJECT_HEADER_NAME_INFO, Directory),
        field("Directory")
    );
    assert_eq!(offset_of!(OBJECT_HEADER_NAME_INFO, Name), field("Name"));
    assert_eq!(
        offset_of!(OBJECT_HEADER_NAME_INFO, ReferenceCount),
        field("ReferenceCount")
    );

    let directory = types
        .layout("_OBJECT_DIRECTORY")
        .expect("_OBJECT_DIRECTORY");
    assert_eq!(OBJECT_DIRECTORY_SIZE, directory.size as usize);

    let link = types
        .layout("_OBJECT_SYMBOLIC_LINK")
        .expect("_OBJECT_SYMBOLIC_LINK");
    let field = |name| offset(&link, "_OBJECT_SYMBOLIC_LINK", name);
    assert_eq!(size_of::<OBJECT_SYMBOLIC_LINK>(), link.size as usize);
    macro_rules! same {
        ($($name:ident),*) => {$(
            assert_eq!(offset_of!(OBJECT_SYMBOLIC_LINK, $name), field(stringify!($name)));
        )*};
    }
    same!(
        CreationTime,
        LinkTarget,
        DosDeviceDriveIndex,
        Flags,
        AccessMask
    );
}

#[test]
fn object_types_match_the_kernel() {
    use crate::ob::*;
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let ty = types.layout("_OBJECT_TYPE").expect("_OBJECT_TYPE");
    let field = |name| offset(&ty, "_OBJECT_TYPE", name);
    assert_eq!(size_of::<OBJECT_TYPE>(), ty.size as usize);
    assert_eq!(offset_of!(OBJECT_TYPE, TypeList), field("TypeList"));
    assert_eq!(offset_of!(OBJECT_TYPE, Name), field("Name"));
    assert_eq!(
        offset_of!(OBJECT_TYPE, DefaultObject),
        field("DefaultObject")
    );
    assert_eq!(offset_of!(OBJECT_TYPE, Index), field("Index"));
    assert_eq!(
        offset_of!(OBJECT_TYPE, TotalNumberOfObjects),
        field("TotalNumberOfObjects")
    );
    assert_eq!(
        offset_of!(OBJECT_TYPE, HighWaterNumberOfHandles),
        field("HighWaterNumberOfHandles")
    );
    assert_eq!(offset_of!(OBJECT_TYPE, TypeInfo), field("TypeInfo"));
    assert_eq!(offset_of!(OBJECT_TYPE, TypeLock), field("TypeLock"));
    assert_eq!(offset_of!(OBJECT_TYPE, Key), field("Key"));
    assert_eq!(offset_of!(OBJECT_TYPE, CallbackList), field("CallbackList"));

    let init = types
        .layout("_OBJECT_TYPE_INITIALIZER")
        .expect("_OBJECT_TYPE_INITIALIZER");
    let field = |name| offset(&init, "_OBJECT_TYPE_INITIALIZER", name);
    assert_eq!(size_of::<OBJECT_TYPE_INITIALIZER>(), init.size as usize);
    macro_rules! same {
        ($($name:ident),*) => {$(
            assert_eq!(offset_of!(OBJECT_TYPE_INITIALIZER, $name), field(stringify!($name)));
        )*};
    }
    same!(
        Length,
        ObjectTypeFlags,
        ObjectTypeCode,
        InvalidAttributes,
        GenericMapping,
        ValidAccessMask,
        RetainAccess,
        PoolType,
        DefaultPagedPoolCharge,
        DefaultNonPagedPoolCharge,
        DumpProcedure,
        OpenProcedure,
        CloseProcedure,
        DeleteProcedure,
        ParseProcedure,
        SecurityProcedure,
        QueryNameProcedure,
        OkayToCloseProcedure,
        WaitObjectFlagMask,
        WaitObjectFlagOffset,
        WaitObjectPointerOffset
    );
    assert_eq!(
        size_of::<GENERIC_MAPPING>(),
        types
            .layout("_GENERIC_MAPPING")
            .expect("_GENERIC_MAPPING")
            .size as usize
    );
}

#[test]
fn exception_structures_match_the_kernel() {
    use crate::seh::x64::{CONTEXT, RUNTIME_FUNCTION, XSAVE_FORMAT};
    use crate::seh::*;
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let context = types.layout("_CONTEXT").expect("_CONTEXT");
    let field = |name| offset(&context, "_CONTEXT", name);
    assert_eq!(size_of::<CONTEXT>(), context.size as usize);
    assert_eq!(offset_of!(CONTEXT, PHome), field("P1Home"));
    macro_rules! same {
        ($($name:ident),*) => {$(
            assert_eq!(offset_of!(CONTEXT, $name), field(stringify!($name)));
        )*};
    }
    same!(
        ContextFlags,
        MxCsr,
        SegCs,
        SegDs,
        SegEs,
        SegFs,
        SegGs,
        SegSs,
        EFlags,
        Dr0,
        Dr1,
        Dr2,
        Dr3,
        Dr6,
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
        LastBranchFromRip,
        LastExceptionToRip,
        LastExceptionFromRip
    );
    // The SSE registers by name are the legacy save area's by number.
    for (n, name) in ["Xmm0", "Xmm6", "Xmm15"].into_iter().zip([0, 6, 15]) {
        assert_eq!(
            field(n),
            offset_of!(CONTEXT, FltSave) + offset_of!(XSAVE_FORMAT, XmmRegisters) + 16 * name
        );
    }
    let save = types.layout("_XSAVE_FORMAT").expect("_XSAVE_FORMAT");
    assert_eq!(size_of::<XSAVE_FORMAT>(), save.size as usize);
    assert_eq!(
        offset_of!(XSAVE_FORMAT, MxCsr),
        offset(&save, "_XSAVE_FORMAT", "MxCsr")
    );
    assert_eq!(
        offset_of!(XSAVE_FORMAT, XmmRegisters),
        offset(&save, "_XSAVE_FORMAT", "XmmRegisters")
    );

    let record = types
        .layout("_EXCEPTION_RECORD")
        .expect("_EXCEPTION_RECORD");
    let field = |name| offset(&record, "_EXCEPTION_RECORD", name);
    assert_eq!(size_of::<EXCEPTION_RECORD>(), record.size as usize);
    assert_eq!(
        offset_of!(EXCEPTION_RECORD, ExceptionFlags),
        field("ExceptionFlags")
    );
    assert_eq!(
        offset_of!(EXCEPTION_RECORD, ExceptionRecord),
        field("ExceptionRecord")
    );
    assert_eq!(
        offset_of!(EXCEPTION_RECORD, ExceptionAddress),
        field("ExceptionAddress")
    );
    assert_eq!(
        offset_of!(EXCEPTION_RECORD, NumberParameters),
        field("NumberParameters")
    );
    assert_eq!(
        offset_of!(EXCEPTION_RECORD, ExceptionInformation),
        field("ExceptionInformation")
    );
    assert_eq!(
        size_of::<EXCEPTION_POINTERS>(),
        types
            .layout("_EXCEPTION_POINTERS")
            .expect("_EXCEPTION_POINTERS")
            .size as usize
    );
    assert_eq!(
        size_of::<M128A>(),
        types.layout("_M128A").expect("_M128A").size as usize
    );
    assert_eq!(
        size_of::<RUNTIME_FUNCTION>(),
        types
            .layout("_IMAGE_RUNTIME_FUNCTION_ENTRY")
            .expect("_IMAGE_RUNTIME_FUNCTION_ENTRY")
            .size as usize
    );
}

#[test]
fn mutexes_match_the_kernel() {
    use crate::ke::{FAST_MUTEX, KMUTANT};
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let mutant = types.layout("_KMUTANT").expect("_KMUTANT");
    let field = |name| offset(&mutant, "_KMUTANT", name);
    assert_eq!(size_of::<KMUTANT>(), mutant.size as usize);
    assert_eq!(
        offset_of!(KMUTANT, MutantListEntry),
        field("MutantListEntry")
    );
    assert_eq!(offset_of!(KMUTANT, OwnerThread), field("OwnerThread"));
    assert_eq!(offset_of!(KMUTANT, MutantFlags), field("MutantFlags"));
    assert_eq!(offset_of!(KMUTANT, ApcDisable), field("ApcDisable"));
    let fast = types.layout("_FAST_MUTEX").expect("_FAST_MUTEX");
    let field = |name| offset(&fast, "_FAST_MUTEX", name);
    assert_eq!(size_of::<FAST_MUTEX>(), fast.size as usize);
    assert_eq!(offset_of!(FAST_MUTEX, Count), field("Count"));
    assert_eq!(offset_of!(FAST_MUTEX, Owner), field("Owner"));
    assert_eq!(offset_of!(FAST_MUTEX, Contention), field("Contention"));
    assert_eq!(offset_of!(FAST_MUTEX, Event), field("Event"));
    assert_eq!(offset_of!(FAST_MUTEX, OldIrql), field("OldIrql"));
}

#[test]
fn work_items_match_the_kernel() {
    use crate::ex::{IO_WORKITEM, WORK_QUEUE_ITEM};
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let item = types.layout("_WORK_QUEUE_ITEM").expect("_WORK_QUEUE_ITEM");
    let field = |name| offset(&item, "_WORK_QUEUE_ITEM", name);
    assert_eq!(size_of::<WORK_QUEUE_ITEM>(), item.size as usize);
    assert_eq!(offset_of!(WORK_QUEUE_ITEM, List), field("List"));
    assert_eq!(
        offset_of!(WORK_QUEUE_ITEM, WorkerRoutine),
        field("WorkerRoutine")
    );
    assert_eq!(offset_of!(WORK_QUEUE_ITEM, Parameter), field("Parameter"));
    let io = types.layout("_IO_WORKITEM").expect("_IO_WORKITEM");
    let field = |name| offset(&io, "_IO_WORKITEM", name);
    assert_eq!(size_of::<IO_WORKITEM>(), io.size as usize);
    assert_eq!(offset_of!(IO_WORKITEM, WorkItem), field("WorkItem"));
    assert_eq!(offset_of!(IO_WORKITEM, Routine), field("Routine"));
    assert_eq!(offset_of!(IO_WORKITEM, IoObject), field("IoObject"));
    assert_eq!(offset_of!(IO_WORKITEM, Context), field("Context"));
    assert_eq!(offset_of!(IO_WORKITEM, Type), field("Type"));
    assert_eq!(offset_of!(IO_WORKITEM, ActivityId), field("ActivityId"));
}

#[test]
fn remove_lock_matches_the_kernel() {
    use crate::io::IO_REMOVE_LOCK;
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let lock = types
        .layout("_IO_REMOVE_LOCK_COMMON_BLOCK")
        .expect("_IO_REMOVE_LOCK_COMMON_BLOCK");
    let field = |name| offset(&lock, "_IO_REMOVE_LOCK_COMMON_BLOCK", name);
    assert_eq!(size_of::<IO_REMOVE_LOCK>(), lock.size as usize);
    assert_eq!(offset_of!(IO_REMOVE_LOCK, Removed), field("Removed"));
    assert_eq!(offset_of!(IO_REMOVE_LOCK, IoCount), field("IoCount"));
    assert_eq!(
        offset_of!(IO_REMOVE_LOCK, RemoveEvent),
        field("RemoveEvent")
    );
}

#[test]
fn security_structures_match_the_kernel() {
    use crate::se::{LUID, SECURITY_DESCRIPTOR};
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let sd = types
        .layout("_SECURITY_DESCRIPTOR")
        .expect("_SECURITY_DESCRIPTOR");
    let field = |name| offset(&sd, "_SECURITY_DESCRIPTOR", name);
    assert_eq!(size_of::<SECURITY_DESCRIPTOR>(), sd.size as usize);
    assert_eq!(offset_of!(SECURITY_DESCRIPTOR, Control), field("Control"));
    assert_eq!(offset_of!(SECURITY_DESCRIPTOR, Owner), field("Owner"));
    assert_eq!(offset_of!(SECURITY_DESCRIPTOR, Group), field("Group"));
    assert_eq!(offset_of!(SECURITY_DESCRIPTOR, Sacl), field("Sacl"));
    assert_eq!(offset_of!(SECURITY_DESCRIPTOR, Dacl), field("Dacl"));
    assert_eq!(
        size_of::<LUID>(),
        types.layout("_LUID").expect("_LUID").size as usize
    );

    // The byte layouts `nk_se` works with.
    let relative = types
        .layout("_SECURITY_DESCRIPTOR_RELATIVE")
        .expect("_SECURITY_DESCRIPTOR_RELATIVE");
    let field = |name| offset(&relative, "_SECURITY_DESCRIPTOR_RELATIVE", name);
    assert_eq!(nk_se::RELATIVE_HEADER, relative.size as usize);
    assert_eq!(
        (
            field("Control"),
            field("Owner"),
            field("Group"),
            field("Sacl"),
            field("Dacl")
        ),
        (2, 4, 8, 12, 16)
    );
    let acl = types.layout("_ACL").expect("_ACL");
    assert_eq!(nk_se::ACL_HEADER, acl.size as usize);
    assert_eq!(
        (
            offset(&acl, "_ACL", "AclSize"),
            offset(&acl, "_ACL", "AceCount")
        ),
        (2, 4)
    );
    let sid = types.layout("_SID").expect("_SID");
    assert_eq!(
        (
            offset(&sid, "_SID", "SubAuthorityCount"),
            offset(&sid, "_SID", "IdentifierAuthority"),
            offset(&sid, "_SID", "SubAuthority")
        ),
        (1, 2, 8)
    );
    // One sub-authority is declared; the size is that of such a SID.
    assert_eq!(nk_se::sid_length(1), sid.size as usize);
}

#[test]
fn access_state_matches_the_kernel() {
    use crate::se::{ACCESS_STATE, SECURITY_SUBJECT_CONTEXT};
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let subject = types
        .layout("_SECURITY_SUBJECT_CONTEXT")
        .expect("_SECURITY_SUBJECT_CONTEXT");
    let field = |name| offset(&subject, "_SECURITY_SUBJECT_CONTEXT", name);
    assert_eq!(size_of::<SECURITY_SUBJECT_CONTEXT>(), subject.size as usize);
    macro_rules! same_subject {
        ($($name:ident),*) => {$(
            assert_eq!(offset_of!(SECURITY_SUBJECT_CONTEXT, $name), field(stringify!($name)));
        )*};
    }
    same_subject!(
        ClientToken,
        ImpersonationLevel,
        PrimaryToken,
        ProcessAuditId
    );

    let state = types.layout("_ACCESS_STATE").expect("_ACCESS_STATE");
    let field = |name| offset(&state, "_ACCESS_STATE", name);
    assert_eq!(size_of::<ACCESS_STATE>(), state.size as usize);
    macro_rules! same_state {
        ($($name:ident),*) => {$(
            assert_eq!(offset_of!(ACCESS_STATE, $name), field(stringify!($name)));
        )*};
    }
    same_state!(
        OperationID,
        SecurityEvaluated,
        GenerateAudit,
        GenerateOnClose,
        PrivilegesAllocated,
        Flags,
        RemainingDesiredAccess,
        PreviouslyGrantedAccess,
        OriginalDesiredAccess,
        SubjectSecurityContext,
        SecurityDescriptor,
        AuxData,
        Privileges,
        AuditPrivileges,
        ObjectName,
        ObjectTypeName
    );
    // The privileges kept in line: a count, a control word and three
    // privileges of twelve bytes each.
    let initial = types
        .layout("_INITIAL_PRIVILEGE_SET")
        .expect("_INITIAL_PRIVILEGE_SET");
    assert_eq!(
        initial.size as usize,
        field("AuditPrivileges") - field("Privileges")
    );
}

#[test]
fn create_requests_match_the_kernel() {
    use crate::io::{IO_SECURITY_CONTEXT, NAMED_PIPE_CREATE_PARAMETERS};
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let context = types
        .layout("_IO_SECURITY_CONTEXT")
        .expect("_IO_SECURITY_CONTEXT");
    let field = |name| offset(&context, "_IO_SECURITY_CONTEXT", name);
    assert_eq!(size_of::<IO_SECURITY_CONTEXT>(), context.size as usize);
    macro_rules! same_context {
        ($($name:ident),*) => {$(
            assert_eq!(offset_of!(IO_SECURITY_CONTEXT, $name), field(stringify!($name)));
        )*};
    }
    same_context!(SecurityQos, AccessState, DesiredAccess, FullCreateOptions);

    let pipe = types
        .layout("_NAMED_PIPE_CREATE_PARAMETERS")
        .expect("_NAMED_PIPE_CREATE_PARAMETERS");
    let field = |name| offset(&pipe, "_NAMED_PIPE_CREATE_PARAMETERS", name);
    assert_eq!(
        size_of::<NAMED_PIPE_CREATE_PARAMETERS>(),
        pipe.size as usize
    );
    macro_rules! same_pipe {
        ($($name:ident),*) => {$(
            assert_eq!(
                offset_of!(NAMED_PIPE_CREATE_PARAMETERS, $name),
                field(stringify!($name))
            );
        )*};
    }
    same_pipe!(
        NamedPipeType,
        ReadMode,
        CompletionMode,
        MaximumInstances,
        InboundQuota,
        OutboundQuota,
        DefaultTimeout,
        TimeoutSpecified
    );
}

#[test]
fn object_attributes_match_the_kernel() {
    use crate::ob::OBJECT_ATTRIBUTES;
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let oa = types
        .layout("_OBJECT_ATTRIBUTES")
        .expect("_OBJECT_ATTRIBUTES");
    let field = |name| offset(&oa, "_OBJECT_ATTRIBUTES", name);
    assert_eq!(size_of::<OBJECT_ATTRIBUTES>(), oa.size as usize);
    assert_eq!(
        offset_of!(OBJECT_ATTRIBUTES, RootDirectory),
        field("RootDirectory")
    );
    assert_eq!(
        offset_of!(OBJECT_ATTRIBUTES, ObjectName),
        field("ObjectName")
    );
    assert_eq!(
        offset_of!(OBJECT_ATTRIBUTES, Attributes),
        field("Attributes")
    );
    assert_eq!(
        offset_of!(OBJECT_ATTRIBUTES, SecurityDescriptor),
        field("SecurityDescriptor")
    );
    assert_eq!(
        offset_of!(OBJECT_ATTRIBUTES, SecurityQualityOfService),
        field("SecurityQualityOfService")
    );
}

#[test]
fn runtime_library_structures_match_the_kernel() {
    use crate::rtl::*;
    use core::mem::{offset_of, size_of};
    let Some(types) = kernel_types() else { return };
    let string = types.layout("_STRING").expect("_STRING");
    let field = |name| offset(&string, "_STRING", name);
    assert_eq!(size_of::<STRING>(), string.size as usize);
    assert_eq!(offset_of!(STRING, Length), field("Length"));
    assert_eq!(offset_of!(STRING, MaximumLength), field("MaximumLength"));
    assert_eq!(offset_of!(STRING, Buffer), field("Buffer"));
}
