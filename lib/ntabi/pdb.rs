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
