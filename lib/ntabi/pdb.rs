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
