//! Tests of what a tracing driver asks of the kernel: the callbacks it
//! leaves for a bugcheck and the stop itself.
//!
//! Each test calls the exports as a driver does, through their
//! `extern "C"` signatures, with records and buffers of its own.

use crate::ke::bugcheck::{
    KeBugCheckEx, KeDeregisterBugCheckReasonCallback, KeRegisterBugCheckReasonCallback,
    KiBugCheckData,
};
use crate::test::{Group, Report, Slot};
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::ke::{
    BUFFER_EMPTY, BUFFER_FINISHED, BUFFER_INSERTED, KB_CALLBACK_RESERVED1,
    KB_CALLBACK_TRIAGE_DUMP_DATA, KBUGCHECK_REASON_CALLBACK_RECORD, KBUGCHECK_TRIAGE_DUMP_DATA,
    LIST_ENTRY,
};

pub static GROUP: Group = Group {
    names: &["ke.bugcheck.register", "ke.bugcheck.order"],
    run,
    manual: false,
};

fn run(r: &mut Report, _: &BootInfo) {
    r.check("ke.bugcheck.register", register);
    r.check("ke.bugcheck.order", order);
}

/// `KbCallbackSecondaryDumpData`: data for a crash dump, which NK does
/// not write.
const SECONDARY_DUMP_DATA: u32 = 2;

/// The component name the tests register with.
static COMPONENT: [u8; 7] = *b"NkTest\0";

type Record = KBUGCHECK_REASON_CALLBACK_RECORD;

/// Records, as a driver keeps them: in its image.
static RECORDS: [Slot<Record>; 8] = [const { Slot::new() }; 8];

fn slot(index: usize) -> *mut Record {
    RECORDS[index].ptr()
}

/// `KeInitializeCallbackRecord`, which is in-line code in a driver.
fn initialize(record: *mut Record) {
    // SAFETY: static storage of the tests' own.
    unsafe { (&raw mut (*record).State).write(BUFFER_EMPTY) };
}

fn state(record: *mut Record) -> u8 {
    // SAFETY: static storage of the tests' own.
    unsafe { (&raw const (*record).State).read() }
}

fn component() -> *mut u8 {
    COMPONENT.as_ptr().cast_mut()
}

/// Register `record` for `reason` with `routine`.
fn add(
    record: *mut Record,
    routine: nk_ntabi::ke::KBUGCHECK_REASON_CALLBACK_ROUTINE,
    reason: u32,
) -> u8 {
    // SAFETY: static storage, and a component name that is never freed.
    unsafe { KeRegisterBugCheckReasonCallback(record, Some(routine), reason, component()) }
}

fn take_back(record: *mut Record) -> u8 {
    // SAFETY: static storage of the tests' own.
    unsafe { KeDeregisterBugCheckReasonCallback(record) }
}

/// A routine that is registered and never called: the system does not
/// stop in these tests.
///
/// # Safety
/// Callable with anything.
unsafe extern "C" fn never(_: u32, _: *mut Record, _: *mut c_void, _: u32) {
    OTHERS.fetch_add(1, Ordering::Relaxed);
}

/// A record is registered once, filled in as Windows fills it in, and
/// taken back once.
fn register() -> Result<(), &'static str> {
    let (record, other) = (slot(0), slot(1));
    initialize(record);
    initialize(other);
    if add(record, never, SECONDARY_DUMP_DATA) != 1 {
        return Err("an empty record was not registered");
    }
    // SAFETY: static storage of the tests' own.
    let (routine, reason, name, checksum) = unsafe {
        (
            (&raw const (*record).CallbackRoutine).read(),
            (&raw const (*record).Reason).read(),
            (&raw const (*record).Component).read(),
            (&raw const (*record).Checksum).read(),
        )
    };
    let address = never as *const () as usize;
    if routine.map(|routine| routine as usize) != Some(address)
        || reason != SECONDARY_DUMP_DATA
        || name != component()
        || state(record) != BUFFER_INSERTED
    {
        return Err("a registered record does not hold what it was registered with");
    }
    if checksum
        != address
            .wrapping_add(SECONDARY_DUMP_DATA as usize)
            .wrapping_add(name.addr())
    {
        return Err("a registered record's checksum is not Windows'");
    }
    if add(record, never, SECONDARY_DUMP_DATA) != 0 {
        return Err("a registered record was registered again");
    }
    // A driver that marks a linked record empty has not unlinked it.
    initialize(record);
    if add(record, never, SECONDARY_DUMP_DATA) != 0 {
        return Err("a record already in the list was linked a second time");
    }
    // SAFETY: static storage of the tests' own.
    unsafe { (&raw mut (*record).State).write(BUFFER_INSERTED) };
    if take_back(record) != 1 || state(record) != BUFFER_EMPTY {
        return Err("a registered record was not taken back");
    }
    if take_back(record) != 0 {
        return Err("a record was taken back twice");
    }
    if take_back(other) != 0 {
        return Err("a record never registered was taken back");
    }
    // Any reason is taken, one Windows does not define included.
    if add(other, never, 0x7FFF_FFFF) != 1 || take_back(other) != 1 {
        return Err("a record with an unknown reason was refused");
    }
    Ok(())
}

/// Triage-data callbacks are kept in the order they registered, behind
/// every other, which are kept newest first.
fn order() -> Result<(), &'static str> {
    let records = [slot(0), slot(1), slot(2), slot(3)];
    let reasons = [
        KB_CALLBACK_RESERVED1,
        KB_CALLBACK_RESERVED1,
        KB_CALLBACK_TRIAGE_DUMP_DATA,
        KB_CALLBACK_TRIAGE_DUMP_DATA,
    ];
    for (&record, reason) in records.iter().zip(reasons) {
        initialize(record);
        if add(record, never, reason) != 1 {
            return Err("an empty record was not registered");
        }
    }
    let next = |record: *mut Record| {
        // SAFETY: a registered record's links; nothing else registers
        // while the tests run.
        unsafe { (&raw const (*record).Entry.Flink).read() }
    };
    let entry = |record: *mut Record| record.cast::<LIST_ENTRY>();
    let in_order = next(records[1]) == entry(records[0])
        && next(records[0]) == entry(records[2])
        && next(records[2]) == entry(records[3]);
    // One taken out of the middle leaves its neighbours linked.
    let unlinked = take_back(records[0]) == 1 && next(records[1]) == entry(records[2]);
    let rest = [records[1], records[2], records[3]]
        .iter()
        .all(|&record| take_back(record) == 1);
    match (in_order, unlinked, rest) {
        (false, _, _) => Err("the records are not linked in Windows' order"),
        (_, false, _) => Err("taking a record back did not unlink it"),
        (_, _, false) => Err("a registered record was not taken back"),
        _ => Ok(()),
    }
}

/// `KeBugCheckEx` must stop the system with its code and parameters.
pub static BUGCHECK_EX: Group = Group {
    names: &["neg.bugcheck-ex"],
    run: bugcheck_ex,
    manual: true,
};

fn bugcheck_ex(_: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.bugcheck-ex");
    KeBugCheckEx(0xE2, 0x11, 0x22, 0x33, 0xFFFF_F880_0000_0044);
}

/// A stop must call the callbacks registered for the reasons Windows
/// calls without a crash dump, newest first and triage callbacks in
/// their own order, show them the stop, and call no others.
pub static BUGCHECK_CALLBACK: Group = Group {
    names: &["neg.bugcheck-callback"],
    run: bugcheck_callback,
    manual: true,
};

/// Calls of the `KbCallbackReserved1` routines: how many, and which
/// record each was for, a decimal digit per call.
static RESERVED_CALLS: AtomicU32 = AtomicU32::new(0);
static RESERVED_ORDER: AtomicU32 = AtomicU32::new(0);
/// Calls of the first triage routine, and what was wrong with one.
static TRIAGE_CALLS: AtomicU32 = AtomicU32::new(0);
static WRONG: AtomicU32 = AtomicU32::new(0);
/// Calls of routines that must not be called.
static OTHERS: AtomicU32 = AtomicU32::new(0);

/// The stop the callback test asks for.
const STOP: [usize; 5] = [0xE2, 0x1001, 0x1002, 0x1003, 0x1004];

/// Something a triage routine can name as its array of ranges.
static RANGES: [u64; 4] = [0; 4];

/// # Safety
/// Called as a bugcheck callback.
unsafe extern "C" fn reserved(reason: u32, record: *mut Record, data: *mut c_void, length: u32) {
    let which = (0..2).find(|&index| slot(index) == record);
    if reason != KB_CALLBACK_RESERVED1 || !data.is_null() || length != 0 || which.is_none() {
        WRONG.fetch_add(1, Ordering::Relaxed);
    }
    RESERVED_CALLS.fetch_add(1, Ordering::Relaxed);
    let digit = which.map_or(9, |index| index as u32 + 1);
    // One processor runs: nothing else changes it in between.
    let order = RESERVED_ORDER.load(Ordering::Relaxed);
    RESERVED_ORDER.store(order * 10 + digit, Ordering::Relaxed);
}

/// What a triage routine is shown: the stop, as `KiBugCheckData` also
/// has it, and no ranges named yet.
///
/// # Safety
/// `data` is what a triage callback is called with.
unsafe fn triage_shown(reason: u32, data: *mut c_void, length: u32) -> bool {
    let data = data.cast::<KBUGCHECK_TRIAGE_DUMP_DATA>();
    // What a driver imports: five words at the variable's address.
    let exported = KiBugCheckData.address().cast::<[usize; 5]>();
    // SAFETY: per the contract; the exported words are the kernel's.
    unsafe {
        reason == KB_CALLBACK_TRIAGE_DUMP_DATA
            && length as usize == size_of::<KBUGCHECK_TRIAGE_DUMP_DATA>()
            && exported.read() == STOP
            && (*data).DataArray.is_null()
            && (*data).BugCheckCode as usize == STOP[0]
            && [
                (*data).BugCheckParameter1,
                (*data).BugCheckParameter2,
                (*data).BugCheckParameter3,
                (*data).BugCheckParameter4,
            ] == STOP[1..]
    }
}

/// The first triage routine names ranges.
///
/// # Safety
/// Called as a bugcheck callback.
unsafe extern "C" fn triage_first(
    reason: u32,
    record: *mut Record,
    data: *mut c_void,
    length: u32,
) {
    // SAFETY: per the contract.
    unsafe {
        if record != slot(5) || !triage_shown(reason, data, length) {
            WRONG.fetch_add(1, Ordering::Relaxed);
        }
        (&raw mut (*data.cast::<KBUGCHECK_TRIAGE_DUMP_DATA>()).DataArray)
            .write(RANGES.as_ptr().cast_mut().cast());
    }
    TRIAGE_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// The second triage routine is the last callback of the stop: it says
/// what was called before it.
///
/// # Safety
/// Called as a bugcheck callback.
unsafe extern "C" fn triage_last(reason: u32, record: *mut Record, data: *mut c_void, length: u32) {
    // SAFETY: per the contract.
    if record != slot(6) || !unsafe { triage_shown(reason, data, length) } {
        WRONG.fetch_add(1, Ordering::Relaxed);
    }
    // The records called so far are finished: the two called without
    // data, and the triage record that named ranges.
    let finished = [slot(0), slot(1), slot(5)]
        .iter()
        .filter(|&&record| state(record) == BUFFER_FINISHED)
        .count();
    kprintln!(
        "NK-STOP-CALLBACK reserved1={} order={} triage={} finished={} wrong={} others={}",
        RESERVED_CALLS.load(Ordering::Relaxed),
        RESERVED_ORDER.load(Ordering::Relaxed),
        TRIAGE_CALLS.load(Ordering::Relaxed),
        finished,
        WRONG.load(Ordering::Relaxed),
        OTHERS.load(Ordering::Relaxed),
    );
}

fn bugcheck_callback(r: &mut Report, _: &BootInfo) {
    for index in 0..RECORDS.len() {
        initialize(slot(index));
    }
    let registered = [
        // Called, the second before the first.
        add(slot(0), reserved, KB_CALLBACK_RESERVED1),
        add(slot(1), reserved, KB_CALLBACK_RESERVED1),
        // Not called: for a crash dump.
        add(slot(2), never, SECONDARY_DUMP_DATA),
        // Not called: taken back.
        add(slot(3), never, KB_CALLBACK_RESERVED1),
        // Not called: no longer what was registered.
        add(slot(4), never, KB_CALLBACK_RESERVED1),
        // Called in this order, after the others.
        add(slot(5), triage_first, KB_CALLBACK_TRIAGE_DUMP_DATA),
        add(slot(6), triage_last, KB_CALLBACK_TRIAGE_DUMP_DATA),
    ];
    // SAFETY: static storage of the tests' own.
    unsafe { (&raw mut (*slot(4)).Component).write(core::ptr::null_mut()) };
    if registered != [1; 7] || take_back(slot(3)) != 1 {
        return r.fail(
            "neg.bugcheck-callback",
            format_args!("the callbacks could not be registered"),
        );
    }
    kprintln!("NK-NEG-ARMED neg.bugcheck-callback");
    KeBugCheckEx(STOP[0] as u32, STOP[1], STOP[2], STOP[3], STOP[4]);
}
