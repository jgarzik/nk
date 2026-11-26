//! Tests of what a tracing driver asks of the kernel: registering as a
//! provider and writing events nobody listens to, the callbacks it
//! leaves for a bugcheck and the stop itself, and its questions about
//! the system (which modules are loaded, is a debugger there, which
//! version is this).
//!
//! Each test calls the exports as a driver does, through their
//! `extern "C"` signatures, with records and buffers of its own.

use crate::etw::{EtwRegister, EtwSetInformation, EtwUnregister, EtwWriteTransfer};
use crate::ex::sysinfo::{
    DbgkWerCaptureLiveKernelDump, MmIsDriverVerifying, NtQuerySystemInformation, PsGetVersion,
    RtlQueryModuleInformation,
};
use crate::ke::bugcheck::{
    KeBugCheckEx, KeDeregisterBugCheckReasonCallback, KeRegisterBugCheckReasonCallback,
    KiBugCheckData,
};
use crate::test::{Group, Report, Slot};
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::etw::{
    ETW_ENABLE_CALLBACK, EVENT_DATA_DESCRIPTOR, EVENT_DESCRIPTOR, EVENT_PROVIDER_SET_TRAITS,
    EVENT_PROVIDER_USE_DESCRIPTOR_TYPE, GUID, REGHANDLE,
};
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::ke::{
    BUFFER_EMPTY, BUFFER_FINISHED, BUFFER_INSERTED, KB_CALLBACK_RESERVED1,
    KB_CALLBACK_TRIAGE_DUMP_DATA, KBUGCHECK_REASON_CALLBACK_RECORD, KBUGCHECK_TRIAGE_DUMP_DATA,
    LIST_ENTRY,
};
use nk_ntabi::status::*;
use nk_ntabi::sysinfo::*;

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

// ---- questions about the system -------------------------------------------

pub static SYSTEM: Group = Group {
    names: &[
        "ex.sysinfo.basic",
        "ex.sysinfo.debugger",
        "ex.sysinfo.isolated-user-mode",
        "ex.sysinfo.class",
        "ex.sysinfo.modules",
        "ex.sysinfo.modules.short",
        "ex.sysinfo.driver",
        "rtl.module-information",
        "ps.version",
        "dbgk.live-dump",
    ],
    run: system,
    manual: false,
};

fn system(r: &mut Report, _: &BootInfo) {
    r.check("ex.sysinfo.basic", basic);
    r.check("ex.sysinfo.debugger", debugger);
    r.check("ex.sysinfo.isolated-user-mode", isolated_user_mode);
    r.check("ex.sysinfo.class", unknown_class);
    r.check("ex.sysinfo.modules", modules);
    r.check("ex.sysinfo.modules.short", modules_short);
    if crate::ldr::boot_file("sioctl.sys").is_some() {
        r.check("ex.sysinfo.driver", driver_listed);
    } else {
        r.skip(
            "ex.sysinfo.driver",
            format_args!("module sioctl.sys not provided"),
        );
    }
    r.check("rtl.module-information", module_information);
    r.check("ps.version", version);
    r.check("dbgk.live-dump", live_dump);
}

/// What a caller leaves in a buffer to see which bytes are written.
const FILL: u8 = 0xAA;
const FILLED: u32 = 0xAAAA_AAAA;

/// Ask for `class` into `buffer`, of which `length` bytes are offered:
/// the status and the length reported.
fn query(class: u32, buffer: &mut [u8], length: usize) -> (NTSTATUS, u32) {
    assert!(length <= buffer.len());
    let mut reported = FILLED;
    // SAFETY: a buffer at least as long as stated, and a length word.
    let status = unsafe {
        NtQuerySystemInformation(
            class,
            buffer.as_mut_ptr().cast(),
            length as u32,
            &raw mut reported,
        )
    };
    (status, reported)
}

fn u32_at(buffer: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(buffer[at..at + 4].try_into().expect("four bytes"))
}

fn u64_at(buffer: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(buffer[at..at + 8].try_into().expect("eight bytes"))
}

/// The basic information is what Windows reports of itself on these
/// machines, takes its exact length, and leaves padding alone.
fn basic() -> Result<(), &'static str> {
    let mut buffer = [FILL; 0x48];
    if query(SYSTEM_BASIC_INFORMATION_CLASS, &mut buffer, 0x40) != (STATUS_SUCCESS, 0x40) {
        return Err("the basic information was refused its own length");
    }
    let processors = buffer[0x38];
    if u32_at(&buffer, 0x08) != 0x1000
        || u32_at(&buffer, 0x18) != 0x1_0000
        || u64_at(&buffer, 0x20) != 0x1_0000
        || u64_at(&buffer, 0x28) != 0x7FFF_FFFE_FFFF
    {
        return Err("page size, granularity or the user range is not Windows'");
    }
    if usize::from(processors) != crate::ke::smp::online_count()
        || u64_at(&buffer, 0x30).count_ones() != u32::from(processors)
    {
        return Err("the processors reported are not the ones running");
    }
    let (pages, lowest, highest) = (
        u32_at(&buffer, 0x0C),
        u32_at(&buffer, 0x10),
        u32_at(&buffer, 0x14),
    );
    if pages == 0 || lowest > highest || u64::from(highest - lowest) + 1 < u64::from(pages) {
        return Err("the physical memory reported cannot be");
    }
    if u32_at(&buffer, 0x04) != crate::ke::time::KeQueryTimeIncrement() {
        return Err("the timer resolution is not the clock's increment");
    }
    // Padding inside and after the structure, and what follows it.
    if buffer[0x1C..0x20] != [FILL; 4] || buffer[0x39..] != [FILL; 0x0F] {
        return Err("bytes that are no field were written");
    }
    // Any other length is refused, and the length needed reported.
    for length in [0, 8, 0x3F, 0x41, 0x48] {
        let mut buffer = [FILL; 0x48];
        if query(SYSTEM_BASIC_INFORMATION_CLASS, &mut buffer, length)
            != (STATUS_INFO_LENGTH_MISMATCH, 0x40)
        {
            return Err("a wrong length was not refused with the length needed");
        }
        if buffer != [FILL; 0x48] {
            return Err("a refused query wrote to its buffer");
        }
    }
    Ok(())
}

/// Whether a kernel debugger is there: enabled and present, or neither.
fn debugger() -> Result<(), &'static str> {
    let attached = crate::kd::debugger_attached();
    let mut buffer = [FILL; 4];
    if query(SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS, &mut buffer, 4) != (STATUS_SUCCESS, 2) {
        return Err("the debugger information was refused a larger buffer");
    }
    if buffer != [u8::from(attached), u8::from(!attached), FILL, FILL] {
        return Err("the debugger information is not enabled-and-present or neither");
    }
    let mut buffer = [FILL; 4];
    if query(SYSTEM_KERNEL_DEBUGGER_INFORMATION_CLASS, &mut buffer, 1)
        != (STATUS_INFO_LENGTH_MISMATCH, 2)
        || buffer != [FILL; 4]
    {
        return Err("one byte was not refused");
    }
    Ok(())
}

/// No secure kernel: sixteen zero bytes, for exactly sixteen.
fn isolated_user_mode() -> Result<(), &'static str> {
    let mut buffer = [FILL; 24];
    if query(SYSTEM_ISOLATED_USER_MODE_INFORMATION_CLASS, &mut buffer, 16) != (STATUS_SUCCESS, 16) {
        return Err("the query was refused its own length");
    }
    if buffer[..16] != [0; 16] || buffer[16..] != [FILL; 8] {
        return Err("the answer is not sixteen zero bytes and no more");
    }
    for length in [8, 24] {
        let mut buffer = [FILL; 24];
        if query(
            SYSTEM_ISOLATED_USER_MODE_INFORMATION_CLASS,
            &mut buffer,
            length,
        ) != (STATUS_INFO_LENGTH_MISMATCH, 16)
            || buffer != [FILL; 24]
        {
            return Err("a wrong length was not refused");
        }
    }
    // With no length word, as msrpc.sys asks.
    let mut buffer = [FILL; 16];
    // SAFETY: a buffer of the length stated.
    let status = unsafe {
        NtQuerySystemInformation(
            SYSTEM_ISOLATED_USER_MODE_INFORMATION_CLASS,
            buffer.as_mut_ptr().cast(),
            16,
            core::ptr::null_mut(),
        )
    };
    if status != STATUS_SUCCESS || buffer != [0; 16] {
        return Err("the query failed without a length word");
    }
    Ok(())
}

/// A class NK does not answer is refused, and nothing is written.
fn unknown_class() -> Result<(), &'static str> {
    for class in [1, 5, 0xA6, 0xFFFF] {
        let mut buffer = [FILL; 16];
        if query(class, &mut buffer, 16) != (STATUS_INVALID_INFO_CLASS, FILLED)
            || buffer != [FILL; 16]
        {
            return Err("an unanswered class was not refused untouched");
        }
    }
    Ok(())
}

const ENTRY: usize = size_of::<RTL_PROCESS_MODULE_INFORMATION>();
const HEADER: usize = RTL_PROCESS_MODULES_HEADER;

/// A module of the class 11 list, by index: base, size, load order
/// index, and its path from the file name on.
fn entry(list: &[u8], index: usize) -> (u64, u32, u16, &[u8]) {
    let at = HEADER + index * ENTRY;
    let path = &list[at + 0x28..at + ENTRY];
    let name = usize::from(u16::from_le_bytes([list[at + 0x26], list[at + 0x27]]));
    let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    (
        u64_at(list, at + 0x10),
        u32_at(list, at + 0x18),
        u16::from_le_bytes([list[at + 0x20], list[at + 0x21]]),
        &path[name.min(end)..end],
    )
}

/// The whole list of loaded modules, as class 11 gives it.
fn module_list() -> Result<alloc::vec::Vec<u8>, &'static str> {
    let (status, needed) = query(SYSTEM_MODULE_INFORMATION_CLASS, &mut [], 0);
    if status != STATUS_INFO_LENGTH_MISMATCH || needed == 0 || needed == FILLED {
        return Err("no buffer did not report the length the module list needs");
    }
    let mut list = alloc::vec![FILL; needed as usize];
    if query(SYSTEM_MODULE_INFORMATION_CLASS, &mut list, needed as usize)
        != (STATUS_SUCCESS, needed)
    {
        return Err("the module list did not fit the length it asked for");
    }
    if needed as usize != HEADER + u32_at(&list, 0) as usize * ENTRY {
        return Err("the length is not that of the count and so many modules");
    }
    Ok(list)
}

/// The list begins with the kernel and `hal.dll`, as Windows' does, and
/// says where each module is.
fn modules() -> Result<(), &'static str> {
    let list = module_list()?;
    let count = u32_at(&list, 0) as usize;
    if count < 2 {
        return Err("fewer than two modules");
    }
    let (base, size, order, name) = entry(&list, 0);
    if name != b"ntoskrnl.exe" || order != 0 {
        return Err("the first module is not ntoskrnl.exe");
    }
    let here = modules as *const () as u64;
    if base != nk_bootinfo::KERNEL_BASE || !(base..base + u64::from(size)).contains(&here) {
        return Err("the kernel's entry is not where the kernel is");
    }
    if &list[HEADER + 0x28..HEADER + 0x28 + 34] != b"\\SystemRoot\\system32\\ntoskrnl.exe\0" {
        return Err("the kernel's path is not Windows'");
    }
    let (hal_base, hal_size, order, name) = entry(&list, 1);
    if name != b"hal.dll" || order != 1 || (hal_base, hal_size) != (base, size) {
        return Err("the second module is not hal.dll, at the kernel's range");
    }
    // What Windows does not write stays the caller's: the first two
    // pointers of an entry, and the path after its terminator.
    for index in 0..count {
        let at = HEADER + index * ENTRY;
        if list[at..at + 0x10] != [FILL; 0x10] || list[at + ENTRY - 1] != FILL {
            return Err("bytes of an entry that Windows leaves alone were written");
        }
    }
    Ok(())
}

/// A buffer too short gets the count of all the modules and the entries
/// that fit whole, and is told the length needed.
fn modules_short() -> Result<(), &'static str> {
    let whole = module_list()?;
    let needed = whole.len() as u32;
    let mut list = alloc::vec![FILL; whole.len()];
    // Room for the count and one entry, less than two.
    let room = HEADER + 2 * ENTRY - 1;
    if query(SYSTEM_MODULE_INFORMATION_CLASS, &mut list, room)
        != (STATUS_INFO_LENGTH_MISMATCH, needed)
    {
        return Err("a short buffer was not refused with the length needed");
    }
    if u32_at(&list, 0) != u32_at(&whole, 0) || entry(&list, 0).3 != b"ntoskrnl.exe" {
        return Err("a short buffer did not get the count and the first entry");
    }
    if list[HEADER + ENTRY..].iter().any(|&b| b != FILL) {
        return Err("an entry that does not fit was written in part");
    }
    // Less than the count itself: nothing.
    let mut list = [FILL; 8];
    if query(SYSTEM_MODULE_INFORMATION_CLASS, &mut list, 4) != (STATUS_INFO_LENGTH_MISMATCH, needed)
        || list != [FILL; 8]
    {
        return Err("a buffer shorter than the count was written");
    }
    Ok(())
}

/// How often the module list names a module with this base and file.
fn times_listed(base: u64, file: &[u8]) -> Result<usize, &'static str> {
    let list = module_list()?;
    Ok((0..u32_at(&list, 0) as usize)
        .map(|index| entry(&list, index))
        .filter(|&(at, _, _, name)| at == base && name.eq_ignore_ascii_case(file))
        .count())
}

/// A driver is in the list once, under its file's name, while loaded.
fn driver_listed() -> Result<(), &'static str> {
    use crate::io::service;
    service::create("SIoctl", "sioctl.sys").map_err(|_| "no service key")?;
    let object = service::start("SIoctl").map_err(|_| "load failed")?;
    // SAFETY: a driver object the kernel just made; the field is
    // written once, before the driver's entry point runs.
    let base = unsafe { (&raw const (*object).DriverStart).read() as u64 };
    let loaded = times_listed(base, b"sioctl.sys");
    let aux = aux_modules().map(|list| {
        list.iter()
            .filter(|module| module.0 == base && module.2.eq_ignore_ascii_case(b"sioctl.sys"))
            .count()
    });
    service::stop("SIoctl")?;
    if loaded? != 1 || aux? != 1 {
        return Err("a loaded driver is not in each list once");
    }
    if times_listed(base, b"sioctl.sys")? != 0 {
        return Err("an unloaded driver is still listed");
    }
    Ok(())
}

const AUX: usize = size_of::<AUX_MODULE_EXTENDED_INFO>();

/// Ask `RtlQueryModuleInformation` with `length` stated.
fn aux_query(length: &mut u32, size_per_module: u32, buffer: *mut u8) -> NTSTATUS {
    // SAFETY: the callers pass no buffer, or one of the length stated.
    unsafe { RtlQueryModuleInformation(length, size_per_module, buffer.cast()) }
}

/// A module as the auxiliary library reports it: base, size, file name.
type AuxModule = (u64, u32, alloc::vec::Vec<u8>);

/// Every module as the auxiliary library reports it.
fn aux_modules() -> Result<alloc::vec::Vec<AuxModule>, &'static str> {
    let mut length = 0;
    if aux_query(&mut length, AUX as u32, core::ptr::null_mut()) != STATUS_SUCCESS
        || length == 0
        || length as usize % AUX != 0
    {
        return Err("no buffer did not report a length of so many modules");
    }
    // Pool memory is aligned for a pointer, as the routine requires.
    let mut words = alloc::vec![0u64; length as usize / 8];
    let buffer = words.as_mut_ptr().cast::<u8>();
    let mut stated = length;
    if aux_query(&mut stated, AUX as u32, buffer) != STATUS_SUCCESS || stated != length {
        return Err("the modules did not fit the length asked for");
    }
    // SAFETY: the vector's own bytes.
    let bytes = unsafe { core::slice::from_raw_parts(buffer, length as usize) };
    Ok(bytes
        .as_chunks::<AUX>()
        .0
        .iter()
        .map(|module| {
            let path = &module[0x0E..0x0E + MODULE_PATH_LENGTH];
            let name = usize::from(u16::from_le_bytes([module[0x0C], module[0x0D]]));
            let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
            (
                u64_at(module, 0),
                u32_at(module, 8),
                path[name.min(end)..end].to_vec(),
            )
        })
        .collect())
}

/// `RtlQueryModuleInformation` reports the same modules, in its two
/// sizes, with Windows' statuses for the calls it refuses.
fn module_information() -> Result<(), &'static str> {
    let mut length = 0x4E4B;
    if aux_query(&mut length, 12, core::ptr::null_mut()) != STATUS_INVALID_PARAMETER_2
        || length != 0x4E4B
    {
        return Err("a size per module that is neither of the two was not refused");
    }
    let mut words = [0u64; 2 * AUX / 8];
    let buffer = words.as_mut_ptr().cast::<u8>();
    // SAFETY: one byte into the buffer, which is not dereferenced.
    if aux_query(&mut length, AUX as u32, unsafe { buffer.add(1) }) != STATUS_INVALID_PARAMETER_3
        || length != 0x4E4B
    {
        return Err("a misaligned buffer was not refused");
    }
    let modules = aux_modules()?;
    let class_11 = module_list()?;
    if modules.len() != u32_at(&class_11, 0) as usize {
        return Err("the two lists differ in length");
    }
    for (index, (base, size, name)) in modules.iter().enumerate() {
        let (listed_base, listed_size, _, listed_name) = entry(&class_11, index);
        if (*base, *size, name.as_slice()) != (listed_base, listed_size, listed_name) {
            return Err("the two lists differ in a module");
        }
    }
    if modules[0].2 != b"ntoskrnl.exe" || modules[1].2 != b"hal.dll" {
        return Err("the list does not begin with ntoskrnl.exe and hal.dll");
    }
    // Room for one module of at least two: refused, with the length
    // needed, and nothing written.
    let needed = (modules.len() * AUX) as u32;
    let mut stated = AUX as u32;
    if aux_query(&mut stated, AUX as u32, buffer) != STATUS_BUFFER_TOO_SMALL
        || stated != needed
        || words != [0; 2 * AUX / 8]
    {
        return Err("a buffer for one module was not refused with the length needed");
    }
    // The short form: each module's base, eight bytes apiece.
    let mut bases = alloc::vec![0u64; modules.len() + 1];
    bases[modules.len()] = u64::from(FILLED);
    let mut stated = needed;
    if aux_query(&mut stated, 8, bases.as_mut_ptr().cast()) != STATUS_SUCCESS
        || stated as usize != modules.len() * 8
    {
        return Err("the short form was refused");
    }
    if bases[modules.len()] != u64::from(FILLED)
        || !modules
            .iter()
            .zip(&bases)
            .all(|(module, &base)| module.0 == base)
    {
        return Err("the short form is not each module's base and no more");
    }
    Ok(())
}

/// `PsGetVersion` gives the version `RtlGetVersion` gives, each part
/// only if asked for.
fn version() -> Result<(), &'static str> {
    let (mut major, mut minor, mut build) = (FILLED, FILLED, FILLED);
    let mut csd = UNICODE_STRING {
        Length: 0xAAAA,
        MaximumLength: 0xAAAA,
        Buffer: core::ptr::dangling_mut(),
    };
    // SAFETY: four writable locals.
    let checked =
        unsafe { PsGetVersion(&raw mut major, &raw mut minor, &raw mut build, &raw mut csd) };
    if checked != 0 || (major, minor, build) != crate::rtl::VERSION {
        return Err("the version is not the one RtlGetVersion reports");
    }
    if csd.Length != 0 {
        return Err("the service-pack string is not empty");
    }
    // As wpprecorder.sys asks: the major version alone.
    let mut major = FILLED;
    // SAFETY: one writable local; the others are not asked for.
    unsafe {
        PsGetVersion(
            &raw mut major,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    };
    if major != 10 {
        return Err("the major version alone was not given");
    }
    if MmIsDriverVerifying(core::ptr::null_mut()) != 0 {
        return Err("a driver is said to be verified, and there is no verifier");
    }
    Ok(())
}

/// A live dump cannot be taken: the answer is Windows' for a system
/// whose live-dump support has not started, and for a raised IRQL.
fn live_dump() -> Result<(), &'static str> {
    let name = [b'T', b'E', b'S', b'T', 0].map(u16::from);
    let capture = || {
        DbgkWerCaptureLiveKernelDump(
            name.as_ptr(),
            0x1D1,
            1,
            2,
            3,
            4,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            0,
        )
    };
    if capture() != STATUS_DEVICE_NOT_READY {
        return Err("a live dump was not refused as not ready");
    }
    let old = crate::ke::irql::raise(crate::ke::irql::DISPATCH_LEVEL);
    let raised = capture();
    crate::ke::irql::lower(old);
    if raised != STATUS_INVALID_LEVEL {
        return Err("a live dump asked for at DISPATCH_LEVEL was not refused for the level");
    }
    Ok(())
}

// ---- trace providers --------------------------------------------------------

pub static PROVIDERS: Group = Group {
    names: &[
        "etw.register",
        "etw.refused",
        "etw.handles",
        "etw.traits",
        "etw.descriptor-type",
        "etw.full",
    ],
    run: providers,
    manual: false,
};

fn providers(r: &mut Report, _: &BootInfo) {
    r.check("etw.register", provider_registers);
    r.check("etw.refused", registration_refused);
    r.check("etw.handles", stray_handles);
    r.check("etw.traits", provider_traits);
    r.check("etw.descriptor-type", descriptor_type);
    r.check("etw.full", table_full);
}

/// A provider of the tests' own, which no session anywhere enables.
static PROVIDER: GUID = GUID {
    Data1: 0x4E4B_E701,
    Data2: 0x41D7,
    Data3: 0x4E58,
    Data4: [0xA3, 0x0C, 0x5E, 0x7B, 0x19, 0xD2, 0x64, 0xF1],
};

/// How often the enable callback was called: never, with no session.
static ENABLE_CALLS: AtomicU32 = AtomicU32::new(0);

/// # Safety
/// Callable with anything.
unsafe extern "C" fn enable(
    _: *const GUID,
    _: u32,
    _: u8,
    _: u64,
    _: u64,
    _: *mut c_void,
    _: *mut c_void,
) {
    ENABLE_CALLS.fetch_add(1, Ordering::Relaxed);
}

/// Register the tests' provider: the status and the handle.
fn etw_register(callback: bool, context: *mut c_void) -> (NTSTATUS, REGHANDLE) {
    let mut handle = u64::from(FILLED);
    let callback = callback.then_some(enable as ETW_ENABLE_CALLBACK);
    // SAFETY: a GUID and a handle of the tests' own.
    let status = unsafe { EtwRegister(&raw const PROVIDER, callback, context, &raw mut handle) };
    (status, handle)
}

/// An event: id 1, level 4 (informational).
static EVENT: EVENT_DESCRIPTOR = EVENT_DESCRIPTOR {
    Id: 1,
    Version: 0,
    Channel: 0,
    Level: 4,
    Opcode: 0,
    Task: 0,
    Keyword: 0,
};

/// Write the event with `data` to `handle`.
fn etw_write(handle: REGHANDLE, data: &[EVENT_DATA_DESCRIPTOR]) -> NTSTATUS {
    let pointer = if data.is_empty() {
        core::ptr::null()
    } else {
        data.as_ptr()
    };
    EtwWriteTransfer(
        handle,
        &raw const EVENT,
        core::ptr::null(),
        core::ptr::null(),
        data.len() as u32,
        pointer,
    )
}

fn etw_set(handle: REGHANDLE, class: u32, information: &[u8]) -> NTSTATUS {
    // SAFETY: a slice and its length.
    unsafe {
        EtwSetInformation(
            handle,
            class,
            information.as_ptr().cast(),
            information.len() as u32,
        )
    }
}

/// A provider registers, writes to nobody at any IRQL, and unregisters;
/// its enable callback is never called.
fn provider_registers() -> Result<(), &'static str> {
    let before = crate::etw::registered();
    let (status, handle) = etw_register(true, core::ptr::null_mut());
    if status != STATUS_SUCCESS || handle == 0 {
        return Err("a provider was not registered");
    }
    // The same provider may register again, and is a registration of
    // its own; so may one with neither callback nor context.
    let (status, second) = etw_register(false, core::ptr::null_mut());
    if status != STATUS_SUCCESS || second == 0 || second == handle {
        return Err("a second registration was not given a handle of its own");
    }
    if crate::etw::registered() != before + 2 {
        return Err("the registrations are not counted");
    }
    let value = 0x4E4Bu32;
    let data = [EVENT_DATA_DESCRIPTOR {
        Ptr: (&raw const value).addr() as u64,
        Size: 4,
        Reserved: 0,
    }];
    if etw_write(handle, &[]) != STATUS_SUCCESS || etw_write(handle, &data) != STATUS_SUCCESS {
        return Err("an event written to nobody was not taken");
    }
    // Events are written from anywhere: a DPC's level, and above.
    let old = crate::ke::irql::raise(crate::ke::irql::HIGH_LEVEL);
    let raised = etw_write(handle, &data);
    crate::ke::irql::lower(old);
    if raised != STATUS_SUCCESS {
        return Err("an event written at HIGH_LEVEL was not taken");
    }
    if EtwUnregister(handle) != STATUS_SUCCESS || EtwUnregister(second) != STATUS_SUCCESS {
        return Err("a provider was not unregistered");
    }
    if crate::etw::registered() != before {
        return Err("an unregistered provider is still counted");
    }
    if ENABLE_CALLS.load(Ordering::Relaxed) != 0 {
        return Err("the enable callback was called, and no session exists");
    }
    Ok(())
}

/// The registrations Windows refuses, and the handle left behind.
fn registration_refused() -> Result<(), &'static str> {
    let mut context = 0u8;
    let (status, handle) = etw_register(false, (&raw mut context).cast());
    if status != STATUS_INVALID_PARAMETER || handle != 0 {
        return Err("a context without a callback was not refused with a zero handle");
    }
    let security = GUID {
        Data1: 0x5484_9625,
        Data2: 0x5478,
        Data3: 0x4994,
        Data4: [0xA5, 0xBA, 0x3E, 0x3B, 0x03, 0x28, 0xC3, 0x0D],
    };
    let mut handle = u64::from(FILLED);
    // SAFETY: a GUID and a handle of the test's own.
    let status = unsafe {
        EtwRegister(
            &raw const security,
            Some(enable),
            core::ptr::null_mut(),
            &raw mut handle,
        )
    };
    if status != STATUS_ACCESS_DENIED || handle != 0 {
        return Err("the security auditing provider was not refused");
    }
    Ok(())
}

/// The provider's traits: its name, as nkc-etw gives them.
const TRAITS: [u8; 9] = [9, 0, b'N', b'k', b'c', b'E', b't', b'w', 0];

/// A handle of zero, and one whose registration has ended, name
/// nothing.
fn stray_handles() -> Result<(), &'static str> {
    if etw_set(0, EVENT_PROVIDER_SET_TRAITS, &TRAITS) != STATUS_INVALID_HANDLE
        || EtwUnregister(0) != STATUS_INVALID_HANDLE
        || etw_write(0, &[]) != STATUS_INVALID_HANDLE
    {
        return Err("a handle of zero was not refused by all three");
    }
    // The handle is looked at before the class.
    if etw_set(0, 0x7F, &TRAITS) != STATUS_INVALID_HANDLE {
        return Err("a handle of zero was not refused before the class");
    }
    let (_, handle) = etw_register(true, core::ptr::null_mut());
    if EtwUnregister(handle) != STATUS_SUCCESS {
        return Err("a provider was not unregistered");
    }
    // The slot is taken again by another registration: the old handle
    // still names nothing.
    let (_, next) = etw_register(true, core::ptr::null_mut());
    let stale = [
        etw_write(handle, &[]),
        etw_set(handle, EVENT_PROVIDER_SET_TRAITS, &TRAITS),
        etw_set(handle, EVENT_PROVIDER_USE_DESCRIPTOR_TYPE, &[1]),
    ];
    let live = etw_write(next, &[]);
    if EtwUnregister(next) != STATUS_SUCCESS {
        return Err("a provider was not unregistered");
    }
    if stale != [STATUS_INVALID_HANDLE; 3] {
        return Err("a handle whose registration has ended was taken");
    }
    if live != STATUS_SUCCESS {
        return Err("the registration that took the slot was refused");
    }
    Ok(())
}

/// Traits are checked as Windows checks them and set once.
fn provider_traits() -> Result<(), &'static str> {
    let (_, handle) = etw_register(true, core::ptr::null_mut());
    // SAFETY: no buffer, which is looked at before its length.
    let no_buffer =
        unsafe { EtwSetInformation(handle, EVENT_PROVIDER_SET_TRAITS, core::ptr::null(), 9) };
    let answers = [
        // A class there is not; and the two only user mode may set.
        etw_set(handle, 0x7F, &TRAITS),
        etw_set(handle, 0, &TRAITS),
        etw_set(handle, 1, &TRAITS),
        // Too short to be traits.
        etw_set(handle, EVENT_PROVIDER_SET_TRAITS, &TRAITS[..2]),
        no_buffer,
        // Long enough, and wrong: the size is not the length; the name
        // does not end.
        etw_set(handle, EVENT_PROVIDER_SET_TRAITS, &TRAITS[..8]),
        etw_set(handle, EVENT_PROVIDER_SET_TRAITS, &[5, 0, b'a', b'b', b'c']),
        // Set, and not a second time, whatever the second blob is.
        etw_set(handle, EVENT_PROVIDER_SET_TRAITS, &TRAITS),
        etw_set(handle, EVENT_PROVIDER_SET_TRAITS, &TRAITS),
        etw_set(handle, EVENT_PROVIDER_SET_TRAITS, &TRAITS[..8]),
    ];
    if EtwUnregister(handle) != STATUS_SUCCESS {
        return Err("a provider was not unregistered");
    }
    let expected = [
        STATUS_INVALID_DEVICE_REQUEST,
        STATUS_INVALID_DEVICE_REQUEST,
        STATUS_INVALID_DEVICE_REQUEST,
        STATUS_INVALID_PARAMETER,
        STATUS_INVALID_PARAMETER,
        STATUS_FILE_CORRUPT_ERROR,
        STATUS_FILE_CORRUPT_ERROR,
        STATUS_SUCCESS,
        STATUS_UNSUCCESSFUL,
        STATUS_UNSUCCESSFUL,
    ];
    if answers != expected {
        return Err("the answers to setting traits are not Windows'");
    }
    // A new registration starts without traits.
    let (_, handle) = etw_register(true, core::ptr::null_mut());
    let again = etw_set(handle, EVENT_PROVIDER_SET_TRAITS, &TRAITS);
    if EtwUnregister(handle) != STATUS_SUCCESS || again != STATUS_SUCCESS {
        return Err("a new registration could not set its traits");
    }
    Ok(())
}

/// The descriptor type is one byte, zero or one.
fn descriptor_type() -> Result<(), &'static str> {
    let (_, handle) = etw_register(true, core::ptr::null_mut());
    let answers = [
        etw_set(handle, EVENT_PROVIDER_USE_DESCRIPTOR_TYPE, &[1]),
        etw_set(handle, EVENT_PROVIDER_USE_DESCRIPTOR_TYPE, &[0]),
        etw_set(handle, EVENT_PROVIDER_USE_DESCRIPTOR_TYPE, &[2]),
        etw_set(handle, EVENT_PROVIDER_USE_DESCRIPTOR_TYPE, &[1, 0]),
        etw_set(handle, EVENT_PROVIDER_USE_DESCRIPTOR_TYPE, &[]),
    ];
    if EtwUnregister(handle) != STATUS_SUCCESS {
        return Err("a provider was not unregistered");
    }
    let expected = [
        STATUS_SUCCESS,
        STATUS_SUCCESS,
        STATUS_INVALID_PARAMETER,
        STATUS_INVALID_PARAMETER,
        STATUS_INVALID_PARAMETER,
    ];
    if answers != expected {
        return Err("the answers to setting the descriptor type are not Windows'");
    }
    Ok(())
}

/// Registrations run out with a status, and come back when given up.
fn table_full() -> Result<(), &'static str> {
    let mut handles = alloc::vec::Vec::new();
    let refusal = loop {
        let (status, handle) = etw_register(true, core::ptr::null_mut());
        if status != STATUS_SUCCESS {
            break (status, handle);
        }
        handles.push(handle);
        if handles.len() > 1 << 16 {
            break (STATUS_SUCCESS, 0);
        }
    };
    let count = handles.len();
    let ended = handles
        .drain(..)
        .all(|handle| EtwUnregister(handle) == STATUS_SUCCESS);
    if refusal != (STATUS_NO_MEMORY, 0) {
        return Err("registrations did not run out with STATUS_NO_MEMORY and a zero handle");
    }
    if !ended || count == 0 {
        return Err("the registrations were not all unregistered");
    }
    let (status, handle) = etw_register(true, core::ptr::null_mut());
    if status != STATUS_SUCCESS || EtwUnregister(handle) != STATUS_SUCCESS {
        return Err("no registration was possible after all were given up");
    }
    Ok(())
}

/// Unregistering a provider twice must stop the system: the handle is
/// no registration any more.
pub static UNREGISTER_TWICE: Group = Group {
    names: &["neg.etw-unregister-twice"],
    run: unregister_twice,
    manual: true,
};

fn unregister_twice(r: &mut Report, _: &BootInfo) {
    let (status, handle) = etw_register(true, core::ptr::null_mut());
    if status != STATUS_SUCCESS || EtwUnregister(handle) != STATUS_SUCCESS {
        return r.fail(
            "neg.etw-unregister-twice",
            format_args!("a provider could not be registered and unregistered"),
        );
    }
    kprintln!("NK-NEG-ARMED neg.etw-unregister-twice");
    EtwUnregister(handle);
    r.fail(
        "neg.etw-unregister-twice",
        format_args!("a provider was unregistered twice, and nothing happened"),
    );
}
