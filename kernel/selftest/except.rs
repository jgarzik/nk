//! Tests of exception dispatch and unwinding from the kernel's side.
//!
//! The frames a driver's compiled C would contribute are assembly
//! routines with real unwind information and scope tables
//! (`arch::seh_test`): a `__try`/`__except`, a `__try`/`__finally`, and
//! a function that overwrites every register a call preserves. The
//! tests stack them around NK's own frames the way driver frames lie
//! around a kernel routine that calls a driver back, raise at the top,
//! and check what ran, in what order, and what state came back.
//!
//! The same frames around bodies that fault check which processor
//! faults arrive as exceptions, with what record, and that a handler
//! which repairs the faulting code's context has it continue.

use crate::arch;
use crate::arch::seh_test::{
    Body, FAULTS, REGISTERS_LOST, SEED_SLOT, nk_seh_call, nk_seh_clobber, nk_seh_edge,
    nk_seh_finally, nk_seh_no_unwind, nk_seh_read, nk_seh_resume, nk_seh_try, nk_seh_write,
};
use crate::ke::dpc::{KeInitializeDpc, KeInsertQueueDpc};
use crate::ke::seh::{self, Guard, system_service};
use crate::ke::{irql, mutex};
use crate::test::{Group, Report, Slot};
use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::ke::KDPC;
use nk_ntabi::seh::EXCEPTION_POINTERS;

pub static GROUP: Group = Group {
    names: &[
        "seh.raise",
        "seh.decline",
        "seh.edge",
        "seh.finally",
        "seh.cross.region",
        "seh.cross.irql",
        "seh.cross.reference",
        "seh.cross.nested",
        "seh.fault.read",
        "seh.fault.write",
        "seh.fault.execute",
        "seh.fault.others",
        "seh.fault.continue",
        "seh.probe",
    ],
    run,
    manual: false,
};

/// A status of the tests' own.
pub(super) const CODE: u32 = 0xE04E_4B20;
/// `EXCEPTION_EXECUTE_HANDLER`, `EXCEPTION_CONTINUE_SEARCH`,
/// `EXCEPTION_CONTINUE_EXECUTION`. A filter told to answer the last
/// first repairs the context: see [`continue_test`].
pub(super) const ACCEPT: i32 = 1;
pub(super) const DECLINE: i32 = 0;
const CONTINUE: i32 = -1;

/// Events, in the order they happened. The low byte says more.
const FILTER: u32 = 0x100;
const FINALLY: u32 = 0x200;
const UNDO: u32 = 0x300;
/// A raise returned: never right.
const RETURNED: u32 = 0x400;

static TRACE: [AtomicU32; 8] = [const { AtomicU32::new(0) }; 8];
static EVENTS: AtomicUsize = AtomicUsize::new(0);
/// What the filter answers, by how often it has been asked.
static ANSWERS: [AtomicI32; 2] = [const { AtomicI32::new(0) }; 2];
static ASKED: AtomicUsize = AtomicUsize::new(0);
/// The code, parameter count and first two parameters of the record the
/// filter was last shown.
static SEEN_CODE: AtomicU32 = AtomicU32::new(0);
static SEEN_PARAMETERS: AtomicU32 = AtomicU32::new(0);
static SEEN_INFORMATION: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
/// What the filter last found where `nk_seh_try` keeps its seed, going
/// by the frame it was given.
static SEEN_SEED: AtomicU64 = AtomicU64::new(0);

fn note(event: u32) {
    let at = EVENTS.fetch_add(1, Ordering::Relaxed);
    if let Some(slot) = TRACE.get(at) {
        slot.store(event, Ordering::Relaxed);
    }
}

/// Start a test: nothing has happened, and the filter will answer
/// `answers` in turn.
pub(super) fn arm(answers: [i32; 2]) {
    EVENTS.store(0, Ordering::Relaxed);
    ASKED.store(0, Ordering::Relaxed);
    for (slot, answer) in ANSWERS.iter().zip(answers) {
        slot.store(answer, Ordering::Relaxed);
    }
}

/// Whether exactly `expected` happened, in that order.
fn happened(expected: &[u32]) -> bool {
    EVENTS.load(Ordering::Relaxed) == expected.len()
        && TRACE
            .iter()
            .zip(expected)
            .all(|(slot, event)| slot.load(Ordering::Relaxed) == *event)
}

/// The filter of `nk_seh_try`: note the record's flags, answer as told.
///
/// # Safety
/// Called by `__C_specific_handler` as a filter.
pub unsafe extern "C" fn filter(pointers: *mut EXCEPTION_POINTERS, frame: u64) -> i32 {
    // SAFETY: a filter's second argument is the frame of its function,
    // which is on the stack beneath and keeps its seed there.
    let seed = unsafe { ((frame + SEED_SLOT) as *const u64).read() };
    SEEN_SEED.store(seed, Ordering::Relaxed);
    // SAFETY: a filter's argument names the exception's record.
    let (code, flags, parameters, information) = unsafe {
        let record = (*pointers).ExceptionRecord;
        (
            (*record).ExceptionCode,
            (*record).ExceptionFlags,
            (*record).NumberParameters,
            (*record).ExceptionInformation,
        )
    };
    note(FILTER | flags);
    SEEN_CODE.store(code, Ordering::Relaxed);
    SEEN_PARAMETERS.store(parameters, Ordering::Relaxed);
    for (slot, value) in SEEN_INFORMATION.iter().zip(information) {
        slot.store(value, Ordering::Relaxed);
    }
    let asked = ASKED.fetch_add(1, Ordering::Relaxed);
    let answer = ANSWERS
        .get(asked)
        .map_or(DECLINE, |answer| answer.load(Ordering::Relaxed));
    if answer == CONTINUE {
        // SAFETY: a filter's argument names the context the faulting
        // code is to continue with, which is the filter's to change.
        let context = unsafe { &mut *(*pointers).ContextRecord.cast::<arch::seh::Context>() };
        arch::seh::repair(context, (&raw const REPAIRED).addr() as u64, MOVED);
    }
    answer
}

/// The `__finally` block of `nk_seh_finally`.
pub extern "C" fn finally(abnormal: u8, _frame: u64) {
    note(FINALLY | u32::from(abnormal));
}

/// A body that returns.
extern "C" fn nothing(_: usize) {}

/// Raise `code`, the way a driver calls `ExRaiseStatus`.
pub(super) extern "C" fn raise(code: usize) {
    // SAFETY: the routine takes any status.
    unsafe { arch::seh::nk_entry_ExRaiseStatus(code as i32) };
    note(RETURNED);
}

/// Raise as `ExRaiseAccessViolation` and `ExRaiseDatatypeMisalignment`
/// do: `which` picks.
extern "C" fn raise_named(which: usize) {
    // SAFETY: the routines take no arguments.
    unsafe {
        if which == 0 {
            arch::seh::nk_entry_ExRaiseAccessViolation();
        } else {
            arch::seh::nk_entry_ExRaiseDatatypeMisalignment();
        }
    }
    note(RETURNED);
}

/// Raise from under a frame that has changed every register a call
/// preserves.
extern "C" fn clobber_and_raise(code: usize) {
    // SAFETY: `raise` takes any argument.
    unsafe { nk_seh_clobber(raise, code) };
}

/// Raise from under a `__finally`.
extern "C" fn finally_around_raise(code: usize) {
    // SAFETY: as above.
    unsafe { nk_seh_finally(clobber_and_raise, code) };
}

/// A `__try` whose filter declines, around a raise.
extern "C" fn inner_try(code: usize) {
    // SAFETY: as above.
    unsafe { nk_seh_try(raise, code, 0x1111) };
}

/// The seed of the `__try` that [`caught_as`] makes.
const SEED: usize = 0x4E4B_0000;

/// Run `body(argument)` inside a `__try` and require that its `__except`
/// block got control with the exception code `code` and every preserved
/// register.
fn caught_as(body: Body, argument: usize, code: u32) -> Result<(), &'static str> {
    // SAFETY: the bodies of this file take any argument.
    match unsafe { nk_seh_try(body, argument, SEED) } as u32 {
        0 => Err("the body returned: nothing was raised, or the raise was swallowed"),
        REGISTERS_LOST => Err("the handler got control with a call-preserved register changed"),
        got if got == code => Ok(()),
        _ => Err("the handler was given another exception's code"),
    }
}

pub(super) fn caught(body: Body, argument: usize) -> Result<(), &'static str> {
    caught_as(body, argument, CODE)
}

/// A raise is offered to the filter with its record, and the handler
/// gets control with the code and the registers of its function.
fn raise_test() -> Result<(), &'static str> {
    arm([ACCEPT, DECLINE]);
    // SAFETY: `nothing` takes any argument.
    if unsafe { nk_seh_try(nothing, 0, 1) } != 0 || !happened(&[]) {
        return Err("a body that raises nothing did not simply return");
    }
    caught(clobber_and_raise, CODE as usize)?;
    if !happened(&[FILTER | 1]) {
        return Err("the filter was not asked exactly once, with a non-continuable record");
    }
    if SEEN_CODE.load(Ordering::Relaxed) != CODE || SEEN_PARAMETERS.load(Ordering::Relaxed) != 0 {
        return Err("the filter was shown another record");
    }
    if SEEN_SEED.load(Ordering::Relaxed) != SEED as u64 {
        return Err("the filter was not given the frame its function keeps its variables by");
    }
    // The two routines that raise a status of their own: no parameters,
    // unlike the memory fault one of them is named after.
    for (which, code) in [
        (0, seh::STATUS_ACCESS_VIOLATION),
        (1, seh::STATUS_DATATYPE_MISALIGNMENT),
    ] {
        arm([ACCEPT, DECLINE]);
        caught_as(raise_named, which, code)?;
        if !happened(&[FILTER | 1]) || SEEN_PARAMETERS.load(Ordering::Relaxed) != 0 {
            return Err("a named raise was not a non-continuable record without parameters");
        }
    }
    Ok(())
}

/// A filter that declines passes the exception to the next scope out.
fn decline_test() -> Result<(), &'static str> {
    arm([DECLINE, ACCEPT]);
    caught(inner_try, CODE as usize)?;
    if !happened(&[FILTER | 1, FILTER | 1]) {
        return Err("the inner and the outer filter were not each asked once");
    }
    Ok(())
}

/// Raise from a call at the very end of a guarded range, outside it by
/// the architecture's rule.
extern "C" fn raise_at_edge(code: usize) {
    // SAFETY: `raise` takes any argument.
    unsafe { nk_seh_edge(raise, code) };
}

/// A guarded range ends where its scope record says: a call just past
/// it is not guarded, however willing the scope's filter.
fn edge_test() -> Result<(), &'static str> {
    arm([ACCEPT, ACCEPT]);
    caught(raise_at_edge, CODE as usize)?;
    if !happened(&[FILTER | 1]) {
        return Err("a scope was asked about a call outside its range");
    }
    Ok(())
}

/// A `__finally` between the raise and the handler runs after every
/// filter and before the handler, as an abnormal termination; left by
/// falling off its `__try`, it runs as a normal one.
fn finally_test() -> Result<(), &'static str> {
    arm([ACCEPT, DECLINE]);
    caught(finally_around_raise, CODE as usize)?;
    if !happened(&[FILTER | 1, FINALLY | 1]) {
        return Err("not the filter, then the __finally block as an abnormal termination");
    }
    arm([DECLINE, DECLINE]);
    // SAFETY: `nothing` takes any argument.
    unsafe { nk_seh_finally(nothing, 0) };
    if !happened(&[FINALLY]) {
        return Err("a __finally left normally did not run once, as a normal termination");
    }
    Ok(())
}

/// What the kernel's frame holds across its call into the "driver" in
/// the crossing tests.
const REGION: usize = 1;
const IRQL: usize = 2;
const REFERENCE: usize = 3;
const OUTER: usize = 4;
/// Added to one of the above: the routine called does not raise.
const QUIET: usize = 0x100;

/// The reference the `REFERENCE` frame holds across its call.
static REFERENCES: AtomicU32 = AtomicU32::new(0);

/// # Safety
/// The thread is in a critical region `through_kernel` entered.
unsafe fn undo_region(_: *mut c_void) {
    note(UNDO | REGION as u32);
    mutex::KeLeaveCriticalRegion();
}

/// # Safety
/// `old` is the IRQL `through_kernel` raised from.
unsafe fn undo_irql(old: *mut c_void) {
    note(UNDO | IRQL as u32);
    arch::set_irql(old.addr() as u8);
}

/// # Safety
/// `through_kernel` holds a reference.
unsafe fn undo_reference(_: *mut c_void) {
    note(UNDO | REFERENCE as u32);
    REFERENCES.fetch_sub(1, Ordering::Relaxed);
}

/// # Safety
/// Callable at any time.
unsafe fn undo_outer(_: *mut c_void) {
    note(UNDO | OUTER as u32);
}

/// A kernel routine a driver calls, which calls a driver back while it
/// holds something: a critical region, as when a request is dispatched;
/// a raised IRQL, as around a routine run at `DISPATCH_LEVEL`; a
/// reference, as a queued work item holds its device; or, for `OUTER`,
/// while it calls another such routine. The driver called raises from
/// under a `__finally` of its own, unless `kind` says `QUIET`.
extern "C" fn through_kernel(kind: usize) {
    let callee: Body = if kind & QUIET != 0 {
        nothing
    } else {
        finally_around_raise
    };
    let call = |guard: &Guard, callee: Body, argument: usize| {
        // SAFETY: the bodies of this file take any argument.
        unsafe { seh::call(callee as usize, [argument, 0, 0, 0], guard) };
    };
    match kind & !QUIET {
        REGION => {
            mutex::KeEnterCriticalRegion();
            let guard = Guard::Undo {
                undo: undo_region,
                context: core::ptr::null_mut(),
            };
            call(&guard, callee, CODE as usize);
            mutex::KeLeaveCriticalRegion();
        }
        IRQL => {
            let old = irql::raise(irql::DISPATCH_LEVEL);
            let guard = Guard::Undo {
                undo: undo_irql,
                context: core::ptr::without_provenance_mut(usize::from(old)),
            };
            call(&guard, callee, CODE as usize);
            irql::lower(old);
        }
        REFERENCE => {
            REFERENCES.fetch_add(1, Ordering::Relaxed);
            let guard = Guard::Undo {
                undo: undo_reference,
                context: core::ptr::null_mut(),
            };
            call(&guard, callee, CODE as usize);
            REFERENCES.fetch_sub(1, Ordering::Relaxed);
        }
        _ => {
            let guard = Guard::Undo {
                undo: undo_outer,
                context: core::ptr::null_mut(),
            };
            call(&guard, through_kernel, REFERENCE | kind & QUIET);
        }
    }
}

/// What must hold again once a crossing is over, however it ended.
fn restored() -> Result<(), &'static str> {
    if mutex::KeAreApcsDisabled() != 0 {
        return Err("the thread is still in the kernel frame's critical region");
    }
    if irql::current() != irql::PASSIVE_LEVEL {
        // Not left raised for the tests after this one.
        arch::set_irql(irql::PASSIVE_LEVEL);
        return Err("the IRQL the kernel frame raised was not put back");
    }
    if REFERENCES.swap(0, Ordering::Relaxed) != 0 {
        return Err("the kernel frame's reference was not given back exactly once");
    }
    Ok(())
}

/// An exception raised beyond a kernel frame is handled by the
/// `__try` beneath it: the filter is asked first, then the raiser's
/// `__finally` runs, then the kernel frame's undo, once, and the
/// handler gets control with its registers and the kernel's state as
/// the frame found it. A call that returns runs no undo.
fn cross_test(kind: usize) -> Result<(), &'static str> {
    arm([ACCEPT, DECLINE]);
    // SAFETY: `through_kernel` takes any argument.
    if unsafe { nk_seh_try(through_kernel, kind | QUIET, 2) } != 0 || !happened(&[]) {
        return Err("a call that returned did not simply return");
    }
    restored()?;
    arm([ACCEPT, DECLINE]);
    let handled = caught(through_kernel, kind);
    restored()?;
    handled?;
    let undone = UNDO | kind as u32;
    let expected: &[u32] = if kind == OUTER {
        &[FILTER | 1, FINALLY | 1, UNDO | REFERENCE as u32, undone]
    } else {
        &[FILTER | 1, FINALLY | 1, undone]
    };
    if !happened(expected) {
        return Err("not the filter, the raiser's __finally, then each kernel frame's undo once");
    }
    Ok(())
}

/// An address in the lowest 64 KiB, where nothing is ever mapped.
const UNMAPPED: usize = 0x8000;

/// Read from under a frame that has changed every register a call
/// preserves.
extern "C" fn clobber_and_read(address: usize) {
    // SAFETY: the read is meant to fault.
    unsafe { nk_seh_clobber(nk_seh_read, address) };
}

/// Whether the filter was asked once, about an exception that may be
/// continued, with exactly `parameters`.
fn shown(parameters: &[u64]) -> bool {
    happened(&[FILTER])
        && SEEN_PARAMETERS.load(Ordering::Relaxed) as usize == parameters.len()
        && SEEN_INFORMATION
            .iter()
            .zip(parameters)
            .all(|(seen, wanted)| seen.load(Ordering::Relaxed) == *wanted)
}

/// A fault on an unmapped user address is an access violation the
/// `__try` around it handles: it may be continued, and says which kind
/// of access it was and where.
fn fault_test(body: Body, access: u64) -> Result<(), &'static str> {
    arm([ACCEPT, DECLINE]);
    caught_as(body, UNMAPPED, seh::STATUS_ACCESS_VIOLATION)?;
    if !shown(&[access, UNMAPPED as u64]) {
        return Err("the filter was not shown one continuable record with the access and address");
    }
    Ok(())
}

/// The architecture's other faults arrive as the exceptions Windows
/// makes of them. Returns how many kinds there are.
fn other_faults_test() -> Result<usize, &'static str> {
    for fault in FAULTS {
        arm([ACCEPT, DECLINE]);
        if let Err(why) = caught_as(fault.body, fault.argument, fault.code) {
            kprintln!("seh.fault.others: {}: {why}", fault.what);
            return Err("a fault did not arrive as its exception");
        }
        if !shown(fault.parameters) {
            kprintln!("seh.fault.others: {}", fault.what);
            return Err("a fault's record is not continuable, or has other parameters");
        }
    }
    Ok(FAULTS.len())
}

/// What the faulting read finds once its pointer is repaired.
static REPAIRED: AtomicU64 = AtomicU64::new(0x4E4B_600D);
/// How far down the repairing filter moves the stack pointer.
const MOVED: u64 = 32;
/// What the read returned, and how far the stack pointer had moved.
static READ: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// Read through `address`, and note the value and where the stack
/// pointer was right after.
extern "C" fn read_and_report(address: usize) {
    let mut value = 0;
    // SAFETY: the read is meant to fault; the routine writes one word.
    let dropped = unsafe { nk_seh_resume(address, &raw mut value) };
    READ.store(value, Ordering::Relaxed);
    DROPPED.store(dropped, Ordering::Relaxed);
}

/// A filter that changes the faulting code's context and answers
/// "continue" has the code go on with the context as changed: a
/// register (the pointer, now good) and the stack pointer.
fn continue_test() -> Result<(), &'static str> {
    // Asked a second time, the filter accepts: the fault came again.
    arm([CONTINUE, ACCEPT]);
    READ.store(0, Ordering::Relaxed);
    // SAFETY: the body takes any argument.
    if unsafe { nk_seh_try(read_and_report, UNMAPPED, 5) } != 0 || !shown(&[0, UNMAPPED as u64]) {
        return Err("the code did not go on after its filter said to continue");
    }
    if READ.load(Ordering::Relaxed) != REPAIRED.load(Ordering::Relaxed) {
        return Err("the code went on without the register its filter changed");
    }
    if DROPPED.load(Ordering::Relaxed) != MOVED {
        return Err("the code went on without the stack pointer its filter changed");
    }
    Ok(())
}

/// One call of `ProbeForRead` or `ProbeForWrite`, and what must come of
/// it: the exception's code, or zero if the probe is to return, and the
/// record's parameter count.
struct Probe {
    write: bool,
    address: u64,
    length: usize,
    alignment: u32,
    code: u32,
    parameters: u32,
}

/// A kernel address, an address in the never-mapped lowest 64 KiB, the
/// same misaligned, the first address past user space, and a mapped
/// user page.
const KERNEL: u64 = 0xFFFF_F800_0000_1000;
const LOW: u64 = UNMAPPED as u64;
const ODD: u64 = LOW + 1;
const LIMIT: u64 = crate::mm::user::USER_PROBE_ADDRESS;
const MAPPED: u64 = 0x4E4D_0000_0000;

const MISALIGNED: u32 = seh::STATUS_DATATYPE_MISALIGNMENT;
const VIOLATION: u32 = seh::STATUS_ACCESS_VIOLATION;

const fn probe(
    write: bool,
    address: u64,
    length: usize,
    alignment: u32,
    code: u32,
    parameters: u32,
) -> Probe {
    Probe {
        write,
        address,
        length,
        alignment,
        code,
        parameters,
    }
}

/// What Windows 10 does, as the conformance driver `nkc-seh` recorded
/// it there. A read probe refuses an address outside user space with a
/// memory fault's access violation (two parameters); a write probe,
/// with the one `ExRaiseAccessViolation` raises (none). Alignment is
/// looked at first, nothing at all for no bytes, and only a write probe
/// touches the range.
const PROBES: &[Probe] = &[
    probe(false, KERNEL, 4, 1, VIOLATION, 2),
    probe(false, ODD, 4, 4, MISALIGNED, 0),
    probe(false, KERNEL + 1, 4, 4, MISALIGNED, 0),
    probe(false, KERNEL, 0, 1, 0, 0),
    probe(false, ODD, 0, 4, 0, 0),
    probe(false, LOW, 16, 4, 0, 0),
    probe(false, LIMIT - 16, 16, 1, 0, 0),
    probe(false, LIMIT - 16, 17, 1, VIOLATION, 2),
    probe(false, LIMIT, 1, 1, VIOLATION, 2),
    probe(true, KERNEL, 4, 1, VIOLATION, 0),
    probe(true, ODD, 4, 4, MISALIGNED, 0),
    probe(true, KERNEL, 0, 1, 0, 0),
    probe(true, LIMIT - 16, 17, 1, VIOLATION, 0),
    probe(true, LOW, 4, 4, VIOLATION, 2),
    probe(true, MAPPED + 0xFF0, 0x1000, 1, 0, 0),
    // The second page of the range is the one that is not there.
    probe(true, MAPPED + 0x1FF0, 0x20, 1, VIOLATION, 2),
];

/// Make the probe `PROBES[index]`, the way a driver calls it.
extern "C" fn probe_body(index: usize) {
    let p = &PROBES[index];
    let address = core::ptr::without_provenance_mut(p.address as usize);
    // SAFETY: the routines take any arguments.
    unsafe {
        if p.write {
            arch::seh::nk_entry_ProbeForWrite(address, p.length, p.alignment);
        } else {
            arch::seh::nk_entry_ProbeForRead(address, p.length, p.alignment);
        }
    }
}

/// `ProbeForRead` and `ProbeForWrite` return or raise as on Windows.
/// Returns how many probes were made.
fn probe_test() -> Result<usize, &'static str> {
    crate::mm::user::map_pages(MAPPED, 2).map_err(|_| "cannot map user pages")?;
    let mut verdict = Ok(PROBES.len());
    for (index, p) in PROBES.iter().enumerate() {
        arm([ACCEPT, DECLINE]);
        // SAFETY: the body takes an index into the table.
        let code = unsafe { nk_seh_try(probe_body, index, 8) } as u32;
        // A fault's exception may be continued; a raised one may not.
        let flags = u32::from(p.parameters == 0);
        let raised = p.code == 0
            || (happened(&[FILTER | flags])
                && SEEN_PARAMETERS.load(Ordering::Relaxed) == p.parameters);
        if code != p.code || !raised {
            kprintln!(
                "seh.probe: probe {index} at {:#x}: code {code:#x}, {} parameters",
                p.address,
                SEEN_PARAMETERS.load(Ordering::Relaxed)
            );
            verdict = Err("a probe did not return or raise as on Windows");
            break;
        }
    }
    crate::mm::user::unmap_pages(MAPPED, 2);
    verdict
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("seh.raise", raise_test);
    r.check("seh.decline", decline_test);
    r.check("seh.edge", edge_test);
    r.check("seh.finally", finally_test);
    r.check("seh.cross.region", || cross_test(REGION));
    r.check("seh.cross.irql", || cross_test(IRQL));
    r.check("seh.cross.reference", || cross_test(REFERENCE));
    r.check("seh.cross.nested", || cross_test(OUTER));
    r.check("seh.fault.read", || {
        fault_test(clobber_and_read, seh::ACCESS_READ)
    });
    r.check("seh.fault.write", || {
        fault_test(nk_seh_write, seh::ACCESS_WRITE)
    });
    r.check("seh.fault.execute", || {
        fault_test(nk_seh_call, seh::ACCESS_EXECUTE)
    });
    match other_faults_test() {
        Ok(kinds) => r.ok_with("seh.fault.others", format_args!("{kinds} kinds")),
        Err(why) => r.fail("seh.fault.others", format_args!("{why}")),
    }
    r.check("seh.fault.continue", continue_test);
    match probe_test() {
        Ok(cases) => r.ok_with("seh.probe", format_args!("{cases} probes")),
        Err(why) => r.fail("seh.probe", format_args!("{why}")),
    }
}

// ---- exceptions nothing handles: each ends the boot ---------------------

/// An exception raised in a system thread with no handler beneath
/// stops the system as Windows does.
pub static THREAD: Group = Group {
    names: &["neg.seh-thread"],
    run: unhandled_in_thread,
    manual: true,
};

fn unhandled_in_thread(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.seh-thread");
    raise(CODE as usize + 1);
    r.fail(
        "neg.seh-thread",
        format_args!("an unhandled raise returned"),
    );
}

/// So does one raised while a system service is served for user mode,
/// with that bugcheck.
pub static SERVICE: Group = Group {
    names: &["neg.seh-service"],
    run: unhandled_in_service,
    manual: true,
};

fn unhandled_in_service(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.seh-service");
    system_service(|| raise(CODE as usize + 2));
    r.fail(
        "neg.seh-service",
        format_args!("an unhandled raise returned"),
    );
}

/// And one raised in a DPC routine, with that one: the `__try` of the
/// code the DPC interrupted is not asked.
pub static DPC: Group = Group {
    names: &["neg.seh-dpc"],
    run: unhandled_in_dpc,
    manual: true,
};

/// A body: queue a DPC that raises.
extern "C" fn queue_raising_dpc(_: usize) {
    /// # Safety
    /// Called as a DPC routine; it dereferences none of its arguments.
    unsafe extern "C" fn routine(_: *mut KDPC, _: *mut c_void, _: *mut c_void, _: *mut c_void) {
        raise(CODE as usize + 3);
    }
    static RAISING: Slot<KDPC> = Slot::new();
    // SAFETY: static storage for a `KDPC`, not queued.
    unsafe {
        KeInitializeDpc(RAISING.ptr(), Some(routine), core::ptr::null_mut());
        KeInsertQueueDpc(RAISING.ptr(), core::ptr::null_mut(), core::ptr::null_mut());
    }
}

fn unhandled_in_dpc(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.seh-dpc");
    arm([ACCEPT, ACCEPT]);
    // SAFETY: the body takes any argument.
    let code = unsafe { nk_seh_try(queue_raising_dpc, 0, 3) };
    r.fail(
        "neg.seh-dpc",
        format_args!("a raise in a DPC routine was survived: the __try around the queueing returned {code:#x}"),
    );
}

/// A frame with no unwind entry between the raise and a handler cannot
/// be crossed: the system stops and names it, however willing the
/// handler beneath.
pub static NO_ENTRY: Group = Group {
    names: &["neg.seh-no-entry"],
    run: no_unwind_entry,
    manual: true,
};

/// A body: raise from under a function with no unwind entry.
extern "C" fn raise_past_no_unwind(code: usize) {
    // SAFETY: `raise` takes any argument.
    unsafe { nk_seh_no_unwind(raise, code) };
}

fn no_unwind_entry(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.seh-no-entry");
    arm([ACCEPT, ACCEPT]);
    // SAFETY: the body takes any argument.
    let code = unsafe { nk_seh_try(raise_past_no_unwind, CODE as usize + 4, 4) };
    r.fail(
        "neg.seh-no-entry",
        format_args!("the walk passed a function with no unwind entry: the handler got {code:#x}"),
    );
}

/// A fault on a kernel address is no exception: the `__try` around the
/// access is not asked, and the system stops with Windows' bugcheck.
pub static KERNEL_FAULT: Group = Group {
    names: &["neg.seh-kernel-fault"],
    run: kernel_fault,
    manual: true,
};

fn kernel_fault(r: &mut Report, _: &BootInfo) {
    // Address space that is reserved but has nothing mapped in it.
    let Some(va) = crate::mm::map::alloc_va(1) else {
        return r.fail(
            "neg.seh-kernel-fault",
            format_args!("no kernel address space"),
        );
    };
    kprintln!("NK-NEG-ARMED neg.seh-kernel-fault");
    arm([ACCEPT, ACCEPT]);
    // SAFETY: the read is meant to fault.
    let code = unsafe { nk_seh_try(nk_seh_read, va as usize, 6) };
    r.fail(
        "neg.seh-kernel-fault",
        format_args!("a read of unmapped kernel memory was survived: the __try returned {code:#x}"),
    );
}

/// Nor is a fault at `DISPATCH_LEVEL`, wherever the address.
pub static FAULT_AT_DISPATCH: Group = Group {
    names: &["neg.seh-fault-at-dispatch"],
    run: fault_at_dispatch,
    manual: true,
};

fn fault_at_dispatch(r: &mut Report, _: &BootInfo) {
    kprintln!("NK-NEG-ARMED neg.seh-fault-at-dispatch");
    arm([ACCEPT, ACCEPT]);
    let old = irql::raise(irql::DISPATCH_LEVEL);
    // SAFETY: the read is meant to fault.
    let code = unsafe { nk_seh_try(nk_seh_read, UNMAPPED, 7) };
    irql::lower(old);
    r.fail(
        "neg.seh-fault-at-dispatch",
        format_args!("a fault at DISPATCH_LEVEL was survived: the __try returned {code:#x}"),
    );
}
