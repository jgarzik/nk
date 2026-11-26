//! Tests of device interrupts, made as a driver makes them: a device
//! that really interrupts (`arch::InterruptTestSource`), connected
//! through `IoConnectInterruptEx`, with the Plug and Play manager's part
//! (translating the device's interrupt and telling `io::interrupt` of
//! it) played by the test.

use crate::arch::{self, InterruptTestSource};
use crate::hal::interrupt::{self as routing, Line, Polarity, Raw, Translated, Trigger};
use crate::io::interrupt::{
    self as device, IoConnectInterruptEx, IoDisconnectInterruptEx, IoReportInterruptActive,
    IoReportInterruptInactive, Resource,
};
use crate::ke::kinterrupt::{
    self, IoGetAffinityInterrupt, KeAcquireInterruptSpinLock, KeReleaseInterruptSpinLock,
    KeSynchronizeExecution,
};
use crate::ke::kspin::KeGetCurrentIrql;
use crate::ke::{self, irql};
use crate::test::{Group, Report};
use core::ffi::c_void;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::interrupt::*;
use nk_ntabi::io::DEVICE_OBJECT;
use nk_ntabi::ke::KSPIN_LOCK;
use nk_ntabi::status::{
    NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_NO_SUCH_DEVICE, STATUS_NOT_FOUND,
    STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
};

pub static GROUP: Group = Group {
    names: &[
        "hal.interrupt.translate",
        "io.interrupt.line",
        "io.interrupt.synchronize",
        "io.interrupt.shared",
        "io.interrupt.message",
        "io.interrupt.refused",
    ],
    run,
    manual: false,
};

const ALL_PROCESSORS: u64 = u64::MAX;

/// What a test's service routine is given: the device it serves and
/// what it saw.
struct Served<'a> {
    source: Option<&'a InterruptTestSource>,
    /// Whether the routine claims its device's interrupts.
    claims: bool,
    /// Whether it serves the device even when it does not claim.
    quiets: bool,
    calls: AtomicU32,
    served: AtomicU32,
    irql: AtomicU32,
    /// Whether the interrupt object's lock was held, every time.
    unlocked: AtomicU32,
    processor: AtomicUsize,
    /// The last message number, for a message's routine.
    message: AtomicU32,
}

impl<'a> Served<'a> {
    fn new(source: Option<&'a InterruptTestSource>, claims: bool) -> Self {
        Self {
            source,
            claims,
            quiets: false,
            calls: AtomicU32::new(0),
            served: AtomicU32::new(0),
            irql: AtomicU32::new(u32::MAX),
            unlocked: AtomicU32::new(0),
            processor: AtomicUsize::new(usize::MAX),
            message: AtomicU32::new(u32::MAX),
        }
    }

    fn context(&self) -> *mut c_void {
        core::ptr::from_ref(self).cast_mut().cast()
    }

    fn served(&self) -> u32 {
        self.served.load(Ordering::Relaxed)
    }

    fn calls(&self) -> u32 {
        self.calls.load(Ordering::Relaxed)
    }

    /// What every service routine does on entry.
    ///
    /// # Safety
    /// `interrupt` is the object the routine was called for.
    unsafe fn entered(&self, interrupt: *mut KINTERRUPT) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.irql
            .store(u32::from(KeGetCurrentIrql()), Ordering::Relaxed);
        // SAFETY: per the contract; the lock word is read atomically.
        let lock = unsafe { AtomicUsize::from_ptr((*interrupt).ActualLock) };
        if lock.load(Ordering::Relaxed) == 0 {
            self.unlocked.fetch_add(1, Ordering::Relaxed);
        }
        self.processor
            .store(ke::pcr::current_processor() as usize, Ordering::Relaxed);
    }
}

/// A line's service routine.
///
/// # Safety
/// Called for an interrupt object connected with a `Served` as context.
unsafe extern "C" fn serve(interrupt: *mut KINTERRUPT, context: *mut c_void) -> u8 {
    // SAFETY: the context is the `Served` the test connected with,
    // which outlives the connection.
    let served = unsafe { &*context.cast::<Served<'_>>() };
    // SAFETY: called for this object.
    unsafe { served.entered(interrupt) };
    let Some(source) = served.source else {
        return 0;
    };
    if !served.claims {
        if served.quiets {
            source.quiet();
        }
        return 0;
    }
    if !source.asking() {
        return 0;
    }
    source.quiet();
    served.served.fetch_add(1, Ordering::Relaxed);
    1
}

/// A message's service routine.
///
/// # Safety
/// As [`serve`].
unsafe extern "C" fn serve_message(
    interrupt: *mut KINTERRUPT,
    context: *mut c_void,
    message: u32,
) -> u8 {
    // SAFETY: as in `serve`.
    let served = unsafe { &*context.cast::<Served<'_>>() };
    // SAFETY: called for this object.
    unsafe { served.entered(interrupt) };
    served.message.store(message, Ordering::Relaxed);
    served.served.fetch_add(1, Ordering::Relaxed);
    1
}

/// Wait up to two seconds for `done`.
fn wait_for(done: impl Fn() -> bool) -> bool {
    for _ in 0..20_000 {
        if done() {
            return true;
        }
        ke::time::stall(100);
    }
    done()
}

/// Long enough for an interrupt that is going to arrive to arrive.
fn settle() {
    ke::time::stall(20_000);
}

/// Stands for a physical device object: `io::interrupt` knows devices
/// by address alone.
fn device_object(which: &'static u8) -> *mut DEVICE_OBJECT {
    core::ptr::from_ref(which).cast_mut().cast()
}

static DEVICE_A: u8 = 0;
static DEVICE_B: u8 = 0;

/// Connection parameters of `version`, with `member` as the union.
fn parameters<T>(version: u32, member: T) -> IO_CONNECT_INTERRUPT_PARAMETERS {
    let mut parameters = MaybeUninit::<IO_CONNECT_INTERRUPT_PARAMETERS>::zeroed();
    // SAFETY: zero is a valid value of every field; the member is one
    // of the union's, which begins at `UNION` and holds the largest.
    unsafe {
        assert!(size_of::<T>() <= size_of::<IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS>());
        parameters
            .as_mut_ptr()
            .byte_add(IO_CONNECT_INTERRUPT_PARAMETERS::UNION)
            .cast::<T>()
            .write(member);
        (*parameters.as_mut_ptr()).Version = version;
        parameters.assume_init()
    }
}

/// Connect fully specified, sharing the vector.
fn connect_fully(
    translated: Translated,
    synchronize_irql: u8,
    share: bool,
    served: &Served<'_>,
    lock: *mut KSPIN_LOCK,
) -> Result<*mut KINTERRUPT, NTSTATUS> {
    let mut interrupt = core::ptr::null_mut();
    let mut p = parameters(
        CONNECT_FULLY_SPECIFIED,
        IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS {
            PhysicalDeviceObject: device_object(&DEVICE_A),
            InterruptObject: &raw mut interrupt,
            ServiceRoutine: Some(serve),
            ServiceContext: served.context(),
            SpinLock: lock,
            SynchronizeIrql: synchronize_irql,
            FloatingSave: 0,
            ShareVector: u8::from(share),
            Vector: translated.vector,
            Irql: translated.level,
            InterruptMode: Trigger::Level.mode(),
            ProcessorEnableMask: translated.affinity as usize,
            Group: 0,
        },
    );
    // SAFETY: the parameters are whole and their pointers live.
    match unsafe { IoConnectInterruptEx(&raw mut p) } {
        STATUS_SUCCESS => Ok(interrupt),
        status => Err(status),
    }
}

/// Disconnect what was connected as `version`.
fn disconnect(version: u32, context: *mut c_void) {
    let mut p = IO_DISCONNECT_INTERRUPT_PARAMETERS {
        Version: version,
        ConnectionContext: context,
    };
    // SAFETY: the context is a live connection of that version.
    unsafe { IoDisconnectInterruptEx(&raw mut p) };
}

/// The translation of a line is a vector at a device IRQL on one
/// running processor; a line translated twice has one vector; a line
/// cannot signal two ways. Returns the vector and IRQL.
fn translate(line: Line) -> Result<(u32, u8), &'static str> {
    let first = routing::translate(Raw::Line(line), ALL_PROCESSORS)
        .map_err(|_| "the line was not translated")?;
    let check = || {
        if !(3..=11).contains(&first.level) {
            return Err("the IRQL is not a device IRQL");
        }
        if first.affinity.count_ones() != 1 || first.affinity & ke::smp::online() == 0 {
            return Err("the affinity is not one running processor");
        }
        let info = routing::info(first.vector).ok_or("the vector is not known")?;
        if info.line != Some(line) || info.level != first.level {
            return Err("the vector is not known as the line's");
        }
        if crate::hal::query::HalConvertDeviceIdtToIrql(first.vector) != first.level {
            return Err("HalConvertDeviceIdtToIrql is not the IRQL of the vector's translation");
        }
        if routing::message(first.vector).is_some() {
            return Err("a line has a message");
        }
        let again = routing::translate(Raw::Line(line), ALL_PROCESSORS);
        if again.is_ok() {
            routing::release(first.vector);
        }
        if again != Ok(first) {
            return Err("a line translated twice has two translations");
        }
        let other = Line {
            trigger: match line.trigger {
                Trigger::Level => Trigger::Edge,
                Trigger::Edge => Trigger::Level,
            },
            ..line
        };
        if routing::translate(Raw::Line(other), ALL_PROCESSORS) != Err(STATUS_INVALID_PARAMETER) {
            return Err("a line was translated as signalling two ways");
        }
        Ok((first.vector, first.level))
    };
    let verdict = check();
    routing::release(first.vector);
    if verdict.is_ok() && routing::info(first.vector).is_some() {
        return Err("the vector outlived its translations");
    }
    verdict
}

/// A line-based connection: the device interrupts, its routine runs at
/// the interrupt's IRQL with the object's lock held on the processor
/// the interrupt is sent to, every time it asks; disconnected, the
/// device asks and nothing hears.
fn line(source: &InterruptTestSource) -> Result<(u32, u8, usize), &'static str> {
    let translated = routing::translate(Raw::Line(source.line()), ALL_PROCESSORS)
        .map_err(|_| "the line was not translated")?;
    let pdo = device_object(&DEVICE_A);
    let resource = Resource {
        translated,
        message: false,
        shared: true,
    };
    let served = Served::new(Some(source), true);
    let check = || {
        if !device::assign(pdo, &[resource]) {
            return Err("no memory for the device's interrupts");
        }
        let mut interrupt: *mut KINTERRUPT = core::ptr::null_mut();
        let mut p = parameters(
            CONNECT_LINE_BASED,
            IO_CONNECT_INTERRUPT_LINE_BASED_PARAMETERS {
                PhysicalDeviceObject: pdo,
                InterruptObject: &raw mut interrupt,
                ServiceRoutine: Some(serve),
                ServiceContext: served.context(),
                SpinLock: core::ptr::null_mut(),
                SynchronizeIrql: 0,
                FloatingSave: 0,
            },
        );
        // SAFETY: the parameters are whole and their pointers live.
        if unsafe { IoConnectInterruptEx(&raw mut p) } != STATUS_SUCCESS || interrupt.is_null() {
            return Err("IoConnectInterruptEx failed");
        }
        let inner = || {
            // SAFETY: a connected interrupt object.
            unsafe {
                if (*interrupt).Vector != translated.vector
                    || (*interrupt).Irql != translated.level
                    || (*interrupt).SynchronizeIrql != translated.level
                    || (*interrupt).ActualLock != &raw mut (*interrupt).SpinLock
                    || (*interrupt).Connected == 0
                    || (*interrupt).Type != INTERRUPT_OBJECT
                {
                    return Err("the interrupt object does not say what was connected");
                }
                let mut affinity = MaybeUninit::<GROUP_AFFINITY>::zeroed().assume_init();
                if IoGetAffinityInterrupt(interrupt, &raw mut affinity) != STATUS_SUCCESS
                    || affinity.Mask as u64 != translated.affinity
                    || affinity.Group != 0
                {
                    return Err("IoGetAffinityInterrupt is not the translated affinity");
                }
            }
            for round in 1..=2 {
                source.fire();
                if !wait_for(|| served.served() == round) {
                    return Err("the service routine did not run");
                }
            }
            if served.irql.load(Ordering::Relaxed) != u32::from(translated.level) {
                return Err("the service routine did not run at the interrupt's IRQL");
            }
            if served.unlocked.load(Ordering::Relaxed) != 0 {
                return Err("the service routine ran without the interrupt's lock");
            }
            let processor = served.processor.load(Ordering::Relaxed);
            if 1u64 << processor != translated.affinity {
                return Err("the interrupt arrived on another processor than its affinity's");
            }
            if irql::current() != irql::PASSIVE_LEVEL {
                return Err("the IRQL did not come back down");
            }
            Ok(processor)
        };
        let verdict = inner();
        disconnect(CONNECT_LINE_BASED, interrupt.cast());
        let processor = verdict?;
        // The device asks; nothing is connected to hear it.
        let before = served.calls();
        source.fire();
        settle();
        let (asking, after) = (source.asking(), served.calls());
        source.quiet();
        if !asking || after != before {
            return Err("a disconnected service routine was called");
        }
        Ok((translated.vector, translated.level, processor))
    };
    let verdict = check();
    device::withdraw(pdo);
    routing::release(translated.vector);
    verdict
}

/// What the routine run by `KeSynchronizeExecution` is given and finds.
struct Synchronized<'a> {
    source: &'a InterruptTestSource,
    served: &'a Served<'a>,
    lock: *const KSPIN_LOCK,
    irql: AtomicU32,
    locked: AtomicU32,
    served_during: AtomicU32,
}

/// Make the device ask and wait: its service routine must not run while
/// this does.
///
/// # Safety
/// `context` is a `Synchronized` that lives for the call.
unsafe extern "C" fn synchronized(context: *mut c_void) -> u8 {
    // SAFETY: the context is the test's, live for the call.
    let s = unsafe { &*context.cast::<Synchronized<'_>>() };
    s.irql
        .store(u32::from(KeGetCurrentIrql()), Ordering::Relaxed);
    // SAFETY: the driver's lock, read atomically.
    let lock = unsafe { AtomicUsize::from_ptr(s.lock.cast_mut()) };
    s.locked.store(
        u32::from(lock.load(Ordering::Relaxed) != 0),
        Ordering::Relaxed,
    );
    let before = s.served.calls();
    s.source.fire();
    ke::time::stall(5_000);
    s.served_during
        .store(s.served.calls() - before, Ordering::Relaxed);
    0x5A
}

/// A fully specified connection with the driver's own lock and a
/// higher `SynchronizeIrql`: `KeSynchronizeExecution` and
/// `KeAcquireInterruptSpinLock` keep the service routine out, and it
/// runs once they let go.
fn synchronize(source: &InterruptTestSource) -> Result<u8, &'static str> {
    let translated = routing::translate(Raw::Line(source.line()), ALL_PROCESSORS)
        .map_err(|_| "the line was not translated")?;
    let synchronize_irql = translated.level + 1;
    let served = Served::new(Some(source), true);
    let mut lock: KSPIN_LOCK = 0;
    let lock = &raw mut lock;
    let check = || {
        let interrupt = connect_fully(translated, synchronize_irql, true, &served, lock)
            .map_err(|_| "IoConnectInterruptEx failed")?;
        let s = Synchronized {
            source,
            served: &served,
            lock,
            irql: AtomicU32::new(0),
            locked: AtomicU32::new(0),
            served_during: AtomicU32::new(u32::MAX),
        };
        let inner = || {
            // SAFETY: a connected interrupt object; the routine and its
            // context are the test's.
            let returned = unsafe {
                if (*interrupt).ActualLock != lock {
                    return Err("the interrupt object does not use the driver's lock");
                }
                KeSynchronizeExecution(
                    interrupt,
                    Some(synchronized),
                    core::ptr::from_ref(&s).cast_mut().cast(),
                )
            };
            if returned != 0x5A {
                return Err("KeSynchronizeExecution did not return the routine's value");
            }
            if s.irql.load(Ordering::Relaxed) != u32::from(synchronize_irql)
                || s.locked.load(Ordering::Relaxed) != 1
            {
                return Err("the routine did not run at SynchronizeIrql with the lock held");
            }
            if s.served_during.load(Ordering::Relaxed) != 0 {
                return Err("the service routine ran during KeSynchronizeExecution");
            }
            if !wait_for(|| served.served() == 1) {
                return Err("the interrupt held off by KeSynchronizeExecution was lost");
            }
            if served.irql.load(Ordering::Relaxed) != u32::from(synchronize_irql) {
                return Err("the service routine did not run at SynchronizeIrql");
            }
            // SAFETY: a connected interrupt object.
            let (held_irql, during) = unsafe {
                let old = KeAcquireInterruptSpinLock(interrupt);
                let held_irql = KeGetCurrentIrql();
                source.fire();
                ke::time::stall(5_000);
                let during = served.calls();
                KeReleaseInterruptSpinLock(interrupt, old);
                (held_irql, during)
            };
            if held_irql != synchronize_irql || irql::current() != irql::PASSIVE_LEVEL {
                return Err("KeAcquireInterruptSpinLock did not raise and restore the IRQL");
            }
            if during != 1 {
                return Err("the service routine ran while its lock was held");
            }
            if !wait_for(|| served.served() == 2) {
                return Err("the interrupt held off by the lock was lost");
            }
            Ok(synchronize_irql)
        };
        let verdict = inner();
        disconnect(CONNECT_FULLY_SPECIFIED, interrupt.cast());
        verdict
    };
    let verdict = check();
    source.quiet();
    routing::release(translated.vector);
    verdict
}

/// Report a connection active or inactive.
fn report(interrupt: *mut KINTERRUPT, active: bool) {
    let mut p = IO_REPORT_INTERRUPT_ACTIVE_STATE_PARAMETERS {
        Version: CONNECT_FULLY_SPECIFIED,
        ConnectionContext: interrupt.cast(),
    };
    // SAFETY: a live connection of that version.
    unsafe {
        if active {
            IoReportInterruptActive(&raw mut p);
        } else {
            IoReportInterruptInactive(&raw mut p);
        }
    }
}

/// Two objects on one vector: the first declines, the second claims;
/// an object that does not share is refused; an inactive object is not
/// called; an interrupt nobody claims is counted. Returns the unclaimed
/// interrupts counted.
fn shared(source: &InterruptTestSource) -> Result<u32, &'static str> {
    let translated = routing::translate(Raw::Line(source.line()), ALL_PROCESSORS)
        .map_err(|_| "the line was not translated")?;
    let level = translated.level;
    let mut stranger = Served::new(Some(source), false);
    stranger.quiets = true;
    let owner = Served::new(Some(source), true);
    let null = core::ptr::null_mut();
    let check = || {
        let first = connect_fully(translated, level, true, &stranger, null)
            .map_err(|_| "the first connection failed")?;
        let Ok(second) = connect_fully(translated, level, true, &owner, null) else {
            disconnect(CONNECT_FULLY_SPECIFIED, first.cast());
            return Err("a second connection to a shared vector failed");
        };
        let inner = || {
            let alone = Served::new(None, false);
            if connect_fully(translated, level, false, &alone, null)
                != Err(STATUS_INVALID_PARAMETER)
            {
                return Err("an object that does not share was connected to a shared vector");
            }
            // The stranger is asked first, serves nothing and declines;
            // but it quiets the device, so the owner finds nothing to
            // claim. With the stranger not quieting, the owner serves.
            let fire = |calls: u32, served: u32| {
                source.fire();
                wait_for(|| stranger.calls() == calls && owner.served() == served)
            };
            let before = kinterrupt::unclaimed(translated.vector);
            let unclaimed = || kinterrupt::unclaimed(translated.vector) - before;
            source.fire();
            if !wait_for(|| stranger.calls() == 1 && owner.calls() == 1) {
                return Err("both objects of a shared vector were not asked");
            }
            // The count is made once the chain has been walked, on the
            // processor the interrupt arrived on, which need not be this
            // one: the routines have been called before it is made.
            if !wait_for(|| unclaimed() != 0) || unclaimed() != 1 || owner.served() != 0 {
                return Err("an interrupt nobody claimed was not counted once");
            }
            let unclaimed = unclaimed();
            report(first, false);
            if !fire(1, 1) {
                return Err("an inactive object was called, or the active one was not");
            }
            report(first, false);
            report(first, true);
            report(first, true);
            // Active again, the stranger is called again; it is now at
            // the end of the chain, so the owner claims first.
            source.fire();
            if !wait_for(|| owner.served() == 2) || stranger.calls() != 1 {
                return Err("the chain did not stop at the object that claimed");
            }
            report(second, false);
            source.fire();
            if !wait_for(|| stranger.calls() == 2) || owner.served() != 2 {
                return Err("an object reported active again was not called");
            }
            report(second, true);
            Ok(unclaimed)
        };
        let verdict = inner();
        disconnect(CONNECT_FULLY_SPECIFIED, first.cast());
        disconnect(CONNECT_FULLY_SPECIFIED, second.cast());
        verdict
    };
    let verdict = check();
    source.quiet();
    routing::release(translated.vector);
    verdict
}

/// What the message test found: how many messages were delivered, or
/// that the machine has none and the connection fell back to the line.
enum Messages {
    Delivered(u32),
    FellBack,
}

/// A message-based connection. Where NK can deliver messages: two of
/// them, each with its address and data, each routine called with its
/// message's number. Where it cannot, and for a device with only a
/// line: the connection falls back to the line and says so.
fn message(source: Option<&InterruptTestSource>) -> Result<Messages, &'static str> {
    let pdo = device_object(&DEVICE_B);
    let served = Served::new(source, true);
    let connect = |context: &mut *mut c_void| {
        let mut p = parameters(
            CONNECT_MESSAGE_BASED,
            IO_CONNECT_INTERRUPT_MESSAGE_BASED_PARAMETERS {
                PhysicalDeviceObject: pdo,
                ConnectionContext: core::ptr::from_mut(context),
                MessageServiceRoutine: Some(serve_message),
                ServiceContext: served.context(),
                SpinLock: core::ptr::null_mut(),
                SynchronizeIrql: 0,
                FloatingSave: 0,
                FallBackServiceRoutine: Some(serve),
            },
        );
        // SAFETY: the parameters are whole and their pointers live.
        let status = unsafe { IoConnectInterruptEx(&raw mut p) };
        (status, p.Version)
    };
    match routing::translate(Raw::Messages(2), ALL_PROCESSORS) {
        Ok(translated) => {
            let resources = [0, 1].map(|i| Resource {
                translated: Translated {
                    vector: translated.vector + i,
                    ..translated
                },
                message: true,
                shared: false,
            });
            let check = || {
                if translated.vector % 2 != 0 {
                    return Err("two messages' vectors do not begin at a multiple of two");
                }
                if !device::assign(pdo, &resources) {
                    return Err("no memory for the device's interrupts");
                }
                let mut context = core::ptr::null_mut();
                if connect(&mut context) != (STATUS_SUCCESS, CONNECT_MESSAGE_BASED) {
                    return Err("the message-based connection failed");
                }
                let table = context.cast::<IO_INTERRUPT_MESSAGE_INFO>();
                let inner = || {
                    // SAFETY: the table the connection returned, of two
                    // entries.
                    unsafe {
                        if (*table).MessageCount != 2 || (*table).UnifiedIrql != translated.level {
                            return Err("the message table's header is wrong");
                        }
                        let entries = (&raw mut (*table).MessageInfo)
                            .cast::<IO_INTERRUPT_MESSAGE_INFO_ENTRY>();
                        for i in 0..2u32 {
                            let entry = entries.add(i as usize);
                            let expected = routing::message(translated.vector + i)
                                .ok_or("a message vector has no message")?;
                            if (*entry).Vector != translated.vector + i
                                || (*entry).MessageData != expected.data
                                || (*entry).MessageAddress != expected.address as i64
                                || (*entry).Irql != translated.level
                                || (*entry).TargetProcessorSet as u64 != translated.affinity
                                || (*(*entry).InterruptObject).MessageIndex != i
                            {
                                return Err("a message table entry is wrong");
                            }
                        }
                    }
                    // A device's message is a write that raises the
                    // vector on the target processor; a processor
                    // raising it on itself is the same event.
                    for i in 0..2u32 {
                        arch::self_interrupt(translated.vector + 1 - i);
                        if !wait_for(|| served.served() == i + 1)
                            || served.message.load(Ordering::Relaxed) != 1 - i
                        {
                            return Err("a message's routine was not called with its number");
                        }
                    }
                    if served.irql.load(Ordering::Relaxed) != u32::from(translated.level) {
                        return Err("a message's routine did not run at its IRQL");
                    }
                    Ok(Messages::Delivered(served.served()))
                };
                let verdict = inner();
                disconnect(CONNECT_MESSAGE_BASED, context);
                verdict
            };
            let verdict = check();
            device::withdraw(pdo);
            routing::release(translated.vector);
            verdict
        }
        Err(STATUS_NOT_SUPPORTED) => {
            let source = source.ok_or("no interrupt source to fall back to")?;
            let translated = routing::translate(Raw::Line(source.line()), ALL_PROCESSORS)
                .map_err(|_| "the line was not translated")?;
            let resource = Resource {
                translated,
                message: false,
                shared: true,
            };
            let check = || {
                if !device::assign(pdo, &[resource]) {
                    return Err("no memory for the device's interrupts");
                }
                let mut context = core::ptr::null_mut();
                if connect(&mut context) != (STATUS_SUCCESS, CONNECT_LINE_BASED) {
                    return Err("the connection did not fall back to the line");
                }
                source.fire();
                let ran = wait_for(|| served.served() == 1);
                let by_line = served.message.load(Ordering::Relaxed) == u32::MAX;
                disconnect(CONNECT_LINE_BASED, context);
                if !ran || !by_line {
                    return Err("the fall-back service routine did not run");
                }
                Ok(Messages::FellBack)
            };
            let verdict = check();
            source.quiet();
            device::withdraw(pdo);
            routing::release(translated.vector);
            verdict
        }
        Err(_) => Err("messages were not translated"),
    }
}

/// What cannot be connected or translated is refused, each with its
/// status.
fn refused() -> Result<(), &'static str> {
    let served = Served::new(None, false);
    // A version nobody defines: refused, and the highest supported is
    // written back.
    let mut p = parameters(99, 0u64);
    // SAFETY: the parameters are whole; the version is read first.
    if unsafe { IoConnectInterruptEx(&raw mut p) } != STATUS_NOT_SUPPORTED
        || p.Version != CONNECT_FULLY_SPECIFIED_GROUP
    {
        return Err("an unknown version was not answered with the highest supported");
    }
    // A vector no translation gave out.
    let nowhere = Translated {
        level: 5,
        vector: 0x5F,
        affinity: 1,
    };
    if connect_fully(nowhere, 5, true, &served, core::ptr::null_mut())
        != Err(STATUS_INVALID_PARAMETER)
    {
        return Err("a vector no resource names was connected");
    }
    // A device with no interrupts.
    let mut interrupt: *mut KINTERRUPT = core::ptr::null_mut();
    let mut p = parameters(
        CONNECT_LINE_BASED,
        IO_CONNECT_INTERRUPT_LINE_BASED_PARAMETERS {
            PhysicalDeviceObject: device_object(&DEVICE_B),
            InterruptObject: &raw mut interrupt,
            ServiceRoutine: Some(serve),
            ServiceContext: served.context(),
            SpinLock: core::ptr::null_mut(),
            SynchronizeIrql: 0,
            FloatingSave: 0,
        },
    );
    // SAFETY: the parameters are whole and their pointers live.
    if unsafe { IoConnectInterruptEx(&raw mut p) } != STATUS_NOT_FOUND || !interrupt.is_null() {
        return Err("a device with no line was connected");
    }
    // A line no controller has; no processor; a count that is no count.
    let nowhere = Line {
        gsi: 100_000,
        trigger: Trigger::Level,
        polarity: Polarity::High,
    };
    let wrong = [
        (Raw::Line(nowhere), ALL_PROCESSORS),
        (Raw::Messages(3), ALL_PROCESSORS),
        (Raw::Messages(32), ALL_PROCESSORS),
        (Raw::Messages(1), 0),
    ];
    for (raw, affinity) in wrong {
        match routing::translate(raw, affinity) {
            Ok(translated) => {
                routing::release(translated.vector);
                return Err("an interrupt that cannot be had was translated");
            }
            Err(STATUS_NO_SUCH_DEVICE | STATUS_INVALID_PARAMETER | STATUS_NOT_SUPPORTED)
            // On arm64 an interrupt id past the distributor's is not a
            // vector at all.
            | Err(nk_ntabi::status::STATUS_INSUFFICIENT_RESOURCES) => {}
            Err(_) => return Err("a refused translation has an unexpected status"),
        }
    }
    Ok(())
}

/// With a real line: a wrong IRQL and a low `SynchronizeIrql` are
/// refused.
fn refused_levels(source: &InterruptTestSource) -> Result<(), &'static str> {
    let translated = routing::translate(Raw::Line(source.line()), ALL_PROCESSORS)
        .map_err(|_| "the line was not translated")?;
    let served = Served::new(None, false);
    let null = core::ptr::null_mut();
    let wrong_level = Translated {
        level: translated.level + 1,
        ..translated
    };
    let results = [
        connect_fully(wrong_level, translated.level + 1, true, &served, null),
        connect_fully(translated, translated.level - 1, true, &served, null),
    ];
    for interrupt in results.into_iter().flatten() {
        disconnect(CONNECT_FULLY_SPECIFIED, interrupt.cast());
    }
    routing::release(translated.vector);
    if results != [Err(STATUS_INVALID_PARAMETER); 2] {
        return Err("a connection at the wrong IRQL was made");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    let source = InterruptTestSource::find();
    let Some(device) = source.as_ref() else {
        r.skip_rest(format_args!(
            "this machine has no device the test can make interrupt"
        ));
        return;
    };
    match translate(device.line()) {
        Ok((vector, level)) => match routing::isa(0) {
            Some(timer) => r.ok_with(
                "hal.interrupt.translate",
                format_args!(
                    "GSI {} is vector {vector:#x} at IRQL {level}; ISA interrupt 0 is GSI {}",
                    device.line().gsi,
                    timer.gsi
                ),
            ),
            None => r.ok_with(
                "hal.interrupt.translate",
                format_args!(
                    "GSI {} is vector {vector:#x} at IRQL {level}; no ISA interrupts",
                    device.line().gsi
                ),
            ),
        },
        Err(why) => r.fail("hal.interrupt.translate", format_args!("{why}")),
    }
    match line(device) {
        Ok((vector, level, processor)) => r.ok_with(
            "io.interrupt.line",
            format_args!("vector {vector:#x} at IRQL {level} on processor {processor}"),
        ),
        Err(why) => r.fail("io.interrupt.line", format_args!("{why}")),
    }
    match synchronize(device) {
        Ok(level) => r.ok_with(
            "io.interrupt.synchronize",
            format_args!("synchronised at IRQL {level}"),
        ),
        Err(why) => r.fail("io.interrupt.synchronize", format_args!("{why}")),
    }
    match shared(device) {
        Ok(unclaimed) => r.ok_with(
            "io.interrupt.shared",
            format_args!("unclaimed interrupts: {unclaimed}"),
        ),
        Err(why) => r.fail("io.interrupt.shared", format_args!("{why}")),
    }
    match message(Some(device)) {
        Ok(Messages::Delivered(n)) => r.ok_with(
            "io.interrupt.message",
            format_args!("messages delivered: {n}"),
        ),
        Ok(Messages::FellBack) => r.ok_with(
            "io.interrupt.message",
            format_args!("no messages on this machine: fell back to the line"),
        ),
        Err(why) => r.fail("io.interrupt.message", format_args!("{why}")),
    }
    r.check("io.interrupt.refused", || {
        refused()?;
        refused_levels(device)
    });
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
