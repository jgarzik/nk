//! What drivers have to do with stopping the system: `KeBugCheckEx`,
//! the callback records they register for that moment, and
//! `KiBugCheckData`.
//!
//! A record is the driver's memory, linked into one list of the
//! kernel's through its first field. The rules of a record (its states,
//! its checksum, which the stop looks at before it calls anything) are
//! `nk_ke::bugcheck`. What NK calls when it stops, and what it never
//! calls, is in `doc/DESIGN.md`, "Stopping the system".

#![allow(non_snake_case, non_upper_case_globals)]

use super::seh::{self, Guard, Unhandled};
use super::{Rank, SpinLock};
use crate::kd;
use core::cell::UnsafeCell;
use core::ffi::c_void;
use core::sync::atomic::{AtomicUsize, Ordering};
use nk_ke::bugcheck::{self as rules, Walk};
use nk_ntabi::ke::{
    BUFFER_EMPTY, BUFFER_FINISHED, BUFFER_INCOMPLETE, BUFFER_INSERTED, KB_CALLBACK_RESERVED1,
    KB_CALLBACK_TRIAGE_DUMP_DATA, KBUGCHECK_REASON_CALLBACK_RECORD,
    KBUGCHECK_REASON_CALLBACK_ROUTINE, KBUGCHECK_TRIAGE_DUMP_DATA, LIST_ENTRY,
};

/// `KiBugCheckData`: the code and the four parameters of the stop in
/// progress, where a driver's bugcheck callback reads them through the
/// address its import is bound to. Zero until the system stops with a
/// Windows code and parameters.
pub struct BugCheckData([AtomicUsize; 5]);

impl BugCheckData {
    /// The address drivers import.
    pub const fn address(&'static self) -> *const () {
        (&raw const self.0).cast()
    }
}

pub static KiBugCheckData: BugCheckData = BugCheckData([const { AtomicUsize::new(0) }; 5]);

/// Note the code and parameters of the stop that has begun. Called by
/// the one processor that stops the system.
pub fn record(data: [usize; 5]) {
    for (word, value) in KiBugCheckData.0.iter().zip(data) {
        word.store(value, Ordering::Relaxed);
    }
}

/// [`KeBugCheckEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kebugcheckex):
/// stop the system, with a code and four parameters.
pub extern "C" fn KeBugCheckEx(code: u32, p1: usize, p2: usize, p3: usize, p4: usize) -> ! {
    let parameters = [p1, p2, p3, p4];
    kd::bugcheck_with(
        [code as usize, p1, p2, p3, p4],
        format_args!("{}", rules::Stop { code, parameters }),
    )
}

/// [`KeBugCheck`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-kebugcheck):
/// stop the system with a code and no parameters.
pub extern "C" fn KeBugCheck(code: u32) -> ! {
    KeBugCheckEx(code, 0, 0, 0, 0)
}

/// The head of the list of registered records. Its links are null until
/// the first record is registered.
struct Head(UnsafeCell<LIST_ENTRY>);

// SAFETY: the list is touched only under its lock, or by the one
// processor left running when the system stops.
unsafe impl Send for Head {}

/// The registered records, linked through their `Entry`. Held at
/// `HIGH_LEVEL`: a record is registered and taken back at any IRQL.
static RECORDS: SpinLock<Head> = SpinLock::new(
    Rank::BugCheckCallbacks,
    Head(UnsafeCell::new(LIST_ENTRY {
        Flink: core::ptr::null_mut(),
        Blink: core::ptr::null_mut(),
    })),
);

/// The list's head, an empty list made of it if it was never used.
///
/// # Safety
/// The caller holds the list's lock, or is stopping the system.
unsafe fn head(head: &Head) -> *mut LIST_ENTRY {
    let head = head.0.get();
    // SAFETY: per the contract, nothing else touches the head.
    unsafe {
        if (*head).Flink.is_null() {
            head.write(LIST_ENTRY {
                Flink: head,
                Blink: head,
            });
        }
    }
    head
}

/// [`KeRegisterBugCheckReasonCallback`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keregisterbugcheckreasoncallback):
/// have `routine` called for `reason` if the system stops. `FALSE` if
/// the record is not empty (`KeInitializeCallbackRecord`) or is in the
/// list already. Any reason is taken; one the stop does not call for is
/// simply never called.
///
/// # Safety
/// `record` is a callback record that stays valid, with `component`,
/// until it is taken back.
pub unsafe extern "C" fn KeRegisterBugCheckReasonCallback(
    record: *mut KBUGCHECK_REASON_CALLBACK_RECORD,
    routine: Option<KBUGCHECK_REASON_CALLBACK_ROUTINE>,
    reason: u32,
    component: *mut u8,
) -> u8 {
    let records = RECORDS.lock();
    // SAFETY: per the contract; the list's links, the records' included,
    // belong to the lock held.
    unsafe {
        if (&raw const (*record).State).read() != BUFFER_EMPTY {
            return 0;
        }
        let head = head(&records);
        let entry = record.cast::<LIST_ENTRY>();
        let mut linked = (*head).Flink;
        while linked != head {
            if linked == entry {
                return 0;
            }
            linked = (*linked).Flink;
        }
        (&raw mut (*record).CallbackRoutine).write(routine);
        (&raw mut (*record).Reason).write(reason);
        (&raw mut (*record).Component).write(component);
        (&raw mut (*record).Checksum).write(rules::checksum(
            routine.map_or(0, |routine| routine as usize),
            reason,
            component.addr(),
        ));
        (&raw mut (*record).State).write(BUFFER_INSERTED);
        // After `before`, which is the head for a record that goes
        // first and the last record for one that goes last.
        let before = if rules::at_tail(reason) {
            (*head).Blink
        } else {
            head
        };
        let after = (*before).Flink;
        entry.write(LIST_ENTRY {
            Flink: after,
            Blink: before,
        });
        (&raw mut (*before).Flink).write(entry);
        (&raw mut (*after).Blink).write(entry);
    }
    1
}

/// [`KeDeregisterBugCheckReasonCallback`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kederegisterbugcheckreasoncallback):
/// take a record back. `FALSE`, and nothing done, unless it is
/// registered.
///
/// # Safety
/// `record` is a callback record.
pub unsafe extern "C" fn KeDeregisterBugCheckReasonCallback(
    record: *mut KBUGCHECK_REASON_CALLBACK_RECORD,
) -> u8 {
    let _records = RECORDS.lock();
    // SAFETY: per the contract; a record in that state is in the list,
    // whose links belong to the lock held.
    unsafe {
        if (&raw const (*record).State).read() != BUFFER_INSERTED {
            return 0;
        }
        (&raw mut (*record).State).write(BUFFER_EMPTY);
        let entry = record.cast::<LIST_ENTRY>().read();
        (&raw mut (*entry.Blink).Flink).write(entry.Flink);
        (&raw mut (*entry.Flink).Blink).write(entry.Blink);
    }
    1
}

/// Call the routines registered for `reason` with `data`, as the
/// system stops. `finished` says what a called record's state becomes.
///
/// # Safety
/// Every other processor is stopped, and this one is at `HIGH_LEVEL`.
unsafe fn call_reason(reason: u32, data: *mut c_void, length: u32, finished: impl Fn() -> u8) {
    // SAFETY: per the contract, nothing else runs: the list is taken
    // whoever held its lock. Records are the drivers' memory, read field
    // by field; one that does not look like a record ends the walk.
    unsafe {
        let head = head(&RECORDS.force_lock());
        let mut previous = head;
        let mut entry = (*head).Flink;
        while entry != head && rules::plausible(entry.addr()) {
            let record = entry.cast::<KBUGCHECK_REASON_CALLBACK_RECORD>();
            let routine = (&raw const (*record).CallbackRoutine).read();
            let fields = rules::Record {
                blink: (*entry).Blink.addr(),
                routine: routine.map_or(0, |routine| routine as usize),
                component: (&raw const (*record).Component).read().addr(),
                checksum: (&raw const (*record).Checksum).read(),
                reason: (&raw const (*record).Reason).read(),
                state: (&raw const (*record).State).read(),
            };
            let next = (*entry).Flink;
            match rules::examine(&fields, previous.addr(), reason) {
                Walk::End => return,
                Walk::Skip => {}
                Walk::Call => {
                    // The driver's routine. Nothing can handle what it
                    // raises: the system is stopping.
                    seh::call(
                        fields.routine,
                        [reason as usize, record.addr(), data.addr(), length as usize],
                        &Guard::Base(Unhandled::KernelMode),
                    );
                    (&raw mut (*record).State).write(finished());
                }
            }
            previous = entry;
            entry = next;
        }
    }
}

/// Call the drivers' bugcheck callbacks that Windows calls on a system
/// that writes no crash dump: those registered as `KbCallbackReserved1`,
/// with no data, then those registered as `KbCallbackTriageDumpData`,
/// each shown the code and parameters of the stop.
///
/// # Safety
/// Called once, by the processor that stops the system, with every
/// other processor stopped, at `HIGH_LEVEL`.
pub unsafe fn run_callbacks() {
    // SAFETY: per the contract.
    unsafe {
        call_reason(KB_CALLBACK_RESERVED1, core::ptr::null_mut(), 0, || {
            BUFFER_FINISHED
        });
    }
    let word = |index: usize| KiBugCheckData.0[index].load(Ordering::Relaxed);
    let mut triage = KBUGCHECK_TRIAGE_DUMP_DATA {
        DataArray: core::ptr::null_mut(),
        // What Windows passes: the flag for a bugcheck in progress, and
        // room for 32 MiB of ranges.
        Flags: 1,
        MaxVirtMemSize: 0x0200_0000,
        BugCheckCode: word(0) as u32,
        BugCheckParameter1: word(1),
        BugCheckParameter2: word(2),
        BugCheckParameter3: word(3),
        BugCheckParameter4: word(4),
    };
    let triage = &raw mut triage;
    // A record whose routine named ranges is finished; one that named
    // none is incomplete, as on Windows. The ranges would go into a
    // dump, and NK writes none: the next routine starts with none named.
    let finished = || {
        // SAFETY: the block above, which the routine may have written.
        unsafe {
            let named = !(&raw const (*triage).DataArray).read_volatile().is_null();
            (&raw mut (*triage).DataArray).write_volatile(core::ptr::null_mut());
            if named {
                BUFFER_FINISHED
            } else {
                BUFFER_INCOMPLETE
            }
        }
    };
    // SAFETY: per the contract.
    unsafe {
        call_reason(
            KB_CALLBACK_TRIAGE_DUMP_DATA,
            triage.cast(),
            size_of::<KBUGCHECK_TRIAGE_DUMP_DATA>() as u32,
            finished,
        );
    }
}
