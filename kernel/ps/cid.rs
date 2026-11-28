//! Global client-ID table (`PspCidTable`): maps every live process ID and
//! thread ID to its `EPROCESS` or `ETHREAD` object.
//!
//! Entries do not hold object references (otherwise a process or thread could
//! never drop to zero references). Instead, every `EPROCESS`/`ETHREAD`
//! unregisters its ID in its `DeleteProcedure` under [`CID_TABLE`]'s exclusive
//! lock before its pool block is freed, and lookups take a reference via
//! [`object::try_reference`] while holding [`CID_TABLE`]'s shared lock.

#![allow(non_snake_case)]

use crate::ke::spinlock::{Rank, SpinLock};
use crate::ob::object::{self, ObRef};
use alloc::collections::BTreeMap;
use core::ffi::c_void;
use nk_ntabi::status::*;

/// Inline hash slots (zero pool allocations under normal concurrency).
const INLINE_SLOTS: usize = 1024;

#[derive(Clone, Copy)]
struct CidSlot {
    /// `0` = empty, `u64::MAX` = tombstone, otherwise a live PID/TID.
    id: u64,
    body: usize,
    is_process: bool,
}

impl CidSlot {
    const EMPTY: Self = Self {
        id: 0,
        body: 0,
        is_process: false,
    };
}

const TOMBSTONE: u64 = u64::MAX;

struct CidTable {
    slots: [CidSlot; INLINE_SLOTS],
    count: usize,
    overflow: BTreeMap<u64, (usize, bool)>,
}

impl CidTable {
    const fn new() -> Self {
        Self {
            slots: [CidSlot::EMPTY; INLINE_SLOTS],
            count: 0,
            overflow: BTreeMap::new(),
        }
    }

    fn hash(id: u64) -> usize {
        ((id >> 2) as usize) & (INLINE_SLOTS - 1)
    }

    fn insert(&mut self, id: u64, body: usize, is_process: bool) {
        if id == 0 || id == TOMBSTONE {
            return;
        }
        if self.count * 4 < INLINE_SLOTS * 3 {
            let start = Self::hash(id);
            let mut first_tomb = None;
            for step in 0..INLINE_SLOTS {
                let idx = (start + step) & (INLINE_SLOTS - 1);
                let s = self.slots[idx].id;
                if s == id {
                    self.slots[idx] = CidSlot {
                        id,
                        body,
                        is_process,
                    };
                    return;
                }
                if s == TOMBSTONE && first_tomb.is_none() {
                    first_tomb = Some(idx);
                }
                if s == 0 {
                    let target = first_tomb.unwrap_or(idx);
                    self.slots[target] = CidSlot {
                        id,
                        body,
                        is_process,
                    };
                    self.count += 1;
                    return;
                }
            }
            if let Some(target) = first_tomb {
                self.slots[target] = CidSlot {
                    id,
                    body,
                    is_process,
                };
                self.count += 1;
                return;
            }
        }
        self.overflow.insert(id, (body, is_process));
    }

    fn get(&self, id: u64) -> Option<(usize, bool)> {
        if id == 0 || id == TOMBSTONE {
            return None;
        }
        let start = Self::hash(id);
        for step in 0..INLINE_SLOTS {
            let idx = (start + step) & (INLINE_SLOTS - 1);
            let slot = self.slots[idx];
            if slot.id == id {
                return Some((slot.body, slot.is_process));
            }
            if slot.id == 0 {
                break;
            }
        }
        self.overflow.get(&id).copied()
    }

    fn remove(&mut self, id: u64) {
        if id == 0 || id == TOMBSTONE {
            return;
        }
        let start = Self::hash(id);
        for step in 0..INLINE_SLOTS {
            let idx = (start + step) & (INLINE_SLOTS - 1);
            let s = self.slots[idx].id;
            if s == id {
                self.slots[idx].id = TOMBSTONE;
                self.slots[idx].body = 0;
                self.count = self.count.saturating_sub(1);
                return;
            }
            if s == 0 {
                break;
            }
        }
        self.overflow.remove(&id);
    }
}

static CID_TABLE: SpinLock<CidTable> = SpinLock::new(Rank::CidTable, CidTable::new());

/// Register a newly allocated `EPROCESS` under `pid`.
pub fn insert_process(pid: u64, process: *mut u8) {
    CID_TABLE.lock().insert(pid, process.addr(), true);
}

/// Register a newly allocated `ETHREAD` under `tid`.
pub fn insert_thread(tid: u64, thread: *mut u8) {
    CID_TABLE.lock().insert(tid, thread.addr(), false);
}

/// Remove a process or thread ID when its object is being deleted.
pub fn remove(id: u64) {
    CID_TABLE.lock().remove(id);
}

/// Look up a live `EPROCESS` by `pid` and return a referenced handle to it.
pub fn lookup_process(pid: u64) -> Result<ObRef, NTSTATUS> {
    let table = CID_TABLE.lock();
    let Some((body, true)) = table.get(pid) else {
        return Err(STATUS_INVALID_CID);
    };
    let ptr = core::ptr::with_exposed_provenance_mut::<u8>(body);
    // SAFETY: `ptr` remains allocated while `CID_TABLE` is held because
    // `process::deleted` acquires `CID_TABLE` before pool free.
    if !unsafe { object::try_reference(ptr) } {
        return Err(STATUS_INVALID_CID);
    }
    // SAFETY: `try_reference` just incremented `PointerCount`.
    Ok(unsafe { ObRef::adopt(ptr) })
}

/// Look up a live `ETHREAD` by `tid` and return a referenced handle to it.
pub fn lookup_thread(tid: u64) -> Result<ObRef, NTSTATUS> {
    let table = CID_TABLE.lock();
    let Some((body, false)) = table.get(tid) else {
        return Err(STATUS_INVALID_CID);
    };
    let ptr = core::ptr::with_exposed_provenance_mut::<u8>(body);
    // SAFETY: `ptr` remains allocated while `CID_TABLE` is held shared because
    // `thread::deleted` acquires `CID_TABLE` exclusively before pool free.
    if !unsafe { object::try_reference(ptr) } {
        return Err(STATUS_INVALID_CID);
    }
    // SAFETY: `try_reference` just incremented `PointerCount`.
    Ok(unsafe { ObRef::adopt(ptr) })
}

/// [`PsLookupProcessByProcessId`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pslookupprocessbyprocessid):
/// return a referenced `PEPROCESS` for `process_id`, or `STATUS_INVALID_CID`.
///
/// # Safety
/// `process` points to writable storage for a `*mut c_void`.
pub unsafe extern "C" fn PsLookupProcessByProcessId(
    process_id: *mut c_void,
    process: *mut *mut c_void,
) -> NTSTATUS {
    match lookup_process(process_id.addr() as u64) {
        Ok(ob) => {
            let body = ob.body();
            core::mem::forget(ob);
            // SAFETY: per the contract.
            unsafe { process.write_unaligned(body.cast()) };
            STATUS_SUCCESS
        }
        Err(st) => {
            // SAFETY: per the contract; Windows leaves null on failure.
            unsafe { process.write_unaligned(core::ptr::null_mut()) };
            st
        }
    }
}

/// [`PsLookupThreadByThreadId`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-pslookupthreadbythreadid):
/// return a referenced `PETHREAD` for `thread_id`, or `STATUS_INVALID_CID`.
///
/// # Safety
/// `thread` points to writable storage for a `*mut c_void`.
pub unsafe extern "C" fn PsLookupThreadByThreadId(
    thread_id: *mut c_void,
    thread: *mut *mut c_void,
) -> NTSTATUS {
    match lookup_thread(thread_id.addr() as u64) {
        Ok(ob) => {
            let body = ob.body();
            core::mem::forget(ob);
            // SAFETY: per the contract.
            unsafe { thread.write_unaligned(body.cast()) };
            STATUS_SUCCESS
        }
        Err(st) => {
            // SAFETY: per the contract.
            unsafe { thread.write_unaligned(core::ptr::null_mut()) };
            st
        }
    }
}
