//! Sequenced singly linked lists (`SLIST_HEADER`): a lock-free stack
//! whose 16-byte head is the driver's memory.
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/singly-and-doubly-linked-lists>
//!
//! The header's fields and transitions are `nk_ex::slist`'s. Here each
//! transition is stored with one 16-byte compare-and-swap
//! (`arch::swap_pair`) and started over if the header changed meanwhile.
//!
//! The header is read as two quadwords, one after the other, so what is
//! read need not be a header that ever was. The swap settles it: it
//! succeeds only if the header is, at that moment, exactly what was
//! read, and since every push changes the sequence number, a header
//! that reads the same stands for the same list.
//!
//! A pop reads the first entry's `Next` before its swap, and by then
//! another processor may have popped that entry and its owner freed it.
//! What is read is then stale and the swap fails, so the value is never
//! used; but the read itself happens. Windows makes the same read and
//! forgives a fault in it. NK has no fault to forgive where entries are
//! pool blocks, as a lookaside list's are: pool memory is never
//! unmapped. An entry in a driver's own image is, when the driver is
//! unloaded; a driver that unloads while another thread is still
//! popping its list stops the system with a page fault.
//!
//! An entry that is not 16-byte aligned cannot be named by a header:
//! pushing one stops the system.

#![allow(non_snake_case)]

use crate::arch;
use core::sync::atomic::{AtomicU64, Ordering};
use nk_ex::slist::{self, Header};
use nk_ntabi::ex::{SLIST_ENTRY, SLIST_HEADER};

/// The header as its two quadwords are now.
///
/// # Safety
/// `header` points to a live `SLIST_HEADER`.
unsafe fn load(header: *mut SLIST_HEADER) -> Header {
    // SAFETY: per the contract; atomic views, since other processors
    // swap the header meanwhile.
    unsafe {
        Header {
            alignment: AtomicU64::from_ptr(&raw mut (*header).Alignment).load(Ordering::Acquire),
            region: AtomicU64::from_ptr(&raw mut (*header).Region).load(Ordering::Acquire),
        }
    }
}

const fn pair(header: Header) -> u128 {
    header.alignment as u128 | (header.region as u128) << 64
}

/// Make the header `new` if it is `old`.
///
/// # Safety
/// `header` points to a live `SLIST_HEADER`.
unsafe fn swap(header: *mut SLIST_HEADER, old: Header, new: Header) -> bool {
    // SAFETY: per the contract; a header is 16 aligned bytes.
    unsafe { arch::swap_pair(header.cast(), pair(old), pair(new)) }
}

/// [`InitializeSListHead`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-initializeslisthead):
/// an empty list is all zero.
///
/// # Safety
/// `header` points to writable, 16-byte aligned storage for a header
/// nothing else is using.
pub unsafe extern "C" fn InitializeSListHead(header: *mut SLIST_HEADER) {
    // SAFETY: per the contract.
    unsafe {
        header.write(SLIST_HEADER {
            Alignment: 0,
            Region: 0,
        });
    }
}

/// [`ExQueryDepthSList`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exquerydepthslist):
/// how many entries the list has.
///
/// # Safety
/// `header` points to a live `SLIST_HEADER`.
pub unsafe extern "C" fn ExQueryDepthSList(header: *mut SLIST_HEADER) -> u16 {
    // SAFETY: per the contract.
    slist::depth(unsafe { load(header) })
}

/// `ExpInterlockedPushEntrySList`, what
/// [`ExInterlockedPushEntrySList`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinterlockedpushentryslist)
/// and `InterlockedPushEntrySList` compile to: put `entry` first.
/// Returns the entry that was first, or null.
///
/// # Safety
/// `header` points to a live `SLIST_HEADER`; `entry` to an entry on no
/// list, which stays valid while it is on this one.
pub unsafe extern "C" fn ExpInterlockedPushEntrySList(
    header: *mut SLIST_HEADER,
    entry: *mut SLIST_ENTRY,
) -> *mut SLIST_ENTRY {
    loop {
        // SAFETY: per the contract. Until the swap the entry is the
        // caller's alone.
        unsafe {
            let old = load(header);
            let Ok((new, next)) = slist::push(old, entry as u64) else {
                crate::kd::bugcheck(format_args!(
                    "0x0000001E KMODE_EXCEPTION_NOT_HANDLED: STATUS_DATATYPE_MISALIGNMENT \
                     (the list entry {entry:p} is not 16-byte aligned)"
                ));
            };
            let next = next as *mut SLIST_ENTRY;
            (&raw mut (*entry).Next).write(next);
            if swap(header, old, new) {
                return next;
            }
        }
    }
}

/// `ExpInterlockedPopEntrySList`, what
/// [`ExInterlockedPopEntrySList`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinterlockedpopentryslist)
/// and `InterlockedPopEntrySList` compile to: take the first entry off.
/// Null if the list is empty.
///
/// # Safety
/// `header` points to a live `SLIST_HEADER` whose entries, while
/// listed, are valid, and whose popped entries stay mapped.
pub unsafe extern "C" fn ExpInterlockedPopEntrySList(
    header: *mut SLIST_HEADER,
) -> *mut SLIST_ENTRY {
    loop {
        // SAFETY: per the contract.
        unsafe {
            let old = load(header);
            let Some(first) = slist::first(old) else {
                return core::ptr::null_mut();
            };
            let first = first as *mut SLIST_ENTRY;
            // Perhaps no longer on the list, nor even an entry: see the
            // top of the file. The swap decides.
            let next = (&raw const (*first).Next).read_volatile();
            if swap(header, old, slist::pop(old, next as u64)) {
                return first;
            }
        }
    }
}

/// `ExpInterlockedFlushSList`, what
/// [`ExInterlockedFlushSList`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exinterlockedflushslist)
/// compiles to: take every entry off. Returns the first, which leads to
/// the rest through `Next`; null if the list was empty.
///
/// # Safety
/// `header` points to a live `SLIST_HEADER`.
pub unsafe extern "C" fn ExpInterlockedFlushSList(header: *mut SLIST_HEADER) -> *mut SLIST_ENTRY {
    loop {
        // SAFETY: per the contract.
        unsafe {
            let old = load(header);
            let Some(first) = slist::first(old) else {
                return core::ptr::null_mut();
            };
            if swap(header, old, slist::flush(old)) {
                return first as *mut SLIST_ENTRY;
            }
        }
    }
}

// ---- tests --------------------------------------------------------------

use super::stress;
use crate::test::Slot;
use core::sync::atomic::AtomicU32;

/// An entry as a driver declares one: the link first, its own data
/// after.
#[repr(C, align(16))]
struct Item {
    entry: SLIST_ENTRY,
    number: u32,
    /// How often the item was popped; written by whoever holds it.
    visits: u32,
}

const ITEMS: usize = 16;
static LIST: Slot<SLIST_HEADER> = Slot::new();
static STORE: Slot<[Item; ITEMS]> = Slot::new();

fn item(index: usize) -> *mut Item {
    STORE.ptr().cast::<Item>().wrapping_add(index)
}

/// The number of the item an entry is in; 0 for no entry.
fn number(entry: *mut SLIST_ENTRY) -> u32 {
    if entry.is_null() {
        0
    } else {
        // SAFETY: every entry the tests list is the first field of an
        // item of the store.
        unsafe { (&raw const (*entry.cast::<Item>()).number).read() }
    }
}

/// The depth and the low 16 bits of the sequence number.
fn low_half() -> u32 {
    // SAFETY: the static header.
    unsafe { load(LIST.ptr()) }.alignment as u32
}

fn fresh() {
    // SAFETY: static storage nobody else is using.
    unsafe {
        LIST.ptr()
            .cast::<u8>()
            .write_bytes(0xEE, size_of::<SLIST_HEADER>());
        InitializeSListHead(LIST.ptr());
        for index in 0..ITEMS {
            item(index).write(Item {
                entry: SLIST_ENTRY {
                    Next: core::ptr::null_mut(),
                },
                number: index as u32 + 1,
                visits: 0,
            });
        }
    }
}

/// The 16-byte swap happens only when both quadwords are as expected,
/// and then writes both.
pub fn swap_test() -> Result<(), &'static str> {
    let old = Header {
        alignment: 0x1111_2222_3333_4444,
        region: 0x5555_6666_7777_8880,
    };
    let new = Header {
        alignment: 0x9999_AAAA_BBBB_CCCC,
        region: 0xDDDD_EEEE_FFFF_0000,
    };
    let list = LIST.ptr();
    // SAFETY: the static header, which nothing else is using.
    unsafe {
        let set = |to: Header| {
            list.write(SLIST_HEADER {
                Alignment: to.alignment,
                Region: to.region,
            });
        };
        for wrong in [
            Header {
                alignment: 0,
                ..old
            },
            Header { region: 0, ..old },
            new,
        ] {
            set(old);
            if swap(list, wrong, new) || load(list) != old {
                return Err("a swap went through against a header that differs");
            }
        }
        set(old);
        if !swap(list, old, new) || load(list) != new {
            return Err("a swap against the header as it is did not replace both quadwords");
        }
    }
    Ok(())
}

/// Push, pop and flush, single-handed: last in is first out, and the
/// header counts as Windows' does. Returns the header's low half at the
/// end.
pub fn order_test() -> Result<u32, &'static str> {
    fresh();
    let list = LIST.ptr();
    // SAFETY: the static header and store, used by this thread alone.
    unsafe {
        if ExQueryDepthSList(list) != 0
            || low_half() != 0
            || !ExpInterlockedPopEntrySList(list).is_null()
        {
            return Err("an initialised list is not empty and zero");
        }
        for index in 0..3 {
            let was_first = ExpInterlockedPushEntrySList(list, item(index).cast());
            if number(was_first) != index as u32 {
                return Err("a push did not return the entry that was first");
            }
            let count = index as u32 + 1;
            if u32::from(ExQueryDepthSList(list)) != count || low_half() != count << 16 | count {
                return Err("a push did not add one to the depth and to the sequence number");
            }
        }
        if number(ExpInterlockedPopEntrySList(list)) != 3 || low_half() != 0x0003_0002 {
            return Err("a pop did not take the last entry pushed and leave the sequence number");
        }
        let chain = ExpInterlockedFlushSList(list);
        let second = if chain.is_null() {
            chain
        } else {
            (&raw const (*chain).Next).read()
        };
        let end = if second.is_null() {
            second
        } else {
            (&raw const (*second).Next).read()
        };
        if (number(chain), number(second), number(end)) != (2, 1, 0) {
            return Err("a flush did not hand back the chain, newest first");
        }
        if ExQueryDepthSList(list) != 0 || low_half() != 0x0003_0000 {
            return Err("a flushed list is not empty with its sequence number kept");
        }
        if !ExpInterlockedFlushSList(list).is_null()
            || !ExpInterlockedPopEntrySList(list).is_null()
            || low_half() != 0x0003_0000
        {
            return Err("flushing or popping an empty list changed it");
        }
        if !ExpInterlockedPushEntrySList(list, item(0).cast()).is_null()
            || low_half() != 0x0004_0001
        {
            return Err("the sequence number did not go on from where it was");
        }
        ExpInterlockedPopEntrySList(list);
    }
    Ok(low_half())
}

const THREADS: usize = 4;
const ROUNDS: u32 = 4000;
static POPS: AtomicU32 = AtomicU32::new(0);

/// Take an entry, mark it, put it back; now and then take the whole
/// list and put it back entry by entry.
fn contender(index: usize) {
    let list = LIST.ptr();
    let mut pops = 0;
    for round in 0..ROUNDS {
        // SAFETY: the static list; an entry taken off is this thread's
        // alone until it is pushed back.
        unsafe {
            let mut taken = if round % 97 == index as u32 {
                ExpInterlockedFlushSList(list)
            } else {
                let one = ExpInterlockedPopEntrySList(list);
                if !one.is_null() {
                    (&raw mut (*one).Next).write(core::ptr::null_mut());
                }
                one
            };
            while !taken.is_null() {
                let next = (&raw const (*taken).Next).read();
                let visits = &raw mut (*taken.cast::<Item>()).visits;
                visits.write(visits.read() + 1);
                pops += 1;
                if round % 64 == 0 {
                    crate::ke::thread::yield_now();
                }
                ExpInterlockedPushEntrySList(list, taken);
                taken = next;
            }
        }
    }
    POPS.fetch_add(pops, Ordering::AcqRel);
}

/// Threads pop, flush and push the same few entries at once: none is
/// lost, none is on the list twice, and every taking is accounted for.
/// Returns the takings.
pub fn contention_test() -> Result<u32, &'static str> {
    fresh();
    POPS.store(0, Ordering::Release);
    let list = LIST.ptr();
    // SAFETY: the static header and store.
    unsafe {
        for index in 0..ITEMS {
            ExpInterlockedPushEntrySList(list, item(index).cast());
        }
    }
    stress::run(THREADS, contender)?;
    let pops = POPS.load(Ordering::Acquire);
    // SAFETY: the threads have ended: the list is this thread's alone.
    unsafe {
        if usize::from(ExQueryDepthSList(list)) != ITEMS {
            return Err("the depth is not the number of entries put on the list");
        }
        let (mut seen, mut visits) = (0u32, 0u32);
        let mut at = ExpInterlockedFlushSList(list);
        for _ in 0..ITEMS {
            if at.is_null() {
                break;
            }
            seen |= 1 << (number(at) - 1);
            visits += (&raw const (*at.cast::<Item>()).visits).read();
            at = (&raw const (*at).Next).read();
        }
        if !at.is_null() || seen != (1 << ITEMS) - 1 {
            return Err("an entry was lost, or is on the list twice");
        }
        if visits != pops {
            return Err("an entry was taken by two threads at once");
        }
    }
    Ok(pops)
}
