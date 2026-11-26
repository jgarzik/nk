//! Range lists. The header is the driver's; the entries are pool
//! blocks of the kernel's, each a range as the iterator hands it out
//! followed by its links, chained from the header in order. The rules
//! are `nk_rtl::range`, which says how NK's one chain stands to
//! Windows' two levels. The caller serialises the calls on one list, as
//! on Windows.
//!
//! The routines allocate, so they are called below dispatch level, as
//! on Windows, where the entries come from a paged lookaside list.

#![allow(non_snake_case)]

use crate::ke::seh::{self, Guard};
use crate::mm::pool;
use core::ffi::c_void;
use core::mem::{offset_of, size_of};
use nk_ntabi::ke::LIST_ENTRY;
use nk_ntabi::rtl::{RTL_RANGE, RTL_RANGE_LIST, RTL_RANGE_LIST_ITERATOR};
use nk_ntabi::status::*;
use nk_rtl::range::{self, FindError, Range, Ranges, Tolerance};

/// One range of a list: what a driver sees of it, then its place in the
/// chain. The links lie where Windows' entries have theirs.
#[repr(C)]
struct Entry {
    range: RTL_RANGE,
    links: LIST_ENTRY,
}

const _: () = {
    assert!(offset_of!(Entry, links) == 0x28);
    assert!(size_of::<Entry>() == 0x38);
};

/// Pool tag of the entries.
const TAG: u32 = u32::from_le_bytes(*b"RRle");

/// A driver's list.
struct Driver(*mut RTL_RANGE_LIST);

impl Driver {
    /// # Safety
    /// `list` is an initialised range list, and stays valid, with every
    /// entry chained from it, while the result is used; nothing else
    /// changes it meanwhile.
    unsafe fn of(list: *mut RTL_RANGE_LIST) -> Self {
        Self(list)
    }

    fn head(&self) -> *mut LIST_ENTRY {
        self.0.cast()
    }

    /// The entry whose links are at `links`, unless that is the head.
    fn entry(&self, links: *mut LIST_ENTRY) -> Option<*mut Entry> {
        (links != self.head()).then(|| links.wrapping_byte_sub(offset_of!(Entry, links)).cast())
    }
}

impl Ranges for Driver {
    type Id = *mut Entry;

    fn first(&self) -> Option<*mut Entry> {
        // SAFETY: `of`'s contract.
        self.entry(unsafe { (&raw const (*self.head()).Flink).read() })
    }

    fn last(&self) -> Option<*mut Entry> {
        // SAFETY: `of`'s contract.
        self.entry(unsafe { (&raw const (*self.head()).Blink).read() })
    }

    fn next(&self, id: *mut Entry) -> Option<*mut Entry> {
        // SAFETY: `of`'s contract: `id` is an entry of the list.
        self.entry(unsafe { (&raw const (*id).links.Flink).read() })
    }

    fn previous(&self, id: *mut Entry) -> Option<*mut Entry> {
        // SAFETY: as for `next`.
        self.entry(unsafe { (&raw const (*id).links.Blink).read() })
    }

    fn range(&self, id: *mut Entry) -> Range {
        // SAFETY: as for `next`.
        unsafe {
            Range {
                start: (&raw const (*id).range.Start).read(),
                end: (&raw const (*id).range.End).read(),
                attributes: (&raw const (*id).range.Attributes).read(),
                flags: (&raw const (*id).range.Flags).read(),
                owner: (&raw const (*id).range.Owner).read().addr(),
            }
        }
    }

    fn set_flags(&mut self, id: *mut Entry, flags: u8) {
        // SAFETY: as for `next`.
        unsafe { (&raw mut (*id).range.Flags).write(flags) }
    }

    fn insert(&mut self, new: *mut Entry, before: Option<*mut Entry>) {
        // SAFETY: `of`'s contract; `new` is a block of the caller's that
        // is in no list.
        unsafe {
            let after = match before {
                Some(before) => &raw mut (*before).links,
                None => self.head(),
            };
            let links = &raw mut (*new).links;
            let previous = (&raw const (*after).Blink).read();
            links.write(LIST_ENTRY {
                Flink: after,
                Blink: previous,
            });
            (&raw mut (*previous).Flink).write(links);
            (&raw mut (*after).Blink).write(links);
        }
    }

    fn remove(&mut self, id: *mut Entry) {
        // SAFETY: as for `next`.
        unsafe {
            let LIST_ENTRY { Flink, Blink } = (&raw const (*id).links).read();
            (&raw mut (*Blink).Flink).write(Flink);
            (&raw mut (*Flink).Blink).write(Blink);
        }
    }
}

/// Count one change to the list: `by` more ranges, and a new stamp.
///
/// # Safety
/// `list` is a range list.
unsafe fn changed(list: *mut RTL_RANGE_LIST, by: i32) {
    // SAFETY: per the contract.
    unsafe {
        let count = &raw mut (*list).Count;
        count.write(count.read().wrapping_add_signed(by));
        let stamp = &raw mut (*list).Stamp;
        stamp.write(stamp.read().wrapping_add(1));
    }
}

/// Give an entry back to the pool. One added with the flag 0x10 gives
/// up its share of its user data, a pool block of the driver's that
/// starts with a count of the entries pointing to it, and frees the
/// block with the last share: what the pinned kernel does
/// (`RtlpFreeRangeListEntry`).
fn free(entry: *mut Entry) {
    // SAFETY: the entry is a pool block of this module's, in no list;
    // counted user data is, by the flag's contract, a pool block that
    // starts with a `ULONG`. The caller serialises the list's users.
    unsafe {
        if (&raw const (*entry).range.Flags).read() & range::COUNTED != 0 {
            let data = (&raw const (*entry).range.UserData).read();
            let count = data.cast::<u32>();
            let left = count.read_unaligned().wrapping_sub(1);
            count.write_unaligned(left);
            if left == 0 {
                pool::ExFreePoolWithTag(data, 0);
            }
        }
        pool::ExFreePoolWithTag(entry.cast(), TAG);
    }
}

/// `RtlInitializeRangeList`: make `list` an empty list.
///
/// # Safety
/// `list` is writable.
pub unsafe extern "C" fn RtlInitializeRangeList(list: *mut RTL_RANGE_LIST) {
    // SAFETY: per the contract.
    unsafe {
        list.write(RTL_RANGE_LIST {
            ListHead: LIST_ENTRY {
                Flink: list.cast(),
                Blink: list.cast(),
            },
            Flags: 0,
            Count: 0,
            Stamp: 0,
        });
    }
}

/// `RtlFreeRangeList`: free every range of `list`, which is then empty.
/// The stamp is left as it is, as on Windows.
///
/// # Safety
/// `list` is an initialised range list.
pub unsafe extern "C" fn RtlFreeRangeList(list: *mut RTL_RANGE_LIST) {
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*list).Flags).write(0);
        (&raw mut (*list).Count).write(0);
        let mut ranges = Driver::of(list);
        while let Some(entry) = ranges.first() {
            ranges.remove(entry);
            free(entry);
        }
    }
}

/// `RtlAddRange`: add `start..=end` to the list. `STATUS_RANGE_LIST_CONFLICT`
/// if it overlaps a range it may not share with, unless the flags say
/// to add it anyway.
///
/// With the flag 0x10, which no header declares and `acpi.sys`
/// passes, `user_data` is a pool block of the caller's that starts
/// with a `ULONG` count of the entries that point to it. The range is
/// marked (0x10 in its flags); adding does not count, a copy of the
/// entry counts one more, and an entry freed counts one less and
/// frees the block at zero, an entry this call could not add included.
///
/// # Safety
/// `list` is an initialised range list; with the flag 0x10,
/// `user_data` is such a block.
pub unsafe extern "C" fn RtlAddRange(
    list: *mut RTL_RANGE_LIST,
    start: u64,
    end: u64,
    attributes: u8,
    flags: u32,
    user_data: *mut c_void,
    owner: *mut c_void,
) -> NTSTATUS {
    if end < start {
        return STATUS_INVALID_PARAMETER;
    }
    let entry = pool::alloc(size_of::<Entry>(), TAG).cast::<Entry>();
    if entry.is_null() {
        // Windows' status for an entry it cannot allocate.
        return STATUS_UNSUCCESSFUL;
    }
    // SAFETY: the block is fresh and large enough; the list is the
    // caller's, per the contract.
    unsafe {
        (&raw mut (*entry).range).write(RTL_RANGE {
            Start: start,
            End: end,
            UserData: user_data,
            Owner: owner,
            Attributes: attributes,
            Flags: if flags & range::ADD_SHARED != 0 {
                range::SHARED
            } else {
                0
            } | if flags & range::ADD_COUNTED != 0 {
                range::COUNTED
            } else {
                0
            },
        });
        let mut ranges = Driver::of(list);
        if range::add(&mut ranges, entry, flags & range::ADD_IF_CONFLICT != 0).is_err() {
            free(entry);
            return STATUS_RANGE_LIST_CONFLICT;
        }
        changed(list, 1);
    }
    STATUS_SUCCESS
}

/// `RtlDeleteRange`: delete the range that starts and ends there and
/// has that owner; `STATUS_RANGE_NOT_FOUND` if there is none.
///
/// # Safety
/// `list` is an initialised range list.
pub unsafe extern "C" fn RtlDeleteRange(
    list: *mut RTL_RANGE_LIST,
    start: u64,
    end: u64,
    owner: *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let mut ranges = Driver::of(list);
        let Some(entry) = range::find_exact(&ranges, start, end, owner.addr()) else {
            return STATUS_RANGE_NOT_FOUND;
        };
        range::remove(&mut ranges, entry);
        free(entry);
        changed(list, -1);
    }
    STATUS_SUCCESS
}

/// `RtlDeleteOwnersRanges`: delete every range of that owner.
///
/// # Safety
/// `list` is an initialised range list.
pub unsafe extern "C" fn RtlDeleteOwnersRanges(
    list: *mut RTL_RANGE_LIST,
    owner: *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let mut ranges = Driver::of(list);
        while let Some(entry) = range::owned_by(&ranges, owner.addr()) {
            range::remove(&mut ranges, entry);
            free(entry);
            changed(list, -1);
        }
    }
    STATUS_SUCCESS
}

/// `RtlCopyRangeList`: make `copy`, which must hold no ranges, a copy of
/// `source`, flags, count and stamp included. Counted user data
/// (`RtlAddRange`'s flag 0x10) is counted once more for each copy of an
/// entry that points to it.
///
/// # Safety
/// Both are initialised range lists.
pub unsafe extern "C" fn RtlCopyRangeList(
    copy: *mut RTL_RANGE_LIST,
    source: *mut RTL_RANGE_LIST,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        if (&raw const (*copy).Count).read() != 0 {
            return STATUS_INVALID_PARAMETER;
        }
        (&raw mut (*copy).Flags).write((&raw const (*source).Flags).read());
        (&raw mut (*copy).Count).write((&raw const (*source).Count).read());
        (&raw mut (*copy).Stamp).write((&raw const (*source).Stamp).read());
        let (from, mut to) = (Driver::of(source), Driver::of(copy));
        let mut at = from.first();
        while let Some(entry) = at {
            let twin = pool::alloc(size_of::<Entry>(), TAG).cast::<Entry>();
            if twin.is_null() {
                RtlFreeRangeList(copy);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            (&raw mut (*twin).range)
                .cast::<u8>()
                .copy_from_nonoverlapping(
                    (&raw const (*entry).range).cast(),
                    size_of::<RTL_RANGE>(),
                );
            // The copy points to the same counted user data.
            if (&raw const (*twin).range.Flags).read() & range::COUNTED != 0 {
                let count = (&raw const (*twin).range.UserData).read().cast::<u32>();
                count.write_unaligned(count.read_unaligned().wrapping_add(1));
            }
            to.insert(twin, None);
            at = from.next(entry);
        }
    }
    STATUS_SUCCESS
}

/// A caller's `PRTL_CONFLICT_RANGE_CALLBACK`, as the search asks it
/// whether to pass a range over.
///
/// # Safety
/// `callback` is null or a routine of that type, callable with
/// `context`.
unsafe fn asker(context: *mut c_void, callback: *const c_void) -> impl FnMut(*mut Entry) -> bool {
    move |entry| {
        if callback.is_null() {
            return false;
        }
        // The entry starts with the range a driver may see. The search
        // holds nothing a driver's exception would leave behind.
        let arguments = [context.addr(), entry.addr(), 0, 0];
        // SAFETY: per the contract.
        let answer = unsafe { seh::call(callback.addr(), arguments, &Guard::Nothing) };
        // A `BOOLEAN`: only the low byte is the answer.
        answer as u8 != 0
    }
}

/// `RtlFindRange`: the highest start, a multiple of `alignment`, of
/// `length` available bytes between `minimum` and `maximum`. What makes
/// a place available is stated at `nk_rtl::range`.
/// `STATUS_UNSUCCESSFUL` if there is none.
///
/// # Safety
/// `list` is an initialised range list, `callback` is null or a
/// `PRTL_CONFLICT_RANGE_CALLBACK`, and `start` is writable.
pub unsafe extern "C" fn RtlFindRange(
    list: *mut RTL_RANGE_LIST,
    minimum: u64,
    maximum: u64,
    length: u64,
    alignment: u64,
    flags: u32,
    attribute_available_mask: u8,
    context: *mut c_void,
    callback: *const c_void,
    start: *mut u64,
) -> NTSTATUS {
    let tolerance = Tolerance {
        flags,
        attributes: attribute_available_mask,
    };
    // SAFETY: per the contract.
    unsafe {
        let ranges = Driver::of(list);
        let mut ask = asker(context, callback);
        match range::find(
            &ranges,
            (minimum, maximum),
            length,
            alignment,
            tolerance,
            &mut ask,
        ) {
            Ok(found) => {
                start.write_unaligned(found);
                STATUS_SUCCESS
            }
            Err(FindError::InvalidParameter) => STATUS_INVALID_PARAMETER,
            Err(FindError::Unsuccessful) => STATUS_UNSUCCESSFUL,
        }
    }
}

/// `RtlIsRangeAvailable`: whether `start..=end` is available.
///
/// # Safety
/// `list` is an initialised range list, `callback` is null or a
/// `PRTL_CONFLICT_RANGE_CALLBACK`, and `available` is writable.
pub unsafe extern "C" fn RtlIsRangeAvailable(
    list: *mut RTL_RANGE_LIST,
    start: u64,
    end: u64,
    flags: u32,
    attribute_available_mask: u8,
    context: *mut c_void,
    callback: *const c_void,
    available: *mut u8,
) -> NTSTATUS {
    let tolerance = Tolerance {
        flags,
        attributes: attribute_available_mask,
    };
    // SAFETY: per the contract.
    unsafe {
        let ranges = Driver::of(list);
        let mut ask = asker(context, callback);
        let met = range::in_the_way(
            &ranges,
            ranges.first(),
            true,
            (start, end),
            tolerance,
            &mut ask,
        );
        available.write(u8::from(met.is_none()));
    }
    STATUS_SUCCESS
}

/// Store where an iterator now is, and say whether that is a range.
///
/// # Safety
/// `iterator` and `found` are writable.
unsafe fn at(
    iterator: *mut RTL_RANGE_LIST_ITERATOR,
    found: *mut *mut RTL_RANGE,
    entry: Option<*mut Entry>,
) -> NTSTATUS {
    let entry = entry.unwrap_or(core::ptr::null_mut());
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*iterator).Current).write(entry.cast());
        found.write_unaligned(entry.cast());
    }
    if entry.is_null() {
        STATUS_NO_MORE_ENTRIES
    } else {
        STATUS_SUCCESS
    }
}

/// `RtlGetFirstRange`: start `iterator` at the first range of `list`.
/// `STATUS_NO_MORE_ENTRIES`, and a null range, if the list is empty.
///
/// # Safety
/// `list` is an initialised range list; `iterator` and `found` are
/// writable.
pub unsafe extern "C" fn RtlGetFirstRange(
    list: *mut RTL_RANGE_LIST,
    iterator: *mut RTL_RANGE_LIST_ITERATOR,
    found: *mut *mut RTL_RANGE,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*iterator).RangeListHead).write(list.cast());
        (&raw mut (*iterator).MergedHead).write(core::ptr::null_mut());
        (&raw mut (*iterator).Stamp).write((&raw const (*list).Stamp).read());
        at(iterator, found, Driver::of(list).first())
    }
}

/// `RtlGetNextRange`: move `iterator` to the range after, or before,
/// the one it is at. `STATUS_INVALID_PARAMETER` if the list has changed
/// since the iterator was started; `STATUS_NO_MORE_ENTRIES`, and a null
/// range, past either end.
///
/// # Safety
/// `iterator` was started by `RtlGetFirstRange` on a list that is still
/// initialised; `found` is writable.
pub unsafe extern "C" fn RtlGetNextRange(
    iterator: *mut RTL_RANGE_LIST_ITERATOR,
    found: *mut *mut RTL_RANGE,
    move_forwards: u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let list = (&raw const (*iterator).RangeListHead)
            .read()
            .cast::<RTL_RANGE_LIST>();
        if (&raw const (*list).Stamp).read() != (&raw const (*iterator).Stamp).read() {
            return STATUS_INVALID_PARAMETER;
        }
        let ranges = Driver::of(list);
        let current = (&raw const (*iterator).Current).read().cast::<Entry>();
        let entry = if current.is_null() {
            None
        } else if move_forwards != 0 {
            ranges.next(current)
        } else {
            ranges.previous(current)
        };
        at(iterator, found, entry)
    }
}

/// `RtlInvertRangeListEx`: add to `inverted` a range for every gap
/// between the ranges of `list`, each with these attributes, user data
/// and owner.
///
/// # Safety
/// Both are initialised range lists.
pub unsafe extern "C" fn RtlInvertRangeListEx(
    inverted: *mut RTL_RANGE_LIST,
    list: *mut RTL_RANGE_LIST,
    attributes: u8,
    user_data: *mut c_void,
    owner: *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        let ranges = Driver::of(list);
        for (start, end) in range::gaps(&ranges) {
            let status = RtlAddRange(inverted, start, end, attributes, 0, user_data, owner);
            if !nt_success(status) {
                return status;
            }
        }
    }
    STATUS_SUCCESS
}

/// `RtlInvertRangeList`: [`RtlInvertRangeListEx`] with no attributes,
/// user data or owner.
///
/// # Safety
/// Both are initialised range lists.
pub unsafe extern "C" fn RtlInvertRangeList(
    inverted: *mut RTL_RANGE_LIST,
    list: *mut RTL_RANGE_LIST,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        RtlInvertRangeListEx(
            inverted,
            list,
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    }
}
