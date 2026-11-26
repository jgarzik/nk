//! Range lists through the routines drivers call, with a conflict
//! callback as a driver has one. The rules themselves are tested on the
//! host (`nk_rtl::range`).

use crate::rtl::range::*;
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_bootinfo::BootInfo;
use nk_ntabi::rtl::{RTL_RANGE, RTL_RANGE_LIST, RTL_RANGE_LIST_ITERATOR};
use nk_ntabi::status::*;

static GROUP: Group = Group {
    names: &["rtl.range-list"],
    run,
    manual: false,
};

const ADD_IF_CONFLICT: u32 = 1;
const ADD_SHARED: u32 = 2;
const SHARED: u8 = 1;
const CONFLICT: u8 = 2;

/// A `PRTL_CONFLICT_RANGE_CALLBACK`: counts its calls in the context,
/// and passes over the ranges of owner 2.
extern "C" fn pass_owner_two(context: *mut c_void, range: *mut RTL_RANGE) -> u8 {
    // SAFETY: the context is the test's counter, and the range one of
    // the list's.
    unsafe {
        *context.cast::<u32>() += 1;
        u8::from((*range).Owner.addr() == 2)
    }
}

/// The ranges of `list`, front to back and then back to front, as the
/// iterator hands them out: start, end, flags.
///
/// # Safety
/// `list` is an initialised range list.
unsafe fn walk(list: *mut RTL_RANGE_LIST) -> Result<Vec<(u64, u64, u8)>, &'static str> {
    // SAFETY: per the contract; the iterator and the range pointer are
    // locals.
    unsafe {
        let mut iterator = core::mem::zeroed::<RTL_RANGE_LIST_ITERATOR>();
        let mut range = core::ptr::null_mut::<RTL_RANGE>();
        let mut seen = Vec::new();
        let mut status = RtlGetFirstRange(list, &raw mut iterator, &raw mut range);
        let mut last = range;
        while status == STATUS_SUCCESS {
            seen.push(((*range).Start, (*range).End, (*range).Flags));
            last = range;
            status = RtlGetNextRange(&raw mut iterator, &raw mut range, 1);
        }
        if status != STATUS_NO_MORE_ENTRIES || !range.is_null() {
            return Err("an iterator did not end with no more entries and a null range");
        }
        // Past the end the iterator stays there; a fresh walk backward
        // from the last range gives the same ranges in reverse.
        if RtlGetNextRange(&raw mut iterator, &raw mut range, 0) != STATUS_NO_MORE_ENTRIES {
            return Err("an iterator past the end came back");
        }
        if !last.is_null() {
            RtlGetFirstRange(list, &raw mut iterator, &raw mut range);
            let mut forward = 1;
            while range != last {
                RtlGetNextRange(&raw mut iterator, &raw mut range, 1);
                forward += 1;
            }
            let mut backward = 1;
            while RtlGetNextRange(&raw mut iterator, &raw mut range, 0) == STATUS_SUCCESS {
                backward += 1;
            }
            if forward != seen.len() || backward != seen.len() {
                return Err("an iterator walked backward over other ranges than forward");
            }
        }
        Ok(seen)
    }
}

fn range_list() -> Result<(), &'static str> {
    let owner = |number: usize| core::ptr::without_provenance_mut::<c_void>(number);
    let none = core::ptr::null_mut::<c_void>();
    // SAFETY: the lists are locals, initialised before use and freed
    // before the test returns; the other pointers are to locals.
    unsafe {
        let mut header = core::mem::zeroed::<RTL_RANGE_LIST>();
        let list = &raw mut header;
        RtlInitializeRangeList(list);
        if !walk(list)?.is_empty() {
            return Err("a new range list is not empty");
        }
        let added = [
            RtlAddRange(list, 0x3000, 0x3FFF, 0, 0, none, owner(1)),
            RtlAddRange(list, 0x1000, 0x1FFF, 0, ADD_SHARED, none, owner(2)),
            RtlAddRange(list, 0x1800, 0x27FF, 0, ADD_SHARED, none, owner(3)),
            RtlAddRange(list, 0x8000, 0x8FFF, 0x40, 0, none, owner(1)),
        ];
        if added != [STATUS_SUCCESS; 4] || (header.Count, header.Stamp) != (4, 4) {
            return Err("RtlAddRange did not add ranges that do not conflict");
        }
        if RtlAddRange(list, 0x3800, 0x4000, 0, 0, none, owner(4)) != STATUS_RANGE_LIST_CONFLICT
            || RtlAddRange(list, 0x1000, 0x1000, 0, 0, none, owner(4)) != STATUS_RANGE_LIST_CONFLICT
            || RtlAddRange(list, 2, 1, 0, 0, none, owner(4)) != STATUS_INVALID_PARAMETER
            || (header.Count, header.Stamp) != (4, 4)
        {
            return Err("RtlAddRange took a range that conflicts, or ends before it starts");
        }
        if RtlAddRange(list, 0x3800, 0x4000, 0, ADD_IF_CONFLICT, none, owner(4)) != STATUS_SUCCESS {
            return Err("RtlAddRange refused a conflict it was told to add");
        }
        let expected = [
            (0x1000, 0x1FFF, SHARED),
            (0x1800, 0x27FF, SHARED),
            (0x3000, 0x3FFF, CONFLICT),
            (0x3800, 0x4000, CONFLICT),
            (0x8000, 0x8FFF, 0),
        ];
        if walk(list)? != expected {
            return Err("the ranges are not in order of start with their flags");
        }

        // An iterator is good for one stamp.
        let mut iterator = core::mem::zeroed::<RTL_RANGE_LIST_ITERATOR>();
        let mut range = core::ptr::null_mut::<RTL_RANGE>();
        RtlGetFirstRange(list, &raw mut iterator, &raw mut range);
        if RtlDeleteRange(list, 0x3800, 0x4000, owner(1)) != STATUS_RANGE_NOT_FOUND
            || RtlDeleteRange(list, 0x3800, 0x4000, owner(4)) != STATUS_SUCCESS
            || (header.Count, header.Stamp) != (4, 6)
            || RtlGetNextRange(&raw mut iterator, &raw mut range, 1) != STATUS_INVALID_PARAMETER
        {
            return Err("RtlDeleteRange did not delete by start, end and owner");
        }
        if walk(list)?[2] != (0x3000, 0x3FFF, 0) {
            return Err("deleting a range left its conflict on another");
        }

        // Availability, with the rules that pass a range over.
        let mut available = 9u8;
        let mut asked = 0u32;
        let context = (&raw mut asked).cast::<c_void>();
        let is_available = |start, end, flags, mask, callback: *const c_void| {
            let mut answer = 9u8;
            let status = RtlIsRangeAvailable(
                list,
                start,
                end,
                flags,
                mask,
                context,
                callback,
                &raw mut answer,
            );
            (status, answer)
        };
        let callback = pass_owner_two as *const c_void;
        if is_available(0x4000, 0x7FFF, 0, 0, none) != (STATUS_SUCCESS, 1)
            || is_available(0x4000, 0x8000, 0, 0, none) != (STATUS_SUCCESS, 0)
            || is_available(0x4000, 0x8000, 0, 0x40, none) != (STATUS_SUCCESS, 1)
            || is_available(0x1000, 0x2FFF, 0, 0, none) != (STATUS_SUCCESS, 0)
            || is_available(0x1000, 0x2FFF, 1, 0, none) != (STATUS_SUCCESS, 1)
        {
            return Err("RtlIsRangeAvailable misjudged a range");
        }
        // Owner 2's range is passed over by the callback; owner 3's is
        // not, and nothing after it is asked about.
        if is_available(0x1000, 0x17FF, 0, 0, callback) != (STATUS_SUCCESS, 1)
            || asked != 1
            || is_available(0x1000, 0x3FFF, 0, 0, callback) != (STATUS_SUCCESS, 0)
            || asked != 3
        {
            return Err("the conflict callback was not asked about the ranges in the way");
        }
        RtlIsRangeAvailable(list, 0, 0xFFF, 0, 0, none, none, &raw mut available);
        if available != 1 {
            return Err("an untouched range is not available");
        }

        // The highest place that fits, from the top down.
        let mut start = 0u64;
        let find = |minimum, maximum, length, alignment, flags| {
            let mut found = 0u64;
            let status = RtlFindRange(
                list,
                minimum,
                maximum,
                length,
                alignment,
                flags,
                0,
                none,
                none,
                &raw mut found,
            );
            (status, found)
        };
        if find(0, 0x8FFF, 0x1000, 0x1000, 0) != (STATUS_SUCCESS, 0x7000)
            || find(0, 0x3FFF, 0x800, 0x800, 0) != (STATUS_SUCCESS, 0x2800)
            || find(0, 0x3FFF, 0x1000, 0x1000, 0) != (STATUS_SUCCESS, 0)
            || find(0, 0x3FFF, 0x1000, 0x1000, 1) != (STATUS_SUCCESS, 0x2000)
            || find(0x800, 0x3FFF, 0x1000, 0x1000, 0).0 != STATUS_UNSUCCESSFUL
            || find(0, 0xFFF, 0x2000, 1, 0).0 != STATUS_INVALID_PARAMETER
            || find(0, 0xFFFF, 0x1000, 0, 0).0 != STATUS_INVALID_PARAMETER
        {
            return Err("RtlFindRange did not find the highest place that fits");
        }
        if RtlFindRange(
            list,
            0,
            0x1FFF,
            0x800,
            0x800,
            0,
            0,
            context,
            callback,
            &raw mut start,
        ) != STATUS_SUCCESS
            || start != 0x1000
        {
            return Err("RtlFindRange did not land on a range its callback passes over");
        }

        // A copy, and the inverse.
        let mut second = core::mem::zeroed::<RTL_RANGE_LIST>();
        let copy = &raw mut second;
        RtlInitializeRangeList(copy);
        if RtlCopyRangeList(copy, list) != STATUS_SUCCESS
            || (second.Count, second.Stamp) != (header.Count, header.Stamp)
            || walk(copy)? != walk(list)?
            || RtlCopyRangeList(copy, list) != STATUS_INVALID_PARAMETER
        {
            return Err("RtlCopyRangeList did not copy the list into an empty one");
        }
        RtlFreeRangeList(copy);
        if second.Count != 0 || !walk(copy)?.is_empty() {
            return Err("RtlFreeRangeList left ranges in the list");
        }
        if RtlInvertRangeList(copy, list) != STATUS_SUCCESS
            || walk(copy)?
                != [
                    (0, 0xFFF, 0),
                    (0x2800, 0x2FFF, 0),
                    (0x4000, 0x7FFF, 0),
                    (0x9000, u64::MAX, 0),
                ]
        {
            return Err("RtlInvertRangeList did not list the gaps");
        }
        RtlFreeRangeList(copy);
        RtlInitializeRangeList(copy);
        let mut marked = core::ptr::null_mut::<RTL_RANGE>();
        if RtlDeleteOwnersRanges(list, owner(1)) != STATUS_SUCCESS
            || header.Count != 2
            || RtlInvertRangeListEx(copy, list, 0x11, context, owner(7)) != STATUS_SUCCESS
            || second.Count != 2
            || RtlGetFirstRange(copy, &raw mut iterator, &raw mut marked) != STATUS_SUCCESS
            || ((*marked).Attributes, (*marked).UserData, (*marked).Owner)
                != (0x11, context, owner(7))
        {
            return Err("RtlDeleteOwnersRanges or RtlInvertRangeListEx did not do its work");
        }
        RtlFreeRangeList(copy);
        RtlFreeRangeList(list);
        if header.Count != 0 || header.ListHead.Flink != list.cast() {
            return Err("RtlFreeRangeList did not empty the list");
        }

        // Counted user data, as `acpi.sys` adds its interrupts: a pool
        // block that starts with a count, which a copy of the entry
        // raises and an entry freed lowers; the last frees the block.
        const TAG: u32 = u32::from_le_bytes(*b"NkRt");
        let data = crate::mm::pool::alloc_zeroed(16, TAG).cast::<u32>();
        if data.is_null() {
            return Err("no memory for a range's user data");
        }
        data.write(1);
        if RtlAddRange(list, 0x10, 0x1F, 0, 0x12, data.cast(), owner(1)) != STATUS_SUCCESS
            || data.read() != 1
            || walk(list)? != [(0x10, 0x1F, 0x11)]
        {
            return Err("RtlAddRange did not mark a range with counted user data");
        }
        RtlInitializeRangeList(copy);
        if RtlCopyRangeList(copy, list) != STATUS_SUCCESS || data.read() != 2 {
            return Err("a copy of a range did not count its user data once more");
        }
        RtlFreeRangeList(copy);
        if data.read() != 1 || crate::mm::pool::info(data.cast()).is_none() {
            return Err("freeing the copy did not give up one share of the user data");
        }
        if RtlDeleteRange(list, 0x10, 0x1F, owner(1)) != STATUS_SUCCESS
            || crate::mm::pool::info(data.cast()).is_some()
        {
            return Err("the last range freed did not free its counted user data");
        }
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("rtl.range-list", range_list);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
