//! Bitmaps. The header and the buffer are the driver's memory; the
//! rules are `nk_rtl::bitmap`, which is handed the buffer to read and
//! write through raw pointers ([`Driver`]). Nothing is kept here. The
//! caller serialises the calls on one bitmap, as on Windows, except the
//! interlocked ones, which change a `ULONG` at a time atomically.

#![allow(non_snake_case)]

use core::sync::atomic::{AtomicU32, Ordering};
use nk_ntabi::rtl::RTL_BITMAP;
use nk_rtl::bitmap::{self, Bits};

/// A driver's bitmap buffer.
struct Driver(*mut u32);

impl Bits for Driver {
    fn byte(&self, index: usize) -> u8 {
        // SAFETY: `of`'s contract: the routines of `nk_rtl::bitmap` reach
        // only what Windows' reach of the buffer.
        unsafe { self.0.cast::<u8>().add(index).read() }
    }

    fn set_byte(&mut self, index: usize, value: u8) {
        // SAFETY: as for `byte`.
        unsafe { self.0.cast::<u8>().add(index).write(value) }
    }

    fn word(&self, index: usize) -> u32 {
        // SAFETY: as for `byte`.
        unsafe { self.0.add(index).read_unaligned() }
    }
}

/// The buffer and the size in bits of the bitmap at `header`.
///
/// # Safety
/// `header` points to an initialised bitmap header, and the buffer holds
/// the bitmap's `ULONG`s and whatever bits past them the caller goes on
/// to name, for as long as the result is used.
unsafe fn of(header: *const RTL_BITMAP) -> (Driver, u32) {
    // SAFETY: per the contract.
    unsafe {
        (
            Driver((&raw const (*header).Buffer).read()),
            (&raw const (*header).SizeOfBitMap).read(),
        )
    }
}

/// [`RtlInitializeBitMap`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlinitializebitmap).
/// The buffer's bits are left as they are.
///
/// # Safety
/// `header` is writable.
pub unsafe extern "C" fn RtlInitializeBitMap(header: *mut RTL_BITMAP, buffer: *mut u32, size: u32) {
    // SAFETY: per the contract.
    unsafe {
        (&raw mut (*header).SizeOfBitMap).write(size);
        (&raw mut (*header).Buffer).write(buffer);
    }
}

/// [`RtlClearAllBits`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearallbits).
///
/// # Safety
/// `header` is an initialised bitmap.
pub unsafe extern "C" fn RtlClearAllBits(header: *mut RTL_BITMAP) {
    // SAFETY: per the contract.
    let (mut bits, size) = unsafe { of(header) };
    bitmap::fill(&mut bits, size, false);
}

/// [`RtlSetAllBits`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetallbits).
///
/// # Safety
/// `header` is an initialised bitmap.
pub unsafe extern "C" fn RtlSetAllBits(header: *mut RTL_BITMAP) {
    // SAFETY: per the contract.
    let (mut bits, size) = unsafe { of(header) };
    bitmap::fill(&mut bits, size, true);
}

/// [`RtlClearBit`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearbit).
///
/// # Safety
/// `header` is an initialised bitmap that has bit `index`.
pub unsafe extern "C" fn RtlClearBit(header: *mut RTL_BITMAP, index: u32) {
    // SAFETY: per the contract.
    let (mut bits, _) = unsafe { of(header) };
    bitmap::set_run(&mut bits, index, 1, false);
}

/// [`RtlSetBit`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetbit).
///
/// # Safety
/// `header` is an initialised bitmap that has bit `index`.
pub unsafe extern "C" fn RtlSetBit(header: *mut RTL_BITMAP, index: u32) {
    // SAFETY: per the contract.
    let (mut bits, _) = unsafe { of(header) };
    bitmap::set_run(&mut bits, index, 1, true);
}

/// [`RtlTestBit`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtltestbit).
///
/// # Safety
/// `header` is an initialised bitmap that has bit `index`.
pub unsafe extern "C" fn RtlTestBit(header: *const RTL_BITMAP, index: u32) -> u8 {
    // SAFETY: per the contract.
    let (bits, _) = unsafe { of(header) };
    u8::from(bitmap::test(&bits, index))
}

/// [`RtlClearBits`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlclearbits).
///
/// # Safety
/// `header` is an initialised bitmap that has the run.
pub unsafe extern "C" fn RtlClearBits(header: *mut RTL_BITMAP, start: u32, count: u32) {
    // SAFETY: per the contract.
    let (mut bits, _) = unsafe { of(header) };
    bitmap::set_run(&mut bits, start, count, false);
}

/// [`RtlSetBits`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlsetbits).
///
/// # Safety
/// `header` is an initialised bitmap that has the run.
pub unsafe extern "C" fn RtlSetBits(header: *mut RTL_BITMAP, start: u32, count: u32) {
    // SAFETY: per the contract.
    let (mut bits, _) = unsafe { of(header) };
    bitmap::set_run(&mut bits, start, count, true);
}

/// [`RtlAreBitsClear`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlarebitsclear).
///
/// # Safety
/// `header` is an initialised bitmap.
pub unsafe extern "C" fn RtlAreBitsClear(header: *const RTL_BITMAP, start: u32, length: u32) -> u8 {
    // SAFETY: per the contract.
    let (bits, size) = unsafe { of(header) };
    u8::from(bitmap::are_clear(&bits, size, start, length))
}

/// [`RtlFindSetBits`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindsetbits).
///
/// # Safety
/// `header` is an initialised bitmap.
pub unsafe extern "C" fn RtlFindSetBits(header: *const RTL_BITMAP, count: u32, hint: u32) -> u32 {
    // SAFETY: per the contract.
    let (bits, size) = unsafe { of(header) };
    bitmap::find_set(&bits, size, count, hint).unwrap_or(u32::MAX)
}

/// [`RtlFindClearBits`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindclearbits).
///
/// # Safety
/// `header` is an initialised bitmap.
pub unsafe extern "C" fn RtlFindClearBits(header: *const RTL_BITMAP, count: u32, hint: u32) -> u32 {
    // SAFETY: per the contract.
    let (bits, size) = unsafe { of(header) };
    bitmap::find_clear(&bits, size, count, hint).unwrap_or(u32::MAX)
}

/// [`RtlFindClearBitsAndSet`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindclearbitsandset):
/// find a clear run of `count` bits starting at `hint`, set those bits, and
/// return the starting index (or `u32::MAX` if no such run exists).
///
/// # Safety
/// `header` is an initialised bitmap.
pub unsafe extern "C" fn RtlFindClearBitsAndSet(
    header: *mut RTL_BITMAP,
    count: u32,
    hint: u32,
) -> u32 {
    // SAFETY: per the contract.
    let (mut bits, size) = unsafe { of(header) };
    let Some(start) = bitmap::find_clear(&bits, size, count, hint) else {
        return u32::MAX;
    };
    bitmap::set_run(&mut bits, start, count, true);
    start
}

/// Store a run's start and return its length.
///
/// # Safety
/// `start` is writable.
unsafe fn run(start: *mut u32, (index, length): (u32, u32)) -> u32 {
    // SAFETY: per the contract.
    unsafe { start.write_unaligned(index) };
    length
}

/// [`RtlFindFirstRunClear`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindfirstrunclear).
///
/// # Safety
/// `header` is an initialised bitmap and `start` is writable.
pub unsafe extern "C" fn RtlFindFirstRunClear(header: *const RTL_BITMAP, start: *mut u32) -> u32 {
    // SAFETY: per the contract.
    unsafe {
        let (bits, size) = of(header);
        run(start, bitmap::next_clear_run(&bits, size, 0))
    }
}

/// [`RtlFindLongestRunClear`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindlongestrunclear).
///
/// # Safety
/// `header` is an initialised bitmap and `start` is writable.
pub unsafe extern "C" fn RtlFindLongestRunClear(header: *const RTL_BITMAP, start: *mut u32) -> u32 {
    // SAFETY: per the contract.
    unsafe {
        let (bits, size) = of(header);
        run(start, bitmap::longest_clear_run(&bits, size))
    }
}

/// [`RtlFindNextForwardRunClear`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindnextforwardrunclear).
///
/// # Safety
/// `header` is an initialised bitmap and `start` is writable.
pub unsafe extern "C" fn RtlFindNextForwardRunClear(
    header: *const RTL_BITMAP,
    from: u32,
    start: *mut u32,
) -> u32 {
    // SAFETY: per the contract.
    unsafe {
        let (bits, size) = of(header);
        run(start, bitmap::next_clear_run(&bits, size, from))
    }
}

/// [`RtlFindLastBackwardRunClear`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindlastbackwardrunclear).
///
/// # Safety
/// `header` is an initialised bitmap and `start` is writable.
pub unsafe extern "C" fn RtlFindLastBackwardRunClear(
    header: *const RTL_BITMAP,
    from: u32,
    start: *mut u32,
) -> u32 {
    // SAFETY: per the contract.
    unsafe {
        let (bits, size) = of(header);
        run(start, bitmap::last_clear_run(&bits, size, from))
    }
}

/// [`RtlNumberOfClearBits`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofclearbits).
///
/// # Safety
/// `header` is an initialised bitmap.
pub unsafe extern "C" fn RtlNumberOfClearBits(header: *const RTL_BITMAP) -> u32 {
    // SAFETY: per the contract.
    let (bits, size) = unsafe { of(header) };
    size - bitmap::count_set(&bits, size)
}

/// [`RtlNumberOfSetBits`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofsetbits).
///
/// # Safety
/// `header` is an initialised bitmap.
pub unsafe extern "C" fn RtlNumberOfSetBits(header: *const RTL_BITMAP) -> u32 {
    // SAFETY: per the contract.
    let (bits, size) = unsafe { of(header) };
    bitmap::count_set(&bits, size)
}

/// [`RtlNumberOfSetBitsUlongPtr`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlnumberofsetbitsulongptr).
pub extern "C" fn RtlNumberOfSetBitsUlongPtr(target: usize) -> u32 {
    target.count_ones()
}

/// [`RtlFindLeastSignificantBit`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindleastsignificantbit).
pub extern "C" fn RtlFindLeastSignificantBit(set: u64) -> i8 {
    bitmap::least_significant(set)
}

/// [`RtlFindMostSignificantBit`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlfindmostsignificantbit).
pub extern "C" fn RtlFindMostSignificantBit(set: u64) -> i8 {
    bitmap::most_significant(set)
}

/// [`RtlCopyBitMap`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopybitmap):
/// the source's bits, as many as fit, to `target` and after it in the
/// destination. The two may share a buffer.
///
/// # Safety
/// Both are initialised bitmaps.
pub unsafe extern "C" fn RtlCopyBitMap(
    source: *const RTL_BITMAP,
    destination: *const RTL_BITMAP,
    target: u32,
) {
    // SAFETY: per the contract.
    let ((from, from_size), (mut to, to_size)) = unsafe { (of(source), of(destination)) };
    let count = bitmap::copy_count(from_size, to_size, target);
    // Where each run starts, in bits of the address space: bits that
    // move up are copied last bit first, as `memmove` would.
    let place = |buffer: *mut u32, bit: u32| (buffer as u128) * 8 + u128::from(bit);
    let backward = place(to.0, target) > place(from.0, 0);
    bitmap::copy(&from, &mut to, target, count, backward);
}

/// The `index`th `ULONG` of the bitmap at `header`, as an atomic.
///
/// # Safety
/// `header` is an initialised bitmap whose buffer is aligned as an array
/// of `ULONG`s is and holds that `ULONG`, for as long as the result is
/// used.
unsafe fn atomic<'a>(header: *const RTL_BITMAP, index: usize) -> &'a AtomicU32 {
    // SAFETY: per the contract. An atomic may be written by others
    // while it is referred to.
    unsafe { AtomicU32::from_ptr((&raw const (*header).Buffer).read().add(index)) }
}

/// `RtlInterlockedSetBitRun` (`wdm.h`): set a run of bits, each `ULONG`
/// of it atomically. Declared in the WDK and not documented.
///
/// # Safety
/// `header` is an initialised bitmap that has the run.
pub unsafe extern "C" fn RtlInterlockedSetBitRun(header: *mut RTL_BITMAP, start: u32, count: u32) {
    for (index, mask) in bitmap::words(start, count) {
        // SAFETY: per the contract.
        unsafe { atomic(header, index) }.fetch_or(mask, Ordering::SeqCst);
    }
}

/// `RtlInterlockedClearBitRun` (`wdm.h`): clear a run of bits, each
/// `ULONG` of it atomically.
///
/// # Safety
/// `header` is an initialised bitmap that has the run.
pub unsafe extern "C" fn RtlInterlockedClearBitRun(
    header: *mut RTL_BITMAP,
    start: u32,
    count: u32,
) {
    for (index, mask) in bitmap::words(start, count) {
        // SAFETY: per the contract.
        unsafe { atomic(header, index) }.fetch_and(!mask, Ordering::SeqCst);
    }
}

/// `RtlInterlockedSetClearRun` (`wdm.h`): take a run of clear bits by
/// setting them, each `ULONG` atomically. Returns 1 with the run set;
/// if a bit of it is set already, returns 0 with the run as it was
/// found (the part taken before the set bit was met is cleared again).
/// The result fills the register, so a caller may read it as a
/// `BOOLEAN` or as a `ULONG`.
///
/// # Safety
/// `header` is an initialised bitmap that has the run.
pub unsafe extern "C" fn RtlInterlockedSetClearRun(
    header: *mut RTL_BITMAP,
    start: u32,
    count: u32,
) -> u32 {
    for (taken, (index, mask)) in bitmap::words(start, count).enumerate() {
        // SAFETY: per the contract.
        let word = unsafe { atomic(header, index) };
        let took = word.try_update(Ordering::SeqCst, Ordering::SeqCst, |bits| {
            (bits & mask == 0).then_some(bits | mask)
        });
        if took.is_err() {
            for (index, mask) in bitmap::words(start, count).take(taken) {
                // SAFETY: per the contract.
                unsafe { atomic(header, index) }.fetch_and(!mask, Ordering::SeqCst);
            }
            return 0;
        }
    }
    1
}
