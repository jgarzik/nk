//! Bitmaps through the routines drivers call, on a buffer as a driver
//! has one. The rules themselves are tested on the host
//! (`nk_rtl::bitmap`).

use crate::rtl::bitmap::*;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_ntabi::rtl::RTL_BITMAP;

static GROUP: Group = Group {
    names: &["rtl.bitmap"],
    run,
    manual: false,
};

fn bitmap() -> Result<(), &'static str> {
    let mut buffer = [0x5555_5555u32; 4];
    let mut header = RTL_BITMAP {
        SizeOfBitMap: 0,
        Buffer: core::ptr::null_mut(),
    };
    let map = &raw mut header;
    let mut start = 0u32;
    // SAFETY: the header and its buffer are locals, 100 bits of 128, and
    // every run named lies within the buffer.
    unsafe {
        RtlInitializeBitMap(map, (&raw mut buffer).cast(), 100);
        if (*map).SizeOfBitMap != 100 || buffer[0] != 0x5555_5555 {
            return Err("RtlInitializeBitMap did not fill in the header and leave the bits");
        }
        RtlClearAllBits(map);
        if buffer != [0; 4] || RtlNumberOfClearBits(map) != 100 {
            return Err("RtlClearAllBits left a bit set");
        }
        RtlSetBits(map, 30, 10);
        RtlSetBit(map, 64);
        RtlClearBit(map, 35);
        if buffer != [0xC000_0000, 0xF7, 1, 0] {
            return Err("RtlSetBits, RtlSetBit and RtlClearBit set other bits than asked");
        }
        if RtlTestBit(map, 34) != 1 || RtlTestBit(map, 35) != 0 || RtlTestBit(map, 64) != 1 {
            return Err("RtlTestBit misread a bit");
        }
        if RtlNumberOfClearBits(map) != 90 {
            return Err("RtlNumberOfClearBits miscounted");
        }
        if RtlAreBitsClear(map, 0, 30) != 1
            || RtlAreBitsClear(map, 0, 31) != 0
            || RtlAreBitsClear(map, 65, 35) != 1
            || RtlAreBitsClear(map, 65, 36) != 0
            || RtlAreBitsClear(map, 0, 0) != 0
        {
            return Err("RtlAreBitsClear misjudged a run");
        }
        // Set: 30..35, 36..40, 64.
        if RtlFindSetBits(map, 4, 0) != 30
            || RtlFindSetBits(map, 4, 32) != 36
            || RtlFindSetBits(map, 5, 31) != 30
            || RtlFindSetBits(map, 6, 0) != u32::MAX
            || RtlFindSetBits(map, 0, 13) != 8
        {
            return Err("RtlFindSetBits did not find the run Windows finds");
        }
        if RtlFindFirstRunClear(map, &raw mut start) != 30 || start != 0 {
            return Err("RtlFindFirstRunClear missed the first run");
        }
        if RtlFindNextForwardRunClear(map, 30, &raw mut start) != 1 || start != 35 {
            return Err("RtlFindNextForwardRunClear missed the run after the index");
        }
        if RtlFindLastBackwardRunClear(map, 64, &raw mut start) != 24 || start != 40 {
            return Err("RtlFindLastBackwardRunClear missed the run before the index");
        }
        if RtlFindLongestRunClear(map, &raw mut start) != 35 || start != 65 {
            return Err("RtlFindLongestRunClear missed the longest run");
        }
        RtlClearBits(map, 30, 10);
        RtlSetAllBits(map);
        if buffer != [u32::MAX; 4] || RtlNumberOfClearBits(map) != 0 {
            return Err("RtlSetAllBits left a bit clear");
        }

        // A second bitmap over the same buffer's last `ULONG`.
        let mut small = RTL_BITMAP {
            SizeOfBitMap: 0,
            Buffer: core::ptr::null_mut(),
        };
        RtlInitializeBitMap(&raw mut small, (&raw mut buffer[3]).cast(), 12);
        RtlClearAllBits(&raw mut small);
        RtlSetBits(&raw mut small, 1, 3);
        RtlClearAllBits(map);
        buffer[3] = 0xE;
        RtlCopyBitMap(&raw const small, map, 60);
        if buffer != [0, 0xE000_0000, 0, 0xE] {
            return Err("RtlCopyBitMap did not copy the source's bits to the target bit");
        }

        RtlClearAllBits(map);
        RtlInterlockedSetBitRun(map, 28, 40);
        if buffer != [0xF000_0000, u32::MAX, 0xF, 0] {
            return Err("RtlInterlockedSetBitRun set other bits than asked");
        }
        RtlInterlockedClearBitRun(map, 30, 4);
        if buffer != [0x3000_0000, 0xFFFF_FFFC, 0xF, 0] {
            return Err("RtlInterlockedClearBitRun cleared other bits than asked");
        }
        // 30..34 is clear and 34 is set: the bits taken in the first
        // `ULONG` are given back.
        if RtlInterlockedSetClearRun(map, 30, 5) != 0
            || buffer != [0x3000_0000, 0xFFFF_FFFC, 0xF, 0]
        {
            return Err("RtlInterlockedSetClearRun took a run with a set bit in it");
        }
        if RtlInterlockedSetClearRun(map, 30, 4) != 1 || buffer != [0xF000_0000, u32::MAX, 0xF, 0] {
            return Err("RtlInterlockedSetClearRun did not take a clear run");
        }
    }
    if RtlNumberOfSetBitsUlongPtr(0xF0F0_0000_0000_0001) != 9 {
        return Err("RtlNumberOfSetBitsUlongPtr miscounted");
    }
    let ends = [
        RtlFindLeastSignificantBit(0),
        RtlFindMostSignificantBit(0),
        RtlFindLeastSignificantBit(0x0100_0000_0001_0000),
        RtlFindMostSignificantBit(0x0100_0000_0001_0000),
    ];
    if ends != [-1, -1, 16, 56] {
        return Err("the least or most significant bit is not where the routine says");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("rtl.bitmap", bitmap);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
