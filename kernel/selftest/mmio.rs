//! Tests of device memory, contiguous memory and the MDL routines over
//! system memory, made as a driver makes them: through the exports.

use crate::hal::pci::{HalGetBusDataByOffset, HalSetBusDataByOffset};
use crate::hal::platform;
use crate::io::mdl::{
    IoAllocateMdl, IoFreeMdl, MmAllocatePagesForMdlEx, MmBuildMdlForNonPagedPool,
    MmFreePagesFromMdl, MmMapLockedPagesSpecifyCache, MmProtectMdlSystemAddress,
    MmUnmapLockedPages,
};
use crate::mm::contig::{
    MmAllocateContiguousMemorySpecifyCache, MmAllocateContiguousNodeMemory, MmFreeContiguousMemory,
    MmFreeContiguousMemorySpecifyCache,
};
use crate::mm::io::{
    MmGetPhysicalAddress, MmGetVirtualForPhysical, MmMapIoSpaceEx, MmUnmapIoSpace,
};
use crate::mm::pool::{ExAllocatePoolWithTag, ExFreePool};
use crate::mm::{PAGE_SIZE, map};
use crate::test::{Group, Report};
use core::ffi::c_void;
use nk_bootinfo::BootInfo;
use nk_hal::pci::{PCI_CONFIGURATION, slot_number};
use nk_mm::protect::{
    MM_CACHED, MM_NON_CACHED, PAGE_EXECUTE_READWRITE, PAGE_NOACCESS, PAGE_NOCACHE, PAGE_READONLY,
    PAGE_READWRITE, PAGE_WRITECOMBINE,
};
use nk_ntabi::io::{KERNEL_MODE, MDL, MDL_MAPPED_TO_SYSTEM_VA, MDL_SOURCE_IS_NONPAGED_POOL};
use nk_ntabi::status::{STATUS_INVALID_PAGE_PROTECTION, STATUS_NOT_MAPPED_VIEW, STATUS_SUCCESS};

pub static GROUP: Group = Group {
    names: &[
        "mm.io.map",
        "mm.io.refused",
        "mm.io.ahci",
        "mm.contiguous",
        "mm.contiguous.refused",
        "mm.mdl.nonpaged",
        "mm.mdl.pages",
    ],
    run,
    manual: false,
};

const PAGE: usize = PAGE_SIZE;
const TAG: u32 = u32::from_le_bytes(*b"NkMi");
const BELOW_4G: i64 = 0xFFFF_FFFF;
/// `MM_ANY_NODE_OK`.
const ANY_NODE: u32 = 0x8000_0000;
/// `NormalPagePriority`.
const NORMAL_PRIORITY: u32 = 16;

/// Bytes of a function of bus 0, by `HalGetBusDataByOffset`.
fn config(device: u8, function: u8, offset: u32, buffer: &mut [u8]) -> u32 {
    // SAFETY: the buffer is valid for its length.
    unsafe {
        HalGetBusDataByOffset(
            PCI_CONFIGURATION,
            0,
            slot_number(device, function),
            buffer.as_mut_ptr().cast(),
            offset,
            buffer.len() as u32,
        )
    }
}

/// The host bridge's configuration space, mapped as a driver maps
/// device memory, reads as the bus-data routine reads it; the mapping's
/// physical address is the one mapped; unmapped, it is gone.
fn map_device() -> Result<u64, &'static str> {
    let (_, ecam) = platform::get()
        .ecam()
        .find(|(_, e)| e.covers(0, 0))
        .ok_or("no memory-mapped configuration space for bus 0")?;
    // Sixteen bytes that start eight bytes into the function's page.
    let pa = ecam.span().0 + 8;
    let va = MmMapIoSpaceEx(pa as i64, 16, PAGE_READWRITE | PAGE_NOCACHE);
    if va.is_null() {
        return Err("MmMapIoSpaceEx returned null");
    }
    if va as usize % PAGE != 8 {
        return Err("the mapping does not keep the offset in the page");
    }
    let mut expected = [0u8; 4];
    config(0, 0, 8, &mut expected);
    // SAFETY: the register is mapped, and aligned to its width.
    let seen = unsafe { va.cast::<u32>().read_volatile() };
    let physical = MmGetPhysicalAddress(va);
    MmUnmapIoSpace(va, 16);
    if seen != u32::from_le_bytes(expected) {
        return Err("the mapped registers do not read as configuration space does");
    }
    if physical != pa as i64 {
        return Err("MmGetPhysicalAddress of the mapping is not the address mapped");
    }
    if MmGetPhysicalAddress(va) != 0 || map::translate(va as u64).is_some() {
        return Err("the mapping survived MmUnmapIoSpace");
    }
    Ok(pa)
}

/// A protection that is not one, no access, and no bytes are refused.
fn map_refused() -> Result<(), &'static str> {
    let (_, ecam) = platform::get()
        .ecam()
        .find(|(_, e)| e.covers(0, 0))
        .ok_or("no memory-mapped configuration space for bus 0")?;
    let pa = ecam.span().0 as i64;
    for protect in [
        0,
        PAGE_NOACCESS,
        PAGE_READWRITE | PAGE_NOCACHE | PAGE_WRITECOMBINE,
        PAGE_READWRITE | 0x100,
    ] {
        if !MmMapIoSpaceEx(pa, PAGE, protect).is_null() {
            return Err("a protection no system mapping can have was mapped");
        }
    }
    if !MmMapIoSpaceEx(pa, 0, PAGE_READWRITE).is_null() {
        return Err("no bytes were mapped");
    }
    // Read-only and write-combined mappings are mappings.
    for protect in [PAGE_READONLY, PAGE_READWRITE | PAGE_WRITECOMBINE] {
        let va = MmMapIoSpaceEx(pa, PAGE, protect);
        if va.is_null() {
            return Err("a valid protection was refused");
        }
        let writable = map::lookup(va as u64).map(|(_, writable)| writable);
        MmUnmapIoSpace(va, PAGE);
        if writable != Some(protect != PAGE_READONLY) {
            return Err("the mapping does not have the protection asked for");
        }
    }
    Ok(())
}

/// Find an AHCI controller on bus 0: device, function.
fn ahci() -> Option<(u8, u8)> {
    (0..32u8)
        .flat_map(|device| (0..8u8).map(move |function| (device, function)))
        .find(|&(device, function)| {
            let mut class = [0u8; 4];
            // Revision, interface, sub-class, base class.
            config(device, function, 8, &mut class) == 4 && class[1..] == [0x01, 0x06, 0x01]
        })
}

/// The AHCI controller's registers (BAR 5), mapped, read as an AHCI
/// controller's: version 1.x, ports implemented. Returns the version.
fn ahci_registers(device: u8, function: u8) -> Result<u32, &'static str> {
    const COMMAND: u32 = 4;
    const MEMORY_SPACE: u8 = 2;
    const BAR5: u32 = 0x24;
    let mut bar = [0u8; 4];
    config(device, function, BAR5, &mut bar);
    let bar = u32::from_le_bytes(bar);
    if bar & 1 != 0 || bar & !0xF == 0 {
        return Err("BAR 5 is not an assigned memory range");
    }
    // The registers answer only while memory decoding is on.
    let mut command = [0u8; 1];
    config(device, function, COMMAND, &mut command);
    let set = |value: u8| {
        // SAFETY: one byte, valid for the call.
        unsafe {
            HalSetBusDataByOffset(
                PCI_CONFIGURATION,
                0,
                slot_number(device, function),
                (&raw const value).cast_mut().cast(),
                COMMAND,
                1,
            )
        }
    };
    set(command[0] | MEMORY_SPACE);
    let va = MmMapIoSpaceEx(i64::from(bar & !0xF), 0x100, PAGE_READWRITE | PAGE_NOCACHE);
    if va.is_null() {
        set(command[0]);
        return Err("MmMapIoSpaceEx returned null");
    }
    // SAFETY: the generic host control registers: CAP at 0, PI at 0xC,
    // VS at 0x10, all in the mapping.
    let (capabilities, ports, version) = unsafe {
        let register = |offset: usize| va.cast::<u32>().byte_add(offset).read_volatile();
        (register(0), register(0xC), register(0x10))
    };
    MmUnmapIoSpace(va, 0x100);
    set(command[0]);
    if version >> 16 != 1 {
        return Err("the version register does not say AHCI 1.x");
    }
    // CAP.NP is the number of ports less one; each has a bit in PI.
    let count = (capabilities & 0x1F) + 1;
    if ports == 0 || ports.count_ones() > count {
        return Err("the ports-implemented register disagrees with the capabilities");
    }
    Ok(version)
}

/// Whether the `bytes` bytes at `va` are one physical run, and where it
/// starts.
fn run_of(va: *mut c_void, bytes: usize) -> Option<i64> {
    let start = MmGetPhysicalAddress(va);
    let contiguous = (0..bytes)
        .step_by(PAGE)
        .all(|off| MmGetPhysicalAddress(va.wrapping_byte_add(off)) == start + off as i64);
    (start != 0 && contiguous).then_some(start)
}

/// Contiguous memory lies where it was asked to, in one run, zeroed and
/// writable; its physical address leads back to it; a boundary is not
/// crossed. Returns the physical address of the first block.
fn contiguous() -> Result<i64, &'static str> {
    let bytes = 3 * PAGE + 100;
    let a = MmAllocateContiguousNodeMemory(bytes, 0, BELOW_4G, 0, PAGE_READWRITE, ANY_NODE);
    if a.is_null() {
        return Err("no contiguous memory below 4 GiB");
    }
    let check = || {
        if a as usize % PAGE != 0 {
            return Err("contiguous memory is not page aligned");
        }
        let pa = run_of(a, bytes).ok_or("the memory is not one physical run")?;
        if pa + bytes as i64 - 1 > BELOW_4G {
            return Err("the memory is not below 4 GiB");
        }
        // SAFETY: `bytes` bytes just allocated.
        unsafe {
            let p = a.cast::<u8>();
            if (0..bytes).any(|i| p.add(i).read() != 0) {
                return Err("contiguous memory is not zeroed");
            }
            p.write_bytes(0xC3, bytes);
        }
        if MmGetVirtualForPhysical(pa + PAGE as i64 + 5) != a.wrapping_byte_add(PAGE + 5) {
            return Err("MmGetVirtualForPhysical does not lead back to the memory");
        }
        // Two pages that may not cross a multiple of two pages, from
        // just above the first block: they begin at such a multiple.
        let boundary = 2 * PAGE as i64;
        let b = MmAllocateContiguousMemorySpecifyCache(
            2 * PAGE,
            pa + PAGE as i64,
            BELOW_4G,
            boundary,
            MM_NON_CACHED,
        );
        if b.is_null() {
            return Err("no contiguous memory within a boundary");
        }
        let run = run_of(b, 2 * PAGE);
        MmFreeContiguousMemorySpecifyCache(b, 2 * PAGE, MM_NON_CACHED);
        match run {
            Some(start) if start % boundary == 0 && start > pa => Ok(pa),
            Some(_) => Err("the memory crosses its boundary or lies below its range"),
            None => Err("the bounded memory is not one physical run"),
        }
    };
    let verdict = check();
    MmFreeContiguousMemory(a);
    verdict
}

/// Requests that cannot be met get null: a range with no memory in it,
/// a run longer than its boundary, executable memory, no bytes, a
/// caching type that is not one.
fn contiguous_refused() -> Result<(), &'static str> {
    let node = |bytes, lowest, highest, boundary, protect| {
        MmAllocateContiguousNodeMemory(bytes, lowest, highest, boundary, protect, ANY_NODE)
    };
    let refused = [
        // Below 1 MiB nothing is ever allocated.
        node(PAGE, 0, 0xF_FFFF, 0, PAGE_READWRITE),
        // The highest address is below the lowest.
        node(PAGE, 0x1000_0000, 0x0FFF_FFFF, 0, PAGE_READWRITE),
        node(3 * PAGE, 0, BELOW_4G, 2 * PAGE as i64, PAGE_READWRITE),
        node(PAGE, 0, BELOW_4G, 0, PAGE_EXECUTE_READWRITE),
        node(PAGE, 0, BELOW_4G, 0, 0),
        node(0, 0, BELOW_4G, 0, PAGE_READWRITE),
        MmAllocateContiguousMemorySpecifyCache(PAGE, 0, BELOW_4G, 0, 77),
    ];
    for block in refused {
        if !block.is_null() {
            MmFreeContiguousMemory(block);
            return Err("a request that cannot be met was given memory");
        }
    }
    Ok(())
}

/// The frame numbers after an MDL's header.
///
/// # Safety
/// `mdl` is a live MDL with at least `count` pages.
unsafe fn frames(mdl: *mut MDL, count: usize) -> alloc::vec::Vec<u64> {
    // SAFETY: per the contract.
    (0..count)
        .map(|i| unsafe { mdl.add(1).cast::<u64>().add(i).read() })
        .collect()
}

/// An MDL built over pool memory names the memory's own pages and its
/// own address.
fn mdl_nonpaged() -> Result<(), &'static str> {
    let block = ExAllocatePoolWithTag(0, 4 * PAGE, TAG);
    if block.is_null() {
        return Err("no pool");
    }
    let buffer = block.wrapping_byte_add(0x10);
    // SAFETY: a buffer inside the block; the MDL is freed below.
    let verdict = unsafe {
        let mdl = IoAllocateMdl(buffer, (2 * PAGE) as u32, 0, 0, core::ptr::null_mut());
        if mdl.is_null() {
            ExFreePool(block);
            return Err("no MDL");
        }
        MmBuildMdlForNonPagedPool(mdl);
        let expected: alloc::vec::Vec<u64> = (0..3)
            .map(|i| MmGetPhysicalAddress(block.wrapping_byte_add(i * PAGE)) as u64 / PAGE as u64)
            .collect();
        let mapped =
            MmMapLockedPagesSpecifyCache(mdl, KERNEL_MODE, MM_CACHED, core::ptr::null_mut(), 0, 16);
        // Nothing to unmap, and nothing is.
        MmUnmapLockedPages(mapped, mdl);
        let verdict = if frames(mdl, 3) != expected {
            Err("the MDL's pages are not the buffer's")
        } else if (*mdl).MdlFlags & MDL_SOURCE_IS_NONPAGED_POOL == 0
            || (*mdl).MdlFlags & MDL_MAPPED_TO_SYSTEM_VA != 0
        {
            Err("the MDL is not marked as built over non-paged memory")
        } else if (*mdl).MappedSystemVa != buffer || mapped != buffer {
            Err("the MDL's system address is not the buffer's own")
        } else if MmProtectMdlSystemAddress(mdl, PAGE_READONLY) != STATUS_NOT_MAPPED_VIEW {
            Err("an MDL with no mapping of its own had its protection changed")
        } else {
            Ok(())
        };
        IoFreeMdl(mdl);
        verdict
    };
    // SAFETY: the block allocated above.
    unsafe { ExFreePool(block) };
    verdict
}

/// Pages allocated for an MDL lie in the range asked for, map, hold
/// what is written, change protection, and are given back.
fn mdl_pages() -> Result<usize, &'static str> {
    const PAGES: usize = 5;
    // SAFETY: the MDL and its pages are freed below.
    unsafe {
        if !MmAllocatePagesForMdlEx(0, 0xF_FFFF, 0, PAGE, MM_CACHED, 0).is_null() {
            return Err("pages were allocated where there is no memory");
        }
        let mdl = MmAllocatePagesForMdlEx(0, BELOW_4G, 0, PAGES * PAGE - 7, MM_CACHED, 0);
        if mdl.is_null() {
            return Err("MmAllocatePagesForMdlEx returned null");
        }
        let check = || {
            if (*mdl).ByteCount as usize != PAGES * PAGE || (*mdl).ByteOffset != 0 {
                return Err("the MDL does not describe whole pages");
            }
            let pfns = frames(mdl, PAGES);
            if pfns
                .iter()
                .any(|&pfn| pfn == 0 || pfn > BELOW_4G as u64 / PAGE as u64)
            {
                return Err("a page lies outside the range asked for");
            }
            let va = MmMapLockedPagesSpecifyCache(
                mdl,
                KERNEL_MODE,
                MM_CACHED,
                core::ptr::null_mut(),
                0,
                NORMAL_PRIORITY,
            );
            if va.is_null() {
                return Err("the pages could not be mapped");
            }
            let inner = || {
                let bytes = va.cast::<u8>();
                if (0..PAGES * PAGE).any(|i| bytes.add(i).read() != 0) {
                    return Err("the pages are not zeroed");
                }
                bytes.write_bytes(0x7E, PAGES * PAGE);
                // The last page, seen through the map of all memory.
                let direct = MmGetVirtualForPhysical((pfns[PAGES - 1] * PAGE as u64) as i64);
                if direct.cast::<u8>().add(PAGE - 1).read() != 0x7E {
                    return Err("the mapping is not of the MDL's pages");
                }
                if MmProtectMdlSystemAddress(mdl, 0x8) != STATUS_INVALID_PAGE_PROTECTION {
                    return Err("a protection that is not one was accepted");
                }
                let writable = || map::lookup(va as u64 + PAGE as u64).map(|(_, w)| w);
                if MmProtectMdlSystemAddress(mdl, PAGE_READONLY) != STATUS_SUCCESS
                    || writable() != Some(false)
                {
                    return Err("the mapping did not become read-only");
                }
                if bytes.add(PAGE).read() != 0x7E {
                    return Err("a read-only mapping does not read");
                }
                if MmProtectMdlSystemAddress(mdl, PAGE_NOACCESS) != STATUS_SUCCESS
                    || writable().is_some()
                {
                    return Err("the mapping did not become inaccessible");
                }
                if MmProtectMdlSystemAddress(mdl, PAGE_READWRITE) != STATUS_SUCCESS
                    || writable() != Some(true)
                {
                    return Err("the mapping did not become writable again");
                }
                bytes.add(PAGE).write(0x11);
                Ok(())
            };
            let verdict = inner();
            MmUnmapLockedPages(va, mdl);
            if verdict.is_ok() && map::translate(va as u64).is_some() {
                return Err("the mapping survived MmUnmapLockedPages");
            }
            verdict
        };
        let verdict = check();
        MmFreePagesFromMdl(mdl);
        ExFreePool(mdl.cast());
        verdict?;
        // Runs of two pages, each at a multiple of two pages.
        let chunked =
            MmAllocatePagesForMdlEx(0, BELOW_4G, 2 * PAGE as i64, 4 * PAGE, MM_CACHED, 0x20);
        if chunked.is_null() {
            return Err("no pages in contiguous chunks");
        }
        let pfns = frames(chunked, 4);
        MmFreePagesFromMdl(chunked);
        ExFreePool(chunked.cast());
        if pfns[0] % 2 != 0 || pfns[1] != pfns[0] + 1 || pfns[2] % 2 != 0 || pfns[3] != pfns[2] + 1
        {
            return Err("the chunks are not aligned runs");
        }
        Ok(PAGES + 4)
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    match map_device() {
        Ok(pa) => r.ok_with("mm.io.map", format_args!("device memory at {pa:#x}")),
        Err(why) => r.fail("mm.io.map", format_args!("{why}")),
    }
    r.check("mm.io.refused", map_refused);
    match ahci() {
        Some((device, function)) => match ahci_registers(device, function) {
            Ok(version) => r.ok_with(
                "mm.io.ahci",
                format_args!("AHCI version {}.{:x}", version >> 16, version & 0xFFFF),
            ),
            Err(why) => r.fail("mm.io.ahci", format_args!("{why}")),
        },
        None => r.skip(
            "mm.io.ahci",
            format_args!("no AHCI controller on bus 0 of this machine"),
        ),
    }
    match contiguous() {
        Ok(pa) => r.ok_with("mm.contiguous", format_args!("at {pa:#x}")),
        Err(why) => r.fail("mm.contiguous", format_args!("{why}")),
    }
    r.check("mm.contiguous.refused", contiguous_refused);
    r.check("mm.mdl.nonpaged", mdl_nonpaged);
    match mdl_pages() {
        Ok(n) => r.ok_with("mm.mdl.pages", format_args!("pages: {n}")),
        Err(why) => r.fail("mm.mdl.pages", format_args!("{why}")),
    }
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
