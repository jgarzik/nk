//! DMA: the adapter a bus-master device's driver gets from
//! [`IoGetDmaAdapter`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetdmaadapter)
//! and the operations it calls through it.
//!
//! The machines NK runs on have no I/O memory management unit, so a bus
//! address is a physical address, and devices see memory as the
//! processor wrote it. What an adapter is for is the device that cannot
//! drive every address bit:
//!
//! - **common buffers** are contiguous memory at addresses the device
//!   reaches (`mm::contig`);
//! - **a transfer** of memory the device cannot reach goes through a
//!   bounce page it can: the data is copied to the page before the
//!   device reads it, and from the page after the device wrote it. A
//!   scatter/gather list names the bounce page in place of the memory;
//!   `MapTransfer` returns its address. Windows counts such pages as map
//!   registers.
//!
//! A driver calls the operations through the table in its adapter. The
//! table is the pinned build's, every slot filled: with the routine, or
//! with a trap that stops the system naming the slot. Trapped are the
//! operations of a device that is not a bus master (a system DMA
//! controller's), the version 3 forms that take a transfer context,
//! DMA domains (an IOMMU's) and common-buffer vectors.
//!
//! Execution routines are called before the routine that was asked
//! returns: nothing here ever has to wait for map registers.
//!
//! The adapter block is NK's state followed by the `DMA_ADAPTER` the
//! driver is handed: the driver's pointer names exactly a `DMA_ADAPTER`.

#![allow(non_snake_case)]

use crate::ke::{irql, seh};
use crate::mm::{self, PAGE_SIZE, contig, pool};
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, Ordering};
use nk_hal::dma::{self, Description, Limits, Runs};
use nk_mm::frames::Within;
use nk_ntabi::dma::*;
use nk_ntabi::io::{DEVICE_OBJECT, MDL};
use nk_ntabi::status::{
    NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER,
    STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
};

const TAG_ADAPTER: u32 = u32::from_le_bytes(*b"Dma ");
const TAG_LIST: u32 = u32::from_le_bytes(*b"DmaS");
const TAG_REGISTERS: u32 = u32::from_le_bytes(*b"DmaR");
const ADAPTER_MAGIC: u32 = u32::from_le_bytes(*b"NKDA");
const RECORD_MAGIC: u32 = u32::from_le_bytes(*b"NKDT");
const REGISTERS_MAGIC: u32 = u32::from_le_bytes(*b"NKDR");
const PAGE: u64 = PAGE_SIZE as u64;

/// NK's state of an adapter.
struct Own {
    magic: u32,
    limits: Limits,
    /// The map registers of an adapter channel whose execution routine
    /// said to keep it, until `FreeAdapterChannel`.
    channel: AtomicPtr<Registers>,
}

/// An adapter: NK's state, then what the driver sees.
#[repr(C)]
struct Block {
    own: Own,
    adapter: DMA_ADAPTER,
}

/// NK's state of the adapter a driver passed.
///
/// # Safety
/// `adapter` came from [`get_adapter`] and has not been put back.
unsafe fn own<'a>(adapter: *mut DMA_ADAPTER) -> &'a Own {
    // SAFETY: per the contract the adapter lies in a `Block`, whose
    // `own` is NK's alone.
    let own = unsafe {
        &*adapter
            .byte_sub(core::mem::offset_of!(Block, adapter))
            .cast::<Own>()
    };
    if own.magic != ADAPTER_MAGIC {
        crate::kd::bugcheck(format_args!("{adapter:p} is not a DMA adapter"));
    }
    own
}

/// The frames a device of these limits can reach.
fn reach(limits: &Limits) -> Within {
    Within {
        lowest: 0,
        // The last frame that lies wholly at or below the highest
        // address.
        highest: (limits.highest() - (PAGE - 1)) / PAGE,
        align: 1,
        boundary: 0,
    }
}

/// Whether some memory is beyond a device of these limits, so that its
/// transfers may need bounce pages.
fn may_bounce(limits: &Limits) -> bool {
    mm::direct_map_bytes() - 1 > limits.highest()
}

/// Make an adapter for the device a description describes, and say how
/// many map registers it has: the pages a transfer may span, plus one.
/// `None` for a description NK makes no adapter for (`nk_hal::dma`) or
/// when there is no memory.
pub fn get_adapter(description: &Description) -> Option<(*mut DMA_ADAPTER, u32)> {
    let limits = dma::limits(description)?;
    let block = pool::alloc(size_of::<Block>(), TAG_ADAPTER).cast::<Block>();
    if block.is_null() {
        return None;
    }
    // SAFETY: a fresh block of the right size.
    unsafe {
        block.write(Block {
            own: Own {
                magic: ADAPTER_MAGIC,
                limits,
                channel: AtomicPtr::new(core::ptr::null_mut()),
            },
            adapter: DMA_ADAPTER {
                Version: description.version as u16,
                Size: size_of::<DMA_ADAPTER>() as u16,
                DmaOperations: &raw const OPERATIONS.0,
            },
        });
        Some((&raw mut (*block).adapter, limits.map_registers))
    }
}

/// `IoGetDmaAdapter`: an adapter for a device. NK asks no bus driver:
/// on these machines every bus's addresses are physical addresses, so
/// the physical device object is not looked at. Null for a device that
/// is not a bus master, a description version above 3, or no memory.
///
/// # Safety
/// `description` points to a `DEVICE_DESCRIPTION` of the version it
/// states; `number_of_map_registers` is valid for a write.
pub unsafe extern "C" fn IoGetDmaAdapter(
    _physical_device_object: *mut DEVICE_OBJECT,
    description: *const DEVICE_DESCRIPTION,
    number_of_map_registers: *mut u32,
) -> *mut DMA_ADAPTER {
    // SAFETY: per the contract; the width is a field of version 3 only.
    let described = unsafe {
        let version = (&raw const (*description).Version).read();
        Description {
            version,
            master: (&raw const (*description).Master).read() != 0,
            scatter_gather: (&raw const (*description).ScatterGather).read() != 0,
            dma32: (&raw const (*description).Dma32BitAddresses).read() != 0,
            dma64: (&raw const (*description).Dma64BitAddresses).read() != 0,
            maximum_length: (&raw const (*description).MaximumLength).read(),
            address_width: if version == DEVICE_DESCRIPTION_VERSION3 {
                (&raw const (*description).DmaAddressWidth).read()
            } else {
                0
            },
        }
    };
    match get_adapter(&described) {
        Some((adapter, registers)) => {
            // SAFETY: per the contract.
            unsafe { number_of_map_registers.write(registers) };
            adapter
        }
        None => core::ptr::null_mut(),
    }
}

// ---- the operations ------------------------------------------------------

/// `PutDmaAdapter`: free the adapter.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn PutDmaAdapter(adapter: *mut DMA_ADAPTER) {
    // SAFETY: the adapter is the driver's to give back.
    unsafe {
        FreeAdapterChannel(adapter);
        let block = adapter.byte_sub(core::mem::offset_of!(Block, adapter));
        (*block.cast::<Own>()).magic = 0;
        if pool::free(block.cast()).is_err() {
            crate::kd::bugcheck(format_args!(
                "PutDmaAdapter: {adapter:p} is not a DMA adapter"
            ));
        }
    }
}

/// Contiguous memory the adapter's device reaches, between `lowest` and
/// `highest` besides; its bus address goes to `logical_address`.
///
/// # Safety
/// As [`own`]; `logical_address` is valid for a write.
unsafe fn common_buffer(
    adapter: *mut DMA_ADAPTER,
    lowest: u64,
    highest: u64,
    length: u32,
    logical_address: *mut i64,
) -> *mut c_void {
    // SAFETY: per the contract.
    let limits = unsafe { own(adapter) }.limits;
    let buffer = contig::alloc(length as usize, lowest, highest.min(limits.highest()), 0);
    if !buffer.is_null() {
        // SAFETY: per the contract.
        unsafe { logical_address.write(mm::direct_to_phys(buffer) as i64) };
    }
    buffer.cast()
}

/// `AllocateCommonBuffer`: memory both the driver and the device use.
/// Always cached, as all of NK's memory is.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn AllocateCommonBuffer(
    adapter: *mut DMA_ADAPTER,
    length: u32,
    logical_address: *mut i64,
    _cache_enabled: u8,
) -> *mut c_void {
    // SAFETY: as the driver's call.
    unsafe { common_buffer(adapter, 0, u64::MAX, length, logical_address) }
}

/// `AllocateCommonBufferEx`: the same, below `maximum_address` too.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn AllocateCommonBufferEx(
    adapter: *mut DMA_ADAPTER,
    maximum_address: *const i64,
    length: u32,
    logical_address: *mut i64,
    _cache_enabled: u8,
    _preferred_node: u32,
) -> *mut c_void {
    // SAFETY: as the driver's call; the bound is optional.
    unsafe {
        let highest = maximum_address.as_ref().map_or(u64::MAX, |m| *m as u64);
        common_buffer(adapter, 0, highest, length, logical_address)
    }
}

/// `AllocateCommonBufferWithBounds`: the same, between two addresses.
/// No flag changes what NK does: memory is zeroed, and nothing waits.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
#[allow(clippy::too_many_arguments, reason = "the operation's signature")]
unsafe extern "C" fn AllocateCommonBufferWithBounds(
    adapter: *mut DMA_ADAPTER,
    minimum_address: *const i64,
    maximum_address: *const i64,
    length: u32,
    _flags: u32,
    _cache_type: *const u32,
    _preferred_node: u32,
    logical_address: *mut i64,
) -> *mut c_void {
    // SAFETY: as the driver's call; the bounds are optional.
    unsafe {
        let lowest = minimum_address.as_ref().map_or(0, |m| *m as u64);
        let highest = maximum_address.as_ref().map_or(u64::MAX, |m| *m as u64);
        common_buffer(adapter, lowest, highest, length, logical_address)
    }
}

/// `FreeCommonBuffer`.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn FreeCommonBuffer(
    _adapter: *mut DMA_ADAPTER,
    _length: u32,
    _logical_address: i64,
    virtual_address: *mut c_void,
    _cache_enabled: u8,
) {
    contig::free(virtual_address.cast());
}

/// `GetDmaAlignment`: a bus master's buffers need none.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn GetDmaAlignment(_adapter: *mut DMA_ADAPTER) -> u32 {
    1
}

/// `FlushDmaBuffer`: make memory and what the device sees of it agree.
/// They always do here: no IOMMU, and devices that see the processor's
/// writes.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn FlushDmaBuffer(
    _adapter: *mut DMA_ADAPTER,
    _mdl: *mut MDL,
    _read_operation: u8,
) -> NTSTATUS {
    STATUS_SUCCESS
}

/// `GetDmaAdapterInfo`, version 1.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn GetDmaAdapterInfo(
    adapter: *mut DMA_ADAPTER,
    info: *mut DMA_ADAPTER_INFO,
) -> NTSTATUS {
    // SAFETY: as the driver's call.
    unsafe {
        if (&raw const (*info).Version).read() != DMA_ADAPTER_INFO_VERSION1 {
            return STATUS_NOT_SUPPORTED;
        }
        let limits = own(adapter).limits;
        let bypass = if may_bounce(&limits) {
            0
        } else {
            ADAPTER_INFO_API_BYPASS
        };
        info.write(DMA_ADAPTER_INFO {
            Version: DMA_ADAPTER_INFO_VERSION1,
            ReadDmaCounterAvailable: 0,
            ScatterGatherLimit: limits.map_registers,
            DmaAddressWidth: u32::from(limits.width),
            Flags: ADAPTER_INFO_SYNCHRONOUS_CALLBACK | bypass,
            MinimumTransferUnit: 1,
        });
    }
    STATUS_SUCCESS
}

// ---- walking a buffer ------------------------------------------------------

/// The frame numbers after an MDL's header.
///
/// # Safety
/// `mdl` is a live MDL whose pages are filled in.
unsafe fn frame(mdl: *mut MDL, page: usize) -> u64 {
    // SAFETY: per the contract.
    unsafe { mdl.add(1).cast::<u64>().add(page).read() }
}

/// Call `piece(physical address, length)` for each part of the buffer
/// that lies in one page: `length` bytes from `current_va`, which is in
/// the buffer of `mdl`, running on through the MDLs chained to it.
/// `false` if the chain describes less than that.
///
/// # Safety
/// `mdl` is a chain of live MDLs whose pages are filled in.
unsafe fn walk(
    mut mdl: *mut MDL,
    current_va: *mut c_void,
    length: u32,
    mut piece: impl FnMut(u64, u32) -> bool,
) -> bool {
    let mut left = length;
    let mut first = true;
    while left != 0 {
        if mdl.is_null() {
            return false;
        }
        // SAFETY: per the contract.
        let (start, offset, count, next) = unsafe {
            (
                (*mdl).StartVa as usize,
                (*mdl).ByteOffset,
                (*mdl).ByteCount,
                (*mdl).Next,
            )
        };
        // Only the first MDL is entered part of the way in.
        let skip = if first {
            (current_va as usize).wrapping_sub(start + offset as usize)
        } else {
            0
        };
        first = false;
        let Some(here) = u32::try_from(skip).ok().and_then(|s| count.checked_sub(s)) else {
            return false;
        };
        let take = here.min(left);
        for p in dma::pieces(offset + skip as u32, take) {
            // SAFETY: the page is one of the MDL's.
            let pa = unsafe { frame(mdl, p.page) } * PAGE + u64::from(p.offset);
            if !piece(pa, p.length) {
                return false;
            }
        }
        left -= take;
        mdl = next;
    }
    true
}

/// Copy `length` bytes between memory at physical address `pa` and the
/// bounce page at `bounce`: to the bounce page, or back from it.
///
/// # Safety
/// Both are RAM NK may touch: a locked buffer's page, a bounce frame.
unsafe fn copy(pa: u64, bounce: u64, length: u32, to_bounce: bool) {
    let (memory, page) = (mm::phys_to_virt(pa), mm::phys_to_virt(bounce));
    // SAFETY: per the contract; the two never overlap.
    unsafe {
        if to_bounce {
            page.copy_from_nonoverlapping(memory, length as usize);
        } else {
            memory.copy_from_nonoverlapping(page, length as usize);
        }
    }
}

// ---- scatter/gather lists --------------------------------------------------

/// One piece of a transfer that goes through a bounce page.
#[derive(Clone, Copy)]
struct Bounce {
    /// Where the data is, physically.
    memory: u64,
    /// Where the device finds it: in a bounce frame, at the same offset
    /// in its page.
    bounce: u64,
    length: u32,
}

/// NK's part of a scatter/gather buffer, after the list's elements; the
/// list's `Reserved` word holds its address.
#[repr(C)]
struct Record {
    magic: u32,
    bounces: u32,
    /// The buffer's address if NK allocated it, else null.
    allocated: *mut u8,
    // `Bounce` entries follow.
}

/// Bytes of a scatter/gather buffer for a transfer that spans `pages`
/// pages: a list with an element a page, and NK's record with a bounce
/// a page.
const fn list_bytes(pages: u32) -> usize {
    size_of::<SCATTER_GATHER_LIST>()
        + size_of::<Record>()
        + pages as usize * (size_of::<SCATTER_GATHER_ELEMENT>() + size_of::<Bounce>())
}

/// The pages a transfer spans, or `None` if the MDLs describe less.
///
/// # Safety
/// As [`walk`].
unsafe fn pages_of(mdl: *mut MDL, current_va: *mut c_void, length: u32) -> Option<u32> {
    let mut pages = 0;
    // SAFETY: per the contract.
    unsafe { walk(mdl, current_va, length, |_, _| (pages += 1, true).1) }.then_some(pages)
}

/// Give back the bounce frames of a record, copying each back to memory
/// first if the device wrote them.
///
/// # Safety
/// `record` is a live record with `count` bounces filled in.
unsafe fn unbounce(record: *mut Record, count: u32, copy_back: bool) {
    // SAFETY: per the contract.
    unsafe {
        let bounces = record.add(1).cast::<Bounce>();
        for i in 0..count as usize {
            let b = bounces.add(i).read();
            if copy_back {
                copy(b.memory, b.bounce, b.length, false);
            }
            mm::free_frames(b.bounce & !(PAGE - 1), 1);
        }
    }
}

/// Build the scatter/gather list of a transfer in `buffer`, which holds
/// `buffer_bytes` bytes: the runs of bus addresses the device is to use,
/// with a bounce page in place of each piece it cannot reach.
///
/// # Safety
/// As [`own`] and [`walk`]; `buffer` is valid for `buffer_bytes` bytes
/// and aligned for a list.
#[allow(clippy::too_many_arguments, reason = "a transfer is this many facts")]
unsafe fn build(
    adapter: *mut DMA_ADAPTER,
    mdl: *mut MDL,
    current_va: *mut c_void,
    length: u32,
    write_to_device: bool,
    buffer: *mut u8,
    buffer_bytes: usize,
    allocated: bool,
) -> Result<*mut SCATTER_GATHER_LIST, NTSTATUS> {
    // SAFETY: per the contract.
    unsafe {
        let limits = own(adapter).limits;
        let pages = pages_of(mdl, current_va, length).ok_or(STATUS_BUFFER_TOO_SMALL)?;
        if buffer_bytes < list_bytes(pages) {
            return Err(STATUS_BUFFER_TOO_SMALL);
        }
        let list = buffer.cast::<SCATTER_GATHER_LIST>();
        let elements = (&raw mut (*list).Elements).cast::<SCATTER_GATHER_ELEMENT>();
        let record = elements.add(pages as usize).cast::<Record>();
        let bounces = record.add(1).cast::<Bounce>();
        let (mut count, mut bounced) = (0u32, 0u32);
        let mut emit = |run: dma::Run| {
            elements.add(count as usize).write(SCATTER_GATHER_ELEMENT {
                Address: run.address as i64,
                Length: run.length,
                Reserved: 0,
            });
            count += 1;
        };
        let mut runs = Runs::new();
        let within = reach(&limits);
        let whole = walk(mdl, current_va, length, |pa, len| {
            if dma::reachable(pa, len, limits.highest()) {
                runs.add(pa, len, false).map(&mut emit);
                return true;
            }
            let Some(page) = mm::alloc_frames_within(1, &within) else {
                return false;
            };
            let bounce = page + pa % PAGE;
            if write_to_device {
                copy(pa, bounce, len, true);
            }
            bounces.add(bounced as usize).write(Bounce {
                memory: pa,
                bounce,
                length: len,
            });
            bounced += 1;
            runs.add(bounce, len, true).map(&mut emit);
            true
        });
        if !whole {
            // No frame the device reaches is free.
            unbounce(record, bounced, false);
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        runs.finish().map(&mut emit);
        record.write(Record {
            magic: RECORD_MAGIC,
            bounces: bounced,
            allocated: if allocated {
                buffer
            } else {
                core::ptr::null_mut()
            },
        });
        (*list).NumberOfElements = count;
        (*list).Reserved = record as usize;
        Ok(list)
    }
}

/// Give up what raising to `DISPATCH_LEVEL` for an execution routine
/// took, if the routine does not return.
///
/// # Safety
/// `old` is the IRQL to go back to, as a pointer-sized value.
unsafe fn come_down(old: *mut c_void) {
    crate::arch::set_irql(old as usize as u8);
}

/// Call a driver's execution routine at `DISPATCH_LEVEL`, where the
/// operations that take one are documented to be called and to call it.
///
/// # Safety
/// `routine` may be called with these arguments.
unsafe fn execute(routine: usize, arguments: [usize; 4]) -> usize {
    let old = irql::current();
    if old < irql::DISPATCH_LEVEL {
        crate::arch::set_irql(irql::DISPATCH_LEVEL);
    }
    let guard = seh::Guard::Undo {
        undo: come_down,
        context: usize::from(old) as *mut c_void,
    };
    // SAFETY: per the contract.
    let result = unsafe { seh::call(routine, arguments, &guard) };
    crate::arch::set_irql(old);
    result
}

/// The request a device object is working on, which execution routines
/// are passed.
///
/// # Safety
/// `device` is null or a live device object.
unsafe fn current_irp(device: *mut DEVICE_OBJECT) -> usize {
    if device.is_null() {
        0
    } else {
        // SAFETY: per the contract.
        unsafe { (&raw const (*device).CurrentIrp).read() as usize }
    }
}

/// `CalculateScatterGatherList`: the bytes `BuildScatterGatherList`
/// needs for a transfer, and the pages it spans.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn CalculateScatterGatherList(
    _adapter: *mut DMA_ADAPTER,
    mdl: *mut MDL,
    current_va: *mut c_void,
    length: u32,
    list_size: *mut u32,
    map_registers: *mut u32,
) -> NTSTATUS {
    // SAFETY: as the driver's call; without an MDL the buffer is the
    // `length` bytes at `current_va`.
    unsafe {
        let pages = if mdl.is_null() {
            Some(dma::span(current_va as usize as u32 & 0xFFF, length))
        } else {
            pages_of(mdl, current_va, length)
        };
        let Some(pages) = pages else {
            return STATUS_BUFFER_TOO_SMALL;
        };
        let Ok(bytes) = u32::try_from(list_bytes(pages)) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        list_size.write(bytes);
        if !map_registers.is_null() {
            map_registers.write(pages);
        }
    }
    STATUS_SUCCESS
}

/// `BuildScatterGatherList`: build a transfer's list in the driver's
/// buffer and call the execution routine with it.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
#[allow(clippy::too_many_arguments, reason = "the operation's signature")]
unsafe extern "C" fn BuildScatterGatherList(
    adapter: *mut DMA_ADAPTER,
    device: *mut DEVICE_OBJECT,
    mdl: *mut MDL,
    current_va: *mut c_void,
    length: u32,
    routine: Option<DRIVER_LIST_CONTROL>,
    context: *mut c_void,
    write_to_device: u8,
    buffer: *mut c_void,
    buffer_length: u32,
) -> NTSTATUS {
    let Some(routine) = routine else {
        return STATUS_INVALID_PARAMETER;
    };
    // SAFETY: as the driver's call.
    unsafe {
        let built = build(
            adapter,
            mdl,
            current_va,
            length,
            write_to_device != 0,
            buffer.cast(),
            buffer_length as usize,
            false,
        );
        match built {
            Ok(list) => {
                execute(
                    routine as usize,
                    [
                        device as usize,
                        current_irp(device),
                        list as usize,
                        context as usize,
                    ],
                );
                STATUS_SUCCESS
            }
            Err(status) => status,
        }
    }
}

/// `GetScatterGatherList`: the same, in a buffer NK allocates and
/// `PutScatterGatherList` frees.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
#[allow(clippy::too_many_arguments, reason = "the operation's signature")]
unsafe extern "C" fn GetScatterGatherList(
    adapter: *mut DMA_ADAPTER,
    device: *mut DEVICE_OBJECT,
    mdl: *mut MDL,
    current_va: *mut c_void,
    length: u32,
    routine: Option<DRIVER_LIST_CONTROL>,
    context: *mut c_void,
    write_to_device: u8,
) -> NTSTATUS {
    let Some(routine) = routine else {
        return STATUS_INVALID_PARAMETER;
    };
    // SAFETY: as the driver's call.
    unsafe {
        let Some(pages) = pages_of(mdl, current_va, length) else {
            return STATUS_BUFFER_TOO_SMALL;
        };
        let bytes = list_bytes(pages);
        let buffer = pool::alloc(bytes, TAG_LIST);
        if buffer.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let built = build(
            adapter,
            mdl,
            current_va,
            length,
            write_to_device != 0,
            buffer,
            bytes,
            true,
        );
        match built {
            Ok(list) => {
                execute(
                    routine as usize,
                    [
                        device as usize,
                        current_irp(device),
                        list as usize,
                        context as usize,
                    ],
                );
                STATUS_SUCCESS
            }
            Err(status) => {
                let _ = pool::free(buffer);
                status
            }
        }
    }
}

/// NK's record of a list a driver passed back.
///
/// # Safety
/// `list` came from `build`.
unsafe fn record_of(list: *mut SCATTER_GATHER_LIST) -> *mut Record {
    // SAFETY: per the contract.
    let record = unsafe { (&raw const (*list).Reserved).read() } as *mut Record;
    // SAFETY: a record NK wrote, in NK's or the driver's buffer.
    if record.is_null() || unsafe { (&raw const (*record).magic).read() } != RECORD_MAGIC {
        crate::kd::bugcheck(format_args!(
            "{list:p} is not a scatter/gather list of NK's"
        ));
    }
    record
}

/// `PutScatterGatherList`: the transfer is over. What the device wrote
/// to bounce pages is copied to the memory they stood for, the pages
/// are freed, and a list NK allocated is freed.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn PutScatterGatherList(
    _adapter: *mut DMA_ADAPTER,
    list: *mut SCATTER_GATHER_LIST,
    write_to_device: u8,
) {
    // SAFETY: as the driver's call.
    unsafe {
        let record = record_of(list);
        let (bounces, allocated) = ((*record).bounces, (*record).allocated);
        unbounce(record, bounces, write_to_device == 0);
        (*record).magic = 0;
        if !allocated.is_null() && pool::free(allocated).is_err() {
            crate::kd::bugcheck(format_args!(
                "PutScatterGatherList: {list:p} was freed already"
            ));
        }
    }
}

/// `BuildMdlFromScatterGatherList`: an MDL for the memory the device is
/// really using. With nothing bounced that is the original MDL, which
/// is what the documentation says is returned then. For a bounced
/// transfer NK builds none, and stops rather than hand back an MDL of
/// memory the device does not use.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn BuildMdlFromScatterGatherList(
    _adapter: *mut DMA_ADAPTER,
    list: *mut SCATTER_GATHER_LIST,
    original: *mut MDL,
    target: *mut *mut MDL,
) -> NTSTATUS {
    // SAFETY: as the driver's call.
    unsafe {
        if (*record_of(list)).bounces != 0 {
            crate::kd::bugcheck(format_args!(
                "BuildMdlFromScatterGatherList: NK does not implement this for a bounced transfer"
            ));
        }
        target.write(original);
    }
    STATUS_SUCCESS
}

// ---- map registers ---------------------------------------------------------

/// The map registers of one adapter-channel allocation: a bounce frame
/// for each page of a transfer, where the device cannot reach all of
/// memory, else none. The frames' addresses follow the header.
#[repr(C)]
struct Registers {
    magic: u32,
    count: u32,
    /// Whether the frames were allocated.
    bounce: bool,
}

/// Allocate `count` map registers for an adapter.
///
/// # Safety
/// As [`own`].
unsafe fn registers(adapter: *mut DMA_ADAPTER, count: u32) -> *mut Registers {
    // SAFETY: per the contract.
    let limits = unsafe { own(adapter) }.limits;
    let bounce = may_bounce(&limits);
    let bytes = size_of::<Registers>() + count as usize * size_of::<u64>();
    let block = pool::alloc_zeroed(bytes, TAG_REGISTERS).cast::<Registers>();
    if block.is_null() {
        return block;
    }
    // SAFETY: a fresh block of that size.
    unsafe {
        block.write(Registers {
            magic: REGISTERS_MAGIC,
            count,
            bounce,
        });
        if bounce {
            let frames = block.add(1).cast::<u64>();
            let within = reach(&limits);
            for i in 0..count as usize {
                match mm::alloc_frames_within(1, &within) {
                    Some(frame) => frames.add(i).write(frame),
                    None => {
                        (*block).count = i as u32;
                        free_registers(block);
                        return core::ptr::null_mut();
                    }
                }
            }
        }
    }
    block
}

/// Free map registers and their bounce frames.
///
/// # Safety
/// `block` came from [`registers`].
unsafe fn free_registers(block: *mut Registers) {
    // SAFETY: per the contract.
    unsafe {
        if (*block).magic != REGISTERS_MAGIC {
            crate::kd::bugcheck(format_args!("{block:p} is not a map register base"));
        }
        if (*block).bounce {
            let frames = block.add(1).cast::<u64>();
            for i in 0..(*block).count as usize {
                mm::free_frames(frames.add(i).read(), 1);
            }
        }
        (*block).magic = 0;
        if pool::free(block.cast()).is_err() {
            crate::kd::bugcheck(format_args!("{block:p} is not a map register base"));
        }
    }
}

/// The bounce frame for page `page` of a transfer's MDL.
///
/// # Safety
/// `base` came from [`registers`].
unsafe fn register(base: *mut c_void, page: usize) -> u64 {
    let block = base.cast::<Registers>();
    // SAFETY: per the contract.
    unsafe {
        if (*block).magic != REGISTERS_MAGIC || !(*block).bounce || page >= (*block).count as usize
        {
            crate::kd::bugcheck(format_args!(
                "a transfer needs map register {page}, which {base:p} does not have"
            ));
        }
        block.add(1).cast::<u64>().add(page).read()
    }
}

/// Which page of its MDL an address in the MDL's buffer is in.
///
/// # Safety
/// `mdl` is a live MDL.
unsafe fn page_of(mdl: *mut MDL, va: usize) -> usize {
    // SAFETY: per the contract.
    (va >> 12).wrapping_sub(unsafe { (*mdl).StartVa } as usize >> 12)
}

/// `AllocateAdapterChannel`: allocate map registers and call the
/// execution routine with them, at once: NK never makes a request wait.
/// `STATUS_INSUFFICIENT_RESOURCES` for more registers than the adapter
/// has, while an earlier allocation is still kept, or with no memory.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn AllocateAdapterChannel(
    adapter: *mut DMA_ADAPTER,
    device: *mut DEVICE_OBJECT,
    number_of_map_registers: u32,
    routine: Option<DRIVER_CONTROL>,
    context: *mut c_void,
) -> NTSTATUS {
    let Some(routine) = routine else {
        return STATUS_INVALID_PARAMETER;
    };
    // SAFETY: as the driver's call.
    unsafe {
        let own = own(adapter);
        if number_of_map_registers > own.limits.map_registers
            || !own.channel.load(Ordering::Acquire).is_null()
        {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let base = registers(adapter, number_of_map_registers);
        if base.is_null() {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let action = execute(
            routine as usize,
            [
                device as usize,
                current_irp(device),
                base as usize,
                context as usize,
            ],
        ) as u32;
        match action {
            KEEP_OBJECT => own.channel.store(base, Ordering::Release),
            DEALLOCATE_OBJECT_KEEP_REGISTERS => {}
            _ => free_registers(base),
        }
    }
    STATUS_SUCCESS
}

/// `FreeAdapterChannel`: free the map registers of an allocation whose
/// execution routine kept the adapter.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn FreeAdapterChannel(adapter: *mut DMA_ADAPTER) {
    // SAFETY: as the driver's call.
    unsafe {
        let kept = own(adapter)
            .channel
            .swap(core::ptr::null_mut(), Ordering::AcqRel);
        if !kept.is_null() {
            free_registers(kept);
        }
    }
}

/// `FreeMapRegisters`: free map registers whose execution routine kept
/// them and not the adapter.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn FreeMapRegisters(
    _adapter: *mut DMA_ADAPTER,
    base: *mut c_void,
    _number_of_map_registers: u32,
) {
    // SAFETY: as the driver's call.
    unsafe { free_registers(base.cast()) };
}

/// `MapTransfer`: the bus address for the start of a transfer, and in
/// `length` how much of it lies there in one run. Memory the device
/// reaches is used where it is, as far as it is contiguous; a page it
/// cannot reach is stood in for by that page's map register, to which
/// the data is copied first if the device is to read it.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn MapTransfer(
    adapter: *mut DMA_ADAPTER,
    mdl: *mut MDL,
    base: *mut c_void,
    current_va: *mut c_void,
    length: *mut u32,
    write_to_device: u8,
) -> i64 {
    // SAFETY: as the driver's call.
    unsafe {
        let highest = own(adapter).limits.highest();
        // The first piece, and how far memory the device reaches runs
        // on from it: the walk stops at the first piece that does not
        // continue the run.
        let mut first = None;
        let (mut run, mut next) = (0u32, 0u64);
        walk(mdl, current_va, length.read(), |pa, len| {
            let reachable = dma::reachable(pa, len, highest);
            if first.is_none() {
                first = Some((pa, len, reachable));
            } else if !reachable || pa != next {
                return false;
            }
            (run, next) = (run + len, pa + u64::from(len));
            reachable
        });
        let Some((pa, len, reachable)) = first else {
            return 0;
        };
        if reachable {
            length.write(run);
            return pa as i64;
        }
        let bounce = register(base, page_of(mdl, current_va as usize)) + pa % PAGE;
        if write_to_device != 0 {
            copy(pa, bounce, len, true);
        }
        length.write(len);
        bounce as i64
    }
}

/// `FlushAdapterBuffers`: a transfer, or part of one, is over: what the
/// device wrote to map registers is copied to the memory they stood for.
///
/// # Safety
/// Called by a driver through its adapter's table, with this
/// operation's arguments.
unsafe extern "C" fn FlushAdapterBuffers(
    adapter: *mut DMA_ADAPTER,
    mdl: *mut MDL,
    base: *mut c_void,
    current_va: *mut c_void,
    length: u32,
    write_to_device: u8,
) -> u8 {
    // SAFETY: as the driver's call.
    unsafe {
        let highest = own(adapter).limits.highest();
        if write_to_device == 0 {
            let mut va = current_va as usize;
            walk(mdl, current_va, length, |pa, len| {
                if !dma::reachable(pa, len, highest) {
                    let bounce = register(base, page_of(mdl, va)) + pa % PAGE;
                    copy(pa, bounce, len, false);
                }
                va += len as usize;
                true
            });
        }
    }
    1
}

// ---- the table ---------------------------------------------------------------

/// The operations NK has no routine for: each stops the system, naming
/// itself.
mod absent {
    macro_rules! absent {
        ($($name:ident),* $(,)?) => {
            $(
                pub extern "C" fn $name() -> ! {
                    crate::kd::bugcheck(format_args!(concat!(
                        "DMA_OPERATIONS.",
                        stringify!($name),
                        ": NK does not implement this routine"
                    )))
                }
            )*
        };
    }
    absent!(
        ReadDmaCounter,
        GetDmaTransferInfo,
        InitializeDmaTransferContext,
        AllocateAdapterChannelEx,
        ConfigureAdapterChannel,
        CancelAdapterChannel,
        MapTransferEx,
        GetScatterGatherListEx,
        BuildScatterGatherListEx,
        FlushAdapterBuffersEx,
        FreeAdapterObject,
        CancelMappedTransfer,
        AllocateDomainCommonBuffer,
        JoinDmaDomain,
        LeaveDmaDomain,
        GetDmaDomain,
        AllocateCommonBufferVector,
        GetCommonBufferFromVectorByIndex,
        FreeCommonBufferFromVector,
        FreeCommonBufferVector,
    );
}

/// The table, which is never written.
struct Operations(DMA_OPERATIONS);

// SAFETY: immutable, and its pointers name functions.
unsafe impl Sync for Operations {}

static OPERATIONS: Operations = Operations(DMA_OPERATIONS {
    Size: size_of::<DMA_OPERATIONS>() as u32,
    PutDmaAdapter: PutDmaAdapter as *const (),
    AllocateCommonBuffer: AllocateCommonBuffer as *const (),
    FreeCommonBuffer: FreeCommonBuffer as *const (),
    AllocateAdapterChannel: AllocateAdapterChannel as *const (),
    FlushAdapterBuffers: FlushAdapterBuffers as *const (),
    FreeAdapterChannel: FreeAdapterChannel as *const (),
    FreeMapRegisters: FreeMapRegisters as *const (),
    MapTransfer: MapTransfer as *const (),
    GetDmaAlignment: GetDmaAlignment as *const (),
    ReadDmaCounter: absent::ReadDmaCounter as *const (),
    GetScatterGatherList: GetScatterGatherList as *const (),
    PutScatterGatherList: PutScatterGatherList as *const (),
    CalculateScatterGatherList: CalculateScatterGatherList as *const (),
    BuildScatterGatherList: BuildScatterGatherList as *const (),
    BuildMdlFromScatterGatherList: BuildMdlFromScatterGatherList as *const (),
    GetDmaAdapterInfo: GetDmaAdapterInfo as *const (),
    GetDmaTransferInfo: absent::GetDmaTransferInfo as *const (),
    InitializeDmaTransferContext: absent::InitializeDmaTransferContext as *const (),
    AllocateCommonBufferEx: AllocateCommonBufferEx as *const (),
    AllocateAdapterChannelEx: absent::AllocateAdapterChannelEx as *const (),
    ConfigureAdapterChannel: absent::ConfigureAdapterChannel as *const (),
    CancelAdapterChannel: absent::CancelAdapterChannel as *const (),
    MapTransferEx: absent::MapTransferEx as *const (),
    GetScatterGatherListEx: absent::GetScatterGatherListEx as *const (),
    BuildScatterGatherListEx: absent::BuildScatterGatherListEx as *const (),
    FlushAdapterBuffersEx: absent::FlushAdapterBuffersEx as *const (),
    FreeAdapterObject: absent::FreeAdapterObject as *const (),
    CancelMappedTransfer: absent::CancelMappedTransfer as *const (),
    AllocateDomainCommonBuffer: absent::AllocateDomainCommonBuffer as *const (),
    FlushDmaBuffer: FlushDmaBuffer as *const (),
    JoinDmaDomain: absent::JoinDmaDomain as *const (),
    LeaveDmaDomain: absent::LeaveDmaDomain as *const (),
    GetDmaDomain: absent::GetDmaDomain as *const (),
    AllocateCommonBufferWithBounds: AllocateCommonBufferWithBounds as *const (),
    AllocateCommonBufferVector: absent::AllocateCommonBufferVector as *const (),
    GetCommonBufferFromVectorByIndex: absent::GetCommonBufferFromVectorByIndex as *const (),
    FreeCommonBufferFromVector: absent::FreeCommonBufferFromVector as *const (),
    FreeCommonBufferVector: absent::FreeCommonBufferVector as *const (),
});

/// [`HalTranslateBusAddress`](https://learn.microsoft.com/en-us/previous-versions/windows/hardware/drivers/ff546644(v=vs.85)):
/// the system's address for a bus's. Memory addresses are the same on
/// every bus of these machines. An I/O port address is the same too
/// where the processor has I/O ports; where it has none (arm64) NK has
/// no translation to give, and says so.
///
/// # Safety
/// `address_space` and `translated_address` are valid for reads and
/// writes.
pub unsafe extern "C" fn HalTranslateBusAddress(
    _interface_type: u32,
    _bus_number: u32,
    bus_address: i64,
    address_space: *mut u32,
    translated_address: *mut i64,
) -> u8 {
    // SAFETY: per the contract. Address space 0 is memory, 1 I/O ports.
    unsafe {
        match address_space.read() {
            0 => {}
            1 if crate::arch::PCI_PORTS.is_some() => {}
            _ => return 0,
        }
        translated_address.write(bus_address);
    }
    1
}
