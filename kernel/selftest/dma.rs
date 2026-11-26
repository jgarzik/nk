//! Tests of DMA, made as a driver makes them: an adapter from
//! `IoGetDmaAdapter`, its operations called through its table, the
//! device played by the test reading and writing memory at the bus
//! addresses it is given.

use crate::hal::dma::{HalTranslateBusAddress, IoGetDmaAdapter};
use crate::io::mdl::{
    MmAllocatePagesForMdlEx, MmFreePagesFromMdl, MmMapLockedPagesSpecifyCache, MmUnmapLockedPages,
};
use crate::ke::kspin::{KeGetCurrentIrql, KeLowerIrql, KfRaiseIrql};
use crate::mm::io::{MmGetPhysicalAddress, MmGetVirtualForPhysical};
use crate::mm::pool::{ExAllocatePoolWithTag, ExFreePool};
use crate::mm::{self, PAGE_SIZE};
use crate::test::{Group, Report};
use core::ffi::c_void;
use core::mem::MaybeUninit;
use nk_bootinfo::BootInfo;
use nk_mm::protect::MM_CACHED;
use nk_ntabi::dma::*;
use nk_ntabi::io::{KERNEL_MODE, MDL};
use nk_ntabi::pcr::DISPATCH_LEVEL;
use nk_ntabi::status::{
    NTSTATUS, STATUS_BUFFER_TOO_SMALL, STATUS_INSUFFICIENT_RESOURCES, STATUS_SUCCESS,
};

pub static GROUP: Group = Group {
    names: &[
        "hal.dma.adapter",
        "hal.dma.common-buffer",
        "hal.dma.scatter-gather",
        "hal.dma.bounce",
        "hal.dma.map-registers",
    ],
    run,
    manual: false,
};

const PAGE: usize = PAGE_SIZE;
const TAG: u32 = u32::from_le_bytes(*b"NkDm");

// The operations, as `wdm.h` declares them.
type PutAdapter = unsafe extern "C" fn(*mut DMA_ADAPTER);
type AllocateCommon = unsafe extern "C" fn(*mut DMA_ADAPTER, u32, *mut i64, u8) -> *mut c_void;
type AllocateCommonEx =
    unsafe extern "C" fn(*mut DMA_ADAPTER, *const i64, u32, *mut i64, u8, u32) -> *mut c_void;
type AllocateCommonBounds = unsafe extern "C" fn(
    *mut DMA_ADAPTER,
    *const i64,
    *const i64,
    u32,
    u32,
    *const u32,
    u32,
    *mut i64,
) -> *mut c_void;
type FreeCommon = unsafe extern "C" fn(*mut DMA_ADAPTER, u32, i64, *mut c_void, u8);
type AllocateChannel = unsafe extern "C" fn(
    *mut DMA_ADAPTER,
    *mut c_void,
    u32,
    Option<DRIVER_CONTROL>,
    *mut c_void,
) -> NTSTATUS;
type FreeChannel = unsafe extern "C" fn(*mut DMA_ADAPTER);
type FreeRegisters = unsafe extern "C" fn(*mut DMA_ADAPTER, *mut c_void, u32);
type Map =
    unsafe extern "C" fn(*mut DMA_ADAPTER, *mut MDL, *mut c_void, *mut c_void, *mut u32, u8) -> i64;
type Flush =
    unsafe extern "C" fn(*mut DMA_ADAPTER, *mut MDL, *mut c_void, *mut c_void, u32, u8) -> u8;
type Alignment = unsafe extern "C" fn(*mut DMA_ADAPTER) -> u32;
type GetList = unsafe extern "C" fn(
    *mut DMA_ADAPTER,
    *mut c_void,
    *mut MDL,
    *mut c_void,
    u32,
    Option<DRIVER_LIST_CONTROL>,
    *mut c_void,
    u8,
) -> NTSTATUS;
type PutList = unsafe extern "C" fn(*mut DMA_ADAPTER, *mut SCATTER_GATHER_LIST, u8);
type Calculate = unsafe extern "C" fn(
    *mut DMA_ADAPTER,
    *mut MDL,
    *mut c_void,
    u32,
    *mut u32,
    *mut u32,
) -> NTSTATUS;
type BuildList = unsafe extern "C" fn(
    *mut DMA_ADAPTER,
    *mut c_void,
    *mut MDL,
    *mut c_void,
    u32,
    Option<DRIVER_LIST_CONTROL>,
    *mut c_void,
    u8,
    *mut c_void,
    u32,
) -> NTSTATUS;
type BuildMdl = unsafe extern "C" fn(
    *mut DMA_ADAPTER,
    *mut SCATTER_GATHER_LIST,
    *mut MDL,
    *mut *mut MDL,
) -> NTSTATUS;
type AdapterInfo = unsafe extern "C" fn(*mut DMA_ADAPTER, *mut DMA_ADAPTER_INFO) -> NTSTATUS;
type FlushBuffer = unsafe extern "C" fn(*mut DMA_ADAPTER, *mut MDL, u8) -> NTSTATUS;

/// An adapter and its table, as a driver holds them.
struct Adapter {
    adapter: *mut DMA_ADAPTER,
    registers: u32,
}

impl Adapter {
    /// `IoGetDmaAdapter` for a bus master that does scatter/gather.
    fn get(version: u32, dma32: bool, dma64: bool, width: u32) -> Option<Self> {
        // SAFETY: zero is a valid value of every field.
        let mut description: DEVICE_DESCRIPTION = unsafe { MaybeUninit::zeroed().assume_init() };
        description.Version = version;
        description.Master = 1;
        description.ScatterGather = 1;
        description.Dma32BitAddresses = u8::from(dma32);
        description.Dma64BitAddresses = u8::from(dma64);
        description.InterfaceType = 5; // PCIBus
        description.MaximumLength = 0x1_0000;
        description.DmaAddressWidth = width;
        Self::described(&description)
    }

    fn described(description: &DEVICE_DESCRIPTION) -> Option<Self> {
        let mut registers = 0;
        // SAFETY: a whole description and a place for the count.
        let adapter =
            unsafe { IoGetDmaAdapter(core::ptr::null_mut(), description, &raw mut registers) };
        (!adapter.is_null()).then(|| Self { adapter, registers })
    }

    /// The operation in one slot of the adapter's table, as a function
    /// of type `F`.
    ///
    /// # Safety
    /// `F` is the function-pointer type of that operation.
    unsafe fn op<F: Copy>(&self, slot: impl FnOnce(&DMA_OPERATIONS) -> *const ()) -> F {
        // SAFETY: the adapter's table, which is never written; per the
        // contract the slot holds a function of type `F`.
        unsafe {
            let routine = slot(&*(*self.adapter).DmaOperations);
            core::mem::transmute_copy(&routine)
        }
    }

    fn info(&self) -> Option<DMA_ADAPTER_INFO> {
        // SAFETY: zero is a valid value; the slot's type is its own.
        unsafe {
            let mut info: DMA_ADAPTER_INFO = MaybeUninit::zeroed().assume_init();
            info.Version = DMA_ADAPTER_INFO_VERSION1;
            let get: AdapterInfo = self.op(|o| o.GetDmaAdapterInfo);
            (get(self.adapter, &raw mut info) == STATUS_SUCCESS).then_some(info)
        }
    }
}

impl Drop for Adapter {
    fn drop(&mut self) {
        // SAFETY: the slot's type is its own; the adapter is not used
        // again.
        unsafe {
            let put: PutAdapter = self.op(|o| o.PutDmaAdapter);
            put(self.adapter);
        }
    }
}

/// An adapter is made for a bus master of each description version and
/// says what it is; a device that is not a bus master, and a version
/// nobody defines, get none. Returns the map registers of a 64 KiB
/// device.
fn adapter() -> Result<u32, &'static str> {
    let a = Adapter::get(DEVICE_DESCRIPTION_VERSION2, true, false, 0)
        .ok_or("no adapter for a 32-bit bus master")?;
    // SAFETY: a live adapter; slots called at their own types.
    unsafe {
        if (*a.adapter).Version != 2
            || usize::from((*a.adapter).Size) != size_of::<DMA_ADAPTER>()
            || (*(*a.adapter).DmaOperations).Size as usize != size_of::<DMA_OPERATIONS>()
        {
            return Err("the adapter's header is wrong");
        }
        let alignment: Alignment = a.op(|o| o.GetDmaAlignment);
        let flush: FlushBuffer = a.op(|o| o.FlushDmaBuffer);
        if alignment(a.adapter) != 1 || flush(a.adapter, core::ptr::null_mut(), 1) != STATUS_SUCCESS
        {
            return Err("a bus master's alignment or flush is wrong");
        }
    }
    if a.registers != 17 {
        return Err("map registers are not the pages of the longest transfer and one");
    }
    let info = a.info().ok_or("GetDmaAdapterInfo failed")?;
    if info.DmaAddressWidth != 32
        || info.ScatterGatherLimit != 17
        || info.ReadDmaCounterAvailable != 0
        || info.Flags & ADAPTER_INFO_SYNCHRONOUS_CALLBACK == 0
    {
        return Err("GetDmaAdapterInfo does not describe the adapter");
    }
    let widths = [
        (DEVICE_DESCRIPTION_VERSION, false, false, 0, 24),
        (DEVICE_DESCRIPTION_VERSION1, true, true, 0, 64),
        (DEVICE_DESCRIPTION_VERSION3, true, false, 40, 40),
        (DEVICE_DESCRIPTION_VERSION3, true, false, 0, 32),
    ];
    for (version, dma32, dma64, stated, width) in widths {
        let a = Adapter::get(version, dma32, dma64, stated).ok_or("a valid description failed")?;
        if a.info().map(|i| i.DmaAddressWidth) != Some(width) {
            return Err("an adapter's address width is not its description's");
        }
    }
    // SAFETY: zero is a valid value of every field.
    let mut slave: DEVICE_DESCRIPTION = unsafe { MaybeUninit::zeroed().assume_init() };
    slave.Version = DEVICE_DESCRIPTION_VERSION2;
    if Adapter::described(&slave).is_some() || Adapter::get(4, true, true, 0).is_some() {
        return Err("an adapter was made for a description NK does not serve");
    }
    // Memory on a bus is where it is for the processor.
    let (mut space, mut translated) = (0u32, 0i64);
    // SAFETY: both are valid for the call.
    let known =
        unsafe { HalTranslateBusAddress(5, 0, 0xFEB0_0000, &raw mut space, &raw mut translated) };
    if known != 1 || translated != 0xFEB0_0000 || space != 0 {
        return Err("a memory address on a bus was not translated to itself");
    }
    Ok(a.registers)
}

/// Whether the `bytes` bytes at `va` are one physical run, and where it
/// starts.
fn run_of(va: *mut c_void, bytes: usize) -> Option<u64> {
    let start = MmGetPhysicalAddress(va);
    let contiguous = (0..bytes)
        .step_by(PAGE)
        .all(|off| MmGetPhysicalAddress(va.wrapping_byte_add(off)) == start + off as i64);
    (start != 0 && contiguous).then_some(start as u64)
}

/// A common buffer is contiguous, where the device reaches it, and its
/// logical address is its physical address; the bounded forms keep to
/// their bounds. Returns the buffer's address.
fn common_buffer() -> Result<u64, &'static str> {
    let a = Adapter::get(DEVICE_DESCRIPTION_VERSION2, true, false, 0).ok_or("no adapter")?;
    let bytes = 3 * PAGE + 17;
    // SAFETY: a live adapter; slots called at their own types.
    unsafe {
        let allocate: AllocateCommon = a.op(|o| o.AllocateCommonBuffer);
        let allocate_ex: AllocateCommonEx = a.op(|o| o.AllocateCommonBufferEx);
        let allocate_bounds: AllocateCommonBounds = a.op(|o| o.AllocateCommonBufferWithBounds);
        let free: FreeCommon = a.op(|o| o.FreeCommonBuffer);
        let mut logical = 0i64;
        let buffer = allocate(a.adapter, bytes as u32, &raw mut logical, 1);
        if buffer.is_null() {
            return Err("AllocateCommonBuffer returned null");
        }
        let check = || {
            if run_of(buffer, bytes) != Some(logical as u64) {
                return Err("a common buffer is not one run at its logical address");
            }
            if logical as u64 + bytes as u64 > 1 << 32 {
                return Err("a 32-bit device's common buffer is not below 4 GiB");
            }
            buffer.cast::<u8>().write_bytes(0xCB, bytes);
            // Below a bound of the caller's that is lower than the
            // adapter's.
            let ceiling = logical + (64 * PAGE) as i64;
            let mut low = 0i64;
            let under = allocate_ex(
                a.adapter,
                &raw const ceiling,
                PAGE as u32,
                &raw mut low,
                1,
                0,
            );
            if under.is_null() {
                return Err("AllocateCommonBufferEx returned null");
            }
            free(a.adapter, PAGE as u32, low, under, 1);
            if low + PAGE as i64 - 1 > ceiling || MmGetPhysicalAddress(under) != low {
                return Err("AllocateCommonBufferEx did not keep below its maximum");
            }
            // At or above a bound of the caller's.
            let floor = logical + 16 * PAGE as i64;
            let mut high = 0i64;
            let over = allocate_bounds(
                a.adapter,
                &raw const floor,
                core::ptr::null(),
                PAGE as u32,
                0,
                core::ptr::null(),
                0,
                &raw mut high,
            );
            if over.is_null() {
                return Err("AllocateCommonBufferWithBounds returned null");
            }
            free(a.adapter, PAGE as u32, high, over, 1);
            if high < floor {
                return Err("AllocateCommonBufferWithBounds went below its minimum");
            }
            Ok(logical as u64)
        };
        let verdict = check();
        free(a.adapter, bytes as u32, logical, buffer, 1);
        verdict
    }
}

/// What an execution routine saw.
struct Executed {
    irql: u8,
    list: *mut SCATTER_GATHER_LIST,
    base: *mut c_void,
    /// What an adapter-channel routine is to return.
    action: u32,
    calls: u32,
}

impl Executed {
    fn new(action: u32) -> Self {
        Self {
            irql: 0xFF,
            list: core::ptr::null_mut(),
            base: core::ptr::null_mut(),
            action,
            calls: 0,
        }
    }
}

/// A scatter/gather execution routine.
///
/// # Safety
/// `context` is the test's `Executed`.
unsafe extern "C" fn list_ready(
    _device: *mut c_void,
    _irp: *mut c_void,
    list: *mut SCATTER_GATHER_LIST,
    context: *mut c_void,
) {
    // SAFETY: per the contract; the test does not touch it meanwhile.
    let executed = unsafe { &mut *context.cast::<Executed>() };
    executed.irql = KeGetCurrentIrql();
    executed.list = list;
    executed.calls += 1;
}

/// An adapter-channel execution routine.
///
/// # Safety
/// `context` is the test's `Executed`.
unsafe extern "C" fn channel_ready(
    _device: *mut c_void,
    _irp: *mut c_void,
    base: *mut c_void,
    context: *mut c_void,
) -> u32 {
    // SAFETY: per the contract; the test does not touch it meanwhile.
    let executed = unsafe { &mut *context.cast::<Executed>() };
    executed.irql = KeGetCurrentIrql();
    executed.base = base;
    executed.calls += 1;
    executed.action
}

/// Pages for a transfer: an MDL of allocated pages in a range of
/// physical addresses, and the mapping through which the test, as the
/// driver, fills and reads them.
struct Buffer {
    mdl: *mut MDL,
    va: *mut u8,
    bytes: usize,
}

impl Buffer {
    fn new(lowest: u64, pages: usize) -> Option<Self> {
        // SAFETY: the MDL and its pages are freed by `drop`.
        unsafe {
            let mdl =
                MmAllocatePagesForMdlEx(lowest as i64, i64::MAX, 0, pages * PAGE, MM_CACHED, 0);
            if mdl.is_null() {
                return None;
            }
            let va = MmMapLockedPagesSpecifyCache(
                mdl,
                KERNEL_MODE,
                MM_CACHED,
                core::ptr::null_mut(),
                0,
                16,
            );
            let buffer = Self {
                mdl,
                va: va.cast(),
                bytes: pages * PAGE,
            };
            (!va.is_null()).then_some(buffer)
        }
    }

    /// Physical address of byte `offset` of the buffer.
    fn physical(&self, offset: usize) -> u64 {
        MmGetPhysicalAddress(self.va.wrapping_add(offset).cast()) as u64
    }

    fn fill(&self, with: impl Fn(usize) -> u8) {
        for i in 0..self.bytes {
            // SAFETY: the buffer's own mapping.
            unsafe { self.va.add(i).write(with(i)) };
        }
    }

    fn holds(&self, from: usize, length: usize, what: impl Fn(usize) -> u8) -> bool {
        // SAFETY: the buffer's own mapping.
        (from..from + length).all(|i| unsafe { self.va.add(i).read() } == what(i))
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        // SAFETY: what `new` allocated and mapped.
        unsafe {
            if !self.va.is_null() {
                MmUnmapLockedPages(self.va.cast(), self.mdl);
            }
            MmFreePagesFromMdl(self.mdl);
            ExFreePool(self.mdl.cast());
        }
    }
}

/// Run `at_dispatch` as a driver's start-I/O path runs: at
/// `DISPATCH_LEVEL`, where the scatter/gather and adapter-channel
/// operations are called.
fn at_dispatch<R>(body: impl FnOnce() -> R) -> R {
    let old = KfRaiseIrql(DISPATCH_LEVEL);
    let result = body();
    KeLowerIrql(old);
    result
}

/// The elements of a list.
///
/// # Safety
/// `list` is a live scatter/gather list.
unsafe fn elements(list: *mut SCATTER_GATHER_LIST) -> alloc::vec::Vec<(u64, u32)> {
    // SAFETY: per the contract.
    unsafe {
        let first = (&raw mut (*list).Elements).cast::<SCATTER_GATHER_ELEMENT>();
        (0..(*list).NumberOfElements as usize)
            .map(|i| {
                let e = first.add(i).read();
                (e.Address as u64, e.Length)
            })
            .collect()
    }
}

/// What the device does with a list: reads or writes every byte it
/// names, in order. `byte(i)` is called with each byte's place in the
/// transfer and the address the device uses for it.
///
/// # Safety
/// The list's addresses are RAM.
unsafe fn device(list: &[(u64, u32)], mut byte: impl FnMut(usize, *mut u8)) {
    let mut at = 0;
    for &(address, length) in list {
        for i in 0..length as usize {
            byte(
                at,
                MmGetVirtualForPhysical((address + i as u64) as i64).cast(),
            );
            at += 1;
        }
    }
}

/// A transfer from the middle of a five-page buffer the device reaches:
/// the list names the buffer's own memory, joined into runs, and is
/// handed to the execution routine at `DISPATCH_LEVEL`, built in the
/// driver's buffer or in one of NK's. Returns the elements of the list.
fn scatter_gather() -> Result<usize, &'static str> {
    let a = Adapter::get(DEVICE_DESCRIPTION_VERSION2, true, true, 0).ok_or("no adapter")?;
    let buffer = Buffer::new(0, 5).ok_or("no pages for the transfer")?;
    buffer.fill(|i| i as u8);
    let (start, length) = (0x234usize, 3 * PAGE + 0x100);
    // Offsets into pages that were allocated for an MDL: its buffer
    // begins at address zero.
    let current_va = start as *mut c_void;
    // SAFETY: a live adapter; slots called at their own types.
    unsafe {
        let calculate: Calculate = a.op(|o| o.CalculateScatterGatherList);
        let build: BuildList = a.op(|o| o.BuildScatterGatherList);
        let get: GetList = a.op(|o| o.GetScatterGatherList);
        let put: PutList = a.op(|o| o.PutScatterGatherList);
        let build_mdl: BuildMdl = a.op(|o| o.BuildMdlFromScatterGatherList);
        let (mut bytes, mut registers) = (0u32, 0u32);
        let status = calculate(
            a.adapter,
            buffer.mdl,
            current_va,
            length as u32,
            &raw mut bytes,
            &raw mut registers,
        );
        if status != STATUS_SUCCESS || registers != 4 || bytes == 0 {
            return Err("CalculateScatterGatherList is wrong for four pages");
        }
        // More than the MDL describes.
        let too_long = calculate(
            a.adapter,
            buffer.mdl,
            current_va,
            (5 * PAGE) as u32,
            &raw mut bytes,
            core::ptr::null_mut(),
        );
        if too_long != STATUS_BUFFER_TOO_SMALL {
            return Err("a transfer longer than its MDL was sized");
        }
        let storage = ExAllocatePoolWithTag(0, bytes as usize, TAG);
        if storage.is_null() {
            return Err("no pool");
        }
        let check = || {
            let mut executed = Executed::new(0);
            let context = (&raw mut executed).cast::<c_void>();
            let short = at_dispatch(|| {
                build(
                    a.adapter,
                    core::ptr::null_mut(),
                    buffer.mdl,
                    current_va,
                    length as u32,
                    Some(list_ready),
                    context,
                    1,
                    storage,
                    bytes - 1,
                )
            });
            if short != STATUS_BUFFER_TOO_SMALL || executed.calls != 0 {
                return Err("a list was built in a buffer too small for it");
            }
            let mut count = 0;
            for own_buffer in [true, false] {
                let status = at_dispatch(|| {
                    if own_buffer {
                        build(
                            a.adapter,
                            core::ptr::null_mut(),
                            buffer.mdl,
                            current_va,
                            length as u32,
                            Some(list_ready),
                            context,
                            1,
                            storage,
                            bytes,
                        )
                    } else {
                        get(
                            a.adapter,
                            core::ptr::null_mut(),
                            buffer.mdl,
                            current_va,
                            length as u32,
                            Some(list_ready),
                            context,
                            1,
                        )
                    }
                });
                if status != STATUS_SUCCESS || executed.list.is_null() {
                    return Err("the scatter/gather list was not built");
                }
                let list = elements(executed.list);
                let mut same = true;
                device(&list, |at, address| {
                    same &= address.read() == (start + at) as u8;
                });
                let mut target = core::ptr::null_mut();
                let mdl_status = build_mdl(a.adapter, executed.list, buffer.mdl, &raw mut target);
                let total: usize = list.iter().map(|e| e.1 as usize).sum();
                let first = list.first().map(|e| e.0);
                let joined = list
                    .windows(2)
                    .all(|w| w[0].0 + u64::from(w[0].1) != w[1].0);
                put(a.adapter, executed.list, 1);
                if executed.irql != DISPATCH_LEVEL {
                    return Err("the execution routine did not run at DISPATCH_LEVEL");
                }
                if total != length || first != Some(buffer.physical(start)) || !same {
                    return Err("the list does not name the transfer's memory");
                }
                if list.len() > 4 || !joined {
                    return Err("adjacent memory was not joined into one element");
                }
                if mdl_status != STATUS_SUCCESS || target != buffer.mdl {
                    return Err("the MDL of a transfer nothing bounced is not the original");
                }
                count = list.len();
            }
            if executed.calls != 2 {
                return Err("the execution routine was not called once for each list");
            }
            Ok(count)
        };
        let verdict = check();
        ExFreePool(storage);
        verdict
    }
}

/// The widest device that cannot reach all of this machine's memory
/// but reaches some of it: its address width, if there is one.
fn narrow_width() -> Option<u32> {
    // The highest frame of memory NK allocates from.
    let (_, _, highest) = mm::physical_memory();
    let width = 63 - (highest * PAGE as u64).leading_zeros();
    // Memory must be free on both sides of the limit.
    let below = Buffer::new(0, 1)?;
    let above = Buffer::new(1 << width, 1)?;
    (below.physical(0) < 1 << width && above.physical(0) >= 1 << width && width >= 24)
        .then_some(width)
}

/// A device that cannot reach the transfer's memory is given bounce
/// pages it can: what the driver wrote is there for the device to read,
/// and what the device wrote is in the driver's memory once the list is
/// put back. Returns the address width of the device.
fn bounce(width: u32) -> Result<u32, &'static str> {
    let a = Adapter::get(DEVICE_DESCRIPTION_VERSION3, true, false, width).ok_or("no adapter")?;
    let limit = 1u64 << width;
    let buffer = Buffer::new(limit, 3).ok_or("no pages above the device's reach")?;
    let (start, length) = (0x7F0usize, PAGE + 0x900);
    let current_va = start as *mut c_void;
    let written = |i: usize| (i as u8) ^ 0x5A;
    let from_device = |i: usize| (i as u8).wrapping_mul(3);
    buffer.fill(written);
    if a.info().map(|i| i.Flags & ADAPTER_INFO_API_BYPASS) != Some(0) {
        return Err("an adapter that must bounce says its routines can be bypassed");
    }
    // SAFETY: a live adapter; slots called at their own types.
    unsafe {
        let get: GetList = a.op(|o| o.GetScatterGatherList);
        let put: PutList = a.op(|o| o.PutScatterGatherList);
        let allocate: AllocateCommon = a.op(|o| o.AllocateCommonBuffer);
        let free: FreeCommon = a.op(|o| o.FreeCommonBuffer);
        // Its common buffers lie within its reach.
        let mut logical = 0i64;
        let common = allocate(a.adapter, PAGE as u32, &raw mut logical, 1);
        if common.is_null() {
            return Err("no common buffer within the device's reach");
        }
        free(a.adapter, PAGE as u32, logical, common, 1);
        if logical as u64 + PAGE as u64 > limit {
            return Err("a common buffer lies beyond the device's reach");
        }
        let mut executed = Executed::new(0);
        let context = (&raw mut executed).cast::<c_void>();
        let transfer = |write_to_device: u8| {
            at_dispatch(|| {
                get(
                    a.adapter,
                    core::ptr::null_mut(),
                    buffer.mdl,
                    current_va,
                    length as u32,
                    Some(list_ready),
                    context,
                    write_to_device,
                )
            })
        };
        // To the device: it finds the driver's bytes where the list
        // says, all within its reach.
        if transfer(1) != STATUS_SUCCESS {
            return Err("the list of a bounced transfer was not built");
        }
        let list = elements(executed.list);
        let within = list
            .iter()
            .all(|&(address, len)| address + u64::from(len) <= limit);
        let total: usize = list.iter().map(|e| e.1 as usize).sum();
        let mut same = true;
        device(&list, |at, address| {
            same &= address.read() == written(start + at);
        });
        put(a.adapter, executed.list, 1);
        if !within || total != length {
            return Err("the list names memory beyond the device's reach");
        }
        if !same {
            return Err("the device does not find what the driver wrote");
        }
        // From the device: its bytes reach the driver's memory when the
        // list is put back, and only the transfer's bytes change.
        if transfer(0) != STATUS_SUCCESS {
            return Err("the list of a bounced transfer was not built");
        }
        let list = elements(executed.list);
        device(&list, |at, address| address.write(from_device(start + at)));
        let early = buffer.holds(start, length, from_device);
        put(a.adapter, executed.list, 0);
        if early {
            return Err("the transfer was not bounced at all");
        }
        if !buffer.holds(start, length, from_device)
            || !buffer.holds(0, start, written)
            || !buffer.holds(start + length, buffer.bytes - start - length, written)
        {
            return Err("what the device wrote did not reach the driver's memory, or more did");
        }
    }
    Ok(width)
}

/// Adapter channels and map registers: the execution routine is called
/// at `DISPATCH_LEVEL` with a register base; `MapTransfer` gives an
/// address the device reaches and the length that lies there;
/// `FlushAdapterBuffers` brings what the device wrote to the driver's
/// memory; registers and channels are freed as the routine's answer
/// says. `width`: a device that must bounce, where the machine has
/// memory beyond some device's reach, else one that reaches everything.
/// Returns how many runs the transfer was mapped in.
fn map_registers(width: Option<u32>) -> Result<u32, &'static str> {
    let (a, lowest) = match width {
        Some(width) => (
            Adapter::get(DEVICE_DESCRIPTION_VERSION3, true, false, width),
            1u64 << width,
        ),
        None => (Adapter::get(DEVICE_DESCRIPTION_VERSION2, true, true, 0), 0),
    };
    let a = a.ok_or("no adapter")?;
    let limit = width.map_or(u64::MAX, |w| 1 << w);
    let buffer = Buffer::new(lowest, 3).ok_or("no pages for the transfer")?;
    let (start, length) = (0x10usize, 2 * PAGE + 0x20);
    let from_device = |i: usize| (i as u8).wrapping_add(7);
    buffer.fill(|_| 0);
    // SAFETY: a live adapter; slots called at their own types.
    unsafe {
        let allocate: AllocateChannel = a.op(|o| o.AllocateAdapterChannel);
        let free_channel: FreeChannel = a.op(|o| o.FreeAdapterChannel);
        let free_registers: FreeRegisters = a.op(|o| o.FreeMapRegisters);
        let map: Map = a.op(|o| o.MapTransfer);
        let flush: Flush = a.op(|o| o.FlushAdapterBuffers);
        let channel = |executed: &mut Executed, registers: u32| {
            let context = core::ptr::from_mut(executed).cast::<c_void>();
            at_dispatch(|| {
                allocate(
                    a.adapter,
                    core::ptr::null_mut(),
                    registers,
                    Some(channel_ready),
                    context,
                )
            })
        };
        // More registers than the adapter has.
        let mut executed = Executed::new(DEALLOCATE_OBJECT);
        if channel(&mut executed, a.registers + 1) != STATUS_INSUFFICIENT_RESOURCES
            || executed.calls != 0
        {
            return Err("more map registers than the adapter has were allocated");
        }
        // The routine keeps the registers, and frees them itself.
        let mut executed = Executed::new(DEALLOCATE_OBJECT_KEEP_REGISTERS);
        if channel(&mut executed, 3) != STATUS_SUCCESS
            || executed.calls != 1
            || executed.irql != DISPATCH_LEVEL
            || executed.base.is_null()
        {
            return Err("the execution routine was not called at DISPATCH_LEVEL with registers");
        }
        let base = executed.base;
        // The device writes the whole transfer, run by run.
        let (mut done, mut runs) = (0usize, 0u32);
        let mut within = true;
        while done < length {
            let mut run = (length - done) as u32;
            let va = (start + done) as *mut c_void;
            let address = map(a.adapter, buffer.mdl, base, va, &raw mut run, 0) as u64;
            if run == 0 || run as usize > length - done {
                free_registers(a.adapter, base, 3);
                return Err("MapTransfer mapped no bytes, or more than were asked");
            }
            within &= address + u64::from(run) <= limit;
            for i in 0..run as usize {
                MmGetVirtualForPhysical((address + i as u64) as i64)
                    .cast::<u8>()
                    .write(from_device(start + done + i));
            }
            if flush(a.adapter, buffer.mdl, base, va, run, 0) != 1 {
                free_registers(a.adapter, base, 3);
                return Err("FlushAdapterBuffers failed");
            }
            done += run as usize;
            runs += 1;
        }
        free_registers(a.adapter, base, 3);
        if !within {
            return Err("MapTransfer gave an address beyond the device's reach");
        }
        if !buffer.holds(start, length, from_device)
            || !buffer.holds(0, start, |_| 0)
            || !buffer.holds(start + length, buffer.bytes - start - length, |_| 0)
        {
            return Err("what the device wrote did not reach the driver's memory, or more did");
        }
        // The routine keeps the adapter: a second allocation waits its
        // turn, which here means it is refused, until the first is
        // freed.
        let mut executed = Executed::new(KEEP_OBJECT);
        if channel(&mut executed, 2) != STATUS_SUCCESS {
            return Err("an adapter channel was not allocated");
        }
        let mut second = Executed::new(DEALLOCATE_OBJECT);
        let busy = channel(&mut second, 2);
        free_channel(a.adapter);
        let free_again = channel(&mut second, 2);
        if busy != STATUS_INSUFFICIENT_RESOURCES || free_again != STATUS_SUCCESS {
            return Err("a kept adapter channel was not held until freed");
        }
        Ok(runs)
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    match adapter() {
        Ok(n) => r.ok_with("hal.dma.adapter", format_args!("map registers: {n}")),
        Err(why) => r.fail("hal.dma.adapter", format_args!("{why}")),
    }
    match common_buffer() {
        Ok(at) => r.ok_with("hal.dma.common-buffer", format_args!("at {at:#x}")),
        Err(why) => r.fail("hal.dma.common-buffer", format_args!("{why}")),
    }
    match scatter_gather() {
        Ok(n) => r.ok_with("hal.dma.scatter-gather", format_args!("elements: {n}")),
        Err(why) => r.fail("hal.dma.scatter-gather", format_args!("{why}")),
    }
    let width = narrow_width();
    match width {
        Some(width) => match bounce(width) {
            Ok(width) => r.ok_with(
                "hal.dma.bounce",
                format_args!("for a device of {width} address bits"),
            ),
            Err(why) => r.fail("hal.dma.bounce", format_args!("{why}")),
        },
        None => r.skip(
            "hal.dma.bounce",
            format_args!("no address width divides this machine's memory"),
        ),
    }
    match map_registers(width) {
        Ok(runs) => r.ok_with("hal.dma.map-registers", format_args!("runs: {runs}")),
        Err(why) => r.fail("hal.dma.map-registers", format_args!("{why}")),
    }
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
