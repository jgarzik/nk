//! More than one processor.
//!
//! The boot processor starts the others one at a time. Each sets up its
//! own state (the architecture's part), starts its clock, reports that it
//! is running, and becomes its own idle thread (`thread.rs`).

use super::{irql, thread, time};
use crate::ex::callback;
use crate::hal::platform;
use crate::mm::stack::Stack;
use crate::ob::handle::OBJ_KERNEL_HANDLE;
use crate::{arch, mm};
use core::ffi::c_void;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use nk_bootinfo::BootInfo;
use nk_ke::topology::{self, Record};
use nk_ntabi::interrupt::GROUP_AFFINITY;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::ke::{
    KE_PROCESSOR_ADD_COMPLETE_NOTIFY, KE_PROCESSOR_ADD_FAILURE_NOTIFY,
    KE_PROCESSOR_ADD_START_NOTIFY, KE_PROCESSOR_CHANGE_ADD_EXISTING,
    KE_PROCESSOR_CHANGE_NOTIFY_CONTEXT, PROCESSOR_CALLBACK_FUNCTION, PROCESSOR_NUMBER,
};
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::{
    NTSTATUS, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_PARAMETER, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL,
};
use nk_ntabi::sysinfo::{
    GROUP_RELATIONSHIP_ENTRY, NUMA_NODE_RELATIONSHIP_ENTRY, PROCESSOR_RELATIONSHIP_ENTRY,
};

/// Bit `n` is set once processor `n` is running. The boot processor is.
static ONLINE: AtomicU64 = AtomicU64::new(1);

/// [`KeNumberProcessors`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/kenumberprocessors):
/// exported single-byte count of active processors in group 0.
#[allow(non_upper_case_globals)]
pub static KeNumberProcessors: crate::kd::variables::Variable<AtomicU8> =
    crate::kd::variables::Variable::new(AtomicU8::new(1));

/// [`KeQueryActiveProcessors`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryactiveprocessors):
/// the bitmask of currently active processors in group 0.
#[allow(non_snake_case)]
pub extern "C" fn KeQueryActiveProcessors() -> usize {
    online() as usize
}

/// How long a processor gets to report in: 100 ns units. Generous; an
/// emulated machine with many processors starts them slowly.
const START_TIMEOUT: u64 = 5 * 10_000_000;

/// The lowest address of the stack each processor started on, which
/// becomes its idle thread's.
static STACKS: [AtomicU64; platform::MAX_CPUS] = [const { AtomicU64::new(0) }; platform::MAX_CPUS];

/// Record the stack processor `number` starts on.
pub fn set_stack(number: usize, stack: Stack) {
    STACKS[number].store(stack.base, Ordering::Release);
}

/// The stack processor `number` started on.
pub fn stack_of(number: usize) -> Stack {
    let base = STACKS[number].load(Ordering::Acquire);
    Stack {
        base,
        top: base + nk_bootinfo::KERNEL_STACK_SIZE,
    }
}

/// The mask of running processors.
pub fn online() -> u64 {
    ONLINE.load(Ordering::Acquire)
}

pub fn online_count() -> usize {
    ONLINE.load(Ordering::Acquire).count_ones() as usize
}

/// `ALL_PROCESSOR_GROUPS`.
const ALL_PROCESSOR_GROUPS: u16 = 0xFFFF;

/// [`KeQueryActiveProcessorCountEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryactiveprocessorcountex):
/// the processors running in a group, or in all groups. There is one
/// group, number 0, as on any Windows system of up to 64 processors;
/// another group has none.
#[allow(non_snake_case)]
pub extern "C" fn KeQueryActiveProcessorCountEx(group: u16) -> u32 {
    match group {
        ALL_PROCESSOR_GROUPS | 0 => online_count() as u32,
        _ => 0,
    }
}

/// [`KeQueryActiveProcessorCount`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryactiveprocessorcount):
/// the processors running in group 0, and, if asked, their mask. With
/// no mask asked for, Windows counts every group's processors; there is
/// only group 0.
///
/// # Safety
/// `mask` is null or writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeQueryActiveProcessorCount(mask: *mut u64) -> u32 {
    if mask.is_null() {
        return KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    }
    let online = online();
    // SAFETY: per the contract.
    unsafe { mask.write_unaligned(online) };
    online.count_ones()
}

pub fn is_online(number: usize) -> bool {
    ONLINE.load(Ordering::Acquire) & 1 << number != 0
}

/// Start every processor firmware listed besides this one. Returns how
/// many are running; a processor that cannot be started is an error.
pub fn start_all(info: &BootInfo) -> Result<usize, &'static str> {
    let cpus = platform::get().cpus().len();
    if cpus > 1 {
        arch::smp_prepare(info)?;
    }
    for number in 1..cpus {
        if !arch::cpu_prepare(number) {
            return Err("no memory for a processor's state");
        }
        super::dpc::prepare_cpu(number)?;
        let stack = mm::stack::alloc().ok_or("no memory for a processor's stack")?;
        set_stack(number, stack);
        arch::cpu_start(number, stack.top)?;
        let deadline = time::interrupt_time() + START_TIMEOUT;
        while !is_online(number) {
            if time::interrupt_time() > deadline {
                kprintln!("ke: processor {number} did not start");
                return Err("a processor did not start");
            }
            core::hint::spin_loop();
        }
    }
    if cpus > 1 {
        arch::smp_finish();
    }
    Ok(online_count())
}

/// Where a started processor arrives once the architecture layer has set
/// up its tables, its PCR and its interrupt controller.
pub fn ap_main(number: usize) -> ! {
    debug_assert_eq!(super::pcr::current_processor() as usize, number);
    arch::set_irql(irql::PASSIVE_LEVEL);
    time::start_cpu();
    // The stack this processor was started on becomes its idle thread's.
    if let Err(why) = thread::init_cpu(stack_of(number)) {
        panic!("processor {number}: {why}");
    }
    let prev = ONLINE.fetch_or(1 << number, Ordering::Release);
    KeNumberProcessors
        .0
        .store((prev | (1 << number)).count_ones() as u8, Ordering::Release);
    arch::enable_interrupts();
    thread::idle_loop()
}

/// Every processor firmware listed is running, and each takes its own
/// clock interrupts. Returns the number running.
pub fn self_test() -> Result<usize, &'static str> {
    let cpus = platform::get().cpus().len();
    if online_count() != cpus {
        return Err("not every processor firmware listed is running");
    }
    if KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS) as usize != online_count()
        || KeQueryActiveProcessorCountEx(0) as usize != online_count()
        || KeQueryActiveProcessorCountEx(1) != 0
    {
        return Err("the active processor count is not the processors running, all in group 0");
    }
    let before: [u64; platform::MAX_CPUS] =
        core::array::from_fn(|n| arch::percpu_of(n).map_or(0, |p| p.ticks()));
    time::stall(250_000);
    for (number, &was) in before.iter().enumerate().take(cpus) {
        let now = arch::percpu_of(number).map_or(0, |p| p.ticks());
        // 16 expected in a quarter second.
        if now - was < 8 {
            return Err("a processor is not taking clock interrupts");
        }
    }
    Ok(cpus)
}

/// [`KeGetCurrentProcessorNumberEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kegetcurrentprocessornumberex):
/// the index of the processor running the caller, and its group and
/// number if asked for.
///
/// # Safety
/// `number` is null or writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeGetCurrentProcessorNumberEx(number: *mut PROCESSOR_NUMBER) -> u32 {
    let index = super::pcr::current_processor();
    if !number.is_null() {
        // SAFETY: per the contract.
        unsafe {
            number.write_unaligned(PROCESSOR_NUMBER {
                Group: 0,
                Number: index as u8,
                Reserved: 0,
            });
        }
    }
    index
}

/// [`KeGetProcessorIndexFromNumber`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kegetprocessorindexfromnumber).
///
/// # Safety
/// `number` is readable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeGetProcessorIndexFromNumber(number: *const PROCESSOR_NUMBER) -> u32 {
    // SAFETY: per the contract.
    let number = unsafe { number.read_unaligned() };
    topology::index_from_number(
        number.Group,
        number.Number,
        number.Reserved,
        online_count() as u32,
    )
}

/// [`KeGetProcessorNumberFromIndex`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kegetprocessornumberfromindex).
///
/// # Safety
/// `number` is writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeGetProcessorNumberFromIndex(
    index: u32,
    number: *mut PROCESSOR_NUMBER,
) -> NTSTATUS {
    let Some((group, in_group)) = topology::number_from_index(index, online_count() as u32) else {
        return STATUS_INVALID_PARAMETER;
    };
    // SAFETY: per the contract.
    unsafe {
        number.write_unaligned(PROCESSOR_NUMBER {
            Group: group,
            Number: in_group,
            Reserved: 0,
        });
    }
    STATUS_SUCCESS
}

/// [`KeQueryMaximumProcessorCountEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequerymaximumprocessorcountex):
/// the most processors a group can have, which is what it has: none is
/// added while the system runs.
#[allow(non_snake_case)]
pub extern "C" fn KeQueryMaximumProcessorCountEx(group: u16) -> u32 {
    topology::count_in_group(group, online_count() as u32)
}

/// [`KeQueryActiveGroupCount`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryactivegroupcount):
/// one.
#[allow(non_snake_case)]
pub extern "C" fn KeQueryActiveGroupCount() -> u16 {
    1
}

/// [`KeQueryMaximumGroupCount`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequerymaximumgroupcount):
/// one.
#[allow(non_snake_case)]
pub extern "C" fn KeQueryMaximumGroupCount() -> u16 {
    1
}

/// [`KeQueryGroupAffinity`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequerygroupaffinity):
/// the running processors of a group, as a mask.
#[allow(non_snake_case)]
pub extern "C" fn KeQueryGroupAffinity(group: u16) -> usize {
    topology::group_affinity(group, online()) as usize
}

/// [`KeGetCurrentNodeNumber`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kegetcurrentnodenumber):
/// the NUMA node of the processor running the caller. There is one
/// node.
#[allow(non_snake_case)]
pub extern "C" fn KeGetCurrentNodeNumber() -> u16 {
    0
}

/// [`KeQueryHighestNodeNumber`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequeryhighestnodenumber).
#[allow(non_snake_case)]
pub extern "C" fn KeQueryHighestNodeNumber() -> u16 {
    0
}

/// [`KeQueryNodeActiveAffinity`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequerynodeactiveaffinity):
/// the running processors of a NUMA node and how many they are. A node
/// there is not has none.
///
/// # Safety
/// Each of `affinity` and `count` is null or writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeQueryNodeActiveAffinity(
    node: u16,
    affinity: *mut GROUP_AFFINITY,
    count: *mut u16,
) {
    let (mask, processors) = topology::node_affinity(node, online());
    // SAFETY: per the contract.
    unsafe {
        if !affinity.is_null() {
            affinity.write_unaligned(GROUP_AFFINITY {
                Mask: mask as usize,
                Group: 0,
                Reserved: [0; 3],
            });
        }
        if !count.is_null() {
            count.write_unaligned(processors);
        }
    }
}

/// [`KeQueryLogicalProcessorRelationship`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kequerylogicalprocessorrelationship):
/// the records of a relationship, for one processor or all
/// (`topology::relationships`). `length` is that of the buffer on
/// entry, and what the records take on return; a processor number
/// that names no processor is `STATUS_INVALID_PARAMETER` and leaves it.
///
/// # Safety
/// `number` is null or readable; `length` is readable and writable;
/// `information` is writable for `*length` bytes.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeQueryLogicalProcessorRelationship(
    number: *const PROCESSOR_NUMBER,
    relationship: u32,
    information: *mut u8,
    length: *mut u32,
) -> NTSTATUS {
    // SAFETY: per the contract; each record written lies within the
    // caller's `*length` bytes, and is written whole through the raw
    // pointer.
    unsafe {
        let given = length.read_unaligned();
        let processor = if number.is_null() {
            None
        } else {
            let index = KeGetProcessorIndexFromNumber(number);
            if index == topology::INVALID_INDEX {
                return STATUS_INVALID_PARAMETER;
            }
            Some(index)
        };
        let (status, needed) =
            topology::relationships(processor, relationship, online(), given, |at, record| {
                let to = information.byte_add(at as usize);
                match *record {
                    Record::Processor(entry) => to
                        .cast::<PROCESSOR_RELATIONSHIP_ENTRY>()
                        .write_unaligned(entry),
                    Record::NumaNode(entry) => to
                        .cast::<NUMA_NODE_RELATIONSHIP_ENTRY>()
                        .write_unaligned(entry),
                    Record::Group(entry) => {
                        to.cast::<GROUP_RELATIONSHIP_ENTRY>().write_unaligned(entry)
                    }
                }
            });
        length.write_unaligned(needed);
        status
    }
}

/// `KeProcessorGroupAffinity`: the affinity that is the one processor
/// at `index`. Undocumented; as the pinned kernel fills it in. Windows
/// does not look whether there is such a processor; NK stops the
/// system if there is none.
///
/// # Safety
/// `affinity` is writable.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeProcessorGroupAffinity(affinity: *mut GROUP_AFFINITY, index: u32) {
    let Some((group, in_group)) = topology::number_from_index(index, online_count() as u32) else {
        crate::kd::bugcheck(format_args!(
            "KeProcessorGroupAffinity for processor {index}, which there is not"
        ));
    };
    // SAFETY: per the contract.
    unsafe {
        affinity.write_unaligned(GROUP_AFFINITY {
            Mask: 1 << in_group,
            Group: group,
            Reserved: [0; 3],
        });
    }
}

/// `KeReportCacheIncoherentDevice`: a device has been found whose DMA
/// does not keep the processors' caches coherent, so buffers must be
/// flushed for devices from now on. NK flushes them wherever the
/// architecture needs it, whether or not this was reported
/// (`KeFlushIoBuffers`), so there is nothing to record.
#[allow(non_snake_case)]
pub extern "C" fn KeReportCacheIncoherentDevice() {}

/// The name of the callback object processor changes are notified
/// through, which Windows and NK make at start.
const PROCESSOR_ADD: [u16; 22] = {
    let text = b"\\Callback\\ProcessorAdd";
    let mut wide = [0u16; 22];
    let mut i = 0;
    while i < text.len() {
        wide[i] = text[i] as u16;
        i += 1;
    }
    wide
};
/// `OBJ_CASE_INSENSITIVE`, with which Windows opens it.
const OBJ_CASE_INSENSITIVE: u32 = 0x40;

/// Open `\Callback\ProcessorAdd`: the object, referenced, or null.
fn processor_add_object() -> *mut c_void {
    let mut text = PROCESSOR_ADD;
    let name = UNICODE_STRING {
        Length: size_of_val(&text) as u16,
        MaximumLength: size_of_val(&text) as u16,
        Buffer: (&raw mut text).cast(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: core::ptr::null_mut(),
        ObjectName: &raw const name,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
        SecurityDescriptor: core::ptr::null_mut(),
        SecurityQualityOfService: core::ptr::null_mut(),
    };
    let mut object = core::ptr::null_mut();
    // SAFETY: the attributes are whole and name a local that outlives
    // the call; `object` is a local.
    let status =
        unsafe { callback::ExCreateCallback(&raw mut object, &raw const attributes, 0, 0) };
    if status < 0 {
        return core::ptr::null_mut();
    }
    object
}

/// Tell `function` of the processor at `index`: `state` and `status`
/// in the context, and `operation` for it to set.
///
/// # Safety
/// `function` may be called with `context`.
unsafe fn notify_processor(
    function: PROCESSOR_CALLBACK_FUNCTION,
    context: *mut c_void,
    index: u32,
    state: u32,
    status: NTSTATUS,
    operation: &mut NTSTATUS,
) {
    let (group, in_group) =
        topology::number_from_index(index, online_count() as u32).unwrap_or((0, 0));
    let mut change = KE_PROCESSOR_CHANGE_NOTIFY_CONTEXT {
        State: state,
        NtNumber: index,
        Status: status,
        ProcNumber: PROCESSOR_NUMBER {
            Group: group,
            Number: in_group,
            Reserved: 0,
        },
    };
    // SAFETY: per the contract; the two pointers are to this frame, for
    // the length of the call. If the routine does not return, NK owes
    // nothing: no lock is held.
    unsafe {
        super::seh::call(
            function as usize,
            [
                context.addr(),
                (&raw mut change).addr(),
                core::ptr::from_mut(operation).addr(),
                0,
            ],
            &super::seh::Guard::Nothing,
        );
    }
}

/// [`KeRegisterProcessorChangeCallback`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keregisterprocessorchangecallback):
/// have `function` told when a processor is added. As on Windows this
/// registers it with the callback object `\Callback\ProcessorAdd`, and
/// what is returned is that registration; null if it could not be made.
/// NK adds no processor while it runs, so the object is never notified.
///
/// With `KE_PROCESSOR_CHANGE_ADD_EXISTING` the routine is called here
/// for the processors there are, as the pinned kernel calls it: for
/// each in turn that its addition starts, then for each that it is
/// complete. If the routine refuses one, by setting the status it is
/// given to a failure, those before it are told of the failure, the
/// registration is undone and null is returned.
///
/// # Safety
/// `function` may be called with `context` until it is unregistered.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeRegisterProcessorChangeCallback(
    function: PROCESSOR_CALLBACK_FUNCTION,
    context: *mut c_void,
    flags: u32,
) -> *mut c_void {
    let object = processor_add_object();
    if object.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: the object is referenced until it is let go below; the
    // rest per the contract.
    unsafe {
        let registration = callback::ExRegisterCallback(object, function as *const c_void, context);
        crate::ob::object::dereference(object.cast());
        if registration.is_null() || flags & KE_PROCESSOR_CHANGE_ADD_EXISTING == 0 {
            return registration;
        }
        let processors = online_count() as u32;
        let mut operation = STATUS_SUCCESS;
        for index in 0..processors {
            operation = STATUS_SUCCESS;
            notify_processor(
                function,
                context,
                index,
                KE_PROCESSOR_ADD_START_NOTIFY,
                STATUS_SUCCESS,
                &mut operation,
            );
            if operation < 0 {
                callback::ExUnregisterCallback(registration);
                let refused = operation;
                for started in 0..index {
                    notify_processor(
                        function,
                        context,
                        started,
                        KE_PROCESSOR_ADD_FAILURE_NOTIFY,
                        refused,
                        &mut operation,
                    );
                }
                return core::ptr::null_mut();
            }
        }
        let status = operation;
        for index in 0..processors {
            notify_processor(
                function,
                context,
                index,
                KE_PROCESSOR_ADD_COMPLETE_NOTIFY,
                status,
                &mut operation,
            );
        }
        registration
    }
}

/// [`KeGetRecommendedSharedDataAlignment`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kegetrecommendedshareddataalignment):
/// the bytes of a cache line.
#[allow(non_snake_case)]
pub extern "C" fn KeGetRecommendedSharedDataAlignment() -> u32 {
    crate::ex::rundown::CACHE_LINE
}

/// [`KeFlushIoBuffers`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-keflushiobuffers):
/// make the caches and memory agree about the buffer an MDL describes,
/// before or after a device reads or writes it. Nothing on x86-64,
/// whose caches a device's access goes through; on arm64 the buffer's
/// lines are written back and dropped.
///
/// # Safety
/// `mdl` describes a buffer mapped in the address space.
#[allow(non_snake_case)]
pub unsafe extern "C" fn KeFlushIoBuffers(
    mdl: *const nk_ntabi::io::MDL,
    _read_operation: u8,
    _dma_operation: u8,
) {
    // SAFETY: per the contract.
    unsafe {
        let start = (&raw const (*mdl).StartVa)
            .read()
            .cast::<u8>()
            .wrapping_add((&raw const (*mdl).ByteOffset).read() as usize);
        arch::sync_dcache(start, (&raw const (*mdl).ByteCount).read() as usize);
    }
}

/// [`KeFlushWriteBuffer`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-keflushwritebuffer):
/// have every store this processor has made reach memory before
/// anything after is done.
#[allow(non_snake_case)]
pub extern "C" fn KeFlushWriteBuffer() {
    core::sync::atomic::fence(Ordering::SeqCst);
}

/// How often the test's processor-change routine was called, by state.
static NOTES: [AtomicU32; 3] = [const { AtomicU32::new(0) }; 3];
/// How often it was told something it should not have been.
static WRONG_NOTES: AtomicU32 = AtomicU32::new(0);
/// The status it refuses a processor with.
const REFUSED: NTSTATUS = nk_ntabi::status::STATUS_INSUFFICIENT_RESOURCES;

/// The test's processor-change routine: each state's calls come for
/// the processors in order, each named right. Its context is one more
/// than the processor to refuse, or zero.
///
/// # Safety
/// Called as a `PROCESSOR_CALLBACK_FUNCTION`.
unsafe extern "C" fn noted(
    context: *mut c_void,
    change: *mut KE_PROCESSOR_CHANGE_NOTIFY_CONTEXT,
    operation: *mut NTSTATUS,
) {
    // SAFETY: per the contract.
    let change = unsafe { change.read_unaligned() };
    let Some(notes) = NOTES.get(change.State as usize) else {
        WRONG_NOTES.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let nth = notes.fetch_add(1, Ordering::Relaxed);
    let named = PROCESSOR_NUMBER {
        Group: 0,
        Number: nth as u8,
        Reserved: 0,
    };
    let status = if change.State == KE_PROCESSOR_ADD_FAILURE_NOTIFY {
        REFUSED
    } else {
        STATUS_SUCCESS
    };
    if change.NtNumber != nth || change.ProcNumber != named || change.Status != status {
        WRONG_NOTES.fetch_add(1, Ordering::Relaxed);
    }
    if change.State == KE_PROCESSOR_ADD_START_NOTIFY && context.addr() == nth as usize + 1 {
        // SAFETY: per the contract.
        unsafe { operation.write_unaligned(REFUSED) };
    }
}

/// A processor-change routine is registered with
/// `\Callback\ProcessorAdd`; asked to, it is told of each processor
/// there is, start then completion; refusing one undoes it all.
fn processor_change_test(processors: u32) -> Result<(), &'static str> {
    let notes = || {
        let taken = [0, 1, 2].map(|state: usize| NOTES[state].swap(0, Ordering::Relaxed));
        (taken, WRONG_NOTES.swap(0, Ordering::Relaxed))
    };
    let register = |refuse: usize, flags: u32| {
        // SAFETY: the routine takes any context.
        unsafe {
            KeRegisterProcessorChangeCallback(
                noted,
                core::ptr::without_provenance_mut(refuse),
                flags,
            )
        }
    };
    notes();
    // Registered only: told nothing until the object is notified.
    let quiet = register(0, 0);
    if quiet.is_null() || notes() != ([0, 0, 0], 0) {
        return Err("a processor-change routine was not registered, or was called unasked");
    }
    // SAFETY: the registration just made; unregistering takes it off
    // the callback object's list, where it must therefore be.
    unsafe { callback::ExUnregisterCallback(quiet) };

    let told = register(0, KE_PROCESSOR_CHANGE_ADD_EXISTING);
    let seen = notes();
    if !told.is_null() {
        // SAFETY: the registration just made.
        unsafe { callback::ExUnregisterCallback(told) };
    }
    if told.is_null() || seen != ([processors, processors, 0], 0) {
        return Err("the routine was not told of each processor there is, start then completion");
    }

    // The last processor is refused: the ones before it are told.
    let refused = register(processors as usize, KE_PROCESSOR_CHANGE_ADD_EXISTING);
    if !refused.is_null() || notes() != ([processors, 0, processors - 1], 0) {
        return Err("a refused processor did not undo the registration");
    }
    Ok(())
}

/// `KeQueryLogicalProcessorRelationship` tells the length first, then
/// writes a package and a core for each processor, the node and the
/// group, and nothing past the length.
fn relationships_test(processors: u32) -> Result<(), &'static str> {
    const ALL: u32 = nk_ntabi::sysinfo::RELATION_ALL;
    const GUARD: u8 = 0xA5;
    // A package and a core for each of up to 64 processors, a node, a
    // group, and a byte that must stay as it is.
    let mut buffer = [GUARD; 64 * 0x60 + 0x80 + 1];
    let information = (&raw mut buffer).cast::<u8>();
    let expected = processors * 0x60 + 0x80;
    let mut length = 0u32;
    // SAFETY: the pointers are to locals; the buffer has the length
    // given, and each record read lies within what was written.
    unsafe {
        let null = core::ptr::null();
        let status = KeQueryLogicalProcessorRelationship(null, ALL, information, &raw mut length);
        if status != STATUS_INFO_LENGTH_MISMATCH || length != expected {
            return Err("the records' length was not told to a caller with no buffer");
        }
        let status = KeQueryLogicalProcessorRelationship(null, ALL, information, &raw mut length);
        if status != STATUS_SUCCESS || length != expected {
            return Err("the records were not written into a buffer of their length");
        }
        for processor in 0..processors as usize {
            let package = information
                .add(processor * 0x60)
                .cast::<PROCESSOR_RELATIONSHIP_ENTRY>()
                .read_unaligned();
            let core = information
                .add(processor * 0x60 + 0x30)
                .cast::<PROCESSOR_RELATIONSHIP_ENTRY>()
                .read_unaligned();
            let own = 1usize << processor;
            if (package.Relationship, package.Size, package.GroupMask.Mask) != (3, 0x30, own)
                || (core.Relationship, core.Size, core.GroupMask.Mask) != (0, 0x30, own)
                || (core.GroupCount, core.Flags) != (1, 0)
            {
                return Err("a processor is not a core of its own in a package of its own");
            }
        }
        let node = information
            .add(processors as usize * 0x60)
            .cast::<NUMA_NODE_RELATIONSHIP_ENTRY>()
            .read_unaligned();
        let group = information
            .add(processors as usize * 0x60 + 0x30)
            .cast::<GROUP_RELATIONSHIP_ENTRY>()
            .read_unaligned();
        if (node.Relationship, node.Size, node.NodeNumber) != (1, 0x30, 0)
            || node.GroupMask.Mask as u64 != online()
            || (group.Relationship, group.Size) != (4, 0x50)
            || u32::from(group.ActiveProcessorCount) != processors
            || group.ActiveProcessorMask as u64 != online()
        {
            return Err("the node and the group records are not of every running processor");
        }
        if buffer[expected as usize..].iter().any(|&b| b != GUARD) {
            return Err("the records were written past their length");
        }
        // One processor: its core alone; a processor there is not.
        let mut number = PROCESSOR_NUMBER {
            Group: 0,
            Number: (processors - 1) as u8,
            Reserved: 0,
        };
        length = 0x30;
        let status =
            KeQueryLogicalProcessorRelationship(&raw const number, 0, information, &raw mut length);
        let core = information
            .cast::<PROCESSOR_RELATIONSHIP_ENTRY>()
            .read_unaligned();
        if status != STATUS_SUCCESS
            || length != 0x30
            || core.GroupMask.Mask != 1 << (processors - 1)
        {
            return Err("the core of one processor was not its own record");
        }
        number.Number = processors as u8;
        length = 0x1234;
        let status =
            KeQueryLogicalProcessorRelationship(&raw const number, 0, information, &raw mut length);
        if status != STATUS_INVALID_PARAMETER || length != 0x1234 {
            return Err("a processor there is not has relationships");
        }
        // Caches: none is known.
        let status = KeQueryLogicalProcessorRelationship(null, 2, information, &raw mut length);
        if status != STATUS_UNSUCCESSFUL || length != 0 {
            return Err("a relationship with no record did not fail");
        }
    }
    Ok(())
}

/// The processor queries answer for one group and one node holding
/// every running processor. Returns the processors.
pub fn queries_test() -> Result<u32, &'static str> {
    let processors = online_count() as u32;
    let mut number = PROCESSOR_NUMBER {
        Group: 9,
        Number: 9,
        Reserved: 9,
    };
    let mut affinity = GROUP_AFFINITY {
        Mask: 0,
        Group: 9,
        Reserved: [9; 3],
    };
    let mut count = 0u16;
    // SAFETY: the pointers are to locals.
    unsafe {
        let old = irql::raise(irql::DISPATCH_LEVEL);
        let here = super::pcr::current_processor();
        let index = KeGetCurrentProcessorNumberEx(&raw mut number);
        let null = KeGetCurrentProcessorNumberEx(core::ptr::null_mut());
        irql::lower(old);
        if (index, null) != (here, here) || (number.Group, u32::from(number.Number)) != (0, here) {
            return Err("KeGetCurrentProcessorNumberEx is not this processor in group 0");
        }
        if KeGetProcessorIndexFromNumber(&raw const number) != here {
            return Err("a processor's number did not lead back to its index");
        }
        number.Group = 1;
        if KeGetProcessorIndexFromNumber(&raw const number) != topology::INVALID_INDEX {
            return Err("a processor of group 1 has an index");
        }
        if KeGetProcessorNumberFromIndex(processors - 1, &raw mut number) != STATUS_SUCCESS
            || (number.Group, u32::from(number.Number), number.Reserved) != (0, processors - 1, 0)
            || KeGetProcessorNumberFromIndex(processors, &raw mut number)
                != STATUS_INVALID_PARAMETER
        {
            return Err("KeGetProcessorNumberFromIndex did not name the last processor only");
        }
        KeQueryNodeActiveAffinity(0, &raw mut affinity, &raw mut count);
        if (affinity.Mask as u64, affinity.Group, u32::from(count)) != (online(), 0, processors) {
            return Err("node 0 does not have every running processor");
        }
        KeQueryNodeActiveAffinity(1, &raw mut affinity, core::ptr::null_mut());
        if affinity.Mask != 0 {
            return Err("a node there is not has processors");
        }
    }
    let counts = (
        KeQueryMaximumProcessorCountEx(0),
        KeQueryMaximumProcessorCountEx(0xFFFF),
        KeQueryMaximumProcessorCountEx(1),
        KeQueryActiveProcessorCountEx(0),
    );
    if counts != (processors, processors, 0, processors) {
        return Err("the processor counts of group 0 are not the running processors");
    }
    if (KeQueryActiveGroupCount(), KeQueryMaximumGroupCount()) != (1, 1)
        || (KeGetCurrentNodeNumber(), KeQueryHighestNodeNumber()) != (0, 0)
        || KeQueryGroupAffinity(0) as u64 != online()
        || KeQueryGroupAffinity(1) != 0
        || KeGetRecommendedSharedDataAlignment() != 64
    {
        return Err("the groups, nodes or cache line are not NK's one of each");
    }
    relationships_test(processors)?;
    processor_change_test(processors)?;
    let mut one = GROUP_AFFINITY {
        Mask: 0,
        Group: 9,
        Reserved: [9; 3],
    };
    // SAFETY: a local.
    unsafe { KeProcessorGroupAffinity(&raw mut one, processors - 1) };
    if (one.Mask, one.Group, one.Reserved) != (1 << (processors - 1), 0, [0; 3]) {
        return Err("KeProcessorGroupAffinity is not the one processor asked for");
    }
    KeReportCacheIncoherentDevice();
    // A buffer flushed for a device still holds what was written.
    let mut buffer = [0x5Au8; 200];
    // SAFETY: a zeroed MDL is a valid one to fill in; it describes the
    // local buffer.
    unsafe {
        let mut mdl = core::mem::zeroed::<nk_ntabi::io::MDL>();
        let page = (&raw mut buffer)
            .cast::<u8>()
            .map_addr(|address| address & !0xFFF);
        mdl.StartVa = page.cast();
        mdl.ByteOffset = ((&raw mut buffer).addr() & 0xFFF) as u32;
        mdl.ByteCount = buffer.len() as u32;
        KeFlushIoBuffers(&raw const mdl, 1, 1);
    }
    KeFlushWriteBuffer();
    if buffer != [0x5A; 200] {
        return Err("flushing a buffer for a device changed it");
    }
    Ok(processors)
}
