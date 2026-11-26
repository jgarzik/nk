//! What drivers ask the HAL about the machine's processors, interrupt
//! vectors and memory: `HalGetProcessorIdByNtNumber`,
//! `HalConvertDeviceIdtToIrql`, `HalGetMessageRoutingInfo` and
//! `HalGetMemoryCachingRequirements`. None is documented; each does what
//! the pinned kernel's routine does, for the machine as NK runs it.

#![allow(non_snake_case)]

use super::platform;
use crate::arch::InterruptVectors;
use crate::ke::smp;
use nk_hal::interrupt::message_routable;
use nk_ntabi::interrupt::{
    HAL_MESSAGE_KIND_MESSAGE, HAL_MESSAGE_ROUTING, HAL_MESSAGE_ROUTING_REQUEST,
    HAL_ROUTING_MESSAGE, HAL_ROUTING_REQUEST,
};
use nk_ntabi::ke::KIRQL;
use nk_ntabi::status::{NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_SUCCESS, STATUS_UNSUCCESSFUL};

/// `HalGetProcessorIdByNtNumber`: the identifier the interrupt
/// controllers know the processor at index `number` by, which is its
/// local APIC's on x86-64 and its `MPIDR` affinity on arm64 (the
/// identifiers of `hal::platform`). `STATUS_INVALID_PARAMETER` for an
/// index that is no processor's.
///
/// The identifier Windows hands out is 32 bits. An arm64 affinity that
/// does not fit (one with a fourth level) stops the system: how Windows
/// names such a processor here is not known to NK.
///
/// # Safety
/// `id` is writable.
pub unsafe extern "C" fn HalGetProcessorIdByNtNumber(number: u32, id: *mut u32) -> NTSTATUS {
    let Some(cpu) = platform::get().cpus().get(number as usize) else {
        return STATUS_INVALID_PARAMETER;
    };
    let Ok(short) = u32::try_from(cpu.hw_id) else {
        crate::kd::bugcheck(format_args!(
            "HalGetProcessorIdByNtNumber: processor {number}'s identifier {:#x} is over 32 bits",
            cpu.hw_id
        ));
    };
    // SAFETY: per the contract.
    unsafe { id.write_unaligned(short) };
    STATUS_SUCCESS
}

/// `HalConvertDeviceIdtToIrql`: the IRQL a device's interrupt on
/// `vector` runs at. On x86-64 the pinned kernel's rule; on arm64,
/// where a vector is an interrupt id, the level NK gives that id.
pub extern "C" fn HalConvertDeviceIdtToIrql(vector: u32) -> KIRQL {
    InterruptVectors::device_irql(vector)
}

/// `HalGetMessageRoutingInfo`: how a message-signalled interrupt for
/// the request's processors is to be delivered. NK remaps no
/// interrupts and addresses processors physically, so a message is
/// delivered as it stands: for a message the answer is its own address
/// and data, and for a request still to be composed, the request's
/// destination mode. `STATUS_INVALID_PARAMETER`, with nothing written,
/// for a target or a mode such a machine cannot route
/// (`nk_hal::interrupt::message_routable`).
///
/// # Safety
/// `request` is readable; `routing` points to the 0x60 bytes of the
/// answer, writable.
pub unsafe extern "C" fn HalGetMessageRoutingInfo(
    request: *const HAL_MESSAGE_ROUTING_REQUEST,
    routing: *mut HAL_MESSAGE_ROUTING,
) -> NTSTATUS {
    // SAFETY: per the contract; the driver's memory, read and written
    // field by field. Only the fields Windows writes are written.
    unsafe {
        let kind = (&raw const (*request).Kind).read_unaligned();
        let target = (&raw const (*request).Target).read_unaligned();
        let mode = (&raw const (*request).DestinationMode).read_unaligned();
        if !message_routable(kind, target.Mask as u64, target.Group, mode, smp::online()) {
            return STATUS_INVALID_PARAMETER;
        }
        (&raw mut (*routing).Count).write_unaligned(1);
        if kind == HAL_MESSAGE_KIND_MESSAGE {
            (&raw mut (*routing).Type).write_unaligned(HAL_ROUTING_MESSAGE);
            (&raw mut (*routing).AddressHigh)
                .write_unaligned((&raw const (*request).AddressHigh).read_unaligned());
            (&raw mut (*routing).AddressLow)
                .write_unaligned((&raw const (*request).AddressLow).read_unaligned());
            (&raw mut (*routing).Data)
                .write_unaligned(u32::from((&raw const (*request).Data).read_unaligned()));
        } else {
            (&raw mut (*routing).Type).write_unaligned(HAL_ROUTING_REQUEST);
            (&raw mut (*routing).AddressLow).write_unaligned(mode);
        }
    }
    STATUS_SUCCESS
}

/// `HalGetMemoryCachingRequirements`: the caching (a
/// `MEMORY_CACHING_TYPE`) that firmware requires of mappings of the
/// physical range. Windows keeps a table of the ranges firmware
/// described so; NK takes no such description from firmware, and
/// answers as Windows does for a range in no entry of an empty table:
/// the type is set to zero and the status is `STATUS_UNSUCCESSFUL`.
/// Without somewhere to put the type: `STATUS_INVALID_PARAMETER`.
///
/// # Safety
/// `caching` is null or writable.
pub unsafe extern "C" fn HalGetMemoryCachingRequirements(
    _address: u64,
    _length: usize,
    caching: *mut u32,
) -> NTSTATUS {
    if caching.is_null() {
        return STATUS_INVALID_PARAMETER;
    }
    // SAFETY: per the contract.
    unsafe { caching.write_unaligned(0) };
    STATUS_UNSUCCESSFUL
}

/// The queries answer for this machine: every processor has an
/// identifier of its own and a processor there is not has none; a
/// device vector's IRQL is the one its translation gave; a message to
/// one processor or to all is routed as it stands and any other target
/// is refused; no range has a caching requirement.
pub fn test() -> Result<(), &'static str> {
    let processors = smp::online_count() as u32;
    // SAFETY: every pointer is to a local.
    unsafe {
        let mut seen = [0u32; platform::MAX_CPUS];
        for number in 0..processors {
            let mut id = u32::MAX;
            if HalGetProcessorIdByNtNumber(number, &raw mut id) != STATUS_SUCCESS {
                return Err("a processor has no identifier");
            }
            if u64::from(id) != platform::get().cpus()[number as usize].hw_id
                || seen[..number as usize].contains(&id)
            {
                return Err("a processor's identifier is not its own");
            }
            seen[number as usize] = id;
        }
        let mut id = 0x5A5A;
        if HalGetProcessorIdByNtNumber(processors, &raw mut id) != STATUS_INVALID_PARAMETER
            || id != 0x5A5A
        {
            return Err("a processor there is not has an identifier");
        }

        let mut request = core::mem::zeroed::<HAL_MESSAGE_ROUTING_REQUEST>();
        request.Target.Mask = 1 << (processors - 1);
        request.DestinationMode = nk_hal::interrupt::DESTINATION_PHYSICAL;
        request.AddressHigh = 0x1234_5678;
        request.AddressLow = 0xFEE0_1000;
        request.Data = 0x4142;
        let mut routing = [0xA5A5_A5A5u32; 0x60 / 4];
        let answer = (&raw mut routing).cast::<HAL_MESSAGE_ROUTING>();
        if HalGetMessageRoutingInfo(&raw const request, answer) != STATUS_SUCCESS {
            return Err("a message for one processor was not routed");
        }
        let written = [
            (0, 1),
            (2, HAL_ROUTING_MESSAGE),
            (20, 0xFEE0_1000),
            (21, 0x1234_5678),
            (22, 0x4142),
        ];
        for (word, value) in routing.iter().enumerate() {
            let expected = written
                .iter()
                .find(|(at, _)| *at == word)
                .map_or(0xA5A5_A5A5, |(_, value)| *value);
            if *value != expected {
                return Err("a routed message is not its own address and data, and nothing else");
            }
        }
        request.Kind = nk_ntabi::interrupt::HAL_MESSAGE_KIND_REQUEST;
        request.Target.Mask = smp::online() as usize;
        if HalGetMessageRoutingInfo(&raw const request, answer) != STATUS_SUCCESS
            || (routing[2], routing[20]) != (HAL_ROUTING_REQUEST, 1)
        {
            return Err("a request for every processor was not answered with its mode");
        }
        let before = routing;
        request.DestinationMode = 2;
        let logical = HalGetMessageRoutingInfo(&raw const request, answer);
        request.DestinationMode = 1;
        request.Target.Mask = 1usize.checked_shl(processors).unwrap_or(0);
        let absent = HalGetMessageRoutingInfo(&raw const request, answer);
        if (logical, absent) != (STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER)
            || routing != before
        {
            return Err("a message that cannot be routed was not refused untouched");
        }

        let mut caching = 7u32;
        if HalGetMemoryCachingRequirements(0x1000, 0x1000, &raw mut caching) != STATUS_UNSUCCESSFUL
            || caching != 0
            || HalGetMemoryCachingRequirements(0x1000, 0x1000, core::ptr::null_mut())
                != STATUS_INVALID_PARAMETER
        {
            return Err("a range was given a caching requirement, or none was not said");
        }
    }
    Ok(())
}
