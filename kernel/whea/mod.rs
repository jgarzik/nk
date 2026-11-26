//! Hardware errors (WHEA): the sources of them that drivers register.
//!
//! A source is a descriptor in a pool block of its own, which drivers
//! are handed and may read, and an entry in the table here, which is
//! NK's and says what state the source is really in. The rules and the
//! numbers are `nk_whea`'s; `doc/DESIGN.md` ("Hardware errors") says
//! what NK does with a source.

#![allow(non_snake_case)]

use crate::ke::seh::{self, Guard};
use crate::ke::{Rank, SpinLock, wait};
use crate::mm::pool;
use core::ffi::c_void;
use nk_ntabi::io::KERNEL_MODE;
use nk_ntabi::status::{
    NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS, nt_success,
};
use nk_ntabi::whea::{
    WHEA_ERR_SRC_STATE_REMOVED, WHEA_ERR_SRC_STATE_STARTED, WHEA_ERR_SRC_TYPE_DEVICE_DRIVER,
    WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER,
    WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1, WHEA_ERROR_SOURCE_DESCRIPTOR,
};
use nk_whea::{Retire, Table};

/// The pool tag of a source's descriptor: Windows' tag for a source.
const TAG_SOURCE: u32 = u32::from_le_bytes(*b"Whea");
/// The pool tag of a device driver source's report packets.
const TAG_PACKETS: u32 = u32::from_le_bytes(*b"WHEA");
/// The bytes of the kernel's state for one report packet.
const PACKET_STATE: usize = 0x68;

/// The sources, and the descriptors of removed ones.
struct Sources {
    table: Table,
    /// Descriptors of sources since removed. They stay allocated, as on
    /// Windows: `WheaGetErrorSource` gave their addresses out.
    kept: usize,
}

static SOURCES: SpinLock<Sources> = SpinLock::new(
    Rank::Whea,
    Sources {
        table: Table::new(),
        kept: 0,
    },
);

/// The pool memory held for good, as `(blocks, bytes)`: the table, and
/// the descriptors of removed sources. A leak check must not count it
/// as lost.
pub fn storage() -> (usize, usize) {
    let sources = SOURCES.lock();
    let table = sources.table.storage();
    (
        sources.kept + usize::from(table != 0),
        sources.kept * size_of::<WHEA_ERROR_SOURCE_DESCRIPTOR>() + table,
    )
}

/// The `Correct` of a device driver source's descriptor: the bytes of a
/// section of its records.
///
/// # Safety
/// `descriptor` points to a descriptor; `section_length` to a `u32`.
unsafe extern "C" fn correct_device_driver(
    descriptor: *const WHEA_ERROR_SOURCE_DESCRIPTOR,
    section_length: *mut u32,
) -> NTSTATUS {
    // SAFETY: per the contract; both are unaligned-safe accesses.
    unsafe {
        let raw = (&raw const (*descriptor).MaxRawDataLength).read_unaligned();
        section_length.write_unaligned(nk_whea::device_driver_section_length(raw));
    }
    STATUS_SUCCESS
}

/// End the call into source `id` that an exception unwinds.
///
/// # Safety
/// `id` is the id of a source entered and not yet left.
unsafe fn leave(id: *mut c_void) {
    SOURCES.lock().table.leave(id.addr() as u32);
}

/// Set the state of source `id` at `block`: NK's, and the copy in the
/// descriptor that drivers read.
///
/// # Safety
/// `block` is the source's descriptor.
unsafe fn set_state(id: u32, block: *mut WHEA_ERROR_SOURCE_DESCRIPTOR, state: u32) {
    SOURCES.lock().table.set_state(id, state);
    // SAFETY: per the contract.
    unsafe { (&raw mut (*block).State).write_unaligned(state) };
}

/// Add the source `descriptor` describes, whose routines are called
/// with `context`, and start it. The status, and the source's
/// descriptor block, which is null unless the source is in the table,
/// started.
///
/// A source whose `Initialize` fails is in no state anything can reach
/// it in, on Windows as here; NK frees it. Its id stays used.
///
/// Only a device driver's source is added: the other kinds are started
/// by routines NK does not have.
fn add(
    descriptor: &WHEA_ERROR_SOURCE_DESCRIPTOR,
    context: usize,
) -> (NTSTATUS, *mut WHEA_ERROR_SOURCE_DESCRIPTOR) {
    let none = core::ptr::null_mut();
    let kind = descriptor.Type;
    if !nk_whea::is_non_hest(kind) {
        return (STATUS_NOT_SUPPORTED, none);
    }
    if kind > WHEA_ERR_SRC_TYPE_DEVICE_DRIVER {
        return (STATUS_INVALID_PARAMETER, none);
    }
    if kind != WHEA_ERR_SRC_TYPE_DEVICE_DRIVER {
        crate::kd::bugcheck(format_args!(
            "WheaAddErrorSource: NK does not implement error sources of type {kind}"
        ));
    }
    let block = pool::alloc(size_of::<WHEA_ERROR_SOURCE_DESCRIPTOR>(), TAG_SOURCE)
        .cast::<WHEA_ERROR_SOURCE_DESCRIPTOR>();
    if block.is_null() {
        return (STATUS_INSUFFICIENT_RESOURCES, none);
    }
    let Some(id) = SOURCES
        .lock()
        .table
        .insert(kind, context, block.expose_provenance())
    else {
        let _ = pool::free(block.cast());
        return (STATUS_INSUFFICIENT_RESOURCES, none);
    };
    // SAFETY: the block just allocated, of a descriptor's size.
    unsafe {
        block.write_unaligned(*descriptor);
        (&raw mut (*block).ErrorSourceId).write_unaligned(id);
        set_state(id, block, WHEA_ERR_SRC_STATE_STARTED);
    }
    // SAFETY: the member a device driver's descriptor has.
    let initialize = unsafe { descriptor.Info.DeviceDriverDescriptor.Config.Initialize };
    let status = if SOURCES.lock().table.enter(id) {
        let guard = Guard::Undo {
            undo: leave,
            context: core::ptr::without_provenance_mut(id as usize),
        };
        // SAFETY: the driver's `Initialize(Context, ErrorSourceId)`,
        // called as Windows calls it: at the IRQL of the caller, which
        // registers at PASSIVE_LEVEL, with no lock held.
        let status = unsafe { seh::call(initialize.addr(), [context, id as usize, 0, 0], &guard) }
            as NTSTATUS;
        SOURCES.lock().table.leave(id);
        status
    } else {
        STATUS_SUCCESS
    };
    kprintln!("whea: error source {id} of type {kind} added: status {status:#x}");
    if nt_success(status) {
        (status, block)
    } else {
        SOURCES.lock().table.forget(id);
        let _ = pool::free(block.cast());
        (status, none)
    }
}

/// Register a device driver as a source with a version 2
/// configuration: Windows' `WheaAddErrorSourceDeviceDriver`.
fn add_device_driver(
    context: usize,
    config: &WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER,
    buffers: u32,
) -> NTSTATUS {
    let correct = correct_device_driver as *mut c_void;
    let (mut descriptor, packets) =
        match nk_whea::device_driver_descriptor(config, buffers, correct) {
            Ok(built) => built,
            Err(status) => return status,
        };
    let (mut buffer, mut states) = (core::ptr::null_mut(), core::ptr::null_mut());
    if let Some(packets) = packets {
        let Some(bytes) = (packets.length as usize).checked_mul(packets.count as usize) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        let Some(state_bytes) = PACKET_STATE.checked_mul(packets.count as usize) else {
            return STATUS_INSUFFICIENT_RESOURCES;
        };
        buffer = pool::alloc_zeroed(bytes, TAG_PACKETS);
        states = pool::alloc_zeroed(state_bytes, TAG_PACKETS);
        if buffer.is_null() || states.is_null() {
            free_packets(buffer, states);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        descriptor.Info.DeviceDriverDescriptor.PacketBuffer = buffer;
        descriptor.Info.DeviceDriverDescriptor.PacketStateBuffer = states;
    }
    let (status, block) = add(&descriptor, context);
    if block.is_null() {
        free_packets(buffer, states);
    }
    status
}

/// Free a device driver source's packets and their states, either of
/// which may be null.
fn free_packets(buffer: *mut u8, states: *mut u8) {
    for block in [buffer, states] {
        if !block.is_null() {
            let _ = pool::free(block);
        }
    }
}

/// [`WheaAddErrorSourceDeviceDriverV1`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-wheaadderrorsourcedevicedriverv1):
/// register the calling driver as a source of hardware errors, with
/// `num_buffers` reports of at most `max_data_length` bytes
/// preallocated. The driver's `Initialize` is called with the source's
/// id before this returns, and its status is this routine's.
///
/// | Refusal | Status |
/// | --- | --- |
/// | a configuration whose version is not 1 | `STATUS_INVALID_PARAMETER_2` |
/// | no `Initialize`, or no `Uninitialize` | `STATUS_INVALID_PARAMETER` |
/// | no memory | `STATUS_INSUFFICIENT_RESOURCES` |
///
/// # Safety
/// `config` points to a version 1 configuration.
pub unsafe extern "C" fn WheaAddErrorSourceDeviceDriverV1(
    context: *mut c_void,
    config: *const WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1,
    num_buffers: u32,
    max_data_length: u32,
) -> NTSTATUS {
    // SAFETY: per the contract; a copy, since the driver may write it.
    let v1 = unsafe { config.read_unaligned() };
    match nk_whea::v2_of_v1(&v1, max_data_length) {
        Ok(v2) => add_device_driver(context.addr(), &v2, num_buffers),
        Err(status) => status,
    }
}

/// [`WheaGetErrorSource`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-wheageterrorsource):
/// the descriptor of the started source `id`, or null.
pub extern "C" fn WheaGetErrorSource(id: u32) -> *mut WHEA_ERROR_SOURCE_DESCRIPTOR {
    let found = SOURCES.lock().table.started(id);
    found.map_or(core::ptr::null_mut(), |source| {
        core::ptr::with_exposed_provenance_mut(source.descriptor)
    })
}

/// [`WheaRemoveErrorSource`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-whearemoveerrorsource):
/// remove the started source `id`: wait for calls into it to end, call
/// its `Uninitialize`, and leave it removed. Nothing happens for an id
/// that names no started source.
///
/// The descriptor stays allocated, as on Windows, for whoever was given
/// its address; a device driver source's packets are freed and the
/// descriptor names none.
pub extern "C" fn WheaRemoveErrorSource(id: u32) {
    let Some(source) = SOURCES.lock().table.begin_remove(id) else {
        return;
    };
    let block: *mut WHEA_ERROR_SOURCE_DESCRIPTOR =
        core::ptr::with_exposed_provenance_mut(source.descriptor);
    // SAFETY: the source's descriptor, which is never freed.
    unsafe {
        (&raw mut (*block).State)
            .write_unaligned(nk_ntabi::whea::WHEA_ERR_SRC_STATE_REMOVE_PENDING);
    }
    while SOURCES.lock().table.retire(id) == Retire::Busy {
        // Windows' interval: 100 microseconds.
        let interval = -1000i64;
        // SAFETY: a relative interval in a local.
        unsafe { wait::KeDelayExecutionThread(KERNEL_MODE, 0, &raw const interval) };
    }
    // SAFETY: the descriptor of a device driver's source, the only kind
    // in the table; `Uninitialize(Context)` is the driver's, called
    // once, at the caller's IRQL, with no lock held.
    unsafe {
        let driver = &raw mut (*block).Info.DeviceDriverDescriptor;
        let uninitialize = (&raw const (*driver).Config.Uninitialize).read_unaligned();
        if !uninitialize.is_null() {
            seh::call(
                uninitialize.addr(),
                [source.context, 0, 0, 0],
                &Guard::Nothing,
            );
        }
        free_packets(
            (&raw const (*driver).PacketBuffer).read_unaligned(),
            (&raw const (*driver).PacketStateBuffer).read_unaligned(),
        );
        (&raw mut (*driver).PacketBuffer).write_unaligned(core::ptr::null_mut());
        (&raw mut (*driver).PacketStateBuffer).write_unaligned(core::ptr::null_mut());
        (&raw mut (*block).State).write_unaligned(WHEA_ERR_SRC_STATE_REMOVED);
    }
    let mut sources = SOURCES.lock();
    sources.table.forget(id);
    sources.kept += 1;
    drop(sources);
    kprintln!("whea: error source {id} removed");
}
