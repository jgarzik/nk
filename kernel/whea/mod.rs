//! Hardware errors (WHEA): the sources of them that drivers register.
//!
//! A source is a descriptor in a pool block of its own, which drivers
//! are handed and may read, and an entry in the table here, which is
//! NK's and says what state the source is really in. An error a source
//! reports becomes an error record, whose summary goes to the boot log;
//! a fatal one stops the system. The rules and the numbers are
//! `nk_whea`'s; `doc/DESIGN.md` ("Hardware errors") says what NK does.

#![allow(non_snake_case)]

use crate::ke::seh::{self, Guard};
use crate::ke::{Rank, SpinLock, bugcheck, time, wait};
use crate::mm::pool;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};
use nk_ntabi::ex::GUID;
use nk_ntabi::io::KERNEL_MODE;
use nk_ntabi::status::{
    NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
    STATUS_SUCCESS, nt_success,
};
use nk_ntabi::whea::{
    WHEA_ERR_SEV_FATAL, WHEA_ERR_SRC_STATE_REMOVED, WHEA_ERR_SRC_STATE_STARTED,
    WHEA_ERR_SRC_TYPE_DEVICE_DRIVER, WHEA_ERROR_PACKET_V2, WHEA_ERROR_RECORD_HEADER,
    WHEA_ERROR_SOURCE_CONFIGURATION, WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER,
    WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1, WHEA_ERROR_SOURCE_DESCRIPTOR,
    WHEA_EVENT_LOG_ENTRY_HEADER,
};
use nk_whea::{Configurations, Packet, Report, Retire, Routines, Table};

/// The pool tag of a source's descriptor: Windows' tag for a source.
const TAG_SOURCE: u32 = u32::from_le_bytes(*b"Whea");
/// The pool tag of a device driver source's report packets.
const TAG_PACKETS: u32 = u32::from_le_bytes(*b"WHEA");
/// The bytes of the kernel's state for one report packet.
const PACKET_STATE: usize = 0x68;

/// The sources, the descriptors of removed ones, and the routines
/// configured for each kind of source.
struct Sources {
    table: Table,
    configurations: Configurations,
    /// Descriptors of sources since removed. They stay allocated, as on
    /// Windows: `WheaGetErrorSource` gave their addresses out.
    kept: usize,
}

static SOURCES: SpinLock<Sources> = SpinLock::new(
    Rank::Whea,
    Sources {
        table: Table::new(),
        configurations: Configurations::new(),
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
/// with `context`, and start it. `packets` are the report packets and
/// their states the kernel allocated for it, null for none: the only
/// ones removal frees, whatever the descriptor names. The status, and the source's
/// descriptor block, which is null unless the source is in the table,
/// started.
///
/// A source whose `Initialize` fails is in no state anything can reach
/// it in, on Windows as here; NK frees it. Its id stays used.
///
/// A device driver's source is started by the `Initialize` in its
/// descriptor; a source of any other kind by the routines configured
/// for its kind (`WheaConfigureErrorSource`), which may be none.
fn add(
    descriptor: &WHEA_ERROR_SOURCE_DESCRIPTOR,
    context: usize,
    packets: [*mut u8; 2],
) -> (NTSTATUS, *mut WHEA_ERROR_SOURCE_DESCRIPTOR) {
    let none = core::ptr::null_mut();
    let kind = descriptor.Type;
    if !nk_whea::is_non_hest(kind) {
        return (STATUS_NOT_SUPPORTED, none);
    }
    if kind > WHEA_ERR_SRC_TYPE_DEVICE_DRIVER {
        return (STATUS_INVALID_PARAMETER, none);
    }
    let block = pool::alloc(size_of::<WHEA_ERROR_SOURCE_DESCRIPTOR>(), TAG_SOURCE)
        .cast::<WHEA_ERROR_SOURCE_DESCRIPTOR>();
    if block.is_null() {
        return (STATUS_INSUFFICIENT_RESOURCES, none);
    }
    let Some(id) = SOURCES.lock().table.insert(
        kind,
        context,
        block.expose_provenance(),
        packets.map(|p| p.expose_provenance()),
    ) else {
        let _ = pool::free(block.cast());
        return (STATUS_INSUFFICIENT_RESOURCES, none);
    };
    // SAFETY: the block just allocated, of a descriptor's size.
    unsafe {
        block.write_unaligned(*descriptor);
        (&raw mut (*block).ErrorSourceId).write_unaligned(id);
        set_state(id, block, WHEA_ERR_SRC_STATE_STARTED);
    }
    let routines = SOURCES.lock().configurations.routines(kind);
    let (initialize, arguments) = if kind == WHEA_ERR_SRC_TYPE_DEVICE_DRIVER {
        // SAFETY: the member a device driver's descriptor has.
        let initialize = unsafe { descriptor.Info.DeviceDriverDescriptor.Config.Initialize };
        // `Initialize(Context, ErrorSourceId)`.
        (initialize.addr(), [context, id as usize, 0, 0])
    } else {
        if routines.correct != 0 {
            let mut section_length = 0u32;
            // SAFETY: the kind's `Correct(Descriptor, SectionLength)`,
            // a driver's. Windows goes on whatever it answers, and so
            // does NK, which keeps no records of the length it gives.
            unsafe {
                seh::call(
                    routines.correct,
                    [block.addr(), (&raw mut section_length).addr(), 0, 0],
                    &Guard::Nothing,
                );
            }
        }
        // `Initialize(Phase, Descriptor, Context)`, in phase 1.
        (routines.initialize, [1, block.addr(), context, 0])
    };
    let status = if initialize != 0 && SOURCES.lock().table.enter(id) {
        let guard = Guard::Undo {
            undo: leave,
            context: core::ptr::without_provenance_mut(id as usize),
        };
        // SAFETY: the source's `Initialize`, a driver's, called as
        // Windows calls it: at the IRQL of the caller, which registers
        // at PASSIVE_LEVEL, with no lock held.
        let status = unsafe { seh::call(initialize, arguments, &guard) } as NTSTATUS;
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
    let (status, block) = add(&descriptor, context, [buffer, states]);
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
/// its address. The packets the kernel allocated for a device driver's
/// source are freed and the descriptor names none; packets named by a
/// descriptor a driver brought to `WheaAddErrorSource` are the
/// driver's and are left alone, as Windows' routine leaves them.
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
    let configured = SOURCES.lock().configurations.routines(source.kind);
    // SAFETY: the source's descriptor. `Uninitialize(Context)` is a
    // driver's, called once, at the caller's IRQL, with no lock held:
    // a device driver's is in its descriptor, another kind's is the
    // one configured for the kind.
    unsafe {
        if source.kind == WHEA_ERR_SRC_TYPE_DEVICE_DRIVER {
            let driver = &raw mut (*block).Info.DeviceDriverDescriptor;
            let uninitialize = (&raw const (*driver).Config.Uninitialize).read_unaligned();
            if !uninitialize.is_null() {
                seh::call(
                    uninitialize.addr(),
                    [source.context, 0, 0, 0],
                    &Guard::Nothing,
                );
            }
            // The packets the kernel allocated are freed and the
            // descriptor names none; packets a caller's descriptor
            // brought are the caller's, and stay.
            let [buffer, states]: [*mut u8; 2] =
                source.packets.map(core::ptr::with_exposed_provenance_mut);
            if !buffer.is_null() {
                free_packets(buffer, states);
                (&raw mut (*driver).PacketBuffer).write_unaligned(core::ptr::null_mut());
                (&raw mut (*driver).PacketStateBuffer).write_unaligned(core::ptr::null_mut());
            }
        } else if configured.uninitialize != 0 {
            seh::call(
                configured.uninitialize,
                [source.context, 0, 0, 0],
                &Guard::Nothing,
            );
        }
        (&raw mut (*block).State).write_unaligned(WHEA_ERR_SRC_STATE_REMOVED);
    }
    let mut sources = SOURCES.lock();
    sources.table.forget(id);
    sources.kept += 1;
    drop(sources);
    kprintln!("whea: error source {id} removed");
}

/// [`WheaAddErrorSource`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-wheaadderrorsource):
/// add the source `descriptor` describes and start it: its kind's
/// `Correct` and `Initialize` are called, where the kind is configured
/// with them, and the status of `Initialize` is this routine's.
///
/// | Refusal | Status |
/// | --- | --- |
/// | a kind the firmware's tables describe (machine check, NMI, boot and the like) | `STATUS_NOT_SUPPORTED` |
/// | a kind past the device driver's | `STATUS_INVALID_PARAMETER` |
/// | no memory | `STATUS_INSUFFICIENT_RESOURCES` |
///
/// # Safety
/// `descriptor` points to a descriptor.
pub unsafe extern "C" fn WheaAddErrorSource(
    descriptor: *const WHEA_ERROR_SOURCE_DESCRIPTOR,
    context: *mut c_void,
) -> NTSTATUS {
    // SAFETY: per the contract; a copy, since the driver may write it.
    let descriptor = unsafe { descriptor.read_unaligned() };
    // The descriptor's packets, if it names any, are the caller's.
    add(&descriptor, context.addr(), [core::ptr::null_mut(); 2]).0
}

/// [`WheaConfigureErrorSource`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-wheaconfigureerrorsource):
/// give the routines of sources of one kind. NK calls `Correct`,
/// `Initialize` and `Uninitialize`; a report from such a source would
/// need `CreateRecord` and `Recover`, and stops the system
/// (`WheaReportHwError`).
///
/// | Refusal | Status |
/// | --- | --- |
/// | a kind past the device driver's | `STATUS_INVALID_PARAMETER` |
/// | a kind configured already | `STATUS_UNSUCCESSFUL` |
///
/// # Safety
/// `configuration` points to a configuration.
pub unsafe extern "C" fn WheaConfigureErrorSource(
    kind: u32,
    configuration: *const WHEA_ERROR_SOURCE_CONFIGURATION,
) -> NTSTATUS {
    // SAFETY: per the contract; a copy, since the driver may write it.
    let given = unsafe { configuration.read_unaligned() };
    let routines = Routines {
        correct: given.Correct.addr(),
        initialize: given.Initialize.addr(),
        uninitialize: given.Uninitialize.addr(),
    };
    SOURCES.lock().configurations.configure(kind, routines)
}

/// [`WheaUnconfigureErrorSource`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-wheaunconfigureerrorsource):
/// forget the routines of sources of one kind. As Windows' routine
/// does, it answers `STATUS_UNSUCCESSFUL` when it has done so, and
/// `STATUS_INVALID_PARAMETER` for a kind past the device driver's.
pub extern "C" fn WheaUnconfigureErrorSource(kind: u32) -> NTSTATUS {
    SOURCES.lock().configurations.unconfigure(kind)
}

/// The id of the last error record made. Windows starts from the
/// system time at boot; so does NK, at the first record.
static RECORD_ID: AtomicU64 = AtomicU64::new(0);

/// The id of the next error record.
fn next_record_id() -> u64 {
    let _ = RECORD_ID.compare_exchange(0, time::boot_time(), Ordering::Relaxed, Ordering::Relaxed);
    RECORD_ID.fetch_add(1, Ordering::Relaxed) + 1
}

/// [`WheaInitializeRecordHeader`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-wheainitializerecordheader):
/// write the header of a new error record: no section yet,
/// informational, made now, with the next record id.
///
/// # Safety
/// `header` points to room for a record header.
pub unsafe extern "C" fn WheaInitializeRecordHeader(
    header: *mut WHEA_ERROR_RECORD_HEADER,
) -> NTSTATUS {
    let fresh = nk_whea::record_header(time::system_time(), next_record_id());
    // SAFETY: per the contract.
    unsafe { header.write_unaligned(fresh) };
    STATUS_SUCCESS
}

/// [`WheaLogInternalEvent`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-whealoginternalevent):
/// log an event of the error machinery itself. Windows writes it to
/// its event log; NK's log is the boot log, where the entry's summary
/// goes.
///
/// # Safety
/// `entry` points to an event log entry.
pub unsafe extern "C" fn WheaLogInternalEvent(entry: *const WHEA_EVENT_LOG_ENTRY_HEADER) {
    // SAFETY: per the contract; a copy of the header alone.
    let event = unsafe { entry.read_unaligned() };
    let (id, kind, owner, payload) = (event.Id, event.Type, event.Owner, event.PayloadLength);
    let owner = owner.to_le_bytes();
    kprintln!(
        "whea: event {id:#x} of type {kind} from {}: {payload} bytes of payload",
        core::str::from_utf8(&owner).unwrap_or("?")
    );
}

/// A device driver's report, as the two report routines take it.
struct DriverReport {
    id: u32,
    data: *const u8,
    data_length: u32,
    log_length: u32,
    section_type: *const GUID,
    severity: u32,
    device_name: *const u8,
    /// A fatal report's last argument, the fourth parameter of the
    /// stop; none for a report that is not fatal.
    fatal: Option<usize>,
}

/// Make the error record of a device driver's report and log its
/// summary; stop the system for a fatal one.
///
/// # Safety
/// `data` is readable for `data_length` bytes, `section_type` points to
/// a GUID, and `device_name` is null or NUL-terminated.
unsafe fn report_device_driver(report: &DriverReport) -> NTSTATUS {
    let Some(source) = SOURCES
        .lock()
        .table
        .started(report.id)
        .filter(|s| s.kind == WHEA_ERR_SRC_TYPE_DEVICE_DRIVER)
    else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    if report.log_length > nk_whea::MAX_LOG_DATA {
        // Windows' routine copies the log data to nowhere then.
        bugcheck::KeBugCheckEx(0x50, 0, 1, 0, 0);
    }
    let block: *const WHEA_ERROR_SOURCE_DESCRIPTOR =
        core::ptr::with_exposed_provenance(source.descriptor);
    // SAFETY: the descriptor of a started source; copies of what it
    // holds, since drivers may write it.
    let (driver, max_raw) = unsafe {
        (
            (&raw const (*block).Info.DeviceDriverDescriptor).read_unaligned(),
            (&raw const (*block).MaxRawDataLength).read_unaligned(),
        )
    };
    if !nk_whea::device_driver_report_fits(&driver, max_raw, report.data_length, report.log_length)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    // SAFETY: per the contract.
    let (data, section_type) = unsafe {
        (
            core::slice::from_raw_parts(report.data, report.data_length as usize),
            report.section_type.read_unaligned(),
        )
    };
    let mut name = [0u8; 19];
    let mut name_length = 0;
    if !report.device_name.is_null() {
        // SAFETY: per the contract, up to the terminator.
        for c in unsafe { crate::rtl::print::characters(report.device_name) }.take(name.len()) {
            name[name_length] = c as u8;
            name_length += 1;
        }
    }
    let record_id = next_record_id();
    let Some(record) = nk_whea::device_driver_record(&Report {
        driver: &driver,
        severity: report.severity,
        section_type,
        device_name: &name[..name_length],
        data,
        system_time: time::system_time(),
        record_id,
    }) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    kprintln!(
        "whea: hardware error from source {}: severity {}, record {record_id:#x} of {} bytes, section {:08x}-{:04x}-{:04x}, device {:?}",
        report.id,
        report.severity,
        record.len(),
        section_type.Data1,
        section_type.Data2,
        section_type.Data3,
        core::str::from_utf8(&name[..name_length]).unwrap_or("?")
    );
    if let Some(context) = report.fatal {
        // WHEA_UNCORRECTABLE_ERROR, as Windows stops for a fatal
        // device driver report: the source's type, the record, the
        // source's GUID, the driver's own word. The record is never
        // freed: it is the stop's second parameter.
        let record = record.leak();
        // SAFETY: the descriptor, which is never freed.
        let guid = unsafe { &raw const (*block).Info.DeviceDriverDescriptor.SourceGuid };
        bugcheck::KeBugCheckEx(
            0x124,
            WHEA_ERR_SRC_TYPE_DEVICE_DRIVER as usize,
            record.as_ptr().addr(),
            guid.addr(),
            context,
        );
    }
    STATUS_SUCCESS
}

/// `WheaReportHwErrorDeviceDriverEx` (the
/// [`WheaReportHwErrorDeviceDriver`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-wheareporthwerrordevicedriver)
/// of later headers, with log data): report an error of the device
/// driver source `id`. The record is made (`nk_whea`) and its summary
/// logged; the log data is not kept.
///
/// | Refusal | Status |
/// | --- | --- |
/// | no such started source; more data than the source registered for; no memory | `STATUS_INSUFFICIENT_RESOURCES` |
///
/// More than 0x24 bytes of log data stop the system, as the page fault
/// in Windows' routine does.
///
/// # Safety
/// `data` is readable for `data_length` bytes, `section_type` points to
/// a GUID, and `device_name` is null or NUL-terminated.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn WheaReportHwErrorDeviceDriverEx(
    id: u32,
    _device: *const c_void,
    data: *const u8,
    data_length: u32,
    _log_data: *const u8,
    log_length: u32,
    section_type: *const GUID,
    _reserved: usize,
    severity: u32,
    device_name: *const u8,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        report_device_driver(&DriverReport {
            id,
            data,
            data_length,
            log_length,
            section_type,
            severity,
            device_name,
            fatal: None,
        })
    }
}

/// `WheaReportFatalHwErrorDeviceDriverEx` (undocumented): report a
/// fatal error of the device driver source `id`. The record is made
/// and its summary logged, and the system stops with
/// `WHEA_UNCORRECTABLE_ERROR` (0x124): parameter 1 the source's type
/// (16), 2 the record, 3 the source's GUID, 4 `context`. It returns
/// only with one of the refusals of `WheaReportHwErrorDeviceDriverEx`.
///
/// # Safety
/// As `WheaReportHwErrorDeviceDriverEx`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn WheaReportFatalHwErrorDeviceDriverEx(
    id: u32,
    _device: *const c_void,
    data: *const u8,
    data_length: u32,
    _log_data: *const u8,
    log_length: u32,
    section_type: *const GUID,
    _reserved: usize,
    device_name: *const u8,
    _reserved2: usize,
    context: usize,
) -> NTSTATUS {
    // SAFETY: per the contract.
    unsafe {
        report_device_driver(&DriverReport {
            id,
            data,
            data_length,
            log_length,
            section_type,
            severity: WHEA_ERR_SEV_FATAL,
            device_name,
            fatal: Some(context),
        })
    }
}

/// [`WheaReportHwError`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-wheareporthwerror):
/// report the error in `packet`. What Windows decides before it makes
/// a record, NK decides the same (`nk_whea::packet`): a malformed
/// severity is refused, an informational report dropped, and a report
/// from no started source stops the system (`WHEA_INTERNAL_ERROR`) or
/// is `STATUS_DEVICE_DOES_NOT_EXIST`.
///
/// A record for a started source is made by the `CreateRecord` routine
/// of its kind, which NK does not call: such a report stops the system
/// naming the kind. Device drivers report through
/// `WheaReportHwErrorDeviceDriverEx`.
///
/// # Safety
/// `packet` points to an error packet.
pub unsafe extern "C" fn WheaReportHwError(packet: *const WHEA_ERROR_PACKET_V2) -> NTSTATUS {
    // SAFETY: per the contract; a copy of the head alone.
    let head = unsafe { packet.read_unaligned() };
    let (id, kind) = (head.ErrorSourceId, head.ErrorSourceType);
    let source = SOURCES.lock().table.started(id);
    match nk_whea::packet(head.ErrorSeverity, head.Flags, source.is_some()) {
        Packet::Status(status) => status,
        Packet::NoSourceStop => {
            bugcheck::KeBugCheckEx(0x122, 9, kind as i32 as usize, id as usize, 0)
        }
        Packet::Record { severity } => crate::kd::bugcheck(format_args!(
            "WheaReportHwError: NK does not implement reports from error sources of type {} \
             (source {id}, severity {severity})",
            source.map_or(kind, |s| s.kind)
        )),
    }
}
