//! Hardware error sources, through the routines drivers import.

use crate::test::{Group, Report};
use crate::whea;
use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::ex::GUID;
use nk_ntabi::status::{
    NTSTATUS, STATUS_DEVICE_DOES_NOT_EXIST, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER_2, STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL,
};
use nk_ntabi::whea::{
    WHEA_ERR_SRC_STATE_REMOVED, WHEA_ERR_SRC_STATE_STARTED, WHEA_ERR_SRC_TYPE_DEVICE_DRIVER,
    WHEA_ERROR_PACKET_V2, WHEA_ERROR_RECORD_HEADER, WHEA_ERROR_SOURCE_CONFIGURATION,
    WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1, WHEA_ERROR_SOURCE_DESCRIPTOR,
    WHEA_EVENT_LOG_ENTRY_HEADER,
};

pub static GROUP: Group = Group {
    names: &[
        "whea.device-driver-source",
        "whea.report",
        "whea.configured-source",
    ],
    run,
    manual: false,
};

/// What the source's routines were last called with, and what
/// `Initialize` is to answer.
static INITIALIZED_WITH: AtomicUsize = AtomicUsize::new(0);
static INITIALIZED_ID: AtomicU32 = AtomicU32::new(u32::MAX);
static UNINITIALIZED_WITH: AtomicUsize = AtomicUsize::new(0);
static ANSWER: AtomicI32 = AtomicI32::new(STATUS_SUCCESS);

const NO_ID: u32 = u32::MAX;
const CONTEXT: usize = 0x4E4B_5748;

extern "C" fn initialize(context: *mut c_void, id: u32) -> NTSTATUS {
    INITIALIZED_WITH.store(context.addr(), Ordering::Relaxed);
    INITIALIZED_ID.store(id, Ordering::Relaxed);
    ANSWER.load(Ordering::Relaxed)
}

extern "C" fn uninitialize(context: *mut c_void) {
    UNINITIALIZED_WITH.store(context.addr(), Ordering::Relaxed);
}

fn config() -> WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1 {
    WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1 {
        Version: 1,
        SourceGuid: GUID {
            Data1: 0x4E4B_0001,
            Data2: 2,
            Data3: 3,
            Data4: [4; 8],
        },
        LogTag: u16::from_le_bytes(*b"NK"),
        Reserved: [0; 6],
        Initialize: initialize as *mut c_void,
        Uninitialize: uninitialize as *mut c_void,
    }
}

/// Register with `config`, as storport does: one report of 0x464
/// bytes.
fn add(config: &WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1) -> NTSTATUS {
    INITIALIZED_ID.store(NO_ID, Ordering::Relaxed);
    let context = core::ptr::without_provenance_mut(CONTEXT);
    // SAFETY: a version 1 configuration in a local.
    unsafe { whea::WheaAddErrorSourceDeviceDriverV1(context, config, 1, 0x464) }
}

fn device_driver_source() -> Result<(), &'static str> {
    // What Windows refuses, before anything is called.
    let mut bad = config();
    bad.Version = 2;
    if add(&bad) != STATUS_INVALID_PARAMETER_2 {
        return Err("a configuration of another version was not refused");
    }
    let mut bad = config();
    bad.Initialize = core::ptr::null_mut();
    if add(&bad) != STATUS_INVALID_PARAMETER {
        return Err("a configuration without Initialize was not refused");
    }
    let mut bad = config();
    bad.Uninitialize = core::ptr::null_mut();
    if add(&bad) != STATUS_INVALID_PARAMETER || INITIALIZED_ID.load(Ordering::Relaxed) != NO_ID {
        return Err("a configuration without Uninitialize was not refused");
    }

    // A source whose Initialize fails: its status is the answer, and
    // the id it was given names no source.
    ANSWER.store(STATUS_UNSUCCESSFUL, Ordering::Relaxed);
    if add(&config()) != STATUS_UNSUCCESSFUL {
        return Err("the status of a failed Initialize was not returned");
    }
    let failed = INITIALIZED_ID.load(Ordering::Relaxed);
    if failed == NO_ID || !whea::WheaGetErrorSource(failed).is_null() {
        return Err("a source whose Initialize failed is still found");
    }

    // A source that starts.
    ANSWER.store(STATUS_SUCCESS, Ordering::Relaxed);
    INITIALIZED_WITH.store(0, Ordering::Relaxed);
    if add(&config()) != STATUS_SUCCESS {
        return Err("a source was not added");
    }
    let id = INITIALIZED_ID.load(Ordering::Relaxed);
    if id != failed.wrapping_add(1) || INITIALIZED_WITH.load(Ordering::Relaxed) != CONTEXT {
        return Err("Initialize was not called with the context and the next id");
    }
    let descriptor = whea::WheaGetErrorSource(id);
    if descriptor.is_null() {
        return Err("a started source was not found by its id");
    }
    // SAFETY: the descriptor of a source that is never freed.
    let found = unsafe { descriptor.read_unaligned() };
    // SAFETY: the member of a device driver's descriptor.
    let driver = unsafe { found.Info.DeviceDriverDescriptor };
    if found.Length != 0x3CC
        || found.Type != WHEA_ERR_SRC_TYPE_DEVICE_DRIVER
        || found.State != WHEA_ERR_SRC_STATE_STARTED
        || found.ErrorSourceId != id
        || found.MaxSectionsPerRecord != 3
        || found.MaxRawDataLength != 3 * 0x464
        || driver.PacketCount != 1
        || driver.PacketLength != nk_whea::packet_length(3 * 0x464, 3)
        || driver.PacketBuffer.is_null()
        || driver.PacketStateBuffer.is_null()
        || driver.LogTag != u16::from_le_bytes(*b"NK")
    {
        return Err("the descriptor is not the one Windows builds");
    }

    // Removed: Uninitialize is called, and the id names nothing.
    whea::WheaRemoveErrorSource(id);
    if UNINITIALIZED_WITH.swap(0, Ordering::Relaxed) != CONTEXT {
        return Err("Uninitialize was not called with the context");
    }
    // SAFETY: as above: a removed source's descriptor stays.
    let state = unsafe { (&raw const (*descriptor).State).read_unaligned() };
    if !whea::WheaGetErrorSource(id).is_null() || state != WHEA_ERR_SRC_STATE_REMOVED {
        return Err("a removed source is still found");
    }
    // Removing it again, or a source that never was, does nothing.
    whea::WheaRemoveErrorSource(id);
    whea::WheaRemoveErrorSource(NO_ID);
    if UNINITIALIZED_WITH.load(Ordering::Relaxed) != 0 {
        return Err("Uninitialize was called for a source already removed");
    }
    Ok(())
}

const SECTION: GUID = GUID {
    Data1: 0x4E4B_0003,
    Data2: 2,
    Data3: 3,
    Data4: [4; 8],
};

/// Report `length` bytes of data from source `id`, as storport does:
/// no log data, severity 1.
fn report_error(id: u32, length: u32) -> NTSTATUS {
    let data = [0x5Au8; 0x500];
    let section = SECTION;
    // SAFETY: data at least as long as any length the test gives, a
    // GUID in a local, a terminated name.
    unsafe {
        whea::WheaReportHwErrorDeviceDriverEx(
            id,
            core::ptr::null(),
            data.as_ptr(),
            length,
            core::ptr::null(),
            0,
            &raw const section,
            0,
            1,
            c"NK test disk".as_ptr().cast(),
        )
    }
}

/// A packet for `WheaReportHwError` from source `id`.
fn packet(id: u32, severity: u32) -> WHEA_ERROR_PACKET_V2 {
    WHEA_ERROR_PACKET_V2 {
        Signature: u32::from_le_bytes(*b"WHEA"),
        Version: 3,
        Length: 0x50,
        Flags: 0,
        ErrorType: 6,
        ErrorSeverity: severity,
        ErrorSourceId: id,
        ErrorSourceType: 12,
        NotifyType: SECTION,
        Context: 0,
        DataFormat: 7,
        Reserved1: 0,
        DataOffset: 0x50,
        DataLength: 0,
        PshedDataOffset: 0,
        PshedDataLength: 0,
    }
}

fn report() -> Result<(), &'static str> {
    // A record header: the next id each time.
    // SAFETY: an all-zero header is a valid value of this plain data.
    let mut first: WHEA_ERROR_RECORD_HEADER = unsafe { core::mem::zeroed() };
    let mut second = first;
    // SAFETY: locals of a header's size.
    unsafe {
        if whea::WheaInitializeRecordHeader(&raw mut first) != STATUS_SUCCESS
            || whea::WheaInitializeRecordHeader(&raw mut second) != STATUS_SUCCESS
        {
            return Err("a record header was not written");
        }
    }
    if first.Signature != u32::from_le_bytes(*b"CPER")
        || first.Revision != 0x210
        || first.Severity != 3
        || first.ValidBits != 2
        || first.RecordId == 0
        || second.RecordId != first.RecordId + 1
    {
        return Err("a record header is not the one Windows writes");
    }

    ANSWER.store(STATUS_SUCCESS, Ordering::Relaxed);
    if add(&config()) != STATUS_SUCCESS {
        return Err("a source was not added");
    }
    let id = INITIALIZED_ID.load(Ordering::Relaxed);
    if report_error(id, 0x464) != STATUS_SUCCESS || report_error(id, 0) != STATUS_SUCCESS {
        return Err("an error within the source's limits was not reported");
    }
    if report_error(id, 0x465) != STATUS_INSUFFICIENT_RESOURCES
        || report_error(NO_ID, 4) != STATUS_INSUFFICIENT_RESOURCES
    {
        return Err("a report past the source's limits, or from no source, was not refused");
    }

    // Packets: decided before any record is made.
    let both_marks = packet(id, 0xC000_0001);
    let informational = packet(id, 3);
    let corrected_from_nowhere = packet(NO_ID, 2);
    // SAFETY: packets in locals.
    unsafe {
        if whea::WheaReportHwError(&raw const both_marks) != STATUS_INVALID_PARAMETER
            || whea::WheaReportHwError(&raw const informational) != STATUS_SUCCESS
            || whea::WheaReportHwError(&raw const corrected_from_nowhere)
                != STATUS_DEVICE_DOES_NOT_EXIST
        {
            return Err("a packet was not judged as Windows judges it");
        }
    }

    let event = WHEA_EVENT_LOG_ENTRY_HEADER {
        Signature: u32::from_le_bytes(*b"WhLg"),
        Version: 1,
        Length: 0x20,
        Type: 2,
        Owner: u32::from_le_bytes(*b"NKNK"),
        Id: 0x8000_0001,
        Flags: 2,
        PayloadLength: 0,
    };
    // SAFETY: an entry with no payload in a local.
    unsafe { whea::WheaLogInternalEvent(&raw const event) };

    whea::WheaRemoveErrorSource(id);
    if report_error(id, 4) != STATUS_INSUFFICIENT_RESOURCES {
        return Err("a removed source still reports");
    }
    Ok(())
}

/// A kind of source that is configured: generic, version 2.
const KIND: u32 = 12;

static CORRECTED: AtomicUsize = AtomicUsize::new(0);
static PHASE: AtomicU32 = AtomicU32::new(0);

extern "C" fn correct(descriptor: *mut c_void, section_length: *mut u32) -> NTSTATUS {
    CORRECTED.store(descriptor.addr(), Ordering::Relaxed);
    // SAFETY: the kernel passes room for the length.
    unsafe { section_length.write_unaligned(0x100) };
    STATUS_SUCCESS
}

extern "C" fn initialize_kind(
    phase: u32,
    descriptor: *const WHEA_ERROR_SOURCE_DESCRIPTOR,
    context: *mut c_void,
) -> NTSTATUS {
    PHASE.store(phase, Ordering::Relaxed);
    INITIALIZED_WITH.store(context.addr(), Ordering::Relaxed);
    // SAFETY: the kernel passes the source's descriptor.
    let id = unsafe { (&raw const (*descriptor).ErrorSourceId).read_unaligned() };
    INITIALIZED_ID.store(id, Ordering::Relaxed);
    ANSWER.load(Ordering::Relaxed)
}

fn configured_source() -> Result<(), &'static str> {
    let routines = WHEA_ERROR_SOURCE_CONFIGURATION {
        Flags: 0,
        Correct: correct as *mut c_void,
        Initialize: initialize_kind as *mut c_void,
        CreateRecord: core::ptr::null_mut(),
        Recover: core::ptr::null_mut(),
        Uninitialize: uninitialize as *mut c_void,
        Reserved: core::ptr::null_mut(),
    };
    // SAFETY: a configuration in a local.
    unsafe {
        if whea::WheaConfigureErrorSource(17, &raw const routines) != STATUS_INVALID_PARAMETER
            || whea::WheaConfigureErrorSource(KIND, &raw const routines) != STATUS_SUCCESS
            || whea::WheaConfigureErrorSource(KIND, &raw const routines) != STATUS_UNSUCCESSFUL
        {
            return Err("a kind of source was not configured once");
        }
    }
    // SAFETY: an all-zero descriptor is a valid value of this plain
    // data.
    let mut descriptor: WHEA_ERROR_SOURCE_DESCRIPTOR = unsafe { core::mem::zeroed() };
    descriptor.Length = 0x3CC;
    descriptor.Version = 11;
    let context = core::ptr::without_provenance_mut(CONTEXT);
    let mut add_kind = |kind: u32| {
        descriptor.Type = kind;
        INITIALIZED_ID.store(NO_ID, Ordering::Relaxed);
        // SAFETY: a descriptor in a local.
        unsafe { whea::WheaAddErrorSource(&raw const descriptor, context) }
    };
    // Kinds the firmware describes, and kinds past the table.
    if add_kind(0) != STATUS_NOT_SUPPORTED
        || add_kind(7) != STATUS_NOT_SUPPORTED
        || add_kind(17) != STATUS_INVALID_PARAMETER
        || INITIALIZED_ID.load(Ordering::Relaxed) != NO_ID
    {
        return Err("a source of a kind that cannot be added was not refused");
    }
    ANSWER.store(STATUS_SUCCESS, Ordering::Relaxed);
    if add_kind(KIND) != STATUS_SUCCESS {
        return Err("a source of a configured kind was not added");
    }
    let id = INITIALIZED_ID.load(Ordering::Relaxed);
    let found = whea::WheaGetErrorSource(id);
    if found.is_null()
        || CORRECTED.load(Ordering::Relaxed) != found.addr()
        || PHASE.load(Ordering::Relaxed) != 1
        || INITIALIZED_WITH.load(Ordering::Relaxed) != CONTEXT
    {
        return Err("the kind's Correct and Initialize were not called as Windows calls them");
    }
    whea::WheaRemoveErrorSource(id);
    if UNINITIALIZED_WITH.swap(0, Ordering::Relaxed) != CONTEXT {
        return Err("the kind's Uninitialize was not called with the context");
    }
    // Windows' routine reports failure even when it forgets the kind.
    if whea::WheaUnconfigureErrorSource(KIND) != STATUS_UNSUCCESSFUL
        || whea::WheaUnconfigureErrorSource(17) != STATUS_INVALID_PARAMETER
    {
        return Err("a kind was not unconfigured as Windows unconfigures one");
    }
    // Unconfigured, a source of the kind starts with nothing called.
    if add_kind(KIND) != STATUS_SUCCESS || INITIALIZED_ID.load(Ordering::Relaxed) != NO_ID {
        return Err("an unconfigured kind's source was not started without routines");
    }
    whea::WheaRemoveErrorSource(id + 1);
    if UNINITIALIZED_WITH.load(Ordering::Relaxed) != 0 {
        return Err("Uninitialize was called for an unconfigured kind");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("whea.device-driver-source", device_driver_source);
    r.check("whea.report", report);
    r.check("whea.configured-source", configured_source);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
