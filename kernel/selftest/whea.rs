//! Hardware error sources, through the routines drivers import.

use crate::test::{Group, Report};
use crate::whea;
use core::ffi::c_void;
use core::sync::atomic::{AtomicI32, AtomicU32, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::ex::GUID;
use nk_ntabi::status::{
    NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_INVALID_PARAMETER_2, STATUS_SUCCESS,
    STATUS_UNSUCCESSFUL,
};
use nk_ntabi::whea::{
    WHEA_ERR_SRC_STATE_REMOVED, WHEA_ERR_SRC_STATE_STARTED, WHEA_ERR_SRC_TYPE_DEVICE_DRIVER,
    WHEA_ERROR_SOURCE_CONFIGURATION_DEVICE_DRIVER_V1,
};

pub static GROUP: Group = Group {
    names: &["whea.device-driver-source"],
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

fn run(r: &mut Report, _: &BootInfo) {
    r.check("whea.device-driver-source", device_driver_source);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
