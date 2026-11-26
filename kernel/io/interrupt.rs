//! Connecting a driver to its device's interrupts:
//! [`IoConnectInterruptEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioconnectinterruptex)
//! and its undoing.
//!
//! A fully specified connection names a vector and IRQL: those of a
//! translated interrupt resource the driver was started with. The other
//! two kinds name only the device, and the kernel finds the device's
//! interrupts itself. It finds them here: the Plug and Play manager
//! tells this module which translated interrupts a physical device
//! object has ([`assign`]) when it gives the device its resources, and
//! takes them back ([`withdraw`]) when the device stops.
//!
//! NK's choices where Microsoft documents none:
//! - a line-based connection is to the device's first line; a device
//!   with no line gets `STATUS_NOT_FOUND`;
//! - a `SynchronizeIrql` of zero means the interrupt's own IRQL (for
//!   messages, the highest of them);
//! - `CONNECT_MESSAGE_BASED_PASSIVE` is not offered: an unsupported
//!   version is answered with `CONNECT_FULLY_SPECIFIED_GROUP` as the
//!   highest supported.

#![allow(non_snake_case)]

use crate::hal::interrupt::{self as routing, Polarity, Translated, Trigger};
use crate::ke::kinterrupt::{self, Connection, Routine};
use crate::ke::{Rank, SpinLock, irql};
use crate::mm::pool;
use alloc::vec::Vec;
use core::ffi::c_void;
use nk_ntabi::interrupt::*;
use nk_ntabi::interrupt::{INTERRUPT_CONNECTION_CONTROLLER_INPUT, INTERRUPT_VECTOR_DATA};
use nk_ntabi::io::DEVICE_OBJECT;
use nk_ntabi::ke::{KIRQL, KSPIN_LOCK};
use nk_ntabi::pnp::DEVPROPKEY;
use nk_ntabi::status::{
    NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_NOT_FOUND,
    STATUS_NOT_SUPPORTED, STATUS_SUCCESS,
};
use nk_pnp::connection::{CONNECTION_DATA_CATEGORY, CONNECTION_DATA_NUMBER};

const TAG: u32 = u32::from_le_bytes(*b"IntM");

/// One translated interrupt of a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resource {
    pub translated: Translated,
    /// A message-signalled interrupt (`CM_RESOURCE_INTERRUPT_MESSAGE`):
    /// `translated` is then one message's vector.
    pub message: bool,
    /// Whether the device shares the interrupt with others
    /// (`CmResourceShareShared`).
    pub shared: bool,
}

/// The interrupts of each device that has been given any, by the
/// address of its physical device object.
static DEVICES: SpinLock<Vec<(usize, Vec<Resource>)>> =
    SpinLock::new(Rank::DeviceInterrupts, Vec::new());

/// Record the translated interrupts of the device `device`, replacing
/// any recorded before. Called by the Plug and Play manager when it
/// gives a device its resources. `false` if there is no memory.
pub fn assign(device: *mut DEVICE_OBJECT, resources: &[Resource]) -> bool {
    let mut own = Vec::new();
    if own.try_reserve_exact(resources.len()).is_err() {
        return false;
    }
    own.extend_from_slice(resources);
    let mut devices = DEVICES.lock();
    devices.retain(|(d, _)| *d != device as usize);
    if devices.try_reserve(1).is_err() {
        return false;
    }
    devices.push((device as usize, own));
    true
}

/// Forget the interrupts of `device`: it has stopped.
pub fn withdraw(device: *mut DEVICE_OBJECT) {
    let mut devices = DEVICES.lock();
    devices.retain(|(d, _)| *d != device as usize);
    if devices.is_empty() {
        // Give the list's own storage back too.
        *devices = Vec::new();
    }
}

/// The interrupts of `device` that are messages, or that are lines.
fn of(device: *mut DEVICE_OBJECT, messages: bool) -> Vec<Resource> {
    let devices = DEVICES.lock();
    devices
        .iter()
        .find(|(d, _)| *d == device as usize)
        .map(|(_, resources)| {
            resources
                .iter()
                .filter(|r| r.message == messages)
                .copied()
                .collect()
        })
        .unwrap_or_default()
}

/// Connect a line: the vector's own trigger and polarity.
///
/// # Safety
/// As [`kinterrupt::connect`].
#[allow(clippy::too_many_arguments, reason = "a connection is this many facts")]
unsafe fn connect_line(
    device: *mut DEVICE_OBJECT,
    vector: u32,
    irql: KIRQL,
    synchronize_irql: KIRQL,
    trigger: Option<Trigger>,
    share: bool,
    routine: Option<KSERVICE_ROUTINE>,
    context: *mut c_void,
    lock: *mut KSPIN_LOCK,
    floating_save: u8,
) -> Result<*mut KINTERRUPT, NTSTATUS> {
    let info = routing::info(vector).ok_or(STATUS_INVALID_PARAMETER)?;
    let routine = routine.ok_or(STATUS_INVALID_PARAMETER)?;
    let line = info.line;
    // A message is edge triggered; a line is as its resource says.
    let (trigger_of_vector, polarity) =
        line.map_or((Trigger::Edge, Polarity::High), |l| (l.trigger, l.polarity));
    // SAFETY: per the contract.
    unsafe {
        kinterrupt::connect(&Connection {
            vector,
            irql,
            synchronize_irql: if synchronize_irql == 0 {
                irql
            } else {
                synchronize_irql
            },
            trigger: trigger.unwrap_or(trigger_of_vector),
            polarity,
            share,
            routine: Routine::Line(routine),
            context,
            lock,
            floating_save: floating_save != 0,
            device,
        })
    }
}

/// Connect every message of a device and build its table.
///
/// # Safety
/// As [`kinterrupt::connect`].
unsafe fn connect_messages(
    parameters: *const IO_CONNECT_INTERRUPT_MESSAGE_BASED_PARAMETERS,
    messages: &[Resource],
) -> Result<*mut IO_INTERRUPT_MESSAGE_INFO, NTSTATUS> {
    // SAFETY: per the contract; the parameters are the caller's.
    unsafe {
        let routine = (*parameters)
            .MessageServiceRoutine
            .ok_or(STATUS_INVALID_PARAMETER)?;
        let unified = messages
            .iter()
            .map(|m| m.translated.level)
            .max()
            .unwrap_or(0);
        let synchronize = match (*parameters).SynchronizeIrql {
            0 => unified,
            asked if asked >= unified => asked,
            _ => return Err(STATUS_INVALID_PARAMETER),
        };
        let size = core::mem::offset_of!(IO_INTERRUPT_MESSAGE_INFO, MessageInfo)
            + messages.len() * size_of::<IO_INTERRUPT_MESSAGE_INFO_ENTRY>();
        let table = pool::alloc_zeroed(size, TAG).cast::<IO_INTERRUPT_MESSAGE_INFO>();
        if table.is_null() {
            return Err(STATUS_INSUFFICIENT_RESOURCES);
        }
        (*table).UnifiedIrql = synchronize;
        let entries = (&raw mut (*table).MessageInfo).cast::<IO_INTERRUPT_MESSAGE_INFO_ENTRY>();
        for (index, resource) in messages.iter().enumerate() {
            let Translated {
                level,
                vector,
                affinity,
            } = resource.translated;
            let connected = match routing::message(vector) {
                Some(message) => kinterrupt::connect(&Connection {
                    vector,
                    irql: level,
                    synchronize_irql: synchronize,
                    trigger: Trigger::Edge,
                    polarity: Polarity::High,
                    share: resource.shared,
                    routine: Routine::Message(routine, index as u32),
                    context: (*parameters).ServiceContext,
                    lock: (*parameters).SpinLock,
                    floating_save: (*parameters).FloatingSave != 0,
                    device: (*parameters).PhysicalDeviceObject,
                })
                .map(|interrupt| (interrupt, message)),
                None => Err(STATUS_INVALID_PARAMETER),
            };
            match connected {
                Ok((interrupt, message)) => {
                    entries.add(index).write(IO_INTERRUPT_MESSAGE_INFO_ENTRY {
                        MessageAddress: message.address as i64,
                        TargetProcessorSet: affinity as usize,
                        InterruptObject: interrupt,
                        MessageData: message.data,
                        Vector: vector,
                        Irql: level,
                        Mode: Trigger::Edge.mode(),
                        Polarity: Polarity::High.value(),
                    });
                    (*table).MessageCount = index as u32 + 1;
                }
                Err(status) => {
                    disconnect_messages(table);
                    return Err(status);
                }
            }
        }
        Ok(table)
    }
}

/// Disconnect every message of a table and free it.
///
/// # Safety
/// `table` came from [`connect_messages`].
unsafe fn disconnect_messages(table: *mut IO_INTERRUPT_MESSAGE_INFO) {
    // SAFETY: per the contract.
    unsafe {
        for interrupt in objects_of_table(table) {
            kinterrupt::disconnect(interrupt);
        }
        if pool::free(table.cast()).is_err() {
            crate::kd::bugcheck(format_args!(
                "IoDisconnectInterruptEx: {table:p} is not a message table"
            ));
        }
    }
}

/// The interrupt objects of a message table.
///
/// # Safety
/// `table` is a live table from [`connect_messages`].
unsafe fn objects_of_table(table: *mut IO_INTERRUPT_MESSAGE_INFO) -> Vec<*mut KINTERRUPT> {
    // SAFETY: per the contract.
    unsafe {
        let entries = (&raw mut (*table).MessageInfo).cast::<IO_INTERRUPT_MESSAGE_INFO_ENTRY>();
        (0..(*table).MessageCount as usize)
            .map(|i| (&raw const (*entries.add(i)).InterruptObject).read())
            .collect()
    }
}

/// The first line in the interrupt connection data a driver stored on
/// the device (`INTERRUPT_CONNECTION_DATA_PKEY`, which is where
/// Windows' line-based connection looks): its vector and IRQL.
///
/// # Safety
/// `device` is readable for two bytes, and a live physical device
/// object if those are a device object's type.
unsafe fn stated_line(device: *mut DEVICE_OBJECT) -> Option<(u32, KIRQL)> {
    // SAFETY: per the contract.
    if unsafe { (&raw const (*device).Type).read_unaligned() } != nk_ntabi::io::IO_TYPE_DEVICE {
        return None;
    }
    const HEADER: usize = 8;
    const ENTRIES: usize = 4;
    let key = DEVPROPKEY {
        fmtid: CONNECTION_DATA_CATEGORY,
        pid: CONNECTION_DATA_NUMBER,
    };
    let mut data = [0u8; HEADER + ENTRIES * size_of::<INTERRUPT_VECTOR_DATA>()];
    let mut length = 0u32;
    // SAFETY: per the contract; locals for the key, the value and its
    // length.
    let status = unsafe {
        crate::pnp::export::IoGetDevicePropertyData(
            device,
            &raw const key,
            0,
            0,
            data.len() as u32,
            data.as_mut_ptr(),
            &raw mut length,
            core::ptr::null_mut(),
        )
    };
    if status != STATUS_SUCCESS {
        return None;
    }
    stated_line_in(&data[..length.min(data.len() as u32) as usize])
}

/// The first line an interrupt connection data value names that is
/// placed now: its vector and IRQL. A value left from before the
/// device's interrupts were withdrawn names a vector no line has any
/// more, and states nothing.
pub fn stated_line_in(data: &[u8]) -> Option<(u32, KIRQL)> {
    const HEADER: usize = 8;
    let count = u32::from_le_bytes(*data.first_chunk::<4>()?) as usize;
    let entries = data
        .get(HEADER..)?
        .as_chunks::<{ size_of::<INTERRUPT_VECTOR_DATA>() }>()
        .0
        .iter()
        .take(count);
    for entry in entries {
        // SAFETY: a chunk of the structure's size, of plain integers.
        let entry = unsafe {
            entry
                .as_ptr()
                .cast::<INTERRUPT_VECTOR_DATA>()
                .read_unaligned()
        };
        let placed = routing::info(entry.Vector)
            .is_some_and(|info| info.line.is_some() && info.level == entry.Irql);
        if entry.Type == INTERRUPT_CONNECTION_CONTROLLER_INPUT && placed {
            return Some((entry.Vector, entry.Irql));
        }
    }
    None
}

/// Connect the device's first line for a line-based connection.
///
/// # Safety
/// As [`kinterrupt::connect`].
unsafe fn connect_first_line(
    device: *mut DEVICE_OBJECT,
    routine: Option<KSERVICE_ROUTINE>,
    context: *mut c_void,
    lock: *mut KSPIN_LOCK,
    synchronize_irql: KIRQL,
    floating_save: u8,
) -> Result<*mut KINTERRUPT, NTSTATUS> {
    let (vector, level, shared) = match of(device, false).first() {
        // Where the line is now: the interrupt arbiter may have moved
        // it since it was translated (`hal::interrupt::assign_line`).
        Some(line) => {
            let (vector, level) = routing::placed(line.translated.vector).map_or(
                (line.translated.vector, line.translated.level),
                |(vector, info)| (vector, info.level),
            );
            (vector, level, line.shared)
        }
        // A device given no line as a resource may still have one its
        // driver stated: `acpi.sys` connects its system control
        // interrupt so.
        None => {
            // SAFETY: per the contract, the device is live.
            let (vector, level) = unsafe { stated_line(device) }.ok_or(STATUS_NOT_FOUND)?;
            (vector, level, true)
        }
    };
    // SAFETY: per the contract.
    unsafe {
        connect_line(
            device,
            vector,
            level,
            synchronize_irql,
            None,
            shared,
            routine,
            context,
            lock,
            floating_save,
        )
    }
}

/// `IoConnectInterruptEx`: connect service routines to a device's
/// interrupts. At `PASSIVE_LEVEL`.
///
/// # Safety
/// `parameters` points to the caller's
/// `IO_CONNECT_INTERRUPT_PARAMETERS`, whose pointers are valid.
pub unsafe extern "C" fn IoConnectInterruptEx(
    parameters: *mut IO_CONNECT_INTERRUPT_PARAMETERS,
) -> NTSTATUS {
    irql::expect_passive("IoConnectInterruptEx");
    // SAFETY: per the contract; the union is read as the member the
    // version selects.
    unsafe {
        let union = parameters.byte_add(IO_CONNECT_INTERRUPT_PARAMETERS::UNION);
        let result = match (*parameters).Version {
            version @ (CONNECT_FULLY_SPECIFIED | CONNECT_FULLY_SPECIFIED_GROUP) => {
                let p = union.cast::<IO_CONNECT_INTERRUPT_FULLY_SPECIFIED_PARAMETERS>();
                let group_ok = version == CONNECT_FULLY_SPECIFIED || (*p).Group == 0;
                let trigger = Trigger::from_mode((*p).InterruptMode);
                if (*p).ProcessorEnableMask == 0 || !group_ok || trigger.is_none() {
                    Err(STATUS_INVALID_PARAMETER)
                } else {
                    connect_line(
                        (*p).PhysicalDeviceObject,
                        (*p).Vector,
                        (*p).Irql,
                        (*p).SynchronizeIrql,
                        trigger,
                        (*p).ShareVector != 0,
                        (*p).ServiceRoutine,
                        (*p).ServiceContext,
                        (*p).SpinLock,
                        (*p).FloatingSave,
                    )
                    .map(|interrupt| (*p).InterruptObject.write(interrupt))
                }
            }
            CONNECT_LINE_BASED => {
                let p = union.cast::<IO_CONNECT_INTERRUPT_LINE_BASED_PARAMETERS>();
                connect_first_line(
                    (*p).PhysicalDeviceObject,
                    (*p).ServiceRoutine,
                    (*p).ServiceContext,
                    (*p).SpinLock,
                    (*p).SynchronizeIrql,
                    (*p).FloatingSave,
                )
                .map(|interrupt| (*p).InterruptObject.write(interrupt))
            }
            CONNECT_MESSAGE_BASED => {
                let p = union.cast::<IO_CONNECT_INTERRUPT_MESSAGE_BASED_PARAMETERS>();
                let messages = of((*p).PhysicalDeviceObject, true);
                if messages.is_empty() {
                    // No messages: the device's line, with the routine
                    // given for that case, and the caller is told.
                    connect_first_line(
                        (*p).PhysicalDeviceObject,
                        (*p).FallBackServiceRoutine,
                        (*p).ServiceContext,
                        (*p).SpinLock,
                        (*p).SynchronizeIrql,
                        (*p).FloatingSave,
                    )
                    .map(|interrupt| {
                        (*p).ConnectionContext.write(interrupt.cast());
                        (*parameters).Version = CONNECT_LINE_BASED;
                    })
                } else {
                    connect_messages(p, &messages)
                        .map(|table| (*p).ConnectionContext.write(table.cast()))
                }
            }
            _ => {
                (*parameters).Version = CONNECT_FULLY_SPECIFIED_GROUP;
                Err(STATUS_NOT_SUPPORTED)
            }
        };
        match result {
            Ok(()) => STATUS_SUCCESS,
            Err(status) => status,
        }
    }
}

/// The interrupt objects a connection context names, by the version it
/// was connected as, and the message table if it is one.
///
/// # Safety
/// `parameters` points to parameters naming a live connection.
unsafe fn connection(
    parameters: *const IO_DISCONNECT_INTERRUPT_PARAMETERS,
) -> Option<(Vec<*mut KINTERRUPT>, Option<*mut IO_INTERRUPT_MESSAGE_INFO>)> {
    // SAFETY: per the contract.
    unsafe {
        let context = (*parameters).ConnectionContext;
        match (*parameters).Version {
            CONNECT_FULLY_SPECIFIED | CONNECT_FULLY_SPECIFIED_GROUP | CONNECT_LINE_BASED => {
                Some((alloc::vec![context.cast()], None))
            }
            CONNECT_MESSAGE_BASED => Some((objects_of_table(context.cast()), Some(context.cast()))),
            _ => None,
        }
    }
}

/// [`IoDisconnectInterruptEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iodisconnectinterruptex):
/// disconnect what `IoConnectInterruptEx` connected, named by the
/// version it reported and the context it returned. When this returns,
/// no service routine of the connection is running or will run.
///
/// # Safety
/// `parameters` names a live connection, not used afterwards.
pub unsafe extern "C" fn IoDisconnectInterruptEx(
    parameters: *mut IO_DISCONNECT_INTERRUPT_PARAMETERS,
) {
    irql::expect_passive("IoDisconnectInterruptEx");
    // SAFETY: per the contract.
    unsafe {
        match connection(parameters) {
            Some((_, Some(table))) => disconnect_messages(table),
            Some((objects, None)) => {
                for interrupt in objects {
                    kinterrupt::disconnect(interrupt);
                }
            }
            None => crate::kd::bugcheck(format_args!(
                "IoDisconnectInterruptEx: version {} names no connection",
                (*parameters).Version
            )),
        }
    }
}

/// [`IoReportInterruptInactive`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioreportinterruptinactive):
/// the connection's service routines are not to be called until it is
/// reported active again. The interrupt objects stay; a vector left
/// with no active object is held back at its controller.
///
/// # Safety
/// `parameters` names a live connection.
pub unsafe extern "C" fn IoReportInterruptInactive(
    parameters: *mut IO_REPORT_INTERRUPT_ACTIVE_STATE_PARAMETERS,
) {
    // SAFETY: per the contract.
    unsafe {
        if let Some((objects, _)) = connection(parameters) {
            for interrupt in objects {
                kinterrupt::deactivate(interrupt);
            }
        }
    }
}

/// [`IoReportInterruptActive`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioreportinterruptactive):
/// undo `IoReportInterruptInactive`.
///
/// # Safety
/// `parameters` names a live connection.
pub unsafe extern "C" fn IoReportInterruptActive(
    parameters: *mut IO_REPORT_INTERRUPT_ACTIVE_STATE_PARAMETERS,
) {
    // SAFETY: per the contract.
    unsafe {
        if let Some((objects, _)) = connection(parameters) {
            for interrupt in objects {
                // An object that was sharing its vector shares it still.
                let _ = kinterrupt::activate(interrupt);
            }
        }
    }
}
