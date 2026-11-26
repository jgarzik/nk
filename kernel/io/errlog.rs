//! The error log: how a driver reports what went wrong with a device
//! ([`IoAllocateErrorLogEntry`], [`IoWriteErrorLogEntry`]).
//!
//! On Windows a written packet goes to the event-log service. NK has
//! none: writing a packet prints one line to the boot log, naming the
//! driver, the device and the error, and frees the packet. The line is
//! there for bringing a driver up: it says what a Microsoft driver
//! complained about.
//!
//! A packet is allocated as the pinned kernel allocates it: behind a
//! header of the I/O manager's (`ERROR_LOG_ENTRY`), within Windows'
//! size limits, counted against Windows' limit on the bytes of packets
//! outstanding, and holding a reference on its device and its driver
//! object until it is written.

#![allow(non_snake_case)]

use crate::mm::pool;
use crate::{kd, ke, ob};
use alloc::string::String;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};
use nk_ntabi::io::*;

/// Pool tag of error-log packets, as Windows spells it.
const TAG: u32 = u32::from_le_bytes(*b"IoEr");

/// The bytes of the packets allocated and not yet written.
static OUTSTANDING: AtomicU32 = AtomicU32::new(0);

/// [`IoAllocateErrorLogEntry`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-ioallocateerrorlogentry):
/// a zeroed packet of `entry_size` bytes for `io_object`, a device or a
/// driver object. Null, as on Windows, for a size outside the limits
/// (`nk_ntabi::io::error_log_allocation`), for an object that is
/// neither, without memory, and while too many bytes of packets are
/// outstanding.
///
/// # Safety
/// `io_object` is null or a live device or driver object.
pub unsafe extern "C" fn IoAllocateErrorLogEntry(
    io_object: *mut c_void,
    entry_size: u8,
) -> *mut c_void {
    if io_object.is_null() {
        return core::ptr::null_mut();
    }
    // SAFETY: per the contract; both kinds of object begin with their
    // type, and a device names its driver.
    let (device, driver) = unsafe {
        match io_object.cast::<i16>().read() {
            IO_TYPE_DEVICE => {
                let device = io_object.cast::<DEVICE_OBJECT>();
                (device, (*device).DriverObject)
            }
            IO_TYPE_DRIVER => (core::ptr::null_mut(), io_object.cast::<DRIVER_OBJECT>()),
            _ => return core::ptr::null_mut(),
        }
    };
    let Some(total) = error_log_allocation(entry_size) else {
        return core::ptr::null_mut();
    };
    if OUTSTANDING.fetch_add(total as u32, Ordering::AcqRel) > ERROR_LOG_OUTSTANDING_LIMIT {
        OUTSTANDING.fetch_sub(total as u32, Ordering::AcqRel);
        return core::ptr::null_mut();
    }
    let entry = pool::alloc_zeroed(total, TAG).cast::<ERROR_LOG_ENTRY>();
    if entry.is_null() {
        OUTSTANDING.fetch_sub(total as u32, Ordering::AcqRel);
        return core::ptr::null_mut();
    }
    // SAFETY: a fresh zeroed block of `total` bytes; the objects are
    // live, and stay until the packet is written.
    unsafe {
        if !device.is_null() {
            ob::object::reference(device.cast());
        }
        if !driver.is_null() {
            ob::object::reference(driver.cast());
        }
        (*entry).Type = IO_TYPE_ERROR_LOG;
        (*entry).Size = total as i16;
        (*entry).DeviceObject = device;
        (*entry).DriverObject = driver;
        entry.add(1).cast()
    }
}

/// A counted string, as text for the log.
///
/// # Safety
/// `name` is a valid counted string, or one with no buffer.
unsafe fn text(name: UNICODE_STRING) -> String {
    if name.Buffer.is_null() {
        return String::new();
    }
    // SAFETY: per the contract.
    let units = unsafe { core::slice::from_raw_parts(name.Buffer, usize::from(name.Length) / 2) };
    char::decode_utf16(units.iter().copied())
        .map(|c| c.ok().filter(|c| c.is_ascii_graphic()).unwrap_or('?'))
        .collect()
}

/// [`IoWriteErrorLogEntry`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iowriteerrorlogentry):
/// the driver has filled the packet in. NK has no event log to queue it
/// to: it prints
/// `NK-ERRORLOG driver=<name> device=<name or address> code=<ErrorCode>
/// final=<FinalStatus> unique=<UniqueErrorValue> major=<MajorFunctionCode>
/// dump=<DumpDataSize>`,
/// lets go of the device and the driver object, and frees the packet.
///
/// # Safety
/// `packet` came from `IoAllocateErrorLogEntry` and has not been
/// written.
pub unsafe extern "C" fn IoWriteErrorLogEntry(packet: *mut c_void) {
    // SAFETY: per the contract; the header check turns a pointer that
    // is no packet into a named stop.
    unsafe {
        let entry = packet.cast::<ERROR_LOG_ENTRY>().sub(1);
        if (*entry).Type != IO_TYPE_ERROR_LOG {
            kd::bugcheck(format_args!(
                "IoWriteErrorLogEntry: {packet:p} is not an error-log packet"
            ));
        }
        // Stamped as Windows stamps it, though nothing reads it later.
        (*entry).TimeStamp = ke::time::system_time() as i64;
        let (device, driver) = ((*entry).DeviceObject, (*entry).DriverObject);
        let packet = packet.cast::<IO_ERROR_LOG_PACKET>();
        let driver_name = if driver.is_null() {
            String::new()
        } else {
            text((*driver).DriverName)
        };
        let info = if device.is_null() {
            core::ptr::null_mut()
        } else {
            ob::object::name_info(device.cast())
        };
        // A device with no name is known by its address.
        let device_name = if info.is_null() {
            alloc::format!("{device:p}")
        } else {
            text((&raw const (*info).Name).read())
        };
        kprintln!(
            "NK-ERRORLOG driver={} device={device_name} code={:#010x} final={:#010x} \
             unique={:#x} major={:#x} dump={}",
            if driver_name.is_empty() {
                "?"
            } else {
                &driver_name
            },
            (*packet).ErrorCode as u32,
            (*packet).FinalStatus as u32,
            (*packet).UniqueErrorValue,
            (*packet).MajorFunctionCode,
            (*packet).DumpDataSize,
        );
        let total = (*entry).Size as u32;
        (*entry).Type = 0;
        if !device.is_null() {
            ob::object::dereference(device.cast());
        }
        if !driver.is_null() {
            ob::object::dereference(driver.cast());
        }
        if let Err(e) = pool::free(entry.cast()) {
            kd::bugcheck(format_args!("freeing error-log packet {packet:p}: {e:?}"));
        }
        OUTSTANDING.fetch_sub(total, Ordering::AcqRel);
    }
}
