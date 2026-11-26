//! Silos, as far as a driver's own structures go.
//!
//! A silo is an opaque pointer to drivers (`PESILO`), and the host
//! silo is the null one. What a driver fills in itself is the
//! registration of a silo monitor.

use core::ffi::c_void;

/// `SILO_MONITOR_REGISTRATION_VERSION`.
pub const SILO_MONITOR_REGISTRATION_VERSION: u8 = 1;

/// [`SILO_MONITOR_REGISTRATION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_silo_monitor_registration):
/// what a driver hands `PsRegisterSiloMonitor`. The callbacks are the
/// driver's: `NTSTATUS CreateCallback(PESILO)` and
/// `VOID TerminateCallback(PESILO)`.
#[repr(C)]
pub struct SILO_MONITOR_REGISTRATION {
    pub Version: u8,
    pub MonitorHost: u8,
    pub MonitorExistingSilos: u8,
    pub Reserved: [u8; 5],
    /// `ComponentName`, or `DriverObjectName`: a union of two pointers
    /// to a counted string.
    pub ComponentName: *const crate::io::UNICODE_STRING,
    pub CreateCallback: *mut c_void,
    pub TerminateCallback: *mut c_void,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<SILO_MONITOR_REGISTRATION>() == 0x20);
    assert!(offset_of!(SILO_MONITOR_REGISTRATION, MonitorHost) == 1);
    assert!(offset_of!(SILO_MONITOR_REGISTRATION, MonitorExistingSilos) == 2);
    assert!(offset_of!(SILO_MONITOR_REGISTRATION, ComponentName) == 8);
    assert!(offset_of!(SILO_MONITOR_REGISTRATION, CreateCallback) == 0x10);
    assert!(offset_of!(SILO_MONITOR_REGISTRATION, TerminateCallback) == 0x18);
};

/// What a thread's `ETHREAD.Silo` holds while the thread is attached
/// to no silo and so uses its process's: -3. It is what
/// `PsAttachSiloToCurrentThread` first returns, for the detach to put
/// back.
pub const THREAD_NOT_ATTACHED: usize = -3isize as usize;
