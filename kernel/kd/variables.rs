//! What a driver can read about the kernel's start-up state: variables
//! Windows' kernel exports, which drivers read through the address
//! their import is bound to.

#![allow(non_upper_case_globals)]

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering};
use nk_bootinfo::{BootInfo, Serial};

/// A variable drivers import and read: `T` is an atomic, so that the
/// kernel can set it once the machine is known.
#[repr(transparent)]
pub struct Variable<T>(pub(crate) T);

impl<T> Variable<T> {
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// The address drivers import.
    pub const fn address(&'static self) -> *const () {
        (&raw const self.0).cast()
    }
}

/// [`KdDebuggerEnabled`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-kdrefreshdebuggernotpresent):
/// whether kernel debugging was turned on for this boot. NK speaks no
/// Windows debugger protocol: false.
pub static KdDebuggerEnabled: Variable<AtomicU8> = Variable(AtomicU8::new(0));

/// `KdDebuggerNotPresent`: true, since no Windows kernel debugger can
/// be attached.
pub static KdDebuggerNotPresent: Variable<AtomicU8> = Variable(AtomicU8::new(1));

/// `KdComPortInUse`: the I/O port address of the serial port the kernel
/// itself is using, or null. Windows names the debugger's port here so
/// that `acpi.sys` and `serial.sys` leave it alone; NK names its
/// console's, which it goes on writing whatever a driver does. A
/// console that is not at an I/O port is not named.
pub static KdComPortInUse: Variable<AtomicUsize> = Variable(AtomicUsize::new(0));

/// `KdHvComPortInUse`: whether a hypervisor's debugger owns a serial
/// port. None does.
pub static KdHvComPortInUse: Variable<AtomicU8> = Variable(AtomicU8::new(0));

/// [`InitSafeBootMode`](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/determining-whether-the-operating-system-is-running-in-safe-mode):
/// which safe mode the system started in. NK has none: 0.
pub static InitSafeBootMode: Variable<AtomicU32> = Variable(AtomicU32::new(0));

/// `Mm64BitPhysicalAddress`: whether physical addresses may exceed 32
/// bits. They may on both architectures NK runs on.
pub static Mm64BitPhysicalAddress: Variable<AtomicU8> = Variable(AtomicU8::new(1));

/// `NtBuildNumber`: free-build Windows 10 22H2 build 19045 (`0xF000_4A65`),
/// matching `RtlGetVersion`.
pub static NtBuildNumber: Variable<AtomicU32> = Variable(AtomicU32::new(0xF000_0000 | 19045));

/// Record what the loader said of the console.
pub fn init(info: &BootInfo) {
    if info.serial.kind == Serial::PORT_16550 {
        KdComPortInUse
            .0
            .store(info.serial.base as usize, Ordering::Relaxed);
    }
}

/// For the self-tests: what a driver reads through each import.
pub fn variables_test(info: &BootInfo) -> Result<(), &'static str> {
    let import = |name: &[u8]| crate::export::resolve(b"ntoskrnl.exe", name);
    // SAFETY: each import is bound to a variable of the size read.
    let byte = |name: &[u8]| import(name).map(|at| unsafe { (at as *const u8).read() });
    if byte(b"KdDebuggerEnabled") != Some(0)
        || byte(b"KdDebuggerNotPresent") != Some(1)
        || byte(b"KdHvComPortInUse") != Some(0)
        || byte(b"Mm64BitPhysicalAddress") != Some(1)
    {
        return Err("a flag a driver imports does not read as NK's state");
    }
    // SAFETY: as above, a 32-bit and a pointer-sized variable.
    let (safe, port) = unsafe {
        (
            import(b"InitSafeBootMode").map(|at| (at as *const u32).read()),
            import(b"KdComPortInUse").map(|at| (at as *const usize).read()),
        )
    };
    let console = if info.serial.kind == Serial::PORT_16550 {
        info.serial.base as usize
    } else {
        0
    };
    if safe != Some(0) || port != Some(console) {
        return Err("the safe-boot mode or the console's port is not what a driver reads");
    }
    Ok(())
}
