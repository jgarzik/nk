//! Platform services below the kernel proper: firmware runtime calls and
//! the description of the machine.

pub mod acpi;
pub mod bus;
pub mod description;
pub mod dispatch;
pub mod dma;
pub mod fatal;
pub mod interrupt;
pub mod pci;
pub mod platform;
pub mod pm;
pub mod query;
pub mod sysinfo;
pub mod target;
pub mod variables;

use crate::arch;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU64, Ordering};
use nk_bootinfo::BootInfo;

/// Physical address of the UEFI runtime services table, or 0.
static EFI_RUNTIME: AtomicU64 = AtomicU64::new(0);

/// Offset of `ResetSystem` in `EFI_RUNTIME_SERVICES`: a 24-byte header,
/// then ten function pointers before it.
const RESET_SYSTEM: u64 = 24 + 10 * 8;
const RESET_SHUTDOWN: u32 = 2;

type ResetSystem = unsafe extern "efiapi" fn(u32, usize, usize, *const c_void) -> !;

pub fn init(info: &BootInfo) {
    EFI_RUNTIME.store(info.efi_runtime, Ordering::Relaxed);
    acpi::init();
    sysinfo::init();
}

/// Run `call`, which calls into firmware's runtime code. Every such call
/// is made through here, from any processor and any context, the path
/// that stops the system included.
///
/// Runtime code runs at its physical addresses, on the caller's stack.
/// The architecture makes the address space what that needs before the
/// call and puts it back after one that returns.
fn firmware_call<R>(call: impl FnOnce() -> R) -> R {
    arch::firmware_enter();
    let result = call();
    arch::firmware_leave();
    result
}

/// Power the machine off through UEFI runtime services; halt if firmware
/// offers none.
pub fn power_off_or_halt() -> ! {
    let table = EFI_RUNTIME.load(Ordering::Relaxed);
    if table != 0 {
        firmware_call(|| {
            // SAFETY: `table` is firmware's runtime services table,
            // identity mapped and valid for the life of the system; the
            // slot holds ResetSystem, which takes no pointers for a
            // shutdown.
            unsafe {
                let reset = ((table + RESET_SYSTEM) as *const ResetSystem).read();
                reset(RESET_SHUTDOWN, 0, 0, core::ptr::null())
            }
        })
    }
    crate::kd::halt()
}
