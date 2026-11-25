//! Platform services below the kernel proper: firmware runtime calls and
//! the description of the machine.

pub mod platform;

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
}

/// Power the machine off through UEFI runtime services; halt if firmware
/// offers none. Runtime code is called at its physical address: nkload
/// keeps firmware's memory identity mapped for this.
pub fn power_off_or_halt() -> ! {
    let table = EFI_RUNTIME.load(Ordering::Relaxed);
    if table != 0 {
        // SAFETY: `table` is firmware's runtime services table, identity
        // mapped and valid for the life of the system; the slot holds
        // ResetSystem, which takes no pointers for a shutdown.
        unsafe {
            let reset = ((table + RESET_SYSTEM) as *const ResetSystem).read();
            reset(RESET_SHUTDOWN, 0, 0, core::ptr::null());
        }
    }
    crate::kd::halt()
}
