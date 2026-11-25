//! The processor control region, as drivers see it.

use crate::arch;
use nk_ntabi::pcr::NATIVE as PCR;

/// The current thread object, found the way a driver's inlined
/// `KeGetCurrentThread()` finds it.
pub fn current_thread() -> *mut u8 {
    // SAFETY: the PCR is initialised by `arch::cpu_init` and the field is
    // an aligned pointer-sized slot inside it.
    unsafe { arch::pcr().add(PCR.current_thread).cast::<*mut u8>().read() }
}

/// Check the PCR links a driver follows: self pointer, PRCB, thread.
pub fn self_test() -> Result<(), &'static str> {
    let pcr = arch::pcr();
    if pcr.is_null() || !(pcr as usize).is_multiple_of(4096) {
        return Err("PCR self pointer is null or unaligned");
    }
    // SAFETY: as in `current_thread`.
    let prcb = unsafe { pcr.add(PCR.current_prcb).cast::<*mut u8>().read() };
    if prcb != pcr.wrapping_add(PCR.prcb) {
        return Err("KPCR.CurrentPrcb does not point at the embedded PRCB");
    }
    if current_thread().is_null() {
        return Err("current thread is null");
    }
    Ok(())
}
