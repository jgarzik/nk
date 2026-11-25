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

/// The index of the processor running this code, read from where the
/// WDK's inlined `KeGetCurrentProcessorIndex()` reads it.
pub fn current_processor() -> u32 {
    // SAFETY: as in `current_thread`; the field is an aligned `u32`.
    unsafe { arch::pcr().add(PCR.number).cast::<u32>().read() }
}

/// Check the PCR fields a driver reads in line: self pointer, PRCB,
/// thread, processor number.
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
    if current_processor() != 0 {
        return Err("the boot processor is not processor 0");
    }
    // Code built with older headers reads the number as one byte.
    // SAFETY: as in `current_thread`.
    if PCR.legacy_number.map(|at| unsafe { pcr.add(at).read() }) > Some(0) {
        return Err("the one-byte processor number is not 0");
    }
    Ok(())
}
