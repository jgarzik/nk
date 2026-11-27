//! What a machine that never hibernates and has nothing to shut down
//! in order answers.

use crate::ke::bugcheck::KeBugCheckEx;
use core::ffi::c_void;

/// `INTERNAL_POWER_ERROR`.
const INTERNAL_POWER_ERROR: u32 = 0xA0;

/// `PoSetHiberRange` (declared in the WDK's headers, not documented):
/// say which memory a hibernation file must hold, or need not. A
/// driver calls it from the routines Windows calls while it hibernates
/// the system, passing no memory map: the one of the hibernation in
/// progress is meant.
///
/// NK never hibernates, so no hibernation is in progress, and the
/// pinned kernel's answer to that is NK's: the system stops with
/// `INTERNAL_POWER_ERROR` (0x10B, 0xA). While the system is already
/// stopping the call does nothing, as on Windows. A memory map of the
/// caller's own can only be the pinned kernel's private one, which no
/// driver has: that stops the system too, saying so.
pub extern "C" fn PoSetHiberRange(
    memory_map: *mut c_void,
    _flags: u32,
    _address: *mut c_void,
    _length: usize,
    _tag: u32,
) {
    if crate::kd::stopping() {
        return;
    }
    if !memory_map.is_null() {
        crate::kd::bugcheck(format_args!(
            "PoSetHiberRange: called with a memory map ({memory_map:p}); NK has no hibernation \
             for one to belong to"
        ));
    }
    KeBugCheckEx(INTERNAL_POWER_ERROR, 0x10B, 0xA, 0, 0)
}

/// `PoShutdownBugCheck` (exported, not documented): stop the system with a bugcheck after
/// shutting it down in order. Windows asks for a critical shutdown
/// (`ZwInitiatePowerAction`), which flushes what the file systems hold,
/// and then calls `KeBugCheckEx` with the code and parameters given.
/// NK has nothing to flush: it stops with them at once.
pub extern "C" fn PoShutdownBugCheck(
    _allow_crash_dump: u8,
    code: u32,
    p1: usize,
    p2: usize,
    p3: usize,
    p4: usize,
) -> ! {
    KeBugCheckEx(code, p1, p2, p3, p4)
}

/// `PoEnergyEstimationEnabled` (undocumented): whether the kernel
/// estimates each component's energy use, for which drivers then count
/// their work (`partmgr.sys` counts its writes). NK estimates nothing.
pub extern "C" fn PoEnergyEstimationEnabled() -> u8 {
    0
}
