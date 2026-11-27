//! The time zone: what turns the system time (UTC) into local time and
//! back (`ExSystemTimeToLocalTime`, `ExLocalTimeToSystemTime`), which a
//! FAT file system uses for every time it stores.
//!
//! Windows computes its bias from the registry's
//! `Control\TimeZoneInformation` at boot and keeps it per silo and in
//! `KUSER_SHARED_DATA.TimeZoneBias`. Without that key the bias is zero,
//! local time is UTC; NK's registry has no such key, so the bias is zero
//! (the shared page's field stays zero). NK does not compute a bias from
//! a configured zone: a registry that has one stops the system at boot,
//! naming the key, rather than have every stored time be wrong.

#![allow(non_snake_case)]

/// The key a configured time zone would be in.
const TIME_ZONE: &str = "Machine\\System\\CurrentControlSet\\Control\\TimeZoneInformation";

/// Check at boot that no time zone is configured.
pub fn init() {
    if crate::cm::exists(TIME_ZONE) {
        crate::kd::bugcheck(format_args!(
            "ex: the registry configures a time zone ({TIME_ZONE}), which NK does not apply"
        ));
    }
}

/// [`ExSystemTimeToLocalTime`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exsystemtimetolocaltime):
/// local time is UTC.
///
/// # Safety
/// `system` is readable and `local` writable.
pub unsafe extern "C" fn ExSystemTimeToLocalTime(system: *const i64, local: *mut i64) {
    // SAFETY: per the contract.
    unsafe { local.write_unaligned(system.read_unaligned()) }
}

/// [`ExLocalTimeToSystemTime`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-exlocaltimetosystemtime):
/// local time is UTC.
///
/// # Safety
/// `local` is readable and `system` writable.
pub unsafe extern "C" fn ExLocalTimeToSystemTime(local: *const i64, system: *mut i64) {
    // SAFETY: per the contract.
    unsafe { system.write_unaligned(local.read_unaligned()) }
}
