//! The status filters file systems apply to exceptions and failures,
//! over `nk_fsrtl::status`.

#![allow(non_snake_case)]

use nk_fsrtl::status;

/// [`FsRtlIsNtstatusExpected`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlisntstatusexpected).
pub extern "C" fn FsRtlIsNtstatusExpected(status: u32) -> u8 {
    u8::from(status::is_expected(status))
}

/// [`FsRtlNormalizeNtstatus`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlnormalizentstatus).
pub extern "C" fn FsRtlNormalizeNtstatus(exception: u32, generic: u32) -> u32 {
    status::normalize(exception, generic)
}

/// [`FsRtlIsTotalDeviceFailure`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlistotaldevicefailure).
pub extern "C" fn FsRtlIsTotalDeviceFailure(status: u32) -> u8 {
    u8::from(status::is_total_device_failure(status))
}
