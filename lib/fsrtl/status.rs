//! Which exception statuses a file system lets through, and which
//! failures mean the device is gone, as the pinned kernel decides:
//! `FsRtlIsNtstatusExpected`, `FsRtlNormalizeNtstatus` and
//! `FsRtlIsTotalDeviceFailure`.

/// The statuses that are not expected of a file system's operation: the
/// processor's exceptions and the like, which it must not pass on.
const UNEXPECTED: [u32; 13] = [
    0x8000_0001, // STATUS_GUARD_PAGE_VIOLATION
    0x8000_0002, // STATUS_DATATYPE_MISALIGNMENT
    0x8000_0003, // STATUS_BREAKPOINT
    0xC000_0005, // STATUS_ACCESS_VIOLATION
    0xC000_001D, // STATUS_ILLEGAL_INSTRUCTION
    0xC000_0046, // STATUS_MUTANT_NOT_OWNED
    0xC000_0047, // STATUS_SEMAPHORE_LIMIT_EXCEEDED
    0xC000_008C, // STATUS_ARRAY_BOUNDS_EXCEEDED
    0xC000_0094, // STATUS_INTEGER_DIVIDE_BY_ZERO
    0xC000_0096, // STATUS_PRIVILEGED_INSTRUCTION
    0xC000_00AA, // STATUS_INSTRUCTION_MISALIGNMENT
    0xC000_0409, // STATUS_STACK_BUFFER_OVERRUN
    0xC000_0420, // STATUS_ASSERTION_FAILURE
];

/// `FsRtlIsNtstatusExpected`.
pub fn is_expected(status: u32) -> bool {
    !UNEXPECTED.contains(&status)
}

/// `FsRtlNormalizeNtstatus`: `status` if expected, else `generic`.
pub fn normalize(status: u32, generic: u32) -> u32 {
    if is_expected(status) { status } else { generic }
}

/// `FsRtlIsTotalDeviceFailure`: a failure or warning other than a data
/// error the device reported (`STATUS_CRC_ERROR`,
/// `STATUS_DEVICE_DATA_ERROR` and 0xC0000470).
pub fn is_total_device_failure(status: u32) -> bool {
    (status as i32) < 0 && !matches!(status, 0xC000_003F | 0xC000_009C | 0xC000_0470)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected() {
        assert!(is_expected(0));
        assert!(is_expected(0x8000_0000));
        assert!(is_expected(0x8000_0005));
        assert!(is_expected(0xC000_0010));
        assert!(is_expected(0xC000_008D));
        assert!(!is_expected(0xC000_0005));
        assert!(!is_expected(0x8000_0002));
        assert_eq!(normalize(0xC000_0094, 0xC000_0001), 0xC000_0001);
        assert_eq!(normalize(0xC000_0034, 0xC000_0001), 0xC000_0034);
    }

    #[test]
    fn device_failure() {
        assert!(!is_total_device_failure(0));
        assert!(is_total_device_failure(0x8000_0005));
        assert!(!is_total_device_failure(0xC000_003F));
        assert!(!is_total_device_failure(0xC000_009C));
        assert!(is_total_device_failure(0xC000_0185));
        assert!(is_total_device_failure(0x8000_0010));
    }
}
