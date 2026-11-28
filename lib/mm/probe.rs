//! Pure user-mode pointer probe and capture checks (`ProbeForRead` /
//! `ProbeForWrite` semantics).
//!
//! No hardware access and no `unsafe`: the kernel combines these range and
//! alignment checks with faulting copies (`kernel/svc/capture.rs`).

/// Windows' `MmUserProbeAddress`: the first address beyond the user range.
pub const USER_PROBE_ADDRESS: u64 = 0x7FFF_FFFF_0000;
/// Lowest mappable user address (the bottom 64 KiB stay unmapped).
pub const LOWEST_USER_ADDRESS: u64 = 0x1_0000;

/// Why a user-mode probe or string header check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeError {
    /// Address lies outside `[0, probe_limit)` or overflows.
    AccessViolation,
    /// Address does not satisfy the required alignment.
    DatatypeMisalignment,
    /// Structure header invariant failed (e.g. odd UTF-16 byte length or
    /// `Length > MaximumLength`).
    InvalidParameter,
}

/// Check `[addr, addr + len)` against `align` and `probe_limit`, matching
/// Windows' `ProbeForRead` / `ProbeForWrite` order:
/// - `len == 0` succeeds unconditionally (Windows never checks address or
///   alignment for zero-length probes).
/// - Otherwise `align` (when > 1) is checked first (`DatatypeMisalignment`).
/// - Then `addr == 0`, arithmetic overflow, and `addr + len > probe_limit`
///   fail with `AccessViolation`.
pub fn check_range(addr: u64, len: u64, align: u64, probe_limit: u64) -> Result<(), ProbeError> {
    if len == 0 {
        return Ok(());
    }
    if align > 1 && addr % align != 0 {
        return Err(ProbeError::DatatypeMisalignment);
    }
    if addr == 0 {
        return Err(ProbeError::AccessViolation);
    }
    let end = addr.checked_add(len).ok_or(ProbeError::AccessViolation)?;
    if end > probe_limit {
        return Err(ProbeError::AccessViolation);
    }
    Ok(())
}

/// Validate a captured `UNICODE_STRING` header for a user-mode caller:
/// - `length` must be even and `<= max_length`.
/// - When `length > 0`, `buf` must be 2-byte aligned and `[buf, buf + length)`
///   must lie below `probe_limit`.
///
/// Returns the number of UTF-16 code units (`length / 2`).
pub fn check_unicode_string(
    length: u16,
    max_length: u16,
    buf: u64,
    probe_limit: u64,
) -> Result<usize, ProbeError> {
    if length & 1 != 0 || length > max_length {
        return Err(ProbeError::InvalidParameter);
    }
    if length == 0 {
        return Ok(0);
    }
    check_range(buf, u64::from(length), 2, probe_limit)?;
    Ok(usize::from(length) / 2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_length_always_succeeds() {
        assert_eq!(check_range(0, 0, 8, USER_PROBE_ADDRESS), Ok(()));
        assert_eq!(check_range(1, 0, 8, USER_PROBE_ADDRESS), Ok(()));
        assert_eq!(check_range(u64::MAX, 0, 16, USER_PROBE_ADDRESS), Ok(()));
    }

    #[test]
    fn alignment_checked_before_bounds() {
        assert_eq!(
            check_range(0x1001, 4, 4, USER_PROBE_ADDRESS),
            Err(ProbeError::DatatypeMisalignment)
        );
        assert_eq!(
            check_range(USER_PROBE_ADDRESS + 1, 4, 4, USER_PROBE_ADDRESS),
            Err(ProbeError::DatatypeMisalignment)
        );
        assert_eq!(check_range(0x1001, 4, 1, USER_PROBE_ADDRESS), Ok(()));
    }

    #[test]
    fn bounds_and_overflow_rejected() {
        assert_eq!(
            check_range(0, 4, 4, USER_PROBE_ADDRESS),
            Err(ProbeError::AccessViolation)
        );
        assert_eq!(
            check_range(USER_PROBE_ADDRESS - 4, 4, 4, USER_PROBE_ADDRESS),
            Ok(())
        );
        assert_eq!(
            check_range(USER_PROBE_ADDRESS - 4, 8, 4, USER_PROBE_ADDRESS),
            Err(ProbeError::AccessViolation)
        );
        assert_eq!(
            check_range(USER_PROBE_ADDRESS, 1, 1, USER_PROBE_ADDRESS),
            Err(ProbeError::AccessViolation)
        );
        assert_eq!(
            check_range(0xFFFF_F800_0000_0000, 8, 8, USER_PROBE_ADDRESS),
            Err(ProbeError::AccessViolation)
        );
        assert_eq!(
            check_range(u64::MAX - 4, 8, 1, USER_PROBE_ADDRESS),
            Err(ProbeError::AccessViolation)
        );
    }

    #[test]
    fn unicode_string_checks() {
        assert_eq!(check_unicode_string(0, 0, 0, USER_PROBE_ADDRESS), Ok(0));
        assert_eq!(
            check_unicode_string(3, 4, 0x10000, USER_PROBE_ADDRESS),
            Err(ProbeError::InvalidParameter)
        );
        assert_eq!(
            check_unicode_string(6, 4, 0x10000, USER_PROBE_ADDRESS),
            Err(ProbeError::InvalidParameter)
        );
        assert_eq!(
            check_unicode_string(4, 4, 0x10001, USER_PROBE_ADDRESS),
            Err(ProbeError::DatatypeMisalignment)
        );
        assert_eq!(
            check_unicode_string(4, 4, 0, USER_PROBE_ADDRESS),
            Err(ProbeError::AccessViolation)
        );
        assert_eq!(
            check_unicode_string(4, 4, USER_PROBE_ADDRESS - 2, USER_PROBE_ADDRESS),
            Err(ProbeError::AccessViolation)
        );
        assert_eq!(
            check_unicode_string(4, 8, 0x10000, USER_PROBE_ADDRESS),
            Ok(2)
        );
    }
}
