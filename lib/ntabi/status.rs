//! `NTSTATUS` values NK returns or checks.
//!
//! Values are from Microsoft's public `ntstatus.h`.

pub type NTSTATUS = i32;

const fn err(v: u32) -> NTSTATUS {
    v as i32
}

pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_PENDING: NTSTATUS = 0x103;
pub const STATUS_BUFFER_OVERFLOW: NTSTATUS = err(0x8000_0005);
pub const STATUS_UNSUCCESSFUL: NTSTATUS = err(0xC000_0001);
pub const STATUS_NOT_IMPLEMENTED: NTSTATUS = err(0xC000_0002);
pub const STATUS_INVALID_INFO_CLASS: NTSTATUS = err(0xC000_0003);
pub const STATUS_ACCESS_VIOLATION: NTSTATUS = err(0xC000_0005);
pub const STATUS_INVALID_HANDLE: NTSTATUS = err(0xC000_0008);
pub const STATUS_INVALID_PARAMETER: NTSTATUS = err(0xC000_000D);
pub const STATUS_NO_SUCH_DEVICE: NTSTATUS = err(0xC000_000E);
pub const STATUS_INVALID_DEVICE_REQUEST: NTSTATUS = err(0xC000_0010);
pub const STATUS_END_OF_FILE: NTSTATUS = err(0xC000_0011);
pub const STATUS_MORE_PROCESSING_REQUIRED: NTSTATUS = err(0xC000_0016);
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = err(0xC000_0023);
pub const STATUS_OBJECT_TYPE_MISMATCH: NTSTATUS = err(0xC000_0024);
pub const STATUS_OBJECT_NAME_INVALID: NTSTATUS = err(0xC000_0033);
pub const STATUS_OBJECT_NAME_NOT_FOUND: NTSTATUS = err(0xC000_0034);
pub const STATUS_OBJECT_NAME_COLLISION: NTSTATUS = err(0xC000_0035);
pub const STATUS_OBJECT_PATH_SYNTAX_BAD: NTSTATUS = err(0xC000_003B);
pub const STATUS_UNKNOWN_REVISION: NTSTATUS = err(0xC000_0058);
pub const STATUS_REVISION_MISMATCH: NTSTATUS = err(0xC000_0059);
pub const STATUS_INVALID_ACL: NTSTATUS = err(0xC000_0077);
pub const STATUS_INVALID_SID: NTSTATUS = err(0xC000_0078);
pub const STATUS_INVALID_SECURITY_DESCR: NTSTATUS = err(0xC000_0079);
pub const STATUS_ALLOTTED_SPACE_EXCEEDED: NTSTATUS = err(0xC000_0099);
pub const STATUS_INSUFFICIENT_RESOURCES: NTSTATUS = err(0xC000_009A);
pub const STATUS_BAD_DESCRIPTOR_FORMAT: NTSTATUS = err(0xC000_00E7);
pub const STATUS_NOT_SUPPORTED: NTSTATUS = err(0xC000_00BB);
pub const STATUS_INVALID_IMAGE_FORMAT: NTSTATUS = err(0xC000_007B);
pub const STATUS_PROCEDURE_NOT_FOUND: NTSTATUS = err(0xC000_007A);
pub const STATUS_IMAGE_MACHINE_TYPE_MISMATCH: NTSTATUS = err(0x4000_000E);
pub const STATUS_DRIVER_UNABLE_TO_LOAD: NTSTATUS = err(0xC000_026C);

/// `NT_SUCCESS`: success and informational codes are non-negative.
pub const fn nt_success(status: NTSTATUS) -> bool {
    status >= 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_classes() {
        assert!(nt_success(STATUS_SUCCESS) && nt_success(STATUS_PENDING));
        assert!(
            nt_success(STATUS_IMAGE_MACHINE_TYPE_MISMATCH),
            "0x4... is informational"
        );
        assert!(!nt_success(STATUS_BUFFER_OVERFLOW), "0x8... is a warning");
        assert!(!nt_success(STATUS_END_OF_FILE));
        assert_eq!(STATUS_END_OF_FILE as u32, 0xC000_0011);
        // The constants are built at compile time; build one at run time
        // too, so the conversion is seen to keep every bit.
        let bits = std::hint::black_box(0xC000_009Au32);
        assert_eq!(err(bits), STATUS_INSUFFICIENT_RESOURCES);
        assert_eq!(err(bits) as u32, bits);
    }
}
