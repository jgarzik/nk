//! `RtlNtStatusToDosErrorNoTeb`: the Windows error code a status code
//! stands for, by the pinned kernel's rules and its table
//! (`doserror_table.rs`, made by `tools/doserror.py`).

#[path = "doserror_table.rs"]
mod table;

/// `ERROR_IO_PENDING`, for `STATUS_PENDING`.
const ERROR_IO_PENDING: u32 = 997;
/// `ERROR_MR_MID_NOT_FOUND`: a status the table does not know.
const ERROR_MR_MID_NOT_FOUND: u32 = 317;
const STATUS_PENDING: u32 = 0x103;
/// The bit of a code a customer defines.
const CUSTOMER: u32 = 1 << 29;
/// `FACILITY_WIN32`, in a status code's facility field.
const FACILITY_WIN32: u32 = 7 << 16;

/// The Windows error code for `status`.
pub fn dos_error(status: u32) -> u32 {
    if status == 0 {
        return 0;
    }
    if status == STATUS_PENDING {
        return ERROR_IO_PENDING;
    }
    if status & CUSTOMER != 0 {
        return status;
    }
    // A Windows error wrapped as a warning or an error status.
    if status & 0x00FF_0000 == FACILITY_WIN32 && matches!(status >> 24, 0x80 | 0xC0) {
        return status & 0xFFFF;
    }
    // Severity 0xD is looked up as 0xC.
    let code = if status & 0xF000_0000 == 0xD000_0000 {
        status & 0xCFFF_FFFF
    } else {
        status
    };
    let at = table::RUNS.partition_point(|&(base, ..)| base <= code);
    if let Some(&(base, count, width, index)) = at.checked_sub(1).map(|i| &table::RUNS[i])
        && code - base < u32::from(count)
    {
        let offset = (code - base) as usize;
        let index = usize::from(index);
        return if width == 1 {
            u32::from(table::ENTRIES[index + offset])
        } else {
            let low = table::ENTRIES[index + 2 * offset];
            let high = table::ENTRIES[index + 2 * offset + 1];
            u32::from(high) << 16 | u32::from(low)
        };
    }
    // Facility 1, the debugger's: its codes carry their error.
    if code & 0xFFFF_0000 == 0xC001_0000 {
        return code & 0xFFFF;
    }
    ERROR_MR_MID_NOT_FOUND
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_before_the_table() {
        assert_eq!(dos_error(0), 0);
        assert_eq!(dos_error(0x103), 997);
        assert_eq!(dos_error(0xE000_1234), 0xE000_1234, "customer code");
        assert_eq!(dos_error(0x8007_0005), 5, "a Windows error as a warning");
        assert_eq!(dos_error(0xC007_0057), 87);
        assert_eq!(dos_error(0xC001_0042), 0x42, "the debugger's facility");
        assert_eq!(dos_error(0xC0FF_FFF0), 317, "not in the table");
    }

    #[test]
    fn the_table_as_windows_documents_it() {
        // Microsoft's mapping, as winerror.h and ntstatus.h name them.
        for (status, error) in [
            (0xC000_0001u32, 31u32), // STATUS_UNSUCCESSFUL: ERROR_GEN_FAILURE
            (0xC000_0005, 998),      // STATUS_ACCESS_VIOLATION: ERROR_NOACCESS
            (0xC000_000D, 87),       // STATUS_INVALID_PARAMETER
            (0xC000_0017, 8),        // STATUS_NO_MEMORY: ERROR_NOT_ENOUGH_MEMORY
            (0xC000_0022, 5),        // STATUS_ACCESS_DENIED
            (0xC000_0034, 2),        // STATUS_OBJECT_NAME_NOT_FOUND: ERROR_FILE_NOT_FOUND
            (0xC000_003A, 3),        // STATUS_OBJECT_PATH_NOT_FOUND
            (0xC000_009A, 1450),     // STATUS_INSUFFICIENT_RESOURCES
            (0xC000_00BB, 50),       // STATUS_NOT_SUPPORTED
            (0x8000_0005, 234),      // STATUS_BUFFER_OVERFLOW: ERROR_MORE_DATA
            (0xC000_0023, 122),      // STATUS_BUFFER_TOO_SMALL
            (0xD000_0022, 5),        // looked up as 0xC000_0022
        ] {
            assert_eq!(dos_error(status), error, "{status:#x}");
        }
    }

    #[test]
    fn the_table_is_sorted() {
        for pair in table::RUNS.windows(2) {
            assert!(pair[0].0 + u32::from(pair[0].1) <= pair[1].0);
        }
    }
}
