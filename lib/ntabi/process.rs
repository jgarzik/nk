//! The process object (`KPROCESS` inside `EPROCESS`).
//!
//! As with the thread object, drivers built with the public headers
//! treat a process as opaque, while Microsoft's own may read fields in
//! line; NK keeps what it maintains at Windows' offsets. The x86-64
//! offsets are checked against the public symbols of the pinned kernel
//! build (`pdb.rs`); arm64 uses the same numbers, by NK's choice.
//!
//! Only the fields NK maintains are named.

/// Size of `EPROCESS`, which begins with the `KPROCESS`.
pub const EPROCESS_SIZE: usize = 0xA40;

/// `KPROCESS.Header.Type` of a process: `ProcessObject`.
pub const PROCESS_OBJECT: u8 = 3;

/// `UniqueProcessId`: the process id, pointer-sized.
pub const UNIQUE_PROCESS_ID: usize = 0x440;
/// `CreateTime`: when the process was made, as system time.
pub const CREATE_TIME: usize = 0x468;
/// `ImageFileName`: the image's name, 15 bytes, zero padded.
pub const IMAGE_FILE_NAME: usize = 0x5A8;
pub const IMAGE_FILE_NAME_LEN: usize = 15;

/// The id of the System process, as on Windows.
pub const SYSTEM_PROCESS_ID: u64 = 4;
