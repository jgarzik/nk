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

/// `KPROCESS.BasePriority`: one signed byte, the priority a thread of
/// the process has unless it is set apart. The System process's is 8.
pub const BASE_PRIORITY: usize = 0x280;
/// `UniqueProcessId`: the process id, pointer-sized.
pub const UNIQUE_PROCESS_ID: usize = 0x440;
/// `CreateTime`: when the process was made, as system time.
pub const CREATE_TIME: usize = 0x468;
/// `Token`: the process's primary token, as an `EX_FAST_REF`: a pointer
/// to the token object whose low four bits ([`FAST_REF_COUNT_MASK`])
/// count references handed out in advance.
pub const TOKEN: usize = 0x4B8;
/// The bits of an `EX_FAST_REF` that are a count, not part of the
/// pointer. Objects are 16-byte aligned, so a pointer has them clear.
pub const FAST_REF_COUNT_MASK: usize = 0xF;
/// `Job`: the job the process is in, or null. The silo a thread of the
/// process is in, unless it is attached to another, is found from
/// here. The System process is in no job.
pub const JOB: usize = 0x510;
/// `ServerSilo`: the server silo the process is in, or null.
pub const SERVER_SILO: usize = 0x870;
/// `Session`: the session the process is in (an `MM_SESSION_SPACE`), or
/// null for a process in none, which reads as session 0. The System
/// process is in none.
pub const SESSION: usize = 0x558;
/// `QuotaBlock`: what the process's pool and page-file use is charged
/// to. Windows never charges the System process and never looks at its
/// block for that; NK leaves the field null.
pub const QUOTA_BLOCK: usize = 0x568;
/// `ImageFileName`: the image's name, 15 bytes, zero padded.
pub const IMAGE_FILE_NAME: usize = 0x5A8;
pub const IMAGE_FILE_NAME_LEN: usize = 15;

/// The id of the System process, as on Windows.
pub const SYSTEM_PROCESS_ID: u64 = 4;
