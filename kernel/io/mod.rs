//! The I/O manager: driver and device objects, IRPs, and the request path
//! from "open this name" to a driver's dispatch routine and back.
//!
//! Objects handed to drivers are allocated from the pool at exactly their
//! Windows size and reached through raw pointers only. A request may be
//! pended and completed later, and cancelled; `doc/DESIGN.md` says how.

pub mod device;
pub mod driver;
pub mod file;
pub mod irp;
pub mod mdl;
pub mod remlock;
pub mod symlink;

/// Pool tags, as Windows spells its own.
pub const TAG_DRIVER: u32 = u32::from_le_bytes(*b"Driv");
pub const TAG_FILE: u32 = u32::from_le_bytes(*b"File");
pub const TAG_IRP: u32 = u32::from_le_bytes(*b"Irp ");
/// Buffers the I/O manager allocates for buffered requests.
pub const TAG_IO_BUFFER: u32 = u32::from_le_bytes(*b"IoSB");
