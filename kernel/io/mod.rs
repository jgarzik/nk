//! The I/O manager: driver and device objects, IRPs, and the request path
//! from "open this name" to a driver's dispatch routine and back.
//!
//! Objects handed to drivers are allocated from the pool at exactly their
//! Windows size and reached through raw pointers only. A request may be
//! pended and completed later, and cancelled; `doc/design/io.md` says how.

pub mod build;
pub mod csq;
pub mod device;
pub mod driver;
pub mod errlog;
pub mod file;
pub mod fsrtl;
pub mod interrupt;
pub mod irp;
pub mod irpext;
pub mod irpinfo;
pub mod mdl;
pub mod mount;
pub mod priority;
pub mod raw;
pub mod remlock;
pub mod service;
pub mod shutdown;
pub mod stack;
pub mod startio;
pub mod symlink;
pub mod wmi;
pub mod zwfile;

// Pool tags, as Windows spells its own.

/// File names: the part of a path a device's driver parses.
pub const TAG_FILE_NAME: u32 = u32::from_le_bytes(*b"IoNm");
pub const TAG_IRP: u32 = u32::from_le_bytes(*b"Irp ");
/// Buffers the I/O manager allocates for buffered requests.
pub const TAG_IO_BUFFER: u32 = u32::from_le_bytes(*b"IoSB");
