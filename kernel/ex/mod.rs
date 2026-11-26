//! The executive: services built on the kernel core that drivers use.

pub mod absent;
pub mod callback;
pub mod em;
pub mod firmware;
pub mod license;
pub mod lookaside;
pub mod pushlock;
pub mod resource;
pub mod rundown;
pub mod shim;
pub mod slist;
pub mod spinlock;
mod stress;
pub mod sysinfo;
pub mod sysinfo_ex;
pub mod timer;
pub mod uuid;
pub mod vsl;
pub mod wnf;
pub mod work;
