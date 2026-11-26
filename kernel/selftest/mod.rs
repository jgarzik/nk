//! The boot self-tests, in the order they run.
//!
//! The driver tests exercise real driver binaries. Each driver is a boot
//! module the loader read from the EFI system partition. A module that is
//! not there (its fixture was not downloaded, or does not exist for this
//! architecture) makes its tests SKIP.

mod base;
mod cancel;
mod clock;
mod cm;
mod csq;
mod dpc;
mod driver_api;
mod ex;
mod library;
mod loader;
mod mutex;
mod neg;
mod null;
mod ob;
mod open;
mod oracle;
mod pend;
mod review;
mod se;
mod seh;
mod service;
mod sioctl;
mod smp;
mod thread;
mod timer;
mod wait;
mod work;

use crate::io::file::{self, OpenRequest};
use crate::mm;
use crate::test::Group;
use nk_ntabi::status::NTSTATUS;

/// Open `name` the way the oracle's plain `open` step does, for a
/// handle.
fn open(name: &str) -> Result<u64, NTSTATUS> {
    file::open(&OpenRequest::new(name)).map(|(handle, _)| handle)
}

/// Every test group. `test=` on the command line selects among them.
pub static GROUPS: &[&Group] = &[
    &base::GROUP,
    &clock::GROUP,
    &smp::GROUP,
    &dpc::GROUP,
    &timer::GROUP,
    &thread::GROUP,
    &seh::GROUP,
    &wait::GROUP,
    &ob::GROUP,
    &se::GROUP,
    &cm::GROUP,
    &csq::GROUP,
    &review::GROUP,
    &mutex::GROUP,
    &work::GROUP,
    &ex::GROUP,
    &pend::GROUP,
    &open::GROUP,
    &service::GROUP,
    &driver_api::GROUP,
    &loader::GROUP,
    &library::GROUP,
    &null::GROUP,
    &sioctl::GROUP,
    &cancel::GROUP,
    &oracle::GROUP,
    &neg::PANIC,
    &neg::FAULT,
    &neg::NULL,
    &neg::LOW_MEMORY,
    &neg::STACK_OVERFLOW,
    &neg::DPC_STACK_OVERFLOW,
    &neg::LOCK_ORDER,
    &neg::LOCK_TWICE,
    &neg::IRQL_LOWER,
    &neg::META_FAIL,
    &neg::BREAKPOINT,
    &oracle::EVENT,
    &oracle::EVENT_DEBUG,
    &smp::STUCK,
    &dpc::WATCHDOG,
    &wait::AT_DISPATCH,
    &wait::IN_DPC,
    &wait::SWITCH_IN_DPC,
    &mutex::EXIT_HOLDING,
    &work::BAD_RETURN,
    &pend::OVERSTATED,
    &neg::PROTECTED_CLOSE,
];

/// Everything the kernel owns that a test or a driver can leak. Compared
/// around every test group, and before loading a driver and after
/// unloading it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resources {
    pool_blocks: usize,
    pool_bytes: usize,
    /// The IRQL: a test that returns with it raised left a lock held or
    /// forgot to lower it.
    irql: u8,
    /// Frames that are free or held in a store the kernel keeps for good
    /// (pool arenas, page tables). Those stores grow on first use; that
    /// is not a leak, and anything else that takes frames is.
    spare_frames: u64,
    /// Entries in the object namespace: device names, symbolic links,
    /// driver objects. The directories made at boot are counted too,
    /// and never change.
    names: usize,
    /// Threads that exist: a test waits for the ones it made to end.
    threads: u32,
    /// Kernel handles open.
    handles: usize,
}

pub fn resources() -> Resources {
    let pool = mm::pool::usage();
    // The handle table keeps its own storage once it has grown.
    let (table_blocks, table_bytes) = crate::ob::handle::storage();
    // The registry keeps what is written to it.
    let (registry_blocks, registry_bytes) = crate::cm::storage();
    Resources {
        pool_blocks: pool.blocks - table_blocks - registry_blocks,
        pool_bytes: pool.bytes - table_bytes - registry_bytes,
        irql: crate::ke::irql::current(),
        spare_frames: mm::free_frame_count() + mm::pool::frames() + mm::map::table_frames(),
        names: crate::ob::count(),
        threads: crate::ke::thread::count(),
        handles: crate::ob::handle::count(),
    }
}
