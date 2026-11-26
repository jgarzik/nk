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
mod etw;
pub mod except;
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

/// Where the tests that make requests as user mode keep the two
/// buffers of a request: far above any memory firmware has.
const USER_INPUT: u64 = 0x4E4B_0000_0000;
const USER_OUTPUT: u64 = 0x4E4C_0000_0000;

/// A buffer in the user range, as a user-mode program has its buffers
/// in its address space: whole pages, mapped while this lives.
struct UserMemory {
    va: u64,
    len: usize,
}

impl UserMemory {
    /// Map pages at `va` and put `bytes` at their start. No bytes, no
    /// pages: an empty buffer is no buffer.
    fn new(va: u64, bytes: &[u8]) -> Result<Self, &'static str> {
        let memory = Self {
            va,
            len: bytes.len(),
        };
        if !bytes.is_empty() {
            mm::user::map_pages(va, memory.pages()).map_err(|_| "cannot map user pages")?;
            // SAFETY: the pages just mapped, which hold the bytes.
            unsafe { (va as *mut u8).copy_from_nonoverlapping(bytes.as_ptr(), bytes.len()) };
        }
        Ok(memory)
    }

    fn pages(&self) -> usize {
        self.len.div_ceil(mm::PAGE_SIZE)
    }

    /// The buffer, as a request names it.
    fn buffer(&self) -> file::Buffer {
        if self.len == 0 {
            file::Buffer::NONE
        } else {
            file::Buffer {
                address: self.va as usize,
                len: self.len,
            }
        }
    }

    /// What the buffer holds now.
    fn contents(&self) -> alloc::vec::Vec<u8> {
        let mut bytes = alloc::vec![0; self.len];
        if self.len != 0 {
            // SAFETY: the pages mapped by `new`.
            unsafe { (self.va as *const u8).copy_to_nonoverlapping(bytes.as_mut_ptr(), self.len) };
        }
        bytes
    }
}

impl Drop for UserMemory {
    fn drop(&mut self) {
        if self.len != 0 {
            mm::user::unmap_pages(self.va, self.pages());
        }
    }
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
    &except::GROUP,
    &wait::GROUP,
    &ob::GROUP,
    &se::GROUP,
    &cm::GROUP,
    &csq::GROUP,
    &review::GROUP,
    &mutex::GROUP,
    &work::GROUP,
    &pend::GROUP,
    &open::GROUP,
    &service::GROUP,
    &driver_api::GROUP,
    &etw::GROUP,
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
    &etw::BUGCHECK_EX,
    &etw::BUGCHECK_CALLBACK,
    &except::THREAD,
    &except::SERVICE,
    &except::DPC,
    &except::NO_ENTRY,
    &except::KERNEL_FAULT,
    &except::FAULT_AT_DISPATCH,
    &oracle::EVENT,
    &oracle::EVENT_DEBUG,
    &oracle::FATAL_DISPATCH,
    &oracle::FATAL_WORK,
    &oracle::FATAL_DPC,
    &oracle::FATAL_KERNEL_READ,
    &oracle::FATAL_THREAD,
    &oracle::CROSS_DPC,
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
