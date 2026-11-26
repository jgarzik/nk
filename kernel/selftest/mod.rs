//! The boot self-tests, in the order they run.
//!
//! The driver tests exercise real driver binaries. Each driver is a boot
//! module the loader read from the EFI system partition. A module that is
//! not there (its fixture was not downloaded, or does not exist for this
//! architecture) makes its tests SKIP.

mod base;
mod bitmap;
mod cancel;
mod clock;
mod cm;
mod csq;
mod dpc;
mod driver_api;
mod etw;
mod ex;
pub mod except;
mod fsd;
mod library;
mod loader;
mod mslib;
mod mutex;
mod neg;
mod null;
mod ob;
mod open;
mod oracle;
mod pend;
mod requestor;
mod review;
mod rtl;
mod se;
mod seh;
mod service;
mod setoken;
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

/// Open `name` as [`open`] does, on behalf of user mode: the handle is
/// one that requests made as user mode may go by.
fn open_as_user(name: &str) -> Result<u64, NTSTATUS> {
    let request = OpenRequest {
        requestor_mode: nk_ntabi::io::USER_MODE,
        ..OpenRequest::new(name)
    };
    file::open(&request).map(|(handle, _)| handle)
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

/// Every test group, file by file. `test=` on the command line selects
/// among them. A file lists its own groups.
pub static GROUPS: &[&[&Group]] = &[
    base::GROUPS,
    clock::GROUPS,
    smp::GROUPS,
    dpc::GROUPS,
    timer::GROUPS,
    thread::GROUPS,
    seh::GROUPS,
    except::GROUPS,
    wait::GROUPS,
    ob::GROUPS,
    rtl::GROUPS,
    bitmap::GROUPS,
    se::GROUPS,
    setoken::GROUPS,
    cm::GROUPS,
    csq::GROUPS,
    review::GROUPS,
    mutex::GROUPS,
    work::GROUPS,
    ex::GROUPS,
    pend::GROUPS,
    open::GROUPS,
    requestor::GROUPS,
    service::GROUPS,
    driver_api::GROUPS,
    etw::GROUPS,
    loader::GROUPS,
    library::GROUPS,
    fsd::GROUPS,
    null::GROUPS,
    mslib::GROUPS,
    sioctl::GROUPS,
    cancel::GROUPS,
    oracle::GROUPS,
    neg::GROUPS,
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
    /// Trace providers registered: a driver unregisters what it
    /// registered.
    providers: usize,
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
        providers: crate::etw::registered(),
    }
}
