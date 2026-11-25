//! Boot self-tests that exercise real driver binaries.
//!
//! Each driver is a boot module the loader read from the EFI system
//! partition. A module that is not there (its fixture was not downloaded,
//! or does not exist for this architecture) makes its tests SKIP.

mod loader;
mod null;
mod sioctl;

use crate::mm;
use nk_bootinfo::BootInfo;

/// The bytes of the boot module called `name`, if the loader supplied it.
fn module<'a>(info: &'a BootInfo, name: &str) -> Option<&'a [u8]> {
    let m = info
        .modules()
        .iter()
        .find(|m| m.name().eq_ignore_ascii_case(name.as_bytes()))?;
    // SAFETY: the loader read the file into reserved memory that stays
    // mapped and unmodified for the life of the kernel.
    Some(unsafe { core::slice::from_raw_parts(mm::phys_to_virt(m.phys), m.size as usize) })
}

/// Everything the kernel owns that a driver can leak. Compared before
/// loading a driver and after unloading it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resources {
    pool_blocks: usize,
    pool_bytes: usize,
    free_frames: u64,
    names: usize,
}

pub fn resources() -> Resources {
    let pool = mm::pool::usage();
    Resources {
        pool_blocks: pool.blocks,
        pool_bytes: pool.bytes,
        free_frames: mm::free_frame_count(),
        names: crate::ob::count(),
    }
}

pub fn run(info: &BootInfo) {
    loader::run(info);
    null::run(info);
    sioctl::run(info);
}
