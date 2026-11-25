//! nkkrnl: the NK kernel.
//!
//! nkload maps this image in the high half and jumps to [`nk_entry`] on
//! the boot CPU with boot services gone, interrupts off and the direct
//! map in place. See `doc/DESIGN.md`.

#![no_std]
#![no_main]

extern crate alloc;

#[macro_use]
mod kd;
mod arch;
mod export;
mod hal;
mod io;
mod ke;
mod ldr;
mod mm;
mod ob;
mod rt;
mod rtl;
mod selftest;
mod test;

use nk_bootinfo::BootInfo;

/// Kernel entry point, named in `build.rs`.
///
/// # Safety
/// Called once, by nkload, with a pointer to a valid `BootInfo` in the
/// direct map.
#[unsafe(no_mangle)]
unsafe extern "C" fn nk_entry(info: *const BootInfo) -> ! {
    // SAFETY: nkload passes a valid, initialised BootInfo that nothing
    // else writes; it lives in loader-reserved memory for the whole run.
    let info: &'static BootInfo = unsafe { &*info };
    kd::console_init(info);
    hal::init(info);
    kprintln!("NK {} ({})", env!("CARGO_PKG_VERSION"), arch::NAME);
    if !info.is_valid() {
        test::abort(
            "boot",
            format_args!("BootInfo magic/version mismatch: loader and kernel differ"),
        );
    }
    arch::cpu_init();
    arch::mm_init(info);
    if let Err(why) = mm::init(info) {
        test::abort("mm.init", format_args!("{why}"));
    }
    kprintln!("memory: {} MiB free", mm::free_frame_count() * 4 / 1024);

    export::print_all();
    test::run_all(selftest::GROUPS, info)
}
