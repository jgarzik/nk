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
    // First of all: the processor block is where locks and IRQL keep
    // their state, and the console takes a lock.
    arch::cpu_init();
    kd::console_init(info);
    hal::init(info);
    kprintln!("NK {} ({})", env!("CARGO_PKG_VERSION"), arch::NAME);
    if !info.is_valid() {
        test::abort(
            "boot",
            format_args!("BootInfo magic/version mismatch: loader and kernel differ"),
        );
    }
    arch::mm_init(info);
    if let Err(why) = mm::init(info) {
        test::abort("mm.init", format_args!("{why}"));
    }
    kprintln!("memory: {} MiB free", mm::free_frame_count() * 4 / 1024);

    // Leave the loader's stack, which lies in the direct map with ordinary
    // memory below it, for one with nothing mapped below.
    let Some(stack) = mm::stack::alloc() else {
        test::abort("mm.stack", format_args!("cannot allocate the boot stack"));
    };
    arch::set_kernel_stack(stack.base);
    arch::switch_stack(stack.top, on_kernel_stack, info)
}

/// The rest of boot, on the kernel's own stack.
extern "C" fn on_kernel_stack(info: &'static BootInfo) -> ! {
    if let Err(why) = hal::platform::init(info) {
        test::abort("hal.platform", format_args!("{why}"));
    }
    if let Err(why) = arch::interrupts_init() {
        test::abort("hal.interrupts", format_args!("{why}"));
    }
    // From here on interrupts are held back by the IRQL alone.
    arch::enable_interrupts();
    if let Err(why) = ke::time::init(info) {
        test::abort("ke.time", format_args!("{why}"));
    }
    ke::ipi::init();
    match ke::smp::start_all(info) {
        Ok(running) => kprintln!("ke: {running} processors running"),
        Err(why) => test::abort("ke.smp", format_args!("{why}")),
    }

    export::print_all();
    test::run_all(selftest::GROUPS, info)
}
