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
mod cm;
mod etw;
mod ex;
mod export;
mod hal;
mod io;
mod ke;
mod ldr;
mod mm;
mod ob;
mod ps;
mod rt;
mod rtl;
mod se;
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
    if let Err(why) = arch::low_half_init() {
        test::abort("mm.low-half", format_args!("{why}"));
    }
    if let Err(why) = ldr::init(info) {
        test::abort("ldr.init", format_args!("{why}"));
    }

    // Leave the loader's stack, which lies in the direct map with ordinary
    // memory below it, for one with nothing mapped below.
    let Some(stack) = mm::stack::alloc() else {
        test::abort("mm.stack", format_args!("cannot allocate the boot stack"));
    };
    arch::set_kernel_stack(stack.base);
    ke::smp::set_stack(0, stack);
    arch::switch_stack(stack.top, on_kernel_stack, info)
}

/// The rest of boot, on the kernel's own stack.
extern "C" fn on_kernel_stack(info: &'static BootInfo) -> ! {
    if let Err(why) = hal::platform::init(info) {
        test::abort("hal.platform", format_args!("{why}"));
    }
    hal::pci::init();
    if let Err(why) = arch::interrupts_init() {
        test::abort("hal.interrupts", format_args!("{why}"));
    }
    // Threads are objects: the object manager comes first.
    ob::object::init(arch::counter());
    if let Err(why) = ps::process::init(info.boot_time) {
        test::abort("ps.process", format_args!("{why}"));
    }
    // What this processor is running becomes its idle thread.
    if let Err(why) = ke::thread::init_cpu(ke::smp::stack_of(0)) {
        test::abort("ke.thread", format_args!("{why}"));
    }
    // From here on interrupts are held back by the IRQL alone.
    arch::enable_interrupts();
    if let Err(why) = ke::time::init(info) {
        test::abort("ke.time", format_args!("{why}"));
    }
    ke::ipi::init();
    if let Err(why) = ke::dpc::init(info) {
        test::abort("ke.dpc", format_args!("{why}"));
    }
    match ke::smp::start_all(info) {
        Ok(running) => kprintln!("ke: {running} processors running"),
        Err(why) => test::abort("ke.smp", format_args!("{why}")),
    }
    if let Err(why) = ex::work::init() {
        test::abort("ex.work", format_args!("{why}"));
    }
    if let Err(why) = ob::init() {
        test::abort("ob", format_args!("{why}"));
    }
    if let Err(why) = cm::init() {
        test::abort("cm", format_args!("{why}"));
    }

    // The rest runs in a thread, at PASSIVE_LEVEL, as drivers expect of
    // whatever calls them; this context idles.
    let info = core::ptr::from_ref(info) as usize;
    if let Err(why) = ke::thread::create(system_thread, info, ke::thread::NORMAL_PRIORITY, 1) {
        test::abort("ke.thread", format_args!("{why}"));
    }
    ke::thread::idle_loop()
}

/// The first thread: start the drivers that start at boot, run the
/// tests, then power off.
fn system_thread(info: usize) {
    // SAFETY: the address of the loader's hand-off block, which lives
    // for ever and is never written.
    let info = unsafe { &*(info as *const BootInfo) };
    export::print_all();
    if let Err(why) = io::service::start_boot_services() {
        test::abort("io.boot-start", format_args!("{why}"));
    }
    test::run_all(selftest::GROUPS, info)
}
