//! More than one processor.
//!
//! The boot processor starts the others one at a time. Each sets up its
//! own state (the architecture's part), starts its clock, reports that it
//! is running, and becomes its own idle thread (`thread.rs`).

use super::{irql, thread, time};
use crate::hal::platform;
use crate::mm::stack::Stack;
use crate::{arch, mm};
use core::sync::atomic::{AtomicU64, Ordering};
use nk_bootinfo::BootInfo;

/// Bit `n` is set once processor `n` is running. The boot processor is.
static ONLINE: AtomicU64 = AtomicU64::new(1);

/// How long a processor gets to report in: 100 ns units. Generous; an
/// emulated machine with many processors starts them slowly.
const START_TIMEOUT: u64 = 5 * 10_000_000;

/// The lowest address of the stack each processor started on, which
/// becomes its idle thread's.
static STACKS: [AtomicU64; platform::MAX_CPUS] = [const { AtomicU64::new(0) }; platform::MAX_CPUS];

/// Record the stack processor `number` starts on.
pub fn set_stack(number: usize, stack: Stack) {
    STACKS[number].store(stack.base, Ordering::Release);
}

/// The stack processor `number` started on.
pub fn stack_of(number: usize) -> Stack {
    let base = STACKS[number].load(Ordering::Acquire);
    Stack {
        base,
        top: base + nk_bootinfo::KERNEL_STACK_SIZE,
    }
}

/// The mask of running processors.
pub fn online() -> u64 {
    ONLINE.load(Ordering::Acquire)
}

pub fn online_count() -> usize {
    ONLINE.load(Ordering::Acquire).count_ones() as usize
}

pub fn is_online(number: usize) -> bool {
    ONLINE.load(Ordering::Acquire) & 1 << number != 0
}

/// Start every processor firmware listed besides this one. Returns how
/// many are running; a processor that cannot be started is an error.
pub fn start_all(info: &BootInfo) -> Result<usize, &'static str> {
    let cpus = platform::get().cpus().len();
    if cpus > 1 {
        arch::smp_prepare(info)?;
    }
    for number in 1..cpus {
        if !arch::cpu_prepare(number) {
            return Err("no memory for a processor's state");
        }
        super::dpc::prepare_cpu(number)?;
        let stack = mm::stack::alloc().ok_or("no memory for a processor's stack")?;
        set_stack(number, stack);
        arch::cpu_start(number, stack.top)?;
        let deadline = time::interrupt_time() + START_TIMEOUT;
        while !is_online(number) {
            if time::interrupt_time() > deadline {
                kprintln!("ke: processor {number} did not start");
                return Err("a processor did not start");
            }
            core::hint::spin_loop();
        }
    }
    if cpus > 1 {
        arch::smp_finish();
    }
    Ok(online_count())
}

/// Where a started processor arrives once the architecture layer has set
/// up its tables, its PCR and its interrupt controller.
pub fn ap_main(number: usize) -> ! {
    debug_assert_eq!(super::pcr::current_processor() as usize, number);
    arch::set_irql(irql::PASSIVE_LEVEL);
    time::start_cpu();
    // The stack this processor was started on becomes its idle thread's.
    if let Err(why) = thread::init_cpu(stack_of(number)) {
        panic!("processor {number}: {why}");
    }
    ONLINE.fetch_or(1 << number, Ordering::Release);
    arch::enable_interrupts();
    thread::idle_loop()
}

/// Every processor firmware listed is running, and each takes its own
/// clock interrupts. Returns the number running.
pub fn self_test() -> Result<usize, &'static str> {
    let cpus = platform::get().cpus().len();
    if online_count() != cpus {
        return Err("not every processor firmware listed is running");
    }
    let before: [u64; platform::MAX_CPUS] =
        core::array::from_fn(|n| arch::percpu_of(n).map_or(0, |p| p.ticks()));
    time::stall(250_000);
    for (number, &was) in before.iter().enumerate().take(cpus) {
        let now = arch::percpu_of(number).map_or(0, |p| p.ticks());
        // 16 expected in a quarter second.
        if now - was < 8 {
            return Err("a processor is not taking clock interrupts");
        }
    }
    Ok(cpus)
}
