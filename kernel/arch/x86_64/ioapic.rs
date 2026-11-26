//! The I/O APICs: where device interrupt lines arrive, and the message a
//! device sends instead of using a line.
//!
//! Each input of an I/O APIC (a global system interrupt) has a
//! redirection register saying which vector it raises, on which
//! processor, and how the line signals. Every input is masked until an
//! interrupt object is connected to its vector. The registers are behind
//! an index register, so their use is serialised: by the caller, which
//! holds the lock of `hal::interrupt`.
//!
//! A level-triggered interrupt needs no acknowledgement here beyond the
//! local APIC's end-of-interrupt, which the local APIC passes on.

use super::smp;
use crate::hal::platform;
use crate::mm;
use nk_hal::interrupt::{Line, Polarity, Trigger};
use nk_hal::x86::{
    DEVICE_VECTORS, IoApic, REDIRECTION_MASKED, VectorMap, io_apic_inputs, irql_of_vector, message,
    redirection, redirection_target,
};

const INDEX: usize = 0x00;
const DATA: usize = 0x10;
const REG_VERSION: u32 = 1;
const REG_REDIRECTION: u32 = 0x10;

fn read(io: &IoApic, register: u32) -> u32 {
    let base = mm::phys_to_virt(io.address);
    // SAFETY: the I/O APIC's register page in the direct map: an index
    // register and a data register, read and written volatile.
    unsafe {
        base.add(INDEX).cast::<u32>().write_volatile(register);
        base.add(DATA).cast::<u32>().read_volatile()
    }
}

fn write(io: &IoApic, register: u32, value: u32) {
    let base = mm::phys_to_virt(io.address);
    // SAFETY: as in `read`.
    unsafe {
        base.add(INDEX).cast::<u32>().write_volatile(register);
        base.add(DATA).cast::<u32>().write_volatile(value);
    }
}

/// Mask every input of every I/O APIC: firmware may have left some
/// routed (its timer, for one).
pub fn init() {
    for io in platform::get().controllers.io_apics() {
        for input in 0..io_apic_inputs(read(io, REG_VERSION)) {
            let register = REG_REDIRECTION + 2 * input;
            write(io, register, read(io, register) | REDIRECTION_MASKED);
        }
    }
}

/// The I/O APIC that global system interrupt `gsi` is an input of, and
/// the low register of that input.
fn input(gsi: u32) -> Option<(&'static IoApic, u32)> {
    platform::get()
        .controllers
        .io_apics()
        .iter()
        .find_map(|io| {
            let input = gsi.checked_sub(io.gsi_base)?;
            (input < io_apic_inputs(read(io, REG_VERSION)))
                .then_some((io, REG_REDIRECTION + 2 * input))
        })
}

/// Have `line` raise `vector` on processor `processor`, masked for now.
/// `false` if no I/O APIC has that input or the processor cannot be
/// named in a redirection register.
pub fn line_route(line: Line, vector: u32, _level: u8, processor: usize) -> bool {
    let (Some((io, register)), Some(target)) = (
        input(line.gsi),
        redirection_target(smp::hardware_id(processor)),
    ) else {
        return false;
    };
    // Masked first, so the input never fires half written.
    write(
        io,
        register,
        redirection(vector, line.trigger, line.polarity, true),
    );
    write(io, register + 1, target);
    true
}

/// Unmask or mask the input `gsi`.
pub fn line_enable(gsi: u32, on: bool) {
    if let Some((io, register)) = input(gsi) {
        let entry = read(io, register);
        write(
            io,
            register,
            if on {
                entry & !REDIRECTION_MASKED
            } else {
                entry | REDIRECTION_MASKED
            },
        );
    }
}

/// The line an ISA interrupt arrives on, by the MADT's interrupt source
/// overrides.
pub fn isa_line(irq: u8) -> Option<Line> {
    platform::get().controllers.isa_line(irq)
}

/// How a level-triggered line that is not an ISA interrupt signals,
/// when all that is known of it is a resource descriptor, which does
/// not say: active low, as PCI's interrupt lines are.
pub fn level_line_polarity() -> nk_hal::interrupt::Polarity {
    nk_hal::interrupt::Polarity::Low
}

/// The hardware identifier of the HAL's own device, as Windows' HAL
/// for this architecture answers it.
pub fn hal_hardware_id() -> Option<&'static str> {
    Some("acpiapic")
}

/// The interrupts the HAL offers the ACPI driver's device, as runs of
/// numbers.
pub fn acpi_device_interrupts() -> &'static [(u32, u32)] {
    const RUNS: [(u32, u32); 2] = nk_hal::x86::acpi_device_interrupts();
    &RUNS
}

/// The address and data a device writes to interrupt `processor` on
/// `vector`.
pub fn interrupt_message(vector: u32, processor: usize) -> Option<(u64, u32)> {
    message(vector, smp::hardware_id(processor))
}

/// Which vectors device interrupts have. A line gets any free vector;
/// its IRQL is the vector's upper four bits.
pub struct InterruptVectors(VectorMap);

impl InterruptVectors {
    /// Devices can be given messages: the local APICs take them.
    pub const MESSAGES: bool = true;

    pub const fn new() -> Self {
        Self(VectorMap::new())
    }

    /// The vectors the interrupt self-test sends itself are not devices'.
    fn taking(&mut self, count: u32) -> Option<(u32, u8)> {
        for (vector, _) in [super::TEST_LOW, super::TEST_HIGH, super::TEST_STRAY] {
            self.0.reserve(vector);
        }
        let vector = self.0.take(count)?;
        Some((vector, irql_of_vector(vector)))
    }

    /// A vector and its IRQL for the line `gsi`.
    pub fn line(&mut self, _gsi: u32) -> Option<(u32, u8)> {
        self.taking(1)
    }

    /// `count` consecutive vectors of one IRQL for a device's messages:
    /// the first vector, and the IRQL.
    pub fn messages(&mut self, count: u32) -> Option<(u32, u8)> {
        self.taking(count)
    }

    /// Give back `count` vectors from `line` or `messages`.
    pub fn release(&mut self, vector: u32, count: u32) {
        self.0.give_back(vector, count);
    }

    /// Whether `vector` is one a device interrupt can have.
    pub fn is_device(vector: u32) -> bool {
        DEVICE_VECTORS.contains(&vector)
    }
}

/// A source of real interrupts for the self-tests: a timer of the high
/// precision event timer, which the kernel does not otherwise use.
///
/// The timer is put in level-triggered, one-shot mode on an I/O APIC
/// input no ISA device has; `fire` sets its comparator a moment ahead,
/// and it then holds its line until its status bit is written.
pub struct TestSource {
    /// The timer block's registers, mapped.
    registers: *mut u8,
    timer: usize,
    gsi: u32,
    /// The block's configuration as found.
    was: u64,
}

// SAFETY: the pointer names device registers; the service routine and
// the test use them from different processors by volatile accesses of
// whole registers.
unsafe impl Sync for TestSource {}
// SAFETY: as above.
unsafe impl Send for TestSource {}

const HPET_CAPABILITIES: usize = 0x000;
const HPET_CONFIGURATION: usize = 0x010;
const HPET_STATUS: usize = 0x020;
const HPET_COUNTER: usize = 0x0F0;
const HPET_ENABLE: u64 = 1;
const TIMER_LEVEL: u64 = 1 << 1;
const TIMER_INTERRUPT: u64 = 1 << 2;
const HPET_PAGE: usize = 0x400;

impl TestSource {
    fn register(&self, offset: usize) -> *mut u64 {
        self.registers.wrapping_add(offset).cast()
    }

    fn get(&self, offset: usize) -> u64 {
        // SAFETY: a 64-bit register of the timer block, mapped by `find`.
        unsafe { self.register(offset).read_volatile() }
    }

    fn put(&self, offset: usize, value: u64) {
        // SAFETY: as in `get`.
        unsafe { self.register(offset).write_volatile(value) }
    }

    fn configuration(&self) -> usize {
        0x100 + 0x20 * self.timer
    }

    fn comparator(&self) -> usize {
        0x108 + 0x20 * self.timer
    }

    /// The machine's event timer, if firmware describes one with a
    /// timer that can be routed to an input above the ISA interrupts.
    pub fn find() -> Option<Self> {
        let address = platform::get().firmware.hpet?;
        let registers = mm::io::map_physical(
            address,
            HPET_PAGE,
            nk_mm::protect::protection(
                nk_mm::protect::PAGE_READWRITE | nk_mm::protect::PAGE_NOCACHE,
            )?,
        )?;
        let mut source = Self {
            registers,
            timer: 0,
            gsi: 0,
            was: 0,
        };
        let timers = (source.get(HPET_CAPABILITIES) >> 8 & 0x1F) as usize + 1;
        // The last timer; the inputs it can use are the upper half of
        // its configuration register.
        source.timer = timers - 1;
        let routes = (source.get(source.configuration()) >> 32) as u32 & !0xFFFF;
        if routes == 0 {
            mm::io::unmap_physical(registers, HPET_PAGE);
            return None;
        }
        source.gsi = 31 - routes.leading_zeros();
        source.was = source.get(HPET_CONFIGURATION);
        source.quiet();
        source.put(HPET_CONFIGURATION, source.was | HPET_ENABLE);
        Some(source)
    }

    /// The line the source interrupts on.
    pub fn line(&self) -> Line {
        Line {
            gsi: self.gsi,
            trigger: Trigger::Level,
            polarity: Polarity::High,
        }
    }

    /// Make the device ask for service, very soon.
    pub fn fire(&self) {
        self.put(
            self.configuration(),
            u64::from(self.gsi) << 9 | TIMER_LEVEL | TIMER_INTERRUPT,
        );
        // The period is in femtoseconds per count: a tenth of a
        // millisecond from now.
        let period = (self.get(HPET_CAPABILITIES) >> 32).max(1);
        let ahead = 100_000_000_000 / period;
        self.put(self.comparator(), self.get(HPET_COUNTER) + ahead);
    }

    /// Whether the device is asking for service.
    pub fn asking(&self) -> bool {
        self.get(HPET_STATUS) & 1 << self.timer != 0
    }

    /// Serve the device: it stops asking. The status bit is written
    /// while the timer still names its input, which is the input the
    /// write releases.
    pub fn quiet(&self) {
        self.put(HPET_STATUS, 1 << self.timer);
        self.put(self.configuration(), u64::from(self.gsi) << 9 | TIMER_LEVEL);
    }
}

impl Drop for TestSource {
    fn drop(&mut self) {
        self.quiet();
        self.put(HPET_CONFIGURATION, self.was);
        mm::io::unmap_physical(self.registers, HPET_PAGE);
    }
}
