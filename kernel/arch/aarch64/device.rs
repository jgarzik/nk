//! Device interrupt lines: the GIC's shared peripheral interrupts.
//!
//! A line's global system interrupt is its GIC interrupt id, and that
//! id is also what the kernel calls its vector. The distributor holds,
//! per interrupt, a priority (from the IRQL NK gives it), whether it is
//! edge triggered, and the processor it is routed to. Every line is
//! disabled until an interrupt object is connected to it. The
//! distributor's registers are written under the lock of
//! `hal::interrupt`, which the caller holds.
//!
//! There are no message-signalled interrupts: they need the GIC's
//! interrupt translation service (or a GICv2m frame), which NK does not
//! drive.

use super::gic;
use crate::hal::platform;
use crate::mm;
use nk_hal::arm::{SPI_BASE, bit_of, config_of, priority, route_to, spi_level};
use nk_hal::interrupt::{Line, Polarity, Trigger};

const GICD_IGROUPR: usize = 0x080;
const GICD_ISENABLER: usize = 0x100;
const GICD_ICENABLER: usize = 0x180;
const GICD_IPRIORITYR: usize = 0x400;
const GICD_ICFGR: usize = 0xC00;
const GICD_IROUTER: usize = 0x6000;

/// Whether `intid` is a shared peripheral interrupt this distributor
/// has.
fn is_line(intid: u32) -> bool {
    (SPI_BASE..gic::lines()).contains(&intid)
}

/// Have `line` interrupt processor `processor` at IRQL `level`,
/// disabled for now. `false` if the distributor has no such interrupt,
/// or the line is active low, which the GIC cannot be told: a board
/// inverts such a line before the GIC sees it.
pub fn line_route(line: Line, _vector: u32, level: u8, processor: usize) -> bool {
    let intid = line.gsi;
    if !is_line(intid) || line.polarity == Polarity::Low {
        return false;
    }
    let distributor = gic::distributor();
    let (word, bit) = bit_of(intid);
    gic::write32(distributor, GICD_ICENABLER + word, bit);
    // Group 1, the group this kernel takes as ordinary interrupts.
    gic::write32(
        distributor,
        GICD_IGROUPR + word,
        gic::read32(distributor, GICD_IGROUPR + word) | bit,
    );
    // SAFETY: the interrupt's priority byte and its routing register,
    // in the distributor's frame.
    unsafe {
        ((distributor as usize + GICD_IPRIORITYR + intid as usize) as *mut u8)
            .write_volatile(priority(level));
        ((distributor as usize + GICD_IROUTER + 8 * intid as usize) as *mut u64)
            .write_volatile(route_to(platform::get().cpus()[processor].hw_id));
    }
    let (word, edge) = config_of(intid);
    let config = gic::read32(distributor, GICD_ICFGR + word);
    gic::write32(
        distributor,
        GICD_ICFGR + word,
        match line.trigger {
            Trigger::Edge => config | edge,
            Trigger::Level => config & !edge,
        },
    );
    true
}

/// Enable or disable the line `gsi`.
pub fn line_enable(gsi: u32, on: bool) {
    if is_line(gsi) {
        let (word, bit) = bit_of(gsi);
        let register = if on { GICD_ISENABLER } else { GICD_ICENABLER };
        gic::write32(gic::distributor(), register + word, bit);
    }
}

/// ISA interrupts: arm64 has none.
pub fn isa_line(_irq: u8) -> Option<Line> {
    None
}

/// How a level-triggered line signals when all that is known of it is
/// a resource descriptor: active high, the only kind the GIC takes.
pub fn level_line_polarity() -> nk_hal::interrupt::Polarity {
    nk_hal::interrupt::Polarity::High
}

/// The hardware identifier of the HAL's own device: what Windows' arm64
/// HAL answers is not known to NK (no arm64 kernel is pinned), so the
/// device has none.
pub fn hal_hardware_id() -> Option<&'static str> {
    None
}

/// The interrupts the HAL offers the ACPI driver's device: none, until
/// the rule of Windows' arm64 HAL is known.
pub fn acpi_device_interrupts() -> &'static [(u32, u32)] {
    &[]
}

/// The message a device writes to interrupt a processor: there is none
/// to give without an interrupt translation service.
pub fn interrupt_message(_vector: u32, _processor: usize) -> Option<(u64, u32)> {
    None
}

/// Which vectors device interrupts have: a line's is its interrupt id,
/// so there is nothing to keep.
pub struct InterruptVectors;

impl InterruptVectors {
    /// Devices cannot be given messages: NK drives no ITS.
    pub const MESSAGES: bool = false;

    pub const fn new() -> Self {
        Self
    }

    /// The vector and IRQL of the line `gsi`.
    pub fn line(&mut self, gsi: u32) -> Option<(u32, u8)> {
        is_line(gsi).then(|| (gsi, spi_level(gsi)))
    }

    /// Vectors for a device's messages: none.
    pub fn messages(&mut self, _count: u32) -> Option<(u32, u8)> {
        None
    }

    /// Nothing was taken.
    pub fn release(&mut self, _vector: u32, _count: u32) {}

    /// Whether `vector` is one a device interrupt can have.
    pub fn is_device(vector: u32) -> bool {
        is_line(vector)
    }
}

/// A source of real interrupts for the self-tests: the console UART's
/// transmit interrupt. A PL011 asks for service whenever its transmit
/// queue has room and the interrupt is unmasked, so unmasking it is
/// asking, and masking it is being served. The console itself never
/// unmasks it.
pub struct TestSource {
    /// The UART's registers, mapped.
    registers: *mut u8,
    gsi: u32,
    /// The interrupt mask as found.
    was: u32,
}

// SAFETY: the pointer names device registers; the service routine and
// the test use them from different processors by volatile accesses of
// whole registers.
unsafe impl Sync for TestSource {}
// SAFETY: as above.
unsafe impl Send for TestSource {}

const UART_MASK: usize = 0x038;
const UART_MASKED_STATUS: usize = 0x040;
const UART_TRANSMIT: u32 = 1 << 5;
const UART_PAGE: usize = 0x1000;

impl TestSource {
    fn get(&self, offset: usize) -> u32 {
        // SAFETY: a register of the UART, mapped by `find`.
        unsafe { self.registers.add(offset).cast::<u32>().read_volatile() }
    }

    fn put(&self, offset: usize, value: u32) {
        // SAFETY: as in `get`.
        unsafe {
            self.registers
                .add(offset)
                .cast::<u32>()
                .write_volatile(value)
        }
    }

    /// The console UART, if firmware describes it with its interrupt.
    pub fn find() -> Option<Self> {
        let (address, gsi) = platform::get().firmware.console?;
        let registers = mm::io::map_physical(
            address,
            UART_PAGE,
            nk_mm::protect::protection(
                nk_mm::protect::PAGE_READWRITE | nk_mm::protect::PAGE_NOCACHE,
            )?,
        )?;
        let mut source = Self {
            registers,
            gsi,
            was: 0,
        };
        source.was = source.get(UART_MASK);
        source.quiet();
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

    /// Make the device ask for service.
    pub fn fire(&self) {
        self.put(UART_MASK, UART_TRANSMIT);
    }

    /// Whether the device is asking for service.
    pub fn asking(&self) -> bool {
        self.get(UART_MASKED_STATUS) & UART_TRANSMIT != 0
    }

    /// Serve the device: it stops asking.
    pub fn quiet(&self) {
        self.put(UART_MASK, 0);
    }
}

impl Drop for TestSource {
    fn drop(&mut self) {
        self.put(UART_MASK, self.was);
        mm::io::unmap_physical(self.registers, UART_PAGE);
    }
}
