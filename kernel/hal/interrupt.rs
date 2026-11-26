//! Device interrupts below the interrupt object: which vector, IRQL and
//! processor an interrupt source gets, and the controller's side of
//! turning it on and off.
//!
//! A device's interrupt is *raw* as firmware or the bus names it (a
//! line: a global system interrupt and how it signals; or a request for
//! some number of message-signalled interrupts) and *translated* once
//! it has a vector, the IRQL its service routine runs at, and the
//! processors it may arrive on. [`translate`] turns the one into the
//! other. It is what the Plug and Play manager calls when it builds a
//! device's translated resource list, and the translated form is what a
//! driver hands back to `IoConnectInterruptEx` (`io::interrupt`).
//!
//! The architecture supplies the controller (`kernel/arch`): on x86-64
//! the I/O APICs and the message format of the local APIC, on arm64 the
//! GIC's shared peripheral interrupts. A vector is the vector number on
//! x86-64, where the IRQL is its upper four bits, and the interrupt id
//! on arm64.
//!
//! Each interrupt goes to one processor, chosen among those its
//! affinity allows and that are running, by its vector, so that
//! different interrupts go to different processors.

use crate::arch::{self, InterruptVectors};
use crate::ke::{self, Rank, SpinLock};
pub use nk_hal::interrupt::{Line, Polarity, Trigger};
use nk_ntabi::interrupt::{INTERRUPT_CONNECTION_CONTROLLER_INPUT, INTERRUPT_VECTOR_DATA};
use nk_ntabi::status::{
    NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_NO_SUCH_DEVICE,
    STATUS_NOT_SUPPORTED, STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};

/// An interrupt source before it has a vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Raw {
    /// An interrupt line.
    Line(Line),
    /// This many message-signalled interrupts, whose vectors are
    /// consecutive: a power of two, at most 16.
    Messages(u32),
}

/// An interrupt source with a vector: what a translated interrupt
/// resource holds (`Level`, `Vector`, `Affinity`). For messages, the
/// first vector; the rest follow it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Translated {
    /// The IRQL the service routine runs at.
    pub level: u8,
    pub vector: u32,
    /// The processors the interrupt may arrive on: one.
    pub affinity: u64,
}

/// What is known of a vector that a translation gave out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Info {
    pub level: u8,
    /// The processor the interrupt is sent to.
    pub processor: u8,
    /// The line, or `None` for a message.
    pub line: Option<Line>,
}

#[derive(Clone, Copy)]
struct Entry {
    info: Info,
    /// The first vector of the block this one was given out in, and for
    /// that first vector how many there are and how many translations
    /// share them.
    first: u32,
    count: u32,
    users: u32,
    /// Whether the line is unmasked: an interrupt object is connected.
    enabled: bool,
}

const VECTORS: usize = 1024;

/// How many lines the interrupt arbiter may have moved to a vector of
/// its choosing while a translation made before still names the old.
const MOVED: usize = 8;

struct State {
    vectors: InterruptVectors,
    entries: [Option<Entry>; VECTORS],
    /// Lines the interrupt arbiter moved: the vector a translation gave
    /// out, which stays taken, and the vector the line raises now.
    moved: [Option<(u32, u32)>; MOVED],
}

impl State {
    /// The vector that what was translated as `vector` raises now.
    fn current(&self, vector: u32) -> u32 {
        self.moved
            .iter()
            .flatten()
            .find(|moved| moved.0 == vector)
            .map_or(vector, |moved| moved.1)
    }
}

/// Which vectors are given out, and the controllers' registers.
static STATE: SpinLock<State> = SpinLock::new(
    Rank::InterruptRouting,
    State {
        vectors: InterruptVectors::new(),
        entries: [None; VECTORS],
        moved: [None; MOVED],
    },
);

/// What picks a vector's processor: vectors given out one after another
/// differ in it, whether they differ by one or by sixteen.
fn spread(vector: u32) -> u32 {
    vector / 16 + vector % 16
}

/// Give an interrupt source a vector, an IRQL and a processor among
/// those `affinity` allows. A line that already has a vector keeps it:
/// devices that share a line share the vector. The line stays masked
/// until an interrupt object is connected. Undone by [`release`].
///
/// - `STATUS_INVALID_PARAMETER`: no running processor is allowed; the
///   line already has a vector and signals differently; a message
///   count that is not a power of two up to 16.
/// - `STATUS_NO_SUCH_DEVICE`: no interrupt controller has such a line.
/// - `STATUS_NOT_SUPPORTED`: messages, where NK cannot deliver them.
/// - `STATUS_INSUFFICIENT_RESOURCES`: no vector is free.
pub fn translate(raw: Raw, affinity: u64) -> Result<Translated, NTSTATUS> {
    let allowed = affinity & ke::smp::online();
    let mut state = STATE.lock();
    let translated = |vector: u32, info: Info| Translated {
        level: info.level,
        vector,
        affinity: 1 << info.processor,
    };
    match raw {
        Raw::Line(line) => {
            let existing = state.entries.iter_mut().enumerate().find_map(|(v, e)| {
                e.as_mut()
                    .filter(|e| e.info.line.is_some_and(|l| l.gsi == line.gsi))
                    .map(|e| (v as u32, e))
            });
            if let Some((vector, entry)) = existing {
                if entry.info.line != Some(line) {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                entry.users += 1;
                return Ok(translated(vector, entry.info));
            }
            let (vector, level) = state
                .vectors
                .line(line.gsi)
                .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
            let Some(processor) = nk_hal::interrupt::target(allowed, spread(vector)) else {
                state.vectors.release(vector, 1);
                return Err(STATUS_INVALID_PARAMETER);
            };
            if !arch::line_route(line, vector, level, usize::from(processor)) {
                state.vectors.release(vector, 1);
                return Err(STATUS_NO_SUCH_DEVICE);
            }
            let info = Info {
                level,
                processor,
                line: Some(line),
            };
            state.entries[vector as usize] = Some(Entry {
                info,
                first: vector,
                count: 1,
                users: 1,
                enabled: false,
            });
            Ok(translated(vector, info))
        }
        Raw::Messages(count) => {
            if !count.is_power_of_two() || count > 16 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            let Some(processor) = nk_hal::interrupt::target(allowed, 0) else {
                return Err(STATUS_INVALID_PARAMETER);
            };
            // Whether a message can be composed at all, for any vector.
            if arch::interrupt_message(0, usize::from(processor)).is_none() {
                return Err(STATUS_NOT_SUPPORTED);
            }
            let (first, level) = state
                .vectors
                .messages(count)
                .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
            let processor = nk_hal::interrupt::target(allowed, spread(first)).unwrap_or(processor);
            let info = Info {
                level,
                processor,
                line: None,
            };
            for vector in first..first + count {
                state.entries[vector as usize] = Some(Entry {
                    info,
                    first,
                    count,
                    users: 1,
                    enabled: false,
                });
            }
            Ok(translated(first, info))
        }
    }
}

/// Undo one [`translate`] that returned `vector`. When the last is
/// undone the vector is free again, and a line masked.
pub fn release(vector: u32) {
    let mut state = STATE.lock();
    let vector = state.current(vector);
    let Some(entry) = state
        .entries
        .get_mut(vector as usize)
        .and_then(Option::as_mut)
    else {
        return;
    };
    let (first, count) = (entry.first, entry.count);
    let Some(Some(head)) = state.entries.get_mut(first as usize) else {
        return;
    };
    head.users -= 1;
    if head.users != 0 {
        return;
    }
    if let Some(line) = head.info.line {
        arch::line_enable(line.gsi, false);
    }
    for v in first..first + count {
        state.entries[v as usize] = None;
    }
    state.vectors.release(first, count);
    // The vectors its translations named before the arbiter moved it.
    for at in 0..MOVED {
        if let Some((old, _)) = state.moved[at].filter(|moved| moved.1 == first) {
            state.vectors.release(old, 1);
            state.moved[at] = None;
        }
    }
}

/// Where the interrupt translated as `vector` arrives now, and what is
/// known of it: the same vector, unless the interrupt arbiter has since
/// moved its line to another ([`assign_line`]).
pub fn placed(vector: u32) -> Option<(u32, Info)> {
    let state = STATE.lock();
    let current = state.current(vector);
    state
        .entries
        .get(current as usize)
        .and_then(|e| e.as_ref())
        .map(|e| (current, e.info))
}

/// The interrupt arbiter's decision for a line: `line` raises `vector`,
/// at IRQL `level`, on a processor of `affinity`. Windows' arbiter is
/// in `acpi.sys`, which chooses the vector itself and has the HAL carry
/// the choice out (`HalAddInterruptRemapping`).
///
/// A line NK already translated to another vector is moved, unless an
/// interrupt object is connected to it: the old vector stays taken
/// until the translations are released, and they find the line where
/// it is now ([`placed`], [`release`]). A line with no translation is
/// routed as one would route it, masked.
///
/// - `STATUS_INVALID_PARAMETER`: no running processor is allowed; the
///   IRQL is not the vector's; the line has that vector already and
///   signals differently.
/// - `STATUS_UNSUCCESSFUL`: the vector is not a free device vector; the
///   line is in use; more lines were moved than NK keeps track of.
/// - `STATUS_NO_SUCH_DEVICE`: no interrupt controller has such a line.
pub fn assign_line(line: Line, vector: u32, level: u8, affinity: u64) -> Result<(), NTSTATUS> {
    let allowed = affinity & ke::smp::online();
    let Some(processor) = nk_hal::interrupt::target(allowed, spread(vector)) else {
        return Err(STATUS_INVALID_PARAMETER);
    };
    let mut state = STATE.lock();
    let existing = state.entries.iter().enumerate().find_map(|(v, e)| {
        e.as_ref()
            .filter(|e| e.info.line.is_some_and(|l| l.gsi == line.gsi))
            .map(|e| (v as u32, *e))
    });
    let mut slot = None;
    if let Some((at, entry)) = existing {
        if at == vector {
            return if entry.info.line == Some(line) && entry.info.level == level {
                Ok(())
            } else {
                Err(STATUS_INVALID_PARAMETER)
            };
        }
        slot = state.moved.iter().position(Option::is_none);
        if entry.enabled || slot.is_none() {
            return Err(STATUS_UNSUCCESSFUL);
        }
    }
    if vector as usize >= VECTORS {
        return Err(STATUS_UNSUCCESSFUL);
    }
    match state.vectors.claim(vector, line.gsi) {
        None => return Err(STATUS_UNSUCCESSFUL),
        Some(own) if own != level => {
            state.vectors.release(vector, 1);
            return Err(STATUS_INVALID_PARAMETER);
        }
        Some(_) => {}
    }
    if !arch::line_route(line, vector, level, usize::from(processor)) {
        state.vectors.release(vector, 1);
        return Err(STATUS_NO_SUCH_DEVICE);
    }
    let mut users = 1;
    if let (Some((at, entry)), Some(slot)) = (existing, slot) {
        state.entries[at as usize] = None;
        state.moved[slot] = Some((at, vector));
        users = entry.users;
    }
    state.entries[vector as usize] = Some(Entry {
        info: Info {
            level,
            processor,
            line: Some(line),
        },
        first: vector,
        count: 1,
        users,
        enabled: false,
    });
    Ok(())
}

/// `HalPrivateDispatchTable.HalAddInterruptRemapping`: the interrupt
/// arbiter in `acpi.sys` has the HAL carry out what it decided for
/// `count` interrupts, each an `INTERRUPT_VECTOR_DATA` at `vectors`.
/// The name is for what Windows' HAL also does here when an IOMMU
/// remaps interrupts; without one, as on NK, it programs the line. The
/// first four arguments name the device to an IOMMU and are not used.
///
/// A line is given the vector, IRQL and processors stated
/// ([`assign_line`]); as in Windows' routine, the mark that a
/// remapping entry is allocated is cleared in each. Partial: a message
/// stops the system, naming itself; NK's own translation gives out
/// messages (`translate`), and nothing NK runs has the arbiter place
/// one.
///
/// # Safety
/// `vectors` points to `count` writable `INTERRUPT_VECTOR_DATA`.
#[allow(non_snake_case)]
pub unsafe extern "C" fn HalAddInterruptRemapping(
    _bus: u32,
    _slot: u32,
    _device: usize,
    _flag: u8,
    vectors: *mut INTERRUPT_VECTOR_DATA,
    count: u32,
) -> NTSTATUS {
    for at in 0..count as usize {
        // SAFETY: per the contract; the driver's memory is read once,
        // by value, and one word of it written.
        let data = unsafe {
            let entry = vectors.add(at);
            let remap = (&raw mut (*entry).IntRemapInfo).cast::<u32>();
            remap.write_unaligned(remap.read_unaligned() & !(1 << 30));
            entry.read_unaligned()
        };
        if data.Type != INTERRUPT_CONNECTION_CONTROLLER_INPUT {
            crate::kd::bugcheck(format_args!(
                "HalAddInterruptRemapping: NK does not implement the arbiter's placing of an \
                 interrupt of type {} (vector {:#x})",
                data.Type, data.Vector
            ));
        }
        let Some(line) = Line::from_vector_data(data.ControllerInputGsiv, data.Polarity, data.Mode)
        else {
            return STATUS_INVALID_PARAMETER;
        };
        if data.TargetProcessors.Group != 0 {
            return STATUS_INVALID_PARAMETER;
        }
        let affinity = data.TargetProcessors.Mask as u64;
        if let Err(status) = assign_line(line, data.Vector, data.Irql, affinity) {
            return status;
        }
    }
    STATUS_SUCCESS
}

/// What is known of `vector`, if a translation gave it out.
pub fn info(vector: u32) -> Option<Info> {
    let state = STATE.lock();
    state
        .entries
        .get(vector as usize)
        .and_then(|e| e.as_ref())
        .map(|e| e.info)
}

/// The line an ISA interrupt (0 to 15) arrives on, where the machine
/// has ISA interrupts: the MADT's interrupt source overrides say which
/// global system interrupt, and how it signals.
pub fn isa(irq: u8) -> Option<Line> {
    arch::isa_line(irq)
}

/// What a device writes, and where, to raise a message vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message {
    pub address: u64,
    pub data: u32,
}

/// The message for `vector`, one a translation of messages gave out.
/// The bus driver programs it into the device.
pub fn message(vector: u32) -> Option<Message> {
    let info = info(vector).filter(|i| i.line.is_none())?;
    arch::interrupt_message(vector, usize::from(info.processor))
        .map(|(address, data)| Message { address, data })
}

/// Let the interrupt on `vector` arrive, or hold it back: a line is
/// unmasked or masked at its controller. A message has no gate here;
/// its device is told to stop by its driver.
pub fn enable(vector: u32, on: bool) {
    let mut state = STATE.lock();
    if let Some(entry) = state
        .entries
        .get_mut(vector as usize)
        .and_then(|e| e.as_mut())
        && let Some(line) = entry.info.line
    {
        entry.enabled = on;
        arch::line_enable(line.gsi, on);
    }
}

/// The HAL's ACPI table, `HalInterruptGetApicVersion`: what `acpi.sys`
/// takes for the version register of the interrupt controller whose
/// lines start at the global system interrupt `gsi_base`, from which it
/// learns how many lines the controller has
/// (`nk_hal::interrupt::apic_version`).
#[allow(non_snake_case)]
pub extern "C" fn HalInterruptGetApicVersion(gsi_base: u32) -> u32 {
    let lines = {
        // The controllers' registers are read under the lock.
        let _state = STATE.lock();
        arch::line_set(gsi_base)
    };
    nk_hal::interrupt::apic_version(lines.map(|(_, count)| count))
}

/// `HalPrivateDispatchTable.HalIsInterruptTypeSecondary`: whether the
/// interrupt `gsiv`, of the kind `kind`, belongs to an interrupt
/// controller behind another interrupt. Never: NK serves no such
/// controller, so no interrupt number is in a secondary range.
/// `acpi.sys`'s arbiter asks it of every line it gives out.
#[allow(non_snake_case)]
pub extern "C" fn HalIsInterruptTypeSecondary(_kind: u32, _gsiv: u32) -> u8 {
    0
}

/// Put the routines of this file in their slots.
pub fn init() {
    use super::dispatch::{HalAcpiDispatchTable, HalPrivateDispatchTable, acpi_slot, private_slot};
    HalPrivateDispatchTable.provide(
        private_slot("HalIsInterruptTypeSecondary"),
        HalIsInterruptTypeSecondary as *const (),
    );
    HalPrivateDispatchTable.provide(
        private_slot("HalAddInterruptRemapping"),
        HalAddInterruptRemapping as *const (),
    );
    HalAcpiDispatchTable.provide(
        acpi_slot("HalInterruptGetApicVersion"),
        HalInterruptGetApicVersion as *const (),
    );
}

/// For the self-tests: the controller's version asked as `acpi.sys`
/// asks it, through the slot at Windows' offset, for the first line a
/// controller has and for one no controller has.
pub fn version_test() -> Result<(), &'static str> {
    // SAFETY: the slot holds `HalInterruptGetApicVersion`, of this type.
    let version: extern "C" fn(u32) -> u32 = unsafe {
        core::mem::transmute(
            super::dispatch::HalAcpiDispatchTable
                .address()
                .cast::<u8>()
                .add(0x40)
                .cast::<*const ()>()
                .read(),
        )
    };
    let Some((base, count)) = ({
        let _state = STATE.lock();
        (0..64).find_map(arch::line_set)
    }) else {
        return Err("no controller has a line among the first 64");
    };
    let answer = version(base);
    if answer & 0xFF != 0x11
        || answer >> 24 != count & 0xFF
        || answer >> 16 & 0xFF != (count - 1) & 0xFF
        || version(base + count - 1) != answer
    {
        return Err("the version does not tell the controller's line count");
    }
    if version(0xFFFF_0000) != 0xF000_0000 {
        return Err("a version was made up for lines no controller has");
    }
    // SAFETY: the slot holds `HalIsInterruptTypeSecondary`, of this type.
    let secondary: extern "C" fn(u32, u32) -> u8 = unsafe {
        core::mem::transmute(
            super::dispatch::HalPrivateDispatchTable
                .address()
                .cast::<u8>()
                .add(0x1f0)
                .cast::<*const ()>()
                .read(),
        )
    };
    if secondary(0, base) != 0 || secondary(0, u32::MAX) != 0 {
        return Err("a line was called secondary on a machine with no secondary controller");
    }
    Ok(())
}

/// For the self-tests: the interrupt arbiter's decisions carried out
/// as `acpi.sys` asks, through the slot at Windows' offset, for a line
/// nothing uses. Returns whether the line could be moved to a vector
/// of the arbiter's choosing, which a line whose vector is its own
/// number cannot.
pub fn arbiter_test() -> Result<bool, &'static str> {
    type Add =
        unsafe extern "C" fn(u32, u32, usize, u8, *mut INTERRUPT_VECTOR_DATA, u32) -> NTSTATUS;
    // SAFETY: the slot holds `HalAddInterruptRemapping`, of this type.
    let add: Add = unsafe {
        core::mem::transmute(
            super::dispatch::HalPrivateDispatchTable
                .address()
                .cast::<u8>()
                .add(0x200)
                .cast::<*const ()>()
                .read(),
        )
    };
    // The last line of the first controller that no translation uses.
    let free = {
        let state = STATE.lock();
        (0..64).find_map(arch::line_set).and_then(|(base, count)| {
            (base..base + count).rev().find(|&gsi| {
                !state
                    .entries
                    .iter()
                    .flatten()
                    .any(|e| e.info.line.is_some_and(|l| l.gsi == gsi))
            })
        })
    };
    let Some(gsi) = free else {
        return Err("every line of the first controller is in use");
    };
    let line = Line {
        gsi,
        trigger: Trigger::Level,
        polarity: Polarity::High,
    };
    let Ok(first) = translate(Raw::Line(line), u64::MAX) else {
        return Err("a free line was not translated");
    };
    let stated = |vector: u32, level: u8, polarity: u32| INTERRUPT_VECTOR_DATA {
        Type: INTERRUPT_CONNECTION_CONTROLLER_INPUT,
        Vector: vector,
        Irql: level,
        Polarity: polarity,
        Mode: line.trigger.mode(),
        TargetProcessors: nk_ntabi::interrupt::GROUP_AFFINITY {
            Mask: first.affinity as usize,
            Group: 0,
            Reserved: [0; 3],
        },
        IntRemapInfo: [1 << 30 | 5, 0, 0, 0],
        ControllerInputGsiv: gsi,
        HvDeviceId: 0,
        Message: [0; 2],
    };
    let ask = |mut data: INTERRUPT_VECTOR_DATA| {
        // SAFETY: one local structure.
        let status = unsafe { add(0, 0, 0, 0, &raw mut data, 1) };
        (status, data.IntRemapInfo[0])
    };
    // What a line-based connection takes from connection data that
    // names the line: found while the line is placed.
    let property = nk_pnp::connection::connection_data(&[nk_pnp::connection::Delivery {
        vector: first.vector,
        irql: first.level,
        affinity: first.affinity,
        source: nk_pnp::connection::Source::Line {
            gsi,
            edge: false,
            low: false,
        },
    }]);
    if crate::io::interrupt::stated_line_in(&property) != Some((first.vector, first.level)) {
        release(first.vector);
        return Err("connection data that names a placed line states no line");
    }
    let result = (|| {
        // Where it is already: nothing to do, and the mark is cleared.
        if ask(stated(first.vector, first.level, 1)) != (STATUS_SUCCESS, 5) {
            return Err("the arbiter's decision for a line where it is was not taken");
        }
        if ask(stated(first.vector, first.level, 3)).0 != STATUS_INVALID_PARAMETER
            || ask(stated(first.vector, first.level, 2)).0 != STATUS_INVALID_PARAMETER
        {
            return Err("a line that signals otherwise was taken");
        }
        // A neighbouring vector of the same IRQL class, where a vector
        // can be chosen at all.
        let other = first.vector ^ 1;
        let (status, _) = ask(stated(other, first.level, 1));
        let now = placed(first.vector).map(|(vector, info)| (vector, info.line));
        let moved = match status {
            STATUS_SUCCESS => {
                if now != Some((other, Some(line))) || info(first.vector).is_some() {
                    return Err("a line the arbiter moved is not at its new vector");
                }
                true
            }
            STATUS_UNSUCCESSFUL => {
                if now != Some((first.vector, Some(line))) {
                    return Err("a line that could not be moved did not stay");
                }
                false
            }
            _ => return Err("the arbiter's choice of another vector got an unexpected answer"),
        };
        if ask(stated(other, first.level + 1, 1)).0 == STATUS_SUCCESS {
            return Err("an IRQL that is not the vector's was taken");
        }
        Ok(moved)
    })();
    release(first.vector);
    if placed(first.vector).is_some() || info(first.vector ^ 1).is_some() {
        return Err("releasing the translation did not free the line");
    }
    if crate::io::interrupt::stated_line_in(&property).is_some() {
        return Err("connection data left from a withdrawn line still states it");
    }
    result
}

/// Whether `vector` is in the range device interrupts have.
pub fn is_device_vector(vector: u32) -> bool {
    InterruptVectors::is_device(vector) && (vector as usize) < VECTORS
}
