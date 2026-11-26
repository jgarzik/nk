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
use nk_ntabi::status::{
    NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_NO_SUCH_DEVICE,
    STATUS_NOT_SUPPORTED,
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
}

const VECTORS: usize = 1024;

struct State {
    vectors: InterruptVectors,
    entries: [Option<Entry>; VECTORS],
}

/// Which vectors are given out, and the controllers' registers.
static STATE: SpinLock<State> = SpinLock::new(
    Rank::InterruptRouting,
    State {
        vectors: InterruptVectors::new(),
        entries: [None; VECTORS],
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
    let state = STATE.lock();
    if let Some(line) = state
        .entries
        .get(vector as usize)
        .and_then(|e| e.as_ref())
        .and_then(|e| e.info.line)
    {
        arch::line_enable(line.gsi, on);
    }
}

/// Whether `vector` is in the range device interrupts have.
pub fn is_device_vector(vector: u32) -> bool {
    InterruptVectors::is_device(vector) && (vector as usize) < VECTORS
}
