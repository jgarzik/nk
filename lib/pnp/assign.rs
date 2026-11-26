//! Which resources a device gets: one list of its requirements turned
//! into a resource list, against what other devices hold.
//!
//! A requirements list states each requirement as a descriptor,
//! optionally followed by alternatives to it
//! (`IO_RESOURCE_ALTERNATIVE`), in the order the driver prefers them.
//! Each requirement is given the first of its choices that can be had:
//! where firmware left the device if that satisfies the choice,
//! otherwise the lowest place the choice allows that nobody holds.
//!
//! NK's own rules, where Windows leaves the choice to a bus driver's
//! arbiter:
//!
//! - One table of claims for the whole machine ([`Claims`]) instead of
//!   an arbiter per bus. A device's ancestors do not stand in its way:
//!   what a bus holds is what its children are given out of.
//! - A line interrupt is given only where the requirement names one
//!   line or firmware configured one: NK routes no interrupts itself.
//! - Message-signalled interrupts are not claimed: the vectors are the
//!   hardware layer's to give out.

use crate::resources::*;
use alloc::vec::Vec;

/// The kinds of numbers devices compete for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Space {
    Port,
    Memory,
    Interrupt,
    BusNumber,
}

/// The space a resource type's numbers are in.
pub const fn space_of(kind: u8) -> Option<Space> {
    match kind {
        TYPE_PORT => Some(Space::Port),
        TYPE_MEMORY | TYPE_MEMORY_LARGE => Some(Space::Memory),
        TYPE_INTERRUPT => Some(Space::Interrupt),
        TYPE_BUS_NUMBER => Some(Space::BusNumber),
        _ => None,
    }
}

/// Numbers `start` to `end` inclusive of one space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range {
    pub space: Space,
    pub start: u64,
    pub end: u64,
    /// Whether the holder lets others have the same numbers
    /// (`CmResourceShareShared`), if they share them too.
    pub shared: bool,
}

impl Range {
    fn overlaps(&self, other: &Range) -> bool {
        self.space == other.space && self.start <= other.end && other.start <= self.end
    }

    /// Whether the two cannot both be held.
    fn excludes(&self, other: &Range) -> bool {
        self.overlaps(other) && !(self.shared && other.shared)
    }
}

/// What every device of the machine holds. A holder is known by a
/// number of the caller's choosing.
#[derive(Debug, Default)]
pub struct Claims {
    held: Vec<(usize, Range)>,
}

impl Claims {
    pub const fn new() -> Self {
        Self { held: Vec::new() }
    }

    /// The claim that keeps `range` from being had, if there is one.
    /// Holders `exempt` says so of do not count.
    pub fn obstacle(&self, range: &Range, exempt: &dyn Fn(usize) -> bool) -> Option<Range> {
        self.held
            .iter()
            .find(|(holder, held)| held.excludes(range) && !exempt(*holder))
            .map(|(_, held)| *held)
    }

    /// Record that `holder` holds `ranges`. `false`, and nothing
    /// recorded, if there is no memory.
    pub fn claim(&mut self, holder: usize, ranges: &[Range]) -> bool {
        if self.held.try_reserve_exact(ranges.len()).is_err() {
            return false;
        }
        self.held
            .extend(ranges.iter().map(|range| (holder, *range)));
        true
    }

    /// Forget what `holder` holds. Returns how many claims that was.
    pub fn release(&mut self, holder: usize) -> usize {
        let before = self.held.len();
        self.held.retain(|(h, _)| *h != holder);
        // What is no longer held takes no memory.
        self.held.shrink_to_fit();
        before - self.held.len()
    }

    /// How many claims `holder` has.
    pub fn count(&self, holder: usize) -> usize {
        self.held.iter().filter(|(h, _)| *h == holder).count()
    }
}

/// Why a list of requirements could not be satisfied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// None of the choices of the requirement that starts at this
    /// descriptor can be had.
    Conflict(usize),
    /// The descriptor at this index is of a kind NK assigns nothing
    /// for.
    Unsupported(usize),
    NoMemory,
}

/// What a device was given.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Assignment {
    /// The partial descriptors of its raw resource list, in the order
    /// of the requirements.
    pub partials: Vec<Partial>,
    /// What it now holds, to be recorded in the [`Claims`].
    pub ranges: Vec<Range>,
}

/// The first multiple of `alignment` at or above `value`.
fn align_up(value: u64, alignment: u64) -> Option<u64> {
    match value % alignment {
        0 => Some(value),
        rest => value.checked_add(alignment - rest),
    }
}

/// One choice for one requirement: where it would go.
struct Choice<'a> {
    descriptor: &'a IoDescriptor,
    space: Space,
    wanted: Wanted,
}

impl Choice<'_> {
    fn shared(&self) -> bool {
        self.descriptor.share == SHARE_SHARED
    }

    fn range(&self, start: u64) -> Range {
        Range {
            space: self.space,
            start,
            end: start + (self.wanted.length - 1),
            shared: self.shared(),
        }
    }

    /// Whether the choice allows `length` numbers from `start`.
    fn allows(&self, start: u64, length: u64) -> bool {
        length == self.wanted.length
            && start % self.wanted.alignment == 0
            && start >= self.wanted.minimum
            && start
                .checked_add(length - 1)
                .is_some_and(|end| end <= self.wanted.maximum)
    }

    /// The descriptor of the device's raw resource list for this
    /// choice placed at `start`.
    fn partial(&self, start: u64) -> Partial {
        let d = self.descriptor;
        if self.space == Space::Interrupt {
            // A line: level and vector are its number; any processor.
            Partial::interrupt(d.share, d.flags, start as u16, 0, start as u32, 0xFFFF_FFFF)
        } else {
            Partial::range(d.kind, d.share, d.flags, start, self.wanted.length)
        }
    }
}

/// Satisfy `list` for a device. `boot` is what firmware configured the
/// device with (its boot configuration), `claims` what the machine's
/// devices hold, and `exempt` says which holders do not stand in this
/// device's way (its ancestors, and itself).
pub fn assign(
    list: &IoList,
    boot: &[Partial],
    claims: &Claims,
    exempt: &dyn Fn(usize) -> bool,
) -> Result<Assignment, Failure> {
    let mut result = Assignment::default();
    let descriptors = &list.descriptors;
    let mut at = 0;
    while at < descriptors.len() {
        // A requirement: a descriptor and the alternatives behind it.
        let mut end = at + 1;
        while end < descriptors.len() && descriptors[end].is_alternative() {
            end += 1;
        }
        let first = &descriptors[at];
        match first.kind {
            TYPE_NULL | TYPE_CONFIG_DATA => {}
            TYPE_DEVICE_PRIVATE => {
                let mut partial = Partial::new(TYPE_DEVICE_PRIVATE, first.share, first.flags);
                partial.data[..12].copy_from_slice(&first.data[..12]);
                push(&mut result.partials, partial)?;
            }
            _ => {
                let placed = descriptors[at..end]
                    .iter()
                    .find_map(|descriptor| place(descriptor, boot, claims, exempt, &result.ranges));
                match placed {
                    Some(Placed::Unsupported) => return Err(Failure::Unsupported(at)),
                    Some(Placed::At(partial, range)) => {
                        push(&mut result.partials, partial)?;
                        if let Some(range) = range {
                            push(&mut result.ranges, range)?;
                        }
                    }
                    None => return Err(Failure::Conflict(at)),
                }
            }
        }
        at = end;
    }
    Ok(result)
}

fn push<T>(list: &mut Vec<T>, item: T) -> Result<(), Failure> {
    list.try_reserve(1).map_err(|_| Failure::NoMemory)?;
    list.push(item);
    Ok(())
}

enum Placed {
    /// The descriptor and, if it claims anything, the claim.
    At(Partial, Option<Range>),
    Unsupported,
}

/// Try one choice of a requirement. `None` if it cannot be had.
fn place(
    descriptor: &IoDescriptor,
    boot: &[Partial],
    claims: &Claims,
    exempt: &dyn Fn(usize) -> bool,
    own: &[Range],
) -> Option<Placed> {
    let (Some(space), Some(wanted)) = (space_of(descriptor.kind), descriptor.wanted()) else {
        return Some(Placed::Unsupported);
    };
    let choice = Choice {
        descriptor,
        space,
        wanted,
    };
    if space == Space::Interrupt && descriptor.flags & INTERRUPT_MESSAGE != 0 {
        // As many messages as the range of tokens is long.
        let count = wanted.maximum.checked_sub(wanted.minimum)? + 1;
        let partial = Partial::raw_messages(
            descriptor.share,
            descriptor.flags,
            u16::try_from(count).ok()?,
            0,
        );
        return Some(Placed::At(partial, None));
    }
    if wanted.length == 0 {
        // Nothing is asked for: the descriptor is passed on.
        return Some(Placed::At(choice.partial(wanted.minimum), None));
    }
    let free = |range: &Range| {
        claims.obstacle(range, exempt).is_none() && !own.iter().any(|held| held.excludes(range))
    };
    // Where firmware left the device, if this choice allows it.
    let configured = boot.iter().find_map(|partial| {
        let (start, length) = match (space, partial.as_interrupt()) {
            (Space::Interrupt, Some((_, _, vector, _))) if !partial.is_message() => {
                (u64::from(vector), 1)
            }
            (Space::Interrupt, _) => return None,
            _ if space_of(partial.kind) == Some(space) => partial.as_range()?,
            _ => return None,
        };
        (choice.allows(start, length) && free(&choice.range(start))).then_some(start)
    });
    if let Some(start) = configured {
        return Some(Placed::At(choice.partial(start), Some(choice.range(start))));
    }
    if space == Space::Interrupt && wanted.minimum != wanted.maximum {
        // A line of the driver's or the bus's choosing: NK chooses none.
        return None;
    }
    // The lowest place the choice allows that nobody holds.
    let mut start = align_up(wanted.minimum, wanted.alignment)?;
    loop {
        let end = start.checked_add(wanted.length - 1)?;
        if end > wanted.maximum {
            return None;
        }
        let range = choice.range(start);
        let obstacle = claims
            .obstacle(&range, exempt)
            .or_else(|| own.iter().find(|held| held.excludes(&range)).copied());
        match obstacle {
            None => return Some(Placed::At(choice.partial(start), Some(range))),
            Some(held) => start = align_up(held.end.checked_add(1)?, wanted.alignment)?,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOBODY: &dyn Fn(usize) -> bool = &|_| false;

    fn list(descriptors: Vec<IoDescriptor>) -> IoList {
        IoList {
            version: 1,
            revision: 1,
            descriptors,
        }
    }

    fn private(index: u32) -> IoDescriptor {
        let mut descriptor = IoDescriptor::interrupt(0, 0, 0, 1, index);
        descriptor.kind = TYPE_DEVICE_PRIVATE;
        descriptor
    }

    /// The AHCI controller of the reference machine: its requirements
    /// (`BasicConfigVector`), with the device-private descriptors
    /// pci.sys puts behind each address range.
    fn ahci() -> IoList {
        list(vec![
            IoDescriptor::range(
                1,
                TYPE_PORT,
                1,
                0x131,
                Wanted {
                    length: 0x20,
                    alignment: 0x20,
                    minimum: 0x6040,
                    maximum: 0x605F,
                },
            ),
            IoDescriptor::range(
                8,
                TYPE_PORT,
                1,
                0x131,
                Wanted {
                    length: 0x20,
                    alignment: 0x20,
                    minimum: 0,
                    maximum: 0xFFFF_FFFF,
                },
            ),
            private(4),
            IoDescriptor::range(
                1,
                TYPE_MEMORY,
                1,
                0x80,
                Wanted {
                    length: 0x1000,
                    alignment: 0x1000,
                    minimum: 0x8101_0000,
                    maximum: 0x8101_0FFF,
                },
            ),
            IoDescriptor::range(
                8,
                TYPE_MEMORY,
                1,
                0x80,
                Wanted {
                    length: 0x1000,
                    alignment: 0x1000,
                    minimum: 0,
                    maximum: 0xFFFF_FFFF,
                },
            ),
            private(5),
            IoDescriptor::interrupt(1, 1, 3, MESSAGE_TOKEN, MESSAGE_TOKEN),
            IoDescriptor::interrupt(8, 3, 0, 0, 0xFFFF_FFFF),
        ])
    }

    /// What Windows gave it (`Control\AllocConfig`).
    #[test]
    fn the_ahci_controller_gets_what_windows_gave_it() {
        let assignment = assign(&ahci(), &[], &Claims::new(), NOBODY).unwrap();
        let mut bar4 = Partial::new(TYPE_DEVICE_PRIVATE, 0, 0);
        bar4.data[..8].copy_from_slice(&[1, 0, 0, 0, 4, 0, 0, 0]);
        let mut bar5 = Partial::new(TYPE_DEVICE_PRIVATE, 0, 0);
        bar5.data[..8].copy_from_slice(&[1, 0, 0, 0, 5, 0, 0, 0]);
        assert_eq!(
            assignment.partials,
            [
                Partial::range(TYPE_PORT, 1, 0x131, 0x6040, 0x20),
                bar4,
                Partial::range(TYPE_MEMORY, 1, 0x80, 0x8101_0000, 0x1000),
                bar5,
                Partial::raw_messages(1, 3, 1, 0),
            ]
        );
        // The message interrupt claims nothing.
        assert_eq!(
            assignment.ranges,
            [
                Range {
                    space: Space::Port,
                    start: 0x6040,
                    end: 0x605F,
                    shared: false
                },
                Range {
                    space: Space::Memory,
                    start: 0x8101_0000,
                    end: 0x8101_0FFF,
                    shared: false
                },
            ]
        );
    }

    #[test]
    fn a_held_range_sends_the_device_to_its_alternative() {
        let mut claims = Claims::new();
        assert!(claims.claim(
            7,
            &[Range {
                space: Space::Port,
                start: 0x6050,
                end: 0x6050,
                shared: false
            }]
        ));
        let assignment = assign(&ahci(), &[], &claims, NOBODY).unwrap();
        // The lowest aligned place of the alternative: port 0.
        assert_eq!(assignment.partials[0].as_range(), Some((0, 0x20)));
        // Unless the holder is one that does not count.
        let assignment = assign(&ahci(), &[], &claims, &|holder| holder == 7).unwrap();
        assert_eq!(assignment.partials[0].as_range(), Some((0x6040, 0x20)));
        assert_eq!(claims.count(7), 1);
        assert_eq!(claims.release(7), 1);
        assert_eq!(claims.release(7), 0);
    }

    #[test]
    fn the_search_steps_over_what_is_held() {
        let mut claims = Claims::new();
        let held = |start, end| Range {
            space: Space::Memory,
            start,
            end,
            shared: false,
        };
        claims.claim(1, &[held(0x1000, 0x2FFF), held(0x4000, 0x4010)]);
        let wanted = list(vec![IoDescriptor::range(
            0,
            TYPE_MEMORY,
            1,
            0,
            Wanted {
                length: 0x1000,
                alignment: 0x1000,
                minimum: 0x1800,
                maximum: 0xFFFF,
            },
        )]);
        let assignment = assign(&wanted, &[], &claims, NOBODY).unwrap();
        assert_eq!(assignment.partials[0].as_range(), Some((0x3000, 0x1000)));
        // Nothing left below the maximum.
        claims.claim(2, &[held(0x3000, 0xFFFF)]);
        assert_eq!(
            assign(&wanted, &[], &claims, NOBODY),
            Err(Failure::Conflict(0))
        );
    }

    #[test]
    fn two_requirements_of_one_device_do_not_overlap() {
        let wanted = list(vec![
            IoDescriptor::range(
                0,
                TYPE_PORT,
                1,
                1,
                Wanted {
                    length: 0x10,
                    alignment: 0x10,
                    minimum: 0x100,
                    maximum: 0x1FF,
                },
            ),
            IoDescriptor::range(
                0,
                TYPE_PORT,
                1,
                1,
                Wanted {
                    length: 0x10,
                    alignment: 0x10,
                    minimum: 0x100,
                    maximum: 0x1FF,
                },
            ),
        ]);
        let assignment = assign(&wanted, &[], &Claims::new(), NOBODY).unwrap();
        assert_eq!(assignment.partials[0].as_range(), Some((0x100, 0x10)));
        assert_eq!(assignment.partials[1].as_range(), Some((0x110, 0x10)));
    }

    #[test]
    fn shared_ranges_may_be_held_twice() {
        let mut claims = Claims::new();
        let line = |shared| Range {
            space: Space::Interrupt,
            start: 10,
            end: 10,
            shared,
        };
        claims.claim(1, &[line(true)]);
        let shared = list(vec![IoDescriptor::interrupt(0, SHARE_SHARED, 0, 10, 10)]);
        let assignment = assign(&shared, &[], &claims, NOBODY).unwrap();
        assert_eq!(
            assignment.partials[0].as_interrupt(),
            Some((10, 0, 10, 0xFFFF_FFFF))
        );
        let exclusive = list(vec![IoDescriptor::interrupt(0, 1, 0, 10, 10)]);
        assert_eq!(
            assign(&exclusive, &[], &claims, NOBODY),
            Err(Failure::Conflict(0))
        );
    }

    /// Without the message alternative, the controller's interrupt is
    /// the line firmware configured (10 on the reference machine).
    #[test]
    fn a_line_comes_from_the_boot_configuration() {
        let wanted = list(vec![IoDescriptor::interrupt(
            0,
            SHARE_SHARED,
            0,
            0,
            0xFFFF_FFFF,
        )]);
        assert_eq!(
            assign(&wanted, &[], &Claims::new(), NOBODY),
            Err(Failure::Conflict(0))
        );
        let boot = [
            Partial::range(TYPE_PORT, 1, 1, 0x6040, 0x20),
            Partial::raw_messages(1, 3, 1, 0),
            Partial::interrupt(SHARE_SHARED, 0, 10, 0, 10, u64::MAX),
        ];
        let assignment = assign(&wanted, &boot, &Claims::new(), NOBODY).unwrap();
        assert_eq!(
            assignment.partials[0].as_interrupt(),
            Some((10, 0, 10, 0xFFFF_FFFF))
        );
        assert_eq!(assignment.ranges[0].start, 10);
    }

    #[test]
    fn the_boot_configuration_is_preferred_where_a_choice_allows_it() {
        let wanted = list(vec![IoDescriptor::range(
            0,
            TYPE_MEMORY,
            1,
            0,
            Wanted {
                length: 0x1000,
                alignment: 0x1000,
                minimum: 0,
                maximum: 0xFFFF_FFFF,
            },
        )]);
        let boot = [Partial::range(TYPE_MEMORY, 1, 0, 0x8101_0000, 0x1000)];
        let assignment = assign(&wanted, &boot, &Claims::new(), NOBODY).unwrap();
        assert_eq!(
            assignment.partials[0].as_range(),
            Some((0x8101_0000, 0x1000))
        );
        // A boot range of another length, or one that is held, is not
        // used.
        let other = [Partial::range(TYPE_MEMORY, 1, 0, 0x8101_0000, 0x2000)];
        let assignment = assign(&wanted, &other, &Claims::new(), NOBODY).unwrap();
        assert_eq!(assignment.partials[0].as_range(), Some((0, 0x1000)));
        let mut claims = Claims::new();
        claims.claim(
            1,
            &[Range {
                space: Space::Memory,
                start: 0x8101_0800,
                end: 0x8101_0900,
                shared: false,
            }],
        );
        let assignment = assign(&wanted, &boot, &claims, NOBODY).unwrap();
        assert_eq!(assignment.partials[0].as_range(), Some((0, 0x1000)));
    }

    #[test]
    fn what_asks_for_nothing_and_what_is_not_assigned() {
        let mut config = IoDescriptor::interrupt(1, 0, 0, 1, 0);
        config.kind = TYPE_CONFIG_DATA;
        let mut null = IoDescriptor::interrupt(0, 0, 0, 0, 0);
        null.kind = TYPE_NULL;
        let empty = IoDescriptor::range(
            0,
            TYPE_MEMORY,
            1,
            0,
            Wanted {
                length: 0,
                alignment: 1,
                minimum: 0x5000,
                maximum: 0x5000,
            },
        );
        let assignment = assign(
            &list(vec![config, null, empty]),
            &[],
            &Claims::new(),
            NOBODY,
        )
        .unwrap();
        assert_eq!(assignment.partials.len(), 1);
        assert_eq!(assignment.partials[0].as_range(), Some((0x5000, 0)));
        assert!(assignment.ranges.is_empty());
        let mut dma = IoDescriptor::interrupt(0, 0, 0, 0, 0);
        dma.kind = TYPE_DMA;
        assert_eq!(
            assign(&list(vec![private(1), dma]), &[], &Claims::new(), NOBODY),
            Err(Failure::Unsupported(1))
        );
    }

    #[test]
    fn requirements_that_cannot_be_met_at_all() {
        // Longer than the range it must lie in.
        let wanted = list(vec![IoDescriptor::range(
            0,
            TYPE_PORT,
            1,
            0,
            Wanted {
                length: 0x20,
                alignment: 1,
                minimum: 0x10,
                maximum: 0x1F,
            },
        )]);
        assert_eq!(
            assign(&wanted, &[], &Claims::new(), NOBODY),
            Err(Failure::Conflict(0))
        );
        // At the very top of the address space.
        let wanted = list(vec![IoDescriptor::range(
            0,
            TYPE_MEMORY,
            1,
            0,
            Wanted {
                length: 0x1000,
                alignment: 0x1000,
                minimum: u64::MAX - 0x10,
                maximum: u64::MAX,
            },
        )]);
        assert_eq!(
            assign(&wanted, &[], &Claims::new(), NOBODY),
            Err(Failure::Conflict(0))
        );
        // More messages than a count holds.
        let wanted = list(vec![IoDescriptor::interrupt(0, 1, 3, 0, MESSAGE_TOKEN)]);
        assert_eq!(
            assign(&wanted, &[], &Claims::new(), NOBODY),
            Err(Failure::Conflict(0))
        );
    }

    #[test]
    fn several_messages() {
        let wanted = list(vec![IoDescriptor::interrupt(
            0,
            1,
            3,
            MESSAGE_TOKEN - 3,
            MESSAGE_TOKEN,
        )]);
        let assignment = assign(&wanted, &[], &Claims::new(), NOBODY).unwrap();
        assert_eq!(
            assignment.partials[0].as_interrupt(),
            Some((0, 4, MESSAGE_TOKEN, 0))
        );
    }

    #[test]
    fn bus_numbers_and_spaces() {
        let mut bus = IoDescriptor::interrupt(0, 1, 0, 0, 0);
        bus.kind = TYPE_BUS_NUMBER;
        bus.data[..4].copy_from_slice(&0x100u32.to_le_bytes());
        bus.data[8..12].copy_from_slice(&0xFFu32.to_le_bytes());
        let assignment = assign(&list(vec![bus]), &[], &Claims::new(), NOBODY).unwrap();
        assert_eq!(assignment.partials[0].as_range(), Some((0, 0x100)));
        assert_eq!(assignment.ranges[0].space, Space::BusNumber);
        assert_eq!(space_of(TYPE_MEMORY_LARGE), Some(Space::Memory));
        assert_eq!(space_of(TYPE_DEVICE_PRIVATE), None);
    }
}
