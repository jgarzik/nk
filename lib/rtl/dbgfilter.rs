//! Which debug messages are let through: the component filter masks of
//! `DbgPrintEx`, `vDbgPrintExWithPrefix` and `DbgSetDebugFilterState`
//! ([Reading and filtering debugging messages](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/reading-and-filtering-debugging-messages)).
//!
//! Each component has a mask; one more, `WIN2000`, applies to every
//! component. A message's level selects a bit, or is itself a mask. The
//! slots and defaults are those of the pinned kernel
//! (`NtQueryDebugFilterState`, `NtSetDebugFilterState`).

/// How many components have a mask: `DPFLTR_ENDOFTABLE_ID`.
pub const COMPONENTS: usize = 0x9C;

/// `DPFLTR_DEFAULT_ID`: the component of plain `DbgPrint`, and the one
/// an unknown component is taken for.
pub const DEFAULT: usize = 0x65;

/// `DPFLTR_INFO_LEVEL`: the level a message of an unknown component is
/// taken to have.
const INFO_LEVEL: u32 = 3;

/// What `WIN2000` starts as: errors of every component pass. The
/// component masks start empty.
pub const WIN2000_AT_BOOT: u32 = 1;

/// The mask a level selects: a level under 32 is a bit number, any
/// other is the mask.
pub fn mask(level: u32) -> u32 {
    if level < 32 { 1 << level } else { level }
}

/// For a message of `component` at `level`: the component whose mask
/// decides, and the mask the message must meet.
pub fn message(component: u32, level: u32) -> (usize, u32) {
    if (component as usize) < COMPONENTS {
        (component as usize, mask(level))
    } else {
        (DEFAULT, mask(INFO_LEVEL))
    }
}

/// Whether a message that must meet `wanted` passes a component whose
/// mask is `component_mask`.
pub fn passes(wanted: u32, component_mask: u32, win2000: u32) -> bool {
    wanted & (component_mask | win2000) != 0
}

/// The mask a change of filter state applies to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Slot {
    Component(usize),
    Win2000,
}

/// The mask `DbgSetDebugFilterState` changes for `component`: its own,
/// `WIN2000` for -1, the default component's for any other number.
pub fn slot(component: u32) -> Slot {
    if (component as usize) < COMPONENTS {
        Slot::Component(component as usize)
    } else if component == u32::MAX {
        Slot::Win2000
    } else {
        Slot::Component(DEFAULT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_level_is_a_bit_or_a_mask() {
        assert_eq!(mask(0), 1);
        assert_eq!(mask(3), 8);
        assert_eq!(mask(31), 0x8000_0000);
        assert_eq!(mask(32), 32);
        assert_eq!(mask(0x8000_0004), 0x8000_0004);
    }

    #[test]
    fn an_unknown_component_is_the_default_at_info() {
        assert_eq!(message(5, 0), (5, 1));
        assert_eq!(message(0x9B, 2), (0x9B, 4));
        assert_eq!(message(0x9C, 0), (DEFAULT, 8));
        assert_eq!(message(u32::MAX, 31), (DEFAULT, 8));
    }

    #[test]
    fn errors_pass_at_boot_and_nothing_else() {
        assert!(passes(mask(0), 0, WIN2000_AT_BOOT));
        assert!(!passes(mask(1), 0, WIN2000_AT_BOOT));
        assert!(!passes(mask(3), 0, WIN2000_AT_BOOT));
        assert!(passes(mask(3), 8, WIN2000_AT_BOOT));
        assert!(passes(mask(3), 0, 8));
    }

    #[test]
    fn the_slot_a_component_names() {
        assert_eq!(slot(0), Slot::Component(0));
        assert_eq!(slot(0x9B), Slot::Component(0x9B));
        assert_eq!(slot(0x9C), Slot::Component(DEFAULT));
        assert_eq!(slot(u32::MAX), Slot::Win2000);
    }
}
