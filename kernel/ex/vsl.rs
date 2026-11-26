//! Virtual secure mode: services of the secure kernel. NK runs without
//! one, and answers as Windows does when virtual secure mode is off.

#![allow(non_snake_case)]

/// `VslGetSecurePciEnabled` (undocumented): whether the secure kernel
/// guards PCI devices. Without virtual secure mode Windows' routine
/// answers false before asking anything.
pub extern "C" fn VslGetSecurePciEnabled() -> u8 {
    0
}
