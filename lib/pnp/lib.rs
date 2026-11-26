//! What the Plug and Play manager decides without touching a device:
//! how a device's instance path is built from what its bus driver
//! answers ([`ids`]), which driver-database record matches its
//! identifiers ([`database`]), which children a bus gained and lost
//! ([`relations`]), what a resource list or a requirements list says
//! ([`resources`]), and which resources a device gets out of its
//! requirements ([`assign`]).
//!
//! The kernel's `pnp` module is the part that sends requests to device
//! stacks and writes the registry; everything it works out, it works
//! out here, where the build host tests it.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod assign;
pub mod connection;
pub mod database;
pub mod depend;
pub mod ids;
pub mod interface;
pub mod relations;
pub mod resources;
