//! The Plug and Play manager: the tree of the machine's devices, and
//! the bringing up of each one's drivers.
//!
//! - [`node`]: what is known of each device, and the tree.
//! - [`engine`]: identifying, stacking, starting and enumerating.
//! - [`query`]: the requests sent to device stacks.
//! - [`registry`]: the `Enum` keys and the driver database.
//! - [`root`]: the manager's own driver, `\Driver\PnpManager`, which
//!   owns the root device and the devices drivers report.
//! - [`export`]: what drivers call.
//!
//! `doc/DESIGN.md`, Plug and Play, says what is NK's own decision here.

pub mod engine;
pub mod export;
pub mod node;
pub mod query;
pub mod registry;
pub mod root;

pub use engine::{boot_drivers_loaded, driver_failed, settle};
pub use root::{remove_reported_device, report_detected_device};

/// Pool tag of the manager's allocations, as Windows spells its own.
pub const TAG: u32 = u32::from_le_bytes(*b"Pnp ");

/// Make the root of the device tree and the manager's driver. Before
/// any driver is started.
pub fn init() -> Result<(), &'static str> {
    engine::init();
    root::init()
}
