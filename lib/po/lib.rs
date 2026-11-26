//! The power manager's rules, with no devices and no threads behind
//! them, so the host can test them.
//!
//! NK's machine is on and stays on: the system is in S0, every device
//! in D0. What is left of a power manager then is bookkeeping, and
//! these are its rules: [`state`] is the power state a device object
//! records (`PoSetPowerState`), [`request`] the order in which the
//! power requests for one device are sent (`PoRequestPowerIrp`),
//! [`setting`] the power settings that have a value and who is told of
//! them (`PoRegisterPowerSettingCallback`), and [`fx`] the runtime power
//! framework: a device's components, each active or idle, and what
//! their driver is told (`PoFxActivateComponent`, `PoFxIdleComponent`).
//! [`action`] is what becomes of a request to change the system's
//! power state (`ZwInitiatePowerAction`), [`logging`] the reasons
//! logged for a sleep state being unavailable (`ZwPowerInformation`).

#![cfg_attr(not(test), no_std)]

extern crate alloc;

pub mod action;
pub mod fx;
pub mod logging;
pub mod request;
pub mod setting;
pub mod state;
