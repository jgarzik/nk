//! Trace providers on a system where no trace session ever runs.
//!
//! NK starts no trace session and has no consumer of WMI data, so every
//! answer here is the one Windows gives a provider nobody listens to
//! (`doc/DESIGN.md`, "Tracing"). What is left is bookkeeping and
//! validation, which the host can test:
//!
//! [`provider`] is the table of registered providers. [`traits`] checks
//! the blob a provider names itself with. [`logger`] answers questions
//! about trace sessions when there are none.

#![cfg_attr(not(test), no_std)]

pub mod logger;
pub mod provider;
pub mod traits;
