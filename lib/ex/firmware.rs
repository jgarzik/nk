//! Who provides firmware tables: the handlers drivers register with
//! `ZwSetSystemInformation(SystemRegisterFirmwareTableInformationHandler)`.
//!
//! A provider is a four-character signature (`'ACPI'`, `'RSMB'`,
//! `'FIRM'`), the routine that enumerates and fetches its tables, and
//! the driver object the routine belongs to. The rules are the pinned
//! kernel's `ExpRegisterFirmwareTableInformationHandler`: one provider
//! per signature; only the driver that registered a provider takes it
//! back.

extern crate alloc;

use alloc::vec::Vec;
use nk_ntabi::status::{
    NTSTATUS, STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_PARAMETER, STATUS_OBJECT_NAME_EXISTS,
};

/// A registered provider.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Provider {
    pub signature: u32,
    pub handler: usize,
    pub driver: usize,
}

/// What a request changed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Changed {
    /// The provider is registered: its driver object is to be
    /// referenced.
    Registered,
    /// The provider is gone: the reference to its driver object is to
    /// be given up.
    Unregistered,
}

/// The providers there are.
pub struct Providers {
    list: Vec<Provider>,
}

impl Providers {
    pub const fn new() -> Self {
        Self { list: Vec::new() }
    }

    /// Register `provider`, or take the provider of its signature back.
    ///
    /// Registering a signature that has a provider answers
    /// `STATUS_OBJECT_NAME_EXISTS` and changes nothing. Taking back a
    /// signature that has none, or one another driver registered, is
    /// `STATUS_INVALID_PARAMETER`.
    pub fn change(&mut self, provider: Provider, register: bool) -> Result<Changed, NTSTATUS> {
        let found = self
            .list
            .iter()
            .position(|known| known.signature == provider.signature);
        match (found, register) {
            (Some(_), true) => Err(STATUS_OBJECT_NAME_EXISTS),
            (Some(at), false) => {
                if self.list[at].driver != provider.driver {
                    return Err(STATUS_INVALID_PARAMETER);
                }
                self.list.remove(at);
                if self.list.is_empty() {
                    // An empty list holds no memory.
                    self.list = Vec::new();
                }
                Ok(Changed::Unregistered)
            }
            (None, false) => Err(STATUS_INVALID_PARAMETER),
            (None, true) => {
                if self.list.try_reserve(1).is_err() {
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
                self.list.push(provider);
                Ok(Changed::Registered)
            }
        }
    }

    /// The provider of `signature`, if one is registered.
    pub fn find(&self, signature: u32) -> Option<Provider> {
        self.list
            .iter()
            .copied()
            .find(|known| known.signature == signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACPI: u32 = u32::from_le_bytes(*b"IPCA");

    fn acpi(driver: usize) -> Provider {
        Provider {
            signature: ACPI,
            handler: 0x1000,
            driver,
        }
    }

    #[test]
    fn a_provider_is_registered_once_per_signature() {
        let mut all = Providers::new();
        assert_eq!(all.find(ACPI), None);
        assert_eq!(all.change(acpi(7), true), Ok(Changed::Registered));
        assert_eq!(all.find(ACPI), Some(acpi(7)));
        // Again, by anyone: it exists, and stays as it was.
        assert_eq!(all.change(acpi(8), true), Err(STATUS_OBJECT_NAME_EXISTS));
        assert_eq!(all.find(ACPI), Some(acpi(7)));
        // Another signature is another provider.
        let other = Provider {
            signature: ACPI + 1,
            handler: 0x2000,
            driver: 8,
        };
        assert_eq!(all.change(other, true), Ok(Changed::Registered));
        assert_eq!(all.find(ACPI + 1), Some(other));
    }

    #[test]
    fn only_its_driver_takes_a_provider_back() {
        let mut all = Providers::new();
        assert_eq!(all.change(acpi(7), false), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(all.change(acpi(7), true), Ok(Changed::Registered));
        assert_eq!(all.change(acpi(8), false), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(all.find(ACPI), Some(acpi(7)));
        assert_eq!(all.change(acpi(7), false), Ok(Changed::Unregistered));
        assert_eq!(all.find(ACPI), None);
        assert_eq!(all.change(acpi(7), false), Err(STATUS_INVALID_PARAMETER));
    }
}
