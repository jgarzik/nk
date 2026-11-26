//! Dependencies between devices that are not parent and child: a
//! driver tells the Plug and Play manager that one device (the
//! dependent) needs another (the provider), either by naming the
//! provider's device (`IoSetDependency`) or by a string the provider
//! will be bound to later (`IoReserveDependency`, then
//! `IoResolveDependency` for the provider). `acpi.sys` binds every
//! device to its firmware name and reserves what `_DEP` lists.
//!
//! What follows from a dependency here: the dependent's drivers are
//! not added until every provider has started.

use alloc::string::String;
use alloc::vec::Vec;

/// `IoReserveDependency` and `IoSetDependency` take a non-zero
/// combination of these two bits and nothing else.
pub const fn flags_valid(flags: u32) -> bool {
    flags & 3 != 0 && flags & !3 == 0
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Provider {
    Device(usize),
    /// Not bound to a device yet: the string it will be bound by.
    Binding(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Edge {
    dependent: usize,
    provider: Provider,
    flags: u32,
}

/// Every dependency and every binding. A device is known by a number
/// of the caller's choosing.
#[derive(Debug, Default)]
pub struct Dependencies {
    bindings: Vec<(String, usize)>,
    edges: Vec<Edge>,
}

fn same(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

impl Dependencies {
    pub const fn new() -> Self {
        Self {
            bindings: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Bind `id` to `device` (`IoResolveDependency`): reservations made
    /// by that string now name the device. A string bound to another
    /// device is bound to this one instead, as on Windows. `false` if
    /// there is no memory.
    pub fn resolve(&mut self, id: &str, device: usize) -> bool {
        if self.bindings.try_reserve_exact(1).is_err() {
            return false;
        }
        self.bindings.retain(|(known, _)| !same(known, id));
        self.bindings.push((id.into(), device));
        for edge in &mut self.edges {
            if matches!(&edge.provider, Provider::Binding(wanted) if same(wanted, id)) {
                edge.provider = Provider::Device(device);
            }
        }
        true
    }

    /// `dependent` needs whichever device `id` is or will be bound to
    /// (`IoReserveDependency`). `false` if there is no memory.
    pub fn reserve(&mut self, dependent: usize, id: &str, flags: u32) -> bool {
        let provider = match self.bindings.iter().find(|(known, _)| same(known, id)) {
            Some((_, device)) => Provider::Device(*device),
            None => Provider::Binding(id.into()),
        };
        self.add(dependent, provider, flags)
    }

    /// `dependent` needs `provider` (`IoSetDependency`). `false` if
    /// there is no memory.
    pub fn set(&mut self, dependent: usize, provider: usize, flags: u32) -> bool {
        self.add(dependent, Provider::Device(provider), flags)
    }

    fn add(&mut self, dependent: usize, provider: Provider, flags: u32) -> bool {
        // The same dependency stated again adds its flags.
        if let Some(known) = self
            .edges
            .iter_mut()
            .find(|edge| edge.dependent == dependent && edge.provider == provider)
        {
            known.flags |= flags;
            return true;
        }
        if self.edges.try_reserve_exact(1).is_err() {
            return false;
        }
        self.edges.push(Edge {
            dependent,
            provider,
            flags,
        });
        true
    }

    /// What `dependent` needs: each provider's device, or `None` for
    /// one that no device has been bound to yet.
    pub fn providers(&self, dependent: usize) -> Vec<Option<usize>> {
        self.edges
            .iter()
            .filter(|edge| edge.dependent == dependent)
            .map(|edge| match &edge.provider {
                Provider::Device(device) => Some(*device),
                Provider::Binding(_) => None,
            })
            .collect()
    }

    /// The device `device` is gone: its bindings, what it needed, and
    /// what needed it. A dependent of a device that is gone no longer
    /// waits for it.
    pub fn forget(&mut self, device: usize) {
        self.bindings.retain(|(_, bound)| *bound != device);
        self.edges
            .retain(|edge| edge.dependent != device && edge.provider != Provider::Device(device));
        self.bindings.shrink_to_fit();
        self.edges.shrink_to_fit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags() {
        for good in [1, 2, 3] {
            assert!(flags_valid(good));
        }
        for bad in [0, 4, 5, 0x8000_0001] {
            assert!(!flags_valid(bad));
        }
    }

    #[test]
    fn a_reservation_waits_for_its_binding() {
        let mut all = Dependencies::new();
        assert!(all.reserve(10, "\\_SB.PCI0.GPI0", 1));
        assert_eq!(all.providers(10), [None]);
        // Another device's binding changes nothing.
        assert!(all.resolve("\\_SB.PCI0.ISA", 30));
        assert_eq!(all.providers(10), [None]);
        // The name is firmware's: letter case does not count.
        assert!(all.resolve("\\_sb.pci0.gpi0", 20));
        assert_eq!(all.providers(10), [Some(20)]);
        // A reservation made after the binding names the device at once.
        assert!(all.reserve(11, "\\_SB.PCI0.GPI0", 2));
        assert_eq!(all.providers(11), [Some(20)]);
        assert!(all.providers(20).is_empty());
    }

    #[test]
    fn a_string_bound_again_names_the_last_device() {
        let mut all = Dependencies::new();
        assert!(all.resolve("NAME", 1));
        assert!(all.resolve("NAME", 2));
        assert!(all.reserve(9, "name", 1));
        assert_eq!(all.providers(9), [Some(2)]);
    }

    #[test]
    fn dependencies_by_device() {
        let mut all = Dependencies::new();
        assert!(all.set(5, 6, 1));
        assert!(all.set(5, 7, 2));
        // Stated again: one dependency.
        assert!(all.set(5, 6, 2));
        assert_eq!(all.providers(5), [Some(6), Some(7)]);
    }

    #[test]
    fn a_device_that_is_gone_is_forgotten() {
        let mut all = Dependencies::new();
        all.resolve("A", 1);
        all.set(2, 1, 1);
        all.set(1, 3, 1);
        all.reserve(4, "A", 1);
        all.forget(1);
        assert!(all.providers(2).is_empty());
        assert!(all.providers(1).is_empty());
        assert!(all.providers(4).is_empty());
        // The string is free to be reserved and bound again.
        all.reserve(4, "A", 1);
        assert_eq!(all.providers(4), [None]);
    }
}
