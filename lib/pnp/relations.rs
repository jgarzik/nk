//! What changed among a bus's children: the devices a bus driver
//! reports for `IRP_MN_QUERY_DEVICE_RELATIONS` (`BusRelations`) against
//! those the Plug and Play manager knew.

use alloc::vec::Vec;

/// The difference between two enumerations of a bus. A device is known
/// by its physical device object's address.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Change {
    /// Reported now and not known before, in the order reported.
    pub arrived: Vec<usize>,
    /// Known before and not reported now, in the order they were known.
    pub gone: Vec<usize>,
    /// Reported more than once: a bus driver's error. The device counts
    /// once.
    pub repeated: Vec<usize>,
}

/// Compare what was `known` with what is `reported`.
pub fn change(known: &[usize], reported: &[usize]) -> Change {
    let mut result = Change::default();
    for (at, device) in reported.iter().enumerate() {
        if reported[..at].contains(device) {
            if !result.repeated.contains(device) {
                result.repeated.push(*device);
            }
        } else if !known.contains(device) {
            result.arrived.push(*device);
        }
    }
    result.gone = known
        .iter()
        .copied()
        .filter(|device| !reported.contains(device))
        .collect();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arrivals_and_departures() {
        assert_eq!(
            change(&[1, 2, 3], &[3, 4, 1, 5]),
            Change {
                arrived: vec![4, 5],
                gone: vec![2],
                repeated: vec![],
            }
        );
    }

    #[test]
    fn nothing_changed() {
        assert_eq!(change(&[7, 8], &[8, 7]), Change::default());
        assert_eq!(change(&[], &[]), Change::default());
    }

    #[test]
    fn a_first_enumeration_and_an_emptied_bus() {
        assert_eq!(change(&[], &[1, 2]).arrived, [1, 2]);
        assert_eq!(change(&[1, 2], &[]).gone, [1, 2]);
    }

    #[test]
    fn a_device_reported_twice_counts_once() {
        let result = change(&[1], &[2, 2, 1, 1, 2]);
        assert_eq!(result.arrived, [2]);
        assert_eq!(result.repeated, [2, 1]);
        assert!(result.gone.is_empty());
    }
}
