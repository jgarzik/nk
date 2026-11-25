//! The order drivers start in, from what their service keys say.
//!
//! Windows starts boot-start services (`Start` 0), then system-start
//! ones (`Start` 1). Within each, the groups listed in
//! `Control\ServiceGroupOrder` go first, in that order; inside a group,
//! `Control\GroupOrderList` may order the services by `Tag`; services
//! in no listed group go last. A service that depends on another
//! (`DependOnService`) or on a group (`DependOnGroup`) starts after it.
//! See [`Services` registry tree](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree).

use alloc::vec::Vec;

/// `SERVICE_BOOT_START` and `SERVICE_SYSTEM_START`.
const STARTS: [u32; 2] = [0, 1];

/// A service key's values that decide when it starts.
#[derive(Debug, Clone, Copy)]
pub struct Service<'a> {
    pub name: &'a [u16],
    /// `Start`.
    pub start: u32,
    /// `Group`; empty if the service is in none.
    pub group: &'a [u16],
    /// `Tag`.
    pub tag: Option<u32>,
    pub depend_on_service: &'a [&'a [u16]],
    pub depend_on_group: &'a [&'a [u16]],
}

/// Why no order was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OrderError {
    /// No memory for the answer.
    NoMemory,
    /// Services wait for each other in a circle; this one is in it.
    Cycle(usize),
}

/// Where `service` stands before dependencies are looked at: its
/// group's place, then its tag's place in the group's tag list.
fn rank(
    service: &Service<'_>,
    group_order: &[&[u16]],
    tag_order: &[(&[u16], &[u32])],
) -> (usize, usize) {
    let same = nk_rtl::names_equal;
    let listed = |group: &&[u16]| !service.group.is_empty() && same(group, service.group);
    let group = group_order
        .iter()
        .position(listed)
        .unwrap_or(group_order.len());
    // A tag that its group's list does not name goes after those it
    // does; where a group has no list, tags decide nothing.
    let tag = tag_order
        .iter()
        .find(|(group, _)| listed(group))
        .map_or(0, |(_, tags)| {
            tags.iter()
                .position(|&tag| Some(tag) == service.tag)
                .unwrap_or(tags.len())
        });
    (group, tag)
}

/// Whether `service` must start after `other`.
fn waits_for(service: &Service<'_>, other: &Service<'_>) -> bool {
    let same = nk_rtl::names_equal;
    let named = service
        .depend_on_service
        .iter()
        .any(|name| same(name, other.name));
    let grouped = service
        .depend_on_group
        .iter()
        .any(|group| !other.group.is_empty() && same(group, other.group));
    named || grouped
}

/// The order to start `services` in, as indexes into the slice: the
/// boot-start ones, then the system-start ones; others are left out.
///
/// `group_order` is `ServiceGroupOrder`'s list. `tag_order` gives, for
/// the groups that have one, the group's `GroupOrderList` tags in
/// order. Services that rank the same keep the order they were given
/// in. A dependency is honoured among services of the same start type
/// (one that starts earlier has started already); one on a service or
/// group that is not there holds nothing up.
pub fn start_order(
    services: &[Service<'_>],
    group_order: &[&[u16]],
    tag_order: &[(&[u16], &[u32])],
) -> Result<Vec<usize>, OrderError> {
    let mut order = Vec::new();
    order
        .try_reserve_exact(services.len())
        .map_err(|_| OrderError::NoMemory)?;
    for start in STARTS {
        let first = order.len();
        order.extend((0..services.len()).filter(|&index| services[index].start == start));
        let phase = &mut order[first..];
        phase
            .sort_unstable_by_key(|&index| (rank(&services[index], group_order, tag_order), index));
        // Take each service in turn; before it, whatever it waits for
        // that has not been placed yet, and before that what that one
        // waits for.
        for place in 0..phase.len() {
            let mut next = place;
            let mut steps = 0;
            while let Some(earlier) = (place..phase.len()).find(|&other| {
                other != next && waits_for(&services[phase[next]], &services[phase[other]])
            }) {
                next = earlier;
                steps += 1;
                // More steps than services: the chain has come round.
                if steps > phase.len() - place {
                    return Err(OrderError::Cycle(phase[next]));
                }
            }
            phase[place..=next].rotate_right(1);
        }
    }
    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::w;

    type Names<'a> = Vec<&'a [u16]>;

    /// Services written as `name start group tag after-services
    /// after-groups`, with `-` for nothing and commas between names;
    /// the order they start in, by name.
    fn order(lines: &[&str], groups: &[&str], tags: &[(&str, &[u32])]) -> Result<String, String> {
        let list = |field: &str| -> Vec<Vec<u16>> {
            field
                .split(',')
                .filter(|name| *name != "-")
                .map(w)
                .collect()
        };
        let parsed: Vec<_> = lines
            .iter()
            .map(|line| {
                let fields: Vec<&str> = line.split(' ').collect();
                let group = list(fields[2]).pop().unwrap_or_default();
                (
                    w(fields[0]),
                    fields[1],
                    group,
                    fields[3],
                    list(fields[4]),
                    list(fields[5]),
                )
            })
            .collect();
        let slices: Vec<(Names<'_>, Names<'_>)> = parsed
            .iter()
            .map(|p| {
                (
                    p.4.iter().map(|n| &n[..]).collect(),
                    p.5.iter().map(|n| &n[..]).collect(),
                )
            })
            .collect();
        let services: Vec<Service<'_>> = parsed
            .iter()
            .zip(&slices)
            .map(|(p, (after, after_groups))| Service {
                name: &p.0,
                start: p.1.parse().unwrap(),
                group: &p.2,
                tag: p.3.parse().ok(),
                depend_on_service: after,
                depend_on_group: after_groups,
            })
            .collect();
        let groups: Vec<Vec<u16>> = groups.iter().map(|group| w(group)).collect();
        let groups: Vec<&[u16]> = groups.iter().map(|group| &group[..]).collect();
        let tags: Vec<(Vec<u16>, &[u32])> = tags.iter().map(|(group, t)| (w(group), *t)).collect();
        let tags: Vec<(&[u16], &[u32])> = tags.iter().map(|(group, t)| (&group[..], *t)).collect();
        let name = |index: usize| String::from_utf16(services[index].name).unwrap();
        match start_order(&services, &groups, &tags) {
            Ok(order) => Ok(order.into_iter().map(name).collect::<Vec<_>>().join(" ")),
            Err(OrderError::Cycle(index)) => Err(name(index)),
            Err(OrderError::NoMemory) => Err("no memory".to_string()),
        }
    }

    const GROUPS: &[&str] = &["Bus", "Disk", "FS"];

    #[test]
    fn boot_start_comes_before_system_start_and_the_rest_is_left_out() {
        let lines = [
            "auto 2 Disk - - -",
            "sys2 1 - - - -",
            "boot1 0 - - - -",
            "demand 3 - - - -",
            "sys1 1 - - - -",
            "boot2 0 - - - -",
            "off 4 - - - -",
        ];
        assert_eq!(order(&lines, GROUPS, &[]).unwrap(), "boot1 boot2 sys2 sys1");
        assert_eq!(order(&[], GROUPS, &[]).unwrap(), "");
    }

    #[test]
    fn groups_start_in_the_listed_order_and_the_ungrouped_last() {
        let lines = [
            "loose 0 - - - -",
            "fs 0 FS - - -",
            "disk 0 Disk - - -",
            "odd 0 Unlisted - - -",
            "acpi 0 bus - - -",
            "disk2 0 DISK - - -",
            "sysdisk 1 Disk - - -",
            "sysbus 1 Bus - - -",
        ];
        // Group names are matched whatever their case. A group the list
        // does not name goes with the ungrouped, in the order given.
        // Each start type is ordered by itself.
        assert_eq!(
            order(&lines, GROUPS, &[]).unwrap(),
            "acpi disk disk2 fs loose odd sysbus sysdisk"
        );
        // Without a group list, the order given.
        assert_eq!(
            order(&lines, &[], &[]).unwrap(),
            "loose fs disk odd acpi disk2 sysdisk sysbus"
        );
    }

    #[test]
    fn tags_order_a_group_that_has_a_tag_list() {
        let lines = [
            "d5 0 Disk 5 - -",
            "d- 0 Disk - - -",
            "d2 0 Disk 2 - -",
            "d9 0 Disk 9 - -",
            "d7 0 Disk 7 - -",
            "b3 0 Bus 3 - -",
            "b1 0 Bus 1 - -",
        ];
        // The listed tags in the list's order, then the unlisted and
        // untagged as given. A group without a list keeps its order.
        let tags: &[(&str, &[u32])] = &[("DISK", &[7, 2, 5])];
        assert_eq!(
            order(&lines, &["Bus", "Disk"], tags).unwrap(),
            "b3 b1 d7 d2 d5 d- d9"
        );
        assert_eq!(
            order(&lines, &["Bus", "Disk"], &[]).unwrap(),
            "b3 b1 d5 d- d2 d9 d7"
        );
    }

    #[test]
    fn a_service_starts_after_what_it_depends_on() {
        let lines = [
            "top 0 Disk - MID,missing -",
            "other 0 Disk - - -",
            "mid 0 - - base -",
            "base 0 - - - -",
            "late 0 - - - -",
        ];
        // What a service waits for is brought forward to just before
        // it; nothing else moves. A name that is no service holds
        // nothing up.
        assert_eq!(
            order(&lines, &["Disk"], &[]).unwrap(),
            "base mid top other late"
        );
        // A whole group; the service's own group does not count
        // against itself.
        let lines = [
            "user 0 A - - b,A,nogroup",
            "peer 0 A - - -",
            "b2 0 B - - -",
            "b1 0 B - - -",
        ];
        assert_eq!(order(&lines, &["A", "B"], &[]).unwrap(), "peer b2 b1 user");
        // A system-start service that depends on a boot-start one has
        // nothing to wait for; the other way about cannot be honoured.
        let lines = ["sys 1 - - boot -", "boot 0 - - sys2 -", "sys2 1 - - - -"];
        assert_eq!(order(&lines, &[], &[]).unwrap(), "boot sys sys2");
    }

    #[test]
    fn a_circle_of_dependencies_is_an_error() {
        let lines = [
            "free 0 - - - -",
            "a 0 - - b -",
            "b 0 - - c -",
            "c 0 - - a -",
        ];
        let stuck = order(&lines, &[], &[]).unwrap_err();
        assert!(["a", "b", "c"].contains(&&stuck[..]), "{stuck}");
        // Through a group as well.
        let lines = ["a 0 G - b -", "b 0 - - - G"];
        assert!(order(&lines, &[], &[]).is_err());
        // A service that names itself waits for nothing; a long chain
        // is no circle.
        let lines = [
            "self 0 - - self -",
            "d 0 - - c -",
            "c 0 - - b -",
            "b 0 - - a -",
            "a 0 - - - -",
        ];
        assert_eq!(order(&lines, &[], &[]).unwrap(), "self a b c d");
    }
}
