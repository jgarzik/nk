//! The order drivers start in, from what their service keys say.
//!
//! Windows starts boot-start services (`Start` 0), then system-start
//! ones (`Start` 1). Within each, the groups listed in
//! `Control\ServiceGroupOrder` go first, in that order; inside a group,
//! `Control\GroupOrderList` may order the services by `Tag`; services
//! in no listed group go last. Group names are compared without regard
//! to case: Windows' own keys spell one group `File system` where the
//! list of groups has `File System`. A service that depends on another
//! (`DependOnService`) or on a group (`DependOnGroup`) starts after it.
//! See [`Services` registry tree](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree).

use crate::{Hive, KeyId};
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

/// The group Windows' loader loads before every group of
/// `ServiceGroupOrder`, though no list names it: `acpi.sys` is in it.
/// Its drivers go in the order of their tags.
const CORE: [u16; 4] = ascii(b"Core");

/// Where `service` stands before dependencies are looked at: its
/// group's place, then its tag's place in the group's tag list.
fn rank(
    service: &Service<'_>,
    group_order: &[&[u16]],
    tag_order: &[(&[u16], &[u32])],
) -> (usize, usize) {
    let same = nk_rtl::names_equal;
    let listed = |group: &&[u16]| !service.group.is_empty() && same(group, service.group);
    if same(service.group, &CORE) {
        return (0, service.tag.map_or(usize::MAX, |tag| tag as usize));
    }
    let group = 1 + group_order
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

/// Registry value types.
const REG_SZ: u32 = 1;
const REG_EXPAND_SZ: u32 = 2;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;
/// `SERVICE_DRIVER`: the `Type` bits of a kernel, file-system or
/// recogniser driver.
const SERVICE_DRIVER: u32 = 0xB;

const fn ascii<const N: usize>(text: &[u8; N]) -> [u16; N] {
    let mut out = [0; N];
    let mut i = 0;
    while i < N {
        out[i] = text[i] as u16;
        i += 1;
    }
    out
}

fn push<T>(list: &mut Vec<T>, item: T) -> Result<(), OrderError> {
    list.try_reserve(1).map_err(|_| OrderError::NoMemory)?;
    list.push(item);
    Ok(())
}

/// The number in the `REG_DWORD` value `name` of `key`.
fn number(hive: &Hive, key: KeyId, name: &[u16]) -> Option<u32> {
    match hive.value(key, name) {
        Ok((_, REG_DWORD, &[a, b, c, d])) => Some(u32::from_le_bytes([a, b, c, d])),
        _ => None,
    }
}

/// The strings in the value `name` of `key`: the one of a `REG_SZ`,
/// each of a `REG_MULTI_SZ`, without their terminators. None if there
/// is no such value.
fn strings(hive: &Hive, key: KeyId, name: &[u16]) -> Result<Vec<Vec<u16>>, OrderError> {
    let mut found = Vec::new();
    let Ok((_, REG_SZ | REG_EXPAND_SZ | REG_MULTI_SZ, data)) = hive.value(key, name) else {
        return Ok(found);
    };
    let (units, _) = data.as_chunks::<2>();
    for text in units.split(|&unit| unit == [0, 0]) {
        // The empty string ends the list.
        if text.is_empty() {
            break;
        }
        let mut string = Vec::new();
        string
            .try_reserve_exact(text.len())
            .map_err(|_| OrderError::NoMemory)?;
        string.extend(text.iter().map(|&unit| u16::from_le_bytes(unit)));
        push(&mut found, string)?;
    }
    Ok(found)
}

/// The tags of a `GroupOrderList` value, in order: the value is a
/// count followed by that many tags, 32 bits each.
fn tag_list(data: &[u8]) -> Result<Vec<u32>, OrderError> {
    let (words, _) = data.as_chunks::<4>();
    let mut words = words.iter().map(|&word| u32::from_le_bytes(word));
    let count = words.next().unwrap_or(0) as usize;
    let mut tags = Vec::new();
    for tag in words.take(count) {
        push(&mut tags, tag)?;
    }
    Ok(tags)
}

/// What a service key says about when its driver starts.
struct Found {
    key: KeyId,
    start: u32,
    group: Vec<u16>,
    tag: Option<u32>,
    after_services: Vec<Vec<u16>>,
    after_groups: Vec<Vec<u16>>,
}

/// One list of names per service, as the slices [`Service`] takes.
fn slices<'a>(
    found: &'a [Found],
    list: impl Fn(&'a Found) -> &'a [Vec<u16>],
) -> Result<Vec<Vec<&'a [u16]>>, OrderError> {
    let mut all = Vec::new();
    for service in found {
        let mut names = Vec::new();
        for name in list(service) {
            push(&mut names, &name[..])?;
        }
        push(&mut all, names)?;
    }
    Ok(all)
}

/// The driver services of the control set `control_set` that start at
/// boot, as their keys under `Services`, in the order they start
/// ([`start_order`]): from each key's `Type`, `Start`, `Group`, `Tag`,
/// `DependOnService` and `DependOnGroup`, and from
/// `Control\ServiceGroupOrder` (`List`) and `Control\GroupOrderList`.
/// A key that is no driver's (`Type`) is left out; a control set with
/// no `Services` key starts nothing.
pub fn boot_start(hive: &Hive, control_set: KeyId) -> Result<Vec<KeyId>, OrderError> {
    const SERVICES: [u16; 8] = ascii(b"Services");
    const GROUP_ORDER: [u16; 25] = ascii(b"Control\\ServiceGroupOrder");
    const TAG_ORDER: [u16; 22] = ascii(b"Control\\GroupOrderList");
    let Ok(services) = hive.open(control_set, &SERVICES) else {
        return Ok(Vec::new());
    };
    let mut found = Vec::new();
    for key in (0..).map_while(|index| hive.subkey(services, index).ok().flatten()) {
        let (Some(kind), Some(start)) = (
            number(hive, key, &ascii(b"Type")),
            number(hive, key, &ascii(b"Start")),
        ) else {
            continue;
        };
        if kind & SERVICE_DRIVER == 0 {
            continue;
        }
        let group = strings(hive, key, &ascii(b"Group"))?
            .pop()
            .unwrap_or_default();
        push(
            &mut found,
            Found {
                key,
                start,
                group,
                tag: number(hive, key, &ascii(b"Tag")),
                after_services: strings(hive, key, &ascii(b"DependOnService"))?,
                after_groups: strings(hive, key, &ascii(b"DependOnGroup"))?,
            },
        )?;
    }
    let group_order = match hive.open(control_set, &GROUP_ORDER) {
        Ok(key) => strings(hive, key, &ascii(b"List"))?,
        Err(_) => Vec::new(),
    };
    // Each group's tag list is a value of one key, named for the group.
    let mut tag_lists = Vec::new();
    if let Ok(key) = hive.open(control_set, &TAG_ORDER) {
        for (group, _, data) in (0..).map_while(|index| hive.value_at(key, index).ok().flatten()) {
            push(&mut tag_lists, (group, tag_list(data)?))?;
        }
    }
    let after_services = slices(&found, |service| &service.after_services)?;
    let after_groups = slices(&found, |service| &service.after_groups)?;
    let mut described = Vec::new();
    for (index, service) in found.iter().enumerate() {
        push(
            &mut described,
            Service {
                name: hive.info(service.key).map_or(&[][..], |info| info.name),
                start: service.start,
                group: &service.group,
                tag: service.tag,
                depend_on_service: &after_services[index],
                depend_on_group: &after_groups[index],
            },
        )?;
    }
    let mut groups: Vec<&[u16]> = Vec::new();
    for group in &group_order {
        push(&mut groups, &group[..])?;
    }
    let mut tags: Vec<(&[u16], &[u32])> = Vec::new();
    for (group, list) in &tag_lists {
        push(&mut tags, (*group, &list[..]))?;
    }
    let mut keys = Vec::new();
    for index in start_order(&described, &groups, &tags)? {
        push(&mut keys, found[index].key)?;
    }
    Ok(keys)
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
    fn the_core_group_starts_first_by_tag_though_no_list_names_it() {
        let lines = [
            "loose 0 - - - -",
            "bus 0 Bus - - -",
            "acpi 0 Core 2 - -",
            "untagged 0 core - - -",
            "acpiex 0 Core 1 - -",
        ];
        assert_eq!(
            order(&lines, GROUPS, &[]).unwrap(),
            "acpiex acpi untagged bus loose"
        );
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

    /// A control set whose service keys are `lines`, written as for
    /// [`order`] with the key's `Type` in front and `_` for a space in
    /// a group's name; the names of the services [`boot_start`] finds,
    /// in order.
    fn from_keys(lines: &[&str], groups: &[&str], tags: &[(&str, &[u32])]) -> String {
        let mut hive = Hive::new();
        let root = hive.root().unwrap();
        let (set, _) = hive.create(root, &w("Set")).unwrap();
        hive.create(set, &w("Control")).unwrap();
        let (services, _) = hive.create(set, &w("Services")).unwrap();
        let multi = |names: &[&str]| -> Vec<u8> {
            let mut text: String = names.iter().map(|name| format!("{name}\0")).collect();
            text.push('\0');
            crate::writer::wide(&text)
        };
        for line in lines {
            let fields: Vec<&str> = line.split(' ').collect();
            let (key, _) = hive.create(services, &w(fields[1])).unwrap();
            for (name, field) in [
                ("Type", fields[0]),
                ("Start", fields[2]),
                ("Tag", fields[4]),
            ] {
                if let Ok(number) = field.parse::<u32>() {
                    hive.set_value(key, &w(name), 4, &number.to_le_bytes())
                        .unwrap();
                }
            }
            if fields[3] != "-" {
                let group = crate::writer::wide(&format!("{}\0", fields[3].replace('_', " ")));
                hive.set_value(key, &w("Group"), 1, &group).unwrap();
            }
            for (name, field) in [("DependOnService", fields[5]), ("DependOnGroup", fields[6])] {
                if field != "-" {
                    let names: Vec<&str> = field.split(',').collect();
                    hive.set_value(key, &w(name), 7, &multi(&names)).unwrap();
                }
            }
        }
        if !groups.is_empty() {
            let (key, _) = hive.create(set, &w("Control\\ServiceGroupOrder")).unwrap();
            hive.set_value(key, &w("List"), 7, &multi(groups)).unwrap();
        }
        if !tags.is_empty() {
            let (key, _) = hive.create(set, &w("Control\\GroupOrderList")).unwrap();
            for (group, list) in tags {
                let data: Vec<u8> = core::iter::once(list.len() as u32)
                    .chain(list.iter().copied())
                    .flat_map(u32::to_le_bytes)
                    .collect();
                hive.set_value(key, &w(group), 3, &data).unwrap();
            }
        }
        let names: Vec<String> = boot_start(&hive, set)
            .unwrap()
            .into_iter()
            .map(|key| String::from_utf16(hive.info(key).unwrap().name).unwrap())
            .collect();
        names.join(" ")
    }

    #[test]
    fn the_service_keys_say_what_starts_at_boot_and_in_what_order() {
        let lines = [
            "1 Late 1 - - - -",
            "2 Fs 1 FS - - -",
            "1 Demand 3 Bus - - -",
            "16 Win32 0 Bus - - -",
            "- NoType 0 Bus - - -",
            "1 NoStart - Bus - - -",
            "1 Disk9 0 Disk 9 - -",
            "1 Disk2 0 Disk 2 - -",
            "1 Bus 0 Bus - - -",
            "8 Recogniser 1 Disk - Late -",
            "1 After 1 Bus - - fs",
        ];
        // Drivers only, boot start then system start; groups in the
        // listed order; tags as the group's list says; dependencies.
        // The keys come in the order of their names.
        assert_eq!(
            from_keys(&lines, GROUPS, &[("disk", &[9, 2])]),
            "Bus Disk9 Disk2 Fs After Late Recogniser"
        );
        // No group list and no tag lists: the order of the names, but
        // for what waits for another.
        assert_eq!(
            from_keys(&lines, &[], &[]),
            "Bus Disk2 Disk9 Fs After Late Recogniser"
        );
        assert_eq!(
            from_keys(&lines[..8], &["Disk", "Bus"], &[]),
            "Disk2 Disk9 Fs Late"
        );
        // A tag list that claims more tags than it holds, or is empty.
        assert_eq!(tag_list(&[5, 0, 0, 0, 7, 0, 0, 0]).unwrap(), [7]);
        assert!(tag_list(&[]).unwrap().is_empty());
    }

    #[test]
    fn a_group_is_found_whatever_its_case_and_its_tag_list_orders_it() {
        // As a Windows installation has it: the list of groups says
        // `File System` and the keys of its drivers `File system`;
        // `Base` has a tag list, which does not go by number.
        let lines = [
            "2 Npfs 1 File_system - - -",
            "2 Msfs 1 File_system - - -",
            "1 Null 1 Base 1 - -",
            "1 msrpc 3 - 1 - -",
            "1 Beep 1 base 2 - -",
            "1 Zeta 1 Base 14 - -",
            "1 Untagged 1 BASE - - -",
            "1 Odd 1 Base 99 - -",
        ];
        let groups = ["Boot Bus Extender", "Base", "Video", "File System"];
        let tags: &[(&str, &[u32])] = &[("Base", &[14, 1, 2, 3]), ("Video", &[1])];
        // `Base` in its tag list's order, then its drivers with a tag
        // the list has not, or with none, as the keys come; then
        // `File System`, which has no tag list, as the keys come.
        assert_eq!(
            from_keys(&lines, &groups, tags),
            "Zeta Null Beep Odd Untagged Msfs Npfs"
        );
        // Without the tag list, `Base` too is as its keys come.
        assert_eq!(
            from_keys(&lines, &groups, &[]),
            "Beep Null Odd Untagged Zeta Msfs Npfs"
        );
        // A group the list does not have, in any case, goes last.
        assert_eq!(
            from_keys(&lines[..3], &["File Systems", "Base"], &[]),
            "Null Msfs Npfs"
        );
    }

    #[test]
    fn a_control_set_without_services_starts_nothing() {
        let mut hive = Hive::new();
        let root = hive.root().unwrap();
        assert_eq!(boot_start(&hive, root), Ok(Vec::new()));
    }
}
