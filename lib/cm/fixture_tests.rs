//! The hive reader against a hive Windows wrote: the fixture
//! `system.hiv`, whose content is nk-fixtures' `hive/system.hive.txt`.
//! Without the fixture the tests say so on stderr and pass.

use crate::regf::Regf;
use crate::{Hive, KeyId, import};
use std::path::PathBuf;

const REG_SZ: u32 = 1;
const REG_BINARY: u32 = 3;
const REG_DWORD: u32 = 4;
const REG_MULTI_SZ: u32 = 7;

fn fixture() -> Option<Vec<u8>> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "target", "fixtures"]
        .iter()
        .collect();
    let file = std::fs::read(path.join("system.hiv")).ok();
    if file.is_none() {
        eprintln!("SKIP: no Windows-written hive (target/fixtures/system.hiv)");
    }
    file
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// The fixture, copied into a tree under its root.
fn tree(file: &[u8]) -> (Hive, KeyId) {
    let regf = Regf::parse(file).expect("a hive Windows saved");
    let mut hive = Hive::new();
    let root = hive.root().unwrap();
    import(&mut hive, root, &regf).expect("every key and value of it");
    (hive, root)
}

fn value(hive: &Hive, root: KeyId, key: &str, name: &str) -> (u32, Vec<u8>) {
    let id = hive
        .open(root, &wide(key))
        .unwrap_or_else(|e| panic!("{key}: {e:?}"));
    let (_, kind, data) = hive
        .value(id, &wide(name))
        .unwrap_or_else(|e| panic!("{key}\\{name}: {e:?}"));
    (kind, data.to_vec())
}

/// `counter:<n>` of the manifest: 0, 1, 2, ... as 32-bit words, cut off.
fn counter(n: usize) -> Vec<u8> {
    (0u32..).flat_map(u32::to_le_bytes).take(n).collect()
}

#[test]
fn what_a_kernel_reads_at_boot_is_there() {
    let Some(file) = fixture() else { return };
    let (hive, root) = tree(&file);
    assert_eq!(
        value(&hive, root, "Select", "Current"),
        (REG_DWORD, 1u32.to_le_bytes().to_vec())
    );
    let (kind, order) = value(
        &hive,
        root,
        "ControlSet001\\Control\\ServiceGroupOrder",
        "List",
    );
    assert_eq!(kind, REG_MULTI_SZ);
    // Windows' list: it starts with this group, and `Base` comes
    // before `File System`.
    assert!(order.starts_with(&utf16("System Reserved\0")));
    let place = |group: &str| {
        let group = utf16(&format!("\0{group}\0"));
        order
            .windows(group.len())
            .position(|window| window == group)
            .unwrap_or_else(|| panic!("no group {group:?}"))
    };
    assert!(place("Base") < place("File System"));
    // Names differ in case from how they are asked for.
    assert_eq!(
        value(&hive, root, "controlset001\\SERVICES\\npfs", "start"),
        (REG_DWORD, 1u32.to_le_bytes().to_vec())
    );
    // Windows spells this group `File system` in its drivers' keys,
    // and so may the hive.
    let (kind, group) = value(&hive, root, "ControlSet001\\Services\\Npfs", "Group");
    assert_eq!(kind, REG_SZ);
    assert!(group.eq_ignore_ascii_case(&utf16("File System\0")));
}

#[test]
fn the_boot_start_services_come_in_group_order() {
    let Some(file) = fixture() else { return };
    let (hive, root) = tree(&file);
    let set = hive.open(root, &wide("ControlSet001")).unwrap();
    let names: Vec<String> = crate::services::boot_start(&hive, set)
        .unwrap()
        .into_iter()
        .map(|key| String::from_utf16(hive.info(key).unwrap().name).unwrap())
        .collect();
    // `Base` comes before `File System` in the group list, however
    // the keys spell the latter; in that group, which has no tag list,
    // Msfs (if the hive has it) comes before Npfs as the keys do;
    // msrpc starts on demand.
    let msfs = hive.open(set, &wide("Services\\Msfs")).is_ok();
    let expected: &[&str] = if msfs {
        &["Null", "Msfs", "Npfs"]
    } else {
        &["Null", "Npfs"]
    };
    assert_eq!(names, expected);
}

#[test]
fn values_of_every_size_come_back_whole() {
    let Some(file) = fixture() else { return };
    let (hive, root) = tree(&file);
    let sizes = "ControlSet001\\Control\\NkTest\\Sizes";
    // Up to four bytes live in the value's own record.
    for n in 0..=5usize {
        let expected: Vec<u8> = (0xA1..).take(n).collect();
        assert_eq!(
            value(&hive, root, sizes, &format!("Size{n}")),
            (REG_BINARY, expected)
        );
    }
    // 16344 bytes is the most one cell holds; more is split.
    for n in [16344usize, 16345, 40000] {
        assert_eq!(
            value(&hive, root, sizes, &format!("Size{n}")),
            (REG_BINARY, counter(n)),
            "{n}"
        );
    }
    assert_eq!(
        value(&hive, root, sizes, "String20000"),
        (REG_SZ, counter(20000))
    );
    assert_eq!(
        value(&hive, root, "ControlSet001\\Control\\NkTest", ""),
        (REG_SZ, utf16("the unnamed value\0"))
    );
}

#[test]
fn names_outside_ascii_are_found() {
    let Some(file) = fixture() else { return };
    let (hive, root) = tree(&file);
    let names = "ControlSet001\\Control\\NkTest\\Names";
    for (name, number) in [
        ("ascii", 1u32),
        ("two words", 2),
        ("caf\u{e9}", 3),
        ("\u{3b1}\u{3b2}\u{3b3}", 4),
        ("\u{65e5}\u{672c}\u{8a9e}", 5),
        ("\u{1f600}", 6),
        ("Mixed.Case-and_punctuation", 9),
    ] {
        assert_eq!(
            value(&hive, root, names, name),
            (REG_DWORD, number.to_le_bytes().to_vec()),
            "{name}"
        );
    }
    // In another letter case, within Latin-1 and beyond it.
    for (name, number) in [("CAF\u{c9}", 3u32), ("\u{391}\u{392}\u{393}", 4)] {
        assert_eq!(
            value(&hive, root, names, name),
            (REG_DWORD, number.to_le_bytes().to_vec()),
            "{name}"
        );
        hive.open(root, &wide(&format!("{names}\\{name}")))
            .unwrap_or_else(|e| panic!("{name}: {e:?}"));
    }
    for subkey in ["two words", "caf\u{e9}", "\u{65e5}\u{672c}\u{8a9e}"] {
        hive.open(root, &wide(&format!("{names}\\{subkey}")))
            .unwrap_or_else(|e| panic!("{subkey}: {e:?}"));
    }
}
