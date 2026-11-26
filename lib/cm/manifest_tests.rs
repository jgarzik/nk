//! The manifest reader: every type and data form, what is refused and
//! at which line, and laying a manifest over a tree; then NK's own
//! overlay file, `fixtures/registry-overlay.txt`, alone and over the
//! Windows-written hive.

use crate::manifest::{ManifestError, Op, apply, parse};
use crate::regf::Regf;
use crate::{Error, Hive, KeyId, import};
use std::path::PathBuf;

fn w(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn key(path: &str) -> Op {
    Op::Key {
        path: w(path),
        class: None,
    }
}

fn value(name: &str, kind: u32, data: &[u8]) -> Op {
    Op::Value {
        name: w(name),
        kind,
        data: data.to_vec(),
    }
}

/// The type and data of the one value `line` describes.
fn one(line: &str) -> (u32, Vec<u8>) {
    let ops = parse(format!("key K\nvalue V {line}").as_bytes())
        .unwrap_or_else(|e| panic!("{line}: {e}"));
    match &ops[..] {
        [_, Op::Value { name, kind, data }] if *name == w("V") => (*kind, data.clone()),
        other => panic!("{line}: {other:?}"),
    }
}

/// What refuses the text, which must be refused at its last line.
fn refused(text: &str) -> &'static str {
    let error = parse(text.as_bytes()).expect_err(text);
    assert_eq!(error.line as usize, text.split('\n').count(), "{text}");
    error.what
}

#[test]
fn every_type_stores_its_data_as_the_format_says() {
    assert_eq!(one("sz nk"), (1, utf16("nk\0")));
    assert_eq!(one("sz \"\""), (1, utf16("\0")));
    assert_eq!(one("sz \"two words\""), (1, utf16("two words\0")));
    assert_eq!(
        one("expand_sz %SystemRoot%\\nk"),
        (2, utf16("%SystemRoot%\\nk\0"))
    );
    assert_eq!(
        one("multi_sz one two \"three and four\""),
        (7, utf16("one\0two\0three and four\0\0"))
    );
    assert_eq!(one("multi_sz"), (7, utf16("\0")));
    assert_eq!(one("dword 0x12345678"), (4, vec![0x78, 0x56, 0x34, 0x12]));
    assert_eq!(one("dword 0X1f"), (4, vec![0x1F, 0, 0, 0]));
    assert_eq!(one("dword 4294967295"), (4, vec![0xFF; 4]));
    assert_eq!(one("dword 0"), (4, vec![0; 4]));
    assert_eq!(
        one("dword_be 0x12345678"),
        (5, vec![0x12, 0x34, 0x56, 0x78])
    );
    assert_eq!(
        one("qword 0x0123456789abcdef"),
        (11, 0x0123_4567_89AB_CDEFu64.to_le_bytes().to_vec())
    );
    assert_eq!(
        one("qword 18446744073709551615"),
        (11, vec![0xFF; 8]),
        "the largest"
    );
    for (name, kind) in [
        ("none", 0),
        ("binary", 3),
        ("resource_list", 8),
        ("full_resource_descriptor", 9),
        ("resource_requirements_list", 10),
    ] {
        assert_eq!(one(&format!("{name} hex:")), (kind, vec![]), "{name}");
        assert_eq!(
            one(&format!("{name} hex:00a1B2ff")),
            (kind, vec![0, 0xA1, 0xB2, 0xFF]),
            "{name}"
        );
    }
}

#[test]
fn any_type_takes_raw_data() {
    // A string as a driver may store one: no terminator, half a
    // character.
    assert_eq!(one("sz hex:6e006b"), (1, vec![0x6E, 0, 0x6B]));
    assert_eq!(one("multi_sz hex:"), (7, vec![]));
    assert_eq!(one("dword hex:0102"), (4, vec![1, 2]));
    assert_eq!(one("qword counter:3"), (11, vec![0, 0, 0]));
    assert_eq!(one("binary counter:0"), (3, vec![]));
    assert_eq!(
        one("binary counter:10"),
        (3, vec![0, 0, 0, 0, 1, 0, 0, 0, 2, 0])
    );
    assert_eq!(one("binary counter:0x10").1.len(), 16);
    let (_, most) = one("sz counter:1048576");
    assert_eq!(most.len(), 1 << 20);
    assert_eq!(most[most.len() - 4..], 0x3_FFFFu32.to_le_bytes());
    // Two fields are two strings, whatever they look like.
    assert_eq!(
        one("multi_sz hex:00 counter:1"),
        (7, utf16("hex:00\0counter:1\0\0"))
    );
}

#[test]
fn quoted_strings_are_json_strings() {
    assert_eq!(
        one(r#"sz "a\\b \"c\" \/ \u00e9\u03B1""#),
        (1, utf16("a\\b \"c\" / \u{e9}\u{3b1}\0"))
    );
    assert_eq!(one(r#"sz "\b\f\n\r\t""#), (1, utf16("\u{8}\u{c}\n\r\t\0")));
    assert_eq!(one(r#"sz "\ud83d\ude00""#), (1, utf16("\u{1f600}\0")));
    assert_eq!(one("sz \"#\""), (1, utf16("#\0")), "no comment in a line");
    // Names: quoted, unnamed, and with a backslash, which a value's
    // name may hold.
    let ops = parse(
        br#"key "Control\\two words\\caf\u00e9"
value "" sz unnamed
value "a\\b c" dword 1"#,
    )
    .unwrap();
    assert_eq!(
        ops,
        [
            key("Control\\two words\\caf\u{e9}"),
            value("", 1, &utf16("unnamed\0")),
            value("a\\b c", 4, &[1, 0, 0, 0]),
        ]
    );
}

#[test]
fn keys_classes_comments_and_blank_lines() {
    let ops = parse(
        b"# a comment\n\n   \n  # another, after spaces\n\
          key A\\B class \"Nk \\u03ba\"\n\
          value   V   dword   1  \n\
          key a\\b\\C\n\
          keys A\\Key 3\n\
          keys Many\\ 0x2\n\
          key D\n",
    )
    .unwrap();
    assert_eq!(
        ops,
        [
            Op::Key {
                path: w("A\\B"),
                class: Some(utf16("Nk \u{3ba}")),
            },
            value("V", 4, &[1, 0, 0, 0]),
            key("a\\b\\C"),
            key("A\\Key0000"),
            key("A\\Key0001"),
            key("A\\Key0002"),
            key("Many\\0000"),
            key("Many\\0001"),
            key("D"),
        ]
    );
    let ops = parse(b"keys K 10000").unwrap();
    assert_eq!(ops.len(), 10000);
    assert_eq!(ops[9999], key("K9999"));
    assert_eq!(ops[1234], key("K1234"));
}

#[test]
fn a_text_that_names_no_key_is_no_operations() {
    assert_eq!(parse(b""), Ok(vec![]));
    assert_eq!(parse(b"\n\n"), Ok(vec![]));
    assert_eq!(parse(b"# only a comment\n   \n"), Ok(vec![]));
}

#[test]
fn what_is_malformed_is_refused_with_its_line() {
    assert_eq!(
        parse(b"key A\n# fine\nvalue V dword\nkey B"),
        Err(ManifestError {
            line: 3,
            what: "this type takes one number that fits it"
        })
    );
    assert_eq!(
        parse(b"key A\n\n\nbogus").unwrap_err().to_string(),
        "line 4: unknown line kind"
    );
    let number = "this type takes one number that fits it";
    let raw = "this type takes hex:<digits> or counter:<length>";
    for (text, what) in [
        ("frob A", "unknown line kind"),
        ("\"\"", "unknown line kind"),
        ("KEY A", "unknown line kind"),
        ("key", "expected: key <path> [class <string>]"),
        ("key A B", "expected: key <path> [class <string>]"),
        ("key A class", "expected: key <path> [class <string>]"),
        ("key A klass B", "expected: key <path> [class <string>]"),
        ("key A class B C", "expected: key <path> [class <string>]"),
        ("key \\A", "a key path has an empty component"),
        ("key A\\", "a key path has an empty component"),
        ("key A\\\\B", "a key path has an empty component"),
        ("key \"\"", "a key path has an empty component"),
        ("key A\nkey B\nkey a", "the key is already there"),
        ("key A\\B\nkey a\\b", "the key is already there"),
        ("keys A 2\nkey a0001", "the key is already there"),
        ("key A0001\nkeys a 2", "the key is already there"),
        (
            "key A\\B\nkey a class C",
            "a key with a class must come before the keys under it",
        ),
        ("keys A", "expected: keys <path-prefix> <count, 1 to 10000>"),
        (
            "keys A 0",
            "expected: keys <path-prefix> <count, 1 to 10000>",
        ),
        (
            "keys A 10001",
            "expected: keys <path-prefix> <count, 1 to 10000>",
        ),
        (
            "keys A x",
            "expected: keys <path-prefix> <count, 1 to 10000>",
        ),
        (
            "keys A 1 2",
            "expected: keys <path-prefix> <count, 1 to 10000>",
        ),
        ("keys A\\\\ 1", "a key path has an empty component"),
        ("value V dword 1", "a value needs a key line before it"),
        (
            "key A\nkeys B 1\nvalue V dword 1",
            "a value needs a key line before it",
        ),
        ("key A\nvalue V", "expected: value <name> <type> <data...>"),
        ("key A\nvalue", "expected: value <name> <type> <data...>"),
        ("key A\nvalue V word 1", "unknown type"),
        ("key A\nvalue V SZ a", "unknown type"),
        (
            "key A\nvalue V dword 1\nvalue W dword 1\nvalue v dword 2",
            "the value is already there",
        ),
        ("key A\nvalue V sz", "this type takes one string"),
        ("key A\nvalue V sz a b", "this type takes one string"),
        ("key A\nvalue V expand_sz", "this type takes one string"),
        (
            "key A\nvalue V multi_sz a \"\" b",
            "an empty string would end a multi_sz early",
        ),
        ("key A\nvalue V dword", number),
        ("key A\nvalue V dword 1 2", number),
        ("key A\nvalue V dword 0x100000000", number),
        ("key A\nvalue V dword_be 4294967296", number),
        ("key A\nvalue V qword 18446744073709551616", number),
        ("key A\nvalue V qword 0x10000000000000000", number),
        ("key A\nvalue V dword -1", number),
        ("key A\nvalue V dword 0x", number),
        ("key A\nvalue V dword 010", number),
        ("key A\nvalue V dword 12a", number),
        ("key A\nvalue V dword \"\"", number),
        ("key A\nvalue V binary", raw),
        ("key A\nvalue V binary 0102", raw),
        ("key A\nvalue V none hex:00 hex:01", raw),
        ("key A\nvalue V resource_list 1", raw),
        (
            "key A\nvalue V binary hex:012",
            "hex: takes pairs of hex digits",
        ),
        (
            "key A\nvalue V binary hex:0g",
            "hex: takes pairs of hex digits",
        ),
        (
            "key A\nvalue V sz counter:1048577",
            "counter: takes a length of at most 1 MiB",
        ),
        (
            "key A\nvalue V sz counter:",
            "counter: takes a length of at most 1 MiB",
        ),
        (
            "key A\nvalue V sz counter:-1",
            "counter: takes a length of at most 1 MiB",
        ),
        ("key A\"B", "a quote inside a bare word"),
        ("key \"A\"B", "a quoted string must be followed by a space"),
        ("key \"A", "a quoted string does not end"),
        ("key \"A\\", "a quoted string does not end"),
        ("key \"A\\x\"", "an unknown escape in a quoted string"),
        ("key \"\\u12\"", "\\u takes four hex digits"),
        ("key \"\\u12g4\"", "\\u takes four hex digits"),
        ("key \"\\ud83d\"", "a string holds half of a surrogate pair"),
        (
            "key A\nvalue \"\\ude00\\ud83d\" dword 1",
            "a string holds half of a surrogate pair",
        ),
        (
            "key caf\u{e9}",
            "not ASCII: write other characters as \\uXXXX in quotes",
        ),
        (
            "# caf\u{e9}",
            "not ASCII: write other characters as \\uXXXX in quotes",
        ),
        ("key A\r", "a control character"),
        ("key\tA", "a control character"),
    ] {
        assert_eq!(refused(text), what, "{text:?}");
    }
    let long = "x".repeat(256);
    assert_eq!(
        refused(&format!("key A\\{long}")),
        "a key name is longer than 255 characters"
    );
    assert_eq!(
        refused(&format!("keys {} 1", &long[..252])),
        "a key name is longer than 255 characters"
    );
    parse(format!("key A\\{}", &long[..255]).as_bytes()).unwrap();
    parse(format!("keys {} 1", &long[..251]).as_bytes()).unwrap();
    let name = "n".repeat(16384);
    assert_eq!(
        refused(&format!("key A\nvalue {name} dword 1")),
        "value name too long"
    );
    parse(format!("key A\nvalue {} dword 1", &name[..16383]).as_bytes()).unwrap();
}

/// A tree with `\Registry\Machine\System`, and that key.
fn tree() -> (Hive, KeyId) {
    let mut hive = Hive::new();
    let root = hive.root().unwrap();
    hive.create(root, &w("Machine")).unwrap();
    let (system, _) = hive.create(root, &w("Machine\\System")).unwrap();
    (hive, system)
}

fn read(hive: &Hive, from: KeyId, path: &str, name: &str) -> (u32, Vec<u8>) {
    let id = hive
        .open(from, &w(path))
        .unwrap_or_else(|e| panic!("{path}: {e:?}"));
    let (_, kind, data) = hive
        .value(id, &w(name))
        .unwrap_or_else(|e| panic!("{path}\\{name}: {e:?}"));
    (kind, data.to_vec())
}

#[test]
fn a_manifest_is_laid_over_what_is_there() {
    let (mut hive, system) = tree();
    let (services, _) = hive.create(system, &w("Services")).unwrap();
    let (acpi, _) = hive.create(system, &w("Services\\ACPI")).unwrap();
    hive.set_value(acpi, &w("Start"), 4, &3u32.to_le_bytes())
        .unwrap();
    hive.set_value(acpi, &w("Group"), 1, &utf16("Core\0"))
        .unwrap();
    hive.set_class(acpi, &utf16("old")).unwrap();
    for key in [system, services, acpi] {
        hive.set_last_write(key, 5).unwrap();
    }
    let ops = parse(
        b"key SERVICES\\acpi class new\n\
          value START dword 0\n\
          value Tag dword 2\n\
          key Services\\Pci\\Parameters\\Deep\n\
          value \"\" sz here\n\
          keys Enum\\Key 2\n\
          key Untouched",
    )
    .unwrap();
    apply(&mut hive, system, &ops, 9).unwrap();

    // The key that was there: one key still, under its own spelling,
    // its other value kept, the value named again replaced under the
    // name it had, the new one after them.
    assert_eq!(hive.open(system, &w("Services\\ACPI")), Ok(acpi));
    let info = hive.info(acpi).unwrap();
    assert_eq!(info.name, w("ACPI"));
    assert_eq!(info.class, utf16("new"));
    assert_eq!(info.values, 3);
    assert_eq!(info.last_write, 9);
    assert_eq!(
        hive.value(acpi, &w("start")),
        Ok((&w("Start")[..], 4, &[0u8; 4][..]))
    );
    assert_eq!(read(&hive, system, "Services\\ACPI", "Group").0, 1);
    assert_eq!(
        hive.value_at(acpi, 2).unwrap().map(|v| v.0.to_vec()),
        Some(w("Tag"))
    );
    assert_eq!(hive.info(services).unwrap().subkeys, 2, "ACPI and Pci");

    // New keys, with every key above them, spelled as the manifest
    // spells them and stamped; so is the key each was made under.
    assert_eq!(
        read(&hive, system, "services\\pci\\parameters\\deep", ""),
        (1, utf16("here\0"))
    );
    let pci = hive.open(system, &w("Services\\Pci")).unwrap();
    assert_eq!(hive.info(pci).unwrap().name, w("Pci"));
    assert_eq!(hive.info(pci).unwrap().last_write, 9);
    assert_eq!(hive.info(services).unwrap().last_write, 9);
    assert_eq!(hive.info(system).unwrap().last_write, 9);
    for path in ["Enum\\Key0000", "Enum\\Key0001", "Untouched"] {
        let key = hive.open(system, &w(path)).unwrap();
        assert_eq!(hive.info(key).unwrap().values, 0, "{path}");
    }
    assert_eq!(hive.open(system, &w("Enum\\Key0002")), Err(Error::NotFound));

    // A key the manifest names and changes nothing of keeps its time.
    let (mut hive, system) = tree();
    let (old, _) = hive.create(system, &w("Old")).unwrap();
    hive.set_last_write(old, 5).unwrap();
    hive.set_last_write(system, 5).unwrap();
    apply(&mut hive, system, &parse(b"key old").unwrap(), 9).unwrap();
    assert_eq!(hive.info(old).unwrap().last_write, 5);
    assert_eq!(hive.info(system).unwrap().last_write, 5);
    assert_eq!(hive.info(system).unwrap().subkeys, 1);
    // No operations change nothing.
    apply(&mut hive, system, &[], 9).unwrap();
    assert_eq!(hive.info(system).unwrap().last_write, 5);
}

#[test]
fn a_symbolic_link_is_a_key_like_any_other() {
    let (mut hive, system) = tree();
    hive.create(system, &w("ControlSet001")).unwrap();
    let (link, _) = hive.create(system, &w("CurrentControlSet")).unwrap();
    hive.link_to(link, &w("\\Registry\\Machine\\System\\ControlSet001"))
        .unwrap();
    let ops = parse(b"key CurrentControlSet\\Services").unwrap();
    apply(&mut hive, system, &ops, 0).unwrap();
    assert_eq!(hive.info(link).unwrap().subkeys, 1);
    let set = hive.open(system, &w("ControlSet001")).unwrap();
    assert_eq!(hive.info(set).unwrap().subkeys, 0);
}

#[test]
fn a_deleted_key_takes_nothing() {
    let (mut hive, system) = tree();
    let (gone, _) = hive.create(system, &w("Gone")).unwrap();
    hive.opened(gone);
    hive.delete(gone).unwrap();
    let ops = parse(b"key A").unwrap();
    assert_eq!(apply(&mut hive, gone, &ops, 0), Err(Error::Deleted));
}

// ---- NK's overlay file ---------------------------------------------------

fn repository() -> PathBuf {
    [env!("CARGO_MANIFEST_DIR"), "..", ".."].iter().collect()
}

fn overlay() -> Vec<Op> {
    let text = std::fs::read(repository().join("fixtures/registry-overlay.txt")).unwrap();
    parse(&text).unwrap_or_else(|e| panic!("fixtures/registry-overlay.txt: {e}"))
}

#[test]
fn the_overlay_file_is_well_formed() {
    let ops = overlay();
    let (mut hive, system) = tree();
    apply(&mut hive, system, &ops, 0).unwrap();
    assert_eq!(
        read(
            &hive,
            system,
            "ControlSet001\\Control\\NkTest\\Overlay",
            "Marker"
        ),
        (1, utf16("laid over the hive\0"))
    );
}

/// Over the Windows-written hive, the overlay's value wins and the
/// hive's other values stay. Without the fixture the test says so on
/// stderr and passes.
#[test]
fn the_overlay_wins_over_the_hive() {
    let Ok(file) = std::fs::read(repository().join("target/fixtures/system.hiv")) else {
        eprintln!("SKIP: no Windows-written hive (target/fixtures/system.hiv)");
        return;
    };
    let (mut hive, system) = tree();
    import(&mut hive, system, &Regf::parse(&file).unwrap()).unwrap();
    let types = "ControlSet001\\Control\\NkTest\\Types";
    assert_eq!(read(&hive, system, types, "String"), (1, utf16("nk\0")));
    let before = hive
        .info(hive.open(system, &w(types)).unwrap())
        .unwrap()
        .values;
    apply(&mut hive, system, &overlay(), 0).unwrap();
    assert_eq!(
        read(&hive, system, types, "String"),
        (1, utf16("overlaid\0"))
    );
    assert_eq!(
        read(&hive, system, types, "Dword"),
        (4, vec![0x78, 0x56, 0x34, 0x12])
    );
    let after = hive
        .info(hive.open(system, &w(types)).unwrap())
        .unwrap()
        .values;
    assert_eq!(before, after, "replaced, not added");
}
