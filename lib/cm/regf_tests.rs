//! Tests of the hive-file walker, on files the test writer makes.

use crate::regf::*;
use crate::writer::{NIL, Sample, Writer, big_data, sample, seal, wide};

/// A key as the walker reports it.
#[derive(Debug, PartialEq)]
struct Found {
    path: String,
    flags: u16,
    time: u64,
    class: Vec<u8>,
    security: Vec<u8>,
    values: Vec<(String, u32, Vec<u8>)>,
}

fn text(name: Name<'_>) -> String {
    let units: Vec<u16> = name.units().collect();
    assert_eq!(units.len(), name.len());
    assert_eq!(units.is_empty(), name.is_empty());
    String::from_utf16(&units).unwrap()
}

fn visit(
    regf: &Regf<'_>,
    key: &KeyNode<'_>,
    above: &str,
    found: &mut Vec<Found>,
) -> Result<(), RegfError> {
    let path = format!("{above}\\{}", text(key.name));
    let mut values = Vec::new();
    for value in regf.values(key)? {
        let value = value?;
        let pieces = regf.data(&value)?;
        let (len, empty) = (pieces.len(), pieces.is_empty());
        let mut data = Vec::new();
        for piece in pieces {
            data.extend(piece?);
        }
        assert_eq!((data.len(), data.is_empty()), (len, empty));
        values.push((text(value.name), value.kind, data));
    }
    found.push(Found {
        path: path.clone(),
        flags: key.flags,
        time: key.last_write,
        class: regf.class(key)?.to_vec(),
        security: regf.security(key)?.to_vec(),
        values,
    });
    for subkey in regf.subkeys(key)? {
        visit(regf, &subkey?, &path, found)?;
    }
    Ok(())
}

/// Everything in a hive file.
fn walk(file: &[u8]) -> Result<Vec<Found>, RegfError> {
    let regf = Regf::parse(file)?;
    let mut found = Vec::new();
    visit(&regf, &regf.root()?, "", &mut found)?;
    Ok(found)
}

/// The sample after `change`, walked.
fn changed(change: impl FnOnce(&mut Writer, &mut Sample)) -> Result<Vec<Found>, RegfError> {
    let (mut hive, mut cells) = sample();
    change(&mut hive, &mut cells);
    walk(&hive.finish(cells.root))
}

/// The cell of the sample's big-data record.
fn db(hive: &Writer, cells: &Sample) -> u32 {
    hive.peek(cells.big, 8)
}

/// The cell of segment `index` of the sample's big value.
fn segment(hive: &Writer, cells: &Sample, index: usize) -> u32 {
    hive.peek(hive.peek(db(hive, cells), 4), 4 * index)
}

#[test]
fn the_checksum_is_the_xor_of_127_words() {
    let mut base = vec![0u8; BASE_BLOCK];
    // Nothing set: zero, which is stored as one.
    assert_eq!(checksum(&base), 1);
    base[..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    base[4..8].copy_from_slice(&0x0F0F_0F0Fu32.to_le_bytes());
    assert_eq!(checksum(&base), 0x1D3B_5977);
    // The last word covered is the 127th; the checksum's own place and
    // what follows are not.
    base[504..508].copy_from_slice(&0x8000_0000u32.to_le_bytes());
    assert_eq!(checksum(&base), 0x9D3B_5977);
    base[508..516].fill(0xFF);
    assert_eq!(checksum(&base), 0x9D3B_5977);
    // All ones is stored as all ones less one.
    base[504..508].copy_from_slice(&(!0x1D3B_5977u32).to_le_bytes());
    assert_eq!(checksum(&base), 0xFFFF_FFFE);
}

#[test]
fn the_lh_hash_is_over_upper_cased_characters() {
    let hash = |name: &str| lh_hash(name.encode_utf16());
    assert_eq!(hash(""), 0);
    assert_eq!(hash("A"), 65);
    assert_eq!(hash("a"), 65);
    assert_eq!(hash("ab"), 65 * 37 + 66);
    assert_eq!(hash("é"), 0xC9);
    // Long enough to wrap: the same sum kept in 64 bits.
    let name = "CurrentControlSet";
    let wrapped = name
        .to_uppercase()
        .bytes()
        .fold(0u64, |h, c| (h * 37 + u64::from(c)) & 0xFFFF_FFFF);
    assert_eq!(u64::from(hash(name)), wrapped);
    assert_ne!(hash("ControlSet001"), hash("ControlSet002"));
}

#[test]
fn a_hive_is_walked_key_by_key() {
    let found = changed(|_, _| {}).unwrap();
    let paths: Vec<&str> = found.iter().map(|key| &key.path[..]).collect();
    assert_eq!(
        paths,
        [
            "\\ROOT",
            "\\ROOT\\Alpha",
            "\\ROOT\\Alpha\\Ключ",
            "\\ROOT\\beta",
            "\\ROOT\\Gamma"
        ]
    );
    let root = &found[0];
    assert_eq!(root.security, [1, 0, 4, 0x80, 9, 9]);
    assert_eq!((root.flags, root.time, &root.class[..]), (0x20, 0, &[][..]));
    let values: Vec<(&str, u32, &[u8])> = root
        .values
        .iter()
        .map(|(name, kind, data)| (&name[..], *kind, &data[..]))
        .collect();
    let big = big_data();
    assert_eq!(
        values,
        [
            ("", 1, &[][..]),
            ("one", 3, &[1]),
            ("two", 3, &[1, 2]),
            ("three", 3, &[1, 2, 3]),
            ("dword", 4, &[0x78, 0x56, 0x34, 0x12]),
            ("text", 1, &wide("regf\0")),
            ("big", 3, &big),
            ("Знач", 3, &[1, 2, 3, 4, 5]),
        ]
    );
    assert_eq!(found[1].class, wide("Cls"));
    assert_eq!(found[1].security, [], "no security record named");
    assert_eq!(found[2].flags, 0, "a UTF-16 name");
    let gamma = &found[4];
    assert_eq!(gamma.flags & KEY_SYM_LINK, KEY_SYM_LINK);
    assert_eq!(gamma.time, 0x01D9_0000_0000_1234);
}

#[test]
fn big_data_come_in_segments() {
    let (hive, cells) = sample();
    let file = hive.finish(cells.root);
    let regf = Regf::parse(&file).unwrap();
    let root = regf.root().unwrap();
    let big = regf.values(&root).unwrap().nth(6).unwrap().unwrap();
    let sizes: Vec<usize> = regf
        .data(&big)
        .unwrap()
        .map(|piece| piece.unwrap().len())
        .collect();
    assert_eq!(sizes, [BIG_SEGMENT, BIG_SEGMENT, 40000 - 2 * BIG_SEGMENT]);
    assert_eq!(regf.key_limit(), (file.len() - BASE_BLOCK) / 0x4C);
    // Before version 1.4 long data lie in one cell.
    let mut old = Writer::new();
    old.minor = 3;
    let key = old.key(NIL, "K", true);
    let long = old.value("long", true, 3, &big_data()[..20000]);
    old.values(key, &[long]);
    let found = walk(&old.finish(key)).unwrap();
    assert_eq!(found[0].values[0].2, big_data()[..20000]);
    // A segment more than the data need holds nothing of them.
    let found = changed(|hive, cells| {
        let extra = hive.cell(&[7; 8]);
        let mut list = Vec::new();
        for cell in [0, 1, 2].map(|i| segment(hive, cells, i)) {
            list.extend(cell.to_le_bytes());
        }
        list.extend(extra.to_le_bytes());
        let list = hive.cell(&list);
        let db = db(hive, cells);
        hive.patch(db, 4, list);
        hive.patch16(db, 2, 4);
    })
    .unwrap();
    assert_eq!(found[0].values[6].2, big_data());
}

#[test]
fn a_base_block_that_is_wrong_is_refused() {
    let (hive, cells) = sample();
    let good = hive.finish(cells.root);
    let size = (good.len() - BASE_BLOCK) as u32;
    let parse = |change: &dyn Fn(&mut Vec<u8>), sealed: bool| {
        let mut file = good.clone();
        change(&mut file);
        if sealed {
            seal(&mut file);
        }
        Regf::parse(&file).map(|_| ())
    };
    let set = |at: usize, value: u32| {
        move |file: &mut Vec<u8>| file[at..at + 4].copy_from_slice(&value.to_le_bytes())
    };
    assert_eq!(parse(&|_| {}, false), Ok(()));
    // What follows the bins is not looked at.
    assert_eq!(parse(&|file| file.extend([0xEE; 100]), false), Ok(()));
    assert_eq!(
        parse(&|file| file.truncate(4095), false),
        Err(RegfError::NotRegf)
    );
    assert_eq!(parse(&|file| file.clear(), false), Err(RegfError::NotRegf));
    assert_eq!(parse(&set(0, 0x6667_6552), true), Err(RegfError::NotRegf));
    // A changed byte without a new checksum; a wrong checksum alone.
    assert_eq!(parse(&set(0x30, 1), false), Err(RegfError::Corrupt));
    assert_eq!(parse(&set(0x1FC, 0), false), Err(RegfError::Corrupt));
    // The sequence numbers differ: the checksum is right, the file is
    // not whole.
    assert_eq!(parse(&set(4, 2), true), Err(RegfError::Dirty));
    assert_eq!(parse(&set(8, 0), true), Err(RegfError::Dirty));
    for (at, value) in [(0x14, 2), (0x18, 2), (0x18, 7), (0x1C, 1), (0x20, 0)] {
        assert_eq!(parse(&set(at, value), true), Err(RegfError::Unsupported));
    }
    for minor in 3..=6 {
        assert_eq!(parse(&set(0x18, minor), true), Ok(()));
    }
    for length in [0, 0x800, size + 0x1000, u32::MAX] {
        assert_eq!(parse(&set(0x28, length), true), Err(RegfError::BadLength));
    }
    // The bin: its signature, where it says it is, its size; and the
    // bins must end where the length does.
    let bin = BASE_BLOCK;
    assert_eq!(parse(&set(bin, 0), false), Err(RegfError::BadBin));
    assert_eq!(parse(&set(bin + 4, 0x1000), false), Err(RegfError::BadBin));
    for wrong in [0, 0x800, size + 0x1000] {
        assert_eq!(parse(&set(bin + 8, wrong), false), Err(RegfError::BadBin));
    }
    assert_eq!(
        parse(&set(0x28, size - 0x1000), true),
        Err(RegfError::BadBin)
    );
    // Two bins where there was one: the second needs a header too.
    assert_eq!(parse(&set(bin + 8, 0x1000), false), Err(RegfError::BadBin));
    let two = |file: &mut Vec<u8>| {
        file[bin + 8..bin + 12].copy_from_slice(&0x1000u32.to_le_bytes());
        let second = bin + 0x1000;
        file[second..second + 4].copy_from_slice(b"hbin");
        file[second + 4..second + 8].copy_from_slice(&0x1000u32.to_le_bytes());
        file[second + 8..second + 12].copy_from_slice(&(size - 0x1000).to_le_bytes());
    };
    assert_eq!(parse(&two, false), Ok(()));
}

#[test]
fn a_cell_must_be_allocated_aligned_and_inside_the_bins() {
    let fails = |change: fn(&mut Writer, &mut Sample)| changed(change).unwrap_err();
    let resize = |hive: &mut Writer, cell: u32, size: i32| {
        hive.bins[cell as usize..][..4].copy_from_slice(&size.to_le_bytes());
    };
    assert_eq!(fails(|_, c| c.root = NIL), RegfError::OutOfBounds);
    assert_eq!(fails(|_, c| c.root = 0x10_0000), RegfError::OutOfBounds);
    // The last three bytes of the bins hold no size.
    assert_eq!(
        fails(|h, c| c.root = ((h.bins.len() + 4095) & !4095) as u32 - 3),
        RegfError::OutOfBounds
    );
    // The size runs past the end of the bins.
    assert_eq!(
        changed(|h, c| resize(h, c.alpha, -0x10_0000)),
        Err(RegfError::OutOfBounds)
    );
    assert_eq!(fails(|h, c| h.free(c.alpha)), RegfError::FreeCell);
    assert_eq!(fails(|h, c| h.free(c.root)), RegfError::FreeCell);
    assert_eq!(
        changed(|h, c| resize(h, c.alpha, 0)),
        Err(RegfError::FreeCell)
    );
    // A size that is no multiple of eight, though the key fits it; an
    // offset that is none, though a cell that holds the class could be
    // read there.
    assert_eq!(
        changed(|h, c| resize(h, c.alpha, -0x5C)),
        Err(RegfError::BadCell)
    );
    assert_eq!(
        fails(|h, c| {
            let inner = h.cell(&(-16i32).to_le_bytes().repeat(4));
            h.patch(c.alpha, 0x30, inner + 4);
        }),
        RegfError::BadCell
    );
}

#[test]
fn a_record_must_fit_its_cell() {
    let fails = |change: fn(&mut Writer, &mut Sample)| changed(change).unwrap_err();
    let bad = RegfError::BadCell;
    let outside = RegfError::OutOfBounds;
    // Key nodes.
    assert_eq!(fails(|h, c| h.patch16(c.alpha, 0, 0x7878)), bad);
    assert_eq!(fails(|h, c| c.root = h.cell(b"nk\0\0\0\0\0\0")), bad);
    assert_eq!(fails(|h, c| h.patch16(c.root, 0x48, 0x1000)), bad);
    assert_eq!(fails(|h, c| h.patch16(c.deep, 0x48, 7)), bad);
    assert_eq!(fails(|h, c| h.patch16(c.alpha, 0x4A, 0x800)), bad);
    assert_eq!(fails(|h, c| h.patch(c.alpha, 0x30, NIL)), outside);
    // A subkey that names another parent; more or fewer subkeys than
    // the key says.
    assert_eq!(fails(|h, c| h.patch(c.alpha, 0x10, c.gamma)), bad);
    assert_eq!(fails(|h, c| h.patch(c.root, 0x14, 4)), bad);
    assert_eq!(fails(|h, c| h.patch(c.root, 0x14, 2)), bad);
    // Subkey lists.
    assert_eq!(fails(|h, c| h.patch16(c.lh, 0, 0x7A7A)), bad);
    assert_eq!(fails(|h, c| h.patch16(c.lh, 2, 500)), bad);
    assert_eq!(fails(|h, c| h.patch16(c.ri, 2, 500)), bad);
    assert_eq!(fails(|h, c| h.patch(c.root, 0x1C, NIL)), outside);
    assert_eq!(fails(|h, c| h.free(c.lf)), RegfError::FreeCell);
    // Values.
    assert_eq!(fails(|h, c| h.patch(c.root, 0x24, 1000)), bad);
    assert_eq!(fails(|h, c| h.patch(c.root, 0x28, NIL)), outside);
    assert_eq!(fails(|h, c| h.patch(c.value_list, 0, c.root)), bad);
    assert_eq!(fails(|h, c| h.patch16(c.text, 2, 0x400)), bad);
    assert_eq!(fails(|h, c| h.patch16(c.wide_value, 2, 3)), bad);
    // Data in the record are four bytes at most; data in a cell are no
    // longer than the cell.
    assert_eq!(fails(|h, c| h.patch(c.dword, 4, 0x8000_0005)), bad);
    assert_eq!(fails(|h, c| h.patch(c.text, 4, 5000)), bad);
    assert_eq!(fails(|h, c| h.patch(c.text, 8, NIL)), outside);
    // Big data: the record, its list of segments, the segments.
    assert_eq!(fails(|h, c| h.patch16(db(h, c), 0, 0x7878)), bad);
    assert_eq!(fails(|h, c| h.patch16(db(h, c), 2, 200)), bad);
    assert_eq!(fails(|h, c| h.patch16(db(h, c), 2, 2)), bad);
    assert_eq!(fails(|h, c| h.patch(c.big, 4, 3 * 16344)), bad);
    assert_eq!(fails(|h, c| h.patch(db(h, c), 4, NIL)), outside);
    assert_eq!(fails(|h, c| h.free(segment(h, c, 1))), RegfError::FreeCell);
    // Security.
    assert_eq!(fails(|h, c| h.patch16(c.sk, 0, 0x7878)), bad);
    assert_eq!(fails(|h, c| h.patch(c.sk, 0x10, 0x1000)), bad);
}

#[test]
fn an_index_root_never_leads_to_another() {
    assert_eq!(
        changed(|hive, cells| {
            let inner = hive.list(b"ri", &[cells.lf]);
            hive.patch(cells.ri, 8, inner);
        }),
        Err(RegfError::TooDeep)
    );
    // An empty list under the root holds no keys and does no harm.
    let found = changed(|hive, cells| {
        let empty = hive.list(b"li", &[]);
        let lists = [cells.lh, empty, cells.lf];
        hive.subkeys(cells.root, b"ri", &lists);
        hive.patch(cells.root, 0x14, 3);
    })
    .unwrap();
    assert_eq!(found.len(), 5);
}

#[test]
fn after_an_error_nothing_more_is_yielded() {
    let (mut hive, cells) = sample();
    hive.free(cells.alpha);
    let second = segment(&hive, &cells, 1);
    hive.free(second);
    let file = hive.finish(cells.root);
    let regf = Regf::parse(&file).unwrap();
    let root = regf.root().unwrap();
    let mut subkeys = regf.subkeys(&root).unwrap();
    assert_eq!(
        subkeys.next().map(|key| key.map(|_| ())),
        Some(Err(RegfError::FreeCell))
    );
    assert!(subkeys.next().is_none());
    let big = regf.values(&root).unwrap().nth(6).unwrap().unwrap();
    let mut data = regf.data(&big).unwrap();
    let mut next = || data.next().map(|piece| piece.map(<[u8]>::len));
    assert_eq!(next(), Some(Ok(BIG_SEGMENT)));
    assert_eq!(next(), Some(Err(RegfError::FreeCell)));
    assert_eq!(next(), None);
}

#[test]
fn a_value_is_read_by_its_path() {
    let (hive, cells) = sample();
    let file = hive.finish(cells.root);
    let regf = Regf::parse(&file).unwrap();
    let mut out = [0u8; 8];
    assert_eq!(regf.read_value(&[], "THREE", &mut out), Ok(3));
    assert_eq!(out[..3], [1, 2, 3]);
    assert_eq!(
        regf.read_value(&["alpha"], "x", &mut out),
        Err(Lookup::NoValue)
    );
    assert_eq!(
        regf.read_value(&["Delta"], "x", &mut out),
        Err(Lookup::NoKey)
    );
    assert_eq!(
        regf.read_value(&["Alpha", "Delta"], "x", &mut out),
        Err(Lookup::NoKey)
    );
    assert_eq!(
        regf.read_value(&[], "big", &mut out),
        Err(Lookup::TooLong(40000))
    );
    let mut big = vec![0u8; 40000];
    assert_eq!(regf.read_value(&[], "big", &mut big), Ok(40000));
    assert_eq!(big, big_data());
}
