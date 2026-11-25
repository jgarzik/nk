//! Copy a hive file into the tree.

use crate::regf::{KEY_SYM_LINK, KeyNode, Regf, RegfError, Subkeys};
use crate::{Error, Hive, KeyId};
use alloc::vec::Vec;

/// How many keys may lie one below another: Windows' own limit on the
/// depth of the registry.
const MAX_DEPTH: usize = 512;

/// Why a hive file was not copied, or not all of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportError {
    /// The file is malformed.
    File(RegfError),
    /// The tree refused a change: no memory, or the key to copy under
    /// has been deleted.
    Tree(Error),
}

impl From<RegfError> for ImportError {
    fn from(error: RegfError) -> Self {
        Self::File(error)
    }
}

impl From<Error> for ImportError {
    fn from(error: Error) -> Self {
        Self::Tree(error)
    }
}

/// Copy what `node` holds itself onto `key`: class, security, last
/// write time, link flag and values.
fn copy(
    hive: &mut Hive,
    key: KeyId,
    regf: &Regf<'_>,
    node: &KeyNode<'_>,
    name: &mut Vec<u16>,
    data: &mut Vec<u8>,
) -> Result<(), ImportError> {
    hive.set_class(key, regf.class(node)?)?;
    hive.set_security(key, regf.security(node)?)?;
    hive.set_last_write(key, node.last_write)?;
    hive.set_link(key, node.flags & KEY_SYM_LINK != 0)?;
    for value in regf.values(node)? {
        let value = value?;
        unpack(name, value.name.len(), value.name.units())?;
        let pieces = regf.data(&value)?;
        // Read through once before room is made for what the value
        // says it holds.
        for piece in pieces.clone() {
            piece?;
        }
        unpack(data, pieces.len(), pieces.flatten().flatten().copied())?;
        hive.set_value(key, name, value.kind, data)?;
    }
    Ok(())
}

/// Put `len` items into `buffer`, in place of what it held.
fn unpack<T>(buffer: &mut Vec<T>, len: usize, items: impl Iterator<Item = T>) -> Result<(), Error> {
    buffer.clear();
    buffer.try_reserve(len).map_err(|_| Error::NoMemory)?;
    buffer.extend(items.take(len));
    Ok(())
}

/// Copy the hive file `regf` into `hive`, its root key onto `under`:
/// the root's name is not used, as a hive is known by where it is
/// mounted.
///
/// The file is laid over what is there. Keys that exist stay, with
/// their subkeys and values; a key the file also has takes the file's
/// class, security descriptor, last write time and link flag, and the
/// file's values, which replace values of the same names.
///
/// On an error the keys copied so far remain.
pub fn import(hive: &mut Hive, under: KeyId, regf: &Regf<'_>) -> Result<(), ImportError> {
    let (mut name, mut data) = (Vec::new(), Vec::new());
    let root = regf.root()?;
    copy(hive, under, regf, &root, &mut name, &mut data)?;
    // A file can hold only so many keys. One whose lists name a key
    // again and again is not copied without end.
    let mut budget = regf.key_limit();
    // The keys being copied, from `under` down, each with the subkeys
    // still to come.
    let mut above: Vec<(KeyId, Subkeys<'_>)> = Vec::new();
    above.try_reserve(1).map_err(|_| Error::NoMemory)?;
    above.push((under, regf.subkeys(&root)?));
    while let Some((parent, subkeys)) = above.last_mut() {
        let parent = *parent;
        let Some(node) = subkeys.next() else {
            above.pop();
            continue;
        };
        let node = node?;
        budget = budget.checked_sub(1).ok_or(RegfError::BadCell)?;
        unpack(&mut name, node.name.len(), node.name.units())?;
        // Such a name would be no key of its parent's in the tree.
        if name.is_empty() || name.contains(&u16::from(b'\\')) {
            return Err(RegfError::BadCell.into());
        }
        let (key, _) = hive.create(parent, &name)?;
        copy(hive, key, regf, &node, &mut name, &mut data)?;
        if above.len() == MAX_DEPTH {
            return Err(RegfError::TooDeep.into());
        }
        above.try_reserve(1).map_err(|_| Error::NoMemory)?;
        above.push((key, regf.subkeys(&node)?));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::writer::{NIL, Writer, big_data, sample, w, wide};

    /// A tree with `\Registry\Machine\System`.
    fn tree() -> (Hive, KeyId) {
        let mut hive = Hive::new();
        let root = hive.root().unwrap();
        hive.create(root, &w("Machine")).unwrap();
        let (system, _) = hive.create(root, &w("Machine\\System")).unwrap();
        (hive, system)
    }

    /// The keys from `key` down, in enumeration order, one line each:
    /// name, class, time, security, link, values.
    fn dump(hive: &Hive, key: KeyId, indent: usize, lines: &mut Vec<String>) {
        let info = hive.info(key).unwrap();
        let mut line = format!(
            "{:indent$}{} class={:?} time={:#x} sd={:?} link={}",
            "",
            String::from_utf16(info.name).unwrap(),
            info.class,
            info.last_write,
            hive.security(key).unwrap(),
            hive.is_link(key).unwrap(),
        );
        for (name, kind, data) in (0..).map_while(|i| hive.value_at(key, i).unwrap()) {
            let name = String::from_utf16(name).unwrap();
            if data.len() > 16 {
                line += &format!(" {name}={kind}:{} bytes", data.len());
            } else {
                line += &format!(" {name}={kind}:{data:?}");
            }
        }
        lines.push(line);
        for subkey in (0..).map_while(|i| hive.subkey(key, i).unwrap()) {
            dump(hive, subkey, indent + 1, lines);
        }
    }

    fn import_file(hive: &mut Hive, under: KeyId, file: &[u8]) -> Result<(), ImportError> {
        import(hive, under, &Regf::parse(file).unwrap())
    }

    #[test]
    fn a_hive_file_becomes_keys_and_values() {
        let (writer, cells) = sample();
        let file = writer.finish(cells.root);
        let (mut hive, system) = tree();
        assert_eq!(import_file(&mut hive, system, &file), Ok(()));
        let mut lines = Vec::new();
        dump(&hive, system, 0, &mut lines);
        assert_eq!(
            lines,
            [
                "System class=[] time=0x0 sd=[1, 0, 4, 128, 9, 9] link=false \
                 =1:[] one=3:[1] two=3:[1, 2] three=3:[1, 2, 3] dword=4:[120, 86, 52, 18] \
                 text=1:[114, 0, 101, 0, 103, 0, 102, 0, 0, 0] big=3:40000 bytes \
                 Знач=3:[1, 2, 3, 4, 5]",
                " Alpha class=[67, 0, 108, 0, 115, 0] time=0x0 sd=[] link=false",
                "  Ключ class=[] time=0x0 sd=[] link=false",
                " beta class=[] time=0x0 sd=[] link=false",
                " Gamma class=[] time=0x1d9000000001234 sd=[] link=true",
            ]
        );
        assert_eq!(hive.value(system, &w("BIG")).unwrap().2, big_data());
        assert_eq!(hive.value(system, &w("text")).unwrap().2, wide("regf\0"));
        // Copied again, nothing is added.
        let once = hive.storage();
        assert_eq!(import_file(&mut hive, system, &file), Ok(()));
        assert_eq!(hive.storage(), once);
    }

    #[test]
    fn the_file_is_laid_over_what_is_there() {
        let (writer, cells) = sample();
        let file = writer.finish(cells.root);
        let (mut hive, system) = tree();
        // Keys and values of the tree's own, some under names the file
        // has too.
        let (existing, _) = hive.create(system, &w("Existing")).unwrap();
        hive.set_value(existing, &w("keep"), 4, &[1, 0, 0, 0])
            .unwrap();
        let (alpha, _) = hive.create(system, &w("ALPHA")).unwrap();
        hive.create(alpha, &w("Own")).unwrap();
        hive.set_value(alpha, &w("old"), 3, &[7]).unwrap();
        hive.set_class(alpha, &[1]).unwrap();
        hive.set_value(system, &w("TWO"), 1, &[0; 8]).unwrap();
        hive.set_value(system, &w("mine"), 3, &[5]).unwrap();
        assert_eq!(import_file(&mut hive, system, &file), Ok(()));
        let mut lines = Vec::new();
        dump(&hive, system, 0, &mut lines);
        assert_eq!(
            lines,
            [
                "System class=[] time=0x0 sd=[1, 0, 4, 128, 9, 9] link=false \
                 TWO=3:[1, 2] mine=3:[5] =1:[] one=3:[1] three=3:[1, 2, 3] \
                 dword=4:[120, 86, 52, 18] \
                 text=1:[114, 0, 101, 0, 103, 0, 102, 0, 0, 0] big=3:40000 bytes \
                 Знач=3:[1, 2, 3, 4, 5]",
                " ALPHA class=[67, 0, 108, 0, 115, 0] time=0x0 sd=[] link=false old=3:[7]",
                "  Own class=[] time=0x0 sd=[] link=false",
                "  Ключ class=[] time=0x0 sd=[] link=false",
                " beta class=[] time=0x0 sd=[] link=false",
                " Existing class=[] time=0x0 sd=[] link=false keep=4:[1, 0, 0, 0]",
                " Gamma class=[] time=0x1d9000000001234 sd=[] link=true",
            ]
        );
        assert_eq!(hive.open(system, &w("existing")), Ok(existing));
        assert_eq!(hive.open(system, &w("Alpha")), Ok(alpha));
    }

    #[test]
    fn a_malformed_file_stops_the_copy() {
        let (mut writer, cells) = sample();
        writer.free(cells.gamma);
        let file = writer.finish(cells.root);
        let (mut hive, system) = tree();
        assert_eq!(
            import_file(&mut hive, system, &file),
            Err(ImportError::File(RegfError::FreeCell))
        );
        // What came before the bad key is there.
        assert!(hive.open(system, &w("Alpha\\Ключ")).is_ok());
        assert_eq!(hive.open(system, &w("Gamma")), Err(Error::NotFound));
        // Bad data stop it before the value is set.
        let (mut writer, cells) = sample();
        writer.patch(cells.text, 4, 5000);
        let file = writer.finish(cells.root);
        let (mut hive, system) = tree();
        assert_eq!(
            import_file(&mut hive, system, &file),
            Err(ImportError::File(RegfError::BadCell))
        );
        assert_eq!(hive.value(system, &w("text")), Err(Error::NotFound));
        assert!(hive.value(system, &w("dword")).is_ok());
        // A key name the tree could not hold: empty, or with a
        // backslash in it.
        for name in ["", "a\\b"] {
            let mut writer = Writer::new();
            let root = writer.key(NIL, "R", true);
            let odd = writer.key(root, name, true);
            writer.subkeys(root, b"li", &[odd]);
            let (mut hive, system) = tree();
            assert_eq!(
                import_file(&mut hive, system, &writer.finish(root)),
                Err(ImportError::File(RegfError::BadCell))
            );
            assert_eq!(hive.subkey(system, 0), Ok(None));
        }
        // No root; a key to copy under that is gone.
        let (writer, _) = sample();
        let (mut hive, system) = tree();
        assert_eq!(
            import_file(&mut hive, system, &writer.finish(NIL)),
            Err(ImportError::File(RegfError::OutOfBounds))
        );
        hive.opened(system);
        hive.delete(system).unwrap();
        let (writer, cells) = sample();
        assert_eq!(
            import_file(&mut hive, system, &writer.finish(cells.root)),
            Err(ImportError::Tree(Error::Deleted))
        );
    }

    /// A file whose keys lie `depth` deep below the root, one in
    /// another.
    fn nested(depth: usize) -> Vec<u8> {
        let mut writer = Writer::new();
        let root = writer.key(NIL, "R", true);
        let mut parent = root;
        for _ in 0..depth {
            let key = writer.key(parent, "k", true);
            writer.subkeys(parent, b"li", &[key]);
            parent = key;
        }
        writer.finish(root)
    }

    #[test]
    fn the_tree_is_no_deeper_than_windows_allows() {
        let (mut hive, system) = tree();
        assert_eq!(import_file(&mut hive, system, &nested(511)), Ok(()));
        let deepest: Vec<u16> = w(&"k\\".repeat(511));
        assert!(hive.open(system, &deepest).is_ok());
        let (mut hive, system) = tree();
        assert_eq!(
            import_file(&mut hive, system, &nested(512)),
            Err(ImportError::File(RegfError::TooDeep))
        );
    }

    #[test]
    fn a_file_that_names_its_keys_over_and_over_is_given_up() {
        // Each key lists its one subkey twice: a walk that believed it
        // would visit two keys, then four, then eight, without end in
        // sight for a file of a few hundred bytes.
        let mut writer = Writer::new();
        let root = writer.key(NIL, "R", true);
        let mut parent = root;
        for _ in 0..40 {
            let key = writer.key(parent, "k", true);
            writer.subkeys(parent, b"li", &[key, key]);
            parent = key;
        }
        let file = writer.finish(root);
        let (mut hive, system) = tree();
        assert_eq!(
            import_file(&mut hive, system, &file),
            Err(ImportError::File(RegfError::BadCell))
        );
        // Listed twice at one level only, a key is simply copied twice.
        let mut writer = Writer::new();
        let root = writer.key(NIL, "R", true);
        let key = writer.key(root, "k", true);
        writer.subkeys(root, b"li", &[key, key]);
        let (mut hive, system) = tree();
        assert_eq!(import_file(&mut hive, system, &writer.finish(root)), Ok(()));
        assert_eq!(hive.info(system).unwrap().subkeys, 1);
    }
}
