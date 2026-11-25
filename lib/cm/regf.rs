//! A registry hive file ("regf"), read in place.
//!
//! The layout is the one Windows writes, as described by Maxim Suhanov's
//! [format specification](https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md)
//! and by the public symbols of the kernel (`_HBASE_BLOCK`, `_HBIN`,
//! `_CM_KEY_NODE`, `_CM_KEY_VALUE`, `_CM_KEY_INDEX`, `_CM_KEY_SECURITY`,
//! `_CM_BIG_DATA`). Versions 1.3 to 1.6 are read; transaction logs are
//! not, so a hive that needs its log replayed is refused as [`RegfError::Dirty`].
//!
//! Input is untrusted: every offset is checked against the bins and
//! against the cell it lies in, a cell must be allocated, and a
//! malformed file is an `Err`, never a panic. Nothing is allocated: keys,
//! values and data are iterators over the file's bytes.

/// Size of the base block, which the bins follow.
pub const BASE_BLOCK: usize = 4096;
/// `KEY_SYM_LINK`: the key is a symbolic link to another key.
pub const KEY_SYM_LINK: u16 = 0x10;
/// `KEY_COMP_NAME`: the key's name is one byte per character.
const KEY_COMP_NAME: u16 = 0x20;
/// `VALUE_COMP_NAME`: the value's name is one byte per character.
const VALUE_COMP_NAME: u16 = 1;
/// The bit of a value's data length that says the data lie in the
/// record itself.
const INLINE: u32 = 0x8000_0000;
/// The most data one cell holds from version 1.4 on; longer data are
/// split into segments of this size.
pub const BIG_SEGMENT: usize = 16344;

/// Offsets in a key node (`_CM_KEY_NODE`).
const NK_FLAGS: usize = 0x02;
const NK_LAST_WRITE: usize = 0x04;
const NK_PARENT: usize = 0x10;
const NK_SUBKEY_COUNT: usize = 0x14;
const NK_SUBKEY_LIST: usize = 0x1C;
const NK_VALUE_COUNT: usize = 0x24;
const NK_VALUE_LIST: usize = 0x28;
const NK_SECURITY: usize = 0x2C;
const NK_CLASS: usize = 0x30;
const NK_NAME_LENGTH: usize = 0x48;
const NK_CLASS_LENGTH: usize = 0x4A;
const NK_NAME: usize = 0x4C;
/// Offsets in a key value (`_CM_KEY_VALUE`).
const VK_NAME_LENGTH: usize = 0x02;
const VK_DATA_LENGTH: usize = 0x04;
const VK_DATA: usize = 0x08;
const VK_TYPE: usize = 0x0C;
const VK_FLAGS: usize = 0x10;
const VK_NAME: usize = 0x14;
/// Offsets in a security record (`_CM_KEY_SECURITY`).
const SK_LENGTH: usize = 0x10;
const SK_DESCRIPTOR: usize = 0x14;

/// Why a hive file was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegfError {
    /// Too short for a base block, or it does not start with `regf`.
    NotRegf,
    /// The base block's checksum is wrong.
    Corrupt,
    /// The two sequence numbers differ: the file was not written out
    /// completely and needs its transaction log.
    Dirty,
    /// Not a primary file of version 1.3 to 1.6.
    Unsupported,
    /// The length of the bins is zero, not a multiple of 4096 bytes or
    /// more than the file holds.
    BadLength,
    /// A bin's header is wrong, or the bins do not add up to the length.
    BadBin,
    /// A cell lies outside the bins.
    OutOfBounds,
    /// A cell that is referred to is free.
    FreeCell,
    /// A cell is misaligned, is not the record it should be, or is too
    /// small for what the record says it holds.
    BadCell,
    /// An index root refers to another index root.
    TooDeep,
}

/// `len` bytes of a cell at `at`.
fn bytes(cell: &[u8], at: usize, len: usize) -> Result<&[u8], RegfError> {
    at.checked_add(len)
        .and_then(|end| cell.get(at..end))
        .ok_or(RegfError::BadCell)
}

fn u16_at(cell: &[u8], at: usize) -> Result<u16, RegfError> {
    bytes(cell, at, 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(cell: &[u8], at: usize) -> Result<u32, RegfError> {
    bytes(cell, at, 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// The checksum of a base block: its first 127 32-bit words XORed
/// together, with the two results Windows does not store replaced.
pub fn checksum(base: &[u8]) -> u32 {
    let (words, _) = base.as_chunks::<4>();
    let sum = words
        .iter()
        .take(127)
        .fold(0, |sum, &word| sum ^ u32::from_le_bytes(word));
    match sum {
        0 => 1,
        u32::MAX => u32::MAX - 1,
        _ => sum,
    }
}

/// The hash an `lh` list keeps beside each subkey, of the subkey's
/// name: over its upper-cased characters, `hash = hash * 37 + character`.
pub fn lh_hash(name: impl Iterator<Item = u16>) -> u32 {
    name.fold(0u32, |hash, unit| {
        hash.wrapping_mul(37)
            .wrapping_add(u32::from(nk_rtl::upcase(unit)))
    })
}

/// A name in a hive: UTF-16, or one byte per character (Latin-1).
#[derive(Debug, Clone, Copy)]
pub struct Name<'a> {
    bytes: &'a [u8],
    wide: bool,
}

impl<'a> Name<'a> {
    fn new(bytes: &'a [u8], wide: bool) -> Result<Self, RegfError> {
        if wide && bytes.len() % 2 != 0 {
            return Err(RegfError::BadCell);
        }
        Ok(Self { bytes, wide })
    }

    /// Its length in UTF-16 units.
    pub fn len(self) -> usize {
        self.bytes.len() / if self.wide { 2 } else { 1 }
    }

    /// Whether it is the empty name (a key's default value has it).
    pub fn is_empty(self) -> bool {
        self.bytes.is_empty()
    }

    /// Its UTF-16 units.
    pub fn units(self) -> impl Iterator<Item = u16> + 'a {
        self.bytes
            .chunks_exact(if self.wide { 2 } else { 1 })
            .map(|unit| {
                unit.iter()
                    .rev()
                    .fold(0, |value, &byte| value << 8 | u16::from(byte))
            })
    }
}

/// A key node (`nk`).
#[derive(Debug, Clone, Copy)]
pub struct KeyNode<'a> {
    /// The cell it is in.
    pub cell: u32,
    /// Its flags; [`KEY_SYM_LINK`] is one.
    pub flags: u16,
    /// When it was last written, as a `FILETIME`.
    pub last_write: u64,
    pub name: Name<'a>,
    record: &'a [u8],
}

/// A key value (`vk`).
#[derive(Debug, Clone, Copy)]
pub struct KeyValue<'a> {
    pub name: Name<'a>,
    /// Its type (`REG_SZ` and so on).
    pub kind: u32,
    record: &'a [u8],
}

/// The cells a list names: the first four bytes of each entry.
#[derive(Debug, Clone, Copy)]
struct Cells<'a> {
    entries: &'a [u8],
    step: usize,
}

const NO_CELLS: Cells<'static> = Cells {
    entries: &[],
    step: 4,
};

impl Iterator for Cells<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        let (entry, rest) = self.entries.split_at_checked(self.step)?;
        self.entries = rest;
        Some(u32::from_le_bytes([entry[0], entry[1], entry[2], entry[3]]))
    }
}

/// A hive file whose base block and bin headers have been checked.
#[derive(Debug, Clone, Copy)]
pub struct Regf<'a> {
    /// The bins: what cell offsets count from.
    bins: &'a [u8],
    root: u32,
    minor: u32,
}

impl<'a> Regf<'a> {
    /// Check the base block of `file` and the headers of its bins.
    pub fn parse(file: &'a [u8]) -> Result<Self, RegfError> {
        let base = file.get(..BASE_BLOCK).ok_or(RegfError::NotRegf)?;
        if &base[..4] != b"regf" {
            return Err(RegfError::NotRegf);
        }
        if u32_at(base, 0x1FC)? != checksum(base) {
            return Err(RegfError::Corrupt);
        }
        if u32_at(base, 4)? != u32_at(base, 8)? {
            return Err(RegfError::Dirty);
        }
        // Major and minor version, file type (primary), format (memory).
        let minor = u32_at(base, 0x18)?;
        if u32_at(base, 0x14)? != 1
            || !(3..=6).contains(&minor)
            || u32_at(base, 0x1C)? != 0
            || u32_at(base, 0x20)? != 1
        {
            return Err(RegfError::Unsupported);
        }
        let length = u32_at(base, 0x28)? as usize;
        let bins = file[BASE_BLOCK..]
            .get(..length)
            .filter(|_| length != 0 && length % 4096 == 0)
            .ok_or(RegfError::BadLength)?;
        // The bins lie end to end and fill the length exactly.
        let mut at = 0;
        while at < length {
            let bin = &bins[at..];
            let size = u32_at(bin, 8)? as usize;
            if &bin[..4] != b"hbin"
                || u32_at(bin, 4)? as usize != at
                || size == 0
                || size % 4096 != 0
                || size > length - at
            {
                return Err(RegfError::BadBin);
            }
            at += size;
        }
        Ok(Self {
            bins,
            root: u32_at(base, 0x24)?,
            minor,
        })
    }

    /// More keys than the file can hold: each takes a cell of at least
    /// this many bytes less.
    pub fn key_limit(&self) -> usize {
        self.bins.len() / NK_NAME
    }

    /// The data of the allocated cell at `offset`.
    fn cell(&self, offset: u32) -> Result<&'a [u8], RegfError> {
        let start = offset as usize;
        let size = self
            .bins
            .get(start..)
            .and_then(|rest| rest.first_chunk::<4>())
            .ok_or(RegfError::OutOfBounds)?;
        let size = i32::from_le_bytes(*size);
        if size >= 0 {
            return Err(RegfError::FreeCell);
        }
        let size = size.unsigned_abs() as usize;
        if start % 8 != 0 || size % 8 != 0 {
            return Err(RegfError::BadCell);
        }
        start
            .checked_add(size)
            .and_then(|end| self.bins.get(start + 4..end))
            .ok_or(RegfError::OutOfBounds)
    }

    /// The cell at `offset`, which starts with `signature` and holds at
    /// least `fixed` bytes.
    fn record(
        &self,
        offset: u32,
        signature: &[u8; 2],
        fixed: usize,
    ) -> Result<&'a [u8], RegfError> {
        let cell = self.cell(offset)?;
        if cell.len() < fixed || &cell[..2] != signature {
            return Err(RegfError::BadCell);
        }
        Ok(cell)
    }

    /// The key the hive starts at.
    pub fn root(&self) -> Result<KeyNode<'a>, RegfError> {
        self.key(self.root)
    }

    fn key(&self, cell: u32) -> Result<KeyNode<'a>, RegfError> {
        let record = self.record(cell, b"nk", NK_NAME)?;
        let flags = u16_at(record, NK_FLAGS)?;
        let name = bytes(
            record,
            NK_NAME,
            usize::from(u16_at(record, NK_NAME_LENGTH)?),
        )?;
        let time = bytes(record, NK_LAST_WRITE, 8)?;
        Ok(KeyNode {
            cell,
            flags,
            last_write: time
                .iter()
                .rev()
                .fold(0, |value, &byte| value << 8 | u64::from(byte)),
            name: Name::new(name, flags & KEY_COMP_NAME == 0)?,
            record,
        })
    }

    /// The class of `key`, as the bytes stored (UTF-16 when Windows
    /// wrote them); empty if it has none.
    pub fn class(&self, key: &KeyNode<'a>) -> Result<&'a [u8], RegfError> {
        match usize::from(u16_at(key.record, NK_CLASS_LENGTH)?) {
            0 => Ok(&[]),
            length => bytes(self.cell(u32_at(key.record, NK_CLASS)?)?, 0, length),
        }
    }

    /// The security descriptor of `key`, self-relative; empty if the key
    /// names none.
    pub fn security(&self, key: &KeyNode<'a>) -> Result<&'a [u8], RegfError> {
        let offset = u32_at(key.record, NK_SECURITY)?;
        if offset == u32::MAX {
            return Ok(&[]);
        }
        let record = self.record(offset, b"sk", SK_DESCRIPTOR)?;
        bytes(record, SK_DESCRIPTOR, u32_at(record, SK_LENGTH)? as usize)
    }

    /// A list of subkeys or of such lists: whether it is an index root
    /// (`ri`), and the cells it names.
    fn list(&self, offset: u32) -> Result<(bool, Cells<'a>), RegfError> {
        let cell = self.cell(offset)?;
        let count = usize::from(u16_at(cell, 2)?);
        let step = match &cell[..2] {
            b"lf" | b"lh" => 8,
            b"li" | b"ri" => 4,
            _ => return Err(RegfError::BadCell),
        };
        let entries = bytes(cell, 4, count * step)?;
        Ok((&cell[..2] == b"ri", Cells { entries, step }))
    }

    /// The subkeys of `key`, in the order the hive lists them.
    pub fn subkeys(&self, key: &KeyNode<'a>) -> Result<Subkeys<'a>, RegfError> {
        let left = u32_at(key.record, NK_SUBKEY_COUNT)?;
        let (lists, leaf) = if left == 0 {
            (NO_CELLS, NO_CELLS)
        } else {
            match self.list(u32_at(key.record, NK_SUBKEY_LIST)?)? {
                (true, lists) => (lists, NO_CELLS),
                (false, leaf) => (NO_CELLS, leaf),
            }
        };
        Ok(Subkeys {
            regf: *self,
            parent: key.cell,
            lists,
            leaf,
            left,
            done: false,
        })
    }

    /// The values of `key`, in the order the hive lists them.
    pub fn values(&self, key: &KeyNode<'a>) -> Result<Values<'a>, RegfError> {
        let entries = match u32_at(key.record, NK_VALUE_COUNT)? as usize {
            0 => &[][..],
            count => bytes(
                self.cell(u32_at(key.record, NK_VALUE_LIST)?)?,
                0,
                count.saturating_mul(4),
            )?,
        };
        Ok(Values {
            regf: *self,
            cells: Cells { entries, step: 4 },
        })
    }

    fn value(&self, cell: u32) -> Result<KeyValue<'a>, RegfError> {
        let record = self.record(cell, b"vk", VK_NAME)?;
        let name = bytes(
            record,
            VK_NAME,
            usize::from(u16_at(record, VK_NAME_LENGTH)?),
        )?;
        let wide = u16_at(record, VK_FLAGS)? & VALUE_COMP_NAME == 0;
        Ok(KeyValue {
            name: Name::new(name, wide)?,
            kind: u32_at(record, VK_TYPE)?,
            record,
        })
    }

    /// The data of `value`: in the record itself, in a cell, or in the
    /// segments of a big-data record.
    pub fn data(&self, value: &KeyValue<'a>) -> Result<Data<'a>, RegfError> {
        let size = u32_at(value.record, VK_DATA_LENGTH)?;
        let len = (size & !INLINE) as usize;
        let mut data = Data {
            regf: *self,
            piece: None,
            segments: NO_CELLS,
            left: 0,
            len,
        };
        if size & INLINE != 0 {
            let field = bytes(value.record, VK_DATA, 4)?;
            data.piece = Some(field.get(..len).ok_or(RegfError::BadCell)?);
        } else if len > BIG_SEGMENT && self.minor > 3 {
            let big = self.record(u32_at(value.record, VK_DATA)?, b"db", 8)?;
            let count = usize::from(u16_at(big, 2)?);
            data.segments = Cells {
                entries: bytes(self.cell(u32_at(big, 4)?)?, 0, count * 4)?,
                step: 4,
            };
            data.left = len;
        } else if len != 0 {
            let cell = self.cell(u32_at(value.record, VK_DATA)?)?;
            data.piece = Some(bytes(cell, 0, len)?);
        }
        Ok(data)
    }
}

/// The subkeys of a key. After an error it yields nothing more.
#[derive(Debug, Clone)]
pub struct Subkeys<'a> {
    regf: Regf<'a>,
    /// The cell of the key whose subkeys these are.
    parent: u32,
    /// The lists an index root names that are still to be read.
    lists: Cells<'a>,
    /// The rest of the list being read.
    leaf: Cells<'a>,
    /// How many subkeys the key says are still to come.
    left: u32,
    done: bool,
}

impl<'a> Subkeys<'a> {
    fn step(&mut self) -> Result<Option<KeyNode<'a>>, RegfError> {
        loop {
            if let Some(cell) = self.leaf.next() {
                let key = self.regf.key(cell)?;
                // A subkey names its parent, and there are as many as
                // the parent says: what keeps a walk of the tree finite.
                if u32_at(key.record, NK_PARENT)? != self.parent || self.left == 0 {
                    return Err(RegfError::BadCell);
                }
                self.left -= 1;
                return Ok(Some(key));
            }
            let Some(list) = self.lists.next() else {
                return if self.left == 0 {
                    Ok(None)
                } else {
                    Err(RegfError::BadCell)
                };
            };
            let (root, leaf) = self.regf.list(list)?;
            if root {
                return Err(RegfError::TooDeep);
            }
            self.leaf = leaf;
        }
    }
}

impl<'a> Iterator for Subkeys<'a> {
    type Item = Result<KeyNode<'a>, RegfError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let result = self.step();
        self.done = !matches!(result, Ok(Some(_)));
        result.transpose()
    }
}

/// The values of a key.
#[derive(Debug, Clone)]
pub struct Values<'a> {
    regf: Regf<'a>,
    cells: Cells<'a>,
}

impl<'a> Iterator for Values<'a> {
    type Item = Result<KeyValue<'a>, RegfError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.cells.next().map(|cell| self.regf.value(cell))
    }
}

/// The data of a value, piece by piece: one piece unless the data are
/// big. After an error it yields nothing more.
#[derive(Debug, Clone)]
pub struct Data<'a> {
    regf: Regf<'a>,
    /// Data that lie in one place.
    piece: Option<&'a [u8]>,
    /// The segments of big data still to be read.
    segments: Cells<'a>,
    /// How many bytes the segments still owe.
    left: usize,
    len: usize,
}

impl Data<'_> {
    /// How many bytes all the pieces hold together.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the value has no data.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<'a> Iterator for Data<'a> {
    type Item = Result<&'a [u8], RegfError>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(piece) = self.piece.take() {
            return Some(Ok(piece));
        }
        let take = self.left.min(BIG_SEGMENT);
        let piece = match self.segments.next() {
            Some(cell) => self.regf.cell(cell).and_then(|cell| bytes(cell, 0, take)),
            // The segments ran out before the data did.
            None if self.left != 0 => Err(RegfError::BadCell),
            None => return None,
        };
        self.left -= take;
        if piece.is_err() {
            self.segments = NO_CELLS;
            self.left = 0;
        }
        Some(piece)
    }
}
