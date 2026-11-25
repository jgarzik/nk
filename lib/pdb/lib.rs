//! Microsoft program database (PDB) files: structure layouts.
//!
//! Microsoft publishes a PDB for every Windows binary. The public ones
//! carry no source information, but the kernel's still holds the type
//! records of its private structures. NK reads them to learn the sizes and
//! field offsets that Microsoft's own drivers were compiled against.
//!
//! Only what that needs is here: the multi-stream file container, the
//! info stream (the identity a PE image names its PDB by), and the type
//! stream's structures, unions, bit fields and arrays. Input is untrusted:
//! every offset is bounds-checked and a malformed file is an `Err`, never
//! a panic.
//!
//! Format: <https://llvm.org/docs/PDB/index.html>.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

const MAGIC: &[u8; 32] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";
const STREAM_INFO: usize = 1;
const STREAM_TYPES: usize = 2;
/// A stream that was deleted has this size.
const NIL_STREAM: u32 = u32::MAX;
/// Type indices below this are built-in types, not records.
const FIRST_RECORD: u32 = 0x1000;

const LF_FIELDLIST: u16 = 0x1203;
const LF_BITFIELD: u16 = 0x1205;
const LF_BCLASS: u16 = 0x1400;
const LF_INDEX: u16 = 0x1404;
const LF_ENUMERATE: u16 = 0x1502;
const LF_CLASS: u16 = 0x1504;
const LF_STRUCTURE: u16 = 0x1505;
const LF_UNION: u16 = 0x1506;
const LF_MEMBER: u16 = 0x150D;
const LF_STMEMBER: u16 = 0x150E;
const LF_NESTTYPE: u16 = 0x1510;
/// Property bit: a declaration without a body.
const PROP_FORWARD: u16 = 0x80;
/// A field list may continue in another record this many times.
const MAX_CONTINUATIONS: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PdbError {
    /// Not a PDB, or its container tables do not fit the file.
    BadContainer,
    /// The file has no such stream.
    NoStream(usize),
    /// A stream ends before the data its header promises.
    Truncated,
    /// A type record is malformed or of a kind this reader cannot follow.
    BadRecord,
    /// No structure or union of that name has a body.
    NoSuchType,
    /// Two bodies of one type disagree about a field they share.
    Conflict,
}

fn u16_at(b: &[u8], off: usize) -> Result<u16, PdbError> {
    let s = b.get(off..off + 2).ok_or(PdbError::Truncated)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], off: usize) -> Result<u32, PdbError> {
    let s = b.get(off..off + 4).ok_or(PdbError::Truncated)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// The identity of a PDB: what a PE image's debug directory records to
/// name the PDB that belongs to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Info {
    pub signature: u32,
    /// How many times the PDB was rewritten. A PE image records the age at
    /// its own link, which can be lower.
    pub age: u32,
    pub guid: [u8; 16],
}

/// A PDB file.
pub struct Pdb<'a> {
    data: &'a [u8],
    block_size: usize,
    /// `(size, first index into blocks)` per stream.
    streams: Vec<(u32, usize)>,
    /// Block numbers of every stream, concatenated.
    blocks: Vec<u32>,
}

impl<'a> Pdb<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, PdbError> {
        if data.get(..32) != Some(MAGIC) {
            return Err(PdbError::BadContainer);
        }
        let bad = |_| PdbError::BadContainer;
        let block_size = u32_at(data, 32).map_err(bad)? as usize;
        let directory_bytes = u32_at(data, 44).map_err(bad)? as usize;
        let map_block = u32_at(data, 52).map_err(bad)? as usize;
        if !(512..=65536).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(PdbError::BadContainer);
        }
        if directory_bytes > data.len() {
            return Err(PdbError::BadContainer);
        }

        // The block map lists the blocks of the directory; the directory
        // lists the size and the blocks of every stream.
        let map = data
            .get(
                map_block
                    .checked_mul(block_size)
                    .ok_or(PdbError::BadContainer)?..,
            )
            .ok_or(PdbError::BadContainer)?;
        let mut directory = Vec::with_capacity(directory_bytes);
        for i in 0..directory_bytes.div_ceil(block_size) {
            let block = u32_at(map, i * 4).map_err(bad)? as usize;
            let start = block
                .checked_mul(block_size)
                .ok_or(PdbError::BadContainer)?;
            let chunk = data
                .get(start..start + block_size)
                .ok_or(PdbError::BadContainer)?;
            directory.extend_from_slice(chunk);
        }
        directory.truncate(directory_bytes);

        let count = u32_at(&directory, 0).map_err(bad)? as usize;
        if count > directory_bytes / 4 {
            return Err(PdbError::BadContainer);
        }
        let mut streams = Vec::with_capacity(count);
        let mut total = 0usize;
        for i in 0..count {
            let size = u32_at(&directory, 4 + i * 4).map_err(bad)?;
            let size = if size == NIL_STREAM { 0 } else { size };
            streams.push((size, total));
            total += (size as usize).div_ceil(block_size);
        }
        let mut blocks = Vec::with_capacity(total);
        let first = 4 + count * 4;
        for i in 0..total {
            blocks.push(u32_at(&directory, first + i * 4).map_err(bad)?);
        }
        Ok(Pdb {
            data,
            block_size,
            streams,
            blocks,
        })
    }

    /// The bytes of stream `index`, gathered from its blocks.
    pub fn stream(&self, index: usize) -> Result<Vec<u8>, PdbError> {
        let &(size, first) = self.streams.get(index).ok_or(PdbError::NoStream(index))?;
        let size = size as usize;
        let mut out = Vec::with_capacity(size);
        for &block in &self.blocks[first..first + size.div_ceil(self.block_size)] {
            let start = (block as usize)
                .checked_mul(self.block_size)
                .ok_or(PdbError::BadContainer)?;
            let chunk = self
                .data
                .get(start..start + self.block_size)
                .ok_or(PdbError::BadContainer)?;
            out.extend_from_slice(chunk);
        }
        out.truncate(size);
        Ok(out)
    }

    pub fn info(&self) -> Result<Info, PdbError> {
        let s = self.stream(STREAM_INFO)?;
        let guid = s.get(12..28).ok_or(PdbError::Truncated)?;
        Ok(Info {
            signature: u32_at(&s, 4)?,
            age: u32_at(&s, 8)?,
            guid: guid.try_into().map_err(|_| PdbError::Truncated)?,
        })
    }

    pub fn types(&self) -> Result<Types, PdbError> {
        Types::parse(self.stream(STREAM_TYPES)?)
    }
}

/// One data member of a structure or union.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub name: String,
    /// Byte offset from the start of the structure.
    pub offset: u64,
    /// `(first bit, bit count)` for a bit field, inside the storage unit
    /// at `offset`.
    pub bits: Option<(u8, u8)>,
}

/// The layout of a structure or union. Members of anonymous unions and
/// structures inside it appear here directly, as the compiler records
/// them, at their offsets from the start of the outer type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub size: u64,
    pub members: Vec<Member>,
}

impl Layout {
    pub fn member(&self, name: &str) -> Option<&Member> {
        self.members.iter().find(|m| m.name == name)
    }
}

/// The type stream.
pub struct Types {
    data: Vec<u8>,
    /// Type index of the first record.
    first: u32,
    /// Offset in `data` of each record's length word.
    records: Vec<u32>,
}

/// A numeric leaf: a value that is either stored directly or prefixed by
/// its width. Returns the value and the bytes it took.
fn numeric(b: &[u8]) -> Result<(u64, usize), PdbError> {
    let lead = u16_at(b, 0)?;
    let take = |n: usize| -> Result<u64, PdbError> {
        let s = b.get(2..2 + n).ok_or(PdbError::Truncated)?;
        let mut v = [0u8; 8];
        v[..n].copy_from_slice(s);
        Ok(u64::from_le_bytes(v))
    };
    Ok(match lead {
        0..0x8000 => (u64::from(lead), 2),
        0x8000 => (take(1)?, 3),           // LF_CHAR
        0x8001 | 0x8002 => (take(2)?, 4),  // LF_SHORT, LF_USHORT
        0x8003 | 0x8004 => (take(4)?, 6),  // LF_LONG, LF_ULONG
        0x8009 | 0x800A => (take(8)?, 10), // LF_QUADWORD, LF_UQUADWORD
        _ => return Err(PdbError::BadRecord),
    })
}

/// A NUL-terminated name. Returns it and the bytes it took, terminator
/// included.
fn name(b: &[u8]) -> Result<(&str, usize), PdbError> {
    let len = b.iter().position(|&c| c == 0).ok_or(PdbError::Truncated)?;
    let s = core::str::from_utf8(&b[..len]).map_err(|_| PdbError::BadRecord)?;
    Ok((s, len + 1))
}

/// The body of a structure, class or union record.
struct Aggregate<'a> {
    forward: bool,
    fields: u32,
    size: u64,
    name: &'a str,
}

impl Types {
    fn parse(data: Vec<u8>) -> Result<Self, PdbError> {
        let header = u32_at(&data, 4)? as usize;
        let first = u32_at(&data, 8)?;
        let end = u32_at(&data, 12)?;
        let bytes = u32_at(&data, 16)? as usize;
        let body_end = header.checked_add(bytes).ok_or(PdbError::Truncated)?;
        if first < FIRST_RECORD || end < first || body_end > data.len() {
            return Err(PdbError::Truncated);
        }
        let mut records = Vec::with_capacity((end - first) as usize);
        let mut off = header;
        while off < body_end {
            let len = usize::from(u16_at(&data, off)?);
            // The length counts the kind word and the record body.
            if len < 2 || off + 2 + len > body_end {
                return Err(PdbError::BadRecord);
            }
            records.push(off as u32);
            off += 2 + len;
        }
        if records.len() != (end - first) as usize {
            return Err(PdbError::BadRecord);
        }
        Ok(Types {
            data,
            first,
            records,
        })
    }

    /// `(kind, body)` of the record with type index `index`.
    fn record(&self, index: u32) -> Result<(u16, &[u8]), PdbError> {
        let i = index.checked_sub(self.first).ok_or(PdbError::BadRecord)?;
        let off = *self.records.get(i as usize).ok_or(PdbError::BadRecord)? as usize;
        let len = usize::from(u16_at(&self.data, off)?);
        Ok((
            u16_at(&self.data, off + 2)?,
            &self.data[off + 4..off + 2 + len],
        ))
    }

    fn aggregate<'a>(kind: u16, body: &'a [u8]) -> Result<Option<Aggregate<'a>>, PdbError> {
        // Classes and structures carry two more type indices than unions.
        let at = match kind {
            LF_STRUCTURE | LF_CLASS => 16,
            LF_UNION => 8,
            _ => return Ok(None),
        };
        let (size, used) = numeric(body.get(at..).ok_or(PdbError::Truncated)?)?;
        let (name, _) = name(&body[at + used..])?;
        Ok(Some(Aggregate {
            forward: u16_at(body, 2)? & PROP_FORWARD != 0,
            fields: u32_at(body, 4)?,
            size,
            name,
        }))
    }

    /// Names of every structure, class and union that has a body, each
    /// once, in file order.
    pub fn names(&self) -> Result<Vec<&str>, PdbError> {
        let mut names: Vec<&str> = Vec::new();
        for i in 0..self.records.len() as u32 {
            let (kind, body) = self.record(self.first + i)?;
            if let Some(a) = Self::aggregate(kind, body)?
                && !a.forward
            {
                names.push(a.name);
            }
        }
        names.sort_unstable();
        names.dedup();
        Ok(names)
    }

    /// The layout of the structure, class or union called `name`.
    ///
    /// A PDB can hold several bodies under one name: Microsoft's public
    /// headers declare the head of a structure whose full form is private
    /// (the processor control region, for one). The largest body is the
    /// real one; every smaller body must agree with it on the fields they
    /// share, or the name is ambiguous and this is an error.
    pub fn layout(&self, name: &str) -> Result<Layout, PdbError> {
        let mut bodies: Vec<Layout> = Vec::new();
        for i in 0..self.records.len() as u32 {
            let (kind, body) = self.record(self.first + i)?;
            if let Some(a) = Self::aggregate(kind, body)?
                && !a.forward
                && a.name == name
            {
                bodies.push(Layout {
                    size: a.size,
                    members: self.members(a.fields)?,
                });
            }
        }
        bodies.sort_by_key(|b| core::cmp::Reverse(b.size));
        let mut bodies = bodies.into_iter();
        let full = bodies.next().ok_or(PdbError::NoSuchType)?;
        for partial in bodies {
            for m in &partial.members {
                if full.member(&m.name).is_some_and(|f| f != m) {
                    return Err(PdbError::Conflict);
                }
            }
        }
        Ok(full)
    }

    /// The data members of a field list, following its continuations.
    fn members(&self, mut list: u32) -> Result<Vec<Member>, PdbError> {
        let mut members = Vec::new();
        for _ in 0..MAX_CONTINUATIONS {
            // An aggregate with no fields names field list 0.
            if list == 0 {
                return Ok(members);
            }
            let (kind, mut b) = self.record(list)?;
            if kind != LF_FIELDLIST {
                return Err(PdbError::BadRecord);
            }
            list = 0;
            while !b.is_empty() {
                // Entries are padded to four bytes with 0xF1..0xF3.
                if b[0] >= 0xF0 {
                    b = b
                        .get(usize::from(b[0] & 0x0F)..)
                        .ok_or(PdbError::BadRecord)?;
                    continue;
                }
                let used = match u16_at(b, 0)? {
                    LF_MEMBER => {
                        let (offset, n) = numeric(b.get(8..).ok_or(PdbError::Truncated)?)?;
                        let (text, m) = name(&b[8 + n..])?;
                        members.push(Member {
                            name: String::from(text),
                            offset,
                            bits: self.bit_field(u32_at(b, 4)?)?,
                        });
                        8 + n + m
                    }
                    LF_INDEX => {
                        list = u32_at(b, 4)?;
                        8
                    }
                    LF_ENUMERATE => {
                        let (_, n) = numeric(b.get(4..).ok_or(PdbError::Truncated)?)?;
                        4 + n + name(&b[4 + n..])?.1
                    }
                    LF_NESTTYPE | LF_STMEMBER => {
                        8 + name(b.get(8..).ok_or(PdbError::Truncated)?)?.1
                    }
                    LF_BCLASS => 8 + numeric(b.get(8..).ok_or(PdbError::Truncated)?)?.1,
                    // Methods and the like: C structures have none, and
                    // guessing an unknown entry's length would misread
                    // everything after it.
                    _ => return Err(PdbError::BadRecord),
                };
                b = b.get(used..).ok_or(PdbError::BadRecord)?;
            }
            if list == 0 {
                return Ok(members);
            }
        }
        Err(PdbError::BadRecord)
    }

    /// `(first bit, bit count)` if type `index` is a bit field.
    fn bit_field(&self, index: u32) -> Result<Option<(u8, u8)>, PdbError> {
        if index < self.first {
            return Ok(None);
        }
        let (kind, body) = self.record(index)?;
        if kind != LF_BITFIELD {
            return Ok(None);
        }
        let b = body.get(4..6).ok_or(PdbError::Truncated)?;
        Ok(Some((b[1], b[0])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- builders -------------------------------------------------------

    fn num(v: u64) -> Vec<u8> {
        if v < 0x8000 {
            (v as u16).to_le_bytes().to_vec()
        } else if v <= u64::from(u32::MAX) {
            let mut b = 0x8004u16.to_le_bytes().to_vec();
            b.extend_from_slice(&(v as u32).to_le_bytes());
            b
        } else {
            let mut b = 0x800Au16.to_le_bytes().to_vec();
            b.extend_from_slice(&v.to_le_bytes());
            b
        }
    }

    /// A type record: length, kind, body, padded to four bytes.
    fn rec(kind: u16, body: &[u8]) -> Vec<u8> {
        let mut body = body.to_vec();
        while (body.len() + 4) % 4 != 0 {
            let pad = 4 - (body.len() + 4) % 4;
            body.push(0xF0 | pad as u8);
        }
        let mut r = ((body.len() + 2) as u16).to_le_bytes().to_vec();
        r.extend_from_slice(&kind.to_le_bytes());
        r.extend_from_slice(&body);
        r
    }

    fn aggregate(kind: u16, prop: u16, fields: u32, size: u64, name: &str) -> Vec<u8> {
        let mut b = 3u16.to_le_bytes().to_vec();
        b.extend_from_slice(&prop.to_le_bytes());
        b.extend_from_slice(&fields.to_le_bytes());
        if kind != LF_UNION {
            b.extend_from_slice(&[0; 8]); // derived, vshape
        }
        b.extend_from_slice(&num(size));
        b.extend_from_slice(name.as_bytes());
        b.push(0);
        rec(kind, &b)
    }

    /// One LF_MEMBER entry, padded as the compiler pads it.
    fn member(ty: u32, offset: u64, name: &str) -> Vec<u8> {
        let mut b = LF_MEMBER.to_le_bytes().to_vec();
        b.extend_from_slice(&3u16.to_le_bytes());
        b.extend_from_slice(&ty.to_le_bytes());
        b.extend_from_slice(&num(offset));
        b.extend_from_slice(name.as_bytes());
        b.push(0);
        while b.len() % 4 != 0 {
            let pad = 4 - b.len() % 4;
            b.push(0xF0 | pad as u8);
        }
        b
    }

    fn fieldlist(entries: &[Vec<u8>]) -> Vec<u8> {
        rec(LF_FIELDLIST, &entries.concat())
    }

    fn index(next: u32) -> Vec<u8> {
        let mut b = LF_INDEX.to_le_bytes().to_vec();
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(&next.to_le_bytes());
        b
    }

    fn bitfield(base: u32, len: u8, pos: u8) -> Vec<u8> {
        let mut b = base.to_le_bytes().to_vec();
        b.extend_from_slice(&[len, pos]);
        rec(LF_BITFIELD, &b)
    }

    /// The type stream: header, then the records, the first with index
    /// 0x1000.
    fn tpi(records: &[Vec<u8>]) -> Vec<u8> {
        let body = records.concat();
        let mut s = Vec::new();
        for v in [
            20040203u32,
            56,
            0x1000,
            0x1000 + records.len() as u32,
            body.len() as u32,
        ] {
            s.extend_from_slice(&v.to_le_bytes());
        }
        s.resize(56, 0);
        s.extend_from_slice(&body);
        s
    }

    fn info_stream(age: u32) -> Vec<u8> {
        let mut s = Vec::new();
        for v in [20000404u32, 0x2FF0_D722, age] {
            s.extend_from_slice(&v.to_le_bytes());
        }
        s.extend_from_slice(&[0xAB; 16]);
        s
    }

    /// A PDB container holding `streams`. Blocks are handed out from the
    /// end of the file backwards, so that no stream is contiguous or in
    /// order: reading one right means following the directory.
    fn msf(streams: &[Vec<u8>], block_size: usize) -> Vec<u8> {
        let blocks_of = |len: usize| len.div_ceil(block_size);
        let stream_blocks: usize = streams.iter().map(|s| blocks_of(s.len())).sum();
        let directory_len = 4 + 4 * streams.len() + 4 * stream_blocks;
        // Block 0 is the superblock, 1 and 2 free-block maps, 3 the block
        // map; data blocks follow.
        let total = 4 + stream_blocks + blocks_of(directory_len);
        let mut file = vec![0u8; total * block_size];
        let mut next = total;
        let mut take = |file: &mut Vec<u8>, bytes: &[u8]| -> Vec<u32> {
            bytes
                .chunks(block_size)
                .map(|chunk| {
                    next -= 1;
                    file[next * block_size..][..chunk.len()].copy_from_slice(chunk);
                    next as u32
                })
                .collect()
        };
        let mut directory = (streams.len() as u32).to_le_bytes().to_vec();
        for s in streams {
            directory.extend_from_slice(&(s.len() as u32).to_le_bytes());
        }
        for s in streams {
            for b in take(&mut file, s) {
                directory.extend_from_slice(&b.to_le_bytes());
            }
        }
        assert_eq!(directory.len(), directory_len);
        let map: Vec<u8> = take(&mut file, &directory)
            .iter()
            .flat_map(|b| b.to_le_bytes())
            .collect();
        assert!(map.len() <= block_size);
        file[3 * block_size..][..map.len()].copy_from_slice(&map);
        file[..32].copy_from_slice(MAGIC);
        for (off, v) in [
            (32, block_size),
            (36, 1),
            (40, total),
            (44, directory_len),
            (52, 3),
        ] {
            file[off..off + 4].copy_from_slice(&(v as u32).to_le_bytes());
        }
        file
    }

    fn pdb_with(records: &[Vec<u8>]) -> Vec<u8> {
        msf(&[vec![], info_stream(5), tpi(records)], 512)
    }

    fn layout_of(records: &[Vec<u8>], name: &str) -> Result<Layout, PdbError> {
        let file = pdb_with(records);
        Pdb::parse(&file)?.types()?.layout(name)
    }

    fn m(name: &str, offset: u64) -> Member {
        Member {
            name: name.into(),
            offset,
            bits: None,
        }
    }

    // ---- tests ----------------------------------------------------------

    #[test]
    fn container_and_info() {
        // A stream longer than one block, in scattered blocks.
        let big: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
        for block_size in [512, 1024, 4096] {
            let file = msf(&[vec![], info_stream(5), tpi(&[]), big.clone()], block_size);
            let pdb = Pdb::parse(&file).expect("container");
            assert_eq!(pdb.stream(3).unwrap(), big);
            assert_eq!(pdb.stream(0).unwrap(), b"");
            assert_eq!(pdb.stream(4), Err(PdbError::NoStream(4)));
            let info = pdb.info().unwrap();
            assert_eq!((info.signature, info.age), (0x2FF0_D722, 5));
            assert_eq!(info.guid, [0xAB; 16]);
        }
    }

    #[test]
    fn simple_structure() {
        let layout = layout_of(
            &[
                fieldlist(&[member(0x75, 0, "Type"), member(0x603, 8, "Next")]),
                aggregate(LF_STRUCTURE, 0, 0x1000, 16, "_THING"),
            ],
            "_THING",
        )
        .unwrap();
        assert_eq!(layout.size, 16);
        assert_eq!(layout.members, [m("Type", 0), m("Next", 8)]);
        assert_eq!(layout.member("Next").map(|f| f.offset), Some(8));
        assert!(layout.member("Missing").is_none());
    }

    #[test]
    fn forward_declarations_are_not_bodies() {
        let records = [
            aggregate(LF_STRUCTURE, PROP_FORWARD, 0, 0, "_THING"),
            fieldlist(&[member(0x75, 4, "Field")]),
            aggregate(LF_STRUCTURE, 0, 0x1001, 8, "_THING"),
            aggregate(LF_STRUCTURE, PROP_FORWARD, 0, 0, "_ONLY_DECLARED"),
        ];
        assert_eq!(layout_of(&records, "_THING").unwrap().size, 8);
        assert_eq!(
            layout_of(&records, "_ONLY_DECLARED"),
            Err(PdbError::NoSuchType)
        );
        assert_eq!(layout_of(&records, "_ABSENT"), Err(PdbError::NoSuchType));
        let file = pdb_with(&records);
        assert_eq!(
            Pdb::parse(&file).unwrap().types().unwrap().names().unwrap(),
            ["_THING"]
        );
    }

    #[test]
    fn largest_body_wins_when_they_agree() {
        // The public head of a structure and its full private form, as
        // with the processor control region, in either order.
        let head = fieldlist(&[member(0x23, 0x18, "Self")]);
        let full = fieldlist(&[member(0x23, 0x18, "Self"), member(0x23, 0x180, "Prcb")]);
        for records in [
            [
                head.clone(),
                aggregate(LF_STRUCTURE, 0, 0x1000, 0x178, "_KPCR"),
                full.clone(),
                aggregate(LF_STRUCTURE, 0, 0x1002, 0xB080, "_KPCR"),
            ],
            [
                full,
                aggregate(LF_STRUCTURE, 0, 0x1000, 0xB080, "_KPCR"),
                head,
                aggregate(LF_STRUCTURE, 0, 0x1002, 0x178, "_KPCR"),
            ],
        ] {
            let layout = layout_of(&records, "_KPCR").unwrap();
            assert_eq!(layout.size, 0xB080);
            assert_eq!(layout.member("Prcb"), Some(&m("Prcb", 0x180)));
        }
    }

    #[test]
    fn disagreeing_bodies_are_an_error() {
        let records = [
            fieldlist(&[member(0x23, 0x18, "Self")]),
            aggregate(LF_STRUCTURE, 0, 0x1000, 0x178, "_KPCR"),
            fieldlist(&[member(0x23, 0x20, "Self")]),
            aggregate(LF_STRUCTURE, 0, 0x1002, 0xB080, "_KPCR"),
        ];
        assert_eq!(layout_of(&records, "_KPCR"), Err(PdbError::Conflict));
    }

    #[test]
    fn bit_fields_unions_and_large_offsets() {
        let records = [
            bitfield(0x75, 3, 0), // 0x1000
            bitfield(0x75, 5, 3), // 0x1001
            fieldlist(&[
                member(0x1000, 4, "Low"),
                member(0x1001, 4, "High"),
                member(0x75, 4, "AllBits"),
                member(0x23, 0x9000, "Far"),
                member(0x23, 0x1_0000_0000, "VeryFar"),
            ]), // 0x1002
            aggregate(LF_UNION, 0, 0x1002, 0x1_0000_0008, "_U"),
        ];
        let layout = layout_of(&records, "_U").unwrap();
        assert_eq!(layout.size, 0x1_0000_0008);
        assert_eq!(layout.member("Low").unwrap().bits, Some((0, 3)));
        assert_eq!(layout.member("High").unwrap().bits, Some((3, 5)));
        assert_eq!(layout.member("AllBits"), Some(&m("AllBits", 4)));
        assert_eq!(layout.member("Far"), Some(&m("Far", 0x9000)));
        assert_eq!(layout.member("VeryFar"), Some(&m("VeryFar", 0x1_0000_0000)));
    }

    #[test]
    fn field_lists_continue_and_skip_what_is_not_a_member() {
        let mut enumerate = LF_ENUMERATE.to_le_bytes().to_vec();
        enumerate.extend_from_slice(&[3, 0]);
        enumerate.extend_from_slice(&num(7));
        enumerate.extend_from_slice(b"Seven\0");
        let mut nested = LF_NESTTYPE.to_le_bytes().to_vec();
        nested.extend_from_slice(&[0, 0]);
        nested.extend_from_slice(&0x1000u32.to_le_bytes());
        nested.extend_from_slice(b"Inner\0\xF2\xF1");
        let records = [
            fieldlist(&[member(0x75, 8, "Second")]), // 0x1000
            fieldlist(&[member(0x75, 0, "First"), enumerate, nested, index(0x1000)]),
            aggregate(LF_STRUCTURE, 0, 0x1001, 12, "_S"),
            aggregate(LF_STRUCTURE, 0, 0, 1, "_EMPTY"),
        ];
        assert_eq!(
            layout_of(&records, "_S").unwrap().members,
            [m("First", 0), m("Second", 8)]
        );
        assert_eq!(layout_of(&records, "_EMPTY").unwrap().members, []);
    }

    #[test]
    fn malformed_files_are_errors_not_panics() {
        assert!(matches!(
            Pdb::parse(b"not a pdb"),
            Err(PdbError::BadContainer)
        ));
        let good = pdb_with(&[
            fieldlist(&[member(0x75, 0, "A")]),
            aggregate(LF_STRUCTURE, 0, 0x1000, 4, "_S"),
        ]);
        assert!(
            Pdb::parse(&good)
                .unwrap()
                .types()
                .unwrap()
                .layout("_S")
                .is_ok()
        );

        // Cut the file short at every length: never a panic.
        for len in 0..good.len() {
            let _ = Pdb::parse(&good[..len]).and_then(|p| p.types()?.layout("_S"));
        }
        // Corrupt each byte in turn: never a panic.
        for i in 0..good.len() {
            let mut bad = good.clone();
            bad[i] ^= 0xFF;
            let _ = Pdb::parse(&bad).and_then(|p| {
                let _ = p.info();
                p.types()?.layout("_S")
            });
        }

        // A field list that continues into itself.
        let looped = [
            fieldlist(&[member(0x75, 0, "A"), index(0x1000)]),
            aggregate(LF_STRUCTURE, 0, 0x1000, 4, "_S"),
        ];
        assert_eq!(layout_of(&looped, "_S"), Err(PdbError::BadRecord));
        // A field list that is not one.
        let wrong = [aggregate(LF_STRUCTURE, 0, 0x1000, 4, "_S")];
        assert_eq!(layout_of(&wrong, "_S"), Err(PdbError::BadRecord));
        // A member kind this reader does not know.
        let mut method = 0x1511u16.to_le_bytes().to_vec();
        method.extend_from_slice(&[0; 6]);
        let unknown = [
            fieldlist(&[method]),
            aggregate(LF_STRUCTURE, 0, 0x1000, 4, "_S"),
        ];
        assert_eq!(layout_of(&unknown, "_S"), Err(PdbError::BadRecord));
    }
}
