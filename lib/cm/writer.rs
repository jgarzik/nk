//! A writer of small hive files, for the tests: it lays cells out in one
//! bin and leaves every link to the caller, so that a test can also
//! write a file that is wrong.

use crate::regf::{BASE_BLOCK, BIG_SEGMENT, checksum, lh_hash};

/// No cell.
pub const NIL: u32 = u32::MAX;

/// `text` as UTF-16 bytes.
pub fn wide(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

/// Store the checksum of a base block that a test has changed.
pub fn seal(file: &mut [u8]) {
    let sum = checksum(file);
    file[0x1FC..0x200].copy_from_slice(&sum.to_le_bytes());
}

/// The bins of a hive being written; the first 32 bytes are the bin's
/// header.
pub struct Writer {
    pub bins: Vec<u8>,
    /// The minor version: above 3, long data are written as big data.
    pub minor: u32,
}

impl Writer {
    pub fn new() -> Self {
        Self {
            bins: vec![0; 32],
            minor: 5,
        }
    }

    /// An allocated cell holding `data`.
    pub fn cell(&mut self, data: &[u8]) -> u32 {
        let at = self.bins.len();
        let size = (4 + data.len() + 7) & !7;
        self.bins.extend((-(size as i32)).to_le_bytes());
        self.bins.extend(data);
        self.bins.resize(at + size, 0);
        at as u32
    }

    /// Change four bytes of a cell's data.
    pub fn patch(&mut self, cell: u32, field: usize, value: u32) {
        let at = cell as usize + 4 + field;
        self.bins[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Change two bytes of a cell's data.
    pub fn patch16(&mut self, cell: u32, field: usize, value: u16) {
        let at = cell as usize + 4 + field;
        self.bins[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    /// Mark a cell free.
    pub fn free(&mut self, cell: u32) {
        let at = cell as usize;
        let size = i32::from_le_bytes(self.bins[at..at + 4].try_into().unwrap());
        self.bins[at..at + 4].copy_from_slice(&(-size).to_le_bytes());
    }

    /// A key node without subkeys, values, class or security. A
    /// `compressed` name is written one byte per character.
    pub fn key(&mut self, parent: u32, name: &str, compressed: bool) -> u32 {
        let mut record = vec![0u8; 0x4C];
        record[..2].copy_from_slice(b"nk");
        record[2] = if compressed { 0x20 } else { 0 };
        record[0x10..0x14].copy_from_slice(&parent.to_le_bytes());
        for link in [0x1C, 0x20, 0x28, 0x2C, 0x30] {
            record[link..link + 4].copy_from_slice(&NIL.to_le_bytes());
        }
        let name = if compressed {
            name.chars().map(|c| c as u8).collect()
        } else {
            wide(name)
        };
        record[0x48..0x4A].copy_from_slice(&(name.len() as u16).to_le_bytes());
        record.extend(name);
        self.cell(&record)
    }

    /// A list of kind `lf`, `lh`, `li` or `ri` naming `cells`.
    pub fn list(&mut self, kind: &[u8; 2], cells: &[u32]) -> u32 {
        let mut record = kind.to_vec();
        record.extend((cells.len() as u16).to_le_bytes());
        for &cell in cells {
            record.extend(cell.to_le_bytes());
            match kind {
                // The start of the name, padded; the hash of the name.
                b"lf" => {
                    record.extend(self.name_of(cell).iter().take(4).map(|&c| c as u8));
                    record.resize((record.len() + 3) & !3, 0);
                }
                b"lh" => record.extend(lh_hash(self.name_of(cell).into_iter()).to_le_bytes()),
                _ => {}
            }
        }
        self.cell(&record)
    }

    /// The name of the key in `cell`.
    fn name_of(&self, cell: u32) -> Vec<u16> {
        let record = &self.bins[cell as usize + 4..];
        let length = usize::from(u16::from_le_bytes([record[0x48], record[0x49]]));
        let name = &record[0x4C..0x4C + length];
        if record[2] & 0x20 != 0 {
            name.iter().map(|&c| u16::from(c)).collect()
        } else {
            name.chunks(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect()
        }
    }

    /// Give `key` the subkeys `children`, in a list of kind `kind`.
    pub fn subkeys(&mut self, key: u32, kind: &[u8; 2], children: &[u32]) -> u32 {
        let list = self.list(kind, children);
        self.patch(key, 0x14, children.len() as u32);
        self.patch(key, 0x1C, list);
        list
    }

    /// A value: data of up to four bytes in the record, longer data in a
    /// cell, and from version 1.4 data over 16344 bytes in segments.
    pub fn value(&mut self, name: &str, compressed: bool, kind: u32, data: &[u8]) -> u32 {
        let (length, place) = if data.len() <= 4 {
            let mut field = [0u8; 4];
            field[..data.len()].copy_from_slice(data);
            (data.len() as u32 | 0x8000_0000, u32::from_le_bytes(field))
        } else if data.len() > BIG_SEGMENT && self.minor > 3 {
            let segments: Vec<u32> = data.chunks(BIG_SEGMENT).map(|s| self.cell(s)).collect();
            // The segment list is bare: no signature or count.
            let list: Vec<u8> = segments.iter().flat_map(|s| s.to_le_bytes()).collect();
            let list = self.cell(&list);
            let mut big = b"db".to_vec();
            big.extend((segments.len() as u16).to_le_bytes());
            big.extend(list.to_le_bytes());
            (data.len() as u32, self.cell(&big))
        } else {
            (data.len() as u32, self.cell(data))
        };
        let mut record = b"vk".to_vec();
        let name = if compressed {
            name.chars().map(|c| c as u8).collect()
        } else {
            wide(name)
        };
        record.extend((name.len() as u16).to_le_bytes());
        record.extend(length.to_le_bytes());
        record.extend(place.to_le_bytes());
        record.extend(kind.to_le_bytes());
        record.extend(u32::from(compressed).to_le_bytes());
        record.extend(name);
        self.cell(&record)
    }

    /// Give `key` the values `values`.
    pub fn values(&mut self, key: u32, values: &[u32]) -> u32 {
        let list: Vec<u8> = values.iter().flat_map(|v| v.to_le_bytes()).collect();
        let list = self.cell(&list);
        self.patch(key, 0x24, values.len() as u32);
        self.patch(key, 0x28, list);
        list
    }

    /// Give `key` a class.
    pub fn class(&mut self, key: u32, class: &[u8]) -> u32 {
        let cell = self.cell(class);
        self.patch(key, 0x30, cell);
        self.patch16(key, 0x4A, class.len() as u16);
        cell
    }

    /// Give `key` a security descriptor.
    pub fn security(&mut self, key: u32, descriptor: &[u8]) -> u32 {
        let mut record = vec![0u8; 0x14];
        record[..2].copy_from_slice(b"sk");
        record[0x10..0x14].copy_from_slice(&(descriptor.len() as u32).to_le_bytes());
        record.extend(descriptor);
        let cell = self.cell(&record);
        self.patch(key, 0x2C, cell);
        cell
    }

    /// The file: a base block, then one bin holding the cells and a
    /// free cell to its end.
    pub fn finish(mut self, root: u32) -> Vec<u8> {
        let used = self.bins.len();
        let size = (used + 4095) & !4095;
        self.bins.resize(size, 0);
        if size != used {
            self.bins[used..used + 4].copy_from_slice(&((size - used) as u32).to_le_bytes());
        }
        self.bins[..4].copy_from_slice(b"hbin");
        self.bins[8..12].copy_from_slice(&(size as u32).to_le_bytes());
        let mut file = vec![0u8; BASE_BLOCK];
        file[..4].copy_from_slice(b"regf");
        // Both sequence numbers, major and minor version, type, format,
        // root cell, length.
        let fields = [1, 1, 0, 0, 1, self.minor, 0, 1, root, size as u32];
        for (i, field) in fields.iter().enumerate() {
            file[4 + 4 * i..8 + 4 * i].copy_from_slice(&field.to_le_bytes());
        }
        seal(&mut file);
        file.extend(self.bins);
        file
    }

    /// Four bytes of a cell's data.
    pub fn peek(&self, cell: u32, field: usize) -> u32 {
        let at = cell as usize + 4 + field;
        u32::from_le_bytes(self.bins[at..at + 4].try_into().unwrap())
    }
}

/// The cells of [`sample`] that tests change.
pub struct Sample {
    pub root: u32,
    pub alpha: u32,
    pub gamma: u32,
    pub deep: u32,
    /// The root's `ri`, and the `lh` and `lf` it names.
    pub ri: u32,
    pub lh: u32,
    pub lf: u32,
    pub value_list: u32,
    pub dword: u32,
    pub text: u32,
    pub big: u32,
    pub wide_value: u32,
    pub sk: u32,
}

/// The 40000 bytes of the sample's big value.
pub fn big_data() -> Vec<u8> {
    (0..40000u32).map(|i| (i % 251) as u8).collect()
}

/// A hive with every kind of record:
///
/// ```text
/// ROOT            security; values "", one, two, three, dword, text, big, Знач
///   Alpha         class "Cls"; subkey Ключ (UTF-16 name, in an `li`)
///   beta
///   Gamma         a symbolic link, last written at 0x01D9_0000_0000_1234
/// ```
///
/// The root lists its subkeys in an `ri` of an `lh` (Alpha, beta) and an
/// `lf` (Gamma).
pub fn sample() -> (Writer, Sample) {
    let mut hive = Writer::new();
    let root = hive.key(NIL, "ROOT", true);
    let alpha = hive.key(root, "Alpha", true);
    let beta = hive.key(root, "beta", true);
    let gamma = hive.key(root, "Gamma", true);
    let deep = hive.key(alpha, "Ключ", false);
    let lh = hive.list(b"lh", &[alpha, beta]);
    let lf = hive.list(b"lf", &[gamma]);
    let ri = hive.subkeys(root, b"ri", &[lh, lf]);
    hive.patch(root, 0x14, 3);
    hive.subkeys(alpha, b"li", &[deep]);
    hive.class(alpha, &wide("Cls"));
    hive.patch16(gamma, 2, 0x30);
    hive.patch(gamma, 4, 0x1234);
    hive.patch(gamma, 8, 0x01D9_0000);
    let sk = hive.security(root, &[1, 0, 4, 0x80, 9, 9]);
    let dword = hive.value("dword", true, 4, &[0x78, 0x56, 0x34, 0x12]);
    let text = hive.value("text", true, 1, &wide("regf\0"));
    let big = hive.value("big", true, 3, &big_data());
    let wide_value = hive.value("Знач", false, 3, &[1, 2, 3, 4, 5]);
    let values = [
        hive.value("", true, 1, &[]),
        hive.value("one", true, 3, &[1]),
        hive.value("two", true, 3, &[1, 2]),
        hive.value("three", true, 3, &[1, 2, 3]),
        dword,
        text,
        big,
        wide_value,
    ];
    let value_list = hive.values(root, &values);
    let cells = Sample {
        root,
        alpha,
        gamma,
        deep,
        ri,
        lh,
        lf,
        value_list,
        dword,
        text,
        big,
        wide_value,
        sk,
    };
    (hive, cells)
}
