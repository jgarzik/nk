//! PE32+ images: parse a file, lay it out in memory, relocate it, bind its
//! imports.
//!
//! One loader serves two users: `nkload` maps the kernel with it, and the
//! kernel maps Windows drivers with it. Input is untrusted: every offset is
//! bounds-checked and a malformed image is an `Err`, never a panic.
//!
//! No allocation and no `unsafe`. The caller owns the image memory and
//! passes it as a byte slice of `size_of_image` bytes.

#![cfg_attr(not(test), no_std)]

pub mod modules;

/// `IMAGE_FILE_MACHINE_AMD64`
pub const MACHINE_AMD64: u16 = 0x8664;
/// `IMAGE_FILE_MACHINE_ARM64`
pub const MACHINE_ARM64: u16 = 0xAA64;

/// The machine type of the architecture this crate was compiled for.
#[cfg(target_arch = "x86_64")]
pub const MACHINE_NATIVE: u16 = MACHINE_AMD64;
/// The machine type of the architecture this crate was compiled for.
#[cfg(target_arch = "aarch64")]
pub const MACHINE_NATIVE: u16 = MACHINE_ARM64;

pub const SCN_MEM_DISCARDABLE: u32 = 0x0200_0000;
pub const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
pub const SCN_MEM_READ: u32 = 0x4000_0000;
pub const SCN_MEM_WRITE: u32 = 0x8000_0000;

pub const DIR_IMPORT: usize = 1;
pub const DIR_EXCEPTION: usize = 3;
pub const DIR_BASERELOC: usize = 5;
pub const DIR_LOAD_CONFIG: usize = 10;

const REL_ABSOLUTE: u16 = 0;
const REL_DIR64: u16 = 10;
const ORDINAL_FLAG: u64 = 1 << 63;
const SECTION_HEADER_SIZE: usize = 40;
const IMPORT_DESC_SIZE: usize = 20;
/// Offset of `SecurityCookie` in `IMAGE_LOAD_CONFIG_DIRECTORY64`.
const LOAD_CONFIG_COOKIE: usize = 88;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeError {
    /// Not an MZ/PE image, or a header runs past the end of the file.
    BadHeader,
    /// A PE image, but not PE32+ (64-bit).
    NotPe32Plus,
    /// The image is for another machine; carries the machine it names.
    WrongMachine(u16),
    /// A section, directory or RVA lies outside the image.
    OutOfBounds,
    /// The destination buffer is smaller than `size_of_image`.
    BufferTooSmall,
    /// The image must move but carries no base relocations.
    NotRelocatable,
    /// A base relocation type this loader does not implement.
    UnsupportedReloc(u16),
    /// An import the resolver could not supply. `dll_rva` and `name_rva`
    /// point at NUL-terminated names inside the image (see [`cstr_at`]);
    /// an import by ordinal has `name_rva == 0` and the ordinal set.
    Unresolved {
        dll_rva: u32,
        name_rva: u32,
        ordinal: u16,
    },
}

fn u16_at(d: &[u8], off: usize) -> Result<u16, PeError> {
    let b = d.get(off..off.checked_add(2).ok_or(PeError::OutOfBounds)?);
    b.map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or(PeError::OutOfBounds)
}

fn u32_at(d: &[u8], off: usize) -> Result<u32, PeError> {
    let b = d.get(off..off.checked_add(4).ok_or(PeError::OutOfBounds)?);
    b.map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or(PeError::OutOfBounds)
}

fn u64_at(d: &[u8], off: usize) -> Result<u64, PeError> {
    let b = d.get(off..off.checked_add(8).ok_or(PeError::OutOfBounds)?);
    b.map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8])))
        .ok_or(PeError::OutOfBounds)
}

fn put_u64(d: &mut [u8], off: usize, v: u64) -> Result<(), PeError> {
    let end = off.checked_add(8).ok_or(PeError::OutOfBounds)?;
    d.get_mut(off..end)
        .ok_or(PeError::OutOfBounds)?
        .copy_from_slice(&v.to_le_bytes());
    Ok(())
}

/// A read past the end of the file while parsing headers is a bad header.
fn hdr<T>(r: Result<T, PeError>) -> Result<T, PeError> {
    r.map_err(|_| PeError::BadHeader)
}

/// The NUL-terminated byte string at `rva` in a mapped image, without the NUL.
pub fn cstr_at(image: &[u8], rva: u32) -> Result<&[u8], PeError> {
    let tail = image.get(rva as usize..).ok_or(PeError::OutOfBounds)?;
    let len = tail
        .iter()
        .position(|&b| b == 0)
        .ok_or(PeError::OutOfBounds)?;
    Ok(&tail[..len])
}

/// A data directory entry: where a table lives in the mapped image.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DataDir {
    pub rva: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Section {
    pub name: [u8; 8],
    pub rva: u32,
    pub virt_size: u32,
    pub raw_off: u32,
    pub raw_size: u32,
    pub characteristics: u32,
}

impl Section {
    /// Bytes the section occupies in memory. A linker may leave `virt_size`
    /// zero, meaning "same as the raw data".
    pub fn mem_size(&self) -> u32 {
        if self.virt_size != 0 {
            self.virt_size
        } else {
            self.raw_size
        }
    }
}

/// What a loader needs to know about an image once the file is gone.
/// `Copy`, so it outlives the file buffer it was parsed from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Headers {
    pub machine: u16,
    pub timestamp: u32,
    pub image_base: u64,
    pub entry_rva: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub subsystem: u16,
    dirs: [DataDir; 16],
}

impl Headers {
    pub fn dir(&self, index: usize) -> DataDir {
        self.dirs.get(index).copied().unwrap_or_default()
    }
}

/// The headers of a PE32+ image, from its first bytes: the file's, or
/// those of an image already laid out in memory. Returns them with the
/// offset of the section table and the number of sections.
fn read_headers(file: &[u8]) -> Result<(Headers, usize, usize), PeError> {
    if file.get(..2) != Some(b"MZ") {
        return Err(PeError::BadHeader);
    }
    let pe = hdr(u32_at(file, 0x3C))? as usize;
    if file.get(pe..pe.saturating_add(4)) != Some(b"PE\0\0") {
        return Err(PeError::BadHeader);
    }
    let coff = pe + 4;
    let machine = hdr(u16_at(file, coff))?;
    let nsections = hdr(u16_at(file, coff + 2))? as usize;
    let timestamp = hdr(u32_at(file, coff + 4))?;
    let opt_size = hdr(u16_at(file, coff + 16))? as usize;
    let opt = coff + 20;
    if hdr(u16_at(file, opt))? != 0x20B {
        return Err(PeError::NotPe32Plus);
    }
    let ndirs = (hdr(u32_at(file, opt + 108))? as usize).min(16);
    let mut dirs = [DataDir::default(); 16];
    for (i, d) in dirs.iter_mut().enumerate().take(ndirs) {
        d.rva = hdr(u32_at(file, opt + 112 + 8 * i))?;
        d.size = hdr(u32_at(file, opt + 116 + 8 * i))?;
    }
    let headers = Headers {
        machine,
        timestamp,
        image_base: hdr(u64_at(file, opt + 24))?,
        entry_rva: hdr(u32_at(file, opt + 16))?,
        size_of_image: hdr(u32_at(file, opt + 56))?,
        size_of_headers: hdr(u32_at(file, opt + 60))?,
        section_alignment: hdr(u32_at(file, opt + 32))?,
        subsystem: hdr(u16_at(file, opt + 68))?,
        dirs,
    };
    Ok((headers, opt + opt_size, nsections))
}

/// The headers of an image laid out in memory, of which `image` is at
/// least the first page.
pub fn image_headers(image: &[u8]) -> Result<Headers, PeError> {
    read_headers(image).map(|(headers, ..)| headers)
}

/// A PE32+ file, as read from disk.
#[derive(Debug, Clone, Copy)]
pub struct Pe<'a> {
    file: &'a [u8],
    headers: Headers,
    sections_off: usize,
    nsections: usize,
}

impl<'a> Pe<'a> {
    pub fn parse(file: &'a [u8]) -> Result<Self, PeError> {
        let (headers, sections_off, nsections) = read_headers(file)?;
        let table_end = sections_off + nsections * SECTION_HEADER_SIZE;
        if table_end > file.len() || headers.size_of_headers as usize > file.len() {
            return Err(PeError::BadHeader);
        }
        let pe = Self {
            file,
            headers,
            sections_off,
            nsections,
        };
        for s in pe.sections() {
            let mem_end = u64::from(s.rva) + u64::from(s.mem_size());
            let raw_end = u64::from(s.raw_off) + u64::from(s.raw_size);
            if mem_end > u64::from(headers.size_of_image) || raw_end > file.len() as u64 {
                return Err(PeError::OutOfBounds);
            }
        }
        if headers.entry_rva >= headers.size_of_image {
            return Err(PeError::OutOfBounds);
        }
        Ok(pe)
    }

    pub fn headers(&self) -> Headers {
        self.headers
    }

    /// Reject an image built for a machine other than `machine`.
    pub fn check_machine(&self, machine: u16) -> Result<(), PeError> {
        if self.headers.machine == machine {
            Ok(())
        } else {
            Err(PeError::WrongMachine(self.headers.machine))
        }
    }

    pub fn sections(&self) -> impl Iterator<Item = Section> + 'a {
        let (file, off) = (self.file, self.sections_off);
        (0..self.nsections).map(move |i| {
            // Bounds were checked in `parse`.
            let h = &file[off + i * SECTION_HEADER_SIZE..][..SECTION_HEADER_SIZE];
            let w = |o: usize| u32::from_le_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]);
            let mut name = [0; 8];
            name.copy_from_slice(&h[..8]);
            Section {
                name,
                virt_size: w(8),
                rva: w(12),
                raw_size: w(16),
                raw_off: w(20),
                characteristics: w(36),
            }
        })
    }

    /// Section characteristics (`SCN_MEM_*`) governing the image page at
    /// `rva`: the section that covers it, or read-only for the headers.
    /// `None` for a page no section covers, which should stay unmapped.
    pub fn page_flags(&self, rva: u32) -> Option<u32> {
        if rva < self.headers.size_of_headers {
            return Some(SCN_MEM_READ);
        }
        self.sections()
            .find(|s| rva >= s.rva && u64::from(rva) < u64::from(s.rva) + u64::from(s.mem_size()))
            .map(|s| s.characteristics)
    }

    /// Lay the file out as it sits in memory: headers, then each section at
    /// its RVA, everything else zero. `image` must hold `size_of_image` bytes.
    pub fn map_into(&self, image: &mut [u8]) -> Result<(), PeError> {
        let size = self.headers.size_of_image as usize;
        let image = image.get_mut(..size).ok_or(PeError::BufferTooSmall)?;
        image.fill(0);
        let hdr = self.headers.size_of_headers as usize;
        image
            .get_mut(..hdr)
            .ok_or(PeError::OutOfBounds)?
            .copy_from_slice(&self.file[..hdr]);
        for s in self.sections() {
            let n = s.raw_size.min(s.mem_size()) as usize;
            let src = &self.file[s.raw_off as usize..][..n];
            image[s.rva as usize..][..n].copy_from_slice(src);
        }
        Ok(())
    }
}

/// Apply base relocations to a mapped image that will run at `new_base`.
pub fn relocate(image: &mut [u8], h: &Headers, new_base: u64) -> Result<(), PeError> {
    let delta = new_base.wrapping_sub(h.image_base);
    if delta == 0 {
        return Ok(());
    }
    let dir = h.dir(DIR_BASERELOC);
    if dir.size == 0 {
        return Err(PeError::NotRelocatable);
    }
    let mut off = dir.rva as usize;
    let end = off
        .checked_add(dir.size as usize)
        .ok_or(PeError::OutOfBounds)?;
    while off + 8 <= end {
        let page = u32_at(image, off)? as usize;
        let block = u32_at(image, off + 4)? as usize;
        if block < 8 || off + block > end {
            return Err(PeError::OutOfBounds);
        }
        for i in (8..block).step_by(2) {
            let entry = u16_at(image, off + i)?;
            let at = page + (entry & 0xFFF) as usize;
            match entry >> 12 {
                REL_ABSOLUTE => {}
                REL_DIR64 => put_u64(image, at, u64_at(image, at)?.wrapping_add(delta))?,
                other => return Err(PeError::UnsupportedReloc(other)),
            }
        }
        off += block;
    }
    Ok(())
}

/// One imported symbol, as the resolver sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Symbol<'a> {
    Name(&'a [u8]),
    Ordinal(u16),
}

/// Walks the import tables of a mapped image one symbol at a time. Holds
/// offsets only, so the image can be written between steps.
struct ImportCursor {
    desc: usize,
    index: usize,
}

/// One import: RVAs of the DLL name and of the IAT slot, plus the raw thunk.
struct RawImport {
    dll_rva: u32,
    thunk: u64,
    slot: u32,
}

impl ImportCursor {
    fn new(h: &Headers) -> Option<Self> {
        let dir = h.dir(DIR_IMPORT);
        (dir.size != 0).then_some(Self {
            desc: dir.rva as usize,
            index: 0,
        })
    }

    fn next(&mut self, image: &[u8]) -> Result<Option<RawImport>, PeError> {
        loop {
            let lookup = u32_at(image, self.desc)?;
            let dll_rva = u32_at(image, self.desc + 12)?;
            let iat = u32_at(image, self.desc + 16)?;
            if dll_rva == 0 {
                return Ok(None);
            }
            // The lookup table is optional; the unbound IAT holds the same data.
            let names = if lookup != 0 { lookup } else { iat } as usize;
            let thunk = u64_at(image, names + 8 * self.index)?;
            if thunk == 0 {
                self.desc += IMPORT_DESC_SIZE;
                self.index = 0;
                continue;
            }
            let off = u32::try_from(8 * self.index)
                .ok()
                .and_then(|o| iat.checked_add(o));
            self.index += 1;
            return Ok(Some(RawImport {
                dll_rva,
                thunk,
                slot: off.ok_or(PeError::OutOfBounds)?,
            }));
        }
    }
}

fn symbol(image: &[u8], thunk: u64) -> Result<Symbol<'_>, PeError> {
    if thunk & ORDINAL_FLAG != 0 {
        return Ok(Symbol::Ordinal(thunk as u16));
    }
    // Skip the 2-byte hint in front of the name.
    let rva = u32::try_from(thunk + 2).map_err(|_| PeError::OutOfBounds)?;
    Ok(Symbol::Name(cstr_at(image, rva)?))
}

/// Call `f(dll, symbol)` for every import of a mapped image.
pub fn for_each_import(
    image: &[u8],
    h: &Headers,
    mut f: impl FnMut(&[u8], Symbol<'_>),
) -> Result<(), PeError> {
    let Some(mut cur) = ImportCursor::new(h) else {
        return Ok(());
    };
    while let Some(imp) = cur.next(image)? {
        f(cstr_at(image, imp.dll_rva)?, symbol(image, imp.thunk)?);
    }
    Ok(())
}

/// Fill the import address table of a mapped image. `resolve(dll, symbol)`
/// returns the address to bind, or `None`; the first `None` aborts with
/// [`PeError::Unresolved`] naming the symbol. Nothing is bound unless
/// everything resolves.
pub fn bind_imports(
    image: &mut [u8],
    h: &Headers,
    mut resolve: impl FnMut(&[u8], Symbol<'_>) -> Option<u64>,
) -> Result<(), PeError> {
    // Pass 1 checks every symbol, pass 2 writes: no half-bound image.
    for bind in [false, true] {
        let Some(mut cur) = ImportCursor::new(h) else {
            return Ok(());
        };
        while let Some(imp) = cur.next(image)? {
            let dll = cstr_at(image, imp.dll_rva)?;
            let sym = symbol(image, imp.thunk)?;
            let addr = resolve(dll, sym).ok_or_else(|| unresolved(image, dll, sym))?;
            if bind {
                put_u64(image, imp.slot as usize, addr)?;
            }
        }
    }
    Ok(())
}

fn unresolved(image: &[u8], dll: &[u8], sym: Symbol<'_>) -> PeError {
    // Both names are subslices of `image`: recover their RVAs.
    let rva = |s: &[u8]| (s.as_ptr() as usize).wrapping_sub(image.as_ptr() as usize) as u32;
    match sym {
        Symbol::Name(n) => PeError::Unresolved {
            dll_rva: rva(dll),
            name_rva: rva(n),
            ordinal: 0,
        },
        Symbol::Ordinal(o) => PeError::Unresolved {
            dll_rva: rva(dll),
            name_rva: 0,
            ordinal: o,
        },
    }
}

/// RVA of the stack-protector cookie (`__security_cookie`) named by the load
/// configuration directory, if the image has one. `loaded_base` is the base
/// the image was relocated to: the directory stores a virtual address.
pub fn security_cookie_rva(image: &[u8], h: &Headers, loaded_base: u64) -> Option<u32> {
    let dir = h.dir(DIR_LOAD_CONFIG);
    let size = u32_at(image, dir.rva as usize).ok()? as usize;
    if dir.size == 0 || size < LOAD_CONFIG_COOKIE + 8 {
        return None;
    }
    let va = u64_at(image, dir.rva as usize + LOAD_CONFIG_COOKIE).ok()?;
    let rva = va.checked_sub(loaded_base)?;
    (va != 0 && rva + 8 <= u64::from(h.size_of_image)).then_some(rva as u32)
}

/// The value MSVC leaves in `__security_cookie` for the loader to replace.
pub const DEFAULT_SECURITY_COOKIE: u64 = 0x2B99_2DDF_A232;

/// What an image gets when the mixing lands on a value it may not have.
const FALLBACK_SECURITY_COOKIE: u64 = 0x0000_1F2E_3D4C_5B6A;
const COOKIE_SEED: u64 = 0x9E37_79B9_7F4A_7C15;
const COOKIE_MULTIPLIER: u64 = 0xBF58_476D_1CE4_E5B9;

/// A stack-protector cookie for one image, mixed from `entropy`: never
/// zero, never the default, and with the top 16 bits clear, which the
/// x64 check routine requires.
pub const fn security_cookie(entropy: u64) -> u64 {
    let mut x = entropy ^ COOKIE_SEED;
    x ^= x >> 30;
    x = x.wrapping_mul(COOKIE_MULTIPLIER);
    x ^= x >> 27;
    let cookie = x & 0x0000_FFFF_FFFF_FFFF;
    if cookie == 0 || cookie == DEFAULT_SECURITY_COOKIE {
        FALLBACK_SECURITY_COOKIE
    } else {
        cookie
    }
}

#[cfg(test)]
mod tests;
