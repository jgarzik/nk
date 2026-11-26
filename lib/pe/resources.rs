//! The resource directory of an image, and message tables.
//!
//! A resource is found by three names, one per level of the directory:
//! its type, its name and its language
//! ([PE format, the .rsrc section](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#the-rsrc-section)).
//! Here every name is a number, which is all a message table needs:
//! `RtlFindMessage` asks for type `RT_MESSAGETABLE`, name 1 and a
//! language, and then for a message by number in the table found
//! ([`find_message`]).
//!
//! Which languages are tried for the one asked for is
//! [`languages`]: the order of the pinned kernel's
//! `LdrpSearchResourceSection_U`.

use crate::DataDir;

/// The resource directory's index among the data directories.
pub const DIR_RESOURCE: usize = 2;
/// `RT_MESSAGETABLE`.
pub const RT_MESSAGETABLE: u32 = 11;
/// `MAKELANGID(LANG_ENGLISH, SUBLANG_ENGLISH_US)`.
pub const LANG_EN_US: u16 = 0x0409;

/// Why a resource was not found. Each but the last is a status of
/// Windows'.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceError {
    /// The image has no resource directory
    /// (`STATUS_RESOURCE_DATA_NOT_FOUND`).
    NoResources,
    /// No resource of the type (`STATUS_RESOURCE_TYPE_NOT_FOUND`).
    Type,
    /// The type has no resource of the name
    /// (`STATUS_RESOURCE_NAME_NOT_FOUND`).
    Name,
    /// The resource is in none of the languages tried
    /// (`STATUS_RESOURCE_LANG_NOT_FOUND`).
    Language,
    /// The directory leads outside the image.
    Malformed,
}

/// Where a resource's bytes are in the image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceData {
    pub rva: u32,
    pub size: u32,
}

/// The languages to try for a resource asked for in language
/// `requested`, in order, and whether any language will do in the end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Languages {
    tried: [u16; 8],
    count: usize,
    /// When none of the languages has the resource, the first language
    /// the resource is in is taken.
    pub any: bool,
}

impl Languages {
    /// The languages, first to last.
    pub fn tried(&self) -> &[u16] {
        &self.tried[..self.count]
    }

    /// Add a language, unless it is the one before it.
    fn push(&mut self, language: u16) {
        if self.count != 0 && self.tried[self.count - 1] == language {
            return;
        }
        if self.count < self.tried.len() {
            self.tried[self.count] = language;
            self.count += 1;
        }
    }
}

/// The language a language falls back to: the same primary language
/// with no sublanguage (`en-US` to `en`); none for a language that has
/// no sublanguage. Windows asks its locale data, where a few languages
/// have another parent (a script: `zh-TW` to `zh-Hant`); those are
/// not known here.
fn parent(language: u16) -> Option<u16> {
    (language >> 10 != 0).then_some(language & 0x3FF)
}

/// The order `LdrpSearchResourceSection_U` tries languages in: the one
/// asked for, then its parents. A request with a primary language
/// ends there. A neutral request (primary language zero) goes on to
/// the machine's UI language, the install language, the system's
/// default locale and US English, each unless it was the one before,
/// and at last takes whatever language there is.
pub fn languages(
    requested: u16,
    machine_ui: u16,
    install_ui: u16,
    system_locale: u16,
) -> Languages {
    let mut order = Languages {
        tried: [0; 8],
        count: 0,
        any: false,
    };
    order.push(requested);
    let mut current = requested;
    while let Some(next) = parent(current) {
        order.push(next);
        current = next;
    }
    if requested & 0x3FF != 0 {
        return order;
    }
    if machine_ui != 0 {
        order.push(machine_ui);
    }
    if install_ui != machine_ui {
        order.push(install_ui);
    }
    if system_locale != install_ui && system_locale != machine_ui {
        order.push(system_locale);
    }
    if ![system_locale, install_ui, machine_ui].contains(&LANG_EN_US) {
        order.push(LANG_EN_US);
    }
    order.any = true;
    order
}

fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let b = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let b = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// The high bit of a directory entry's second word: it leads to
/// another directory, not to data.
const SUBDIRECTORY: u32 = 0x8000_0000;

/// What a directory entry leads to: an offset into the resource
/// section, of a directory or of a data entry.
#[derive(Clone, Copy)]
enum Leads {
    Directory(usize),
    Data(usize),
}

fn leads(word: u32) -> Leads {
    if word & SUBDIRECTORY != 0 {
        Leads::Directory((word & !SUBDIRECTORY) as usize)
    } else {
        Leads::Data(word as usize)
    }
}

/// The entries of the directory at `at` that are named by number:
/// they follow the ones named by string. `None` if the directory is
/// not within the section.
fn numbered(section: &[u8], at: usize) -> Option<impl Iterator<Item = (u32, Leads)> + '_> {
    let named = usize::from(u16_at(section, at.checked_add(12)?)?);
    let ids = usize::from(u16_at(section, at.checked_add(14)?)?);
    let first = at.checked_add(16)?.checked_add(named.checked_mul(8)?)?;
    let entries = section.get(first..first.checked_add(ids.checked_mul(8)?)?)?;
    Some(entries.as_chunks::<8>().0.iter().map(|e| {
        (
            u32::from_le_bytes([e[0], e[1], e[2], e[3]]),
            leads(u32::from_le_bytes([e[4], e[5], e[6], e[7]])),
        )
    }))
}

/// The data entry at `at`: where the resource's bytes are.
fn data(section: &[u8], at: usize) -> Result<ResourceData, ResourceError> {
    match (
        u32_at(section, at),
        at.checked_add(4).and_then(|at| u32_at(section, at)),
    ) {
        (Some(rva), Some(size)) => Ok(ResourceData { rva, size }),
        _ => Err(ResourceError::Malformed),
    }
}

/// Find the resource of type `type_id` and name `name_id` in the
/// image laid out in memory at `image`, whose resource directory is
/// `dir`, in the first of `languages` it is in. An entry that leads
/// to data where a directory was expected is the resource, as on
/// Windows.
pub fn find(
    image: &[u8],
    dir: DataDir,
    type_id: u32,
    name_id: u32,
    languages: &Languages,
) -> Result<ResourceData, ResourceError> {
    if dir.rva == 0 || dir.size == 0 {
        return Err(ResourceError::NoResources);
    }
    let section = image
        .get(dir.rva as usize..)
        .ok_or(ResourceError::Malformed)?;
    let step = |at: usize, id: u32, missing: ResourceError| {
        numbered(section, at)
            .ok_or(ResourceError::Malformed)?
            .find(|(entry, _)| *entry == id)
            .map(|(_, leads)| leads)
            .ok_or(missing)
    };
    let names = match step(0, type_id, ResourceError::Type)? {
        Leads::Directory(at) => at,
        Leads::Data(at) => return data(section, at),
    };
    let in_languages = match step(names, name_id, ResourceError::Name)? {
        Leads::Directory(at) => at,
        Leads::Data(at) => return data(section, at),
    };
    let found = languages
        .tried()
        .iter()
        .find_map(|&language| {
            match step(in_languages, u32::from(language), ResourceError::Language) {
                Err(ResourceError::Language) => None,
                other => Some(other),
            }
        })
        .or_else(|| {
            if !languages.any {
                return None;
            }
            match numbered(section, in_languages) {
                None => Some(Err(ResourceError::Malformed)),
                Some(mut entries) => entries.next().map(|(_, leads)| Ok(leads)),
            }
        })
        .unwrap_or(Err(ResourceError::Language))?;
    match found {
        Leads::Data(at) => data(section, at),
        // A fourth level is no resource.
        Leads::Directory(_) => Err(ResourceError::Malformed),
    }
}

/// Where message `id` is in the message table `table` (a
/// `MESSAGE_RESOURCE_DATA`): the offset of its `MESSAGE_RESOURCE_ENTRY`,
/// which begins with its own length. `None` if no block of the table
/// has the number, or the table ends before the message
/// (`STATUS_MESSAGE_NOT_FOUND`).
pub fn find_message(table: &[u8], id: u32) -> Option<usize> {
    let blocks = u32_at(table, 0)? as usize;
    for block in 0..blocks {
        let at = 4usize.checked_add(block.checked_mul(12)?)?;
        let (low, high) = (u32_at(table, at)?, u32_at(table, at + 4)?);
        if id < low || id > high {
            continue;
        }
        // The block's entries follow one another, each as long as it
        // says.
        let mut entry = u32_at(table, at + 8)? as usize;
        for _ in low..id {
            entry = entry.checked_add(usize::from(u16_at(table, entry)?))?;
        }
        // The entry's own header is within the table.
        u16_at(table, entry)?;
        return Some(entry);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSRC: u32 = 0x1000;

    /// A directory: its entries named by number, each leading to a
    /// directory (`true`) or data at an offset.
    fn directory(named: u16, entries: &[(u32, bool, u32)]) -> Vec<u8> {
        let mut out = vec![0; 12];
        out.extend(named.to_le_bytes());
        out.extend(((entries.len() - usize::from(named)) as u16).to_le_bytes());
        for &(id, sub, at) in entries {
            out.extend(id.to_le_bytes());
            out.extend((at | if sub { SUBDIRECTORY } else { 0 }).to_le_bytes());
        }
        out
    }

    /// An image whose resource section has: type 11, name 1, in
    /// languages 0x0407 and 0x0409 (data entries naming RVAs 0x2000
    /// and 0x3000); type 11, name 2, in language 0x0c0a only; type 16,
    /// a string-named entry first, then name 1 leading straight to
    /// data.
    fn image() -> (Vec<u8>, DataDir) {
        let mut section = Vec::new();
        // 0x00: root.
        section.extend(directory(0, &[(11, true, 0x20), (16, true, 0x40)]));
        // 0x20: type 11's names.
        section.resize(0x20, 0);
        section.extend(directory(0, &[(1, true, 0x60), (2, true, 0x80)]));
        // 0x40: type 16's names: one by string, one by number.
        section.resize(0x40, 0);
        section.extend(directory(
            1,
            &[(0x8000_0200, false, 0xC0), (1, false, 0xC0)],
        ));
        // 0x60: name 1's languages.
        section.resize(0x60, 0);
        section.extend(directory(
            0,
            &[(0x0407, false, 0xA0), (0x0409, false, 0xB0)],
        ));
        // 0x80: name 2's languages.
        section.resize(0x80, 0);
        section.extend(directory(0, &[(0x0C0A, false, 0xC0)]));
        // 0xA0, 0xB0, 0xC0: data entries.
        section.resize(0xA0, 0);
        for (rva, size) in [(0x2000u32, 0x10u32), (0x3000, 0x20), (0x4000, 0x30)] {
            section.extend(rva.to_le_bytes());
            section.extend(size.to_le_bytes());
            section.extend([0; 8]);
        }
        let mut image = vec![0; RSRC as usize];
        image.extend(&section);
        let dir = DataDir {
            rva: RSRC,
            size: section.len() as u32,
        };
        (image, dir)
    }

    fn en_us(requested: u16) -> Languages {
        languages(requested, LANG_EN_US, LANG_EN_US, LANG_EN_US)
    }

    #[test]
    fn languages_are_tried_in_windows_order() {
        // Neutral: itself, the system's languages once, then any.
        let neutral = en_us(0);
        assert_eq!(neutral.tried(), [0, 0x0409]);
        assert!(neutral.any);
        // A system of three languages, none of them US English.
        let mixed = languages(0, 0x0407, 0x040C, 0x0410);
        assert_eq!(mixed.tried(), [0, 0x0407, 0x040C, 0x0410, 0x0409]);
        // The install language and the locale are not tried twice.
        assert_eq!(
            languages(0, 0x0407, 0x0407, 0x0407).tried(),
            [0, 0x0407, 0x0409]
        );
        assert_eq!(
            languages(0, 0x0407, 0x040C, 0x0407).tried(),
            [0, 0x0407, 0x040C, 0x0409]
        );
        // No machine language: the install language first.
        assert_eq!(languages(0, 0, 0x0409, 0x0409).tried(), [0, 0x0409]);
        // A sublanguage of the neutral language is neutral too.
        let default = en_us(0x0400);
        assert_eq!(default.tried(), [0x0400, 0, 0x0409]);
        assert!(default.any);
        // A language asked for: itself and its parent, nothing else.
        let german = en_us(0x0C07);
        assert_eq!(german.tried(), [0x0C07, 0x0007]);
        assert!(!german.any);
        let primary = en_us(0x0009);
        assert_eq!(primary.tried(), [0x0009]);
        assert!(!primary.any);
    }

    #[test]
    fn a_resource_is_found_by_type_name_and_language() {
        let (image, dir) = image();
        let found = |ty, name, language| find(&image, dir, ty, name, &en_us(language));
        let (german, english, spanish) = (
            ResourceData {
                rva: 0x2000,
                size: 0x10,
            },
            ResourceData {
                rva: 0x3000,
                size: 0x20,
            },
            ResourceData {
                rva: 0x4000,
                size: 0x30,
            },
        );
        assert_eq!(found(11, 1, 0x0407), Ok(german));
        assert_eq!(found(11, 1, 0x0409), Ok(english));
        // Neutral: the system's language before the first there is.
        assert_eq!(found(11, 1, 0), Ok(english));
        // Neutral, and the system's language is not there: any.
        assert_eq!(found(11, 2, 0), Ok(spanish));
        // A language asked for that is not there: no other will do.
        assert_eq!(found(11, 1, 0x040C), Err(ResourceError::Language));
        assert_eq!(found(11, 2, 0x0409), Err(ResourceError::Language));
        assert_eq!(found(11, 3, 0), Err(ResourceError::Name));
        assert_eq!(found(12, 1, 0), Err(ResourceError::Type));
        // Entries named by string are not numbers; one that leads
        // straight to data is the resource.
        assert_eq!(found(16, 0x200, 0), Err(ResourceError::Name));
        assert_eq!(found(16, 1, 0x0409), Ok(spanish));
    }

    #[test]
    fn an_image_without_resources_or_with_broken_ones_has_none() {
        let (image, dir) = image();
        let neutral = en_us(0);
        let none = DataDir { rva: 0, size: 0 };
        assert_eq!(
            find(&image, none, 11, 1, &neutral),
            Err(ResourceError::NoResources)
        );
        let outside = DataDir {
            rva: 0x9000,
            size: 0x100,
        };
        assert_eq!(
            find(&image, outside, 11, 1, &neutral),
            Err(ResourceError::Malformed)
        );
        // Cut anywhere, the search fails or finds what is whole; it
        // never reads past the image.
        for cut in RSRC as usize..image.len() {
            let _ = find(&image[..cut], dir, 11, 1, &neutral);
            let _ = find(&image[..cut], dir, 11, 2, &neutral);
        }
        assert_eq!(
            find(&image[..RSRC as usize + 0x30], dir, 11, 1, &neutral),
            Err(ResourceError::Malformed)
        );
    }

    /// A message table of two blocks: messages 1..=3 and 0x100.
    fn table() -> Vec<u8> {
        let entry = |text: &[u8]| {
            let mut out = ((4 + text.len()) as u16).to_le_bytes().to_vec();
            out.extend(0u16.to_le_bytes());
            out.extend(text);
            out
        };
        let first = [entry(b"one\0"), entry(b"two!\0\0\0\0"), entry(b"3\0\0\0")].concat();
        let second = entry(b"big\0");
        let mut out = 2u32.to_le_bytes().to_vec();
        let at = 4 + 2 * 12;
        for (low, high, offset) in [(1u32, 3u32, at), (0x100, 0x100, at + first.len())] {
            out.extend(low.to_le_bytes());
            out.extend(high.to_le_bytes());
            out.extend((offset as u32).to_le_bytes());
        }
        out.extend(first);
        out.extend(second);
        out
    }

    #[test]
    fn a_message_is_found_by_number() {
        let table = table();
        let text = |id| {
            find_message(&table, id).map(|at| {
                let length = usize::from(u16_at(&table, at).unwrap());
                &table[at + 4..at + length]
            })
        };
        assert_eq!(text(1), Some(&b"one\0"[..]));
        assert_eq!(text(2), Some(&b"two!\0\0\0\0"[..]));
        assert_eq!(text(3), Some(&b"3\0\0\0"[..]));
        assert_eq!(text(0x100), Some(&b"big\0"[..]));
        for missing in [0, 4, 0xFF, 0x101, u32::MAX] {
            assert_eq!(text(missing), None, "{missing:#x}");
        }
        // Cut anywhere, a message is found whole or not at all.
        for cut in 0..table.len() {
            for id in [1, 2, 3, 0x100] {
                if let Some(at) = find_message(&table[..cut], id) {
                    assert!(at + 2 <= cut);
                }
            }
        }
        assert_eq!(find_message(&[], 1), None);
    }
}
