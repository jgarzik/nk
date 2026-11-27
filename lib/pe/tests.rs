//! Tests run against small PE32+ images assembled here, so they need no
//! fixture files. `Builder` is also the documentation of the layout the
//! loader expects.

use super::*;

const BASE: u64 = 0x1_4000_0000;
const TEXT: u32 = 0x1000;
const DATA: u32 = 0x2000;
const IMAGE_SIZE: u32 = 0x3000;

/// Offsets inside the data section.
const PTR_SLOT: u32 = DATA; // a pointer that needs relocating
const COOKIE: u32 = DATA + 8;
const RELOC: u32 = DATA + 0x100;
const LOADCFG: u32 = DATA + 0x200;
const IMPORTS: u32 = DATA + 0x400;

struct Builder {
    machine: u16,
    imports: Vec<(&'static str, Vec<&'static str>)>,
    ordinal: Option<u16>,
    relocs: bool,
    reloc_type: u16,
    lookup_table: bool,
}

impl Builder {
    fn new() -> Self {
        Self {
            machine: MACHINE_AMD64,
            imports: vec![("ntoskrnl.exe", vec!["IoCreateDevice", "IofCompleteRequest"])],
            ordinal: None,
            relocs: true,
            reloc_type: REL_DIR64,
            lookup_table: true,
        }
    }

    fn build(&self) -> Vec<u8> {
        let mut data = vec![0u8; 0x1000];
        let at = |rva: u32| (rva - DATA) as usize;
        data[at(PTR_SLOT)..][..8].copy_from_slice(&(BASE + u64::from(TEXT) + 0x10).to_le_bytes());
        data[at(COOKIE)..][..8].copy_from_slice(&0x2B99_2DDF_A232u64.to_le_bytes());

        // One relocation block for the data page: the pointer, plus padding.
        let entries = [(self.reloc_type << 12) | (PTR_SLOT - DATA) as u16, 0];
        data[at(RELOC)..][..4].copy_from_slice(&DATA.to_le_bytes());
        data[at(RELOC) + 4..][..4].copy_from_slice(&12u32.to_le_bytes());
        for (i, e) in entries.iter().enumerate() {
            data[at(RELOC) + 8 + 2 * i..][..2].copy_from_slice(&e.to_le_bytes());
        }

        data[at(LOADCFG)..][..4].copy_from_slice(&0x100u32.to_le_bytes());
        let cookie_va = BASE + u64::from(COOKIE);
        data[at(LOADCFG) + LOAD_CONFIG_COOKIE..][..8].copy_from_slice(&cookie_va.to_le_bytes());

        // Import descriptors, then per-DLL: name, hint/name entries, ILT, IAT.
        let ndesc = self.imports.len() + 1;
        let mut next = IMPORTS + (ndesc * IMPORT_DESC_SIZE) as u32;
        let mut put = |data: &mut Vec<u8>, bytes: &[u8]| {
            let rva = next;
            data[at(rva)..][..bytes.len()].copy_from_slice(bytes);
            next += (bytes.len() as u32).next_multiple_of(8);
            rva
        };
        for (i, (dll, names)) in self.imports.iter().enumerate() {
            let dll_rva = put(&mut data, format!("{dll}\0").as_bytes());
            let mut thunks: Vec<u64> = names
                .iter()
                .map(|n| u64::from(put(&mut data, format!("\0\0{n}\0").as_bytes())))
                .collect();
            if let (0, Some(o)) = (i, self.ordinal) {
                thunks.push(ORDINAL_FLAG | u64::from(o));
            }
            thunks.push(0);
            let table: Vec<u8> = thunks.iter().flat_map(|t| t.to_le_bytes()).collect();
            let ilt = if self.lookup_table {
                put(&mut data, &table)
            } else {
                0
            };
            let iat = put(&mut data, &table);
            let d = at(IMPORTS) + i * IMPORT_DESC_SIZE;
            data[d..][..4].copy_from_slice(&ilt.to_le_bytes());
            data[d + 12..][..4].copy_from_slice(&dll_rva.to_le_bytes());
            data[d + 16..][..4].copy_from_slice(&iat.to_le_bytes());
        }

        let mut f = vec![0u8; 0x400];
        f[..2].copy_from_slice(b"MZ");
        f[0x3C..][..4].copy_from_slice(&0x80u32.to_le_bytes());
        f[0x80..][..4].copy_from_slice(b"PE\0\0");
        let coff = 0x84;
        f[coff..][..2].copy_from_slice(&self.machine.to_le_bytes());
        f[coff + 2..][..2].copy_from_slice(&2u16.to_le_bytes());
        f[coff + 4..][..4].copy_from_slice(&0x5F00_0000u32.to_le_bytes());
        f[coff + 16..][..2].copy_from_slice(&240u16.to_le_bytes());
        let opt = coff + 20;
        f[opt..][..2].copy_from_slice(&0x20Bu16.to_le_bytes());
        f[opt + 16..][..4].copy_from_slice(&(TEXT + 0x10).to_le_bytes());
        f[opt + 24..][..8].copy_from_slice(&BASE.to_le_bytes());
        f[opt + 32..][..4].copy_from_slice(&0x1000u32.to_le_bytes());
        f[opt + 56..][..4].copy_from_slice(&IMAGE_SIZE.to_le_bytes());
        f[opt + 60..][..4].copy_from_slice(&0x400u32.to_le_bytes());
        f[opt + 68..][..2].copy_from_slice(&1u16.to_le_bytes());
        f[opt + 70..][..2].copy_from_slice(&0x4160u16.to_le_bytes());
        f[opt + 108..][..4].copy_from_slice(&16u32.to_le_bytes());
        let mut dir = |i: usize, rva: u32, size: u32| {
            f[opt + 112 + 8 * i..][..4].copy_from_slice(&rva.to_le_bytes());
            f[opt + 116 + 8 * i..][..4].copy_from_slice(&size.to_le_bytes());
        };
        dir(DIR_IMPORT, IMPORTS, (ndesc * IMPORT_DESC_SIZE) as u32);
        dir(DIR_LOAD_CONFIG, LOADCFG, 0x100);
        if self.relocs {
            dir(DIR_BASERELOC, RELOC, 12);
        }
        let sect = opt + 240;
        let mut section =
            |i: usize, name: &[u8], rva: u32, vsize: u32, raw: u32, rsize: u32, ch: u32| {
                let s = sect + i * SECTION_HEADER_SIZE;
                f[s..][..name.len()].copy_from_slice(name);
                for (o, v) in [(8, vsize), (12, rva), (16, rsize), (20, raw), (36, ch)] {
                    f[s + o..][..4].copy_from_slice(&v.to_le_bytes());
                }
            };
        // .text has less raw data than virtual size: the tail must be zeroed.
        section(
            0,
            b".text",
            TEXT,
            0x800,
            0x400,
            0x200,
            SCN_MEM_EXECUTE | SCN_MEM_READ,
        );
        section(
            1,
            b".data",
            DATA,
            0x1000,
            0x600,
            0x1000,
            SCN_MEM_READ | SCN_MEM_WRITE,
        );
        f.extend(std::iter::repeat_n(0xCC, 0x200));
        f.extend(data);
        f
    }
}

fn mapped(file: &[u8]) -> (Headers, Vec<u8>) {
    let pe = Pe::parse(file).unwrap();
    // Dirty memory: map_into must not rely on a zeroed buffer.
    let mut image = vec![0xAA; pe.headers().size_of_image as usize];
    pe.map_into(&mut image).unwrap();
    (pe.headers(), image)
}

fn kernel_resolver(dll: &[u8], sym: Symbol<'_>) -> Option<Bind> {
    match (dll, sym) {
        (b"ntoskrnl.exe", Symbol::Name(b"IoCreateDevice")) => {
            Some(Bind::Address(0xFFFF_F800_0000_1000))
        }
        (b"ntoskrnl.exe", Symbol::Name(b"IofCompleteRequest")) => {
            Some(Bind::Address(0xFFFF_F800_0000_2000))
        }
        _ => None,
    }
}

fn import_names(image: &[u8], h: &Headers) -> Vec<String> {
    let mut out = Vec::new();
    for_each_import(image, h, |dll, sym| {
        let dll = String::from_utf8_lossy(dll);
        out.push(match sym {
            Symbol::Name(n) => format!("{dll}!{}", String::from_utf8_lossy(n)),
            Symbol::Ordinal(o) => format!("{dll}!#{o}"),
        });
    })
    .unwrap();
    out
}

#[test]
fn headers_and_sections() {
    let file = Builder::new().build();
    let pe = Pe::parse(&file).unwrap();
    let h = pe.headers();
    assert_eq!(
        (h.machine, h.image_base, h.size_of_image),
        (MACHINE_AMD64, BASE, IMAGE_SIZE)
    );
    assert_eq!(
        (h.entry_rva, h.subsystem, h.section_alignment),
        (TEXT + 0x10, 1, 0x1000)
    );
    assert_eq!(h.dll_characteristics, 0x4160);
    let s: Vec<Section> = pe.sections().collect();
    assert_eq!(s.len(), 2);
    assert_eq!(&s[0].name[..5], b".text");
    assert_eq!((s[0].rva, s[0].mem_size()), (TEXT, 0x800));
    assert_eq!(s[1].characteristics, SCN_MEM_READ | SCN_MEM_WRITE);
    assert_eq!(h.dir(DIR_EXCEPTION), DataDir::default());
    assert_eq!(h.dir(99), DataDir::default());
}

/// An image in memory answers for its headers from its first page
/// alone, though the file's sections are not where a file has them.
#[test]
fn headers_are_read_from_a_mapped_image() {
    let (h, image) = mapped(&Builder::new().build());
    assert_eq!(image_headers(&image[..0x1000]), Ok(h));
    assert_eq!(image_headers(&image[..0x40]), Err(PeError::BadHeader));
    assert_eq!(image_headers(b"MZ"), Err(PeError::BadHeader));
}

#[test]
fn page_flags_follow_sections() {
    let file = Builder::new().build();
    let pe = Pe::parse(&file).unwrap();
    assert_eq!(
        pe.page_flags(0),
        Some(SCN_MEM_READ),
        "headers are read-only"
    );
    assert_eq!(pe.page_flags(TEXT), Some(SCN_MEM_EXECUTE | SCN_MEM_READ));
    assert_eq!(
        pe.page_flags(DATA + 0xFFF),
        Some(SCN_MEM_READ | SCN_MEM_WRITE)
    );
    assert_eq!(pe.page_flags(IMAGE_SIZE), None, "past the image");
}

#[test]
fn page_flags_are_read_from_a_mapped_image_s_headers() {
    let file = Builder::new().build();
    let pe = Pe::parse(&file).unwrap();
    let (_, image) = mapped(&file);
    for rva in (0..=IMAGE_SIZE).step_by(0x1000) {
        assert_eq!(image_page_flags(&image[..0x1000], rva), pe.page_flags(rva));
    }
    // Headers that end before the section table describe no page.
    assert_eq!(image_page_flags(&image[..0x100], TEXT), None);
    assert_eq!(image_page_flags(b"MZ", 0), None);
}

#[test]
fn machine_check() {
    let pe_file = Builder {
        machine: MACHINE_ARM64,
        ..Builder::new()
    }
    .build();
    let pe = Pe::parse(&pe_file).unwrap();
    assert_eq!(pe.check_machine(MACHINE_ARM64), Ok(()));
    assert_eq!(
        pe.check_machine(MACHINE_AMD64),
        Err(PeError::WrongMachine(MACHINE_ARM64))
    );
}

#[test]
fn map_zero_fills_and_places_sections() {
    let file = Builder::new().build();
    let (_, image) = mapped(&file);
    assert_eq!(&image[..2], b"MZ");
    assert!(
        image[0x400..TEXT as usize].iter().all(|&b| b == 0),
        "gap after headers"
    );
    assert!(image[TEXT as usize..][..0x200].iter().all(|&b| b == 0xCC));
    assert!(
        image[TEXT as usize + 0x200..DATA as usize]
            .iter()
            .all(|&b| b == 0),
        "bss tail"
    );
}

#[test]
fn map_rejects_small_buffer() {
    let file = Builder::new().build();
    let pe = Pe::parse(&file).unwrap();
    assert_eq!(
        pe.map_into(&mut [0u8; 0x1000]),
        Err(PeError::BufferTooSmall)
    );
}

#[test]
fn relocate_moves_pointers() {
    let file = Builder::new().build();
    let (h, mut image) = mapped(&file);
    let new_base = 0xFFFF_F880_0000_0000;
    relocate(&mut image, &h, new_base).unwrap();
    assert_eq!(
        u64_at(&image, PTR_SLOT as usize),
        Ok(new_base + u64::from(TEXT) + 0x10)
    );
    // The cookie is data, not a pointer: untouched.
    assert_eq!(u64_at(&image, COOKIE as usize), Ok(0x2B99_2DDF_A232));
}

#[test]
fn relocate_same_base_needs_no_table() {
    let file = Builder {
        relocs: false,
        ..Builder::new()
    }
    .build();
    let (h, mut image) = mapped(&file);
    assert_eq!(relocate(&mut image, &h, BASE), Ok(()));
    assert_eq!(
        relocate(&mut image, &h, BASE + 0x1000),
        Err(PeError::NotRelocatable)
    );
}

#[test]
fn relocate_rejects_unknown_type() {
    let file = Builder {
        reloc_type: 3,
        ..Builder::new()
    }
    .build();
    let (h, mut image) = mapped(&file);
    assert_eq!(
        relocate(&mut image, &h, BASE + 0x1000),
        Err(PeError::UnsupportedReloc(3))
    );
}

#[test]
fn imports_listed() {
    let b = Builder {
        imports: vec![
            ("ntoskrnl.exe", vec!["IoCreateDevice"]),
            ("HAL.dll", vec!["KeStallExecutionProcessor"]),
        ],
        ordinal: Some(7),
        ..Builder::new()
    };
    let (h, image) = mapped(&b.build());
    assert_eq!(
        import_names(&image, &h),
        [
            "ntoskrnl.exe!IoCreateDevice",
            "ntoskrnl.exe!#7",
            "HAL.dll!KeStallExecutionProcessor"
        ]
    );
}

#[test]
fn bind_fills_iat() {
    for lookup_table in [true, false] {
        let file = Builder {
            lookup_table,
            ..Builder::new()
        }
        .build();
        let (h, mut image) = mapped(&file);
        bind_imports(&mut image, &h, h.image_base, kernel_resolver).unwrap();
        let iat = u32_at(&image, IMPORTS as usize + 16).unwrap() as usize;
        assert_eq!(u64_at(&image, iat), Ok(0xFFFF_F800_0000_1000));
        assert_eq!(u64_at(&image, iat + 8), Ok(0xFFFF_F800_0000_2000));
        assert_eq!(u64_at(&image, iat + 16), Ok(0));
    }
}

/// An import the image has a routine of its own for keeps it: the slot
/// is left alone if it holds an address inside the image, and the
/// import is unresolved if it holds only the import's name.
#[test]
fn an_import_bound_to_the_images_own_routine_keeps_what_the_slot_holds() {
    let (h, mut image) = mapped(&Builder::new().build());
    let iat = u32_at(&image, IMPORTS as usize + 16).unwrap() as usize;
    let own = |_: &[u8], _: Symbol<'_>| Some(Bind::Own);
    // As linked, the slots hold the names: there is no routine to keep.
    let before = image.clone();
    assert!(matches!(
        bind_imports(&mut image, &h, h.image_base, own),
        Err(PeError::Unresolved { .. })
    ));
    assert_eq!(image, before);
    // With the image's own routines in them, they stay.
    let stub = h.image_base + 0x1000;
    put_u64(&mut image, iat, stub).unwrap();
    put_u64(&mut image, iat + 8, stub + 0x10).unwrap();
    bind_imports(&mut image, &h, h.image_base, own).unwrap();
    assert_eq!(u64_at(&image, iat), Ok(stub));
    assert_eq!(u64_at(&image, iat + 8), Ok(stub + 0x10));
    // An address outside the image is not the image's routine.
    put_u64(&mut image, iat, h.image_base + u64::from(h.size_of_image)).unwrap();
    assert!(matches!(
        bind_imports(&mut image, &h, h.image_base, own),
        Err(PeError::Unresolved { .. })
    ));
}

#[test]
fn an_image_with_no_import_directory_binds_and_lists_nothing() {
    let (mut h, mut image) = mapped(&Builder::new().build());
    h.dirs[DIR_IMPORT] = DataDir::default();
    let before = image.clone();
    // The descriptors are still in the image; without the directory
    // nothing leads to them, and nobody is asked to resolve anything.
    bind_imports(&mut image, &h, h.image_base, |_, _| {
        panic!("asked to resolve an import")
    })
    .unwrap();
    assert_eq!(image, before);
    for_each_import(&image, &h, |_, _| panic!("an import was listed")).unwrap();
}

#[test]
fn unresolved_import_is_named_and_nothing_is_bound() {
    let b = Builder {
        imports: vec![("ntoskrnl.exe", vec!["IoCreateDevice", "NoSuchRoutine"])],
        ..Builder::new()
    };
    let (h, mut image) = mapped(&b.build());
    let before = image.clone();
    let Err(PeError::Unresolved {
        dll_rva,
        name_rva,
        ordinal,
    }) = bind_imports(&mut image, &h, h.image_base, kernel_resolver)
    else {
        panic!("bind must fail");
    };
    assert_eq!(cstr_at(&image, dll_rva).unwrap(), b"ntoskrnl.exe");
    assert_eq!(cstr_at(&image, name_rva).unwrap(), b"NoSuchRoutine");
    assert_eq!(ordinal, 0);
    assert_eq!(
        image, before,
        "a failed bind must leave the image untouched"
    );
}

#[test]
fn unresolved_ordinal_is_reported() {
    let (h, mut image) = mapped(
        &Builder {
            ordinal: Some(42),
            ..Builder::new()
        }
        .build(),
    );
    let err = bind_imports(&mut image, &h, h.image_base, kernel_resolver).unwrap_err();
    assert!(matches!(
        err,
        PeError::Unresolved {
            name_rva: 0,
            ordinal: 42,
            ..
        }
    ));
}

#[test]
fn security_cookie_located_after_relocation() {
    let file = Builder::new().build();
    let (h, mut image) = mapped(&file);
    assert_eq!(security_cookie_rva(&image, &h, BASE), Some(COOKIE));
    let new_base = BASE + 0x10_0000;
    // The load-config pointer is not in this image's relocation table, so
    // patch it the way a real table would.
    put_u64(
        &mut image,
        LOADCFG as usize + LOAD_CONFIG_COOKIE,
        new_base + u64::from(COOKIE),
    )
    .unwrap();
    assert_eq!(security_cookie_rva(&image, &h, new_base), Some(COOKIE));
    assert_eq!(
        security_cookie_rva(&image, &h, new_base + 0x1000_0000),
        None
    );
}

#[test]
fn garbage_is_rejected_not_panicked_on() {
    assert_eq!(Pe::parse(b"").unwrap_err(), PeError::BadHeader);
    assert_eq!(
        Pe::parse(b"\x7fELF\0\0\0\0").unwrap_err(),
        PeError::BadHeader
    );
    let good = Builder::new().build();
    let mut pe32 = good.clone();
    pe32[0x98..0x9A].copy_from_slice(&0x10Bu16.to_le_bytes());
    assert_eq!(Pe::parse(&pe32).unwrap_err(), PeError::NotPe32Plus);
    // Every truncation and every single-byte corruption of the headers must
    // yield Ok or Err, never a panic or an out-of-bounds read.
    for len in 0..good.len().min(0x400) {
        let _ = Pe::parse(&good[..len]);
    }
    for i in 0..0x400 {
        let mut bad = good.clone();
        bad[i] ^= 0xFF;
        if let Ok(pe) = Pe::parse(&bad) {
            let mut image = vec![0; pe.headers().size_of_image as usize];
            if pe.map_into(&mut image).is_ok() {
                let h = pe.headers();
                let _ = relocate(&mut image, &h, BASE + 0x1000);
                let _ = bind_imports(&mut image, &h, h.image_base, kernel_resolver);
                let _ = security_cookie_rva(&image, &h, BASE);
            }
        }
    }
}

#[test]
fn section_outside_image_is_rejected() {
    let mut file = Builder::new().build();
    // .data virtual size: push it past size_of_image.
    let vsize = 0x84 + 20 + 240 + SECTION_HEADER_SIZE + 8;
    file[vsize..][..4].copy_from_slice(&0x10_0000u32.to_le_bytes());
    assert_eq!(Pe::parse(&file).unwrap_err(), PeError::OutOfBounds);
}

/// The entropy that mixes to `mixed`, before the top bits are dropped:
/// each step of the mixing is undone in turn.
fn entropy_for(mixed: u64) -> u64 {
    // `y = x ^ (x >> s)` gives back `x` by repeating the fold.
    fn unfold(y: u64, s: u32) -> u64 {
        (0..64 / s).fold(y, |x, _| y ^ (x >> s))
    }
    // The inverse of an odd number modulo 2^64, by Newton's iteration.
    let inverse = (0..6).fold(COOKIE_MULTIPLIER, |x, _| {
        x.wrapping_mul(2u64.wrapping_sub(COOKIE_MULTIPLIER.wrapping_mul(x)))
    });
    assert_eq!(COOKIE_MULTIPLIER.wrapping_mul(inverse), 1);
    unfold(unfold(mixed, 27).wrapping_mul(inverse), 30) ^ COOKIE_SEED
}

#[test]
fn security_cookies_fit_the_check_routine() {
    let mut seen = std::collections::HashSet::new();
    // Counter values as a loader would see them, and the extremes.
    let counters = (0..2000u64)
        .map(|n| 0x0000_0123_4567_89AB + n * 977)
        .chain([0, 1, u64::MAX, COOKIE_SEED, 1 << 63]);
    for entropy in counters {
        let cookie = security_cookie(entropy);
        assert_ne!(cookie, 0, "entropy {entropy:#x}");
        assert_ne!(cookie, DEFAULT_SECURITY_COOKIE, "entropy {entropy:#x}");
        assert_eq!(cookie >> 48, 0, "entropy {entropy:#x}");
        seen.insert(cookie);
    }
    // Nearby counter values do not give the same cookie.
    assert_eq!(seen.len(), 2005);
}

#[test]
fn security_cookie_mixing_is_the_documented_one() {
    // The steps undone: any 48-bit value can be reached, so the helper
    // below really does steer the mixing.
    assert_eq!(security_cookie(entropy_for(0x1234)), 0x1234);
    assert_eq!(
        security_cookie(entropy_for(0x0000_FFFF_FFFF_FFFF)),
        0x0000_FFFF_FFFF_FFFF
    );
    // The top 16 bits of the mix are dropped.
    assert_eq!(security_cookie(entropy_for(0xABCD_0000_0000_1234)), 0x1234);
}

#[test]
fn a_security_cookie_that_would_be_zero_or_the_default_is_replaced() {
    for forbidden in [0, DEFAULT_SECURITY_COOKIE] {
        // With the dropped bits clear, and with them set.
        for top in [0, 1 << 48, 0xFFFF << 48] {
            let cookie = security_cookie(entropy_for(forbidden | top));
            assert_eq!(cookie, FALLBACK_SECURITY_COOKIE);
        }
    }
    // The replacement is itself a cookie an image may have.
    assert_ne!(FALLBACK_SECURITY_COOKIE, 0);
    assert_ne!(FALLBACK_SECURITY_COOKIE, DEFAULT_SECURITY_COOKIE);
    assert_eq!(FALLBACK_SECURITY_COOKIE >> 48, 0);
    // One off from a forbidden value is fine as it is.
    assert_eq!(security_cookie(entropy_for(1)), 1);
    assert_eq!(
        security_cookie(entropy_for(DEFAULT_SECURITY_COOKIE + 1)),
        DEFAULT_SECURITY_COOKIE + 1
    );
}
