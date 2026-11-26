//! Export drivers: a driver that imports from another image, the
//! library it imports from, and what the loader keeps of the two.
//!
//! The library is nk-fixtures' `nkc-lib.sys`; `nkc-libuser.sys` imports
//! from it by name, by ordinal and a variable, and `nkc-libbad.sys` a
//! name it does not have. What they do on Windows is in
//! `oracle/nkc-lib*.txt`.

use super::resources;
use crate::io::file;
use crate::io::service::{self, ServiceError};
use crate::ldr::{self, LoadError, TestImporter};
use crate::mm::map;
use crate::test::{Group, Report};
use alloc::vec::Vec;
use nk_bootinfo::BootInfo;
use nk_ntabi::status::*;
use nk_pe::{DataDir, Symbol};

pub static GROUP: Group = Group {
    names: &[
        "ldr.lib.bind",
        "ldr.lib.counts",
        "ldr.lib.refused",
        "ldr.lib.as-service",
        "ldr.lib.absent",
        "ldr.lib.forwarder",
        "ldr.lib.no-memory",
    ],
    run,
    manual: false,
};

const LIBRARY: &str = "nkc-lib.sys";
const USER: &str = "nkc-libuser";
const BAD: &str = "nkc-libbad";
/// `NKC_IOCTL_RUN`: the importer logs what it got from the library.
const RUN: u32 = 0x0022_2000;
/// What the importer logs (`nkc-libuser.c`), ending with `NKC_END`: the
/// seventh value counts the calls of the library's `DllInitialize`,
/// `DllUnload` and entry point, a byte each.
const VALUES: [u32; 10] = [
    5,
    0x4F52_4437,
    0x4441_5441,
    0x4441_5441,
    0x4E4B_0001,
    0x4E4B_0002,
    0x4441_5441,
    1,
    0,
    0x4E4B_4321,
];

fn start(name: &str) -> Result<(), ServiceError> {
    service::create(name, &alloc::format!("{name}.sys"))?;
    service::start(name).map(|_| ())
}

/// The values the importer logs when asked.
fn values() -> Result<Vec<u32>, &'static str> {
    let handle = super::open("\\Device\\NkcLibUser").map_err(|_| "the importer's device")?;
    let mut output = [0u8; 64];
    let result = file::device_control(handle, RUN, &[], &mut output);
    file::close(handle);
    let result = result.map_err(|_| "the importer did not complete the request")?;
    if result.status != STATUS_SUCCESS {
        return Err("the importer failed the request");
    }
    Ok(output[..result.information]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|word| u32::from_le_bytes(*word))
        .collect())
}

/// How many importers the library has, if it is loaded as a library.
fn importers() -> Option<u32> {
    ldr::module_named(LIBRARY)
        .filter(|module| module.library)
        .map(|module| module.references)
}

/// An importer loads its library with it, is bound to the library's
/// exports, and takes the library with it when it goes.
fn bind() -> Result<(), &'static str> {
    let before = resources();
    if ldr::module_named(LIBRARY).is_some() {
        return Err("the library is loaded before anything imports from it");
    }
    start(USER).map_err(|_| "the importer did not load")?;
    let loaded = ldr::module_named(LIBRARY);
    let logged = values();
    service::stop(USER)?;
    let Some(library) = loaded else {
        return Err("the importer's library is not in the table of images");
    };
    if !library.library || library.references != 1 || library.exports.size == 0 {
        return Err("the library is not listed as a library with one importer");
    }
    if logged? != VALUES {
        return Err("the importer did not get from the library what it gets on Windows");
    }
    if ldr::module_named(LIBRARY).is_some() {
        return Err("the library outlived its only importer");
    }
    if resources() != before {
        return Err("loading and unloading an importer and its library left something behind");
    }
    Ok(())
}

/// A library stays for as long as one importer does, is initialised
/// once per load, and is loaded afresh the next time.
fn counts() -> Result<(), &'static str> {
    let before = resources();
    start(USER).map_err(|_| "the importer did not load")?;
    // A second importer of the same library.
    let second = TestImporter::of(LIBRARY).map_err(|_| "a second importer was refused")?;
    let with_two = importers();
    service::stop(USER)?;
    let with_one = importers();
    // The first importer again: the library is there, and is not
    // initialised a second time.
    let again = start(USER).map(|()| (importers(), values()));
    drop(second);
    let without_second = importers();
    let stopped = service::stop(USER);
    let (with_two_again, logged) = again.map_err(|_| "the importer did not load again")?;
    stopped?;
    if with_two != Some(2) || with_two_again != Some(2) {
        return Err("a library with two importers does not count two");
    }
    if with_one != Some(1) {
        return Err("a library was unloaded while an importer was left");
    }
    if logged? != VALUES {
        return Err("a library that stayed loaded was initialised again");
    }
    if without_second != Some(1) || importers().is_some() {
        return Err("a library did not go with its last importer");
    }
    // Loaded afresh, its counters start over (`VALUES` again).
    start(USER).map_err(|_| "the importer did not load a third time")?;
    let fresh = values();
    service::stop(USER)?;
    if fresh? != VALUES {
        return Err("a library loaded afresh did not start over");
    }
    if resources() != before {
        return Err("importers coming and going left something behind");
    }
    Ok(())
}

/// A driver that imports a name its library lacks is refused with
/// Windows' status, and its library goes with it, unless another
/// importer holds it.
fn refused() -> Result<(), &'static str> {
    let before = resources();
    let attempt = || match start(BAD) {
        Err(error) => {
            let named = matches!(
                &error,
                ServiceError::Driver(crate::io::driver::DriverError::Load(
                    LoadError::Unresolved { module, symbol },
                )) if module == LIBRARY && symbol == "NkcLibAbsent"
            );
            kprintln!("ldr: nkc-libbad refused: {error:?}");
            Ok((error.status(), named))
        }
        Ok(()) => {
            let _ = service::stop(BAD);
            Err("a driver importing a name its library lacks was loaded")
        }
    };
    let alone = attempt()?;
    let left = importers();
    // With the library loaded for another importer, it stays.
    start(USER).map_err(|_| "the importer did not load")?;
    let beside = attempt();
    let kept = importers();
    let logged = values();
    service::stop(USER)?;
    if alone != (STATUS_DRIVER_ENTRYPOINT_NOT_FOUND, true) || beside? != alone {
        return Err("the refusal is not STATUS_DRIVER_ENTRYPOINT_NOT_FOUND naming the import");
    }
    if left.is_some() {
        return Err("the library of a refused importer was left loaded");
    }
    if kept != Some(1) || logged? != VALUES {
        return Err("a refused importer disturbed the library another importer uses");
    }
    if resources() != before {
        return Err("a refused importer left something behind");
    }
    Ok(())
}

/// A library started as a service runs its entry point, which refuses;
/// a driver started twice is refused the second time. Windows' statuses.
fn as_service() -> Result<(), &'static str> {
    let before = resources();
    let library = start("nkc-lib").map_err(|error| error.status());
    start(USER).map_err(|_| "the importer did not load")?;
    let twice = service::start(USER).map(|_| ()).map_err(|e| e.status());
    // The library is loaded now, for its importer: not as a driver too.
    let both = start("nkc-lib").map_err(|error| error.status());
    service::stop(USER)?;
    if library != Err(STATUS_NOT_SUPPORTED) || ldr::module_named(LIBRARY).is_some() {
        return Err("a library started as a service did not fail with its entry point's status");
    }
    if twice != Err(STATUS_IMAGE_ALREADY_LOADED) || both != Err(STATUS_IMAGE_ALREADY_LOADED) {
        return Err("an image loaded already was not refused as such");
    }
    if resources() != before {
        return Err("refused starts left something behind");
    }
    Ok(())
}

/// A library that is nowhere: Windows' status for its importer.
fn absent() -> Result<(), &'static str> {
    let before = resources();
    let status = match TestImporter::of("nk-no-such-library.sys") {
        Err(error @ LoadError::NoLibrary { .. }) => error.status(),
        Err(_) => return Err("a missing library was refused for another reason"),
        Ok(_) => return Err("a library that is not among the boot files was loaded"),
    };
    if status != STATUS_OBJECT_NAME_NOT_FOUND {
        return Err("a missing library is not STATUS_OBJECT_NAME_NOT_FOUND");
    }
    if resources() != before {
        return Err("a missing library left something behind");
    }
    Ok(())
}

/// Importing from a library takes memory at several points: to count
/// the importer, to list the library, to tell it its name. Whichever
/// of them the pool refuses, the import fails for lack of memory and
/// the library is not left loaded with nobody to unload it.
fn no_memory() -> Result<(), &'static str> {
    let before = resources();
    // How many allocations an import takes when all are granted.
    crate::rt::watch(0);
    let importer = TestImporter::of(LIBRARY);
    let granted = crate::rt::unwatch();
    drop(importer.map_err(|_| "the library could not be imported from")?);
    if granted == 0 || ldr::module_named(LIBRARY).is_some() {
        return Err("an import allocated nothing, or its library outlived it");
    }
    // The last first: the one made once the library is loaded.
    for refuse in (1..=granted).rev() {
        crate::rt::watch(refuse);
        let importer = TestImporter::of(LIBRARY);
        crate::rt::unwatch();
        let left = ldr::module_named(LIBRARY).is_some();
        match importer {
            Err(LoadError::NoMemory) => {}
            Err(_) => return Err("an import refused memory failed for another reason"),
            Ok(_) => return Err("an import went through without the memory it asked for"),
        }
        if left {
            return Err("a library whose importer was not counted for lack of memory stays loaded");
        }
    }
    if resources() != before {
        return Err("imports that failed for lack of memory left something behind");
    }
    Ok(())
}

/// The export directory of an image that exists only in this test, at
/// RVA `DIR`: `addresses` from ordinal `BASE`, the `named` exports
/// (name and slot, sorted by name), and forwarders in the slots
/// `forwards` names.
const DIR: u32 = 0x40;
const BASE: u32 = 5;

fn export_directory(
    addresses: &[u32],
    named: &[(&str, u16)],
    forwards: &[(usize, &str)],
) -> (Vec<u8>, DataDir) {
    let mut image = alloc::vec![0u8; 0x400];
    let put = |image: &mut [u8], at: u32, value: u32| {
        image[at as usize..at as usize + 4].copy_from_slice(&value.to_le_bytes());
    };
    let address_table = DIR + 40;
    let name_table = address_table + 4 * addresses.len() as u32;
    let ordinal_table = name_table + 4 * named.len() as u32;
    let mut end = ordinal_table + 2 * named.len() as u32;
    let mut string = |image: &mut [u8], text: &str| {
        let at = end;
        image[at as usize..at as usize + text.len()].copy_from_slice(text.as_bytes());
        end += text.len() as u32 + 1;
        at
    };
    let mut addresses = addresses.to_vec();
    for (slot, target) in forwards {
        addresses[*slot] = string(&mut image, target);
    }
    for (i, (name, slot)) in named.iter().enumerate() {
        let at = string(&mut image, name);
        put(&mut image, name_table + 4 * i as u32, at);
        let entry = (ordinal_table + 2 * i as u32) as usize;
        image[entry..entry + 2].copy_from_slice(&slot.to_le_bytes());
    }
    for (i, address) in addresses.iter().enumerate() {
        put(&mut image, address_table + 4 * i as u32, *address);
    }
    for (field, value) in [
        (16, BASE),
        (20, addresses.len() as u32),
        (24, named.len() as u32),
        (28, address_table),
        (32, name_table),
        (36, ordinal_table),
    ] {
        put(&mut image, DIR + field, value);
    }
    let size = end - DIR;
    (image, DataDir { rva: DIR, size })
}

/// Imports are bound through an export directory by name and by
/// ordinal, and a forwarder leads to the export it names, in the
/// kernel or in a library; one that leads round in a circle, or
/// nowhere, binds nothing.
fn forwarder() -> Result<(), &'static str> {
    let before = resources();
    // Slots: 0 Alpha, 1 a gap, 2 by ordinal only, then forwarders. The
    // addresses lie outside the directory, as code does.
    let (image, exports) = export_directory(
        &[0x1110, 0, 0x2220, 0, 0, 0, 0, 0],
        &[
            ("Alpha", 0),
            ("ByOrdinal", 4),
            ("Loop", 5),
            ("NoSuchName", 7),
            ("Nowhere", 6),
            ("ToKernel", 3),
        ],
        &[
            (3, "NTOSKRNL.KeSetEvent"),
            (4, "nkt-forward.#7"),
            (5, "nkt-forward.Loop"),
            (6, "nk-no-such-library.Alpha"),
            (7, "ntoskrnl.NoSuchRoutineInAnyKernel"),
        ],
    );
    let pages = image.len().div_ceil(crate::mm::PAGE_SIZE);
    let base = map::alloc_va(pages).ok_or("no address space")?;
    let symbols = [
        Symbol::Name(b"Alpha"),
        Symbol::Ordinal(BASE as u16 + 2),
        Symbol::Name(b"ToKernel"),
        Symbol::Name(b"ByOrdinal"),
        // What binds nothing: a gap, an ordinal counted from zero or
        // past the table, a name not exported, forwarders that end
        // nowhere.
        Symbol::Ordinal(BASE as u16 + 1),
        Symbol::Ordinal(2),
        Symbol::Ordinal(BASE as u16 + 8),
        Symbol::Name(b"Beta"),
        Symbol::Name(b"Loop"),
        Symbol::Name(b"Nowhere"),
        Symbol::Name(b"NoSuchName"),
    ];
    // SAFETY: address space reserved above for nothing else.
    let bound = unsafe { ldr::bind_for_test("nkt-forward.sys", base, &image, exports, &symbols) };
    map::free_va(base, pages);
    let bound = bound.ok_or("the test's image could not be entered")?;
    let kernel = crate::export::resolve(b"ntoskrnl.exe", b"KeSetEvent");
    let expected = [
        Some(base + 0x1110),
        Some(base + 0x2220),
        kernel,
        Some(base + 0x2220),
    ];
    if kernel.is_none() || bound[..4] != expected {
        return Err("an import was not bound to the export it names, or its forwarder's");
    }
    if bound[4..].iter().any(Option::is_some) {
        return Err("an import that names no export was bound");
    }
    drop(bound);
    drop(image);
    if resources() != before {
        return Err("binding left something behind");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("ldr.lib.absent", absent);
    r.check("ldr.lib.forwarder", forwarder);
    if [LIBRARY, "nkc-libuser.sys", "nkc-libbad.sys"]
        .iter()
        .any(|file| ldr::boot_file(file).is_none())
    {
        return r.skip_rest(format_args!("modules nkc-lib*.sys not provided"));
    }
    r.check("ldr.lib.bind", bind);
    r.check("ldr.lib.counts", counts);
    r.check("ldr.lib.refused", refused);
    r.check("ldr.lib.as-service", as_service);
    r.check("ldr.lib.no-memory", no_memory);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
