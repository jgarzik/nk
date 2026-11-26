//! Print what the NK loader sees in a PE image, one fact per line.
//!
//! The output is line-oriented so scripts can read it:
//!
//! ```text
//! machine x86_64
//! image_base 0x1c0000000
//! section .text rva=0x1000 size=0x200 r-x
//! import ntoskrnl.exe IoCreateDevice
//! export 12 ExAllocatePool rva=0x2000
//! export 13 - forward=HAL.#4
//! ```
//!
//! It goes through `nk-pe`, the same code the kernel loads drivers with,
//! so the ledger and the kernel cannot disagree about a binary.

use nk_pe::exports::{Export, Exports};
use nk_pe::{Pe, Symbol, for_each_import};
use std::collections::HashMap;
use std::process::ExitCode;

fn machine(m: u16) -> String {
    match m {
        nk_pe::MACHINE_AMD64 => "x86_64".into(),
        nk_pe::MACHINE_ARM64 => "aarch64".into(),
        other => format!("{other:#06x}"),
    }
}

fn dump(path: &str) -> Result<(), String> {
    let file = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let pe = Pe::parse(&file).map_err(|e| format!("{path}: {e:?}"))?;
    let h = pe.headers();
    println!("machine {}", machine(h.machine));
    println!("timestamp {:#x}", h.timestamp);
    println!("image_base {:#x}", h.image_base);
    println!("size_of_image {:#x}", h.size_of_image);
    println!("entry_rva {:#x}", h.entry_rva);
    println!("subsystem {}", h.subsystem);
    for s in pe.sections() {
        let name = String::from_utf8_lossy(&s.name);
        let flag = |bit, c| if s.characteristics & bit != 0 { c } else { '-' };
        println!(
            "section {} rva={:#x} size={:#x} {}{}{}{}",
            name.trim_end_matches('\0'),
            s.rva,
            s.mem_size(),
            flag(nk_pe::SCN_MEM_READ, 'r'),
            flag(nk_pe::SCN_MEM_WRITE, 'w'),
            flag(nk_pe::SCN_MEM_EXECUTE, 'x'),
            flag(nk_pe::SCN_MEM_DISCARDABLE, 'd'),
        );
    }
    let mut image = vec![0; h.size_of_image as usize];
    pe.map_into(&mut image)
        .map_err(|e| format!("{path}: map: {e:?}"))?;
    for (name, index) in [
        ("exception", nk_pe::DIR_EXCEPTION),
        ("reloc", nk_pe::DIR_BASERELOC),
    ] {
        println!(
            "dir {name} rva={:#x} size={:#x}",
            h.dir(index).rva,
            h.dir(index).size
        );
    }
    if let Some(rva) = nk_pe::security_cookie_rva(&image, &h, h.image_base) {
        println!("security_cookie_rva {rva:#x}");
    }
    for_each_import(&image, &h, |dll, sym| {
        let dll = String::from_utf8_lossy(dll);
        match sym {
            Symbol::Name(n) => println!("import {dll} {}", String::from_utf8_lossy(n)),
            Symbol::Ordinal(o) => println!("import {dll} #{o}"),
        }
    })
    .map_err(|e| format!("{path}: imports: {e:?}"))?;
    exports(&image, &h).map_err(|e| format!("{path}: exports: {e:?}"))
}

/// One line per export, by ordinal: its name (`-` if it has none) and
/// where it leads.
fn exports(image: &[u8], h: &nk_pe::Headers) -> Result<(), nk_pe::PeError> {
    let Some(exports) = Exports::parse(image, h.dir(nk_pe::DIR_EXPORT))? else {
        return Ok(());
    };
    let mut names = HashMap::new();
    for index in 0..exports.names() {
        let (name, ordinal) = exports.name(index)?;
        names.insert(ordinal, String::from_utf8_lossy(name).into_owned());
    }
    for ordinal in exports.ordinals() {
        let name = names.get(&ordinal).map_or("-", String::as_str);
        match exports.by_ordinal(ordinal)? {
            Some(Export::Rva(rva)) => println!("export {ordinal} {name} rva={rva:#x}"),
            Some(Export::Forward(to)) => {
                println!(
                    "export {ordinal} {name} forward={}",
                    String::from_utf8_lossy(to)
                )
            }
            None => {}
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 1 {
        eprintln!("usage: peinfo <image>");
        return ExitCode::from(2);
    }
    match dump(&args[0]) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("peinfo: {e}");
            ExitCode::FAILURE
        }
    }
}
