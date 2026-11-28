//! Print structure layouts from a Microsoft PDB, one fact per line.
//!
//! ```text
//! pdbinfo <file.pdb>                 identity, then the name of every type
//! pdbinfo <file.pdb> <type>...       the layout of each named type
//! ```
//!
//! Layout lines use the form of the WDK-built ABI tables, so the same
//! comparison code reads both (`lib/ntabi/probe.rs`):
//!
//! ```text
//! sizeof _KTHREAD 1072
//! offsetof _KTHREAD Header 0
//! bits _KTHREAD Alertable 116 4 1      (offset, first bit, bit count)
//! ```
//!
//! A name that is an enumeration prints its values instead:
//!
//! ```text
//! enum _POOL_TYPE NonPagedPool 0
//! ```
//!
//! It goes through `nk-pdb`, so NK has one reading of the format.

use nk_pdb::Pdb;
use std::process::ExitCode;

fn run(args: &[String]) -> Result<(), String> {
    let [path, types @ ..] = args else {
        return Err("usage: pdbinfo <file.pdb> [type...]".into());
    };
    let file = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
    let pdb = Pdb::parse(&file).map_err(|e| format!("{path}: {e:?}"))?;
    let all = pdb.types().map_err(|e| format!("{path}: types: {e:?}"))?;
    if types.is_empty() {
        let info = pdb.info().map_err(|e| format!("{path}: info: {e:?}"))?;
        // As a PE image's debug directory spells it: the first three
        // fields little-endian, the rest in file order.
        let g = info.guid;
        let guid: String = [g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6]]
            .iter()
            .chain(&g[8..])
            .map(|b| format!("{b:02X}"))
            .collect();
        println!("guid {guid}");
        println!("age {}", info.age);
        for name in all.names().map_err(|e| format!("{path}: types: {e:?}"))? {
            println!("type {name}");
        }
        return Ok(());
    }
    for name in types {
        if let Ok(values) = all.enumerators(name) {
            for (value_name, value) in values {
                println!("enum {name} {value_name} {value}");
            }
            continue;
        }
        let layout = all
            .layout(name)
            .map_err(|e| format!("{path}: {name}: {e:?}"))?;
        println!("sizeof {name} {}", layout.size);
        for m in &layout.members {
            match m.bits {
                None => println!("offsetof {name} {} {}", m.name, m.offset),
                Some((first, count)) => {
                    println!("bits {name} {} {} {first} {count}", m.name, m.offset);
                }
            }
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("pdbinfo: {e}");
            ExitCode::FAILURE
        }
    }
}
