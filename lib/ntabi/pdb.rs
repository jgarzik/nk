//! Check the private layouts against Microsoft's public symbols.
//!
//! Structures the WDK does not declare (the processor block, the thread
//! object) are still read in line by Microsoft's own drivers, so NK gives
//! them Windows' layout. The authority is the type information in the
//! public PDB of the pinned kernel build, a fixture:
//! `target/fixtures/ntkrnlmp.x64.pdb`. As with the WDK tables, an absent
//! fixture is reported on stderr and never counted as agreement.
//!
//! There is no arm64 counterpart: no Windows 10 arm64 kernel or symbol
//! file is available to NK. See `doc/ABI.md`.

use crate::pcr;
use nk_pdb::{Layout, Pdb, Types};
use std::path::PathBuf;

/// The kernel's type records, or `None` (with a note) without the fixture.
fn kernel_types() -> Option<Types> {
    let path: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "target", "fixtures"]
        .iter()
        .collect();
    let Ok(file) = std::fs::read(path.join("ntkrnlmp.x64.pdb")) else {
        eprintln!("SKIP: no kernel symbols (target/fixtures/ntkrnlmp.x64.pdb)");
        return None;
    };
    let pdb = Pdb::parse(&file).expect("the kernel PDB");
    Some(pdb.types().expect("the kernel PDB's types"))
}

fn offset(layout: &Layout, ty: &str, field: &str) -> usize {
    let member = layout
        .member(field)
        .unwrap_or_else(|| panic!("{ty} has no field {field}"));
    assert_eq!(member.bits, None, "{ty}.{field} is a bit field");
    member.offset as usize
}

#[test]
fn processor_block_matches_the_kernel() {
    let Some(types) = kernel_types() else { return };
    let kpcr = types.layout("_KPCR").expect("_KPCR");
    let kprcb = types.layout("_KPRCB").expect("_KPRCB");
    let l = pcr::X86_64;
    assert_eq!(l.self_ptr, offset(&kpcr, "_KPCR", "Self"));
    assert_eq!(l.current_prcb, offset(&kpcr, "_KPCR", "CurrentPrcb"));
    assert_eq!(l.prcb, offset(&kpcr, "_KPCR", "Prcb"));
    assert_eq!(
        l.current_thread,
        l.prcb + offset(&kprcb, "_KPRCB", "CurrentThread"),
        "what the WDK's inlined KeGetCurrentThread reads"
    );
    assert_eq!(l.number, l.prcb + offset(&kprcb, "_KPRCB", "Number"));
    assert_eq!(
        l.legacy_number,
        Some(l.prcb + offset(&kprcb, "_KPRCB", "LegacyNumber"))
    );
    // The control region ends with the processor block.
    assert_eq!(l.size, kpcr.size as usize);
    assert_eq!(kpcr.size as usize, l.prcb + kprcb.size as usize);
    eprintln!(
        "x64: processor block matches the kernel symbols (KPCR {:#x} bytes)",
        kpcr.size
    );
}
