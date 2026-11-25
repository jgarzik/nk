//! Sweeps over real drivers: every function of every image under
//! `target/fixtures/` (`make fixtures`) and of the corpus of Microsoft's
//! inbox binaries (`$NK_CACHE/corpus`, default `~/.cache/nk/corpus`;
//! `make corpus`). Without the files a test prints a SKIP note and passes.
//!
//! Three kinds of check:
//! - every unwind record parses, and the totals equal those a separate
//!   Python prototype counted over the same images;
//! - a prolog (and, on arm64, an epilog) is run forwards here, and from
//!   every instruction boundary the unwind must land on the same caller;
//! - where two descriptions of the same code exist, they must agree: the
//!   x64 epilog table against the epilog's instructions, the arm64
//!   unwind codes against the instructions they stand for.

use crate::{Place, arm64, x64};
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;

const MACHINE_AMD64: u16 = 0x8664;
const MACHINE_ARM64: u16 = 0xAA64;

struct Image {
    name: String,
    bytes: Vec<u8>,
    dir_rva: u32,
    dir_size: u32,
}

/// Every image for `machine` among the fixtures and, if asked, the
/// corpus, mapped as a loader would.
fn images(machine: u16, corpus: bool) -> Vec<Image> {
    let fixtures: PathBuf = [env!("CARGO_MANIFEST_DIR"), "..", "..", "target", "fixtures"]
        .iter()
        .collect();
    let cache = match std::env::var_os("NK_CACHE") {
        Some(dir) => Some(PathBuf::from(dir)),
        None => std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache").join("nk")),
    };
    let corpus = cache.filter(|_| corpus).map(|c| c.join("corpus"));
    let mut out = Vec::new();
    for dir in [Some(fixtures), corpus].into_iter().flatten() {
        let files = std::fs::read_dir(&dir).into_iter().flatten().flatten();
        for path in files.map(|e| e.path()) {
            let Some(file) = std::fs::read(&path).ok() else {
                continue;
            };
            let Ok(pe) = nk_pe::Pe::parse(&file) else {
                continue;
            };
            let h = pe.headers();
            if h.machine != machine {
                continue;
            }
            let mut bytes = vec![0; h.size_of_image as usize];
            pe.map_into(&mut bytes).expect("a fixture maps");
            let dir = h.dir(nk_pe::DIR_EXCEPTION);
            out.push(Image {
                name: path.file_name().unwrap().to_string_lossy().into_owned(),
                bytes,
                dir_rva: dir.rva,
                dir_size: dir.size,
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    if out.is_empty() {
        eprintln!("SKIP: no drivers for machine {machine:#x} (make fixtures)");
    }
    out
}

/// The simulated stack: every address is readable and holds a value
/// derived from the address, so a wrong slot gives a wrong value.
fn mem(addr: u64) -> u64 {
    addr.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(23) ^ 0x5DEE_CE66
}

/// The caller's stack pointer in every simulation.
const CALLER: u64 = 0xFFFF_9000_0080_0000;

// ------------------------------------------------------------------ x64

/// What the prototype (`unwind_survey.py`) counted, per image: `.pdata`
/// entries, distinct unwind records, version 1 and 2 records, records
/// with EHANDLER, UHANDLER, CHAININFO, then codes: PUSH_NONVOL,
/// ALLOC_LARGE, ALLOC_SMALL, SET_FPREG, SAVE_NONVOL, SAVE_XMM128, and
/// pairs of EPILOG slots.
const X64_SURVEY: &[(&str, [usize; 14])] = &[
    (
        "npfs.sys",
        [225, 198, 6, 192, 12, 5, 99, 295, 14, 77, 0, 253, 0, 94],
    ),
    (
        "msfs.sys",
        [133, 102, 5, 97, 8, 2, 54, 99, 3, 39, 0, 118, 0, 43],
    ),
    (
        "msrpc.sys",
        [
            1403, 949, 6, 943, 62, 57, 375, 1344, 46, 521, 0, 995, 1, 567,
        ],
    ),
    (
        "wpprecorder.sys",
        [147, 110, 5, 105, 8, 7, 63, 59, 7, 35, 0, 137, 0, 47],
    ),
    ("wmilib.sys", [20, 16, 4, 12, 0, 0, 7, 9, 1, 4, 0, 18, 0, 5]),
    (
        "ksecdd.sys",
        [425, 280, 6, 274, 37, 28, 82, 402, 41, 149, 0, 232, 2, 200],
    ),
    (
        "cng.sys",
        [
            1597, 1094, 7, 1087, 198, 199, 335, 2546, 195, 528, 0, 1174, 101, 751,
        ],
    ),
    (
        "fastfat.sys",
        [
            827, 421, 6, 415, 126, 209, 6, 1417, 113, 288, 0, 472, 6, 407,
        ],
    ),
    (
        "ntfs.sys",
        [
            5015, 4304, 9, 4295, 572, 1102, 1046, 9249, 795, 2419, 8, 2944, 3, 3256,
        ],
    ),
    (
        "win32kfull.sys",
        [
            11340, 7781, 6, 7775, 1600, 1048, 2626, 13638, 1146, 3881, 0, 7287, 171, 5153,
        ],
    ),
    ("sioctl.x64.sys", [8, 6, 1, 5, 1, 0, 0, 8, 0, 5, 0, 3, 0, 5]),
    (
        "cancel.x64.sys",
        [53, 40, 2, 38, 3, 3, 0, 98, 2, 33, 0, 45, 0, 37],
    ),
    ("null.x64.sys", [15, 11, 4, 7, 0, 0, 3, 4, 0, 4, 0, 2, 0, 4]),
];

fn x64_entries(img: &Image) -> Vec<x64::RuntimeFunction> {
    let n = img.dir_size as usize / x64::ENTRY_SIZE;
    (0..n)
        .map(|i| x64::entry(&img.bytes, img.dir_rva, i).unwrap())
        .collect()
}

#[test]
fn x64_records_parse_and_total_as_surveyed() {
    let (mut functions, mut matched) = (0, 0);
    for img in images(MACHINE_AMD64, true) {
        let entries = x64_entries(&img);
        functions += entries.len();
        let mut seen = HashSet::new();
        let mut t = [0usize; 14];
        t[0] = entries.len();
        for (i, f) in entries.iter().enumerate() {
            assert!(f.begin < f.end, "{}: empty entry {i}", img.name);
            assert!(
                i == 0 || entries[i - 1].end <= f.begin,
                "{}: entries overlap at {i}",
                img.name
            );
            for rva in [f.begin, f.end - 1] {
                let found = x64::lookup(&img.bytes, img.dir_rva, img.dir_size, rva);
                assert_eq!(found, Ok(Some(*f)), "{}: lookup {rva:#x}", img.name);
            }
            // The record and every record it chains to.
            let mut rva = f.unwind;
            while seen.insert(rva) {
                let info = x64::UnwindInfo::parse(&img.bytes, rva)
                    .unwrap_or_else(|e| panic!("{}: record {rva:#x}: {e:?}", img.name));
                t[1] += 1;
                t[1 + info.version as usize] += 1;
                for (bit, slot) in [
                    (x64::UNW_FLAG_EHANDLER, 4),
                    (x64::UNW_FLAG_UHANDLER, 5),
                    (x64::UNW_FLAG_CHAININFO, 6),
                ] {
                    t[slot] += usize::from(info.flags & bit != 0);
                }
                let mut epilog_slots = 0;
                for (n, c) in info.codes().enumerate() {
                    match c.opcode {
                        x64::UWOP_PUSH_NONVOL => t[7] += 1,
                        x64::UWOP_ALLOC_LARGE => t[8] += 1,
                        x64::UWOP_ALLOC_SMALL => t[9] += 1,
                        x64::UWOP_SET_FPREG => t[10] += 1,
                        x64::UWOP_SAVE_NONVOL => t[11] += 1,
                        x64::UWOP_SAVE_XMM128 => t[12] += 1,
                        x64::UWOP_EPILOG => {
                            // The table leads the array.
                            assert_eq!(n, epilog_slots, "{}: record {rva:#x}", img.name);
                            epilog_slots += 1;
                        }
                        _ => {}
                    }
                }
                assert_eq!(epilog_slots % 2, 0, "{}: record {rva:#x}", img.name);
                t[13] += epilog_slots / 2;
                if let x64::Tail::Chained(parent) = info.tail {
                    rva = parent.unwind;
                }
            }
        }
        if let Some((_, want)) = X64_SURVEY.iter().find(|(name, _)| *name == img.name) {
            assert_eq!(&t, want, "{}", img.name);
            matched += 1;
        }
    }
    eprintln!("x64 parse sweep: {functions} functions, {matched} images match the survey");
    assert!(functions == 0 || matched >= 3);
}

/// Registers and the stack as a prolog run forwards leaves them.
struct X64Frame {
    regs: x64::Regs,
    /// Where each integer register's caller value was stored.
    gpr_at: [Option<u64>; 16],
    xmm_at: [Option<u64>; 10],
    fp_set: bool,
}

/// The unwind records of `f`, its own first. `None` for a chain this
/// simulation does not model (a machine frame).
fn x64_chain<'a>(image: &'a [u8], f: &x64::RuntimeFunction) -> Option<Vec<x64::UnwindInfo<'a>>> {
    let mut chain = vec![x64::UnwindInfo::parse(image, f.unwind).unwrap()];
    while let x64::Tail::Chained(parent) = chain.last().unwrap().tail {
        chain.push(x64::UnwindInfo::parse(image, parent.unwind).unwrap());
    }
    let machine_frame = |c: x64::Code| matches!(c.op, x64::Op::PushMachframe { .. });
    (!chain.iter().any(|info| info.codes().any(machine_frame))).then_some(chain)
}

/// Run the prolog described by `chain` from the caller's `call`: the
/// parents' whole prologs, then the function's own up to prolog offset
/// `limit` (all of it for `None`).
fn x64_run_prolog(chain: &[x64::UnwindInfo<'_>], limit: Option<u32>) -> X64Frame {
    let mut regs = x64::Regs {
        gpr: core::array::from_fn(|i| 0x1111_0000 + i as u64),
        rip: 0,
        xmm: core::array::from_fn(|i| 0x2222_0000 + i as u128),
    };
    let (frame_reg, frame_offset) = (
        chain[0].frame_reg as usize,
        u64::from(chain[0].frame_offset),
    );
    let mut rsp = CALLER - 8;
    let mut fp_set = false;
    // Saves in the order they ran: a push knows its address, a move is
    // relative to the finished frame.
    let mut saves = Vec::new();
    for (depth, info) in chain.iter().enumerate().rev() {
        let codes: Vec<x64::Code> = info.codes().collect();
        for c in codes.iter().rev() {
            if depth == 0 && limit.is_some_and(|l| u32::from(c.offset) > l) {
                continue;
            }
            match c.op {
                x64::Op::PushNonvol(reg) => {
                    rsp -= 8;
                    saves.push((false, reg, Ok(rsp)));
                }
                x64::Op::Alloc(n) => rsp -= u64::from(n),
                x64::Op::SetFpreg => {
                    regs.gpr[frame_reg] = rsp + frame_offset;
                    fp_set = true;
                }
                x64::Op::SaveNonvol { reg, offset } => saves.push((false, reg, Err(offset))),
                x64::Op::SaveXmm128 { reg, offset } => saves.push((true, reg, Err(offset))),
                x64::Op::PushMachframe { .. } | x64::Op::Epilog { .. } => {}
            }
        }
    }
    regs.gpr[x64::RSP] = rsp;
    let frame = if fp_set {
        regs.gpr[frame_reg] - frame_offset
    } else {
        rsp
    };
    let (mut gpr_at, mut xmm_at) = ([None; 16], [None; 10]);
    for (is_xmm, reg, place) in saves {
        let addr = place.unwrap_or_else(|offset| frame + u64::from(offset));
        // The first save of a register holds the caller's value.
        if is_xmm {
            xmm_at[reg as usize - 6].get_or_insert(addr);
        } else {
            gpr_at[reg as usize].get_or_insert(addr);
        }
    }
    X64Frame {
        regs,
        gpr_at,
        xmm_at,
        fp_set,
    }
}

/// Unwind `f` from `pc` in the state `frame` and require the caller's
/// stack pointer, return address and saved registers. Returns the place
/// the unwinder saw, or `None` if it saw an epilog (whose registers the
/// prolog simulation does not describe).
fn x64_check(img: &Image, f: &x64::RuntimeFunction, pc: u32, frame: &X64Frame) -> Option<Place> {
    let u = x64::virtual_unwind(&img.bytes, f, pc, &frame.regs, &mut |a| Some(mem(a)))
        .unwrap_or_else(|e| panic!("{}: unwind at {pc:#x}: {e:?}", img.name));
    if u.place == Place::Epilog {
        return None;
    }
    let at = format!("{} pc {pc:#x} of {:#x}", img.name, f.begin);
    assert_eq!(u.regs.gpr[x64::RSP], CALLER, "{at}");
    assert_eq!(u.regs.rip, mem(CALLER - 8), "{at}");
    for reg in (0..16).filter(|&r| r != x64::RSP) {
        let want = frame.gpr_at[reg].map_or(frame.regs.gpr[reg], mem);
        assert_eq!(u.regs.gpr[reg], want, "{at}: register {reg}");
    }
    for reg in 0..10 {
        let saved = |a: u64| u128::from(mem(a + 8)) << 64 | u128::from(mem(a));
        let want = frame.xmm_at[reg].map_or(frame.regs.xmm[reg], saved);
        assert_eq!(u.regs.xmm[reg], want, "{at}: xmm{}", reg + 6);
    }
    Some(u.place)
}

#[test]
fn x64_unwind_from_every_prolog_offset_reaches_the_same_caller() {
    let (mut functions, mut offsets, mut bodies) = (0, 0, 0);
    for img in images(MACHINE_AMD64, true) {
        for f in x64_entries(&img) {
            let Some(chain) = x64_chain(&img.bytes, &f) else {
                continue;
            };
            functions += 1;
            let prolog = u32::from(chain[0].prolog_size);

            // The body: the whole prolog has run, and in a function with
            // a frame register rsp has since moved.
            let mut body = x64_run_prolog(&chain, None);
            if body.fp_set {
                body.regs.gpr[x64::RSP] -= 0x1230;
            }
            if f.begin + prolog < f.end {
                let place = x64_check(&img, &f, f.begin + prolog, &body);
                assert_ne!(place, Some(Place::Prolog));
                bodies += usize::from(place == Some(Place::Body));
            }

            // Every boundary the codes name inside the prolog, and its start.
            let mut stops: Vec<u32> = chain[0].codes().map(|c| u32::from(c.offset)).collect();
            stops.push(0);
            stops.sort();
            stops.dedup();
            for k in stops.into_iter().filter(|&k| k < prolog) {
                let partial = x64_run_prolog(&chain, Some(k));
                assert_eq!(
                    x64_check(&img, &f, f.begin + k, &partial),
                    Some(Place::Prolog)
                );
                offsets += 1;
            }
        }
    }
    eprintln!("x64 prolog sweep: {functions} functions, {bodies} bodies, {offsets} prolog offsets");
    assert!(functions == 0 || (bodies > functions / 2 && offsets > functions));
}

/// The version 2 epilog table and the epilog instructions describe the
/// same code. Per function of the fixtures, for every byte past the
/// prolog:
/// - a listed epilog decodes, from its start and from each instruction
///   in it, as pops and a return with no stack trim, and ends where the
///   table says (a final `rex.w jmp` is listed by its first byte);
/// - bytes the table lists but the decoder refuses are inside an
///   instruction;
/// - where the decoder finds a stack trim, the trim leads straight into
///   a listed epilog, and unwinding before it (by the unwind codes) and
///   after it (by the remaining instructions) reaches the same caller.
#[test]
fn x64_epilog_table_agrees_with_instruction_decode() {
    let (mut epilogs, mut agree, mut inside, mut trims, mut stray) = (0, 0, 0, 0, 0);
    for img in images(MACHINE_AMD64, false) {
        for f in x64_entries(&img) {
            let info = x64::UnwindInfo::parse(&img.bytes, f.unwind).unwrap();
            if info.version != 2 {
                continue;
            }
            let at = format!("{} function {:#x}", img.name, f.begin);
            let listed: Vec<(u32, u32)> = info.epilogs(&f).collect();
            // Instruction starts inside listed epilogs, and where each
            // epilog's code ends.
            let mut starts = HashSet::new();
            let mut ends = BTreeMap::new();
            for &(start, len) in &listed {
                epilogs += 1;
                let e = x64::decode_epilog(&img.bytes, &f, start)
                    .unwrap_or_else(|| panic!("{at}: epilog {start:#x}"));
                assert_eq!(e.trim, x64::Trim::None, "{at}: epilog {start:#x}");
                let rex_jmp =
                    e.len > len && (0x48..=0x4F).contains(&img.bytes[(start + len - 1) as usize]);
                assert!(
                    e.len == len || rex_jmp,
                    "{at}: epilog {start:#x} is {} bytes, listed {len}",
                    e.len
                );
                ends.insert(start + e.len, start);
                let mut pc = start;
                for (i, &reg) in e.pops().iter().enumerate() {
                    starts.insert(pc);
                    let rest = x64::decode_epilog(&img.bytes, &f, pc).unwrap();
                    assert_eq!(rest.pops(), &e.pops()[i..], "{at}: {pc:#x}");
                    pc += if reg >= 8 { 2 } else { 1 };
                }
                starts.insert(pc);
                assert!(
                    x64::decode_epilog(&img.bytes, &f, pc).is_some_and(|r| r.pops().is_empty())
                );
            }
            for pc in f.begin + u32::from(info.prolog_size)..f.end {
                let in_table = listed
                    .iter()
                    .any(|&(start, len)| pc.wrapping_sub(start) < len);
                match (in_table, x64::decode_epilog(&img.bytes, &f, pc)) {
                    (true, Some(_)) => agree += 1,
                    (true, None) => {
                        assert!(!starts.contains(&pc), "{at}: {pc:#x}");
                        inside += 1;
                    }
                    (false, Some(e)) if e.trim != x64::Trim::None => {
                        let Some(&start) = ends.get(&(pc + e.len)) else {
                            panic!("{at}: a stack trim at {pc:#x} leads to no listed epilog");
                        };
                        x64_trim_agrees(&img, &f, pc, start, &e);
                        trims += 1;
                    }
                    (false, Some(_)) => stray += 1,
                    (false, None) => {}
                }
            }
        }
    }
    eprintln!(
        "x64 epilog sweep: {epilogs} listed epilogs; bytes: {agree} agree, {inside} inside an instruction, \
         {trims} stack trims before a listed epilog, {stray} epilog-shaped bytes the table omits"
    );
    assert!(epilogs == 0 || (agree > epilogs && trims > epilogs / 2));
}

/// Unwinding from the stack trim at `pc`, which the table calls body,
/// and from the epilog at `start` just after it, with the registers the
/// trim leaves, must reach the same caller.
fn x64_trim_agrees(img: &Image, f: &x64::RuntimeFunction, pc: u32, start: u32, e: &x64::Epilog) {
    let mut before = x64::Regs {
        gpr: core::array::from_fn(|i| CALLER - 0x10_0000 + 0x1000 * i as u64),
        rip: 0,
        xmm: [0; 10],
    };
    before.gpr[x64::RSP] = CALLER - 0x20_0000;
    let mut after = before;
    after.gpr[x64::RSP] = match e.trim {
        x64::Trim::Add(n) => before.gpr[x64::RSP].wrapping_add_signed(i64::from(n)),
        x64::Trim::Lea { base, disp } => {
            before.gpr[base as usize].wrapping_add_signed(i64::from(disp))
        }
        x64::Trim::None => unreachable!(),
    };
    let unwind = |pc, regs: &x64::Regs| {
        x64::virtual_unwind(&img.bytes, f, pc, regs, &mut |a| Some(mem(a))).unwrap()
    };
    let (a, b) = (unwind(pc, &before), unwind(start, &after));
    let at = format!("{} function {:#x} trim {pc:#x}", img.name, f.begin);
    assert_eq!((a.place, b.place), (Place::Body, Place::Epilog), "{at}");
    assert_eq!(
        (a.regs.gpr[x64::RSP], a.regs.rip),
        (b.regs.gpr[x64::RSP], b.regs.rip),
        "{at}"
    );
}

// ---------------------------------------------------------------- arm64

/// The prototype's opcode table: mask, value, length, name. Kept apart
/// from `arm64::decode` so the two check each other.
const A64_CODES: &[(u8, u8, usize, &str)] = &[
    (0xE0, 0x00, 1, "alloc_s"),
    (0xE0, 0x20, 1, "save_r19r20_x"),
    (0xC0, 0x40, 1, "save_fplr"),
    (0xC0, 0x80, 1, "save_fplr_x"),
    (0xF8, 0xC0, 2, "alloc_m"),
    (0xFC, 0xC8, 2, "save_regp"),
    (0xFC, 0xCC, 2, "save_regp_x"),
    (0xFC, 0xD0, 2, "save_reg"),
    (0xFE, 0xD4, 2, "save_reg_x"),
    (0xFE, 0xD6, 2, "save_lrpair"),
    (0xFE, 0xD8, 2, "save_fregp"),
    (0xFE, 0xDA, 2, "save_fregp_x"),
    (0xFE, 0xDC, 2, "save_freg"),
    (0xFF, 0xDE, 2, "save_freg_x"),
    (0xFF, 0xE0, 4, "alloc_l"),
    (0xFF, 0xE1, 1, "set_fp"),
    (0xFF, 0xE2, 2, "add_fp"),
    (0xFF, 0xE3, 1, "nop"),
    (0xFF, 0xE4, 1, "end"),
    (0xFF, 0xE5, 1, "end_c"),
    (0xFF, 0xE6, 1, "save_next"),
    (0xFF, 0xE9, 1, "MSFT_OP_MACHINE_FRAME"),
    (0xFF, 0xEA, 1, "MSFT_OP_CONTEXT"),
    (0xFF, 0xEC, 1, "MSFT_OP_CLEAR_UNWOUND_TO_CALL"),
    (0xFF, 0xFC, 1, "pac_sign_lr"),
];

/// What the prototype counted, per image: `.pdata` entries, entries with
/// `.xdata`, packed entries, packed with CR=3 and with CR=2, distinct
/// `.xdata` records, records with a handler; then every code byte of
/// every record by name, padding included.
type A64Survey = (&'static str, [usize; 7], &'static [(&'static str, usize)]);
const A64_SURVEY: &[A64Survey] = &[
    (
        "sioctl.arm64.sys",
        [19, 15, 4, 3, 1, 15, 1],
        &[
            ("end", 15),
            ("alloc_s", 42),
            ("set_fp", 1),
            ("save_fplr_x", 1),
            ("save_regp", 3),
            ("save_r19r20_x", 1),
            ("nop", 2),
        ],
    ),
    (
        "cancel.arm64.sys",
        [59, 27, 32, 4, 28, 27, 3],
        &[
            ("set_fp", 8),
            ("save_fplr_x", 12),
            ("end", 35),
            ("alloc_s", 69),
            ("save_regp", 13),
            ("save_r19r20_x", 3),
            ("nop", 9),
            ("MSFT_OP_CLEAR_UNWOUND_TO_CALL", 1),
            ("save_reg", 2),
            ("pac_sign_lr", 5),
        ],
    ),
    (
        "nkc-wait.arm64.sys",
        [12, 5, 7, 6, 1, 5, 1],
        &[("end", 5), ("alloc_s", 15)],
    ),
    (
        "echo.arm64.sys",
        [18, 4, 14, 7, 7, 4, 0],
        &[
            ("set_fp", 3),
            ("save_fplr_x", 2),
            ("end", 4),
            ("nop", 6),
            ("save_regp", 4),
            ("save_r19r20_x", 2),
            ("pac_sign_lr", 1),
            ("alloc_s", 3),
            ("save_fplr", 1),
            ("alloc_m", 1),
        ],
    ),
];

fn a64_entries(img: &Image) -> Vec<arm64::FunctionEntry> {
    let n = img.dir_size as usize / arm64::ENTRY_SIZE;
    let entry = |i| arm64::entry(&img.bytes, img.dir_rva, i);
    (0..n)
        .map(|i| entry(i).unwrap_or_else(|e| panic!("{}: entry {i}: {e:?}", img.name)))
        .collect()
}

#[test]
fn arm64_records_parse_and_total_as_surveyed() {
    let (mut functions, mut matched) = (0, 0);
    for img in images(MACHINE_ARM64, true) {
        let entries = a64_entries(&img);
        functions += entries.len();
        let mut seen = HashSet::new();
        let mut t = [0usize; 7];
        let mut ops: BTreeMap<&str, usize> = BTreeMap::new();
        t[0] = entries.len();
        for (i, f) in entries.iter().enumerate() {
            assert!(f.len != 0, "{}: empty entry {i}", img.name);
            let sorted = i == 0 || entries[i - 1].begin + entries[i - 1].len <= f.begin;
            assert!(sorted, "{}: entries overlap at {i}", img.name);
            for rva in [f.begin, f.begin + f.len - 4] {
                let found = arm64::lookup(&img.bytes, img.dir_rva, img.dir_size, rva);
                assert_eq!(found, Ok(Some(*f)), "{}: lookup {rva:#x}", img.name);
            }
            match f.unwind {
                arm64::UnwindData::Packed(word) => {
                    t[2] += 1;
                    t[3] += usize::from((word >> 21) & 3 == 3);
                    t[4] += usize::from((word >> 21) & 3 == 2);
                    let expanded = arm64::canonical(word, false);
                    assert!(
                        expanded.is_ok(),
                        "{}: packed {word:#x}: {expanded:?}",
                        img.name
                    );
                }
                arm64::UnwindData::Xdata(rva) => {
                    t[1] += 1;
                    if !seen.insert(rva) {
                        continue;
                    }
                    let x = arm64::Xdata::parse(&img.bytes, rva).unwrap();
                    t[5] += 1;
                    t[6] += usize::from(x.handler.is_some());
                    // Every byte of the code words is a code, to the last.
                    let mut codes = x.code_bytes();
                    while let Some(&b) = codes.first() {
                        let &(_, _, len, name) = A64_CODES.iter().find(|c| b & c.0 == c.1).unwrap();
                        let decoded = arm64::decode(codes);
                        assert_eq!(decoded.map(|d| d.1), Ok(len), "{}: {name}", img.name);
                        *ops.entry(name).or_default() += 1;
                        codes = &codes[len..];
                    }
                    for (start, index) in x.epilog_scopes() {
                        assert!(start < x.function_len && (index as usize) < x.code_bytes().len());
                    }
                }
            }
        }
        if let Some((_, want, want_ops)) = A64_SURVEY.iter().find(|(name, ..)| *name == img.name) {
            assert_eq!(&t, want, "{}", img.name);
            assert_eq!(ops, want_ops.iter().copied().collect(), "{}", img.name);
            matched += 1;
        }
    }
    eprintln!("arm64 parse sweep: {functions} functions, {matched} images match the survey");
    assert!(functions == 0 || matched >= 3);
}

/// A function's code sequences, as the unwinder is meant to read them.
struct A64Function {
    /// The codes run from the body, stored order, `End` last.
    prolog: Vec<arm64::Op>,
    /// How many of them, from the front, are the function's own prolog.
    own: usize,
    /// Each epilog: start offset and its codes, `End` last.
    epilogs: Vec<(u32, Vec<arm64::Op>)>,
}

fn a64_describe(img: &Image, f: &arm64::FunctionEntry) -> A64Function {
    match f.unwind {
        arm64::UnwindData::Packed(word) => {
            let prolog = arm64::canonical(word, false).unwrap().ops().to_vec();
            let epilog = arm64::canonical(word, true).unwrap().ops().to_vec();
            let whole = word & 3 == 1;
            A64Function {
                own: if whole { prolog.len() - 1 } else { 0 },
                prolog,
                epilogs: if whole {
                    vec![(f.len - 4 * epilog.len() as u32, epilog)]
                } else {
                    vec![]
                },
            }
        }
        arm64::UnwindData::Xdata(rva) => {
            let x = arm64::Xdata::parse(&img.bytes, rva).unwrap();
            let sequence = |index: u32| {
                let mut ops: Vec<arm64::Op> = x.codes(index).map(Result::unwrap).collect();
                let end = ops.iter().position(|op| *op == arm64::Op::End).unwrap();
                ops.truncate(end + 1);
                ops
            };
            let prolog = sequence(0);
            let ends = |op: &arm64::Op| matches!(op, arm64::Op::End | arm64::Op::EndC);
            let own = prolog.iter().position(ends).unwrap();
            let epilogs = match x.packed_epilog {
                Some(index) => {
                    let ops = sequence(index);
                    vec![(x.function_len - 4 * a64_instructions(&ops) as u32, ops)]
                }
                None => x
                    .epilog_scopes()
                    .map(|(start, index)| (start, sequence(index)))
                    .collect(),
            };
            A64Function {
                prolog,
                own,
                epilogs,
            }
        }
    }
}

/// Whether a code stands for an instruction of its own.
fn a64_is_instruction(op: &arm64::Op) -> bool {
    !matches!(
        op,
        arm64::Op::ClearUnwoundToCall | arm64::Op::MachineFrame | arm64::Op::Context
    )
}

/// Instructions in a sequence, its `End` (the return) included.
fn a64_instructions(ops: &[arm64::Op]) -> usize {
    ops.iter().filter(|op| a64_is_instruction(op)).count()
}

/// `ops` without the codes of its first `n` instructions.
fn a64_skip(ops: &[arm64::Op], n: usize) -> &[arm64::Op] {
    let mut rest = ops;
    for _ in 0..n {
        let at = rest.iter().position(a64_is_instruction).unwrap();
        rest = &rest[at + 1..];
    }
    rest
}

/// Registers and stack once the instructions behind some codes have run.
struct A64Frame {
    regs: arm64::Regs,
    x_at: [Option<u64>; 12],
    d_at: [Option<u64>; 8],
    uses_fp: bool,
}

impl A64Frame {
    /// Note where `reg` was stored. The first store of a register holds
    /// the caller's value.
    fn stored(&mut self, reg: arm64::Reg, at: u64) {
        let slot = match reg {
            arm64::Reg::X(n) => &mut self.x_at[n as usize - 19],
            arm64::Reg::D(n) => &mut self.d_at[n as usize - 8],
        };
        slot.get_or_insert(at);
    }
}

/// Run the instructions that the stored codes `ops` describe, last code
/// first, from the caller's `bl`. `None` for codes this simulation does
/// not model.
fn a64_run(ops: &[arm64::Op]) -> Option<A64Frame> {
    let mut f = A64Frame {
        regs: arm64::Regs {
            x: core::array::from_fn(|i| 0x3333_0000 + i as u64),
            sp: CALLER,
            pc: 0,
            d: core::array::from_fn(|i| 0x4444_0000 + i as u64),
        },
        x_at: [None; 12],
        d_at: [None; 8],
        uses_fp: false,
    };
    for op in ops.iter().rev() {
        match *op {
            arm64::Op::Alloc(n) => f.regs.sp -= u64::from(n),
            arm64::Op::Save { reg, offset, pre } => {
                f.regs.sp -= if pre { u64::from(offset) } else { 0 };
                f.stored(reg, f.regs.sp + if pre { 0 } else { u64::from(offset) });
            }
            arm64::Op::SavePair { a, b, offset, pre } => {
                f.regs.sp -= if pre { u64::from(offset) } else { 0 };
                let at = f.regs.sp + if pre { 0 } else { u64::from(offset) };
                f.stored(a, at);
                f.stored(b, at + 8);
            }
            arm64::Op::SetFp => (f.regs.x[arm64::FP], f.uses_fp) = (f.regs.sp, true),
            arm64::Op::AddFp(n) => {
                (f.regs.x[arm64::FP], f.uses_fp) = (f.regs.sp + u64::from(n), true)
            }
            arm64::Op::Nop
            | arm64::Op::PacSignLr
            | arm64::Op::End
            | arm64::Op::EndC
            | arm64::Op::ClearUnwoundToCall => {}
            arm64::Op::SaveNext | arm64::Op::MachineFrame | arm64::Op::Context => return None,
        }
    }
    Some(f)
}

/// Unwind `f` from `pc` in the state `frame`; require `place`, the
/// caller's stack pointer and every saved register.
fn a64_check(img: &Image, f: &arm64::FunctionEntry, pc: u32, frame: &A64Frame, place: Place) {
    let at = format!("{} pc {pc:#x} of {:#x}", img.name, f.begin);
    let u = arm64::virtual_unwind(&img.bytes, f, pc, &frame.regs, &mut |a| Some(mem(a)));
    let u = u.unwrap_or_else(|e| panic!("{at}: {e:?}"));
    assert_eq!(u.place, place, "{at}");
    assert_eq!((u.regs.sp, u.establisher), (CALLER, CALLER), "{at}");
    for i in 0..12 {
        let want = frame.x_at[i].map_or(frame.regs.x[i], mem);
        assert_eq!(u.regs.x[i], want, "{at}: x{}", i + 19);
    }
    for i in 0..8 {
        let want = frame.d_at[i].map_or(frame.regs.d[i], mem);
        assert_eq!(u.regs.d[i], want, "{at}: d{}", i + 8);
    }
    assert_eq!(u.regs.pc, u.regs.x[arm64::LR], "{at}");
}

#[test]
fn arm64_unwind_from_every_prolog_and_epilog_instruction_reaches_the_same_caller() {
    let (mut functions, mut bodies, mut prologs, mut epilogs) = (0, 0, 0, 0);
    for img in images(MACHINE_ARM64, true) {
        for f in a64_entries(&img) {
            let d = a64_describe(&img, &f);
            functions += 1;
            // After each instruction of the prolog; after the last one is
            // the body, where sp may since have moved below x29.
            for n in 0..=d.own {
                let Some(mut frame) = a64_run(&d.prolog[d.own - n..]) else {
                    continue;
                };
                let offset = 4 * n as u32;
                let in_epilog = d.epilogs.iter().any(|(start, ops)| {
                    offset >= *start && offset < start + 4 * a64_instructions(ops) as u32
                });
                if n < d.own {
                    a64_check(&img, &f, f.begin + offset, &frame, Place::Prolog);
                    prologs += 1;
                } else if offset < f.len && !in_epilog {
                    if frame.uses_fp {
                        frame.regs.sp -= 0x1230;
                    }
                    a64_check(&img, &f, f.begin + offset, &frame, Place::Body);
                    bodies += 1;
                }
            }
            // Before each instruction of every epilog, the return included.
            for (start, ops) in &d.epilogs {
                for k in 0..a64_instructions(ops) {
                    let Some(frame) = a64_run(a64_skip(ops, k)) else {
                        continue;
                    };
                    a64_check(
                        &img,
                        &f,
                        f.begin + start + 4 * k as u32,
                        &frame,
                        Place::Epilog,
                    );
                    epilogs += 1;
                }
            }
        }
    }
    eprintln!(
        "arm64 sweep: {functions} functions, {bodies} bodies, {prologs} prolog and {epilogs} epilog instructions"
    );
    assert!(
        functions == 0 || (bodies > functions / 2 && prologs > functions && epilogs > functions)
    );
}

fn a64_signed(value: u32, bits: u32) -> i64 {
    i64::from(value << (32 - bits)) << 32 >> (64 - bits)
}

/// Whether instruction `w` is what the code `op` says it is: a store in
/// a prolog, the mirrored load in an epilog (`load`).
fn a64_matches(op: &arm64::Op, w: u32, load: bool) -> bool {
    let l = u32::from(load) << 22;
    let imm12 = |w: u32| ((w >> 10) & 0xFFF) << (12 * ((w >> 22) & 1));
    let number = |reg: arm64::Reg| match reg {
        arm64::Reg::X(n) | arm64::Reg::D(n) => u32::from(n),
    };
    let vector = |reg: arm64::Reg| matches!(reg, arm64::Reg::D(_));
    // Base register, first and second data register.
    let (base, rt, rt2) = ((w >> 5) & 31, w & 31, (w >> 10) & 31);
    // A prolog writes back before the store, an epilog after the load.
    let writeback = |offset: u32| {
        if load {
            i64::from(offset)
        } else {
            -i64::from(offset)
        }
    };
    match *op {
        // `sub sp, sp, #n` (`add` in an epilog), or a call to a helper
        // that moves sp by a known amount.
        arm64::Op::Alloc(n) => {
            let adjust = if load { 0x9100_03FF } else { 0xD100_03FF };
            (w & 0xFF80_03FF == adjust && imm12(w) == n) || w >> 26 == 0x25
        }
        arm64::Op::SavePair { a, b, offset, pre } => {
            let plain = if vector(a) { 0x6D00_0000 } else { 0xA900_0000 } | l;
            // A store is pre-indexed (bit 23), a load post-indexed (bit
            // 23 without bit 24).
            let form = match (pre, load) {
                (false, _) => plain,
                (true, false) => plain | 0x0080_0000,
                (true, true) => (plain | 0x0080_0000) & !0x0100_0000,
            };
            let imm = a64_signed((w >> 15) & 0x7F, 7) * 8;
            let want = if pre {
                writeback(offset)
            } else {
                i64::from(offset)
            };
            w & 0xFFC0_0000 == form && (base, rt, rt2) == (31, number(a), number(b)) && imm == want
        }
        arm64::Op::Save {
            reg,
            offset,
            pre: false,
        } => {
            let form = if vector(reg) {
                0xFD00_0000
            } else {
                0xF900_0000
            } | l;
            w & 0xFFC0_0000 == form
                && (base, rt) == (31, number(reg))
                && ((w >> 10) & 0xFFF) * 8 == offset
        }
        arm64::Op::Save {
            reg,
            offset,
            pre: true,
        } => {
            let index = if load { 0x400 } else { 0xC00 };
            let form = if vector(reg) {
                0xFC00_0000
            } else {
                0xF800_0000
            } | l
                | index;
            let imm = a64_signed((w >> 12) & 0x1FF, 9);
            w & 0xFFE0_0C00 == form && (base, rt) == (31, number(reg)) && imm == writeback(offset)
        }
        // `mov x29, sp`; in an epilog `mov sp, x29`.
        arm64::Op::SetFp => w == if load { 0x9100_03BF } else { 0x9100_03FD },
        arm64::Op::AddFp(n) => !load && w & 0xFFC0_03FF == 0x9100_03FD && imm12(w) == n,
        // `pacibsp`; in an epilog `autibsp`.
        arm64::Op::PacSignLr => w == if load { 0xD503_23FF } else { 0xD503_237F },
        // `ret`, or the branch of a tail call.
        arm64::Op::End => w == 0xD65F_03C0 || w >> 26 == 0x05 || w & 0xFFFF_FC1F == 0xD61F_0000,
        _ => true,
    }
}

/// Each unwind code describes one instruction. Decode the instruction
/// and compare: the kind, the registers, the offset. For packed unwind
/// data this checks the canonical expansion against what the compiler
/// actually emitted.
#[test]
fn arm64_codes_match_the_instructions_they_describe() {
    let (mut functions, mut compared) = (0, 0);
    for img in images(MACHINE_ARM64, true) {
        let word =
            |rva: u32| u32::from_le_bytes(img.bytes[rva as usize..][..4].try_into().unwrap());
        for f in a64_entries(&img) {
            let d = a64_describe(&img, &f);
            functions += 1;
            // The prolog runs its codes last to first.
            let prolog = d.prolog[..d.own]
                .iter()
                .rev()
                .filter(|op| a64_is_instruction(op));
            let prolog = prolog
                .enumerate()
                .map(|(i, op)| (f.begin + 4 * i as u32, op, false));
            let epilogs = d.epilogs.iter().flat_map(|(start, ops)| {
                let ops = ops.iter().filter(|op| a64_is_instruction(op));
                ops.enumerate()
                    .map(move |(k, op)| (f.begin + start + 4 * k as u32, op, true))
            });
            for (rva, op, load) in prolog.chain(epilogs) {
                let w = word(rva);
                assert!(
                    a64_matches(op, w, load),
                    "{} {rva:#x}: {w:#010x} is not {op:?}",
                    img.name
                );
                compared += 1;
            }
        }
    }
    eprintln!(
        "arm64 instruction sweep: {functions} functions, {compared} instructions match their codes"
    );
    assert!(functions == 0 || compared > 2 * functions);
}
