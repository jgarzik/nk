//! arm64 tests against `.pdata` and `.xdata` assembled here. The unwind
//! never reads code, so the images hold tables only; the stack is a map
//! from address to value. The worked examples of Microsoft's document
//! are used as they are printed.

use crate::arm64::*;
use crate::{Place, UnwindError};
use std::collections::HashMap;

const PDATA: u32 = 0x2000;
const XDATA: u32 = 0x3000;
const IMAGE_SIZE: usize = 0x8000;

const SP: u64 = 0xFFFF_8000_0010_0000;
const RET: u64 = 0xFFFF_8000_2000_1234;

struct Image {
    bytes: Vec<u8>,
    funcs: u32,
    xdata: u32,
}

impl Image {
    fn new() -> Self {
        Self {
            bytes: vec![0; IMAGE_SIZE],
            funcs: 0,
            xdata: XDATA,
        }
    }

    fn words(&mut self, words: &[u32]) -> u32 {
        let rva = self.xdata;
        for w in words {
            self.bytes[self.xdata as usize..][..4].copy_from_slice(&w.to_le_bytes());
            self.xdata += 4;
        }
        rva
    }

    /// Append an `.xdata` record of a function `len` bytes long with the
    /// given epilog scopes `(start offset, code index)`; returns its RVA.
    fn xdata(
        &mut self,
        len: u32,
        scopes: &[(u32, u32)],
        codes: &[u8],
        handler: Option<u32>,
    ) -> u32 {
        let mut codes = codes.to_vec();
        codes.resize(codes.len().next_multiple_of(4), 0);
        let (epilogs, words) = (scopes.len() as u32, codes.len() as u32 / 4);
        let head = (len / 4) | (u32::from(handler.is_some()) << 20);
        let mut out = if epilogs > 31 || words > 31 || (epilogs == 0 && words == 0) {
            vec![head, epilogs | words << 16]
        } else {
            vec![head | epilogs << 22 | words << 27]
        };
        out.extend(
            scopes
                .iter()
                .map(|&(start, index)| (start / 4) | (index << 22)),
        );
        out.extend(
            codes
                .chunks(4)
                .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])),
        );
        out.extend(handler);
        self.words(&out)
    }

    /// Append a `.pdata` entry and return what `lookup` should find.
    fn func(&mut self, begin: u32, word: u32) -> FunctionEntry {
        let at = (PDATA + 8 * self.funcs) as usize;
        self.bytes[at..][..4].copy_from_slice(&begin.to_le_bytes());
        self.bytes[at + 4..][..4].copy_from_slice(&word.to_le_bytes());
        self.funcs += 1;
        entry(&self.bytes, PDATA, self.funcs as usize - 1).unwrap()
    }

    fn lookup(&self, rva: u32) -> Result<Option<FunctionEntry>, UnwindError> {
        lookup(&self.bytes, PDATA, 8 * self.funcs, rva)
    }
}

/// A packed unwind word. `len` and `frame` are in bytes.
fn packed(flag: u32, len: u32, reg_f: u32, reg_i: u32, h: u32, cr: u32, frame: u32) -> u32 {
    flag | (len / 4) << 2 | reg_f << 13 | reg_i << 16 | h << 20 | cr << 21 | (frame / 16) << 23
}

fn regs(sp: u64) -> Regs {
    Regs {
        x: core::array::from_fn(|i| 0xAAAA_0000 + i as u64),
        sp,
        pc: 0,
        d: core::array::from_fn(|i| 0xDDDD_0000 + i as u64),
    }
}

fn stack(slots: &[(u64, u64)]) -> HashMap<u64, u64> {
    slots.iter().copied().collect()
}

fn unwind(
    img: &Image,
    f: &FunctionEntry,
    pc: u32,
    r: &Regs,
    mem: &HashMap<u64, u64>,
) -> Result<Unwound, UnwindError> {
    virtual_unwind(&img.bytes, f, pc, r, &mut |a| mem.get(&a).copied())
}

/// A function at 0x1000 of `len` bytes whose record has these codes and
/// no epilog scope.
fn with_codes(len: u32, codes: &[u8]) -> (Image, FunctionEntry) {
    let mut img = Image::new();
    let x = img.xdata(len, &[], codes, None);
    let f = img.func(0x1000, x);
    (img, f)
}

const X19: usize = 0;
const X20: usize = 1;
const X21: usize = 2;
const X22: usize = 3;

fn x(n: u8) -> Reg {
    Reg::X(n)
}

fn pair(a: Reg, b: Reg, offset: u32, pre: bool) -> Op {
    Op::SavePair { a, b, offset, pre }
}

fn save(reg: Reg, offset: u32, pre: bool) -> Op {
    Op::Save { reg, offset, pre }
}

#[test]
fn decode_reads_every_code_of_the_table() {
    let fplr = |offset, pre| pair(x(29), x(30), offset, pre);
    let cases: &[(&[u8], Op)] = &[
        (&[0x05], Op::Alloc(0x50)),
        (&[0x1F], Op::Alloc(496)),
        (&[0x22], pair(x(19), x(20), 16, true)),
        (&[0x3F], pair(x(19), x(20), 248, true)),
        (&[0x40], fplr(0, false)),
        (&[0x7F], fplr(504, false)),
        (&[0x80], fplr(8, true)),
        (&[0x91], fplr(0x90, true)),
        (&[0xBF], fplr(512, true)),
        (&[0xC0, 0x81], Op::Alloc(0x810)),
        (&[0xC7, 0xFF], Op::Alloc(0x7FF0)),
        (&[0xC8, 0x02], pair(x(19), x(20), 16, false)),
        (&[0xC8, 0x84], pair(x(21), x(22), 32, false)),
        (&[0xCA, 0x7F], pair(x(28), x(29), 504, false)),
        (&[0xCC, 0x41], pair(x(20), x(21), 16, true)),
        (&[0xD1, 0x06], save(x(23), 48, false)),
        (&[0xD4, 0x01], save(x(19), 16, true)),
        (&[0xD4, 0xA3], save(x(24), 32, true)),
        (&[0xD6, 0x00], pair(x(19), x(30), 0, false)),
        (&[0xD6, 0xC2], pair(x(25), x(30), 16, false)),
        (&[0xD8, 0x41], pair(Reg::D(9), Reg::D(10), 8, false)),
        (&[0xDA, 0x83], pair(Reg::D(10), Reg::D(11), 32, true)),
        (&[0xDC, 0xC5], save(Reg::D(11), 40, false)),
        (&[0xDE, 0x47], save(Reg::D(10), 64, true)),
        (&[0xE0, 0x01, 0x00, 0x00], Op::Alloc(0x10_0000)),
        (&[0xE1], Op::SetFp),
        (&[0xE2, 0x05], Op::AddFp(40)),
        (&[0xE3], Op::Nop),
        (&[0xE4], Op::End),
        (&[0xE5], Op::EndC),
        (&[0xE6], Op::SaveNext),
        (&[0xE9], Op::MachineFrame),
        (&[0xEA], Op::Context),
        (&[0xEC], Op::ClearUnwoundToCall),
        (&[0xFC], Op::PacSignLr),
    ];
    for (bytes, op) in cases {
        // Trailing bytes belong to the next code.
        let mut longer = bytes.to_vec();
        longer.push(0xE4);
        assert_eq!(decode(&longer), Ok((*op, bytes.len())), "{bytes:02x?}");
    }
}

#[test]
fn decode_rejects_what_it_does_not_implement() {
    // alloc_z, save_any_reg, the trap frame and EC context, and every
    // reserved code.
    let unsupported = [
        0xDF, 0xE7, 0xE8, 0xEB, 0xED, 0xEE, 0xEF, 0xF0, 0xF7, 0xF8, 0xFB, 0xFD, 0xFF,
    ];
    for b in unsupported {
        assert_eq!(
            decode(&[b, 0, 0, 0, 0]),
            Err(UnwindError::Unsupported(b)),
            "{b:#x}"
        );
    }
    for truncated in [&[][..], &[0xC0], &[0xE2], &[0xE0, 0, 0], &[0xE7, 0]] {
        assert_eq!(
            decode(truncated),
            Err(UnwindError::BadUnwindInfo),
            "{truncated:02x?}"
        );
    }
}

/// "Example 2: Frame-chained, full-form with mirror Prolog & Epilog".
const EXAMPLE_2: [u32; 4] = [0x1040_003D, 0x0100_0038, 0xE422_91E1, 0xE422_91E1];
/// "Example 3: Variadic unchained Function".
const EXAMPLE_3: [u32; 5] = [
    0x1840_0012,
    0x0200_000F,
    0xE3E3_E3E3,
    0xE405_00D6,
    0xE405_00D6,
];

#[test]
fn xdata_parse_reads_the_documented_examples() {
    let mut img = Image::new();
    let rva = img.words(&EXAMPLE_2);
    let x2 = Xdata::parse(&img.bytes, rva).unwrap();
    assert_eq!(x2.function_len, 0x3D * 4);
    assert_eq!((x2.handler, x2.packed_epilog), (None, None));
    assert_eq!(x2.epilog_scopes().collect::<Vec<_>>(), [(0x38 * 4, 4)]);
    assert_eq!(
        x2.code_bytes(),
        [0xE1, 0x91, 0x22, 0xE4, 0xE1, 0x91, 0x22, 0xE4]
    );
    let ops: Vec<_> = x2.codes(4).map(Result::unwrap).collect();
    let want = [
        Op::SetFp,
        pair(x(29), x(30), 0x90, true),
        pair(x(19), x(20), 0x10, true),
        Op::End,
    ];
    assert_eq!(ops, want);
    assert_eq!(x2.codes(100).count(), 0);

    let rva = img.words(&EXAMPLE_3);
    let x3 = Xdata::parse(&img.bytes, rva).unwrap();
    assert_eq!(x3.function_len, 18 * 4);
    assert_eq!(x3.epilog_scopes().collect::<Vec<_>>(), [(15 * 4, 8)]);
    let ops: Vec<_> = x3.codes(0).map(Result::unwrap).take(7).collect();
    let want = [
        Op::Nop,
        Op::Nop,
        Op::Nop,
        Op::Nop,
        pair(x(19), x(30), 0, false),
        Op::Alloc(0x50),
        Op::End,
    ];
    assert_eq!(ops, want);
}

#[test]
fn xdata_parse_handles_each_header_form() {
    let mut img = Image::new();
    // Handler: its RVA follows the codes, its data follows that.
    let rva = img.xdata(0x40, &[(0x30, 0)], &[0xE4], Some(0x1F00));
    let x = Xdata::parse(&img.bytes, rva).unwrap();
    assert_eq!(
        x.handler,
        Some(Handler {
            rva: 0x1F00,
            data_rva: rva + 4 + 4 + 4 + 4
        })
    );

    // E bit: the epilog count field is a code index and no scope follows.
    let rva = img.words(&[0x10 | 1 << 21 | 3 << 22 | 1 << 27, 0xE4E4_E4E4]);
    let x = Xdata::parse(&img.bytes, rva).unwrap();
    assert_eq!((x.packed_epilog, x.epilog_scopes().count()), (Some(3), 0));
    assert_eq!(x.code_bytes().len(), 4);

    // Extension word: 40 code words and 33 scopes do not fit the header.
    let codes = vec![0xE3; 160];
    let scopes: Vec<(u32, u32)> = (0..33).map(|i| (0x100 + 8 * i, i)).collect();
    let rva = img.xdata(0x400, &scopes, &codes, Some(0x1F00));
    let x = Xdata::parse(&img.bytes, rva).unwrap();
    assert_eq!(x.function_len, 0x400);
    assert_eq!(x.epilog_scopes().collect::<Vec<_>>(), scopes);
    assert_eq!(x.code_bytes(), codes);
    assert_eq!(x.handler.map(|h| h.rva), Some(0x1F00));

    // A record with no codes at all still has the extension word.
    let rva = img.xdata(0x20, &[], &[], None);
    let x = Xdata::parse(&img.bytes, rva).unwrap();
    assert_eq!((x.function_len, x.code_bytes().len()), (0x20, 0));
}

#[test]
fn xdata_parse_rejects_malformed_records() {
    let mut img = Image::new();
    let rva = img.words(&[0x10 | 1 << 18 | 1 << 27, 0xE4E4_E4E4]);
    assert_eq!(
        Xdata::parse(&img.bytes, rva).map(|_| ()),
        Err(UnwindError::BadUnwindInfo)
    );

    // The header, extension word, scopes, codes and handler must each
    // lie inside the image.
    let end = IMAGE_SIZE as u32;
    let put = |img: &mut Image, at: u32, w: u32| {
        img.bytes[at as usize..][..4].copy_from_slice(&w.to_le_bytes())
    };
    for (at, word) in [
        (end, 0),
        (end - 4, 0x10),
        (end - 4, 0x10 | 2 << 22 | 1 << 27),
        (end - 4, 0x10 | 1 << 27),
        (end - 8, 0x10 | 1 << 20 | 1 << 27),
    ] {
        let mut img = Image::new();
        if at < end {
            put(&mut img, at, word);
        }
        assert_eq!(
            Xdata::parse(&img.bytes, at).map(|_| ()),
            Err(UnwindError::OutOfBounds),
            "{word:#x}"
        );
    }
}

#[test]
fn lookup_finds_packed_and_xdata_entries() {
    let mut img = Image::new();
    let x = img.xdata(0x40, &[], &[0xE4], None);
    let a = img.func(0x1000, x);
    let b = img.func(0x1100, packed(1, 0x80, 0, 0, 0, 3, 0x20));
    let c = img.func(0x1180, packed(2, 0x20, 0, 0, 0, 3, 0x20));
    assert_eq!(
        (a.begin, a.len, a.unwind),
        (0x1000, 0x40, UnwindData::Xdata(x))
    );
    assert_eq!((b.begin, b.len), (0x1100, 0x80));
    assert!(matches!(b.unwind, UnwindData::Packed(_)));
    assert_eq!(img.lookup(0x0FFC), Ok(None));
    assert_eq!(img.lookup(0x1000), Ok(Some(a)));
    assert_eq!(img.lookup(0x103C), Ok(Some(a)));
    assert_eq!(
        img.lookup(0x1040),
        Ok(None),
        "past the length the record gives"
    );
    assert_eq!(img.lookup(0x10FC), Ok(None));
    assert_eq!(img.lookup(0x1100), Ok(Some(b)));
    assert_eq!(
        locate(&img.bytes, PDATA, 24, 0x1100),
        Ok(Some((PDATA + 8, b))),
        "where the entry itself is"
    );
    assert_eq!(img.lookup(0x117C), Ok(Some(b)));
    assert_eq!(img.lookup(0x1180), Ok(Some(c)));
    assert_eq!(img.lookup(0x11A0), Ok(None));
    assert_eq!(
        entry(&img.bytes, PDATA, usize::MAX),
        Err(UnwindError::OutOfBounds)
    );
    assert_eq!(
        lookup(&img.bytes, IMAGE_SIZE as u32, 8, 0),
        Err(UnwindError::OutOfBounds)
    );

    // A link record names its parent and has no length of its own.
    let at = (PDATA + 8 * img.funcs) as usize;
    img.bytes[at..][..8].copy_from_slice(&[0, 0x20, 0, 0, 0x03, 0x20, 0, 0]);
    img.funcs += 1;
    assert_eq!(img.lookup(0x2000), Err(UnwindError::Unsupported(3)));
}

/// Example 2 as a function at 0x1000, and its stack in the body with
/// `sp == SP`: the frame record at the bottom, x19/x20 above it.
fn example_2() -> (Image, FunctionEntry, HashMap<u64, u64>) {
    let mut img = Image::new();
    let x = img.words(&EXAMPLE_2);
    let f = img.func(0x1000, x);
    let mem = stack(&[
        (SP, 0xF9),
        (SP + 8, RET),
        (SP + 0x90, 0x19),
        (SP + 0x98, 0x20),
    ]);
    (img, f, mem)
}

#[test]
fn body_unwind_runs_every_code() {
    let (img, f, mem) = example_2();
    // sp has moved since the prolog; x29 still names the frame record.
    let mut r = regs(SP - 0x400);
    r.x[FP] = SP;
    let u = unwind(&img, &f, 0x1000 + 12, &r, &mem).unwrap();
    assert_eq!(u.place, Place::Body);
    assert_eq!((u.regs.sp, u.establisher), (SP + 0xA0, SP + 0xA0));
    assert_eq!((u.regs.pc, u.regs.x[LR], u.regs.x[FP]), (RET, RET, 0xF9));
    assert_eq!((u.regs.x[X19], u.regs.x[X20]), (0x19, 0x20));
    assert_eq!((u.regs.x[X21], u.regs.d), (r.x[X21], r.d));
    assert!(u.unwound_to_call);
    assert_eq!(u.handler, None);
    // The instruction after the epilog's return is body too.
    assert_eq!(unwind(&img, &f, 0x1000 + 0xF0, &r, &mem).unwrap(), u);
}

#[test]
fn prolog_unwind_undoes_only_what_has_run() {
    let (img, f, mem) = example_2();
    let caller = SP + 0xA0;
    // Nothing has run: the return address is still in lr.
    let r = regs(caller);
    let u = unwind(&img, &f, 0x1000, &r, &mem).unwrap();
    assert_eq!(u.place, Place::Prolog);
    assert_eq!((u.regs.sp, u.regs.pc), (caller, r.x[LR]));
    assert_eq!(u.regs.x, r.x);

    // After `stp x19,x20,[sp,#-0x10]!`.
    let r = regs(caller - 0x10);
    let u = unwind(&img, &f, 0x1004, &r, &mem).unwrap();
    assert_eq!(
        (u.place, u.regs.sp, u.regs.pc),
        (Place::Prolog, caller, r.x[LR])
    );
    assert_eq!(
        (u.regs.x[X19], u.regs.x[X20], u.regs.x[FP]),
        (0x19, 0x20, r.x[FP])
    );

    // After `stp fp,lr,[sp,#-0x90]!`, before `mov fp,sp`: x29 is not yet
    // this function's and must not be used.
    let r = regs(SP);
    let u = unwind(&img, &f, 0x1008, &r, &mem).unwrap();
    assert_eq!(
        (u.place, u.regs.sp, u.regs.pc),
        (Place::Prolog, caller, RET)
    );
    assert_eq!((u.regs.x[X19], u.regs.x[FP]), (0x19, 0xF9));
}

#[test]
fn epilog_unwind_skips_what_has_been_undone() {
    let (img, f, mem) = example_2();
    let caller = SP + 0xA0;
    let epilog = 0x1000 + 0xE0;

    // At `mov sp,fp`: everything remains.
    let mut r = regs(SP - 0x400);
    r.x[FP] = SP;
    let u = unwind(&img, &f, epilog, &r, &mem).unwrap();
    assert_eq!(
        (u.place, u.regs.sp, u.regs.pc),
        (Place::Epilog, caller, RET)
    );
    assert_eq!((u.regs.x[X19], u.regs.x[FP]), (0x19, 0xF9));

    // At `ldp fp,lr,[sp],#0x90`: sp is right, whatever x29 says.
    let r = regs(SP);
    let u = unwind(&img, &f, epilog + 4, &r, &mem).unwrap();
    assert_eq!(
        (u.place, u.regs.sp, u.regs.pc),
        (Place::Epilog, caller, RET)
    );

    // At `ldp x19,x20,[sp],#0x10`: lr is already the caller's.
    let mut r = regs(SP + 0x90);
    r.x[LR] = 0x7777;
    let u = unwind(&img, &f, epilog + 8, &r, &mem).unwrap();
    assert_eq!(
        (u.place, u.regs.sp, u.regs.pc),
        (Place::Epilog, caller, 0x7777)
    );
    assert_eq!((u.regs.x[X19], u.regs.x[X20]), (0x19, 0x20));

    // At `ret`: nothing remains.
    let r = regs(caller);
    let u = unwind(&img, &f, epilog + 12, &r, &mem).unwrap();
    assert_eq!(
        (u.place, u.regs.sp, u.regs.pc),
        (Place::Epilog, caller, r.x[LR])
    );
    assert_eq!(u.regs.x, r.x);
}

#[test]
fn packed_epilog_in_the_header_sits_at_the_function_end() {
    let mut img = Image::new();
    // E bit, epilog codes from index 1: the prolog without its set_fp.
    let x = img.words(&[(0x40 / 4) | 1 << 21 | 1 << 22 | 1 << 27, 0xE422_91E1]);
    let f = img.func(0x1000, x);
    let mem = stack(&[
        (SP, 0xF9),
        (SP + 8, RET),
        (SP + 0x90, 0x19),
        (SP + 0x98, 0x20),
    ]);
    let caller = SP + 0xA0;
    // Three instructions: two loads and the return.
    let mut r = regs(SP);
    r.x[FP] = 0xBAD;
    for (pc, sp, place) in [
        (0x1030, SP, Place::Body),
        (0x1034, SP, Place::Epilog),
        (0x1038, SP + 0x90, Place::Epilog),
        (0x103C, caller, Place::Epilog),
    ] {
        r.sp = sp;
        r.x[FP] = if place == Place::Body { SP } else { 0xBAD };
        let u = unwind(&img, &f, pc, &r, &mem).unwrap();
        assert_eq!((u.place, u.regs.sp), (place, caller), "pc {pc:#x}");
    }
}

#[test]
fn handler_is_reported_from_the_record() {
    let mut img = Image::new();
    let x = img.xdata(0x40, &[], &[0xE4], Some(0x1F00));
    let f = img.func(0x1000, x);
    let u = unwind(&img, &f, 0x1010, &regs(SP), &stack(&[])).unwrap();
    assert_eq!(
        u.handler,
        Some(Handler {
            rva: 0x1F00,
            data_rva: x + 12
        })
    );
}

#[test]
fn each_save_form_restores_its_registers() {
    // Stored order: last prolog instruction first.
    let codes = [
        0xE0, 0x00, 0x01, 0x00, // alloc_l 0x1000
        0xC0, 0x20, // alloc_m 0x200
        0x02, // alloc_s 0x20
        0xDC, 0x45, // save_freg d9 at 40
        0xD8, 0x03, // save_fregp d8,d9 at 24
        0xD6, 0x42, // save_lrpair x21,lr at 16
        0xD0, 0x41, // save_reg x20 at 8
        0xDE, 0x05, // save_freg_x d8 at [sp-48]!
        0xDA, 0x01, // save_fregp_x d8,d9 at [sp-16]!
        0xD4, 0x21, // save_reg_x x20 at [sp-16]!
        0xCC, 0x01, // save_regp_x x19,x20 at [sp-16]!
        0xE4,
    ];
    let (img, f) = with_codes(0x100, &codes);
    let body = SP + 0x1220;
    let mem = stack(&[
        (body, 0xD80),
        (body + 8, 0x200),
        (body + 16, 0x21),
        (body + 24, 0xD81),
        (body + 32, 0xD91),
        (body + 40, 0xD90),
        (body + 48, 0xD82),
        (body + 56, 0xD92),
        (body + 64, 0x201),
        (body + 80, 0x19),
        (body + 88, 0x202),
    ]);
    let u = unwind(&img, &f, 0x1080, &regs(SP), &mem).unwrap();
    assert_eq!(u.regs.sp, body + 96);
    // Each register ends with the value its earliest save stored.
    assert_eq!(
        (u.regs.x[X19], u.regs.x[X20], u.regs.x[X21]),
        (0x19, 0x202, 0x21)
    );
    assert_eq!((u.regs.d[0], u.regs.d[1]), (0xD82, 0xD92));
    // save_lrpair reads lr from the slot above x21.
    assert_eq!((u.regs.x[LR], u.regs.pc), (0xD81, 0xD81));
    assert_eq!(u.regs.x[X22], regs(SP).x[X22]);
}

#[test]
fn save_next_extends_the_pair_save_that_follows() {
    // Prolog: stp x19,x20,[sp,#-48]!; stp x21,x22,[sp,#16]; stp x23,x24,[sp,#32].
    let (img, f) = with_codes(0x40, &[0xE6, 0xE6, 0xCC, 0x05, 0xE4]);
    let mem = stack(&[
        (SP, 19),
        (SP + 8, 20),
        (SP + 16, 21),
        (SP + 24, 22),
        (SP + 32, 23),
        (SP + 40, 24),
    ]);
    let u = unwind(&img, &f, 0x1020, &regs(SP), &mem).unwrap();
    assert_eq!(u.regs.sp, SP + 48);
    assert_eq!(u.regs.x[..6], [19, 20, 21, 22, 23, 24]);

    // One instruction short of the end of the prolog, the last pair has
    // not been stored.
    let r = regs(SP);
    let u = unwind(&img, &f, 0x1008, &r, &mem).unwrap();
    assert_eq!(u.place, Place::Prolog);
    assert_eq!(u.regs.x[..6], [19, 20, 21, 22, r.x[4], r.x[5]]);

    // Vector pairs, not pre-indexed.
    let (img, f) = with_codes(0x40, &[0xE6, 0xD8, 0x02, 0xE4]);
    let mem = stack(&[(SP + 16, 8), (SP + 24, 9), (SP + 32, 10), (SP + 40, 11)]);
    let u = unwind(&img, &f, 0x1020, &regs(SP), &mem).unwrap();
    assert_eq!((u.regs.sp, &u.regs.d[..4]), (SP, &[8, 9, 10, 11][..]));

    // It must be followed by a pair save, and cannot repeat forever.
    let many = [[0xE6; 12].as_slice(), &[0xE4]].concat();
    for codes in [
        &[0xE6, 0xE4][..],
        &[0xE6, 0x01, 0xE4],
        &[0xE6, 0xD0, 0x00, 0xE4],
        &many,
    ] {
        let (img, f) = with_codes(0x40, codes);
        assert_eq!(
            unwind(&img, &f, 0x1030, &regs(SP), &mem).map(|_| ()),
            Err(UnwindError::BadUnwindInfo),
            "{codes:02x?}"
        );
    }
}

#[test]
fn frame_pointer_codes_take_sp_from_x29() {
    // Prolog: stp fp,lr,[sp,#-32]!; add fp,sp,#16.
    let (img, f) = with_codes(0x40, &[0xE2, 0x02, 0x83, 0xE4]);
    let mem = stack(&[(SP, 0xF9), (SP + 8, RET)]);
    let mut r = regs(SP - 0x1000);
    r.x[FP] = SP + 16;
    let u = unwind(&img, &f, 0x1010, &r, &mem).unwrap();
    assert_eq!((u.regs.sp, u.regs.x[FP], u.regs.pc), (SP + 32, 0xF9, RET));
}

#[test]
fn fragment_codes_continue_into_the_parent_prolog() {
    // "Region 2" of the document: a fragment that saves x21/x22 itself;
    // past end_c are the codes of the prolog that ran in its parent.
    let codes = [0xC8, 0x9C, 0xE5, 0xE1, 0xC8, 0x1E, 0x9F, 0xE4];
    let (img, f) = with_codes(0x40, &codes);
    let mem = stack(&[
        (SP, 0xF9),
        (SP + 8, RET),
        (SP + 224, 21),
        (SP + 232, 22),
        (SP + 240, 19),
        (SP + 248, 20),
    ]);
    let mut r = regs(SP);
    r.x[FP] = SP;
    let u = unwind(&img, &f, 0x1010, &r, &mem).unwrap();
    assert_eq!(
        (u.place, u.regs.sp, u.regs.pc),
        (Place::Body, SP + 256, RET)
    );
    assert_eq!(u.regs.x[..4], [19, 20, 21, 22]);

    // The fragment's own prolog is the one instruction before end_c.
    let u = unwind(&img, &f, 0x1000, &r, &mem).unwrap();
    assert_eq!((u.place, u.regs.sp), (Place::Prolog, SP + 256));
    assert_eq!(u.regs.x[..4], [19, 20, r.x[X21], r.x[X22]]);
    assert_eq!(
        unwind(&img, &f, 0x1004, &r, &mem).unwrap().place,
        Place::Body
    );
}

#[test]
fn custom_frames_restore_an_interrupted_context() {
    // MSFT_OP_MACHINE_FRAME: sp points at {sp, pc}.
    let (img, f) = with_codes(0x40, &[0xE9, 0xE4]);
    let mem = stack(&[(SP, 0x5000), (SP + 8, 0x6000)]);
    let u = unwind(&img, &f, 0x1010, &regs(SP), &mem).unwrap();
    assert_eq!(
        (u.regs.sp, u.regs.pc, u.establisher),
        (0x5000, 0x6000, 0x5000)
    );
    assert!(!u.unwound_to_call);

    // MSFT_OP_CONTEXT: sp points at a CONTEXT.
    let (img, f) = with_codes(0x40, &[0xEA, 0xE4]);
    let mut mem = stack(&[(SP + 0x100, 0x5000), (SP + 0x108, 0x6000)]);
    for n in 0..=30 {
        mem.insert(SP + 8 + 8 * n, 0x100 + n);
    }
    for n in 0..32 {
        mem.insert(SP + 0x110 + 16 * n, 0x200 + n);
    }
    let u = unwind(&img, &f, 0x1010, &regs(SP), &mem).unwrap();
    assert_eq!((u.regs.sp, u.regs.pc), (0x5000, 0x6000));
    assert_eq!(u.regs.x, core::array::from_fn(|i| 0x100 + 19 + i as u64));
    assert_eq!(u.regs.d, core::array::from_fn(|i| 0x200 + 8 + i as u64));
    assert!(!u.unwound_to_call);
    mem.remove(&(SP + 0x108));
    assert_eq!(
        unwind(&img, &f, 0x1010, &regs(SP), &mem),
        Err(UnwindError::BadStack)
    );
}

#[test]
fn custom_codes_are_not_instructions() {
    // A routine of a real driver: no prolog, and an epilog of
    // `add sp,sp,#16; ret` that also clears "unwound to call".
    let mut img = Image::new();
    let x = img.xdata(0x2C, &[(0x18, 1)], &[0xE4, 0x01, 0xEC, 0xE4], None);
    let f = img.func(0x1000, x);
    let r = regs(SP);
    let mem = stack(&[]);
    let u = unwind(&img, &f, 0x1000, &r, &mem).unwrap();
    assert_eq!(
        (u.place, u.regs.sp, u.regs.pc, u.unwound_to_call),
        (Place::Body, SP, r.x[LR], true)
    );
    let u = unwind(&img, &f, 0x1018, &r, &mem).unwrap();
    assert_eq!(
        (u.place, u.regs.sp, u.unwound_to_call),
        (Place::Epilog, SP + 16, false)
    );
    let u = unwind(&img, &f, 0x101C, &r, &mem).unwrap();
    assert_eq!(
        (u.place, u.regs.sp, u.unwound_to_call),
        (Place::Epilog, SP, false)
    );
    // The epilog is two instructions long, not three.
    let u = unwind(&img, &f, 0x1020, &r, &mem).unwrap();
    assert_eq!((u.place, u.unwound_to_call), (Place::Body, true));
}

#[test]
fn malformed_code_sequences_are_errors() {
    let r = regs(SP);
    let mem = stack(&[]);
    // No end; an unsupported code; a save from an unreadable stack.
    for (codes, err) in [
        (&[0xE3, 0xE3, 0xE3, 0xE3][..], UnwindError::BadUnwindInfo),
        (&[0x01, 0xE8, 0xE4], UnwindError::Unsupported(0xE8)),
        (&[0xD0, 0x00, 0xE4], UnwindError::BadStack),
        (&[0x81, 0xE4], UnwindError::BadStack),
        (&[0xE9, 0xE4], UnwindError::BadStack),
    ] {
        let (img, f) = with_codes(0x40, codes);
        assert_eq!(
            unwind(&img, &f, 0x1020, &r, &mem).map(|_| ()),
            Err(err),
            "{codes:02x?}"
        );
    }
    // An epilog scope whose codes never end.
    let mut img = Image::new();
    let x = img.xdata(0x40, &[(0x30, 1)], &[0xE4, 0xE3, 0xE3, 0xE3], None);
    let f = img.func(0x1000, x);
    assert_eq!(
        unwind(&img, &f, 0x1030, &r, &mem).map(|_| ()),
        Err(UnwindError::BadUnwindInfo)
    );
    // A record that is no longer where the entry says.
    let gone = FunctionEntry {
        begin: 0x1000,
        len: 0x40,
        unwind: UnwindData::Xdata(IMAGE_SIZE as u32),
    };
    assert_eq!(
        unwind(&img, &gone, 0x1020, &r, &mem).map(|_| ()),
        Err(UnwindError::OutOfBounds)
    );
}

#[test]
fn leaf_unwind_returns_through_lr() {
    let r = regs(SP);
    let u = unwind_leaf(&r);
    assert_eq!((u.pc, u.sp, u.x), (r.x[LR], SP, r.x));
}

#[test]
fn canonical_expands_the_documented_packed_example() {
    // "Example 1: Frame-chained, compact-form": str x19,[sp,#-0x10]!;
    // sub sp,sp,#0x810; stp fp,lr,[sp]; mov fp,sp.
    let word = 0x4161_01ED;
    assert_eq!(word, packed(1, 492, 0, 1, 0, 3, 2080));
    let want = [
        Op::SetFp,
        pair(x(29), x(30), 0, false),
        Op::Alloc(0x810),
        save(x(19), 0x10, true),
        Op::End,
    ];
    assert_eq!(canonical(word, false).unwrap().ops(), want);
    assert_eq!(canonical(word, true).unwrap().ops(), &want[1..]);
}

#[test]
fn canonical_follows_the_table_for_each_step() {
    let d = Reg::D;
    let prolog = |reg_f, reg_i, h, cr, frame| {
        canonical(packed(1, 0x100, reg_f, reg_i, h, cr, frame), false)
            .unwrap()
            .ops()
            .to_vec()
    };
    let epilog = |reg_f, reg_i, h, cr, frame| {
        canonical(packed(1, 0x100, reg_f, reg_i, h, cr, frame), true)
            .unwrap()
            .ops()
            .to_vec()
    };

    // lr saved with an odd count of integer registers: one pair with x21.
    assert_eq!(
        prolog(0, 3, 0, 1, 0x40),
        [
            Op::Alloc(32),
            pair(x(21), x(30), 16, false),
            pair(x(19), x(20), 32, true),
            Op::End
        ]
    );
    // lr after an even count, vector registers, homed parameters.
    let want = [
        Op::Alloc(16),
        Op::Nop,
        Op::Nop,
        Op::Nop,
        Op::Nop,
        pair(d(8), d(9), 24, false),
        save(x(30), 16, false),
        pair(x(19), x(20), 112, true),
        Op::End,
    ];
    assert_eq!(prolog(1, 2, 1, 1, 0x80), want);
    // The epilog has no homing instructions.
    assert_eq!(epilog(1, 2, 1, 1, 0x80), [&want[..1], &want[5..]].concat());

    // Signed return address, an odd count of vector registers allocating
    // the save area, a small chained frame.
    let want = [
        Op::SetFp,
        pair(x(29), x(30), 32, true),
        save(d(10), 16, false),
        pair(d(8), d(9), 32, true),
        Op::PacSignLr,
        Op::End,
    ];
    assert_eq!(prolog(2, 0, 0, 2, 0x40), want);
    assert_eq!(epilog(2, 0, 0, 2, 0x40), &want[1..]);

    // Locals over 4080 bytes take two subtractions.
    assert_eq!(
        prolog(0, 0, 0, 0, 0x1100),
        [Op::Alloc(0x1100 - 4080), Op::Alloc(4080), Op::End]
    );
    assert_eq!(
        prolog(0, 0, 0, 3, 0x1100),
        [
            Op::SetFp,
            pair(x(29), x(30), 0, false),
            Op::Alloc(0x1100 - 4080),
            Op::Alloc(4080),
            Op::End
        ]
    );
    // Locals between 512 and 4080 bytes: one subtraction, then the pair.
    assert_eq!(
        prolog(0, 0, 0, 3, 0x260),
        [
            Op::SetFp,
            pair(x(29), x(30), 0, false),
            Op::Alloc(0x260),
            Op::End
        ]
    );
    assert_eq!(
        prolog(0, 0, 0, 3, 0x200),
        [Op::SetFp, pair(x(29), x(30), 0x200, true), Op::End]
    );
    // All ten integer registers and all eight vector registers.
    let all = prolog(7, 10, 0, 0, 0x90);
    assert_eq!(all.len(), 5 + 4 + 1);
    assert_eq!(all[0], pair(d(14), d(15), 80 + 48, false));
    assert_eq!(all[4], pair(x(27), x(28), 64, false));
    assert_eq!(all[8], pair(x(19), x(20), 0x90, true));
    // An odd count of integer registers without lr ends in a single save.
    assert_eq!(prolog(0, 1, 0, 0, 0x10), [save(x(19), 16, true), Op::End]);
    assert_eq!(
        prolog(0, 3, 0, 0, 0x20),
        [
            save(x(21), 16, false),
            pair(x(19), x(20), 32, true),
            Op::End
        ]
    );

    // With nothing else to carry the pre-decrement: lr alone, x19 with
    // lr, and the first homing store.
    assert_eq!(
        prolog(0, 0, 0, 1, 0x20),
        [Op::Alloc(16), save(x(30), 16, true), Op::End]
    );
    assert_eq!(
        prolog(0, 1, 0, 1, 0x10),
        [pair(x(19), x(30), 16, true), Op::End]
    );
    let want = [
        Op::Alloc(16),
        Op::Nop,
        Op::Nop,
        Op::Nop,
        Op::Alloc(64),
        Op::End,
    ];
    assert_eq!(prolog(0, 0, 1, 0, 0x50), want);
    assert_eq!(
        epilog(0, 0, 1, 0, 0x50),
        [Op::Alloc(16), Op::Alloc(64), Op::End]
    );
    // No frame at all.
    assert_eq!(prolog(0, 0, 0, 0, 0), [Op::End]);
}

#[test]
fn canonical_rejects_impossible_packed_data() {
    let bad =
        |reg_f, reg_i, h, cr, frame| canonical(packed(1, 0x100, reg_f, reg_i, h, cr, frame), false);
    // More integer registers than x19..x28; a save area larger than the
    // frame; a chained frame with no room for the frame record.
    assert_eq!(bad(0, 11, 0, 0, 0x100), Err(UnwindError::BadUnwindInfo));
    assert_eq!(bad(0, 4, 0, 0, 0x10), Err(UnwindError::BadUnwindInfo));
    assert_eq!(bad(0, 2, 0, 3, 0x10), Err(UnwindError::BadUnwindInfo));
    let mut img = Image::new();
    let f = img.func(0x1000, packed(1, 0x100, 0, 11, 0, 0, 0x100));
    assert_eq!(
        unwind(&img, &f, 0x1000, &regs(SP), &stack(&[])).map(|_| ()),
        Err(UnwindError::BadUnwindInfo)
    );
    let f = img.func(0x1100, packed(1, 0x100, 0, 2, 0, 3, 0x10));
    assert_eq!(
        unwind(&img, &f, 0x1180, &regs(SP), &stack(&[])).map(|_| ()),
        Err(UnwindError::BadUnwindInfo)
    );
}

#[test]
fn packed_unwind_of_the_documented_example() {
    let mut img = Image::new();
    let f = img.func(0x1000, 0x4161_01ED);
    assert_eq!(f.len, 492);
    let body = SP;
    let caller = body + 0x810 + 0x10;
    let mem = stack(&[(body, 0xF9), (body + 8, RET), (body + 0x810, 0x19)]);
    let mut r = regs(body);
    r.x[FP] = body;
    let u = unwind(&img, &f, 0x1000 + 16, &r, &mem).unwrap();
    assert_eq!((u.place, u.regs.sp, u.regs.pc), (Place::Body, caller, RET));
    assert_eq!((u.regs.x[X19], u.regs.x[FP]), (0x19, 0xF9));
    assert_eq!((u.handler, u.unwound_to_call), (None, true));

    // Prolog: str x19; sub sp; stp fp,lr; mov fp,sp.
    for (pc, sp, x19, pc_from_stack) in [
        (0x1000, caller, false, false),
        (0x1004, caller - 0x10, true, false),
        (0x1008, body, true, false),
        (0x100C, body, true, true),
    ] {
        let r = regs(sp);
        let u = unwind(&img, &f, pc, &r, &mem).unwrap();
        assert_eq!((u.place, u.regs.sp), (Place::Prolog, caller), "pc {pc:#x}");
        assert_eq!(
            u.regs.x[X19],
            if x19 { 0x19 } else { r.x[X19] },
            "pc {pc:#x}"
        );
        assert_eq!(
            u.regs.pc,
            if pc_from_stack { RET } else { r.x[LR] },
            "pc {pc:#x}"
        );
    }
    // Epilog, the last four instructions: ldp fp,lr; add sp; ldr x19; ret.
    let end = 0x1000 + 492;
    for (pc, sp, place) in [
        (end - 20, body, Place::Body),
        (end - 16, body, Place::Epilog),
        (end - 12, body, Place::Epilog),
        (end - 8, caller - 0x10, Place::Epilog),
        (end - 4, caller, Place::Epilog),
    ] {
        let mut r = regs(sp);
        r.x[FP] = if place == Place::Body { body } else { 0xBAD };
        let u = unwind(&img, &f, pc, &r, &mem).unwrap();
        assert_eq!((u.place, u.regs.sp), (place, caller), "pc {pc:#x}");
    }
}

#[test]
fn packed_fragment_has_neither_prolog_nor_epilog() {
    let mut img = Image::new();
    let f = img.func(0x1000, packed(2, 0x40, 0, 2, 0, 3, 0x30));
    let mem = stack(&[(SP, 0xF9), (SP + 8, RET), (SP + 0x20, 19), (SP + 0x28, 20)]);
    let mut r = regs(SP);
    r.x[FP] = SP;
    for pc in [0x1000, 0x1004, 0x1020, 0x1038, 0x103C] {
        let u = unwind(&img, &f, pc, &r, &mem).unwrap();
        assert_eq!(
            (u.place, u.regs.sp, u.regs.pc),
            (Place::Body, SP + 0x30, RET),
            "pc {pc:#x}"
        );
        assert_eq!(u.regs.x[..2], [19, 20]);
    }
}

/// The bytes of an unwind code, where the format has one for the
/// operation. The inverse of `decode`, written from the same table.
fn encode(op: &Op) -> Option<Vec<u8>> {
    let two = |base: u32, reg: u32, z: u32, zbits: u32| {
        let v = base << 8 | reg << zbits | z;
        Some(vec![(v >> 8) as u8, v as u8])
    };
    let pre_z = |offset: u32, pre: bool| offset / 8 - u32::from(pre);
    match *op {
        Op::Alloc(n) if n < 512 => Some(vec![(n / 16) as u8]),
        Op::Alloc(n) if n < 0x8000 => two(0xC0, 0, n / 16, 0),
        Op::Alloc(n) => Some(vec![0xE0, (n >> 20) as u8, (n >> 12) as u8, (n >> 4) as u8]),
        Op::SavePair {
            a: Reg::X(29),
            offset,
            pre,
            ..
        } => Some(vec![
            if pre { 0x80 } else { 0x40 } | pre_z(offset, pre) as u8,
        ]),
        Op::SavePair {
            a: Reg::X(n),
            b: Reg::X(30),
            offset,
            pre: false,
        } if n % 2 == 1 => two(0xD6, u32::from(n - 19) / 2, offset / 8, 6),
        Op::SavePair { b: Reg::X(30), .. } => None,
        Op::SavePair {
            a: Reg::X(n),
            offset,
            pre,
            ..
        } => two(
            if pre { 0xCC } else { 0xC8 },
            u32::from(n - 19),
            pre_z(offset, pre),
            6,
        ),
        Op::SavePair {
            a: Reg::D(n),
            offset,
            pre,
            ..
        } => two(
            if pre { 0xDA } else { 0xD8 },
            u32::from(n - 8),
            pre_z(offset, pre),
            6,
        ),
        Op::Save {
            reg: Reg::X(30), ..
        } => None,
        Op::Save {
            reg: Reg::X(n),
            offset,
            pre: false,
        } => two(0xD0, u32::from(n - 19), offset / 8, 6),
        Op::Save {
            reg: Reg::X(n),
            offset,
            pre: true,
        } => two(0xD4, u32::from(n - 19), offset / 8 - 1, 5),
        Op::Save {
            reg: Reg::D(n),
            offset,
            pre: false,
        } => two(0xDC, u32::from(n - 8), offset / 8, 6),
        Op::Save {
            reg: Reg::D(n),
            offset,
            pre: true,
        } => two(0xDE, u32::from(n - 8), offset / 8 - 1, 5),
        Op::SetFp => Some(vec![0xE1]),
        Op::Nop => Some(vec![0xE3]),
        Op::End => Some(vec![0xE4]),
        Op::PacSignLr => Some(vec![0xFC]),
        _ => None,
    }
}

fn encode_all(ops: &[Op]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for op in ops {
        let bytes = encode(op)?;
        assert_eq!(
            decode(&bytes),
            Ok((*op, bytes.len())),
            "encode and decode disagree"
        );
        out.extend(bytes);
    }
    Some(out)
}

/// Packed unwind data and the `.xdata` record the document says it stands
/// for must unwind alike from every instruction of the function.
#[test]
fn packed_and_equivalent_xdata_unwind_alike() {
    let mut compared = 0;
    for bits in 0..(8 * 11 * 2 * 4) {
        let (reg_f, reg_i, h, cr) = (bits % 8, bits / 8 % 11, bits / 88 % 2, bits / 176);
        for extra in [0, 16, 0x1F0, 0x200, 0x210, 0xFF0, 0x1000, 0x1800] {
            let int = reg_i * 8 + if cr == 1 { 8 } else { 0 };
            let fp = if reg_f == 0 { 0 } else { (reg_f + 1) * 8 };
            let frame = ((int + fp + 64 * h + 15) & !15) + extra;
            if frame > 511 * 16 {
                continue;
            }
            let word = packed(1, 0x200, reg_f, reg_i, h, cr, frame);
            let (Ok(prolog), Ok(epilog)) = (canonical(word, false), canonical(word, true)) else {
                assert!(
                    cr >= 2 && extra == 0,
                    "only a chained frame without locals is refused"
                );
                continue;
            };
            let (Some(p), Some(e)) = (encode_all(prolog.ops()), encode_all(epilog.ops())) else {
                continue;
            };
            let mut img = Image::new();
            let by_packed = img.func(0x1000, word);
            let start = 0x200 - 4 * epilog.ops().len() as u32;
            let x = img.xdata(0x200, &[(start, p.len() as u32)], &[p, e].concat(), None);
            let by_xdata = img.func(0x1200, x);
            for offset in (0..0x200).step_by(4) {
                let mut r = regs(SP);
                r.x[FP] = SP + 0x40;
                // Every address is readable and holds a value of its own.
                let mut read = |a: u64| Some(a.wrapping_mul(0x9E37_79B9_7F4A_7C15));
                let a =
                    virtual_unwind(&img.bytes, &by_packed, 0x1000 + offset, &r, &mut read).unwrap();
                let b =
                    virtual_unwind(&img.bytes, &by_xdata, 0x1200 + offset, &r, &mut read).unwrap();
                assert_eq!(a, b, "word {word:#x} offset {offset:#x}");
                assert!(a.regs.sp >= SP);
            }
            compared += 1;
        }
    }
    // Most of the field space has an encodable equivalent.
    assert!(compared > 3000, "{compared}");
}
