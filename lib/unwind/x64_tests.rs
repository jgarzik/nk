//! x64 tests against images assembled here: code bytes, `.pdata` and
//! unwind records laid out as a loader would map them, and a stack that
//! is a map from address to value.

use crate::x64::*;
use crate::{Place, UnwindError};
use std::collections::HashMap;

const PDATA: u32 = 0x2000;
const XDATA: u32 = 0x3000;
const IMAGE_SIZE: usize = 0x4000;

/// The stack pointer the tests start from.
const SP: u64 = 0xFFFF_8000_0010_0000;
/// The return address the simulated caller left.
const RET: u64 = 0xFFFF_8000_2000_1234;

struct Image {
    bytes: Vec<u8>,
    funcs: u32,
    xdata: u32,
}

/// One unwind code slot.
fn slot(offset: u8, op: u8, info: u8) -> u16 {
    u16::from(offset) | u16::from(op | info << 4) << 8
}

impl Image {
    fn new() -> Self {
        Self {
            bytes: vec![0; IMAGE_SIZE],
            funcs: 0,
            xdata: XDATA,
        }
    }

    fn put(&mut self, rva: u32, bytes: &[u8]) {
        self.bytes[rva as usize..][..bytes.len()].copy_from_slice(bytes);
    }

    /// Append an `UNWIND_INFO`; returns its RVA. `tail` is whatever
    /// follows the padded code array.
    fn info(
        &mut self,
        version: u8,
        flags: u8,
        prolog: u8,
        frame: u8,
        codes: &[u16],
        tail: &[u32],
    ) -> u32 {
        let rva = self.xdata;
        let mut b = vec![version | flags << 3, prolog, codes.len() as u8, frame];
        b.extend(codes.iter().flat_map(|c| c.to_le_bytes()));
        if codes.len() % 2 == 1 {
            b.extend([0, 0]);
        }
        b.extend(tail.iter().flat_map(|t| t.to_le_bytes()));
        self.put(rva, &b);
        self.xdata += (b.len() as u32).next_multiple_of(4);
        rva
    }

    /// Append a `.pdata` entry.
    fn func(&mut self, begin: u32, end: u32, unwind: u32) -> RuntimeFunction {
        let words: Vec<u8> = [begin, end, unwind]
            .iter()
            .flat_map(|w| w.to_le_bytes())
            .collect();
        self.put(PDATA + 12 * self.funcs, &words);
        self.funcs += 1;
        RuntimeFunction { begin, end, unwind }
    }

    fn lookup(&self, rva: u32) -> Result<Option<RuntimeFunction>, UnwindError> {
        lookup(&self.bytes, PDATA, 12 * self.funcs, rva)
    }
}

/// Registers with a recognisable value in each, and `rsp` as given.
fn regs(rsp: u64) -> Regs {
    let mut r = Regs {
        gpr: core::array::from_fn(|i| 0xAAAA_0000 + i as u64),
        rip: 0,
        xmm: core::array::from_fn(|i| 0xBBBB_0000 + i as u128),
    };
    r.gpr[RSP] = rsp;
    r
}

fn stack(slots: &[(u64, u64)]) -> HashMap<u64, u64> {
    slots.iter().copied().collect()
}

fn unwind(
    img: &Image,
    f: &RuntimeFunction,
    pc: u32,
    r: &Regs,
    mem: &HashMap<u64, u64>,
) -> Result<Unwound, UnwindError> {
    virtual_unwind(&img.bytes, f, pc, r, &mut |a| mem.get(&a).copied())
}

const RBX: usize = 3;
const RBP: usize = 5;
const RSI: usize = 6;
const RDI: usize = 7;
const R12: usize = 12;
const R13: usize = 13;

/// `push rbx; push rdi; sub rsp, 0x20; ...; add rsp, 0x20; pop rdi;
/// pop rbx; ret` at 0x1000, with the given unwind-info version.
fn plain(img: &mut Image, version: u8, flags: u8, tail: &[u32]) -> RuntimeFunction {
    img.put(0x1000, &[0x40, 0x53, 0x57, 0x48, 0x83, 0xEC, 0x20]);
    img.put(0x1007, &[0x90; 9]);
    img.put(0x1010, &[0x48, 0x83, 0xC4, 0x20, 0x5F, 0x5B, 0xC3]);
    let mut codes = vec![
        slot(7, UWOP_ALLOC_SMALL, 3),
        slot(3, UWOP_PUSH_NONVOL, RDI as u8),
        slot(2, UWOP_PUSH_NONVOL, RBX as u8),
    ];
    if version == 2 {
        // One epilog of 3 bytes (the pops and the return) ending the function.
        codes.splice(0..0, [slot(3, UWOP_EPILOG, 1), slot(0, UWOP_EPILOG, 0)]);
    }
    let info = img.info(version, flags, 7, 0, &codes, tail);
    img.func(0x1000, 0x1017, info)
}

/// The stack of `plain` in its body with `rsp == SP`.
fn plain_stack() -> HashMap<u64, u64> {
    stack(&[(SP + 0x20, 0xD1), (SP + 0x28, 0xB1), (SP + 0x30, RET)])
}

#[test]
fn lookup_finds_the_entry_covering_an_rva() {
    let mut img = Image::new();
    let a = img.func(0x1000, 0x1010, 0x3000);
    let b = img.func(0x1020, 0x1030, 0x3010);
    let c = img.func(0x1030, 0x1100, 0x3020);
    assert_eq!(img.lookup(0x0FFF), Ok(None));
    assert_eq!(img.lookup(0x1000), Ok(Some(a)));
    assert_eq!(img.lookup(0x100F), Ok(Some(a)));
    assert_eq!(
        img.lookup(0x1010),
        Ok(None),
        "the gap between two functions"
    );
    assert_eq!(img.lookup(0x1020), Ok(Some(b)));
    assert_eq!(
        locate(&img.bytes, PDATA, 36, 0x1020),
        Ok(Some((PDATA + 12, b))),
        "where the entry itself is"
    );
    assert_eq!(img.lookup(0x102F), Ok(Some(b)));
    assert_eq!(img.lookup(0x1030), Ok(Some(c)));
    assert_eq!(img.lookup(0x10FF), Ok(Some(c)));
    assert_eq!(img.lookup(0x1100), Ok(None));
    assert_eq!(entry(&img.bytes, PDATA, 1), Ok(b));
    assert_eq!(
        entry(&img.bytes, PDATA, usize::MAX),
        Err(UnwindError::OutOfBounds)
    );
    assert_eq!(
        lookup(&img.bytes, PDATA, 0, 0x1000),
        Ok(None),
        "an empty directory"
    );
    assert_eq!(
        lookup(&img.bytes, IMAGE_SIZE as u32 - 12, 24, 0x1000),
        Err(UnwindError::OutOfBounds)
    );
}

#[test]
fn lookup_follows_an_indirect_entry() {
    let mut img = Image::new();
    // Bit 0 of the unwind RVA: it names another RUNTIME_FUNCTION.
    img.func(0x1000, 0x1010, 0x3800 | 1);
    img.put(
        0x3800,
        &[0x00, 0x18, 0, 0, 0x40, 0x18, 0, 0, 0x00, 0x30, 0, 0],
    );
    let target = RuntimeFunction {
        begin: 0x1800,
        end: 0x1840,
        unwind: 0x3000,
    };
    assert_eq!(img.lookup(0x1008), Ok(Some(target)));
    // The entry a handler is told of is the one pointed at.
    assert_eq!(
        locate(&img.bytes, PDATA, 12, 0x1008),
        Ok(Some((0x3800, target)))
    );

    // An entry that names itself never resolves.
    img.func(0x1100, 0x1110, (PDATA + 12) | 1);
    assert_eq!(img.lookup(0x1100), Err(UnwindError::ChainTooDeep));
}

#[test]
fn parse_decodes_every_opcode_and_counts_its_slots() {
    let mut img = Image::new();
    let codes = [
        slot(0x40, UWOP_SAVE_XMM128_FAR, 15),
        0x5678,
        0x0012,
        slot(0x38, UWOP_SAVE_XMM128, 6),
        0x0004,
        slot(0x30, UWOP_SAVE_NONVOL_FAR, 14),
        0x4320,
        0x0001,
        slot(0x28, UWOP_SAVE_NONVOL, 6),
        0x0009,
        slot(0x20, UWOP_SET_FPREG, 0),
        slot(0x18, UWOP_ALLOC_LARGE, 1),
        0x0008,
        0x0010,
        slot(0x10, UWOP_ALLOC_LARGE, 0),
        0x0100,
        slot(0x08, UWOP_ALLOC_SMALL, 15),
        slot(0x04, UWOP_PUSH_NONVOL, 13),
        slot(0x00, UWOP_PUSH_MACHFRAME, 1),
    ];
    let rva = img.info(
        1,
        UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER,
        0x40,
        0x35,
        &codes,
        &[0x1F00, 7],
    );
    let info = UnwindInfo::parse(&img.bytes, rva).unwrap();
    assert_eq!((info.version, info.flags, info.prolog_size), (1, 3, 0x40));
    assert_eq!((info.frame_reg, info.frame_offset), (5, 0x30));
    // 19 slots are padded to 20: the handler follows the padding.
    assert_eq!(
        info.tail,
        Tail::Handler {
            rva: 0x1F00,
            data_rva: rva + 4 + 40 + 4
        }
    );
    let got: Vec<(u8, u8, Op)> = info.codes().map(|c| (c.offset, c.opcode, c.op)).collect();
    let want = [
        (
            0x40,
            9,
            Op::SaveXmm128 {
                reg: 15,
                offset: 0x12_5678,
            },
        ),
        (
            0x38,
            8,
            Op::SaveXmm128 {
                reg: 6,
                offset: 0x40,
            },
        ),
        (
            0x30,
            5,
            Op::SaveNonvol {
                reg: 14,
                offset: 0x1_4320,
            },
        ),
        (
            0x28,
            4,
            Op::SaveNonvol {
                reg: 6,
                offset: 0x48,
            },
        ),
        (0x20, 3, Op::SetFpreg),
        (0x18, 1, Op::Alloc(0x10_0008)),
        (0x10, 1, Op::Alloc(0x800)),
        (0x08, 2, Op::Alloc(128)),
        (0x04, 0, Op::PushNonvol(13)),
        (0x00, 10, Op::PushMachframe { error_code: true }),
    ];
    assert_eq!(got, want);
}

#[test]
fn parse_reads_the_tail_the_flags_announce() {
    let mut img = Image::new();
    let none = img.info(1, 0, 0, 0, &[], &[]);
    assert_eq!(
        UnwindInfo::parse(&img.bytes, none).unwrap().tail,
        Tail::None
    );
    assert_eq!(
        UnwindInfo::parse(&img.bytes, none).unwrap().codes().count(),
        0
    );

    let chained = img.info(
        1,
        UNW_FLAG_CHAININFO,
        0,
        0,
        &[slot(4, UWOP_ALLOC_SMALL, 0)],
        &[0x1000, 0x1080, none],
    );
    let parent = RuntimeFunction {
        begin: 0x1000,
        end: 0x1080,
        unwind: none,
    };
    assert_eq!(
        UnwindInfo::parse(&img.bytes, chained).unwrap().tail,
        Tail::Chained(parent)
    );

    let handler = img.info(
        2,
        UNW_FLAG_UHANDLER,
        0,
        0,
        &[slot(2, UWOP_EPILOG, 1), slot(0, UWOP_EPILOG, 0)],
        &[0x1F00],
    );
    let info = UnwindInfo::parse(&img.bytes, handler).unwrap();
    assert_eq!(info.version, 2);
    assert_eq!(
        info.tail,
        Tail::Handler {
            rva: 0x1F00,
            data_rva: handler + 12
        }
    );
}

#[test]
fn parse_rejects_malformed_records() {
    let bad = |version: u8, codes: &[u16]| {
        let mut img = Image::new();
        let rva = img.info(version, 0, 0, 0, codes, &[]);
        UnwindInfo::parse(&img.bytes, rva).map(|_| ())
    };
    assert_eq!(bad(0, &[]), Err(UnwindError::BadUnwindInfo));
    assert_eq!(bad(3, &[]), Err(UnwindError::BadUnwindInfo));
    // A two-slot code in the last slot; a three-slot code with one left.
    assert_eq!(
        bad(1, &[slot(4, UWOP_ALLOC_LARGE, 0)]),
        Err(UnwindError::BadUnwindInfo)
    );
    assert_eq!(
        bad(1, &[slot(4, UWOP_SAVE_NONVOL, 3)]),
        Err(UnwindError::BadUnwindInfo)
    );
    assert_eq!(
        bad(1, &[slot(4, UWOP_SAVE_XMM128, 6)]),
        Err(UnwindError::BadUnwindInfo)
    );
    assert_eq!(
        bad(1, &[slot(4, UWOP_ALLOC_LARGE, 1), 0]),
        Err(UnwindError::BadUnwindInfo)
    );
    assert_eq!(
        bad(1, &[slot(4, UWOP_SAVE_NONVOL_FAR, 3), 0]),
        Err(UnwindError::BadUnwindInfo)
    );
    assert_eq!(
        bad(1, &[slot(4, UWOP_SAVE_XMM128_FAR, 6), 0]),
        Err(UnwindError::BadUnwindInfo)
    );
    // Operation info the format does not define.
    assert_eq!(
        bad(1, &[slot(4, UWOP_ALLOC_LARGE, 2), 0]),
        Err(UnwindError::BadUnwindInfo)
    );
    assert_eq!(
        bad(1, &[slot(0, UWOP_PUSH_MACHFRAME, 2)]),
        Err(UnwindError::BadUnwindInfo)
    );
    // Opcode 6 means an epilog only from version 2; 7 and 11+ never.
    assert_eq!(
        bad(1, &[slot(4, UWOP_EPILOG, 0), 0]),
        Err(UnwindError::Unsupported(6))
    );
    assert_eq!(bad(2, &[slot(4, UWOP_EPILOG, 0), 0]), Ok(()));
    assert_eq!(
        bad(2, &[slot(4, 7, 0), 0, 0]),
        Err(UnwindError::Unsupported(7))
    );
    assert_eq!(bad(1, &[slot(4, 11, 0)]), Err(UnwindError::Unsupported(11)));

    let img = Image::new();
    for rva in [IMAGE_SIZE as u32 - 2, IMAGE_SIZE as u32, u32::MAX] {
        assert_eq!(
            UnwindInfo::parse(&img.bytes, rva).map(|_| ()),
            Err(UnwindError::OutOfBounds)
        );
    }
    // A record whose codes, chained entry or handler run off the image.
    let mut img = Image::new();
    let end = IMAGE_SIZE as u32;
    img.put(end - 4, &[1, 0, 4, 0]);
    assert_eq!(
        UnwindInfo::parse(&img.bytes, end - 4).map(|_| ()),
        Err(UnwindError::OutOfBounds)
    );
    img.put(end - 4, &[1 | UNW_FLAG_CHAININFO << 3, 0, 0, 0]);
    assert_eq!(
        UnwindInfo::parse(&img.bytes, end - 4).map(|_| ()),
        Err(UnwindError::OutOfBounds)
    );
    img.put(end - 4, &[1 | UNW_FLAG_EHANDLER << 3, 0, 0, 0]);
    assert_eq!(
        UnwindInfo::parse(&img.bytes, end - 4).map(|_| ()),
        Err(UnwindError::OutOfBounds)
    );
}

#[test]
fn body_unwind_restores_pushes_and_names_the_handler() {
    let mut img = Image::new();
    let f = plain(&mut img, 1, UNW_FLAG_EHANDLER, &[0x1F00, 0x55]);
    let mem = plain_stack();
    let r = regs(SP);
    let u = unwind(&img, &f, 0x1008, &r, &mem).unwrap();
    assert_eq!(u.place, Place::Body);
    assert_eq!(u.establisher, SP);
    assert!(!u.machine_frame);
    assert_eq!(u.regs.rip, RET);
    assert_eq!(u.regs.gpr[RSP], SP + 0x38);
    assert_eq!((u.regs.gpr[RDI], u.regs.gpr[RBX]), (0xD1, 0xB1));
    // Everything the prolog did not save is untouched.
    assert_eq!(u.regs.gpr[RSI], r.gpr[RSI]);
    assert_eq!(u.regs.xmm, r.xmm);
    let h = u.handler.unwrap();
    assert_eq!((h.rva, h.data_rva), (0x1F00, f.unwind + 4 + 8 + 4));
    assert!(h.exception && !h.termination);

    // The first byte past the prolog is body.
    assert_eq!(unwind(&img, &f, 0x1007, &r, &mem).unwrap(), u);
}

#[test]
fn a_termination_handler_is_reported_as_one() {
    let mut img = Image::new();
    let f = plain(&mut img, 1, UNW_FLAG_UHANDLER, &[0x1F00]);
    let h = unwind(&img, &f, 0x1008, &regs(SP), &plain_stack())
        .unwrap()
        .handler
        .unwrap();
    assert!(h.termination && !h.exception);

    let mut img = Image::new();
    let f = plain(&mut img, 1, 0, &[]);
    assert_eq!(
        unwind(&img, &f, 0x1008, &regs(SP), &plain_stack())
            .unwrap()
            .handler,
        None
    );
}

#[test]
fn prolog_unwind_undoes_only_what_has_run() {
    let mut img = Image::new();
    let f = plain(&mut img, 1, UNW_FLAG_EHANDLER, &[0x1F00]);
    let caller = SP + 0x38;
    // (pc, rsp at pc, registers already pushed)
    for (pc, rsp, rdi, rbx) in [
        (0x1000, caller - 8, false, false),
        (0x1002, caller - 16, false, true),
        (0x1003, caller - 24, true, true),
    ] {
        let r = regs(rsp);
        let u = unwind(&img, &f, pc, &r, &plain_stack()).unwrap();
        assert_eq!(u.place, Place::Prolog, "pc {pc:#x}");
        assert_eq!(
            u.handler, None,
            "no handler runs for a frame still being built"
        );
        assert_eq!(u.establisher, rsp);
        assert_eq!((u.regs.gpr[RSP], u.regs.rip), (caller, RET), "pc {pc:#x}");
        assert_eq!(
            u.regs.gpr[RDI],
            if rdi { 0xD1 } else { r.gpr[RDI] },
            "pc {pc:#x}"
        );
        assert_eq!(
            u.regs.gpr[RBX],
            if rbx { 0xB1 } else { r.gpr[RBX] },
            "pc {pc:#x}"
        );
    }
    // A code takes effect at the offset it names, not one byte earlier.
    let u = unwind(&img, &f, 0x1001, &regs(caller - 8), &plain_stack()).unwrap();
    assert_eq!((u.regs.gpr[RSP], u.regs.rip), (caller, RET));
}

#[test]
fn version_1_epilog_is_recognised_by_its_instructions() {
    let mut img = Image::new();
    let f = plain(&mut img, 1, UNW_FLAG_EHANDLER, &[0x1F00]);
    let caller = SP + 0x38;
    for (pc, rsp, rdi, rbx) in [
        (0x1010, SP, true, true),
        (0x1014, SP + 0x20, true, true),
        (0x1015, SP + 0x28, false, true),
        (0x1016, SP + 0x30, false, false),
    ] {
        let r = regs(rsp);
        let u = unwind(&img, &f, pc, &r, &plain_stack()).unwrap();
        assert_eq!(u.place, Place::Epilog, "pc {pc:#x}");
        assert_eq!(u.handler, None);
        assert_eq!((u.regs.gpr[RSP], u.regs.rip), (caller, RET), "pc {pc:#x}");
        assert_eq!(
            u.regs.gpr[RDI],
            if rdi { 0xD1 } else { r.gpr[RDI] },
            "pc {pc:#x}"
        );
        assert_eq!(
            u.regs.gpr[RBX],
            if rbx { 0xB1 } else { r.gpr[RBX] },
            "pc {pc:#x}"
        );
    }
}

#[test]
fn version_2_epilog_is_found_by_the_table() {
    let mut img = Image::new();
    let f = plain(&mut img, 2, UNW_FLAG_EHANDLER, &[0x1F00]);
    let info = UnwindInfo::parse(&img.bytes, f.unwind).unwrap();
    assert_eq!(info.epilogs(&f).collect::<Vec<_>>(), [(0x1014, 3)]);
    assert_eq!(info.codes().count(), 5);
    let caller = SP + 0x38;

    // The table starts at the first pop. The stack trim before it has not
    // run yet at 0x1010, so that address is body and unwinds by the codes.
    let u = unwind(&img, &f, 0x1010, &regs(SP), &plain_stack()).unwrap();
    assert_eq!(u.place, Place::Body);
    assert!(u.handler.is_some());
    assert_eq!((u.regs.gpr[RSP], u.regs.rip), (caller, RET));

    for (pc, rsp) in [
        (0x1014, SP + 0x20),
        (0x1015, SP + 0x28),
        (0x1016, SP + 0x30),
    ] {
        let u = unwind(&img, &f, pc, &regs(rsp), &plain_stack()).unwrap();
        assert_eq!(u.place, Place::Epilog, "pc {pc:#x}");
        assert_eq!((u.regs.gpr[RSP], u.regs.rip), (caller, RET), "pc {pc:#x}");
    }

    // Prolog codes still apply by offset; the table slots are skipped.
    let u = unwind(&img, &f, 0x1002, &regs(caller - 16), &plain_stack()).unwrap();
    assert_eq!(u.place, Place::Prolog);
    assert_eq!((u.regs.gpr[RSP], u.regs.gpr[RBX]), (caller, 0xB1));
}

#[test]
fn version_2_table_lists_epilogs_by_distance_from_the_end() {
    let mut img = Image::new();
    // Epilogs of 2 bytes (`pop rbx; ret`) at 0x1020, 0x1040 and, by the
    // first slot's flag, at the end. A zero slot is padding.
    for at in [0x1020, 0x1040, 0x105E] {
        img.put(at, &[0x5B, 0xC3]);
    }
    let codes = [
        slot(2, UWOP_EPILOG, 1),
        slot(0x40, UWOP_EPILOG, 0),
        slot(0x20, UWOP_EPILOG, 0),
        slot(0, UWOP_EPILOG, 0),
        slot(2, UWOP_PUSH_NONVOL, RBX as u8),
    ];
    let info = img.info(2, 0, 2, 0, &codes, &[]);
    let f = img.func(0x1000, 0x1060, info);
    let parsed = UnwindInfo::parse(&img.bytes, info).unwrap();
    assert_eq!(
        parsed.epilogs(&f).collect::<Vec<_>>(),
        [(0x105E, 2), (0x1020, 2), (0x1040, 2)]
    );

    let mem = stack(&[(SP, 0xB1), (SP + 8, RET)]);
    for at in [0x1020, 0x1040, 0x105E] {
        let u = unwind(&img, &f, at, &regs(SP), &mem).unwrap();
        assert_eq!(
            (u.place, u.regs.gpr[RSP], u.regs.gpr[RBX]),
            (Place::Epilog, SP + 16, 0xB1)
        );
        let u = unwind(&img, &f, at + 1, &regs(SP + 8), &mem).unwrap();
        assert_eq!(
            (u.place, u.regs.gpr[RSP], u.regs.rip),
            (Place::Epilog, SP + 16, RET)
        );
        // One byte past the listed length is body again.
        let u = unwind(&img, &f, at + 2, &regs(SP), &mem);
        assert_eq!(u.map(|u| u.place), Ok(Place::Body));
    }

    // Without the flag the first slot only gives the length. A distance
    // uses all 12 bits.
    let codes = [slot(2, UWOP_EPILOG, 0), slot(0x34, UWOP_EPILOG, 0x2)];
    let info = img.info(2, 0, 0, 0, &codes, &[]);
    let big = RuntimeFunction {
        begin: 0x1000,
        end: 0x1300,
        unwind: info,
    };
    let parsed = UnwindInfo::parse(&img.bytes, info).unwrap();
    assert_eq!(
        parsed.epilogs(&big).collect::<Vec<_>>(),
        [(0x1300 - 0x234, 2)]
    );
}

#[test]
fn version_2_ignores_epilog_shaped_code_the_table_does_not_list() {
    let mut img = Image::new();
    img.put(0x1010, &[0x5B, 0xC3]); // not listed
    img.put(0x101E, &[0x5B, 0xC3]); // listed, by the end flag
    img.put(0x1030, &[0x90, 0x90]); // listed, and not an epilog
    let codes = [
        slot(2, UWOP_EPILOG, 1),
        slot(0, UWOP_EPILOG, 0),
        slot(2, UWOP_PUSH_NONVOL, RBX as u8),
    ];
    let info = img.info(2, 0, 2, 0, &codes, &[]);
    let f = img.func(0x1000, 0x1020, info);
    let mem = stack(&[(SP, 0xB1), (SP + 8, RET)]);
    assert_eq!(
        unwind(&img, &f, 0x1010, &regs(SP), &mem).unwrap().place,
        Place::Body
    );
    assert_eq!(
        unwind(&img, &f, 0x101E, &regs(SP), &mem).unwrap().place,
        Place::Epilog
    );

    let g = img.func(0x1022, 0x1032, info);
    assert_eq!(
        unwind(&img, &g, 0x1030, &regs(SP), &mem),
        Err(UnwindError::BadUnwindInfo)
    );
}

/// Decode `code` placed at 0x1100 as an epilog of a function spanning
/// 0x1000..0x1200.
fn epilog_of(code: &[u8]) -> Option<Epilog> {
    let mut img = Image::new();
    img.put(0x1100, code);
    let f = RuntimeFunction {
        begin: 0x1000,
        end: 0x1200,
        unwind: 0,
    };
    decode_epilog(&img.bytes, &f, 0x1100)
}

#[test]
fn epilog_decoder_accepts_each_documented_form() {
    let shape = |code: &[u8]| epilog_of(code).map(|e| (e.len, e.trim, e.pops().to_vec()));
    let none: Vec<u8> = vec![];
    // Stack trims.
    assert_eq!(
        shape(&[0x48, 0x83, 0xC4, 0x28, 0xC3]),
        Some((5, Trim::Add(0x28), none.clone()))
    );
    assert_eq!(
        shape(&[0x48, 0x81, 0xC4, 0x00, 0x01, 0x00, 0x00, 0xC3]),
        Some((8, Trim::Add(0x100), none.clone()))
    );
    assert_eq!(
        shape(&[0x48, 0x8D, 0x65, 0xF0, 0xC3]),
        Some((5, Trim::Lea { base: 5, disp: -16 }, none.clone()))
    );
    assert_eq!(
        shape(&[0x49, 0x8D, 0xA5, 0x80, 0x00, 0x00, 0x00, 0xC3]),
        Some((
            8,
            Trim::Lea {
                base: 13,
                disp: 0x80
            },
            none.clone()
        ))
    );
    // Pops, with and without a REX prefix.
    assert_eq!(
        shape(&[
            0x48, 0x83, 0xC4, 0x20, 0x41, 0x5F, 0x41, 0x5C, 0x5F, 0x5D, 0xC3
        ]),
        Some((11, Trim::Add(0x20), vec![15, 12, 7, 5]))
    );
    assert_eq!(shape(&[0x5B, 0xC3]), Some((2, Trim::None, vec![3])));
    // Returns.
    assert_eq!(shape(&[0xC3]), Some((1, Trim::None, none.clone())));
    assert_eq!(
        shape(&[0xC2, 0x08, 0x00]),
        Some((3, Trim::None, none.clone()))
    );
    assert_eq!(shape(&[0xF3, 0xC3]), Some((2, Trim::None, none.clone())));
    // Tail calls: a jump out of the function, or to its own start.
    assert_eq!(
        shape(&[0xE9, 0x00, 0x10, 0x00, 0x00]),
        Some((5, Trim::None, none.clone()))
    );
    assert_eq!(
        shape(&[0xE9, 0xFB, 0xFE, 0xFF, 0xFF]),
        Some((5, Trim::None, none.clone()))
    );
    assert_eq!(
        shape(&[0xE9, 0xFA, 0xFE, 0xFF, 0xFF]),
        Some((5, Trim::None, none.clone()))
    );
    assert_eq!(
        shape(&[0xEB, 0x7F]),
        None,
        "a short jump inside the function"
    );
    assert_eq!(
        shape(&[0xFF, 0x25, 0x00, 0x10, 0x00, 0x00]),
        Some((6, Trim::None, none.clone()))
    );
    // rex.w jmp through a register or memory, each ModRM shape.
    for (code, len) in [
        (&[0x48, 0xFF, 0xE0][..], 3),
        (&[0x48, 0xFF, 0x25, 0, 0, 0, 0][..], 7),
        (&[0x48, 0xFF, 0x20][..], 3),
        (&[0x48, 0xFF, 0x24, 0x24][..], 4),
        (&[0x48, 0xFF, 0x24, 0x25, 0, 0, 0, 0][..], 8),
        (&[0x49, 0xFF, 0x60, 0x08][..], 4),
        (&[0x48, 0xFF, 0x64, 0x24, 0x08][..], 5),
        (&[0x48, 0xFF, 0xA0, 0, 0, 0, 0][..], 7),
    ] {
        assert_eq!(
            shape(code),
            Some((len, Trim::None, none.clone())),
            "{code:02x?}"
        );
    }
}

#[test]
fn epilog_decoder_rejects_everything_else() {
    // A jump that stays inside the function is not a tail call.
    assert_eq!(epilog_of(&[0xE9, 0x10, 0x00, 0x00, 0x00]), None);
    assert_eq!(epilog_of(&[0xEB, 0x10]), None);
    // Ordinary code, and an epilog with something scheduled inside it.
    assert_eq!(epilog_of(&[0x90, 0xC3]), None);
    assert_eq!(epilog_of(&[0x48, 0x83, 0xC4, 0x20, 0x33, 0xC0, 0xC3]), None);
    assert_eq!(epilog_of(&[0xF3, 0x90]), None);
    assert_eq!(
        epilog_of(&[0xFF, 0xE0]),
        None,
        "jmp rax without the rex.w marker"
    );
    assert_eq!(epilog_of(&[0x48, 0xFF, 0xD0]), None, "a call");
    // lea forms that are not `lea rsp, [reg + disp]`: another
    // destination, a SIB base, no displacement, a register operand.
    for code in [
        [0x48, 0x8D, 0x45, 0x10, 0xC3],
        [0x48, 0x8D, 0x64, 0x24, 0xC3],
        [0x48, 0x8D, 0x20, 0xC3, 0xC3],
        [0x48, 0x8D, 0xE5, 0xC3, 0xC3],
    ] {
        assert_eq!(epilog_of(&code), None, "{code:02x?}");
    }
    // More pops than there are registers.
    let mut pops = vec![0x5B; 17];
    pops.push(0xC3);
    assert_eq!(epilog_of(&pops), None);
    // Code that runs off the image.
    let img = Image::new();
    let f = RuntimeFunction {
        begin: 0x1000,
        end: 0x5000,
        unwind: 0,
    };
    assert_eq!(decode_epilog(&img.bytes, &f, IMAGE_SIZE as u32), None);
    let mut img = Image::new();
    for tail in [
        &[0x5B][..],
        &[0x48, 0x83, 0xC4][..],
        &[0x48, 0x81, 0xC4, 0][..],
        &[0xE9, 0][..],
        &[0x48, 0xFF, 0x25][..],
    ] {
        let at = IMAGE_SIZE - tail.len();
        img.bytes[at..].copy_from_slice(tail);
        assert_eq!(
            decode_epilog(&img.bytes, &f, at as u32),
            None,
            "{tail:02x?}"
        );
    }
}

#[test]
fn epilog_with_a_frame_register_trim_restores_rsp_from_it() {
    let mut img = Image::new();
    // push rbp; sub rsp, 0x40; lea rbp, [rsp+0x20]; ...; lea rsp, [rbp+0x20]; pop rbp; ret
    img.put(
        0x1000,
        &[0x55, 0x48, 0x83, 0xEC, 0x40, 0x48, 0x8D, 0x6C, 0x24, 0x20],
    );
    img.put(0x1020, &[0x48, 0x8D, 0x65, 0x20, 0x5D, 0xC3]);
    let codes = [
        slot(10, UWOP_SET_FPREG, 0),
        slot(5, UWOP_ALLOC_SMALL, 7),
        slot(1, UWOP_PUSH_NONVOL, RBP as u8),
    ];
    let info = img.info(1, 0, 10, 0x25, &codes, &[]);
    let f = img.func(0x1000, 0x1026, info);
    let mem = stack(&[(SP + 0x40, 0xB9), (SP + 0x48, RET)]);
    let caller = SP + 0x50;

    // In the body rsp has moved (an alloca); the frame register has not.
    let mut r = regs(SP - 0x300);
    r.gpr[RBP] = SP + 0x20;
    let u = unwind(&img, &f, 0x1010, &r, &mem).unwrap();
    assert_eq!((u.place, u.establisher), (Place::Body, SP));
    assert_eq!(
        (u.regs.gpr[RSP], u.regs.gpr[RBP], u.regs.rip),
        (caller, 0xB9, RET)
    );

    // At the lea of the epilog, and after it.
    let u = unwind(&img, &f, 0x1020, &r, &mem).unwrap();
    assert_eq!(
        (u.place, u.regs.gpr[RSP], u.regs.gpr[RBP]),
        (Place::Epilog, caller, 0xB9)
    );
    let u = unwind(&img, &f, 0x1024, &regs(SP + 0x40), &mem).unwrap();
    assert_eq!(
        (u.place, u.regs.gpr[RSP], u.regs.gpr[RBP]),
        (Place::Epilog, caller, 0xB9)
    );

    // In the prolog before the frame register is set, rsp is the frame.
    let r = regs(SP);
    let u = unwind(&img, &f, 0x1005, &r, &mem).unwrap();
    assert_eq!((u.place, u.establisher), (Place::Prolog, SP));
    assert_eq!((u.regs.gpr[RSP], u.regs.gpr[RBP]), (caller, 0xB9));
    let u = unwind(&img, &f, 0x1001, &regs(SP + 0x40), &mem).unwrap();
    assert_eq!((u.regs.gpr[RSP], u.regs.gpr[RBP]), (caller, 0xB9));
}

#[test]
fn large_allocations_and_moved_saves_are_undone() {
    let mut img = Image::new();
    let codes = [
        slot(0x30, UWOP_SAVE_XMM128_FAR, 5),
        0x0060,
        0x0000,
        slot(0x2C, UWOP_SAVE_XMM128_FAR, 15),
        0x0050,
        0x0000,
        slot(0x28, UWOP_SAVE_XMM128, 6),
        0x0004,
        slot(0x20, UWOP_SAVE_NONVOL_FAR, R13 as u8),
        0x0038,
        0x0000,
        slot(0x18, UWOP_SAVE_NONVOL, R12 as u8),
        0x0006,
        slot(0x10, UWOP_ALLOC_LARGE, 1),
        0x0000,
        0x0008,
        slot(0x08, UWOP_ALLOC_LARGE, 0),
        0x0200,
    ];
    let info = img.info(1, 0, 0x30, 0, &codes, &[]);
    let f = img.func(0x1000, 0x1100, info);
    let total = 0x8_0000 + 0x1000;
    let mem = stack(&[
        (SP + 0x30, 0xC12),
        (SP + 0x38, 0xC13),
        (SP + 0x40, 0x6666_0000),
        (SP + 0x48, 0x6666_1111),
        (SP + 0x50, 0xFFFF_0000),
        (SP + 0x58, 0xFFFF_1111),
        (SP + 0x60, 5),
        (SP + 0x68, 5),
        (SP + total, RET),
    ]);
    let r = regs(SP);
    let u = unwind(&img, &f, 0x1080, &r, &mem).unwrap();
    assert_eq!((u.regs.gpr[RSP], u.regs.rip), (SP + total + 8, RET));
    assert_eq!((u.regs.gpr[R12], u.regs.gpr[R13]), (0xC12, 0xC13));
    assert_eq!(u.regs.xmm[0], 0x6666_1111_u128 << 64 | 0x6666_0000);
    assert_eq!(u.regs.xmm[9], 0xFFFF_1111_u128 << 64 | 0xFFFF_0000);
    // xmm5 is volatile: its save is read, not kept.
    assert_eq!(u.regs.xmm[1..9], r.xmm[1..9]);

    // After the allocations but before any save.
    let u = unwind(&img, &f, 0x1010, &r, &mem).unwrap();
    assert_eq!(
        (u.regs.gpr[RSP], u.regs.gpr[R12]),
        (SP + total + 8, r.gpr[R12])
    );
    // After the first allocation only.
    let u = unwind(&img, &f, 0x1008, &regs(SP + 0x8_0000), &mem).unwrap();
    assert_eq!(u.regs.gpr[RSP], SP + total + 8);
}

#[test]
fn machine_frame_supplies_rip_and_rsp() {
    for error_code in [false, true] {
        let mut img = Image::new();
        let codes = [
            slot(4, UWOP_ALLOC_SMALL, 1),
            slot(0, UWOP_PUSH_MACHFRAME, u8::from(error_code)),
        ];
        let info = img.info(1, 0, 4, 0, &codes, &[]);
        let f = img.func(0x1000, 0x1100, info);
        let frame = SP + 0x10 + if error_code { 8 } else { 0 };
        let mem = stack(&[(frame, RET), (frame + 24, 0x7000_0000)]);
        let u = unwind(&img, &f, 0x1050, &regs(SP), &mem).unwrap();
        assert!(u.machine_frame);
        assert_eq!(
            (u.regs.rip, u.regs.gpr[RSP]),
            (RET, 0x7000_0000),
            "error code {error_code}"
        );
    }
}

#[test]
fn chained_info_continues_in_the_parent_record() {
    let mut img = Image::new();
    let parent = plain(&mut img, 1, UNW_FLAG_EHANDLER, &[0x1F00]);
    // A fragment at 0x1800 that saves rsi into the parent's frame.
    let codes = [slot(5, UWOP_SAVE_NONVOL, RSI as u8), 0x0002];
    let info = img.info(
        1,
        UNW_FLAG_CHAININFO,
        5,
        0,
        &codes,
        &[parent.begin, parent.end, parent.unwind],
    );
    let f = img.func(0x1800, 0x1840, info);
    let mut mem = plain_stack();
    mem.insert(SP + 0x10, 0x51);
    let r = regs(SP);

    let u = unwind(&img, &f, 0x1810, &r, &mem).unwrap();
    assert_eq!(u.place, Place::Body);
    assert_eq!((u.regs.gpr[RSP], u.regs.rip), (SP + 0x38, RET));
    assert_eq!(
        (u.regs.gpr[RSI], u.regs.gpr[RDI], u.regs.gpr[RBX]),
        (0x51, 0xD1, 0xB1)
    );
    assert_eq!(
        u.handler.map(|h| h.rva),
        Some(0x1F00),
        "the handler is the parent's"
    );

    // In the fragment's prolog its own save has not happened; the
    // parent's whole prolog has.
    let u = unwind(&img, &f, 0x1802, &r, &mem).unwrap();
    assert_eq!(u.place, Place::Prolog);
    assert_eq!(
        (u.regs.gpr[RSP], u.regs.gpr[RSI], u.regs.gpr[RBX]),
        (SP + 0x38, r.gpr[RSI], 0xB1)
    );
    assert_eq!(u.handler, None);
}

#[test]
fn a_chain_that_never_ends_is_an_error() {
    let mut img = Image::new();
    let rva = img.xdata;
    let info = img.info(1, UNW_FLAG_CHAININFO, 0, 0, &[], &[0x1000, 0x1100, rva]);
    let f = img.func(0x1000, 0x1100, info);
    assert_eq!(
        unwind(&img, &f, 0x1010, &regs(SP), &stack(&[])),
        Err(UnwindError::ChainTooDeep)
    );
}

#[test]
fn leaf_unwind_pops_the_return_address() {
    let mem = stack(&[(SP, RET)]);
    let r = regs(SP);
    let u = unwind_leaf(&r, &mut |a| mem.get(&a).copied()).unwrap();
    assert_eq!((u.rip, u.gpr[RSP]), (RET, SP + 8));
    assert_eq!(u.gpr[RBX], r.gpr[RBX]);
    assert_eq!(unwind_leaf(&r, &mut |_| None), Err(UnwindError::BadStack));
}

#[test]
fn an_unreadable_stack_is_an_error_wherever_it_is_needed() {
    let mut img = Image::new();
    let f = plain(&mut img, 1, 0, &[]);
    let full = plain_stack();
    for missing in [SP + 0x20, SP + 0x28, SP + 0x30] {
        let mut mem = full.clone();
        mem.remove(&missing);
        assert_eq!(
            unwind(&img, &f, 0x1008, &regs(SP), &mem),
            Err(UnwindError::BadStack)
        );
        // The epilog path reads the same slots.
        assert_eq!(
            unwind(&img, &f, 0x1010, &regs(SP), &mem),
            Err(UnwindError::BadStack)
        );
    }
    // A function whose record does not parse.
    let g = img.func(0x1100, 0x1200, IMAGE_SIZE as u32);
    assert_eq!(
        unwind(&img, &g, 0x1100, &regs(SP), &full),
        Err(UnwindError::OutOfBounds)
    );

    // Each kind of save reads the stack.
    for codes in [
        vec![slot(4, UWOP_SAVE_NONVOL, 3), 1],
        vec![slot(4, UWOP_SAVE_XMM128, 6), 1],
        vec![slot(0, UWOP_PUSH_MACHFRAME, 0)],
    ] {
        let mut img = Image::new();
        let info = img.info(1, 0, 4, 0, &codes, &[]);
        let f = img.func(0x1000, 0x1100, info);
        assert_eq!(
            unwind(&img, &f, 0x1050, &regs(SP), &stack(&[])),
            Err(UnwindError::BadStack)
        );
        // A value half there is not there.
        let half = stack(&[(SP, 1), (SP + 0x10, 1)]);
        assert_eq!(
            unwind(&img, &f, 0x1050, &regs(SP), &half),
            Err(UnwindError::BadStack)
        );
    }
}
