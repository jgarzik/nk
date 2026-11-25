//! x86-64: `RUNTIME_FUNCTION` lookup, `UNWIND_INFO` parsing and the
//! virtual unwind of one frame.
//!
//! Microsoft documents `UNWIND_INFO` version 1. Version 2, which nearly
//! every function of a Windows 10 driver uses, is not documented; what
//! follows is what the compiler's output shows. Version 2 adds
//! `UWOP_EPILOG` codes at the head of the code array: a table of where
//! the function's epilogs are, so an unwinder need not recognise them by
//! their instructions. The first such code holds the epilog length in
//! its offset byte and, in bit 0 of its info, whether an epilog ends the
//! function; each later one holds a 12-bit distance from the function's
//! end back to an epilog's start, zero meaning padding. A listed epilog
//! starts at its first `pop`: the `add rsp` before it is body, where the
//! prolog codes still describe the frame exactly.
//!
//! NK reads the table for version 2 and recognises the documented epilog
//! instruction forms for version 1. Either way the rest of an epilog is
//! undone by simulating its instructions.

use crate::{
    MAX_CHAIN, Place, UnwindError, bytes_at, last_at_or_below, slot, u8_at, u16_at, u32_at,
};

pub const UNW_FLAG_EHANDLER: u8 = 1;
pub const UNW_FLAG_UHANDLER: u8 = 2;
pub const UNW_FLAG_CHAININFO: u8 = 4;

pub const UWOP_PUSH_NONVOL: u8 = 0;
pub const UWOP_ALLOC_LARGE: u8 = 1;
pub const UWOP_ALLOC_SMALL: u8 = 2;
pub const UWOP_SET_FPREG: u8 = 3;
pub const UWOP_SAVE_NONVOL: u8 = 4;
pub const UWOP_SAVE_NONVOL_FAR: u8 = 5;
pub const UWOP_EPILOG: u8 = 6;
pub const UWOP_SAVE_XMM128: u8 = 8;
pub const UWOP_SAVE_XMM128_FAR: u8 = 9;
pub const UWOP_PUSH_MACHFRAME: u8 = 10;

/// Index of `rsp` in [`Regs::gpr`]; the others follow the instruction
/// encoding (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi, r8..r15).
pub const RSP: usize = 4;

/// Size of a `RUNTIME_FUNCTION` in `.pdata`.
pub const ENTRY_SIZE: usize = 12;

/// The registers an unwind can change: the integer registers, `rip`, and
/// the non-volatile `xmm6`..`xmm15` (index 0 is `xmm6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Regs {
    pub gpr: [u64; 16],
    pub rip: u64,
    pub xmm: [u128; 10],
}

/// One `.pdata` entry: a function, or a fragment of one, and its unwind
/// record. All three are RVAs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeFunction {
    pub begin: u32,
    pub end: u32,
    pub unwind: u32,
}

fn entry_at(image: &[u8], off: usize) -> Result<RuntimeFunction, UnwindError> {
    Ok(RuntimeFunction {
        begin: u32_at(image, off)?,
        end: u32_at(image, off + 4)?,
        unwind: u32_at(image, off + 8)?,
    })
}

/// The `index`th entry of the exception directory at `dir_rva`.
pub fn entry(image: &[u8], dir_rva: u32, index: usize) -> Result<RuntimeFunction, UnwindError> {
    let off = index
        .checked_mul(ENTRY_SIZE)
        .and_then(|o| o.checked_add(dir_rva as usize))
        .ok_or(UnwindError::OutOfBounds)?;
    entry_at(image, off)
}

/// The entry covering `rva`, from the exception directory (`dir_rva`,
/// `dir_size`) of a mapped image. `Ok(None)` means no entry: a leaf
/// function, which [`unwind_leaf`] undoes, or an address that is not code.
///
/// An entry whose unwind RVA has bit 0 set points at another entry, which
/// is returned in its place.
pub fn lookup(
    image: &[u8],
    dir_rva: u32,
    dir_size: u32,
    rva: u32,
) -> Result<Option<RuntimeFunction>, UnwindError> {
    let Some(index) = last_at_or_below(image, dir_rva, dir_size, ENTRY_SIZE, rva)? else {
        return Ok(None);
    };
    let mut f = entry(image, dir_rva, index)?;
    if rva >= f.end {
        return Ok(None);
    }
    for _ in 0..MAX_CHAIN {
        if f.unwind & 1 == 0 {
            return Ok(Some(f));
        }
        f = entry_at(image, (f.unwind & !1) as usize)?;
    }
    Err(UnwindError::ChainTooDeep)
}

/// One decoded unwind operation. Allocation and save forms that differ
/// only in how they encode a size are one variant; [`Code::opcode`] keeps
/// the encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `push reg`.
    PushNonvol(u8),
    /// `sub rsp, n`.
    Alloc(u32),
    /// `lea fpreg, [rsp + frame_offset]`.
    SetFpreg,
    /// `mov [frame + offset], reg`.
    SaveNonvol { reg: u8, offset: u32 },
    /// `movaps [frame + offset], xmm<reg>`.
    SaveXmm128 { reg: u8, offset: u32 },
    /// A hardware interrupt frame, with or without an error code below it.
    PushMachframe { error_code: bool },
    /// A version 2 epilog table slot: not a prolog operation.
    Epilog { low: u8, info: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Code {
    /// Offset in the prolog of the end of the instruction.
    pub offset: u8,
    /// The `UWOP_*` number as encoded.
    pub opcode: u8,
    pub op: Op,
}

/// Decode the code starting at slot `i`; returns it and its slot count.
fn decode(codes: &[u8], i: usize, version: u8) -> Result<(Code, usize), UnwindError> {
    let bad = |_| UnwindError::BadUnwindInfo;
    let offset = u8_at(codes, 2 * i).map_err(bad)?;
    let b = u8_at(codes, 2 * i + 1).map_err(bad)?;
    let (opcode, info) = (b & 15, b >> 4);
    let next16 = || u16_at(codes, 2 * i + 2).map(u32::from).map_err(bad);
    let next32 = || u32_at(codes, 2 * i + 2).map_err(bad);
    let (op, slots) = match opcode {
        UWOP_PUSH_NONVOL => (Op::PushNonvol(info), 1),
        UWOP_ALLOC_LARGE if info == 0 => (Op::Alloc(next16()? * 8), 2),
        UWOP_ALLOC_LARGE if info == 1 => (Op::Alloc(next32()?), 3),
        UWOP_ALLOC_SMALL => (Op::Alloc(u32::from(info) * 8 + 8), 1),
        UWOP_SET_FPREG => (Op::SetFpreg, 1),
        UWOP_SAVE_NONVOL => {
            let offset = next16()? * 8;
            (Op::SaveNonvol { reg: info, offset }, 2)
        }
        UWOP_SAVE_NONVOL_FAR => {
            let offset = next32()?;
            (Op::SaveNonvol { reg: info, offset }, 3)
        }
        UWOP_EPILOG if version >= 2 => (Op::Epilog { low: offset, info }, 1),
        UWOP_SAVE_XMM128 => {
            let offset = next16()? * 16;
            (Op::SaveXmm128 { reg: info, offset }, 2)
        }
        UWOP_SAVE_XMM128_FAR => {
            let offset = next32()?;
            (Op::SaveXmm128 { reg: info, offset }, 3)
        }
        UWOP_PUSH_MACHFRAME if info <= 1 => (
            Op::PushMachframe {
                error_code: info == 1,
            },
            1,
        ),
        UWOP_ALLOC_LARGE | UWOP_PUSH_MACHFRAME => return Err(UnwindError::BadUnwindInfo),
        _ => return Err(UnwindError::Unsupported(opcode)),
    };
    Ok((Code { offset, opcode, op }, slots))
}

/// What follows the unwind codes of an `UNWIND_INFO`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tail {
    None,
    /// `UNW_FLAG_CHAININFO`: the record continues in this entry's.
    Chained(RuntimeFunction),
    /// A language handler and the RVA of its data (for
    /// `__C_specific_handler`, a scope table).
    Handler {
        rva: u32,
        data_rva: u32,
    },
}

/// A parsed `UNWIND_INFO`.
#[derive(Debug, Clone, Copy)]
pub struct UnwindInfo<'a> {
    pub version: u8,
    /// `UNW_FLAG_*`.
    pub flags: u8,
    pub prolog_size: u8,
    /// Frame register number, 0 for none.
    pub frame_reg: u8,
    /// `frame register - frame_offset` is `rsp` as the prolog left it.
    pub frame_offset: u32,
    pub tail: Tail,
    codes: &'a [u8],
}

impl<'a> UnwindInfo<'a> {
    /// Parse the record at `rva`. Every code is decoded here, and must
    /// fill the declared slot count exactly, so iteration cannot fail.
    pub fn parse(image: &'a [u8], rva: u32) -> Result<Self, UnwindError> {
        let at = rva as usize;
        let head = bytes_at(image, at, 4)?;
        let (version, flags) = (head[0] & 7, head[0] >> 3);
        if version != 1 && version != 2 {
            return Err(UnwindError::BadUnwindInfo);
        }
        let count = head[2] as usize;
        let codes = bytes_at(image, at + 4, 2 * count)?;
        let mut i = 0;
        while i < count {
            i += decode(codes, i, version)?.1;
        }
        if i != count {
            return Err(UnwindError::BadUnwindInfo);
        }
        // The array is padded to an even number of slots.
        let after = at + 4 + 2 * ((count + 1) & !1);
        let tail = if flags & UNW_FLAG_CHAININFO != 0 {
            Tail::Chained(entry_at(image, after)?)
        } else if flags & (UNW_FLAG_EHANDLER | UNW_FLAG_UHANDLER) != 0 {
            let data_rva = u32::try_from(after + 4).map_err(|_| UnwindError::OutOfBounds)?;
            Tail::Handler {
                rva: u32_at(image, after)?,
                data_rva,
            }
        } else {
            Tail::None
        };
        Ok(Self {
            version,
            flags,
            prolog_size: head[1],
            frame_reg: head[3] & 15,
            frame_offset: u32::from(head[3] >> 4) * 16,
            tail,
            codes,
        })
    }

    /// The unwind codes, in stored order: last prolog instruction first.
    pub fn codes(&self) -> Codes<'a> {
        Codes {
            codes: self.codes,
            version: self.version,
            slot: 0,
        }
    }

    /// The version 2 epilog table of the function `func`: `(start RVA,
    /// length)` of each epilog.
    pub fn epilogs(&self, func: &RuntimeFunction) -> impl Iterator<Item = (u32, u32)> + use<'a> {
        let end = func.end;
        let mut len = 0;
        self.codes()
            .map_while(|c| match c.op {
                Op::Epilog { low, info } => Some((low, info)),
                _ => None,
            })
            .enumerate()
            .filter_map(move |(i, (low, info))| {
                let back = if i == 0 {
                    len = u32::from(low);
                    if info & 1 != 0 { len } else { 0 }
                } else {
                    u32::from(info) << 8 | u32::from(low)
                };
                (back != 0).then(|| (end.wrapping_sub(back), len))
            })
    }
}

/// Iterator over the codes of an [`UnwindInfo`].
#[derive(Debug, Clone)]
pub struct Codes<'a> {
    codes: &'a [u8],
    version: u8,
    slot: usize,
}

impl Iterator for Codes<'_> {
    type Item = Code;

    fn next(&mut self) -> Option<Code> {
        let (code, slots) = decode(self.codes, self.slot, self.version).ok()?;
        self.slot += slots;
        Some(code)
    }
}

/// The stack trim that may open an epilog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Trim {
    None,
    /// `add rsp, imm`.
    Add(i32),
    /// `lea rsp, [base + disp]`.
    Lea {
        base: u8,
        disp: i32,
    },
}

/// The rest of an epilog, decoded from its instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Epilog {
    /// Bytes from the decoded address to the end of the return or jump.
    pub len: u32,
    pub trim: Trim,
    pops: [u8; 16],
    npops: usize,
}

impl Epilog {
    /// The registers popped, in order.
    pub fn pops(&self) -> &[u8] {
        &self.pops[..self.npops]
    }
}

/// Decode the code at `pc` as the remainder of an epilog of `func`, in
/// the forms Microsoft documents
/// (<https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog>): an
/// optional `add rsp, imm` or `lea rsp, [reg + disp]`, any number of
/// `pop reg`, then `ret` or a jump that leaves the function. `None` when
/// the instructions are anything else.
pub fn decode_epilog(image: &[u8], func: &RuntimeFunction, pc: u32) -> Option<Epilog> {
    let code = image.get(pc as usize..)?;
    let b = |i: usize| code.get(i).copied();
    let imm8 = |i: usize| b(i).map(|v| i32::from(v as i8));
    let imm32 = |i: usize| Some(i32::from_le_bytes(code.get(i..i + 4)?.try_into().ok()?));
    let (trim, mut i) = match (b(0)?, b(1), b(2)) {
        (0x48, Some(0x83), Some(0xC4)) => (Trim::Add(imm8(3)?), 4),
        (0x48, Some(0x81), Some(0xC4)) => (Trim::Add(imm32(3)?), 7),
        // REX.W (+B) lea with rsp as destination and a plain base register.
        (rex @ (0x48 | 0x49), Some(0x8D), Some(m)) if m & 0x3F != 0x24 && m & 0x38 == 0x20 => {
            let base = (m & 7) | (rex & 1) << 3;
            match m >> 6 {
                1 => (
                    Trim::Lea {
                        base,
                        disp: imm8(3)?,
                    },
                    4,
                ),
                2 => (
                    Trim::Lea {
                        base,
                        disp: imm32(3)?,
                    },
                    7,
                ),
                _ => (Trim::None, 0),
            }
        }
        _ => (Trim::None, 0),
    };
    let (mut pops, mut npops) = ([0u8; 16], 0);
    loop {
        let (reg, len) = match (b(i)?, b(i + 1)) {
            (op @ 0x58..=0x5F, _) => (op - 0x58, 1),
            (0x41, Some(op @ 0x58..=0x5F)) => (op - 0x50, 2),
            _ => break,
        };
        *pops.get_mut(npops)? = reg;
        npops += 1;
        i += len;
    }
    let leaves = |next: usize, rel: i32| {
        let target = i64::from(pc) + next as i64 + i64::from(rel);
        target < i64::from(func.begin)
            || target >= i64::from(func.end)
            || target == i64::from(func.begin)
    };
    let end = match (b(i)?, b(i + 1), b(i + 2)) {
        (0xC3, ..) => i + 1,
        (0xC2, ..) => i + 3,
        (0xF3, Some(0xC3), _) => i + 2,
        (0xEB, ..) if leaves(i + 2, imm8(i + 1)?) => i + 2,
        (0xE9, ..) if leaves(i + 5, imm32(i + 1)?) => i + 5,
        (0xFF, Some(0x25), _) => i + 6,
        // `rex.w jmp r/m64`: the compiler's marker for a tail call.
        (0x48..=0x4F, Some(0xFF), Some(m)) if m & 0x38 == 0x20 => i + 3 + modrm_tail(m, b(i + 3)?),
        _ => return None,
    };
    Some(Epilog {
        len: end as u32,
        trim,
        pops,
        npops,
    })
}

/// Bytes of SIB and displacement that follow the ModRM byte `m`.
fn modrm_tail(m: u8, sib: u8) -> usize {
    let has_sib = m & 7 == 4 && m >> 6 != 3;
    let disp = match (m >> 6, m & 7) {
        (0, 5) => 4,
        (0, 4) if sib & 7 == 5 => 4,
        (1, _) => 1,
        (2, _) => 4,
        _ => 0,
    };
    usize::from(has_sib) + disp
}

/// A language handler named by a function's unwind record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handler {
    pub rva: u32,
    /// RVA of the handler's data, the `HandlerData` of a
    /// `DISPATCHER_CONTEXT`.
    pub data_rva: u32,
    /// `UNW_FLAG_EHANDLER`: call it when searching for a handler.
    pub exception: bool,
    /// `UNW_FLAG_UHANDLER`: call it when unwinding.
    pub termination: bool,
}

/// The result of unwinding one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unwound {
    /// The caller's registers; `rip` is the return address.
    pub regs: Regs,
    /// The frame's fixed stack base, which language handlers receive.
    pub establisher: u64,
    pub place: Place,
    /// The function's handler; `None` outside the body, where Windows
    /// calls none.
    pub handler: Option<Handler>,
    /// The frame was an interrupt's: `rip` is the interrupted
    /// instruction, not a return address.
    pub machine_frame: bool,
}

/// Unwind a function that has no `.pdata` entry: a leaf, which by the
/// ABI never moves `rsp`, so its return address is on top of the stack.
pub fn unwind_leaf(
    regs: &Regs,
    read: &mut impl FnMut(u64) -> Option<u64>,
) -> Result<Regs, UnwindError> {
    let mut r = *regs;
    pop_return(&mut r, read)?;
    Ok(r)
}

fn pop_return(r: &mut Regs, read: &mut impl FnMut(u64) -> Option<u64>) -> Result<(), UnwindError> {
    r.rip = slot(read, r.gpr[RSP])?;
    r.gpr[RSP] = r.gpr[RSP].wrapping_add(8);
    Ok(())
}

/// Unwind the frame of `func` from `pc_rva`: compute the registers of its
/// caller. `regs` are the registers at `pc_rva`; `read` returns the
/// 64-bit value at a stack address, or `None` if it is not readable.
pub fn virtual_unwind(
    image: &[u8],
    func: &RuntimeFunction,
    pc_rva: u32,
    regs: &Regs,
    read: &mut impl FnMut(u64) -> Option<u64>,
) -> Result<Unwound, UnwindError> {
    let mut info = UnwindInfo::parse(image, func.unwind)?;
    let offset = pc_rva.wrapping_sub(func.begin);
    let in_prolog = offset < u32::from(info.prolog_size);
    let mut r = *regs;

    // The frame base is rsp, or the frame register once the prolog set it.
    let fp_set = !in_prolog
        || info
            .codes()
            .any(|c| c.op == Op::SetFpreg && u32::from(c.offset) <= offset);
    let establisher = if info.frame_reg != 0 && fp_set {
        r.gpr[info.frame_reg as usize].wrapping_sub(u64::from(info.frame_offset))
    } else {
        r.gpr[RSP]
    };
    let mut out = Unwound {
        regs: r,
        establisher,
        place: if in_prolog {
            Place::Prolog
        } else {
            Place::Body
        },
        handler: None,
        machine_frame: false,
    };

    // Past the prolog, an epilog: by the table for version 2, by its
    // instructions for version 1.
    let epilog = if in_prolog {
        None
    } else if info.version >= 2 {
        let listed = info
            .epilogs(func)
            .any(|(start, len)| pc_rva.wrapping_sub(start) < len);
        match decode_epilog(image, func, pc_rva) {
            Some(e) if listed => Some(e),
            None if listed => return Err(UnwindError::BadUnwindInfo),
            _ => None,
        }
    } else {
        decode_epilog(image, func, pc_rva)
    };
    if let Some(e) = epilog {
        run_epilog(&e, &mut r, read)?;
        out.regs = r;
        out.place = Place::Epilog;
        return Ok(out);
    }

    // In the prolog only the instructions already run are undone; records
    // further up a chain describe code that ran before this fragment.
    let mut limit = in_prolog.then_some(offset);
    for _ in 0..MAX_CHAIN {
        for c in info.codes() {
            if limit.is_some_and(|l| u32::from(c.offset) > l) {
                continue;
            }
            out.machine_frame |= undo(&c.op, &info, establisher, &mut r, read)?;
        }
        match info.tail {
            Tail::Chained(parent) => {
                info = UnwindInfo::parse(image, parent.unwind)?;
                limit = None;
            }
            tail => {
                if !out.machine_frame {
                    pop_return(&mut r, read)?;
                }
                if let (Tail::Handler { rva, data_rva }, Place::Body) = (tail, out.place) {
                    out.handler = Some(Handler {
                        rva,
                        data_rva,
                        exception: info.flags & UNW_FLAG_EHANDLER != 0,
                        termination: info.flags & UNW_FLAG_UHANDLER != 0,
                    });
                }
                out.regs = r;
                return Ok(out);
            }
        }
    }
    Err(UnwindError::ChainTooDeep)
}

/// Undo one prolog operation. Returns whether it was a machine frame,
/// which supplies `rip` itself.
fn undo(
    op: &Op,
    info: &UnwindInfo<'_>,
    frame: u64,
    r: &mut Regs,
    read: &mut impl FnMut(u64) -> Option<u64>,
) -> Result<bool, UnwindError> {
    let rsp = r.gpr[RSP];
    match *op {
        Op::PushNonvol(reg) => {
            r.gpr[reg as usize] = slot(read, rsp)?;
            r.gpr[RSP] = rsp.wrapping_add(8);
        }
        Op::Alloc(n) => r.gpr[RSP] = rsp.wrapping_add(u64::from(n)),
        Op::SetFpreg => {
            r.gpr[RSP] = r.gpr[info.frame_reg as usize].wrapping_sub(u64::from(info.frame_offset));
        }
        Op::SaveNonvol { reg, offset } => {
            r.gpr[reg as usize] = slot(read, frame.wrapping_add(u64::from(offset)))?;
        }
        Op::SaveXmm128 { reg, offset } => {
            let at = frame.wrapping_add(u64::from(offset));
            let lo = slot(read, at)?;
            let hi = slot(read, at.wrapping_add(8))?;
            // xmm0-5 are volatile and not part of the register set.
            if let Some(x) = (reg as usize).checked_sub(6).and_then(|i| r.xmm.get_mut(i)) {
                *x = u128::from(hi) << 64 | u128::from(lo);
            }
        }
        Op::PushMachframe { error_code } => {
            let at = rsp.wrapping_add(if error_code { 8 } else { 0 });
            r.rip = slot(read, at)?;
            r.gpr[RSP] = slot(read, at.wrapping_add(24))?;
            return Ok(true);
        }
        Op::Epilog { .. } => {}
    }
    Ok(false)
}

/// Simulate the rest of an epilog.
fn run_epilog(
    e: &Epilog,
    r: &mut Regs,
    read: &mut impl FnMut(u64) -> Option<u64>,
) -> Result<(), UnwindError> {
    match e.trim {
        Trim::None => {}
        Trim::Add(n) => r.gpr[RSP] = r.gpr[RSP].wrapping_add_signed(i64::from(n)),
        Trim::Lea { base, disp } => {
            r.gpr[RSP] = r.gpr[base as usize].wrapping_add_signed(i64::from(disp));
        }
    }
    for &reg in e.pops() {
        r.gpr[reg as usize] = slot(read, r.gpr[RSP])?;
        r.gpr[RSP] = r.gpr[RSP].wrapping_add(8);
    }
    pop_return(r, read)
}
