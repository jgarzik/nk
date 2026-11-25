//! arm64: `.pdata` lookup, `.xdata` and packed unwind data, and the
//! virtual unwind of one frame.
//!
//! A function is described by a byte string of unwind codes, one per
//! prolog instruction, stored in the order they are undone. Packed unwind
//! data names a canonical prolog instead; [`canonical`] expands it to the
//! same operations, so one executor serves both.
//!
//! NK does not enable pointer authentication, so `pac_sign_lr` undoes
//! nothing: the return address in `lr` is already plain.

use crate::{Place, UnwindError, bytes_at, last_at_or_below, slot, u32_at};

/// Size of a `.pdata` entry.
pub const ENTRY_SIZE: usize = 8;

/// Index in [`Regs::x`] of `x29`, the frame pointer.
pub const FP: usize = 10;
/// Index in [`Regs::x`] of `x30`, the link register.
pub const LR: usize = 11;

/// Offsets in the arm64 `CONTEXT` that `MSFT_OP_CONTEXT` restores from.
const CONTEXT_X0: u64 = 0x08;
const CONTEXT_SP: u64 = 0x100;
const CONTEXT_PC: u64 = 0x108;
const CONTEXT_V0: u64 = 0x110;

/// The registers an unwind can change: `x19`..`x30` (index 0 is `x19`),
/// `sp`, `pc`, and the low halves `d8`..`d15` of the non-volatile vector
/// registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Regs {
    pub x: [u64; 12],
    pub sp: u64,
    pub pc: u64,
    pub d: [u64; 8],
}

/// The second word of a `.pdata` entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnwindData {
    /// Packed unwind data: the whole word.
    Packed(u32),
    /// RVA of an `.xdata` record.
    Xdata(u32),
}

/// One `.pdata` entry: a function or fragment and how to unwind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionEntry {
    /// Start RVA.
    pub begin: u32,
    /// Length in bytes, from the unwind data.
    pub len: u32,
    pub unwind: UnwindData,
}

/// The `index`th entry of the exception directory at `dir_rva`.
pub fn entry(image: &[u8], dir_rva: u32, index: usize) -> Result<FunctionEntry, UnwindError> {
    let off = index
        .checked_mul(ENTRY_SIZE)
        .and_then(|o| o.checked_add(dir_rva as usize))
        .ok_or(UnwindError::OutOfBounds)?;
    let begin = u32_at(image, off)?;
    let word = u32_at(image, off + 4)?;
    let (len, unwind) = match word & 3 {
        0 => (
            Xdata::parse(image, word)?.function_len,
            UnwindData::Xdata(word),
        ),
        1 | 2 => (((word >> 2) & 0x7FF) * 4, UnwindData::Packed(word)),
        // A link to a parent record: it carries no length of its own.
        _ => return Err(UnwindError::Unsupported(3)),
    };
    Ok(FunctionEntry { begin, len, unwind })
}

/// The entry covering `rva`, from the exception directory (`dir_rva`,
/// `dir_size`) of a mapped image. `Ok(None)` means no entry: a leaf
/// function, which [`unwind_leaf`] undoes, or an address that is not code.
pub fn lookup(
    image: &[u8],
    dir_rva: u32,
    dir_size: u32,
    rva: u32,
) -> Result<Option<FunctionEntry>, UnwindError> {
    let Some(index) = last_at_or_below(image, dir_rva, dir_size, ENTRY_SIZE, rva)? else {
        return Ok(None);
    };
    let f = entry(image, dir_rva, index)?;
    Ok((rva - f.begin < f.len).then_some(f))
}

/// A register an unwind code saves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reg {
    /// `x<n>`.
    X(u8),
    /// `d<n>`.
    D(u8),
}

impl Reg {
    /// The register `n` places after this one.
    fn plus(self, n: u8) -> Reg {
        match self {
            Reg::X(r) => Reg::X(r.wrapping_add(n)),
            Reg::D(r) => Reg::D(r.wrapping_add(n)),
        }
    }
}

/// One unwind operation: what a prolog instruction did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// `sub sp, sp, #n`.
    Alloc(u32),
    /// Store one register at `[sp + offset]`, or with `pre` at
    /// `[sp - offset]!`, moving `sp` down first.
    Save { reg: Reg, offset: u32, pre: bool },
    /// Store a pair the same way; the second register is 8 bytes above.
    SavePair {
        a: Reg,
        b: Reg,
        offset: u32,
        pre: bool,
    },
    /// The pair save that follows in the array (precedes in the prolog)
    /// covers one more pair of registers.
    SaveNext,
    /// `mov x29, sp`.
    SetFp,
    /// `add x29, sp, #n`.
    AddFp(u32),
    /// An instruction with nothing to undo.
    Nop,
    /// `pacibsp`.
    PacSignLr,
    /// End of the sequence; in an epilog, the `ret`.
    End,
    /// End of this fragment's own prolog; the parent's codes follow.
    EndC,
    /// `sp` points at a saved `{sp, pc}` pair.
    MachineFrame,
    /// `sp` points at a `CONTEXT`.
    Context,
    /// The frame's `pc` is where it stopped, not the return address of a
    /// call.
    ClearUnwoundToCall,
}

impl Op {
    /// Whether the code stands for one instruction. The custom frame
    /// codes describe a stack somebody else built.
    fn is_instruction(&self) -> bool {
        !matches!(
            self,
            Op::MachineFrame | Op::Context | Op::ClearUnwoundToCall
        )
    }
}

/// Decode the unwind code at the head of `codes`; returns it and its
/// length in bytes. Codes the format reserves, the Windows 11 and SVE
/// additions, and the frames whose layout is private to Windows
/// (`MSFT_OP_TRAP_FRAME`, `MSFT_OP_EC_CONTEXT`) are
/// [`UnwindError::Unsupported`].
pub fn decode(codes: &[u8]) -> Result<(Op, usize), UnwindError> {
    let b0 = *codes.first().ok_or(UnwindError::BadUnwindInfo)?;
    let len = match b0 {
        0x00..=0xBF | 0xE1 | 0xE3..=0xE6 | 0xE8..=0xEC | 0xFC => 1,
        0xC0..=0xDF | 0xE2 => 2,
        0xE7 => 3,
        0xE0 => 4,
        _ => return Err(UnwindError::Unsupported(b0)),
    };
    let c = codes.get(..len).ok_or(UnwindError::BadUnwindInfo)?;
    // Operands are big-endian bit fields behind the opcode bits.
    let v = c.iter().fold(0u32, |v, &b| v << 8 | u32::from(b));
    let z6 = (v & 0x3F) * 8;
    let pair = |first: Reg, offset: u32, pre: bool| Op::SavePair {
        a: first,
        b: first.plus(1),
        offset,
        pre,
    };
    let x = |n: u32| Reg::X(19 + n as u8);
    let d = |n: u32| Reg::D(8 + n as u8);
    let op = match b0 {
        0x00..=0x1F => Op::Alloc((v & 0x1F) * 16),
        0x20..=0x3F => pair(Reg::X(19), (v & 0x1F) * 8, true),
        0x40..=0x7F => pair(Reg::X(29), z6, false),
        0x80..=0xBF => pair(Reg::X(29), z6 + 8, true),
        0xC0..=0xC7 => Op::Alloc((v & 0x7FF) * 16),
        0xC8..=0xCB => pair(x((v >> 6) & 15), z6, false),
        0xCC..=0xCF => pair(x((v >> 6) & 15), z6 + 8, true),
        0xD0..=0xD3 => Op::Save {
            reg: x((v >> 6) & 15),
            offset: z6,
            pre: false,
        },
        0xD4..=0xD5 => Op::Save {
            reg: x((v >> 5) & 15),
            offset: (v & 0x1F) * 8 + 8,
            pre: true,
        },
        0xD6..=0xD7 => Op::SavePair {
            a: x(2 * ((v >> 6) & 7)),
            b: Reg::X(30),
            offset: z6,
            pre: false,
        },
        0xD8..=0xD9 => pair(d((v >> 6) & 7), z6, false),
        0xDA..=0xDB => pair(d((v >> 6) & 7), z6 + 8, true),
        0xDC..=0xDD => Op::Save {
            reg: d((v >> 6) & 7),
            offset: z6,
            pre: false,
        },
        0xDE => Op::Save {
            reg: d((v >> 5) & 7),
            offset: (v & 0x1F) * 8 + 8,
            pre: true,
        },
        0xE0 => Op::Alloc((v & 0xFF_FFFF) * 16),
        0xE1 => Op::SetFp,
        0xE2 => Op::AddFp((v & 0xFF) * 8),
        0xE3 => Op::Nop,
        0xE4 => Op::End,
        0xE5 => Op::EndC,
        0xE6 => Op::SaveNext,
        0xE9 => Op::MachineFrame,
        0xEA => Op::Context,
        0xEC => Op::ClearUnwoundToCall,
        0xFC => Op::PacSignLr,
        _ => return Err(UnwindError::Unsupported(b0)),
    };
    Ok((op, len))
}

/// Iterator over a byte string of unwind codes. Stops after an error.
#[derive(Debug, Clone)]
pub struct Codes<'a>(&'a [u8]);

impl Iterator for Codes<'_> {
    type Item = Result<Op, UnwindError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() {
            return None;
        }
        let r = decode(self.0);
        self.0 = match r {
            Ok((_, len)) => &self.0[len..],
            Err(_) => &[],
        };
        Some(r.map(|(op, _)| op))
    }
}

/// A language handler named by an `.xdata` record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handler {
    pub rva: u32,
    /// RVA of the handler's data, the `HandlerData` of a
    /// `DISPATCHER_CONTEXT`.
    pub data_rva: u32,
}

/// A parsed `.xdata` record.
#[derive(Debug, Clone, Copy)]
pub struct Xdata<'a> {
    /// Length of the function or fragment in bytes.
    pub function_len: u32,
    pub handler: Option<Handler>,
    /// The E bit: one epilog, at the end of the function, whose codes
    /// start at this index.
    pub packed_epilog: Option<u32>,
    scopes: &'a [u8],
    codes: &'a [u8],
}

impl<'a> Xdata<'a> {
    pub fn parse(image: &'a [u8], rva: u32) -> Result<Self, UnwindError> {
        let mut at = rva as usize;
        let head = u32_at(image, at)?;
        at += 4;
        if (head >> 18) & 3 != 0 {
            return Err(UnwindError::BadUnwindInfo);
        }
        let (has_handler, e) = (head & 1 << 20 != 0, head & 1 << 21 != 0);
        let (mut epilogs, mut words) = ((head >> 22) & 0x1F, head >> 27);
        if epilogs == 0 && words == 0 {
            let ext = u32_at(image, at)?;
            at += 4;
            (epilogs, words) = (ext & 0xFFFF, (ext >> 16) & 0xFF);
        }
        let scopes = bytes_at(image, at, if e { 0 } else { 4 * epilogs as usize })?;
        at += scopes.len();
        let codes = bytes_at(image, at, 4 * words as usize)?;
        at += codes.len();
        let handler = if has_handler {
            Some(Handler {
                rva: u32_at(image, at)?,
                data_rva: u32::try_from(at + 4).map_err(|_| UnwindError::OutOfBounds)?,
            })
        } else {
            None
        };
        Ok(Self {
            function_len: (head & 0x3_FFFF) * 4,
            handler,
            packed_epilog: e.then_some(epilogs),
            scopes,
            codes,
        })
    }

    /// The unwind code bytes, padding included.
    pub fn code_bytes(&self) -> &'a [u8] {
        self.codes
    }

    /// The codes from byte `index` on.
    pub fn codes(&self, index: u32) -> Codes<'a> {
        Codes(self.codes.get(index as usize..).unwrap_or(&[]))
    }

    /// The epilog scopes: `(start offset in bytes, first code index)`.
    /// Empty when the E bit packs the one epilog into the header.
    pub fn epilog_scopes(&self) -> impl Iterator<Item = (u32, u32)> + use<'a> {
        self.scopes.as_chunks::<4>().0.iter().map(|w| {
            let w = u32::from_le_bytes(*w);
            ((w & 0x3_FFFF) * 4, w >> 22)
        })
    }
}

/// Longest canonical sequence: frame setup (4), parameter homing (4),
/// eight vector registers (4), ten integer registers and `lr` (6),
/// `pacibsp`, end.
const CANONICAL_MAX: usize = 20;

/// The operations of a canonical prolog or epilog, in the order an
/// `.xdata` record would store them, ending with [`Op::End`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Canonical {
    ops: [Op; CANONICAL_MAX],
    len: usize,
}

impl Canonical {
    pub fn ops(&self) -> &[Op] {
        &self.ops[..self.len]
    }

    fn push(&mut self, op: Op) {
        // CANONICAL_MAX bounds every sequence `canonical` can build.
        if let Some(slot) = self.ops.get_mut(self.len) {
            *slot = op;
            self.len += 1;
        }
    }
}

/// Expand packed unwind data to the canonical prolog it names (or, with
/// `epilog`, the canonical epilog: the same without the frame-pointer
/// setup and the parameter homing).
///
/// The combinations with no integer or vector register to carry the
/// save area's pre-decrement follow the table in Microsoft's document
/// where it speaks and LLVM's reading of it where it does not: `lr`
/// alone is stored pre-indexed, `x19` with `lr` as a pre-indexed pair,
/// and a homing-only save area by the first homing store.
pub fn canonical(packed: u32, epilog: bool) -> Result<Canonical, UnwindError> {
    let reg_f = (packed >> 13) & 7;
    let reg_i = (packed >> 16) & 15;
    let homes = (packed >> 20) & 1 != 0;
    let cr = (packed >> 21) & 3;
    let frame = (packed >> 23) * 16;
    let (save_lr, chained) = (cr == 1, cr >= 2);

    let int_size = reg_i * 8 + if save_lr { 8 } else { 0 };
    let fp_regs = if reg_f == 0 { 0 } else { reg_f + 1 };
    let saved = (int_size + fp_regs * 8 + if homes { 64 } else { 0 } + 15) & !15;
    if reg_i > 10 || saved > frame {
        return Err(UnwindError::BadUnwindInfo);
    }
    let locals = frame - saved;
    if chained && locals == 0 {
        return Err(UnwindError::BadUnwindInfo);
    }

    // Built in prolog order, reversed at the end. The first store into
    // the save area allocates it.
    let mut c = Canonical {
        ops: [Op::End; CANONICAL_MAX],
        len: 0,
    };
    let mut first = saved != 0;
    let mut place = |offset: u32| {
        let pre = core::mem::take(&mut first);
        (if pre { saved } else { offset }, pre)
    };
    if cr == 2 {
        c.push(Op::PacSignLr);
    }
    for i in (0..reg_i).step_by(2) {
        let a = Reg::X(19 + i as u8);
        let (offset, pre) = place(i * 8);
        c.push(if i + 1 < reg_i {
            Op::SavePair {
                a,
                b: a.plus(1),
                offset,
                pre,
            }
        } else if save_lr {
            Op::SavePair {
                a,
                b: Reg::X(30),
                offset,
                pre,
            }
        } else {
            Op::Save {
                reg: a,
                offset,
                pre,
            }
        });
    }
    if save_lr && reg_i % 2 == 0 {
        let (offset, pre) = place(int_size - 8);
        c.push(Op::Save {
            reg: Reg::X(30),
            offset,
            pre,
        });
    }
    for i in (0..fp_regs).step_by(2) {
        let a = Reg::D(8 + i as u8);
        let (offset, pre) = place(int_size + i * 8);
        c.push(if i + 1 < fp_regs {
            Op::SavePair {
                a,
                b: a.plus(1),
                offset,
                pre,
            }
        } else {
            Op::Save {
                reg: a,
                offset,
                pre,
            }
        });
    }
    if homes {
        let (_, pre) = place(0);
        if pre {
            c.push(Op::Alloc(saved));
        } else if !epilog {
            c.push(Op::Nop);
        }
        for _ in 0..if epilog { 0 } else { 3 } {
            c.push(Op::Nop);
        }
    }
    let fplr = |offset: u32, pre: bool| Op::SavePair {
        a: Reg::X(29),
        b: Reg::X(30),
        offset,
        pre,
    };
    if chained && locals <= 512 {
        c.push(fplr(locals, true));
    } else if locals != 0 {
        c.push(Op::Alloc(locals.min(4080)));
        if locals > 4080 {
            c.push(Op::Alloc(locals - 4080));
        }
        if chained {
            c.push(fplr(0, false));
        }
    }
    if chained && !epilog {
        c.push(Op::SetFp);
    }
    c.ops[..c.len].reverse();
    c.len += 1; // the End the array was filled with
    Ok(c)
}

/// The result of unwinding one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unwound {
    /// The caller's registers; `pc` is where the frame resumes.
    pub regs: Regs,
    /// The caller's `sp`, which language handlers receive as the frame.
    pub establisher: u64,
    pub place: Place,
    pub handler: Option<Handler>,
    /// `regs.pc` is the return address of a call, so the instruction that
    /// was executing is the one before it. False after an interrupted
    /// frame.
    pub unwound_to_call: bool,
}

/// Unwind a function that has no `.pdata` entry: a leaf, which keeps its
/// return address in `lr` and never moves `sp`.
pub fn unwind_leaf(regs: &Regs) -> Regs {
    let mut r = *regs;
    r.pc = r.x[LR];
    r
}

/// Unwind the frame of `func` from `pc_rva`: compute the registers of its
/// caller. `regs` are the registers at `pc_rva`; `read` returns the
/// 64-bit value at a stack address, or `None` if it is not readable.
pub fn virtual_unwind(
    image: &[u8],
    func: &FunctionEntry,
    pc_rva: u32,
    regs: &Regs,
    read: &mut impl FnMut(u64) -> Option<u64>,
) -> Result<Unwound, UnwindError> {
    let offset = pc_rva.wrapping_sub(func.begin);
    match func.unwind {
        UnwindData::Packed(word) => {
            let prolog = canonical(word, false)?;
            let epilog = canonical(word, true)?;
            let ops = |c: Canonical| c.ops.into_iter().take(c.len).map(Ok);
            // Flag 2 is a fragment with neither prolog nor epilog.
            let (prolog_len, epilog_len) = if word & 3 == 1 {
                (4 * (prolog.len as u32 - 1), 4 * epilog.len as u32)
            } else {
                (0, 0)
            };
            let epilog_start = func.len.wrapping_sub(epilog_len);
            let (place, seq, skip) = if offset < prolog_len {
                (Place::Prolog, ops(prolog), (prolog_len - offset) / 4)
            } else if offset >= epilog_start && offset < func.len {
                (Place::Epilog, ops(epilog), (offset - epilog_start) / 4)
            } else {
                (Place::Body, ops(prolog), 0)
            };
            run(seq, skip, place, None, regs, read)
        }
        UnwindData::Xdata(rva) => {
            let x = Xdata::parse(image, rva)?;
            let prolog_len = 4 * instructions(x.codes(0))?;
            let (place, index, skip) = if offset < prolog_len {
                (Place::Prolog, 0, (prolog_len - offset) / 4)
            } else if let Some((start, index)) = epilog_at(&x, offset)? {
                (Place::Epilog, index, (offset - start) / 4)
            } else {
                (Place::Body, 0, 0)
            };
            run(x.codes(index), skip, place, x.handler, regs, read)
        }
    }
}

/// Instructions a code sequence stands for, up to its end.
fn instructions(codes: impl Iterator<Item = Result<Op, UnwindError>>) -> Result<u32, UnwindError> {
    let mut n = 0;
    for op in codes {
        match op? {
            Op::End | Op::EndC => return Ok(n),
            op => n += u32::from(op.is_instruction()),
        }
    }
    Err(UnwindError::BadUnwindInfo)
}

/// The epilog containing byte `offset` of the function: its start offset
/// and first code index. An epilog is its codes plus the return.
fn epilog_at(x: &Xdata<'_>, offset: u32) -> Result<Option<(u32, u32)>, UnwindError> {
    if let Some(index) = x.packed_epilog {
        let len = 4 * (instructions(x.codes(index))? + 1);
        let start = x.function_len.wrapping_sub(len);
        return Ok((offset.wrapping_sub(start) < len).then_some((start, index)));
    }
    for (start, index) in x.epilog_scopes() {
        if offset >= start && offset - start < 4 * (instructions(x.codes(index))? + 1) {
            return Ok(Some((start, index)));
        }
    }
    Ok(None)
}

/// Execute a code sequence after skipping the codes of `skip`
/// instructions: those the prolog had not yet run, or the epilog already
/// had.
fn run(
    codes: impl Iterator<Item = Result<Op, UnwindError>>,
    mut skip: u32,
    place: Place,
    handler: Option<Handler>,
    regs: &Regs,
    read: &mut impl FnMut(u64) -> Option<u64>,
) -> Result<Unwound, UnwindError> {
    let mut r = *regs;
    let mut out = Unwound {
        regs: r,
        establisher: 0,
        place,
        handler,
        unwound_to_call: true,
    };
    let mut pc_restored = false;
    // Registers a pending `save_next` adds to the pair save after it.
    let mut extra = 0u8;
    for op in codes {
        let op = op?;
        if skip != 0 && op != Op::End {
            skip -= u32::from(op.is_instruction());
            continue;
        }
        if extra != 0 && !matches!(op, Op::SaveNext | Op::SavePair { .. }) {
            return Err(UnwindError::BadUnwindInfo);
        }
        match op {
            Op::Alloc(n) => r.sp = r.sp.wrapping_add(u64::from(n)),
            Op::Save { reg, offset, pre } => {
                let at = r.sp.wrapping_add(if pre { 0 } else { u64::from(offset) });
                set(&mut r, reg, slot(read, at)?);
                if pre {
                    r.sp = r.sp.wrapping_add(u64::from(offset));
                }
            }
            Op::SavePair { a, b, offset, pre } => {
                let at = r.sp.wrapping_add(if pre { 0 } else { u64::from(offset) });
                set(&mut r, a, slot(read, at)?);
                set(&mut r, b, slot(read, at.wrapping_add(8))?);
                for i in 0..extra {
                    let value = slot(read, at.wrapping_add(16 + 8 * u64::from(i)))?;
                    set(&mut r, b.plus(1 + i), value);
                }
                extra = 0;
                if pre {
                    r.sp = r.sp.wrapping_add(u64::from(offset));
                }
            }
            Op::SaveNext if extra >= 16 => return Err(UnwindError::BadUnwindInfo),
            Op::SaveNext => extra += 2,
            Op::SetFp => r.sp = r.x[FP],
            Op::AddFp(n) => r.sp = r.x[FP].wrapping_sub(u64::from(n)),
            Op::Nop | Op::PacSignLr | Op::EndC => {}
            Op::MachineFrame => {
                r.pc = slot(read, r.sp.wrapping_add(8))?;
                r.sp = slot(read, r.sp)?;
                (pc_restored, out.unwound_to_call) = (true, false);
            }
            Op::Context => {
                restore_context(&mut r, read)?;
                (pc_restored, out.unwound_to_call) = (true, false);
            }
            Op::ClearUnwoundToCall => out.unwound_to_call = false,
            Op::End => {
                if !pc_restored {
                    r.pc = r.x[LR];
                }
                out.regs = r;
                out.establisher = r.sp;
                return Ok(out);
            }
        }
    }
    Err(UnwindError::BadUnwindInfo)
}

fn set(r: &mut Regs, reg: Reg, value: u64) {
    // Registers outside the non-volatile sets are not tracked.
    let slot = match reg {
        Reg::X(n) => (n as usize).checked_sub(19).and_then(|i| r.x.get_mut(i)),
        Reg::D(n) => (n as usize).checked_sub(8).and_then(|i| r.d.get_mut(i)),
    };
    if let Some(slot) = slot {
        *slot = value;
    }
}

/// Reload the tracked registers from the `CONTEXT` at `sp`.
fn restore_context(
    r: &mut Regs,
    read: &mut impl FnMut(u64) -> Option<u64>,
) -> Result<(), UnwindError> {
    let base = r.sp;
    for n in 19..=30 {
        let value = slot(read, base.wrapping_add(CONTEXT_X0 + 8 * n))?;
        set(r, Reg::X(n as u8), value);
    }
    for n in 8..=15 {
        let value = slot(read, base.wrapping_add(CONTEXT_V0 + 16 * n))?;
        set(r, Reg::D(n as u8), value);
    }
    r.pc = slot(read, base.wrapping_add(CONTEXT_PC))?;
    r.sp = slot(read, base.wrapping_add(CONTEXT_SP))?;
    Ok(())
}
