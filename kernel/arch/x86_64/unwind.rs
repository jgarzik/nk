//! Stack walking on x86-64: capturing a register set to start from, and
//! one step of the walk, over `nk_unwind::x64`.

use core::arch::global_asm;
use core::mem::MaybeUninit;
use nk_pe::DataDir;
use nk_unwind::UnwindError;
use nk_unwind::x64::{self, RSP};

pub use nk_unwind::x64::Regs;

/// What `nk_capture_context` stores: the registers a call preserves, as
/// its caller has them.
#[repr(C)]
struct Captured {
    /// rbx, rbp, rsi, rdi, r12-r15.
    gpr: [u64; 8],
    /// The caller's stack pointer once the call has returned.
    rsp: u64,
    /// Where the call returns to.
    rip: u64,
    /// xmm6-xmm15.
    xmm: [[u64; 2]; 10],
}

/// Where each of `Captured::gpr` goes in `Regs::gpr`, which is indexed by
/// register number.
const GPR: [usize; 8] = [3, 5, 6, 7, 12, 13, 14, 15];

global_asm!(
    r#"
    .text
    .globl nk_capture_context
// rcx: a `Captured` to fill in. Uses no stack, so the caller's stack
// pointer is this one's less the return address.
nk_capture_context:
    .seh_proc nk_capture_context
    .seh_endprologue
    mov [rcx + 0x00], rbx
    mov [rcx + 0x08], rbp
    mov [rcx + 0x10], rsi
    mov [rcx + 0x18], rdi
    mov [rcx + 0x20], r12
    mov [rcx + 0x28], r13
    mov [rcx + 0x30], r14
    mov [rcx + 0x38], r15
    lea rax, [rsp + 8]
    mov [rcx + 0x40], rax
    mov rax, [rsp]
    mov [rcx + 0x48], rax
    movups [rcx + 0x50], xmm6
    movups [rcx + 0x60], xmm7
    movups [rcx + 0x70], xmm8
    movups [rcx + 0x80], xmm9
    movups [rcx + 0x90], xmm10
    movups [rcx + 0xA0], xmm11
    movups [rcx + 0xB0], xmm12
    movups [rcx + 0xC0], xmm13
    movups [rcx + 0xD0], xmm14
    movups [rcx + 0xE0], xmm15
    ret
    .seh_endproc
"#
);

unsafe extern "C" {
    fn nk_capture_context(into: *mut Captured);
}

/// The registers of the function this is written in, as they are right
/// after this call: what a walk of the current stack starts from. Always
/// in line, so that "the caller" is that function and not a wrapper whose
/// frame is gone by the time the walk reads it. The volatile registers
/// are zero.
#[inline(always)]
pub fn capture() -> Regs {
    let mut captured = MaybeUninit::<Captured>::uninit();
    // SAFETY: the routine fills in every field of the block it is given
    // and touches nothing else.
    let c = unsafe {
        nk_capture_context(captured.as_mut_ptr());
        captured.assume_init()
    };
    let mut regs = Regs {
        gpr: [0; 16],
        rip: c.rip,
        xmm: c.xmm.map(|[lo, hi]| u128::from(hi) << 64 | u128::from(lo)),
    };
    for (&at, value) in GPR.iter().zip(c.gpr) {
        regs.gpr[at] = value;
    }
    regs.gpr[RSP] = c.rsp;
    regs
}

pub fn pc(regs: &Regs) -> u64 {
    regs.rip
}

pub fn sp(regs: &Regs) -> u64 {
    regs.gpr[RSP]
}

/// One frame undone.
pub struct Step {
    /// The registers of the frame beneath.
    pub regs: Regs,
    /// RVA of the start of the function the frame was in.
    pub function: u32,
    /// The frame was an interrupt's: the frame beneath was stopped at
    /// its `pc`, not waiting for a call to return there.
    pub interrupted: bool,
    /// RVA of the function's entry in the function table.
    pub entry: u32,
    /// The frame's base, as its language handler is given it.
    pub establisher: u64,
    /// The function's language handler, when the frame is in its body.
    pub handler: Option<Handler>,
}

/// A language handler a function's unwind record names.
#[derive(Clone, Copy)]
pub struct Handler {
    pub rva: u32,
    /// RVA of the handler's data.
    pub data_rva: u32,
    /// Called while a handler for the exception is searched for.
    pub search: bool,
    /// Called while the frame is unwound.
    pub unwind: bool,
}

/// Undo the frame of the function that holds `rva` in the image `image`,
/// whose function table is `pdata`. `None` if no entry covers `rva`. A
/// return address is looked up as it is, as Windows does: a compiler
/// for Windows puts an instruction after a call that would otherwise
/// end its function.
pub fn step(
    image: &[u8],
    pdata: DataDir,
    rva: u32,
    regs: &Regs,
    _return_address: bool,
    read: &mut impl FnMut(u64) -> Option<u64>,
) -> Result<Option<Step>, UnwindError> {
    let Some((entry, function)) = x64::locate(image, pdata.rva, pdata.size, rva)? else {
        return Ok(None);
    };
    let unwound = x64::virtual_unwind(image, &function, rva, regs, read)?;
    Ok(Some(Step {
        regs: unwound.regs,
        function: function.begin,
        interrupted: unwound.machine_frame,
        entry,
        establisher: unwound.establisher,
        handler: unwound.handler.map(|h| Handler {
            rva: h.rva,
            data_rva: h.data_rva,
            search: h.exception,
            unwind: h.termination,
        }),
    }))
}

/// Undo the frame of a function with no entry, taken for a leaf: its
/// return address is on top of the stack.
pub fn leaf(regs: &Regs, read: &mut impl FnMut(u64) -> Option<u64>) -> Result<Regs, UnwindError> {
    x64::unwind_leaf(regs, read)
}
