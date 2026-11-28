//! Stack walking on arm64: capturing a register set to start from, and
//! one step of the walk, over `nk_unwind::arm64`.

use core::arch::global_asm;
use core::mem::MaybeUninit;
use nk_pe::DataDir;
use nk_unwind::UnwindError;
use nk_unwind::arm64;

pub use nk_unwind::arm64::Regs;

/// What `nk_capture_context` stores: the registers a call preserves, as
/// its caller has them.
#[repr(C)]
struct Captured {
    /// x19-x30. x30 is where the call returns to.
    x: [u64; 12],
    sp: u64,
    /// d8-d15.
    d: [u64; 8],
}

global_asm!(
    r#"
    .text
    .globl nk_capture_context
// x0: a `Captured` to fill in. Uses no stack: the stack pointer is the
// caller's.
nk_capture_context:
    .seh_proc nk_capture_context
    .seh_endprologue
    stp x19, x20, [x0]
    stp x21, x22, [x0, #16]
    stp x23, x24, [x0, #32]
    stp x25, x26, [x0, #48]
    stp x27, x28, [x0, #64]
    stp x29, x30, [x0, #80]
    mov x9, sp
    str x9, [x0, #96]
    stp d8, d9, [x0, #104]
    stp d10, d11, [x0, #120]
    stp d12, d13, [x0, #136]
    stp d14, d15, [x0, #152]
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
/// frame is gone by the time the walk reads it.
#[inline(always)]
pub fn capture() -> Regs {
    let mut captured = MaybeUninit::<Captured>::uninit();
    // SAFETY: the routine fills in every field of the block it is given
    // and touches nothing else.
    let c = unsafe {
        nk_capture_context(captured.as_mut_ptr());
        captured.assume_init()
    };
    Regs {
        x: c.x,
        sp: c.sp,
        pc: c.x[arm64::LR],
        d: c.d,
    }
}

pub fn pc(regs: &Regs) -> u64 {
    regs.pc
}

pub fn sp(regs: &Regs) -> u64 {
    regs.sp
}

/// Fill a Windows `CONTEXT` record with the captured register state.
///
/// # Safety
/// `context` is writable for an arm64 `CONTEXT` structure.
pub unsafe fn fill_context(regs: &Regs, context: *mut core::ffi::c_void) {
    let context = context.cast::<nk_ntabi::seh::arm64::CONTEXT>();
    // SAFETY: per the contract.
    unsafe {
        core::ptr::write_bytes(
            context.cast::<u8>(),
            0,
            size_of::<nk_ntabi::seh::arm64::CONTEXT>(),
        );
        (*context).ContextFlags = nk_ntabi::seh::arm64::CONTEXT_FULL;
        (*context).Pc = regs.pc;
        (*context).Sp = regs.sp;
        for (i, &val) in regs.x[..10].iter().enumerate() {
            (*context).X[19 + i] = val;
        }
        (*context).Fp = regs.x[10];
        (*context).Lr = regs.x[11];
    }
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
/// return address is looked up as the call before it, as Windows does:
/// a call may be a function's last instruction, and what follows it
/// another function.
pub fn step(
    image: &[u8],
    pdata: DataDir,
    rva: u32,
    regs: &Regs,
    return_address: bool,
    read: &mut impl FnMut(u64) -> Option<u64>,
) -> Result<Option<Step>, UnwindError> {
    let rva = if return_address {
        rva.wrapping_sub(4)
    } else {
        rva
    };
    let Some((entry, function)) = arm64::locate(image, pdata.rva, pdata.size, rva)? else {
        return Ok(None);
    };
    let unwound = arm64::virtual_unwind(image, &function, rva, regs, read)?;
    // An arm64 record names one handler for both passes.
    let handler = unwound
        .handler
        .filter(|_| unwound.place == nk_unwind::Place::Body)
        .map(|h| Handler {
            rva: h.rva,
            data_rva: h.data_rva,
            search: true,
            unwind: true,
        });
    Ok(Some(Step {
        regs: unwound.regs,
        function: function.begin,
        interrupted: !unwound.unwound_to_call,
        entry,
        establisher: unwound.establisher,
        handler,
    }))
}

/// Undo the frame of a function with no entry, taken for a leaf: its
/// return address is in `x30`.
pub fn leaf(regs: &Regs, _read: &mut impl FnMut(u64) -> Option<u64>) -> Result<Regs, UnwindError> {
    Ok(arm64::unwind_leaf(regs))
}
