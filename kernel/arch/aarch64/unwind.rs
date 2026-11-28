//! Stack walking on arm64: capturing a register set to start from, and
//! one step of the walk, over `nk_unwind::arm64`.

use core::arch::global_asm;
use core::ffi::c_void;
use core::mem::MaybeUninit;
use nk_ntabi::seh::arm64::{CONTEXT, CONTEXT_FULL};
use nk_pe::DataDir;
use nk_unwind::UnwindError;
use nk_unwind::arm64;

pub use nk_unwind::arm64::Regs;

/// `ContextFlags` populated by [`nk_rtl_capture_context`].
pub const CAPTURE_CONTEXT_FLAGS: u32 = CONTEXT_FULL;

/// Return `ContextFlags` from an arm64 `CONTEXT`.
pub fn context_flags(context: &CONTEXT) -> u32 {
    context.ContextFlags
}

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

    .globl nk_rtl_capture_context
// x0: a Windows arm64 `CONTEXT` (`0x390` bytes) to fill with the caller's
// state directly at the ABI boundary, with no intervening wrapper frame.
// Volatile scratch registers `x9`-`x11` are recorded as zero.
nk_rtl_capture_context:
    .seh_proc nk_rtl_capture_context
    .seh_endprologue
    cbz x0, 9f
    mrs x11, nzcv
    mov x9, #0x390
2:  sub x9, x9, #16
    add x10, x0, x9
    stp xzr, xzr, [x10]
    cbnz x9, 2b
    mov w9, #{flags_low}
    movk w9, #{flags_high}, lsl #16
    str w9, [x0]
    mrs x10, daif
    orr x11, x11, x10
    mrs x10, CurrentEL
    orr x11, x11, x10
    orr x11, x11, #1
    str w11, [x0, #4]
    stp x0, x1, [x0, #0x08]
    stp x2, x3, [x0, #0x18]
    stp x4, x5, [x0, #0x28]
    stp x6, x7, [x0, #0x38]
    stp x8, xzr, [x0, #0x48]
    stp xzr, xzr, [x0, #0x58]
    stp x12, x13, [x0, #0x68]
    stp x14, x15, [x0, #0x78]
    stp x16, x17, [x0, #0x88]
    stp x18, x19, [x0, #0x98]
    stp x20, x21, [x0, #0xA8]
    stp x22, x23, [x0, #0xB8]
    stp x24, x25, [x0, #0xC8]
    stp x26, x27, [x0, #0xD8]
    stp x28, x29, [x0, #0xE8]
    mov x9, sp
    stp x30, x9, [x0, #0xF8]
    str x30, [x0, #0x108]
    stp q0, q1, [x0, #0x110]
    stp q2, q3, [x0, #0x130]
    stp q4, q5, [x0, #0x150]
    stp q6, q7, [x0, #0x170]
    stp q8, q9, [x0, #0x190]
    stp q10, q11, [x0, #0x1B0]
    stp q12, q13, [x0, #0x1D0]
    stp q14, q15, [x0, #0x1F0]
    stp q16, q17, [x0, #0x210]
    stp q18, q19, [x0, #0x230]
    stp q20, q21, [x0, #0x250]
    stp q22, q23, [x0, #0x270]
    stp q24, q25, [x0, #0x290]
    stp q26, q27, [x0, #0x2B0]
    stp q28, q29, [x0, #0x2D0]
    stp q30, q31, [x0, #0x2F0]
    mrs x9, fpcr
    mrs x10, fpsr
    str w9, [x0, #0x310]
    str w10, [x0, #0x314]
9:  ret
    .seh_endproc
"#,
    flags_low = const (CAPTURE_CONTEXT_FLAGS & 0xFFFF),
    flags_high = const (CAPTURE_CONTEXT_FLAGS >> 16),
);

unsafe extern "C" {
    fn nk_capture_context(into: *mut Captured);
    /// [`RtlCaptureContext`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlcapturecontext):
    /// capture the caller's register context into `context` at the ABI boundary.
    pub fn nk_rtl_capture_context(context: *mut c_void);
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
