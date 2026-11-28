//! Extended processor state (x87, SSE, AVX via XSAVE/XRSTOR with FXSAVE fallback)
//! and CPUID feature discovery for `KUSER_SHARED_DATA`.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use nk_ntabi::ke::{
    SHARED_PROCESSOR_FEATURES, SHARED_XSTATE, XSTATE_MASK_AVX, XSTATE_MASK_LEGACY, pf,
};
use nk_ntabi::seh::x64::{XSTATE_CONFIGURATION, XSTATE_FEATURE};

/// Maximum XSAVE area size NK supports (legacy 512 + header 64 + AVX YMMH 256 = 832;
/// 1024 leaves headroom and stays 64-byte aligned).
pub const MAX_AREA_SIZE: usize = 1024;
/// Inline buffer size in `Thread` so any 16-byte-aligned struct contains a
/// 64-byte-aligned `MAX_AREA_SIZE`-byte save area.
pub const AREA_BUF_SIZE: usize = MAX_AREA_SIZE + 64;

const INITIAL_FPCSR: u16 = 0x027F;
const INITIAL_MXCSR: u32 = 0x1F80;
const CR4_OSXSAVE: u64 = 1 << 18;

static USE_XSAVE: AtomicBool = AtomicBool::new(false);
static USE_XSAVEOPT: AtomicBool = AtomicBool::new(false);
static ENABLED_MASK: AtomicU64 = AtomicU64::new(XSTATE_MASK_LEGACY);
static AREA_SIZE: AtomicUsize = AtomicUsize::new(512);
static AVX_OFFSET: AtomicU32 = AtomicU32::new(0);
static AVX_SIZE: AtomicU32 = AtomicU32::new(0);
static MXCSR_MASK: AtomicU32 = AtomicU32::new(0xFFBF);
static HAS_SMEP: AtomicBool = AtomicBool::new(false);
/// Bitmask of `PF_*` indices supported on this processor (all indices < 64).
static PF_MASK: AtomicU64 = AtomicU64::new(0);

fn cpuid(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ecx, edx): (u32, u32, u32);
    let ebx_full: u64;
    // SAFETY: `cpuid` is a side-effect-free processor query; `rbx` is saved and
    // restored in a scratch register because LLVM reserves `rbx` on x86-64.
    unsafe {
        core::arch::asm!(
            "mov {tmp}, rbx",
            "cpuid",
            "xchg {tmp}, rbx",
            tmp = out(reg) ebx_full,
            inout("eax") leaf => eax,
            inout("ecx") subleaf => ecx,
            out("edx") edx,
            options(nomem, nostack),
        );
    }
    (eax, ebx_full as u32, ecx, edx)
}

fn enable_cr4_osxsave() {
    // SAFETY: setting `CR4.OSXSAVE` is valid once CPUID.1:ECX[26] reports XSAVE.
    unsafe {
        core::arch::asm!(
            "mov {t}, cr4",
            "or {t}, {bit}",
            "mov cr4, {t}",
            t = out(reg) _,
            bit = const CR4_OSXSAVE,
            options(nomem, nostack),
        );
    }
}

fn write_xcr0(mask: u64) {
    // SAFETY: called only after `CR4.OSXSAVE` is enabled and `mask` has been
    // masked against CPUID.0Dh.0 supported bits with x87 (bit 0) set.
    unsafe {
        core::arch::asm!(
            "xsetbv",
            in("ecx") 0u32,
            in("eax") mask as u32,
            in("edx") (mask >> 32) as u32,
            options(nomem, nostack),
        );
    }
}

fn probe_mxcsr_mask() -> u32 {
    #[repr(C, align(16))]
    struct FxArea([u8; 512]);
    let mut area = FxArea([0; 512]);
    // SAFETY: `CR4.OSFXSR` is enabled before `detect_and_enable` runs, and
    // `area` is 16-byte aligned and 512 bytes long.
    unsafe {
        core::arch::asm!(
            "fxsave64 [{p}]",
            p = in(reg) area.0.as_mut_ptr(),
            options(nostack),
        );
    }
    let mask = u32::from_le_bytes([area.0[28], area.0[29], area.0[30], area.0[31]]);
    if mask == 0 { 0xFFBF } else { mask }
}

/// Detect CPUID features and enable `CR4.OSXSAVE` / `XCR0` on this CPU.
/// Called during `cpu::init` on the BSP (`is_bsp == true`) and each AP.
pub fn detect_and_enable(is_bsp: bool) {
    if !is_bsp {
        if USE_XSAVE.load(Ordering::Acquire) {
            enable_cr4_osxsave();
            write_xcr0(ENABLED_MASK.load(Ordering::Acquire));
        }
        return;
    }

    MXCSR_MASK.store(probe_mxcsr_mask(), Ordering::Release);

    let (max_leaf, _, _, _) = cpuid(0, 0);
    let (_, _, ecx1, edx1) = cpuid(1, 0);
    let (max_ext, _, _, _) = cpuid(0x8000_0000, 0);
    let ext_edx = if max_ext >= 0x8000_0001 {
        cpuid(0x8000_0001, 0).3
    } else {
        0
    };
    let ebx7 = if max_leaf >= 7 { cpuid(7, 0).1 } else { 0 };

    HAS_SMEP.store((ebx7 & (1 << 7)) != 0, Ordering::Release);

    let has_xsave = (ecx1 & (1 << 26)) != 0;
    let cpu_avx = (ecx1 & (1 << 28)) != 0;
    let cpu_avx2 = (ebx7 & (1 << 5)) != 0;

    let mut enabled_mask = XSTATE_MASK_LEGACY;
    let mut area_size = 512usize;
    let mut use_xsave = false;
    let mut use_xsaveopt = false;
    let mut avx_offset = 0u32;
    let mut avx_size = 0u32;

    if has_xsave && max_leaf >= 0x0D {
        enable_cr4_osxsave();
        let (xcr0_lo, _, _, xcr0_hi) = cpuid(0x0D, 0);
        let supported = u64::from(xcr0_lo) | (u64::from(xcr0_hi) << 32);
        let mut desired = supported & XSTATE_MASK_LEGACY;
        if cpu_avx && (supported & XSTATE_MASK_AVX) != 0 {
            desired |= XSTATE_MASK_AVX;
        }
        if (desired & XSTATE_MASK_LEGACY) == XSTATE_MASK_LEGACY {
            write_xcr0(desired);
            let (_, cur_size, _, _) = cpuid(0x0D, 0);
            if (cur_size as usize) <= MAX_AREA_SIZE && cur_size >= 576 {
                enabled_mask = desired;
                area_size = cur_size as usize;
                use_xsave = true;
            } else {
                // Clamp to legacy components if hardware reports an oversized area.
                write_xcr0(XSTATE_MASK_LEGACY);
                let (_, legacy_size, _, _) = cpuid(0x0D, 0);
                if (legacy_size as usize) <= MAX_AREA_SIZE && legacy_size >= 576 {
                    enabled_mask = XSTATE_MASK_LEGACY;
                    area_size = legacy_size as usize;
                    use_xsave = true;
                }
            }
            if use_xsave {
                let (eax_sub1, _, _, _) = cpuid(0x0D, 1);
                use_xsaveopt = (eax_sub1 & 1) != 0;
                if (enabled_mask & XSTATE_MASK_AVX) != 0 {
                    let (sz, off, _, _) = cpuid(0x0D, 2);
                    avx_size = sz;
                    avx_offset = off;
                }
            }
        }
    }

    USE_XSAVE.store(use_xsave, Ordering::Release);
    USE_XSAVEOPT.store(use_xsaveopt, Ordering::Release);
    ENABLED_MASK.store(enabled_mask, Ordering::Release);
    AREA_SIZE.store(area_size, Ordering::Release);
    AVX_OFFSET.store(avx_offset, Ordering::Release);
    AVX_SIZE.store(avx_size, Ordering::Release);

    let mut pf_mask = 0u64;
    let mut set_pf = |idx: usize, cond: bool| {
        if cond {
            pf_mask |= 1u64 << idx;
        }
    };
    set_pf(pf::COMPARE_EXCHANGE_DOUBLE, (edx1 & (1 << 8)) != 0);
    set_pf(pf::MMX_INSTRUCTIONS_AVAILABLE, (edx1 & (1 << 23)) != 0);
    set_pf(pf::XMMI_INSTRUCTIONS_AVAILABLE, (edx1 & (1 << 25)) != 0);
    set_pf(pf::RDTSC_INSTRUCTION_AVAILABLE, (edx1 & (1 << 4)) != 0);
    set_pf(pf::PAE_ENABLED, (edx1 & (1 << 6)) != 0);
    set_pf(pf::XMMI64_INSTRUCTIONS_AVAILABLE, (edx1 & (1 << 26)) != 0);
    set_pf(pf::NX_ENABLED, (ext_edx & (1 << 20)) != 0);
    set_pf(pf::SSE3_INSTRUCTIONS_AVAILABLE, (ecx1 & (1 << 0)) != 0);
    set_pf(pf::COMPARE_EXCHANGE128, (ecx1 & (1 << 13)) != 0);
    set_pf(pf::XSAVE_ENABLED, use_xsave);
    set_pf(pf::FASTFAIL_AVAILABLE, true);
    set_pf(pf::RDTSCP_INSTRUCTION_AVAILABLE, (ext_edx & (1 << 27)) != 0);
    let avx_active = (enabled_mask & XSTATE_MASK_AVX) != 0;
    set_pf(pf::AVX_INSTRUCTIONS_AVAILABLE, avx_active);
    set_pf(pf::AVX2_INSTRUCTIONS_AVAILABLE, avx_active && cpu_avx2);
    PF_MASK.store(pf_mask, Ordering::Release);
}

/// Whether the CPU supports Supervisor Mode Execution Prevention (`CR4.SMEP`).
#[allow(dead_code)]
pub fn has_smep() -> bool {
    HAS_SMEP.load(Ordering::Acquire)
}

/// Bitmask of enabled XState features (`0x3` legacy, `0x7` with AVX).
pub fn enabled_mask() -> u64 {
    ENABLED_MASK.load(Ordering::Acquire)
}

/// Byte size of the active XSAVE/FXSAVE save area.
pub fn area_size() -> usize {
    AREA_SIZE.load(Ordering::Acquire)
}

/// Whether hardware `XSAVE`/`XRSTOR` is active (else `FXSAVE`/`FXRSTOR`).
pub fn use_xsave() -> bool {
    USE_XSAVE.load(Ordering::Acquire)
}

/// Align a buffer pointer of length [`AREA_BUF_SIZE`] up to a 64-byte boundary.
pub fn align_area(buf: *mut u8) -> *mut u8 {
    let addr = buf.addr();
    buf.with_addr((addr + 63) & !63)
}

/// Initialize a 64-byte-aligned thread save area to Windows x64 defaults.
///
/// # Safety
/// `area` is 64-byte aligned and points to at least [`MAX_AREA_SIZE`] writable bytes.
pub unsafe fn init_area(area: *mut u8) {
    // SAFETY: per the contract.
    unsafe {
        core::ptr::write_bytes(area, 0, MAX_AREA_SIZE);
        area.cast::<u16>().write(INITIAL_FPCSR);
        area.add(0x18).cast::<u32>().write(INITIAL_MXCSR);
        area.add(0x1C)
            .cast::<u32>()
            .write(MXCSR_MASK.load(Ordering::Acquire));
        if use_xsave() {
            // Mark legacy x87 + SSE present so XRSTOR loads our FCW/MXCSR and
            // zeroes any enabled extended components (e.g. AVX YMMH).
            area.add(0x200).cast::<u64>().write(XSTATE_MASK_LEGACY);
        }
    }
}

/// Save all enabled extended processor state into `area`.
///
/// # Safety
/// `area` is 64-byte aligned and points to at least [`area_size()`] writable bytes.
pub unsafe fn save(area: *mut u8) {
    // SAFETY: per the contract.
    unsafe { save_mask(area, enabled_mask()) };
}

/// Restore all enabled extended processor state from `area`.
///
/// # Safety
/// `area` is 64-byte aligned and holds a valid save image for [`enabled_mask()`].
pub unsafe fn restore(area: *mut u8) {
    // SAFETY: per the contract.
    unsafe { restore_mask(area, enabled_mask()) };
}

/// Save the components in `mask` (clamped to [`enabled_mask()`]) into `area`.
///
/// # Safety
/// `area` is 64-byte aligned and points to at least [`area_size()`] writable bytes.
pub unsafe fn save_mask(area: *mut u8, mask: u64) {
    let rf = mask & enabled_mask();
    // SAFETY: per the contract; `USE_XSAVE` is only true when `CR4.OSXSAVE` is set.
    unsafe {
        if use_xsave() {
            core::arch::asm!(
                "xsave64 [{p}]",
                p = in(reg) area,
                in("eax") rf as u32,
                in("edx") (rf >> 32) as u32,
                options(nostack),
            );
        } else {
            core::arch::asm!(
                "fxsave64 [{p}]",
                p = in(reg) area,
                options(nostack),
            );
        }
    }
}

/// Restore the components in `mask` (clamped to [`enabled_mask()`]) from `area`.
///
/// # Safety
/// `area` is 64-byte aligned and holds a valid save image for `mask & enabled_mask()`.
pub unsafe fn restore_mask(area: *mut u8, mask: u64) {
    let rf = mask & enabled_mask();
    // SAFETY: per the contract; `USE_XSAVE` is only true when `CR4.OSXSAVE` is set.
    unsafe {
        if use_xsave() {
            core::arch::asm!(
                "xrstor64 [{p}]",
                p = in(reg) area,
                in("eax") rf as u32,
                in("edx") (rf >> 32) as u32,
                options(nostack),
            );
        } else {
            core::arch::asm!(
                "fxrstor64 [{p}]",
                p = in(reg) area,
                options(nostack),
            );
        }
    }
}

/// Populate `KUSER_SHARED_DATA.ProcessorFeatures` from detected CPUID features.
///
/// # Safety
/// `page` points to the mapped `KUSER_SHARED_DATA` page.
pub unsafe fn write_kusd_features(page: *mut u8) {
    let mask = PF_MASK.load(Ordering::Acquire);
    // SAFETY: per the contract; `SHARED_PROCESSOR_FEATURES + 64 <= 4096`.
    unsafe {
        let base = page.add(SHARED_PROCESSOR_FEATURES);
        for idx in 0..64 {
            base.add(idx)
                .write_volatile(u8::from((mask >> idx) & 1 != 0));
        }
    }
}

/// Populate `KUSER_SHARED_DATA.XState` (`XSTATE_CONFIGURATION`).
///
/// # Safety
/// `page` points to the mapped `KUSER_SHARED_DATA` page.
pub unsafe fn write_kusd_xstate(page: *mut u8) {
    let enabled = enabled_mask();
    let size = area_size() as u32;
    let mut cfg = XSTATE_CONFIGURATION {
        EnabledFeatures: enabled,
        EnabledVolatileFeatures: enabled,
        Size: size,
        ControlFlags: u32::from(USE_XSAVEOPT.load(Ordering::Acquire)),
        Features: [XSTATE_FEATURE { Offset: 0, Size: 0 }; 64],
        EnabledSupervisorFeatures: 0,
        AlignedFeatures: 0,
        AllFeatureSize: size,
        AllFeatures: [0; 64],
        EnabledUserVisibleSupervisorFeatures: 0,
    };
    cfg.Features[0] = XSTATE_FEATURE {
        Offset: 0,
        Size: 160,
    };
    cfg.AllFeatures[0] = 160;
    cfg.Features[1] = XSTATE_FEATURE {
        Offset: 160,
        Size: 256,
    };
    cfg.AllFeatures[1] = 256;
    if (enabled & XSTATE_MASK_AVX) != 0 {
        let off = AVX_OFFSET.load(Ordering::Acquire);
        let sz = AVX_SIZE.load(Ordering::Acquire);
        cfg.Features[2] = XSTATE_FEATURE {
            Offset: off,
            Size: sz,
        };
        cfg.AllFeatures[2] = sz;
    }
    // SAFETY: per the contract; `SHARED_XSTATE` is 8-byte aligned inside the
    // 4 KiB page and `SHARED_XSTATE + size_of::<XSTATE_CONFIGURATION>() <= 4096`.
    unsafe {
        page.add(SHARED_XSTATE)
            .cast::<XSTATE_CONFIGURATION>()
            .write(cfg);
    }
}

/// Verify `KeSaveExtendedProcessorState` / `KeRestoreExtendedProcessorState`
/// and thread context-switch preservation of XMM/YMM extended state.
pub fn self_test() -> Result<(), &'static str> {
    use nk_ntabi::seh::x64::{XSTATE_CONTEXT, XSTATE_SAVE};

    let mask = enabled_mask();
    let mut save_rec = XSTATE_SAVE {
        Prev: core::ptr::null_mut(),
        Thread: core::ptr::null_mut(),
        Level: 0,
        _pad: [0; 7],
        XStateContext: XSTATE_CONTEXT {
            Mask: 0,
            Length: 0,
            Reserved1: 0,
            Area: core::ptr::null_mut(),
            Buffer: core::ptr::null_mut(),
        },
    };

    if (mask & XSTATE_MASK_AVX) != 0 {
        let pattern: [u64; 4] = [
            0x1122_3344_5566_7788,
            0x99AA_BBCC_DDEE_FF00,
            0xCAFE_BABE_DEAD_BEEF,
            0x0123_4567_89AB_CDEF,
        ];
        let clobber: [u64; 4] = [0xAAAA_AAAA_AAAA_AAAA; 4];
        let mut after_restore = [0u64; 4];
        let mut after_switch = [0u64; 4];

        fn avx_clobber_thread(arg: usize) {
            let val: [u64; 4] = [0x5555_5555_5555_5555; 4];
            // SAFETY: AVX is enabled in XCR0; clobbering `ymm6` inside this
            // thread must not affect any other thread's saved `ymm6`.
            unsafe {
                core::arch::asm!(
                    "vmovdqu ymm6, [{p}]",
                    "vmovdqu ymm7, [{p}]",
                    p = in(reg) val.as_ptr(),
                    options(readonly, nostack),
                );
                let _ = arg;
                core::arch::asm!("vzeroupper", options(nomem, nostack));
            }
        }

        // SAFETY: `XSTATE_MASK_AVX` is enabled in `XCR0`, so `vmovdqu` on `ymm6`
        // is architecturally valid; `xmm6` is callee-saved and `nkkrnl` emits no
        // VEX instructions, so `ymm6` is preserved across Rust calls and context
        // switches via XSAVE/XRSTOR.
        unsafe {
            core::arch::asm!(
                "vmovdqu ymm6, [{p}]",
                p = in(reg) pattern.as_ptr(),
                options(readonly, nostack),
            );
            let status = crate::ke::time::KeSaveExtendedProcessorState(mask, &raw mut save_rec);
            if status != nk_ntabi::status::STATUS_SUCCESS {
                core::arch::asm!("vzeroupper", options(nomem, nostack));
                return Err("KeSaveExtendedProcessorState failed for enabled mask");
            }
            core::arch::asm!(
                "vmovdqu ymm6, [{p}]",
                p = in(reg) clobber.as_ptr(),
                options(readonly, nostack),
            );
            crate::ke::time::KeRestoreExtendedProcessorState(&raw mut save_rec);
            core::arch::asm!(
                "vmovdqu [{p}], ymm6",
                p = in(reg) after_restore.as_mut_ptr(),
                options(nostack),
            );
            // Spawn a thread pinned to our current processor so it MUST
            // context-switch on this CPU, clobber `ymm6`, and switch back.
            let cpu_mask = 1u64 << crate::ke::pcr::current_processor();
            let other = crate::ke::thread::create_referenced(
                avx_clobber_thread,
                0,
                crate::ke::thread::NORMAL_PRIORITY + 1,
                cpu_mask,
            )?;
            let _ =
                crate::ke::wait::KeWaitForSingleObject(other.cast(), 0, 0, 0, core::ptr::null());
            crate::ob::object::dereference(other.cast());
            core::arch::asm!(
                "vmovdqu [{p}], ymm6",
                p = in(reg) after_switch.as_mut_ptr(),
                options(nostack),
            );
            core::arch::asm!("vzeroupper", options(nomem, nostack));
        }
        if after_restore != pattern {
            return Err("KeRestoreExtendedProcessorState did not restore YMM6");
        }
        if after_switch != pattern {
            return Err("YMM6 did not survive context switch");
        }
    } else {
        // Legacy SSE-only fallback: verify save/restore preserves XMM6.
        let pattern: [u64; 2] = [0x1122_3344_5566_7788, 0xCAFE_BABE_DEAD_BEEF];
        let clobber: [u64; 2] = [0x5555_5555_5555_5555; 2];
        let mut after = [0u64; 2];
        // SAFETY: SSE2 is baseline on x86-64; save/restore preserves `xmm6`.
        unsafe {
            core::arch::asm!(
                "movdqu xmm6, [{p}]",
                p = in(reg) pattern.as_ptr(),
                options(readonly, nostack),
            );
            let status = crate::ke::time::KeSaveExtendedProcessorState(mask, &raw mut save_rec);
            if status != nk_ntabi::status::STATUS_SUCCESS {
                return Err("KeSaveExtendedProcessorState failed for legacy mask");
            }
            core::arch::asm!(
                "movdqu xmm6, [{p}]",
                p = in(reg) clobber.as_ptr(),
                options(readonly, nostack),
            );
            crate::ke::time::KeRestoreExtendedProcessorState(&raw mut save_rec);
            core::arch::asm!(
                "movdqu [{p}], xmm6",
                p = in(reg) after.as_mut_ptr(),
                options(nostack),
            );
        }
        if after != pattern {
            return Err("KeRestoreExtendedProcessorState did not restore XMM6");
        }
    }
    Ok(())
}
