//! Structured exception handling: what a driver's handlers are handed.
//!
//! A language handler (`__C_specific_handler`, or a driver's own, such
//! as the stack-cookie check) receives an `EXCEPTION_RECORD`, a
//! `CONTEXT` and a `DISPATCHER_CONTEXT` and reads and writes them, so
//! all three are ABI. `CONTEXT` and `DISPATCHER_CONTEXT` differ by
//! architecture; both forms are declared on every host so the layouts
//! can be checked there. Both are compared with the table the WDK's
//! compiler produced (`probe.rs`), the x86-64 forms also with the
//! kernel's public symbols (`pdb.rs`).

use core::ffi::c_void;

/// Most parameters an exception carries.
pub const EXCEPTION_MAXIMUM_PARAMETERS: usize = 15;

/// [`EXCEPTION_RECORD`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-exception_record).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: u32,
    pub ExceptionFlags: u32,
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ExceptionAddress: *mut c_void,
    pub NumberParameters: u32,
    pub ExceptionInformation: [u64; EXCEPTION_MAXIMUM_PARAMETERS],
}

/// `EXCEPTION_POINTERS`: what `GetExceptionInformation()` returns.
#[repr(C)]
pub struct EXCEPTION_POINTERS {
    pub ExceptionRecord: *mut EXCEPTION_RECORD,
    pub ContextRecord: *mut c_void,
}

/// `ExceptionFlags` bits.
pub const EXCEPTION_NONCONTINUABLE: u32 = 0x01;
pub const EXCEPTION_UNWINDING: u32 = 0x02;
pub const EXCEPTION_EXIT_UNWIND: u32 = 0x04;
pub const EXCEPTION_STACK_INVALID: u32 = 0x08;
pub const EXCEPTION_NESTED_CALL: u32 = 0x10;
pub const EXCEPTION_TARGET_UNWIND: u32 = 0x20;
pub const EXCEPTION_COLLIDED_UNWIND: u32 = 0x40;

/// `M128A`: one vector register.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct M128A {
    pub Low: u64,
    pub High: i64,
}

/// The x86-64 forms.
pub mod x64 {
    use super::M128A;
    use core::ffi::c_void;

    /// `CONTEXT_AMD64` and the parts of a context it says are present.
    pub const CONTEXT_AMD64: u32 = 0x0010_0000;
    pub const CONTEXT_CONTROL: u32 = CONTEXT_AMD64 | 0x1;
    pub const CONTEXT_INTEGER: u32 = CONTEXT_AMD64 | 0x2;
    pub const CONTEXT_SEGMENTS: u32 = CONTEXT_AMD64 | 0x4;
    pub const CONTEXT_FLOATING_POINT: u32 = CONTEXT_AMD64 | 0x8;
    pub const CONTEXT_DEBUG_REGISTERS: u32 = CONTEXT_AMD64 | 0x10;
    pub const CONTEXT_XSTATE: u32 = CONTEXT_AMD64 | 0x40;
    pub const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;

    /// `XSAVE_FORMAT`: the legacy floating-point and SSE state.
    #[repr(C, align(16))]
    #[derive(Clone, Copy)]
    pub struct XSAVE_FORMAT {
        pub ControlWord: u16,
        pub StatusWord: u16,
        pub TagWord: u8,
        pub Reserved1: u8,
        pub ErrorOpcode: u16,
        pub ErrorOffset: u32,
        pub ErrorSelector: u16,
        pub Reserved2: u16,
        pub DataOffset: u32,
        pub DataSelector: u16,
        pub Reserved3: u16,
        pub MxCsr: u32,
        pub MxCsr_Mask: u32,
        pub FloatRegisters: [M128A; 8],
        pub XmmRegisters: [M128A; 16],
        pub Reserved4: [u8; 96],
    }

    /// [`CONTEXT`](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context)
    /// on x86-64.
    #[repr(C, align(16))]
    #[derive(Clone, Copy)]
    pub struct CONTEXT {
        pub PHome: [u64; 6],
        pub ContextFlags: u32,
        pub MxCsr: u32,
        pub SegCs: u16,
        pub SegDs: u16,
        pub SegEs: u16,
        pub SegFs: u16,
        pub SegGs: u16,
        pub SegSs: u16,
        pub EFlags: u32,
        pub Dr0: u64,
        pub Dr1: u64,
        pub Dr2: u64,
        pub Dr3: u64,
        pub Dr6: u64,
        pub Dr7: u64,
        pub Rax: u64,
        pub Rcx: u64,
        pub Rdx: u64,
        pub Rbx: u64,
        pub Rsp: u64,
        pub Rbp: u64,
        pub Rsi: u64,
        pub Rdi: u64,
        pub R8: u64,
        pub R9: u64,
        pub R10: u64,
        pub R11: u64,
        pub R12: u64,
        pub R13: u64,
        pub R14: u64,
        pub R15: u64,
        pub Rip: u64,
        pub FltSave: XSAVE_FORMAT,
        pub VectorRegister: [M128A; 26],
        pub VectorControl: u64,
        pub DebugControl: u64,
        pub LastBranchToRip: u64,
        pub LastBranchFromRip: u64,
        pub LastExceptionToRip: u64,
        pub LastExceptionFromRip: u64,
    }

    /// `RUNTIME_FUNCTION`: one entry of an image's function table.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct RUNTIME_FUNCTION {
        pub BeginAddress: u32,
        pub EndAddress: u32,
        pub UnwindData: u32,
    }

    /// `DISPATCHER_CONTEXT`: what the dispatcher tells a language
    /// handler about the frame it is called for.
    #[repr(C)]
    pub struct DISPATCHER_CONTEXT {
        pub ControlPc: u64,
        pub ImageBase: u64,
        pub FunctionEntry: *mut RUNTIME_FUNCTION,
        pub EstablisherFrame: u64,
        pub TargetIp: u64,
        pub ContextRecord: *mut CONTEXT,
        pub LanguageHandler: *mut c_void,
        pub HandlerData: *mut c_void,
        pub HistoryTable: *mut c_void,
        pub ScopeIndex: u32,
        pub Fill0: u32,
    }

    /// `KTRAP_FRAME` on x86-64 (400 bytes, `0x190`): Windows' kernel trap
    /// frame for interrupts, exceptions, and `syscall` entries.
    #[repr(C, align(16))]
    #[derive(Clone, Copy)]
    pub struct KTRAP_FRAME {
        pub P1Home: u64,
        pub P2Home: u64,
        pub P3Home: u64,
        pub P4Home: u64,
        pub P5: u64,
        pub PreviousMode: i8,
        pub PreviousIrql: u8,
        pub FaultIndicator: u8,
        pub ExceptionActive: u8,
        pub MxCsr: u32,
        pub Rax: u64,
        pub Rcx: u64,
        pub Rdx: u64,
        pub R8: u64,
        pub R9: u64,
        pub R10: u64,
        pub R11: u64,
        pub GsBase: u64,
        pub Xmm0: M128A,
        pub Xmm1: M128A,
        pub Xmm2: M128A,
        pub Xmm3: M128A,
        pub Xmm4: M128A,
        pub Xmm5: M128A,
        pub FaultAddress: u64,
        pub Dr0: u64,
        pub Dr1: u64,
        pub Dr2: u64,
        pub Dr3: u64,
        pub Dr6: u64,
        pub Dr7: u64,
        pub DebugControl: u64,
        pub LastBranchToRip: u64,
        pub LastBranchFromRip: u64,
        pub LastExceptionToRip: u64,
        pub LastExceptionFromRip: u64,
        pub SegDs: u16,
        pub SegEs: u16,
        pub SegFs: u16,
        pub SegGs: u16,
        pub TrapFrame: u64,
        pub Rbx: u64,
        pub Rdi: u64,
        pub Rsi: u64,
        pub Rbp: u64,
        pub ErrorCode: u64,
        pub Rip: u64,
        pub SegCs: u16,
        pub Fill0: u8,
        pub Logging: u8,
        pub Fill1: [u16; 2],
        pub EFlags: u32,
        pub Fill2: u32,
        pub Rsp: u64,
        pub SegSs: u16,
        pub Fill3: u16,
        pub Fill4: u32,
    }

    /// `KEXCEPTION_FRAME` on x86-64 (320 bytes, `0x140`): nonvolatile state
    /// saved alongside a trap frame when entering exception/APC/context paths.
    #[repr(C, align(16))]
    #[derive(Clone, Copy)]
    pub struct KEXCEPTION_FRAME {
        pub P1Home: u64,
        pub P2Home: u64,
        pub P3Home: u64,
        pub P4Home: u64,
        pub P5: u64,
        pub Spare1: u64,
        pub Xmm6: M128A,
        pub Xmm7: M128A,
        pub Xmm8: M128A,
        pub Xmm9: M128A,
        pub Xmm10: M128A,
        pub Xmm11: M128A,
        pub Xmm12: M128A,
        pub Xmm13: M128A,
        pub Xmm14: M128A,
        pub Xmm15: M128A,
        pub TrapFrame: u64,
        pub OutputBuffer: u64,
        pub OutputLength: u64,
        pub Spare2: u64,
        pub MxCsr: u64,
        pub Rbp: u64,
        pub Rbx: u64,
        pub Rdi: u64,
        pub Rsi: u64,
        pub R12: u64,
        pub R13: u64,
        pub R14: u64,
        pub R15: u64,
        pub Return: u64,
    }

    /// `XSTATE_FEATURE`: offset and byte size of one XSAVE component.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct XSTATE_FEATURE {
        pub Offset: u32,
        pub Size: u32,
    }

    /// `XSTATE_CONFIGURATION` (824 bytes): embedded at `KUSER_SHARED_DATA + 0x3D8`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct XSTATE_CONFIGURATION {
        pub EnabledFeatures: u64,
        pub EnabledVolatileFeatures: u64,
        pub Size: u32,
        pub ControlFlags: u32,
        pub Features: [XSTATE_FEATURE; 64],
        pub EnabledSupervisorFeatures: u64,
        pub AlignedFeatures: u64,
        pub AllFeatureSize: u32,
        pub AllFeatures: [u32; 64],
        pub EnabledUserVisibleSupervisorFeatures: u64,
    }

    /// `XSAVE_AREA_HEADER` (64 bytes): at offset `0x200` of an XSAVE area.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct XSAVE_AREA_HEADER {
        pub Mask: u64,
        pub CompactionMask: u64,
        pub Reserved2: [u64; 6],
    }

    /// `XSTATE_CONTEXT` (32 bytes): embedded inside `XSTATE_SAVE`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct XSTATE_CONTEXT {
        pub Mask: u64,
        pub Length: u32,
        pub Reserved1: u32,
        pub Area: *mut c_void,
        pub Buffer: *mut c_void,
    }

    /// `XSTATE_SAVE` (56 bytes): caller-owned record for
    /// `KeSaveExtendedProcessorState` / `KeRestoreExtendedProcessorState`.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct XSTATE_SAVE {
        pub Prev: *mut XSTATE_SAVE,
        pub Thread: *mut c_void,
        pub Level: i8,
        pub _pad: [u8; 7],
        pub XStateContext: XSTATE_CONTEXT,
    }

    const _: () = {
        use core::mem::{offset_of, size_of};
        assert!(size_of::<XSAVE_FORMAT>() == 0x200);
        assert!(offset_of!(XSAVE_FORMAT, MxCsr) == 0x18);
        assert!(offset_of!(XSAVE_FORMAT, XmmRegisters) == 0xA0);
        assert!(size_of::<CONTEXT>() == 0x4D0);
        assert!(offset_of!(CONTEXT, ContextFlags) == 0x30);
        assert!(offset_of!(CONTEXT, SegCs) == 0x38);
        assert!(offset_of!(CONTEXT, EFlags) == 0x44);
        assert!(offset_of!(CONTEXT, Rax) == 0x78);
        assert!(offset_of!(CONTEXT, Rsp) == 0x98);
        assert!(offset_of!(CONTEXT, Rip) == 0xF8);
        assert!(offset_of!(CONTEXT, FltSave) == 0x100);
        assert!(offset_of!(CONTEXT, VectorRegister) == 0x300);
        assert!(offset_of!(CONTEXT, LastExceptionFromRip) == 0x4C8);
        assert!(size_of::<RUNTIME_FUNCTION>() == 12);
        assert!(size_of::<DISPATCHER_CONTEXT>() == 0x50);
        assert!(offset_of!(DISPATCHER_CONTEXT, ContextRecord) == 0x28);
        assert!(offset_of!(DISPATCHER_CONTEXT, ScopeIndex) == 0x48);
        assert!(size_of::<KTRAP_FRAME>() == 0x190);
        assert!(offset_of!(KTRAP_FRAME, PreviousMode) == 0x28);
        assert!(offset_of!(KTRAP_FRAME, Rax) == 0x30);
        assert!(offset_of!(KTRAP_FRAME, Xmm0) == 0x70);
        assert!(offset_of!(KTRAP_FRAME, FaultAddress) == 0xD0);
        assert!(offset_of!(KTRAP_FRAME, TrapFrame) == 0x138);
        assert!(offset_of!(KTRAP_FRAME, ErrorCode) == 0x160);
        assert!(offset_of!(KTRAP_FRAME, Rip) == 0x168);
        assert!(offset_of!(KTRAP_FRAME, SegCs) == 0x170);
        assert!(offset_of!(KTRAP_FRAME, EFlags) == 0x178);
        assert!(offset_of!(KTRAP_FRAME, Rsp) == 0x180);
        assert!(offset_of!(KTRAP_FRAME, SegSs) == 0x188);
        assert!(size_of::<KEXCEPTION_FRAME>() == 0x140);
        assert!(offset_of!(KEXCEPTION_FRAME, Xmm6) == 0x30);
        assert!(offset_of!(KEXCEPTION_FRAME, TrapFrame) == 0xD0);
        assert!(offset_of!(KEXCEPTION_FRAME, MxCsr) == 0xF0);
        assert!(offset_of!(KEXCEPTION_FRAME, R12) == 0x118);
        assert!(offset_of!(KEXCEPTION_FRAME, Return) == 0x138);
        assert!(size_of::<XSTATE_FEATURE>() == 8);
        assert!(size_of::<XSTATE_CONFIGURATION>() == 824);
        assert!(offset_of!(XSTATE_CONFIGURATION, Features) == 24);
        assert!(offset_of!(XSTATE_CONFIGURATION, EnabledUserVisibleSupervisorFeatures) == 816);
        assert!(size_of::<XSAVE_AREA_HEADER>() == 64);
        assert!(size_of::<XSTATE_CONTEXT>() == 32);
        assert!(size_of::<XSTATE_SAVE>() == 56);
    };
}

/// The arm64 forms.
pub mod arm64 {
    use core::ffi::c_void;

    /// `CONTEXT_ARM64` and the parts of a context it says are present.
    pub const CONTEXT_ARM64: u32 = 0x0040_0000;
    pub const CONTEXT_CONTROL: u32 = CONTEXT_ARM64 | 0x1;
    pub const CONTEXT_INTEGER: u32 = CONTEXT_ARM64 | 0x2;
    pub const CONTEXT_FLOATING_POINT: u32 = CONTEXT_ARM64 | 0x4;
    pub const CONTEXT_FULL: u32 = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT;
    /// The context's `Pc` is a return address: the frame was left by a
    /// call, and the instruction it was executing is the one before.
    pub const CONTEXT_UNWOUND_TO_CALL: u32 = 0x2000_0000;

    /// `ARM64_NT_NEON128`: one vector register.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct NEON128 {
        pub Low: u64,
        pub High: i64,
    }

    /// `CONTEXT` on arm64 (`ARM64_NT_CONTEXT`).
    #[repr(C, align(16))]
    #[derive(Clone, Copy)]
    pub struct CONTEXT {
        pub ContextFlags: u32,
        pub Cpsr: u32,
        /// x0 to x28.
        pub X: [u64; 29],
        pub Fp: u64,
        pub Lr: u64,
        pub Sp: u64,
        pub Pc: u64,
        pub V: [NEON128; 32],
        pub Fpcr: u32,
        pub Fpsr: u32,
        pub Bcr: [u32; 8],
        pub Bvr: [u64; 8],
        pub Wcr: [u32; 2],
        pub Wvr: [u64; 2],
    }

    /// `RUNTIME_FUNCTION` on arm64: where the function begins, and its
    /// unwind data or, packed into the same word, the unwinding itself.
    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct RUNTIME_FUNCTION {
        pub BeginAddress: u32,
        pub UnwindData: u32,
    }

    /// `DISPATCHER_CONTEXT` on arm64.
    #[repr(C)]
    pub struct DISPATCHER_CONTEXT {
        pub ControlPc: u64,
        pub ImageBase: u64,
        pub FunctionEntry: *mut RUNTIME_FUNCTION,
        pub EstablisherFrame: u64,
        pub TargetPc: u64,
        pub ContextRecord: *mut CONTEXT,
        pub LanguageHandler: *mut c_void,
        pub HandlerData: *mut c_void,
        pub HistoryTable: *mut c_void,
        pub ScopeIndex: u32,
        pub ControlPcIsUnwound: u8,
        pub NonVolatileRegisters: *mut u8,
    }

    const _: () = {
        use core::mem::{offset_of, size_of};
        assert!(size_of::<CONTEXT>() == 0x390);
        assert!(offset_of!(CONTEXT, X) == 0x8);
        assert!(offset_of!(CONTEXT, Fp) == 0xF0);
        assert!(offset_of!(CONTEXT, Sp) == 0x100);
        assert!(offset_of!(CONTEXT, Pc) == 0x108);
        assert!(offset_of!(CONTEXT, V) == 0x110);
        assert!(offset_of!(CONTEXT, Fpcr) == 0x310);
        assert!(offset_of!(CONTEXT, Bvr) == 0x338);
        assert!(offset_of!(CONTEXT, Wvr) == 0x380);
        assert!(size_of::<RUNTIME_FUNCTION>() == 8);
        assert!(size_of::<DISPATCHER_CONTEXT>() == 0x58);
        assert!(offset_of!(DISPATCHER_CONTEXT, ControlPcIsUnwound) == 0x4C);
        assert!(offset_of!(DISPATCHER_CONTEXT, NonVolatileRegisters) == 0x50);
    };
}

/// One record of a `SCOPE_TABLE`, the handler data of
/// `__C_specific_handler`: a guarded range of a function and its filter
/// or termination handler, all as offsets from the image's base. The
/// table is a `u32` count followed by this many records.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SCOPE_RECORD {
    pub BeginAddress: u32,
    pub EndAddress: u32,
    pub HandlerAddress: u32,
    pub JumpTarget: u32,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<EXCEPTION_RECORD>() == 0x98);
    assert!(offset_of!(EXCEPTION_RECORD, ExceptionAddress) == 0x10);
    assert!(offset_of!(EXCEPTION_RECORD, NumberParameters) == 0x18);
    assert!(offset_of!(EXCEPTION_RECORD, ExceptionInformation) == 0x20);
    assert!(size_of::<EXCEPTION_POINTERS>() == 16);
    assert!(size_of::<M128A>() == 16);
    assert!(size_of::<SCOPE_RECORD>() == 16);
};
