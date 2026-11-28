//! User-mode ABI structures shared between the kernel and `ntdll.dll`
//! (Windows 10 19041/19045 x86-64).
//!
//! Layouts are verified against `target/fixtures/ntdll.x64.pdb` in `pdb.rs`.

use crate::io::UNICODE_STRING;
use crate::ke::LIST_ENTRY;
use crate::status::NTSTATUS;
use core::ffi::c_void;

/// `_NT_TIB` (56 bytes): Thread Information Block at offset 0 of `TEB`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct NT_TIB {
    pub ExceptionList: *mut c_void,
    pub StackBase: *mut c_void,
    pub StackLimit: *mut c_void,
    pub SubSystemTib: *mut c_void,
    pub FiberData: *mut c_void,
    pub ArbitraryUserPointer: *mut c_void,
    pub SelfPtr: *mut NT_TIB,
}

/// `_CLIENT_ID` (16 bytes): `(UniqueProcess, UniqueThread)`.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CLIENT_ID {
    pub UniqueProcess: *mut c_void,
    pub UniqueThread: *mut c_void,
}

/// `_CURDIR` (24 bytes): current working directory in `RTL_USER_PROCESS_PARAMETERS`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    pub Handle: *mut c_void,
}

/// `_RTL_DRIVE_LETTER_CURDIR` (24 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RTL_DRIVE_LETTER_CURDIR {
    pub Flags: u16,
    pub Length: u16,
    pub TimeStamp: u32,
    pub DosPath: UNICODE_STRING,
}

/// `_ACTIVATION_CONTEXT_STACK` (40 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ACTIVATION_CONTEXT_STACK {
    pub ActiveFrame: *mut c_void,
    pub FrameListCache: LIST_ENTRY,
    pub Flags: u32,
    pub NextCookieSequenceNumber: u32,
    pub StackId: u32,
    pub _pad: u32,
}

/// `_RTL_USER_PROCESS_PARAMETERS` (1088 bytes = `0x440`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: u32,
    pub Length: u32,
    pub Flags: u32,
    pub DebugFlags: u32,
    pub ConsoleHandle: *mut c_void,
    pub ConsoleFlags: u32,
    pub _pad0: u32,
    pub StandardInput: *mut c_void,
    pub StandardOutput: *mut c_void,
    pub StandardError: *mut c_void,
    pub CurrentDirectory: CURDIR,
    pub DllPath: UNICODE_STRING,
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
    pub Environment: *mut c_void,
    pub StartingX: u32,
    pub StartingY: u32,
    pub CountX: u32,
    pub CountY: u32,
    pub CountCharsX: u32,
    pub CountCharsY: u32,
    pub FillAttribute: u32,
    pub WindowFlags: u32,
    pub ShowWindowFlags: u32,
    pub _pad1: u32,
    pub WindowTitle: UNICODE_STRING,
    pub DesktopInfo: UNICODE_STRING,
    pub ShellInfo: UNICODE_STRING,
    pub RuntimeData: UNICODE_STRING,
    pub CurrentDirectores: [RTL_DRIVE_LETTER_CURDIR; 32],
    pub EnvironmentSize: usize,
    pub EnvironmentVersion: usize,
    pub PackageDependencyData: *mut c_void,
    pub ProcessGroupId: u32,
    pub LoaderThreads: u32,
    pub RedirectionDllName: UNICODE_STRING,
    pub HeapPartitionName: UNICODE_STRING,
    pub DefaultThreadpoolCpuSetMasks: *mut u64,
    pub DefaultThreadpoolCpuSetMaskCount: u32,
    pub DefaultThreadpoolThreadMaximum: u32,
}

/// `RTL_USER_PROC_PARAMS_NORMALIZED`: `RTL_USER_PROCESS_PARAMETERS` strings are
/// already absolute pointers (not offsets from the struct base).
pub const RTL_USER_PROC_PARAMS_NORMALIZED: u32 = 0x0000_0001;

/// `_PEB` (1992 bytes = `0x7C8`): Process Environment Block (Windows 10 19041/19045 x64).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PEB {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,
    pub BeingDebugged: u8,
    pub BitField: u8,
    pub Padding0: [u8; 4],
    pub Mutant: *mut c_void,
    pub ImageBaseAddress: *mut c_void,
    pub Ldr: *mut c_void,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub SubSystemData: *mut c_void,
    pub ProcessHeap: *mut c_void,
    pub FastPebLock: *mut c_void,
    pub AtlThunkSListPtr: *mut c_void,
    pub IFEOKey: *mut c_void,
    pub CrossProcessFlags: u32,
    pub Padding1: [u8; 4],
    pub KernelCallbackTable: *mut c_void,
    pub SystemReserved: u32,
    pub AtlThunkSListPtr32: u32,
    pub ApiSetMap: *mut c_void,
    pub TlsExpansionCounter: u32,
    pub Padding2: [u8; 4],
    pub TlsBitmap: *mut c_void,
    pub TlsBitmapBits: [u32; 2],
    pub ReadOnlySharedMemoryBase: *mut c_void,
    pub SharedData: *mut c_void,
    pub ReadOnlyStaticServerData: *mut *mut c_void,
    pub AnsiCodePageData: *mut c_void,
    pub OemCodePageData: *mut c_void,
    pub UnicodeCaseTableData: *mut c_void,
    pub NumberOfProcessors: u32,
    pub NtGlobalFlag: u32,
    pub CriticalSectionTimeout: i64,
    pub HeapSegmentReserve: usize,
    pub HeapSegmentCommit: usize,
    pub HeapDeCommitTotalFreeThreshold: usize,
    pub HeapDeCommitFreeBlockThreshold: usize,
    pub NumberOfHeaps: u32,
    pub MaximumNumberOfHeaps: u32,
    pub ProcessHeaps: *mut *mut c_void,
    pub GdiSharedHandleTable: *mut c_void,
    pub ProcessStarterHelper: *mut c_void,
    pub GdiDCAttributeList: u32,
    pub Padding3: [u8; 4],
    pub LoaderLock: *mut c_void,
    pub OSMajorVersion: u32,
    pub OSMinorVersion: u32,
    pub OSBuildNumber: u16,
    pub OSCSDVersion: u16,
    pub OSPlatformId: u32,
    pub ImageSubsystem: u32,
    pub ImageSubsystemMajorVersion: u32,
    pub ImageSubsystemMinorVersion: u32,
    pub Padding4: [u8; 4],
    pub ActiveProcessAffinityMask: usize,
    pub GdiHandleBuffer: [u32; 60],
    pub PostProcessInitRoutine: *mut c_void,
    pub TlsExpansionBitmap: *mut c_void,
    pub TlsExpansionBitmapBits: [u32; 32],
    pub SessionId: u32,
    pub Padding5: [u8; 4],
    pub AppCompatFlags: u64,
    pub AppCompatFlagsUser: u64,
    pub pShimData: *mut c_void,
    pub AppCompatInfo: *mut c_void,
    pub CSDVersion: UNICODE_STRING,
    pub ActivationContextData: *mut c_void,
    pub ProcessAssemblyStorageMap: *mut c_void,
    pub SystemDefaultActivationContextData: *mut c_void,
    pub SystemAssemblyStorageMap: *mut c_void,
    pub MinimumStackCommit: usize,
    pub _tail: [u8; 1992 - 800],
}

/// `_TEB` (6200 bytes = `0x1838`): Thread Environment Block (Windows 10 19041/19045 x64).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TEB {
    pub NtTib: NT_TIB,
    pub EnvironmentPointer: *mut c_void,
    pub ClientId: CLIENT_ID,
    pub ActiveRpcHandle: *mut c_void,
    pub ThreadLocalStoragePointer: *mut c_void,
    pub ProcessEnvironmentBlock: *mut PEB,
    pub LastErrorValue: u32,
    pub CountOfOwnedCriticalSections: u32,
    pub CsrClientThread: *mut c_void,
    pub Win32ThreadInfo: *mut c_void,
    pub User32Reserved: [u32; 26],
    pub UserReserved: [u32; 5],
    pub _pad_wow: u32,
    pub WOW32Reserved: *mut c_void,
    pub CurrentLocale: u32,
    pub FpSoftwareStatusRegister: u32,
    pub _mid0: [u8; 656 - 272],
    pub ActivationStack: ACTIVATION_CONTEXT_STACK,
    pub WorkingOnBehalfTicket: u64,
    pub ExceptionCode: i32,
    pub Padding0: [u8; 4],
    pub ActivationContextStackPointer: *mut ACTIVATION_CONTEXT_STACK,
    pub _mid1: [u8; 2008 - 720],
    pub RealClientId: CLIENT_ID,
    pub _mid2: [u8; 4688 - 2024],
    pub LastStatusValue: u32,
    pub Padding2: [u8; 4],
    pub StaticUnicodeString: UNICODE_STRING,
    pub StaticUnicodeBuffer: [u16; 261],
    pub Padding3: [u8; 6],
    pub DeallocationStack: *mut c_void,
    pub TlsSlots: [*mut c_void; 64],
    pub TlsLinks: LIST_ENTRY,
    pub _mid3: [u8; 5808 - 5776],
    pub HardErrorMode: u32,
    pub _mid4: [u8; 5956 - 5812],
    pub IdealProcessorValue: u32,
    pub GuaranteedStackBytes: u32,
    pub _mid5: [u8; 6124 - 5964],
    pub CrossTebFlags: u16,
    pub SameTebFlags: u16,
    pub _tail: [u8; 6200 - 6128],
}

/// `TEB.SameTebFlags` bit 10 (`InitialThread`).
pub const TEB_SAME_INITIAL_THREAD: u16 = 1 << 10;

/// `PS_SYSTEM_DLL_INIT_BLOCK` (240 bytes = `0xF0`) patched into `ntdll!LdrSystemDllInitBlock`
/// for each new user process (verified against Windows 10 19041.1949 `ntdll.dll`).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PS_SYSTEM_DLL_INIT_BLOCK {
    pub Size: u32,
    pub _pad0: u32,
    pub SystemDllWowRelocation: u64,
    pub SystemDllNativeRelocation: u64,
    pub Wow64SharedInformation: [u64; 16],
    pub RngData: u32,
    pub Flags: u32,
    pub MitigationOptionsMap: [u64; 3],
    pub CfgBitMap: u64,
    pub CfgBitMapSize: u64,
    pub Wow64CfgBitMap: u64,
    pub Wow64CfgBitMapSize: u64,
    pub MitigationAuditOptionsMap: [u64; 3],
}

/// `PROCESS_BASIC_INFORMATION` (48 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PROCESS_BASIC_INFORMATION {
    pub ExitStatus: NTSTATUS,
    pub _pad0: u32,
    pub PebBaseAddress: *mut PEB,
    pub AffinityMask: usize,
    pub BasePriority: i32,
    pub _pad1: u32,
    pub UniqueProcessId: usize,
    pub InheritedFromUniqueProcessId: usize,
}

/// `THREAD_BASIC_INFORMATION` (48 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct THREAD_BASIC_INFORMATION {
    pub ExitStatus: NTSTATUS,
    pub _pad0: u32,
    pub TebBaseAddress: *mut TEB,
    pub ClientId: CLIENT_ID,
    pub AffinityMask: usize,
    pub Priority: i32,
    pub BasePriority: i32,
}

/// `PS_CREATE_NOTIFY_INFO` (72 bytes) passed to `PsSetCreateProcessNotifyRoutineEx*`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PS_CREATE_NOTIFY_INFO {
    pub Size: usize,
    pub Flags: u32,
    pub _pad0: u32,
    pub ParentProcessId: *mut c_void,
    pub CreatingThreadId: CLIENT_ID,
    pub FileObject: *mut c_void,
    pub ImageFileName: *const UNICODE_STRING,
    pub CommandLine: *const UNICODE_STRING,
    pub CreationStatus: NTSTATUS,
    pub _pad1: u32,
}

/// `IMAGE_INFO` (40 bytes) passed to `PsSetLoadImageNotifyRoutine` callbacks.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_INFO {
    pub Properties: usize,
    pub ImageBase: *mut c_void,
    pub ImageSelector: usize,
    pub ImageSize: usize,
    pub ImageSectionNumber: usize,
}

/// `PROCESS_*` access rights.
pub const PROCESS_TERMINATE: u32 = 0x0001;
pub const PROCESS_CREATE_THREAD: u32 = 0x0002;
pub const PROCESS_VM_OPERATION: u32 = 0x0008;
pub const PROCESS_VM_READ: u32 = 0x0010;
pub const PROCESS_VM_WRITE: u32 = 0x0020;
pub const PROCESS_DUP_HANDLE: u32 = 0x0040;
pub const PROCESS_CREATE_PROCESS: u32 = 0x0080;
pub const PROCESS_SET_QUOTA: u32 = 0x0100;
pub const PROCESS_SET_INFORMATION: u32 = 0x0200;
pub const PROCESS_QUERY_INFORMATION: u32 = 0x0400;
pub const PROCESS_SUSPEND_RESUME: u32 = 0x0800;
pub const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
pub const PROCESS_ALL_ACCESS: u32 = 0x001F_FFFF;

/// `THREAD_*` access rights.
pub const THREAD_TERMINATE: u32 = 0x0001;
pub const THREAD_SUSPEND_RESUME: u32 = 0x0002;
pub const THREAD_ALERT: u32 = 0x0004;
pub const THREAD_GET_CONTEXT: u32 = 0x0008;
pub const THREAD_SET_CONTEXT: u32 = 0x0010;
pub const THREAD_SET_INFORMATION: u32 = 0x0020;
pub const THREAD_QUERY_INFORMATION: u32 = 0x0040;
pub const THREAD_SET_THREAD_TOKEN: u32 = 0x0080;
pub const THREAD_IMPERSONATE: u32 = 0x0100;
pub const THREAD_DIRECT_IMPERSONATION: u32 = 0x0200;
pub const THREAD_SET_LIMITED_INFORMATION: u32 = 0x0400;
pub const THREAD_QUERY_LIMITED_INFORMATION: u32 = 0x0800;
pub const THREAD_ALL_ACCESS: u32 = 0x001F_FFFF;

/// Selected `PROCESSINFOCLASS` values.
pub const PROCESS_BASIC_INFORMATION_CLASS: u32 = 0;
pub const PROCESS_TIMES_CLASS: u32 = 4;
pub const PROCESS_DEBUG_PORT_CLASS: u32 = 7;
pub const PROCESS_DEFAULT_HARD_ERROR_MODE_CLASS: u32 = 12;
pub const PROCESS_PRIORITY_CLASS: u32 = 18;
pub const PROCESS_HANDLE_COUNT_CLASS: u32 = 20;
pub const PROCESS_SESSION_INFORMATION_CLASS: u32 = 24;
pub const PROCESS_WOW64_INFORMATION_CLASS: u32 = 26;
pub const PROCESS_IMAGE_FILE_NAME_CLASS: u32 = 27;
pub const PROCESS_BREAK_ON_TERMINATION_CLASS: u32 = 29;
pub const PROCESS_DEBUG_OBJECT_HANDLE_CLASS: u32 = 30;
pub const PROCESS_DEBUG_FLAGS_CLASS: u32 = 31;
pub const PROCESS_EXECUTE_FLAGS_CLASS: u32 = 34;
pub const PROCESS_COOKIE_CLASS: u32 = 36;
pub const PROCESS_IMAGE_FILE_NAME_WIN32_CLASS: u32 = 43;
pub const PROCESS_MITIGATION_POLICY_CLASS: u32 = 52;
pub const PROCESS_SUBSYSTEM_INFORMATION_CLASS: u32 = 75;

/// Selected `THREADINFOCLASS` values.
pub const THREAD_BASIC_INFORMATION_CLASS: u32 = 0;
pub const THREAD_TIMES_CLASS: u32 = 1;
pub const THREAD_PRIORITY_CLASS: u32 = 2;
pub const THREAD_BASE_PRIORITY_CLASS: u32 = 3;
pub const THREAD_AFFINITY_MASK_CLASS: u32 = 4;
pub const THREAD_IMPERSONATION_TOKEN_CLASS: u32 = 5;
pub const THREAD_QUERY_SET_WIN32_START_ADDRESS_CLASS: u32 = 9;
pub const THREAD_IS_IO_PENDING_CLASS: u32 = 16;
pub const THREAD_HIDE_FROM_DEBUGGER_CLASS: u32 = 17;
pub const THREAD_IDEAL_PROCESSOR_CLASS: u32 = 18;
pub const THREAD_TEB_INFORMATION_CLASS: u32 = 26;
pub const THREAD_IDEAL_PROCESSOR_EX_CLASS: u32 = 33;
pub const THREAD_NAME_INFORMATION_CLASS: u32 = 38;

const _: () = {
    assert!(core::mem::size_of::<NT_TIB>() == 56);
    assert!(core::mem::size_of::<CLIENT_ID>() == 16);
    assert!(core::mem::size_of::<CURDIR>() == 24);
    assert!(core::mem::size_of::<RTL_DRIVE_LETTER_CURDIR>() == 24);
    assert!(core::mem::size_of::<ACTIVATION_CONTEXT_STACK>() == 40);
    assert!(core::mem::size_of::<RTL_USER_PROCESS_PARAMETERS>() == 1088);
    assert!(core::mem::size_of::<PEB>() == 1992);
    assert!(core::mem::size_of::<TEB>() == 6200);
    assert!(core::mem::size_of::<PS_SYSTEM_DLL_INIT_BLOCK>() == 0xF0);
    assert!(core::mem::size_of::<PROCESS_BASIC_INFORMATION>() == 48);
    assert!(core::mem::size_of::<THREAD_BASIC_INFORMATION>() == 48);
    assert!(core::mem::size_of::<PS_CREATE_NOTIFY_INFO>() == 72);
    assert!(core::mem::size_of::<IMAGE_INFO>() == 40);
};
