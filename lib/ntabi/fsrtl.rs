//! What a file system keeps for the kernel at the front of each stream's
//! control block: the FCB header (`ntifs.h`).
//!
//! The file system allocates and initialises the header itself, in line
//! ([`FsRtlSetupAdvancedHeader`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-fsrtlsetupadvancedheader)
//! is a macro), so every field is the driver's to write.

use crate::ex::{ERESOURCE, EX_PUSH_LOCK};
use crate::ke::{FAST_MUTEX, LIST_ENTRY};
use core::ffi::c_void;

/// [`FSRTL_COMMON_FCB_HEADER`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_fsrtl_common_fcb_header).
#[repr(C)]
pub struct FSRTL_COMMON_FCB_HEADER {
    pub NodeTypeCode: i16,
    pub NodeByteSize: i16,
    /// `FSRTL_FLAG_*`.
    pub Flags: u8,
    pub IsFastIoPossible: u8,
    /// `FSRTL_FLAG2_*`.
    pub Flags2: u8,
    /// Two bit fields: `Reserved` in the low four bits, `Version` in
    /// the high four ([`fcb_header_version`]).
    pub ReservedAndVersion: u8,
    pub Resource: *mut ERESOURCE,
    pub PagingIoResource: *mut ERESOURCE,
    pub AllocationSize: i64,
    pub FileSize: i64,
    pub ValidDataLength: i64,
}

/// [`FSRTL_ADVANCED_FCB_HEADER`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_fsrtl_advanced_fcb_header):
/// the common header, which it begins with, and what was added to it
/// since. `Flags` says whether a header is this long
/// ([`FSRTL_FLAG_ADVANCED_HEADER`]) and `Version` which of the later
/// fields it has.
#[repr(C)]
pub struct FSRTL_ADVANCED_FCB_HEADER {
    pub Common: FSRTL_COMMON_FCB_HEADER,
    /// The file system's own mutex, which also guards `FilterContexts`
    /// in a header of version 0.
    pub FastMutex: *mut FAST_MUTEX,
    /// The stream's [`FSRTL_PER_STREAM_CONTEXT`]s, by their `Links`.
    pub FilterContexts: LIST_ENTRY,
    /// Guards `FilterContexts`. Version 1 and later.
    pub PushLock: EX_PUSH_LOCK,
    /// Version 1 and later.
    pub FileContextSupportPointer: *mut *mut c_void,
    /// A union: `Oplock`, or `ReservedForRemote`. Version 2 and later.
    pub Oplock: *mut c_void,
    /// Version 3 and later.
    pub ReservedContext: *mut c_void,
}

/// [`FSRTL_PER_STREAM_CONTEXT`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_fsrtl_per_stream_context):
/// what a filter attaches to a stream, at the front of a block of its
/// own.
#[repr(C)]
pub struct FSRTL_PER_STREAM_CONTEXT {
    pub Links: LIST_ENTRY,
    pub OwnerId: *mut c_void,
    pub InstanceId: *mut c_void,
    /// Called with the context when the stream is torn down; it frees
    /// the block.
    pub FreeCallback: Option<unsafe extern "C" fn(*mut FSRTL_PER_STREAM_CONTEXT)>,
}

/// `Flags`: the header is an `FSRTL_ADVANCED_FCB_HEADER`.
pub const FSRTL_FLAG_ADVANCED_HEADER: u8 = 0x40;
/// `Flags2`: filters may attach contexts to the stream; `FilterContexts`
/// is a list.
pub const FSRTL_FLAG2_SUPPORTS_FILTER_CONTEXTS: u8 = 0x02;

/// `Version`: the header ends with `FilterContexts`.
pub const FSRTL_FCB_HEADER_V0: u8 = 0;
/// `Version`: `PushLock` and `FileContextSupportPointer` follow.
pub const FSRTL_FCB_HEADER_V1: u8 = 1;
/// `Version`: `Oplock` follows.
pub const FSRTL_FCB_HEADER_V2: u8 = 2;
/// `Version`: `ReservedContext` follows. What the headers of the pinned
/// build's kit set.
pub const FSRTL_FCB_HEADER_V3: u8 = 3;

/// The `Version` in a header's `ReservedAndVersion` byte.
pub const fn fcb_header_version(reserved_and_version: u8) -> u8 {
    reserved_and_version >> 4
}

/// `ReservedAndVersion` with its `Version` set to `version`, the
/// reserved bits kept.
pub const fn with_fcb_header_version(reserved_and_version: u8, version: u8) -> u8 {
    (reserved_and_version & 0x0F) | (version << 4)
}

/// `FILE_LOCK` (`ntifs.h`): a stream's byte-range locks, which a file
/// system embeds in its control block. The public symbols do not
/// describe it; the size and offsets are those the pinned kernel's
/// routines use (initialising writes a `LONG` at 0x58).
#[repr(C)]
pub struct FILE_LOCK {
    pub CompleteLockIrpRoutine: *mut c_void,
    pub UnlockRoutine: *mut c_void,
    pub FastIoIsQuestionable: u8,
    pub SpareC: [u8; 3],
    /// The kernel's own record of the locks, made with the first lock.
    pub LockInformation: *mut c_void,
    /// `FILE_LOCK_INFO LastReturnedLockInfo`.
    pub LastReturnedLockInfo: [u64; 6],
    pub LastReturnedLock: *mut c_void,
    pub LockRequestsInProgress: i32,
}

/// `TUNNEL` (`ntifs.h`): a volume's tunnel cache, which a file system
/// embeds in its volume control block. The public symbols do not
/// describe it; the offsets are those the pinned kernel's routines use.
#[repr(C)]
pub struct TUNNEL {
    pub Mutex: FAST_MUTEX,
    /// The kernel's own record of the entries.
    pub Cache: *mut c_void,
    pub TimerQueue: LIST_ENTRY,
    pub NumEntries: u16,
}

/// `BASE_MCB` (`ntifs.h`): the mapping a `LARGE_MCB` holds. The public
/// symbols do not describe it; the offsets are those the pinned kernel's
/// MCB routines use.
#[repr(C)]
pub struct BASE_MCB {
    pub MaximumPairCount: u32,
    pub PairCount: u32,
    pub PoolType: u16,
    pub Flags: u16,
    /// `MaximumPairCount` pairs of `{ NextVbn, Lbn }`, 32 bits each.
    pub Mapping: *mut c_void,
}

/// `LARGE_MCB` (`ntifs.h`): a `BASE_MCB` with the mutex that guards it,
/// which a file system embeds in its control blocks.
#[repr(C)]
pub struct LARGE_MCB {
    pub GuardedMutex: *mut FAST_MUTEX,
    pub BaseMcb: BASE_MCB,
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<FSRTL_COMMON_FCB_HEADER>() == 0x30);
    assert!(offset_of!(FSRTL_COMMON_FCB_HEADER, NodeByteSize) == 0x02);
    assert!(offset_of!(FSRTL_COMMON_FCB_HEADER, Flags) == 0x04);
    assert!(offset_of!(FSRTL_COMMON_FCB_HEADER, IsFastIoPossible) == 0x05);
    assert!(offset_of!(FSRTL_COMMON_FCB_HEADER, Flags2) == 0x06);
    assert!(offset_of!(FSRTL_COMMON_FCB_HEADER, ReservedAndVersion) == 0x07);
    assert!(offset_of!(FSRTL_COMMON_FCB_HEADER, Resource) == 0x08);
    assert!(offset_of!(FSRTL_COMMON_FCB_HEADER, PagingIoResource) == 0x10);
    assert!(offset_of!(FSRTL_COMMON_FCB_HEADER, AllocationSize) == 0x18);
    assert!(offset_of!(FSRTL_COMMON_FCB_HEADER, FileSize) == 0x20);
    assert!(offset_of!(FSRTL_COMMON_FCB_HEADER, ValidDataLength) == 0x28);

    assert!(size_of::<FSRTL_ADVANCED_FCB_HEADER>() == 0x68);
    assert!(offset_of!(FSRTL_ADVANCED_FCB_HEADER, Common) == 0x00);
    assert!(offset_of!(FSRTL_ADVANCED_FCB_HEADER, FastMutex) == 0x30);
    assert!(offset_of!(FSRTL_ADVANCED_FCB_HEADER, FilterContexts) == 0x38);
    assert!(offset_of!(FSRTL_ADVANCED_FCB_HEADER, PushLock) == 0x48);
    assert!(offset_of!(FSRTL_ADVANCED_FCB_HEADER, FileContextSupportPointer) == 0x50);
    assert!(offset_of!(FSRTL_ADVANCED_FCB_HEADER, Oplock) == 0x58);
    assert!(offset_of!(FSRTL_ADVANCED_FCB_HEADER, ReservedContext) == 0x60);

    assert!(size_of::<FILE_LOCK>() == 0x60);
    assert!(offset_of!(FILE_LOCK, FastIoIsQuestionable) == 0x10);
    assert!(offset_of!(FILE_LOCK, LockInformation) == 0x18);
    assert!(offset_of!(FILE_LOCK, LastReturnedLock) == 0x50);
    assert!(offset_of!(FILE_LOCK, LockRequestsInProgress) == 0x58);

    assert!(size_of::<TUNNEL>() == 0x58);
    assert!(offset_of!(TUNNEL, Cache) == 0x38);
    assert!(offset_of!(TUNNEL, TimerQueue) == 0x40);
    assert!(offset_of!(TUNNEL, NumEntries) == 0x50);

    assert!(size_of::<BASE_MCB>() == 0x18);
    assert!(offset_of!(BASE_MCB, PairCount) == 0x04);
    assert!(offset_of!(BASE_MCB, PoolType) == 0x08);
    assert!(offset_of!(BASE_MCB, Flags) == 0x0A);
    assert!(offset_of!(BASE_MCB, Mapping) == 0x10);
    assert!(size_of::<LARGE_MCB>() == 0x20);
    assert!(offset_of!(LARGE_MCB, BaseMcb) == 0x08);

    assert!(size_of::<FSRTL_PER_STREAM_CONTEXT>() == 0x28);
    assert!(offset_of!(FSRTL_PER_STREAM_CONTEXT, OwnerId) == 0x10);
    assert!(offset_of!(FSRTL_PER_STREAM_CONTEXT, InstanceId) == 0x18);
    assert!(offset_of!(FSRTL_PER_STREAM_CONTEXT, FreeCallback) == 0x20);
};

/// [`FS_FILTER_CALLBACKS`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_fs_filter_callbacks):
/// a file system's routines around the operations the kernel starts on
/// its behalf, in pairs (pre, post) per operation, each pair at the
/// offset its constant names. Only `SizeOfFsFilterCallbacks` bytes are
/// there.
#[repr(C)]
pub struct FS_FILTER_CALLBACKS {
    pub SizeOfFsFilterCallbacks: u32,
    pub Reserved: u32,
    pub Routines: [*mut c_void; 14],
}

/// The offsets of the pre-operation routines in `FS_FILTER_CALLBACKS`;
/// each post-operation routine is the next pointer.
pub const PRE_ACQUIRE_FOR_SECTION_SYNCHRONIZATION: usize = 0x08;
pub const PRE_RELEASE_FOR_SECTION_SYNCHRONIZATION: usize = 0x18;
pub const PRE_ACQUIRE_FOR_CC_FLUSH: usize = 0x28;
pub const PRE_RELEASE_FOR_CC_FLUSH: usize = 0x38;

/// `FS_FILTER_CALLBACK_DATA.Operation`.
pub const FS_FILTER_ACQUIRE_FOR_SECTION_SYNCHRONIZATION: u8 = 0xFF;
pub const FS_FILTER_RELEASE_FOR_SECTION_SYNCHRONIZATION: u8 = 0xFE;
pub const FS_FILTER_ACQUIRE_FOR_CC_FLUSH: u8 = 0xFB;
pub const FS_FILTER_RELEASE_FOR_CC_FLUSH: u8 = 0xFA;

/// `FS_FILTER_SECTION_SYNC_TYPE`: what a section is being synchronised
/// for; `SyncTypeOther` is a plain exclusive acquisition.
pub const SYNC_TYPE_OTHER: u32 = 0;

/// What a pre-operation routine returns when it did the operation
/// itself (`STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY`).
pub const STATUS_FSFILTER_OP_COMPLETED_SUCCESSFULLY: i32 = 0x126;

/// [`FS_FILTER_CALLBACK_DATA`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_fs_filter_callback_data):
/// what each routine is given. `Parameters` is the union
/// `FS_FILTER_PARAMETERS`; for a section's synchronisation its first
/// two `ULONG`s are `SyncType` and `PageProtection`.
#[repr(C)]
pub struct FS_FILTER_CALLBACK_DATA {
    pub SizeOfFsFilterCallbackData: u32,
    pub Operation: u8,
    pub Reserved: u8,
    pub DeviceObject: *mut c_void,
    pub FileObject: *mut c_void,
    pub Parameters: [u64; 5],
}

const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(size_of::<FS_FILTER_CALLBACKS>() == 0x78);
    assert!(offset_of!(FS_FILTER_CALLBACKS, Routines) == PRE_ACQUIRE_FOR_SECTION_SYNCHRONIZATION);
    assert!(size_of::<FS_FILTER_CALLBACK_DATA>() == 0x40);
    assert!(offset_of!(FS_FILTER_CALLBACK_DATA, Operation) == 0x04);
    assert!(offset_of!(FS_FILTER_CALLBACK_DATA, DeviceObject) == 0x08);
    assert!(offset_of!(FS_FILTER_CALLBACK_DATA, FileObject) == 0x10);
    assert!(offset_of!(FS_FILTER_CALLBACK_DATA, Parameters) == 0x18);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_version_is_the_high_four_bits_and_leaves_the_low_four() {
        // What `FsRtlSetupAdvancedHeader` compiles to in npfs.sys and
        // msfs.sys: `and al, 0x0F; or al, 0x30`.
        assert_eq!(with_fcb_header_version(0x00, FSRTL_FCB_HEADER_V3), 0x30);
        assert_eq!(with_fcb_header_version(0xA5, FSRTL_FCB_HEADER_V1), 0x15);
        assert_eq!(fcb_header_version(0x30), FSRTL_FCB_HEADER_V3);
        assert_eq!(fcb_header_version(0x0F), FSRTL_FCB_HEADER_V0);
        assert_eq!(fcb_header_version(0x2F), FSRTL_FCB_HEADER_V2);
    }
}
