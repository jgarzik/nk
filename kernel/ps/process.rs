//! The System process: the one process there is.
//!
//! Every thread belongs to it. Its block has `EPROCESS`'s size and
//! Windows' layout for the fields NK keeps; the rest is zero. It is made
//! before the first thread and never goes away, so threads point at it
//! without counting references. It holds the SYSTEM token
//! (`se::token`), the only token there is.

#![allow(non_snake_case, non_upper_case_globals)]

use crate::arch;
use crate::ke::thread;
use crate::mm::space::AddressSpace;
use crate::ob::object;
use core::ffi::c_void;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use nk_ntabi::ke::{KAPC_STATE, KAPC_STATE_NOT_ATTACHED, LIST_ENTRY};
use nk_ntabi::process as layout;
use nk_ntabi::status::{NTSTATUS, STATUS_SUCCESS};
use nk_ntabi::thread as thread_layout;

/// A variable a driver imports that holds a process: the import is
/// bound to its address, and the driver reads the pointer.
#[repr(transparent)]
pub struct ProcessVariable(AtomicPtr<u8>);

impl ProcessVariable {
    /// The address drivers import.
    pub const fn address(&'static self) -> *const () {
        core::ptr::from_ref(self).cast()
    }
}

/// `PsInitialSystemProcess` (`ntddk.h`):
/// the System process. Written once, before the first thread and long
/// before the first driver.
pub static PsInitialSystemProcess: ProcessVariable =
    ProcessVariable(AtomicPtr::new(core::ptr::null_mut()));

/// The next thread id. Process and thread ids come from one sequence
/// of multiples of four, as on Windows; the System process has the
/// first.
static NEXT_ID: AtomicU64 = AtomicU64::new(layout::SYSTEM_PROCESS_ID + 4);

/// Make the System process, created at `time` (system time).
/// `IoPriorityNormal`.
pub const IO_PRIORITY_NORMAL: u32 = 2;
/// `MEMORY_PRIORITY_NORMAL`, the page priority of a normal thread.
pub const MEMORY_PRIORITY_NORMAL: u32 = 5;

/// The I/O and page priority a new thread of `process` starts with, as
/// `CrossThreadFlags` bits: the process's defaults, as `PspInsertThread`
/// copies them.
///
/// # Safety
/// `process` is a process object.
pub unsafe fn thread_priorities(process: *const u8) -> u32 {
    // SAFETY: per the contract: two aligned 32-bit fields of its block.
    unsafe {
        let io = process.add(layout::FLAGS).cast::<u32>().read()
            >> layout::DEFAULT_IO_PRIORITY_SHIFT
            & 7;
        let page = process.add(layout::FLAGS2).cast::<u32>().read()
            >> layout::DEFAULT_PAGE_PRIORITY_SHIFT
            & 7;
        io << nk_ntabi::thread::THREAD_IO_PRIORITY_SHIFT
            | page << nk_ntabi::thread::THREAD_PAGE_PRIORITY_SHIFT
    }
}

/// NK's process object: Windows' `EPROCESS` at offset 0 so any `PEPROCESS`
/// pointer drivers hold is directly a `*mut Process`, followed by NK's own
/// process state.
#[repr(C, align(16))]
pub struct Process {
    object: [u8; layout::EPROCESS_SIZE],
    /// Per-process user address space (`None` for the System process, which
    /// owns `arch::kernel_address_space()`).
    space: Option<AddressSpace>,
    /// Per-process user-mode metadata (`None` for the System process and
    /// minimal kernel-test processes).
    user: Option<alloc::boxed::Box<super::user::UserProcessState>>,
}

/// Physical address of `process`'s root page table (`KPROCESS.DirectoryTableBase`).
///
/// # Safety
/// `process` is a live `EPROCESS`.
pub unsafe fn directory_table_base(process: *const u8) -> u64 {
    // SAFETY: per the contract; immutable once initialised.
    unsafe {
        process
            .add(layout::DIRECTORY_TABLE_BASE)
            .cast::<u64>()
            .read()
    }
}

/// The non-System process's user [`AddressSpace`], or `None` for the System
/// process.
///
/// # Safety
/// `process` is a live `EPROCESS` that outlives `'a`.
pub unsafe fn address_space<'a>(process: *const u8) -> Option<&'a AddressSpace> {
    // SAFETY: per the contract; `EPROCESS` is at offset 0 of `Process`.
    unsafe { (*process.cast::<Process>()).space.as_ref() }
}

/// The user process's [`super::user::UserProcessState`], if initialized.
///
/// # Safety
/// `process` is a live `EPROCESS` that outlives `'a`.
#[allow(dead_code)]
pub unsafe fn user_state<'a>(process: *const u8) -> Option<&'a super::user::UserProcessState> {
    // SAFETY: per the contract.
    unsafe { (*process.cast::<Process>()).user.as_deref() }
}

/// Attach `state` to a newly created user process.
///
/// # Safety
/// `process` is a live `EPROCESS` with exclusive ownership during creation.
#[allow(dead_code)]
pub unsafe fn set_user_state(
    process: *mut u8,
    state: alloc::boxed::Box<super::user::UserProcessState>,
) {
    // SAFETY: per the contract.
    unsafe {
        (*process.cast::<Process>()).user = Some(state);
    }
}

/// Allocate a new unique process or thread id (multiples of 4, starting at 8).
pub fn new_id() -> u64 {
    NEXT_ID.fetch_add(4, Ordering::Relaxed)
}

pub fn init(time: u64) -> Result<(), &'static str> {
    let process = object::create(&object::PROCESS_TYPE, size_of::<Process>())
        .ok_or("no memory for the System process")?;
    let token = crate::se::token::create(nk_se::token::Token::system())
        .ok_or("no memory for the System process's token")?;
    crate::se::token::init()?;
    // SAFETY: a fresh, zeroed object of a process's size, which the pool
    // aligns to 16 bytes; nothing else has it yet.
    unsafe {
        process
            .add(layout::DIRECTORY_TABLE_BASE)
            .cast::<u64>()
            .write(arch::kernel_address_space());
        (&raw mut (*process.cast::<Process>()).space).write(None);
        (&raw mut (*process.cast::<Process>()).user).write(None);
        // An `EX_FAST_REF`. Its count bits stay zero: NK hands out no
        // references in advance, every one is taken from the object.
        process.add(layout::TOKEN).cast::<*mut u8>().write(token);
        process
            .add(layout::OBJECT_TABLE)
            .cast::<*mut crate::ob::handle::HandleTable>()
            .write(crate::ob::handle::kernel_table());
        process.write(layout::PROCESS_OBJECT);
        // A process is something a thread can wait on: for its end,
        // which never comes.
        crate::ke::object::init_wait_list(process.cast());
        process
            .add(layout::UNIQUE_PROCESS_ID)
            .cast::<u64>()
            .write(layout::SYSTEM_PROCESS_ID);
        process.add(layout::CREATE_TIME).cast::<u64>().write(time);
        process
            .add(layout::BASE_PRIORITY)
            .write(thread::NORMAL_PRIORITY);
        process
            .add(layout::EXIT_STATUS)
            .cast::<NTSTATUS>()
            .write(nk_ntabi::status::STATUS_PENDING);
        // The priorities its threads start with: Windows' normal I/O
        // priority and normal page priority.
        process
            .add(layout::FLAGS2)
            .cast::<u32>()
            .write(MEMORY_PRIORITY_NORMAL << layout::DEFAULT_PAGE_PRIORITY_SHIFT);
        process
            .add(layout::FLAGS)
            .cast::<u32>()
            .write(IO_PRIORITY_NORMAL << layout::DEFAULT_IO_PRIORITY_SHIFT);
        process
            .add(layout::IMAGE_FILE_NAME)
            .copy_from_nonoverlapping(b"System".as_ptr(), 6);
    }
    PsInitialSystemProcess.0.store(process, Ordering::Release);
    super::cid::insert_process(layout::SYSTEM_PROCESS_ID, process);
    super::silo::init();
    Ok(())
}

/// Create a minimal non-System process object with its own per-process handle
/// table (`EPROCESS.ObjectTable`), unique PID, copied primary token reference
/// from `parent`, and optional `OBJ_INHERIT` handle duplication.
///
/// # Safety
/// `parent` is a live `EPROCESS` (typically [`system()`] or the current
/// process).
pub unsafe fn create_minimal(
    name: &[u8],
    parent: *mut u8,
    inherit: bool,
) -> Result<object::ObRef, NTSTATUS> {
    let process = object::create(&object::PROCESS_TYPE, size_of::<Process>())
        .ok_or(nk_ntabi::status::STATUS_INSUFFICIENT_RESOURCES)?;
    let Some(table) = crate::ob::handle::create_table() else {
        // SAFETY: newly created process with no resources attached yet.
        unsafe {
            (&raw mut (*process.cast::<Process>()).space).write(None);
            (&raw mut (*process.cast::<Process>()).user).write(None);
            object::dereference(process);
        }
        return Err(nk_ntabi::status::STATUS_INSUFFICIENT_RESOURCES);
    };
    let Some(space) = AddressSpace::new() else {
        // SAFETY: newly created process; tear down table before dereferencing.
        unsafe {
            (&raw mut (*process.cast::<Process>()).space).write(None);
            (&raw mut (*process.cast::<Process>()).user).write(None);
            crate::ob::handle::destroy_table(process, table);
            object::dereference(process);
        }
        return Err(nk_ntabi::status::STATUS_INSUFFICIENT_RESOURCES);
    };
    let dtb = space.root();
    // SAFETY: `parent` is live per the contract.
    let token = unsafe { PsReferencePrimaryToken(parent.cast()).cast::<u8>() };
    // SAFETY: `parent` is live per the contract.
    let parent_pid = unsafe { PsGetProcessId(parent.cast()).addr() as u64 };
    let pid = new_id();
    let now = crate::ke::time::system_time();
    // SAFETY: `process` is a fresh zeroed `Process` block owned exclusively
    // until returned.
    unsafe {
        process
            .add(layout::DIRECTORY_TABLE_BASE)
            .cast::<u64>()
            .write(dtb);
        (&raw mut (*process.cast::<Process>()).space).write(Some(space));
        (&raw mut (*process.cast::<Process>()).user).write(None);
        process.add(layout::TOKEN).cast::<*mut u8>().write(token);
        process
            .add(layout::OBJECT_TABLE)
            .cast::<*mut crate::ob::handle::HandleTable>()
            .write(table);
        process.write(layout::PROCESS_OBJECT);
        crate::ke::object::init_wait_list(process.cast());
        process
            .add(layout::UNIQUE_PROCESS_ID)
            .cast::<u64>()
            .write(pid);
        process
            .add(layout::INHERITED_FROM_UNIQUE_PROCESS_ID)
            .cast::<u64>()
            .write(parent_pid);
        process.add(layout::CREATE_TIME).cast::<u64>().write(now);
        process
            .add(layout::BASE_PRIORITY)
            .write(thread::NORMAL_PRIORITY);
        process
            .add(layout::EXIT_STATUS)
            .cast::<NTSTATUS>()
            .write(nk_ntabi::status::STATUS_PENDING);
        process
            .add(layout::FLAGS2)
            .cast::<u32>()
            .write(MEMORY_PRIORITY_NORMAL << layout::DEFAULT_PAGE_PRIORITY_SHIFT);
        process
            .add(layout::FLAGS)
            .cast::<u32>()
            .write(IO_PRIORITY_NORMAL << layout::DEFAULT_IO_PRIORITY_SHIFT);
        let len = name.len().min(layout::IMAGE_FILE_NAME_LEN - 1);
        process
            .add(layout::IMAGE_FILE_NAME)
            .copy_from_nonoverlapping(name.as_ptr(), len);
    }
    // SAFETY: `process` has its initial reference; `ObRef::adopt` cleans it up
    // on error via `deleted`.
    let held = unsafe { object::ObRef::adopt(process) };
    super::cid::insert_process(pid, held.body());
    if inherit {
        // SAFETY: both `parent` and `process` are live with valid tables.
        unsafe { crate::ob::handle::inherit_handles(parent, held.body()) }?;
    }
    Ok(held)
}

/// `PROCESS_TYPE`'s delete procedure: unregisters the PID, tears down the
/// process's handle table (if still present), drops its primary token
/// reference, and destroys its user address space.
///
/// # Safety
/// `body` is a `Process` object with no remaining references.
pub unsafe extern "C" fn deleted(body: *mut c_void) {
    let process = body.cast::<u8>();
    // SAFETY: per the contract; exclusive access during object deletion.
    unsafe {
        let pid = process.add(layout::UNIQUE_PROCESS_ID).cast::<u64>().read();
        super::cid::remove(pid);
        let table_slot = process
            .add(layout::OBJECT_TABLE)
            .cast::<*mut crate::ob::handle::HandleTable>();
        let table = table_slot.read();
        table_slot.write(core::ptr::null_mut());
        if !table.is_null() {
            crate::ob::handle::destroy_table(process, table);
        }
        let token_slot = process.add(layout::TOKEN).cast::<usize>();
        let field = token_slot.read();
        token_slot.write(0);
        let token = (field & !layout::FAST_REF_COUNT_MASK) as *mut u8;
        if !token.is_null() {
            object::dereference(token);
        }
        let sec_slot = process.add(layout::SECTION_OBJECT).cast::<*mut u8>();
        let sec = sec_slot.read();
        sec_slot.write(core::ptr::null_mut());
        if !sec.is_null() {
            object::dereference(sec);
        }
        core::ptr::drop_in_place(&raw mut (*process.cast::<Process>()).user);
        core::ptr::drop_in_place(&raw mut (*process.cast::<Process>()).space);
    }
}

/// The System process object.
pub fn system() -> *mut u8 {
    PsInitialSystemProcess.0.load(Ordering::Acquire)
}

/// The System process's primary token, with a reference for the caller
/// to drop (`object::dereference`).
pub fn reference_primary_token() -> *mut u8 {
    // SAFETY: the System process, which lives for ever.
    unsafe { PsReferencePrimaryToken(system().cast()).cast() }
}

/// [`PsGetCurrentProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetcurrentprocess):
/// the process whose address space the calling thread is in, which is
/// what the thread says it is attached to (`ApcState.Process`). The
/// kit's headers turn the name into `IoGetCurrentProcess`; Microsoft's
/// own drivers import this one.
pub extern "C" fn PsGetCurrentProcess() -> *mut c_void {
    // SAFETY: the running thread's block; the field is pointer-aligned
    // and only the thread itself changes it.
    unsafe {
        thread::object_field::<*mut c_void>(thread::current(), thread_layout::APC_STATE_PROCESS)
            .read()
    }
}

/// [`IoGetCurrentProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetcurrentprocess):
/// [`PsGetCurrentProcess`] by its documented name.
pub extern "C" fn IoGetCurrentProcess() -> *mut c_void {
    PsGetCurrentProcess()
}

/// Move the contents (including doubly-linked APC queues) of `KAPC_STATE`
/// `src` into `dst`, leaving `src` empty.
///
/// # Safety
/// Both pointers are valid writable `KAPC_STATE`s and the thread's APC lock
/// is held.
unsafe fn move_apc_state(src: *mut KAPC_STATE, dst: *mut KAPC_STATE) {
    // SAFETY: per the contract.
    unsafe {
        for mode in 0..2 {
            let src_head = (&raw mut (*src).ApcListHead).cast::<LIST_ENTRY>().add(mode);
            let dst_head = (&raw mut (*dst).ApcListHead).cast::<LIST_ENTRY>().add(mode);
            let LIST_ENTRY { Flink, Blink } = src_head.read_unaligned();
            if Flink == src_head {
                dst_head.write_unaligned(LIST_ENTRY {
                    Flink: dst_head,
                    Blink: dst_head,
                });
            } else {
                dst_head.write_unaligned(LIST_ENTRY { Flink, Blink });
                (*Flink).Blink = dst_head;
                (*Blink).Flink = dst_head;
            }
            src_head.write_unaligned(LIST_ENTRY {
                Flink: src_head,
                Blink: src_head,
            });
        }
        (&raw mut (*dst).Process).write_unaligned((&raw const (*src).Process).read_unaligned());
        (&raw mut (*dst).InProgressFlags).write((*src).InProgressFlags);
        (&raw mut (*dst).KernelApcPending).write((*src).KernelApcPending);
        (&raw mut (*dst).UserApcPendingAll).write((*src).UserApcPendingAll);
        (&raw mut (*src).Process).write_unaligned(core::ptr::null_mut());
        (&raw mut (*src).InProgressFlags).write(0);
        (&raw mut (*src).KernelApcPending).write(0);
        (&raw mut (*src).UserApcPendingAll).write(0);
    }
}

/// [`KeStackAttachProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-kestackattachprocess):
/// put the calling thread in `process`'s address space, supporting nested
/// attaches. A thread already in `process` is left as it is and `apc_state`
/// receives [`KAPC_STATE_NOT_ATTACHED`] in `Process` with nothing else
/// written. From a DPC routine it stops as on Windows
/// ([`INVALID_PROCESS_ATTACH_ATTEMPT`](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x5--invalid-process-attach-attempt)).
///
/// # Safety
/// `process` is a live process object; `apc_state` points to room for a
/// `KAPC_STATE`.
pub unsafe extern "C" fn KeStackAttachProcess(process: *mut c_void, apc_state: *mut KAPC_STATE) {
    let current = PsGetCurrentProcess();
    if crate::ke::dpc::running() || process.is_null() {
        crate::kd::bugcheck(format_args!(
            "0x00000005 INVALID_PROCESS_ATTACH_ATTEMPT: invalid attach (parameters {process:p}, \
             {current:p}, 0, {})",
            u8::from(crate::ke::dpc::running())
        ));
    }
    if process == current {
        // SAFETY: per the contract; the driver's memory, written through
        // its pointer.
        unsafe {
            (&raw mut (*apc_state).Process)
                .write_unaligned(core::ptr::without_provenance_mut(KAPC_STATE_NOT_ATTACHED));
        }
        return;
    }
    let me = thread::current();
    // SAFETY: `me` is the running thread and `process` is a live process.
    // Holding the thread's APC lock raises IRQL to DISPATCH_LEVEL so no
    // preemption or concurrent APC insertion can observe a half-swapped state.
    unsafe {
        let _lock = thread::apc_lock(me).lock();
        let active = thread::object_field::<KAPC_STATE>(me, thread_layout::APC_STATE);
        let saved = thread::object_field::<KAPC_STATE>(me, thread_layout::SAVED_APC_STATE);
        let index_ptr = thread::object_field::<u8>(me, thread_layout::APC_STATE_INDEX);
        if index_ptr.read() == 0 {
            // Top-level attach: save original state inside `KTHREAD.SavedApcState`
            // and mark the caller's `KAPC_STATE.Process` as null.
            move_apc_state(active, saved);
            (&raw mut (*apc_state).Process).write_unaligned(core::ptr::null_mut());
            index_ptr.write(1);
        } else {
            // Nested attach: save current attached state in caller's `apc_state`.
            move_apc_state(active, apc_state);
        }
        (&raw mut (*active).Process).write(process);
        arch::switch_address_space(directory_table_base(process.cast()));
    }
}

/// [`KeUnstackDetachProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-keunstackdetachprocess):
/// undo [`KeStackAttachProcess`]. A state marked as an attach that did
/// nothing needs nothing undone. Any other state on an unattached thread
/// stops the system
/// ([`INVALID_PROCESS_DETACH_ATTEMPT`](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x6--invalid-process-detach-attempt)).
///
/// # Safety
/// `apc_state` is the state a `KeStackAttachProcess` filled in.
pub unsafe extern "C" fn KeUnstackDetachProcess(apc_state: *mut KAPC_STATE) {
    // SAFETY: per the contract.
    let saved_proc = unsafe { (&raw const (*apc_state).Process).read_unaligned() };
    if saved_proc.addr() == KAPC_STATE_NOT_ATTACHED {
        return;
    }
    let me = thread::current();
    // SAFETY: `me` is the running thread.
    let deliver_apc = unsafe {
        let _lock = thread::apc_lock(me).lock();
        let index_ptr = thread::object_field::<u8>(me, thread_layout::APC_STATE_INDEX);
        if index_ptr.read() == 0 {
            crate::kd::bugcheck(format_args!(
                "0x00000006 INVALID_PROCESS_DETACH_ATTEMPT: a detach by a thread that is not \
                 attached (saved process {saved_proc:p})"
            ));
        }
        let active = thread::object_field::<KAPC_STATE>(me, thread_layout::APC_STATE);
        let kernel_head = (&raw mut (*active).ApcListHead).cast::<LIST_ENTRY>();
        let user_head = kernel_head.add(1);
        if (*active).InProgressFlags != 0
            || (*kernel_head).Flink != kernel_head
            || (*user_head).Flink != user_head
        {
            crate::kd::bugcheck(format_args!(
                "0x00000006 INVALID_PROCESS_DETACH_ATTEMPT: attached APC state not empty on detach"
            ));
        }
        if saved_proc.is_null() {
            let saved = thread::object_field::<KAPC_STATE>(me, thread_layout::SAVED_APC_STATE);
            move_apc_state(saved, active);
            index_ptr.write(0);
        } else {
            move_apc_state(apc_state, active);
        }
        let restored = (*active).Process;
        arch::switch_address_space(directory_table_base(restored.cast()));
        let restored_kernel_head = (&raw mut (*active).ApcListHead).cast::<LIST_ENTRY>();
        let has_kernel_apc = (*active).KernelApcPending != 0
            || (*restored_kernel_head).Flink != restored_kernel_head;
        if has_kernel_apc {
            (*active).KernelApcPending = 1;
        }
        has_kernel_apc
    };
    if deliver_apc {
        arch::self_interrupt(arch::APC.0);
    }
}

/// Stop unless `process` is the System process: quota is asked about
/// a process, and there is no other.
fn only_the_system_process(routine: &str, process: *mut c_void) {
    if process != system().cast() {
        crate::kd::bugcheck(format_args!(
            "{routine}: {process:p} is not the System process, and there is no other"
        ));
    }
}

/// `PsChargeProcessPagedPoolQuota` (`ntoskrnl.exe` exports it; the
/// kit's headers do not declare it): charge `amount` bytes of paged
/// pool to a process's quota. The System process is charged nothing,
/// whatever the amount: Windows compares the process with
/// `PsInitialSystemProcess` and answers success without looking at a
/// quota block, and so does NK, which has no other process to charge.
///
/// # Safety
/// `process` is a process object.
pub unsafe extern "C" fn PsChargeProcessPagedPoolQuota(
    process: *mut c_void,
    _amount: usize,
) -> NTSTATUS {
    only_the_system_process("PsChargeProcessPagedPoolQuota", process);
    STATUS_SUCCESS
}

/// `PsReturnProcessPagedPoolQuota` (exported, not in the kit's
/// headers): give back quota [`PsChargeProcessPagedPoolQuota`] charged.
/// Nothing was charged to the System process, and nothing is returned.
///
/// # Safety
/// `process` is a process object.
pub unsafe extern "C" fn PsReturnProcessPagedPoolQuota(process: *mut c_void, _amount: usize) {
    only_the_system_process("PsReturnProcessPagedPoolQuota", process);
}

/// The running thread's client id: its process's id, then its own.
fn current_client_id() -> [*mut c_void; 2] {
    // SAFETY: the running thread's block; the field is pointer-aligned
    // and written once, when the thread is made.
    unsafe {
        thread::object_field::<[*mut c_void; 2]>(thread::current(), thread_layout::CID).read()
    }
}

/// [`PsGetCurrentProcessId`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetcurrentprocessid):
/// the id of the calling thread's process, from the thread's client id.
pub extern "C" fn PsGetCurrentProcessId() -> *mut c_void {
    current_client_id()[0]
}

/// [`PsGetCurrentThreadId`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetcurrentthreadid):
/// the calling thread's id.
pub extern "C" fn PsGetCurrentThreadId() -> *mut c_void {
    current_client_id()[1]
}

/// `PsGetProcessImageFileName` (undocumented): short ASCII image name of a
/// process (`EPROCESS.ImageFileName`).
///
/// # Safety
/// `process` is null or a live `EPROCESS`.
pub unsafe extern "C" fn PsGetProcessImageFileName(process: *mut c_void) -> *const u8 {
    if process.is_null() {
        return c"System".as_ptr().cast();
    }
    // SAFETY: per the contract; `ImageFileName` is 15 bytes inside `EPROCESS`.
    unsafe { process.cast::<u8>().add(layout::IMAGE_FILE_NAME) }
}

/// [`PsGetProcessId`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocessid).
///
/// # Safety
/// `process` is a process object.
pub unsafe extern "C" fn PsGetProcessId(process: *mut c_void) -> *mut c_void {
    // SAFETY: per the contract; the field is pointer-aligned and
    // written once.
    unsafe {
        process
            .cast::<u8>()
            .add(layout::UNIQUE_PROCESS_ID)
            .cast::<*mut c_void>()
            .read()
    }
}

/// [`PsGetThreadProcessId`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psgetthreadprocessid):
/// the id of the process `thread` belongs to, from the thread's client
/// id.
///
/// # Safety
/// `thread` is a thread object.
pub unsafe extern "C" fn PsGetThreadProcessId(thread: *mut c_void) -> *mut c_void {
    // SAFETY: per the contract; the field is pointer-aligned and
    // written once.
    unsafe {
        thread
            .cast::<u8>()
            .add(thread_layout::CID)
            .cast::<*mut c_void>()
            .read()
    }
}

/// `PsGetProcessSessionId` (`ntoskrnl.exe` exports it; the kit's
/// headers do not declare it): the id of the session `process` is in.
/// A process in no session (`EPROCESS.Session` null) reads as session
/// 0, as on Windows, and no process is ever in one: there are no
/// session spaces to point at.
///
/// # Safety
/// `process` is a process object.
pub unsafe extern "C" fn PsGetProcessSessionId(process: *mut c_void) -> u32 {
    // SAFETY: per the contract; the field is pointer-aligned.
    let session = unsafe {
        process
            .cast::<u8>()
            .add(layout::SESSION)
            .cast::<*mut c_void>()
            .read()
    };
    if !session.is_null() {
        crate::kd::bugcheck(format_args!(
            "PsGetProcessSessionId: process {process:p} names a session, and there are none"
        ));
    }
    0
}

/// `PsGetThreadSessionId` (exported, not in the kit's headers): the
/// session of the process `thread` belongs to.
///
/// # Safety
/// `thread` is a thread object.
pub unsafe extern "C" fn PsGetThreadSessionId(thread: *mut c_void) -> u32 {
    // SAFETY: per the contract.
    unsafe { PsGetProcessSessionId(PsGetThreadProcess(thread)) }
}

/// [`PsGetThreadProcess`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psgetthreadprocess):
/// the process a thread belongs to (`KTHREAD.Process`), without a
/// reference, as on Windows.
///
/// # Safety
/// `thread` is a thread object.
pub unsafe extern "C" fn PsGetThreadProcess(thread: *mut c_void) -> *mut c_void {
    // SAFETY: per the contract: a thread names its process, which
    // lives at least as long, at a pointer-aligned offset.
    unsafe {
        thread
            .cast::<u8>()
            .add(thread_layout::PROCESS)
            .cast::<*mut c_void>()
            .read()
    }
}

/// [`PsReferencePrimaryToken`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psreferenceprimarytoken):
/// the process's primary token, with a reference the caller gives up
/// through [`PsDereferencePrimaryToken`]. The token is read out of the
/// process's fast reference (`EPROCESS.Token`), whose count bits are
/// not part of the pointer; every reference is taken on the token
/// itself.
///
/// # Safety
/// `process` is a process object.
pub unsafe extern "C" fn PsReferencePrimaryToken(process: *mut c_void) -> *mut c_void {
    // SAFETY: per the contract: a process holds its token for as long
    // as it lives, at a pointer-aligned offset; the field is written
    // once, when the process is made.
    unsafe {
        let field = process
            .cast::<u8>()
            .add(layout::TOKEN)
            .cast::<usize>()
            .read();
        let token = (field & !layout::FAST_REF_COUNT_MASK) as *mut u8;
        object::reference(token);
        token.cast()
    }
}

/// [`PsDereferencePrimaryToken`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psdereferenceprimarytoken):
/// give up a reference [`PsReferencePrimaryToken`] took. The kit's
/// headers turn the name into `ObDereferenceObject`; Microsoft's own
/// drivers import this one.
///
/// # Safety
/// `token` came from [`PsReferencePrimaryToken`] and the caller owns
/// that reference.
pub unsafe extern "C" fn PsDereferencePrimaryToken(token: *mut c_void) {
    // SAFETY: per the contract.
    unsafe { object::dereference(token.cast()) };
}

/// An id for a new thread.
pub fn new_thread_id() -> u64 {
    new_id()
}

/// [`PsGetCurrentThreadTeb`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetcurrentthreadteb):
/// the user-mode `TEB` pointer of the calling thread (`KTHREAD.Teb`), or null
/// for a system thread.
pub extern "C" fn PsGetCurrentThreadTeb() -> *mut c_void {
    let me = thread::current();
    // SAFETY: `me` is the running thread.
    unsafe { thread::object_field::<*mut c_void>(me, thread_layout::TEB).read() }
}

/// [`PsGetProcessCreateTimeQuadPart`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psgetprocesscreatetimequadpart):
/// creation time of `process` (`EPROCESS.CreateTime`).
///
/// # Safety
/// `process` is a live `EPROCESS`.
pub unsafe extern "C" fn PsGetProcessCreateTimeQuadPart(process: *mut c_void) -> i64 {
    // SAFETY: per the contract.
    unsafe {
        process
            .cast::<u8>()
            .add(layout::CREATE_TIME)
            .cast::<i64>()
            .read()
    }
}

/// [`PsIsThreadTerminating`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-psisthreadterminating):
/// whether `thread` is terminated or terminating.
///
/// # Safety
/// `thread` is a live `ETHREAD`.
pub unsafe extern "C" fn PsIsThreadTerminating(thread: *mut c_void) -> u8 {
    // SAFETY: per the contract.
    unsafe {
        let state = thread.cast::<u8>().add(thread_layout::STATE).read();
        let flags = thread
            .cast::<u8>()
            .add(thread_layout::CROSS_THREAD_FLAGS)
            .cast::<u32>()
            .read();
        u8::from(state == thread_layout::state::TERMINATED || (flags & 1) != 0)
    }
}

/// `PsIsProtectedProcess`: NK does not run PPL/Protected Processes.
pub extern "C" fn PsIsProtectedProcess(_process: *mut c_void) -> u8 {
    0
}

// ---- tests --------------------------------------------------------------

/// The System process as a binary reading it would find it, and the
/// calling thread's place in it.
pub fn self_test() -> Result<(), &'static str> {
    use crate::ob::handle;
    let process = system();
    // What a driver reads from the variable it imports, and what the
    // two names for "the current process" give it.
    // SAFETY: the variable is a pointer-sized static.
    let imported = unsafe { PsInitialSystemProcess.address().cast::<*mut u8>().read() };
    if imported != process || process.is_null() {
        return Err("PsInitialSystemProcess does not hold the System process");
    }
    if PsGetCurrentProcess() != process.cast() || IoGetCurrentProcess() != process.cast() {
        return Err("the current process is not the System process");
    }
    let thread = crate::ke::thread::current().cast::<u8>();
    // SAFETY: the process is live for ever and the running thread for
    // the duration; the offsets are inside their blocks and aligned.
    let (kind, id, name, owner, attached, client) = unsafe {
        (
            process.read(),
            process.add(layout::UNIQUE_PROCESS_ID).cast::<u64>().read(),
            process
                .add(layout::IMAGE_FILE_NAME)
                .cast::<[u8; 7]>()
                .read(),
            thread.add(thread_layout::PROCESS).cast::<*mut u8>().read(),
            thread
                .add(thread_layout::APC_STATE_PROCESS)
                .cast::<*mut u8>()
                .read(),
            thread.add(thread_layout::CID).cast::<[u64; 2]>().read(),
        )
    };
    if kind != layout::PROCESS_OBJECT || id != layout::SYSTEM_PROCESS_ID || &name != b"System\0" {
        return Err("the System process does not say what it is");
    }
    if owner != process || attached != process {
        return Err("the running thread does not belong to the System process");
    }
    if client[0] != layout::SYSTEM_PROCESS_ID || client[1] <= id || client[1] % 4 != 0 {
        return Err("the running thread's client id is not a System thread's");
    }
    // `NtCurrentProcess()` names it, and only as a process.
    let current = -1i64 as u64;
    match handle::reference(current, Some(&raw const object::PROCESS_TYPE)) {
        Ok(body) if body.body() == process => {}
        Ok(_) => return Err("NtCurrentProcess names another object"),
        Err(_) => return Err("NtCurrentProcess names nothing"),
    }
    if handle::reference(current, Some(&raw const object::THREAD_TYPE)).is_ok() {
        return Err("NtCurrentProcess was accepted as a thread");
    }
    // F4: per-process handle table isolation, OBJ_INHERIT duplication, and
    // clean process teardown with zero pool leak.
    {
        use crate::mm::pool;
        use nk_ob::handles::{Attributes, Mode};

        let blocks = || pool::usage().blocks - handle::storage().0;
        let before = blocks();
        let ev1 = object::create(&object::EVENT_TYPE, size_of::<nk_ntabi::ke::KEVENT>())
            .ok_or("F4: no memory for event 1")?;
        let ev2 = object::create(&object::EVENT_TYPE, size_of::<nk_ntabi::ke::KEVENT>())
            .ok_or("F4: no memory for event 2")?;
        // SAFETY: newly created events held by `ObRef::adopt`.
        let (ev1, ev2) = unsafe { (object::ObRef::adopt(ev1), object::ObRef::adopt(ev2)) };
        // SAFETY: `system()` is live.
        let p1 = unsafe { create_minimal(b"test1.exe", process, false) }
            .map_err(|_| "F4: could not create process 1")?;
        // Open one inheritable handle and one non-inheritable handle in P1.
        // SAFETY: `p1`, `ev1`, and `ev2` are live.
        let h_inh = unsafe {
            handle::open_in(
                p1.body(),
                ev1.body(),
                0x3,
                Attributes {
                    inherit: true,
                    protect_from_close: false,
                },
                false,
            )
        }
        .map_err(|_| "F4: could not open inheritable handle in P1")?;
        // SAFETY: `p1` and `ev2` are live.
        let h_priv =
            unsafe { handle::open_in(p1.body(), ev2.body(), 0x3, Attributes::default(), false) }
                .map_err(|_| "F4: could not open private handle in P1")?;
        // P1's handle must resolve in P1 and must NOT resolve in a fresh empty P3.
        // SAFETY: `p1` is live.
        let (found_p1, _) = unsafe {
            handle::reference_in(
                p1.body(),
                h_inh,
                Some(&raw const object::EVENT_TYPE),
                0x1,
                Mode::User,
            )
        }
        .map_err(|_| "F4: handle in P1 did not resolve in P1")?;
        if found_p1.body() != ev1.body() {
            return Err("F4: handle in P1 resolved to wrong object");
        }
        drop(found_p1);
        // SAFETY: `p1` is live.
        let p2 = unsafe { create_minimal(b"test2.exe", p1.body(), true) }
            .map_err(|_| "F4: could not create child process P2")?;
        // P2 must inherit ev1 (first slot -> same handle value `h_inh`) and NOT ev2 (`h_priv`).
        // SAFETY: `p2` is live.
        let (found_p2, _) = unsafe {
            handle::reference_in(
                p2.body(),
                h_inh,
                Some(&raw const object::EVENT_TYPE),
                0x1,
                Mode::User,
            )
        }
        .map_err(|_| "F4: P2 did not inherit OBJ_INHERIT handle")?;
        if found_p2.body() != ev1.body() {
            return Err("F4: P2 inherited handle points to wrong object");
        }
        drop(found_p2);
        // SAFETY: `p2` is live.
        if unsafe { handle::reference_in(p2.body(), h_priv, None, 0, Mode::User) }.is_ok() {
            return Err("F4: P2 inherited a non-inheritable handle");
        }
        // `NtCurrentProcess()` in P2 returns P2, not System.
        // SAFETY: `p2` is live.
        let (cur_p2, _) = unsafe {
            handle::reference_in(
                p2.body(),
                current,
                Some(&raw const object::PROCESS_TYPE),
                0,
                Mode::User,
            )
        }
        .map_err(|_| "F4: NtCurrentProcess failed in P2")?;
        if cur_p2.body() != p2.body() {
            return Err("F4: NtCurrentProcess in P2 did not return P2");
        }
        drop(cur_p2);
        // CID table + PsLookupProcessByProcessId + ZwOpenProcess + ZwOpenThread.
        {
            use nk_ntabi::ob::OBJECT_ATTRIBUTES;
            use nk_ntabi::user::{CLIENT_ID, PROCESS_QUERY_INFORMATION, THREAD_QUERY_INFORMATION};
            // SAFETY: `p2` is live.
            let p2_pid = unsafe { PsGetProcessId(p2.body().cast()) };
            let mut looked: *mut c_void = core::ptr::null_mut();
            // SAFETY: `looked` is a local pointer slot.
            let st = unsafe { super::cid::PsLookupProcessByProcessId(p2_pid, &raw mut looked) };
            if st != STATUS_SUCCESS || looked != p2.body().cast() {
                return Err("PsLookupProcessByProcessId did not find P2");
            }
            // SAFETY: reference taken by `PsLookupProcessByProcessId`.
            unsafe { object::dereference(looked.cast()) };
            let oa = OBJECT_ATTRIBUTES {
                Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
                RootDirectory: core::ptr::null_mut(),
                ObjectName: core::ptr::null_mut(),
                Attributes: 0,
                SecurityDescriptor: core::ptr::null_mut(),
                SecurityQualityOfService: core::ptr::null_mut(),
            };
            let cid_p2 = CLIENT_ID {
                UniqueProcess: p2_pid,
                UniqueThread: core::ptr::null_mut(),
            };
            let mut h_p2: *mut c_void = core::ptr::null_mut();
            // SAFETY: local pointers in kernel mode.
            let st = unsafe {
                super::ZwOpenProcess(
                    &raw mut h_p2,
                    PROCESS_QUERY_INFORMATION,
                    &raw const oa,
                    &raw const cid_p2,
                )
            };
            if st != STATUS_SUCCESS || h_p2.is_null() {
                return Err("ZwOpenProcess failed for live P2");
            }
            let _ = handle::close(h_p2 as u64);
            let cid_me = CLIENT_ID {
                UniqueProcess: PsGetCurrentProcessId(),
                UniqueThread: PsGetCurrentThreadId(),
            };
            let mut h_th: *mut c_void = core::ptr::null_mut();
            // SAFETY: local pointers in kernel mode.
            let st = unsafe {
                super::ZwOpenThread(
                    &raw mut h_th,
                    THREAD_QUERY_INFORMATION,
                    &raw const oa,
                    &raw const cid_me,
                )
            };
            if st != STATUS_SUCCESS || h_th.is_null() {
                return Err("ZwOpenThread failed for current thread");
            }
            let _ = handle::close(h_th as u64);
            let cid_bad = CLIENT_ID {
                UniqueProcess: core::ptr::with_exposed_provenance_mut(0xDEAD_0000),
                UniqueThread: core::ptr::null_mut(),
            };
            // SAFETY: local pointers in kernel mode.
            if unsafe {
                super::ZwOpenProcess(
                    &raw mut h_p2,
                    PROCESS_QUERY_INFORMATION,
                    &raw const oa,
                    &raw const cid_bad,
                )
            } != nk_ntabi::status::STATUS_INVALID_CID
            {
                return Err("ZwOpenProcess did not return STATUS_INVALID_CID for unknown PID");
            }
        }
        drop(p2);
        drop(p1);
        drop(ev2);
        drop(ev1);
        if blocks() != before {
            return Err("F4: destroying processes with open handles leaked pool blocks");
        }
    }
    Ok(())
}

/// What a thread beside the tested one says it is.
static PEER: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];

/// Who a thread is, as a driver asks: the System process's id is 4 by
/// every route, each thread has an id of its own from the same
/// sequence, and process and threads are in session 0. Returns the
/// questions asked.
pub fn identity_test() -> Result<u32, &'static str> {
    fn peer(_: usize) {
        PEER[0].store(PsGetCurrentProcessId().addr() as u64, Ordering::Release);
        PEER[1].store(PsGetCurrentThreadId().addr() as u64, Ordering::Release);
        PEER[2].store(PsGetCurrentProcess().addr() as u64, Ordering::Release);
    }
    let process = system().cast::<c_void>();
    let me = thread::current().cast::<c_void>();
    let (pid, tid) = (
        PsGetCurrentProcessId().addr(),
        PsGetCurrentThreadId().addr(),
    );
    // SAFETY: the System process and the running thread.
    let (of_process, of_thread) = unsafe {
        (
            PsGetProcessId(process).addr(),
            PsGetThreadProcessId(me).addr(),
        )
    };
    if pid as u64 != layout::SYSTEM_PROCESS_ID || of_process != pid || of_thread != pid {
        return Err("the System process's id is not 4 by every way of asking");
    }
    if tid == 0 || tid % 4 != 0 || tid == pid {
        return Err("the calling thread's id is not an id of its own");
    }
    let other = thread::create_referenced(peer, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)?;
    // SAFETY: a thread this test holds a reference to, which it gives
    // up at the end; the wait is for that thread's end.
    let (waited, its_process, sessions) = unsafe {
        let waited = crate::ke::wait::wait(Some(other.cast()), None);
        let facts = (
            PsGetThreadProcessId(other.cast()).addr(),
            [
                PsGetProcessSessionId(process),
                PsGetThreadSessionId(me),
                PsGetThreadSessionId(other.cast()),
            ],
        );
        object::dereference(other.cast());
        (waited, facts.0, facts.1)
    };
    let said = PEER
        .each_ref()
        .map(|fact| fact.load(Ordering::Acquire) as usize);
    if waited != 0 {
        return Err("the other thread could not be waited for");
    }
    if said[0] != pid || said[2] != process.addr() || its_process != pid {
        return Err("another system thread is not in the System process");
    }
    if said[1] == tid || said[1] == 0 || said[1] % 4 != 0 || said[1] == pid {
        return Err("another thread does not have an id of its own");
    }
    if sessions != [0; 3] {
        return Err("the System process or a thread of it is not in session 0");
    }
    Ok(11)
}

/// Attaching to the process the thread is in, single and nested attaches to
/// distinct per-process address spaces with isolation at the same VA,
/// firmware CR3 save/restore while attached, and zero frame/pool leak on
/// teardown.
pub fn attach_test() -> Result<(), &'static str> {
    let process = system().cast::<c_void>();
    let before = crate::ke::irql::current();
    let mut state = [0xAAu8; size_of::<KAPC_STATE>()];
    let at = core::mem::offset_of!(KAPC_STATE, Process);
    // SAFETY: the System process, and a local of a `KAPC_STATE`'s size.
    unsafe { KeStackAttachProcess(process, state.as_mut_ptr().cast()) };
    let marked = state[at..at + 8] == KAPC_STATE_NOT_ATTACHED.to_le_bytes();
    let untouched = state[..at]
        .iter()
        .chain(&state[at + 8..])
        .all(|&b| b == 0xAA);
    if !marked {
        return Err("an attach to the thread's own process did not mark the saved state");
    }
    if !untouched {
        return Err("an attach that saved nothing wrote more than the mark");
    }
    if PsGetCurrentProcess() != process || crate::ke::irql::current() != before {
        return Err("an attach to the thread's own process moved the thread or the IRQL");
    }
    // SAFETY: the state the attach filled in.
    unsafe { KeUnstackDetachProcess(state.as_mut_ptr().cast()) };
    if PsGetCurrentProcess() != process || crate::ke::irql::current() != before {
        return Err("a detach moved the thread or the IRQL");
    }

    // F7: two isolated address spaces mapped at the same low-half VA, nested
    // attach/detach, firmware CR3 save/restore, and leak-free teardown.
    use crate::mm::{self, pool};
    use crate::ob::handle;
    use nk_mm::pt::Prot;

    const TEST_VA: u64 = 0x2000_0000;
    let frames_before = mm::free_frame_count();
    let pool_before = pool::usage().blocks - handle::storage().0;
    let sys_root = arch::kernel_address_space();

    // SAFETY: `system()` is live.
    let p1 = unsafe { create_minimal(b"space1.exe", system(), false) }
        .map_err(|_| "F7: could not create process 1")?;
    // SAFETY: `system()` is live.
    let p2 = unsafe { create_minimal(b"space2.exe", system(), false) }
        .map_err(|_| "F7: could not create process 2")?;
    let f1 = mm::alloc_frames(1).ok_or("F7: no frame for p1")?;
    let f2 = mm::alloc_frames(1).ok_or("F7: no frame for p2")?;
    // SAFETY: `p1` and `p2` are live non-System processes with distinct spaces.
    let (s1, s2) = unsafe {
        (
            address_space(p1.body()).ok_or("F7: p1 has no address space")?,
            address_space(p2.body()).ok_or("F7: p2 has no address space")?,
        )
    };
    if s1.root() == sys_root || s2.root() == sys_root || s1.root() == s2.root() {
        return Err("F7: processes do not have distinct root page tables");
    }
    s1.map_page(TEST_VA, f1, Prot::USER_RW)
        .map_err(|_| "F7: map_page failed for p1")?;
    s2.map_page(TEST_VA, f2, Prot::USER_RW)
        .map_err(|_| "F7: map_page failed for p2")?;
    if s1.translate(TEST_VA) != Some(f1) || s2.translate(TEST_VA) != Some(f2) {
        return Err("F7: AddressSpace::translate did not return the mapped frame");
    }

    let mut st1 = core::mem::MaybeUninit::<KAPC_STATE>::zeroed();
    let mut st2 = core::mem::MaybeUninit::<KAPC_STATE>::zeroed();
    // Attach to p1, write pattern A, nested attach to p2, write pattern B,
    // check isolation on both sides and across firmware_enter/leave.
    // SAFETY: `p1`, `p2` are live; `TEST_VA` is mapped RW in each.
    let (seen_p1_after, seen_p2, fw_ok) = unsafe {
        KeStackAttachProcess(p1.body().cast(), st1.as_mut_ptr());
        if PsGetCurrentProcess() != p1.body().cast() || arch::current_address_space() != s1.root() {
            KeUnstackDetachProcess(st1.as_mut_ptr());
            return Err("F7: top-level attach did not switch process/address space");
        }
        (TEST_VA as *mut u64).write_volatile(0x1111_2222_3333_4444);

        // Nested attach to p2.
        KeStackAttachProcess(p2.body().cast(), st2.as_mut_ptr());
        let nested_ok =
            PsGetCurrentProcess() == p2.body().cast() && arch::current_address_space() == s2.root();
        let initial_p2 = (TEST_VA as *const u64).read_volatile();
        (TEST_VA as *mut u64).write_volatile(0x5555_6666_7777_8888);
        let read_p2 = (TEST_VA as *const u64).read_volatile();

        // Firmware enter/leave while attached to p2 must switch to System and back.
        let saved = arch::firmware_enter();
        let in_fw = arch::current_address_space() == sys_root;
        arch::firmware_leave(saved);
        let after_fw = arch::current_address_space() == s2.root();

        KeUnstackDetachProcess(st2.as_mut_ptr());
        let back_p1 =
            PsGetCurrentProcess() == p1.body().cast() && arch::current_address_space() == s1.root();
        let read_p1 = (TEST_VA as *const u64).read_volatile();

        KeUnstackDetachProcess(st1.as_mut_ptr());
        let back_sys =
            PsGetCurrentProcess() == process && arch::current_address_space() == sys_root;
        if !nested_ok || !back_p1 || !back_sys || initial_p2 != 0 {
            return Err("F7: nested attach/detach or address-space isolation failed");
        }
        (read_p1, read_p2, in_fw && after_fw)
    };
    if seen_p1_after != 0x1111_2222_3333_4444 || seen_p2 != 0x5555_6666_7777_8888 {
        return Err("F7: writes in p1 and p2 did not stay isolated");
    }
    if !fw_ok {
        return Err("F7: firmware_enter/leave did not switch to System CR3 and back");
    }
    if s1.unmap_page(TEST_VA) != Some(f1) || s2.unmap_page(TEST_VA) != Some(f2) {
        return Err("F7: unmap_page did not return the mapped frame");
    }
    mm::free_frames(f1, 1);
    mm::free_frames(f2, 1);
    drop(p2);
    drop(p1);
    if mm::free_frame_count() != frames_before {
        return Err("F7: destroying process address spaces leaked frames");
    }
    if pool::usage().blocks - handle::storage().0 != pool_before {
        return Err("F7: destroying processes leaked pool blocks");
    }
    Ok(())
}

/// The System process is charged no quota: any amount is fine, giving
/// it back is too, and neither touches the process's quota block,
/// which it does not have.
pub fn quota_test() -> Result<(), &'static str> {
    let process = system();
    let pool = crate::mm::pool::usage().blocks;
    // SAFETY: the System process, here and below.
    let block = || unsafe { process.add(layout::QUOTA_BLOCK).cast::<usize>().read() };
    for amount in [0, 4096, usize::MAX] {
        // SAFETY: as above.
        unsafe {
            if PsChargeProcessPagedPoolQuota(process.cast(), amount) != STATUS_SUCCESS {
                return Err("the System process was refused quota");
            }
            PsReturnProcessPagedPoolQuota(process.cast(), amount);
        }
    }
    if block() != 0 || crate::mm::pool::usage().blocks != pool {
        return Err("charging the System process left something behind");
    }
    Ok(())
}

/// How many references `body` has, the caller's own included.
///
/// # Safety
/// `body` is an object the caller holds a reference to.
unsafe fn references(body: *mut u8) -> i64 {
    // SAFETY: per the contract.
    unsafe {
        object::reference(body);
        object::dereference(body)
    }
}

static TOKEN_WRONG: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// The primary token is handed out referenced and given back, by one
/// thread and by threads on every processor at once: the same token
/// each time, a token object, with no reference lost or left. Returns
/// the references taken.
pub fn token_test() -> Result<u32, &'static str> {
    const ROUNDS: u32 = 2000;
    fn body(expected: usize) {
        for _ in 0..ROUNDS {
            // SAFETY: the System process; the reference taken is the
            // one given up.
            unsafe {
                let token = PsReferencePrimaryToken(system().cast());
                if token.addr() != expected {
                    TOKEN_WRONG.fetch_add(1, Ordering::Relaxed);
                }
                PsDereferencePrimaryToken(token);
            }
        }
    }
    let process = system();
    // SAFETY: the System process and its token live for ever; every
    // reference this takes it gives up.
    unsafe {
        let field = process.add(layout::TOKEN).cast::<usize>().read();
        let token = PsReferencePrimaryToken(process.cast()).cast::<u8>();
        if token.is_null()
            || token.addr() != field & !layout::FAST_REF_COUNT_MASK
            || !core::ptr::eq(object::type_of(token), &raw const object::TOKEN_TYPE)
        {
            return Err("the primary token is not the token object the process holds");
        }
        let held = references(token);
        let again = PsReferencePrimaryToken(process.cast()).cast::<u8>();
        if again != token || references(token) != held + 1 {
            return Err("a second reference to the primary token was not counted");
        }
        PsDereferencePrimaryToken(again.cast());
        if references(token) != held {
            return Err("a reference to the primary token was not given back");
        }
        TOKEN_WRONG.store(0, Ordering::Relaxed);
        let threads_before = thread::count();
        let processors = crate::ke::smp::online_count();
        let threads = processors.max(2);
        for n in 0..threads {
            thread::create(
                body,
                token.addr(),
                thread::NORMAL_PRIORITY,
                1 << (n % processors),
            )?;
        }
        thread::settle(threads_before);
        let left = references(token);
        PsDereferencePrimaryToken(token.cast());
        if TOKEN_WRONG.load(Ordering::Relaxed) != 0 {
            return Err("a thread was handed another token");
        }
        if left != held {
            return Err("references taken on several processors were lost or left behind");
        }
        Ok(threads as u32 * ROUNDS + 2)
    }
}

/// [`PsIsDiskCountersEnabled`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psisdiskcountersenabled):
/// whether file systems are to count each process's disk I/O. Windows
/// turns the counters off only for the registry value
/// `Session Manager\kernel\DisableDiskCounters`, which NK does not
/// read: the counters are on, as on Windows without the value.
pub extern "C" fn PsIsDiskCountersEnabled() -> u8 {
    1
}

/// [`PsUpdateDiskCounters`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-psupdatediskcounters):
/// add a file system's disk I/O to the process's counters, where it has
/// them (`EPROCESS.DiskCounters`); a process without counters is left
/// alone, as on Windows.
///
/// # Safety
/// `process` is a process object.
pub unsafe extern "C" fn PsUpdateDiskCounters(
    process: *mut core::ffi::c_void,
    bytes_read: u64,
    bytes_written: u64,
    reads: u32,
    writes: u32,
    flushes: u32,
) {
    use core::sync::atomic::{AtomicU64, Ordering};
    // SAFETY: per the contract; the counters are five 64-bit words the
    // kernel owns, updated atomically as Windows does.
    unsafe {
        let counters = process
            .cast::<u8>()
            .add(nk_ntabi::process::DISK_COUNTERS)
            .cast::<*mut AtomicU64>()
            .read();
        if counters.is_null() {
            return;
        }
        for (at, value) in [
            bytes_read,
            bytes_written,
            u64::from(reads),
            u64::from(writes),
            u64::from(flushes),
        ]
        .into_iter()
        .enumerate()
        {
            if value != 0 {
                (*counters.add(at)).fetch_add(value, Ordering::Relaxed);
            }
        }
    }
}
