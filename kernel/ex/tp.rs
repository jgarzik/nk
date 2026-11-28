//! User-mode threadpool kernel primitives required by `ntdll.dll`:
//! - `WAIT_COMPLETION_PACKET_TYPE` (`Nt{Create,Associate,Cancel}WaitCompletionPacket`)
//! - `TIMER_TYPE` over `KTIMER2` (`Nt{Create,Set,Cancel}Timer2`)
//! - `WORKER_FACTORY_TYPE` (`NtCreateWorkerFactory`, `Nt{Query,Set}InformationWorkerFactory`,
//!   `NtReleaseWorkerFactoryWorker`, `NtWorkerFactoryWorkerReady`,
//!   `NtWaitForWorkViaWorkerFactory`, `NtShutdownWorkerFactory`)

#![allow(non_snake_case)]

use crate::io::completion::{self, FileIoCompletionInformation, IO_COMPLETION_MODIFY_STATE};
use crate::ke::object::{self as ke_obj, ObjectLock, WAIT_WCP};
use crate::ke::spinlock::{Rank, SpinLock};
use crate::ke::timer2;
use crate::ob::{
    handle,
    object::{self, ObRef},
};
use crate::svc::capture;
use core::ffi::c_void;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicPtr, AtomicU32, Ordering};
use nk_ntabi::ke::{
    DISPATCHER_HEADER, KTIMER2, KWAIT_BLOCK, WAIT_BLOCK_ACTIVE, WAIT_BLOCK_INACTIVE,
};
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::*;
use nk_ob::handles::Attributes;

const OBJ_INHERIT: u32 = 0x2;
const OBJ_KERNEL_HANDLE: u32 = 0x200;

/// `STATUS_ASSOCIATION_ALREADY_EXISTS` / `STATUS_INVALID_PARAMETER` when WCP already bound.
const STATUS_CANCELLED_WCP: NTSTATUS = 0xC000_0120u32 as NTSTATUS;

// ---- WaitCompletionPacket -------------------------------------------------

struct WcpPayload {
    associated: bool,
    iocp: Option<ObRef>,
    target: Option<ObRef>,
    key: usize,
    apc_context: usize,
    io_status: NTSTATUS,
    io_info: usize,
}

// SAFETY: `ObRef` points to kernel objects safe to transfer across threads.
unsafe impl Send for WcpPayload {}

/// Body of a `WAIT_COMPLETION_PACKET_TYPE` object.
#[repr(C)]
pub struct WaitCompletionPacket {
    wait_block: KWAIT_BLOCK,
    wake_link: AtomicPtr<u8>,
    state: SpinLock<WcpPayload>,
}

/// Chain `wcp` onto `Woken::wcps` under the target dispatcher object's `ObjectLock`.
///
/// # Safety
/// `wcp` is a live `WaitCompletionPacket` whose `wait_block` was just unlinked by `satisfy`.
pub unsafe fn set_wcp_wake_link(wcp: *mut u8, next: *mut u8) {
    // SAFETY: per the contract.
    unsafe {
        (*wcp.cast::<WaitCompletionPacket>())
            .wake_link
            .store(next, Ordering::Relaxed);
    }
}

/// Read and clear `wcp`'s intrusive `wake_link` inside `Woken::ready`.
///
/// # Safety
/// `wcp` is a live `WaitCompletionPacket` owned by `Woken`.
pub unsafe fn take_wcp_wake_link(wcp: *mut u8) -> *mut u8 {
    // SAFETY: per the contract.
    unsafe {
        (*wcp.cast::<WaitCompletionPacket>())
            .wake_link
            .swap(core::ptr::null_mut(), Ordering::Relaxed)
    }
}

/// Post a fired `WaitCompletionPacket` to its associated I/O completion port
/// and release the self-reference held while linked on its target object.
/// Called from `ke::object::Woken::ready` after releasing `ObjectLock`.
///
/// # Safety
/// `wcp_body` is a live `WaitCompletionPacket` whose `wait_block` was unlinked by `satisfy`.
pub unsafe fn fire_wcp(wcp_body: *mut u8) {
    let wcp = wcp_body.cast::<WaitCompletionPacket>();
    // SAFETY: per the contract.
    let to_post = unsafe {
        let mut guard = (*wcp).state.lock();
        if !guard.associated {
            None
        } else {
            guard.associated = false;
            let iocp = guard.iocp.take();
            let _target = guard.target.take();
            Some((
                iocp,
                guard.key,
                guard.apc_context,
                guard.io_status,
                guard.io_info,
            ))
        }
    };
    if let Some((Some(iocp), key, apc_context, status, info)) = to_post {
        // SAFETY: `iocp` is a live `IO_COMPLETION_TYPE` object; `completion::post` is DISPATCH-safe.
        let _ = unsafe { completion::post(iocp.body(), key, apc_context, status, info) };
    }
    // Release the self-reference taken when `wait_block` was linked.
    // SAFETY: matched with `object::reference(wcp_body)` in `NtAssociateWaitCompletionPacket`.
    unsafe { object::dereference(wcp_body) };
}

/// `WAIT_COMPLETION_PACKET_TYPE`'s delete procedure.
///
/// # Safety
/// `body` is a `WaitCompletionPacket` with zero remaining references.
pub unsafe extern "C" fn wcp_deleted(body: *mut c_void) {
    // SAFETY: per the contract; no active link can exist while refcount is 0.
    unsafe {
        core::ptr::drop_in_place(body.cast::<WaitCompletionPacket>());
    }
}

fn is_dispatcher_object(ty: &object::ObjectType) -> bool {
    [
        &raw const object::EVENT_TYPE,
        &raw const object::THREAD_TYPE,
        &raw const object::PROCESS_TYPE,
        &raw const object::TIMER_TYPE,
        &raw const object::MUTANT_TYPE,
        &raw const object::SEMAPHORE_TYPE,
    ]
    .iter()
    .any(|&known| core::ptr::eq(ty, known))
}

/// `NtCreateWaitCompletionPacket`: create a `WAIT_COMPLETION_PACKET_TYPE` object.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtCreateWaitCompletionPacket(
    wcp_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract.
    let oa = match unsafe { capture::capture_object_attributes(object_attributes, mode) } {
        Ok(oa) => oa,
        Err(st) => return st,
    };
    let attrs = oa.map_or(0, |a| a.attributes);
    let Some(body) = object::create(
        &object::WAIT_COMPLETION_PACKET_TYPE,
        size_of::<WaitCompletionPacket>(),
    ) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    let wcp = body.cast::<WaitCompletionPacket>();
    // SAFETY: `body` is fresh zeroed storage of `size_of::<WaitCompletionPacket>()`.
    unsafe {
        (&raw mut (*wcp).wait_block.BlockState).write(WAIT_BLOCK_INACTIVE);
        (&raw mut (*wcp).wake_link).write(AtomicPtr::new(core::ptr::null_mut()));
        (&raw mut (*wcp).state).write(SpinLock::new(
            Rank::WaitCompletion,
            WcpPayload {
                associated: false,
                iocp: None,
                target: None,
                key: 0,
                apc_context: 0,
                io_status: 0,
                io_info: 0,
            },
        ));
    }
    // SAFETY: `body` starts with 1 reference.
    let held = unsafe { ObRef::adopt(body) };
    let kernel_handle = !capture::is_user(mode) || (attrs & OBJ_KERNEL_HANDLE) != 0;
    // SAFETY: `held` keeps `body` alive.
    let h = match unsafe {
        handle::open_with(
            held.body(),
            desired_access,
            Attributes {
                inherit: (attrs & OBJ_INHERIT) != 0,
                protect_from_close: false,
            },
            kernel_handle,
        )
    } {
        Ok(h) => h,
        Err(st) => return st,
    };
    // SAFETY: per the contract.
    if let Err(st) = unsafe { capture::write(wcp_handle, h as *mut c_void, mode) } {
        let _ = handle::close_for(h, capture::handle_mode(mode));
        return st;
    }
    STATUS_SUCCESS
}

/// `NtAssociateWaitCompletionPacket`: associate a `WaitCompletionPacket` with
/// a target dispatcher object and an I/O completion port.
///
/// # Safety
/// `already_signaled` is null or satisfies `PreviousMode`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn NtAssociateWaitCompletionPacket(
    wcp_handle: *mut c_void,
    iocp_handle: *mut c_void,
    target_handle: *mut c_void,
    key_context: *mut c_void,
    apc_context: *mut c_void,
    io_status: NTSTATUS,
    io_status_information: usize,
    already_signaled: *mut u8,
) -> NTSTATUS {
    let mode = capture::mode();
    let hmode = capture::handle_mode(mode);
    let (wcp_ref, _) = match handle::reference_for(
        wcp_handle as u64,
        Some(&raw const object::WAIT_COMPLETION_PACKET_TYPE),
        1,
        hmode,
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    let (iocp_ref, _) = match handle::reference_for(
        iocp_handle as u64,
        Some(&raw const object::IO_COMPLETION_TYPE),
        IO_COMPLETION_MODIFY_STATE,
        hmode,
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    let (target_ref, _) =
        match handle::reference_for(target_handle as u64, None, 0x0010_0000, hmode) {
            Ok(found) => found,
            Err(st) => return st,
        };
    // SAFETY: `target_ref` is a live object.
    let target_ty = unsafe { object::type_of(target_ref.body()) };
    if !is_dispatcher_object(target_ty) {
        return STATUS_OBJECT_TYPE_MISMATCH;
    }

    let wcp = wcp_ref.body().cast::<WaitCompletionPacket>();
    let target_hdr = target_ref.body().cast::<DISPATCHER_HEADER>();
    let iocp_body = iocp_ref.body();

    // Populate WCP payload BEFORE linking under `ObjectLock` so if `satisfy` fires
    // immediately on another CPU, `fire_wcp` sees a complete payload.
    {
        // SAFETY: `wcp_ref` holds a live `WaitCompletionPacket`.
        let mut guard = unsafe { (*wcp).state.lock() };
        if guard.associated {
            return STATUS_INVALID_PARAMETER;
        }
        guard.associated = true;
        guard.iocp = Some(iocp_ref);
        guard.target = Some(target_ref);
        guard.key = key_context.addr();
        guard.apc_context = apc_context.addr();
        guard.io_status = io_status;
        guard.io_info = io_status_information;
    }

    // Check target signal state / link wait block under `ObjectLock` (no ranked lock held!).
    // SAFETY: `target_hdr` and `wcp` are live objects (`target` is held inside `wcp.state`).
    let signaled_now = unsafe {
        let _lock = ObjectLock::take(target_hdr);
        if ke_obj::signal(target_hdr).load(Ordering::Relaxed) > 0 {
            ke_obj::take(target_hdr, core::ptr::null_mut());
            true
        } else {
            let block = &raw mut (*wcp).wait_block;
            (&raw mut (*block).WaitType).write(WAIT_WCP);
            (&raw mut (*block).WaitKey).write(0);
            (&raw mut (*block).Thread).write(wcp_ref.body().cast());
            (&raw mut (*block).Object).write(target_hdr.cast());
            // Self-reference keeps `wcp` alive while linked on `target_hdr`.
            object::reference(wcp_ref.body());
            ke_obj::link(target_hdr, block);
            false
        }
    };

    if signaled_now {
        // Clear `associated` and retrieve `iocp_ref` to post immediately.
        // SAFETY: `wcp` is live.
        let iocp_owned = unsafe {
            let mut guard = (*wcp).state.lock();
            guard.associated = false;
            guard.target = None;
            guard.iocp.take()
        };
        if let Some(iocp_owned) = iocp_owned {
            // SAFETY: `iocp_owned` is live.
            let post_st = unsafe {
                completion::post(
                    iocp_owned.body(),
                    key_context.addr(),
                    apc_context.addr(),
                    io_status,
                    io_status_information,
                )
            };
            if post_st != STATUS_SUCCESS {
                return post_st;
            }
        }
        if !already_signaled.is_null() {
            // SAFETY: per the contract.
            if let Err(st) = unsafe { capture::write(already_signaled, 1u8, mode) } {
                return st;
            }
        }
        let _ = iocp_body;
        return STATUS_SUCCESS;
    }

    if !already_signaled.is_null() {
        // SAFETY: per the contract.
        if let Err(st) = unsafe { capture::write(already_signaled, 0u8, mode) } {
            return st;
        }
    }
    STATUS_SUCCESS
}

/// `NtCancelWaitCompletionPacket`: cancel an active association.
pub extern "C" fn NtCancelWaitCompletionPacket(
    wcp_handle: *mut c_void,
    _remove_signaled_packet: u8,
) -> NTSTATUS {
    let mode = capture::handle_mode(capture::mode());
    let (wcp_ref, _) = match handle::reference_for(
        wcp_handle as u64,
        Some(&raw const object::WAIT_COMPLETION_PACKET_TYPE),
        1,
        mode,
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    let wcp = wcp_ref.body().cast::<WaitCompletionPacket>();
    // Peek target without clearing `associated` yet so we can take `ObjectLock` outside `state`.
    let target_body: Option<*mut u8> = {
        // SAFETY: `wcp` is live.
        let guard = unsafe { (*wcp).state.lock() };
        if !guard.associated {
            return STATUS_CANCELLED_WCP;
        }
        guard.target.as_ref().map(|t| {
            // SAFETY: `t` is live while `guard` holds it; take a local ref.
            unsafe { object::reference(t.body()) };
            t.body()
        })
    };
    let Some(target_ptr) = target_body else {
        return STATUS_PENDING;
    };
    // SAFETY: reference taken above.
    let target_ref = unsafe { ObRef::adopt(target_ptr) };
    let target_hdr = target_ref.body().cast::<DISPATCHER_HEADER>();
    // Try unlinking under `ObjectLock`.
    // SAFETY: `target_hdr` and `wcp` are live.
    let unlinked = unsafe {
        let _lock = ObjectLock::take(target_hdr);
        let block = &raw mut (*wcp).wait_block;
        if (&raw const (*block).BlockState).read() == WAIT_BLOCK_ACTIVE {
            ke_obj::unlink(block);
            true
        } else {
            false
        }
    };
    if unlinked {
        // SAFETY: `wcp` is live; clear association and release self-reference from link.
        unsafe {
            let mut guard = (*wcp).state.lock();
            guard.associated = false;
            guard.iocp = None;
            guard.target = None;
            drop(guard);
            object::dereference(wcp_ref.body());
        }
        STATUS_SUCCESS
    } else {
        STATUS_PENDING
    }
}

// ---- Timer2 (`TIMER_TYPE`) ------------------------------------------------

/// Body of a `TIMER_TYPE` object: starts with `KTIMER2` -> `KTIMER` -> `DISPATCHER_HEADER`.
#[repr(C)]
pub struct UserTimer2 {
    timer: KTIMER2,
}

/// `TIMER_TYPE`'s delete procedure: cancel the underlying `KTIMER2`.
///
/// # Safety
/// `body` is a `UserTimer2` with zero remaining references.
pub unsafe extern "C" fn timer2_deleted(body: *mut c_void) {
    // SAFETY: per the contract.
    unsafe {
        timer2::KeCancelTimer2(body.cast::<KTIMER2>(), core::ptr::null_mut());
    }
}

/// `NtCreateTimer2`: create a user-mode `TIMER_TYPE` object backed by `KTIMER2`.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtCreateTimer2(
    timer_handle: *mut *mut c_void,
    _reserved1: *mut c_void,
    object_attributes: *const OBJECT_ATTRIBUTES,
    attributes: u32,
    desired_access: u32,
) -> NTSTATUS {
    let mode = capture::mode();
    // SAFETY: per the contract.
    let oa = match unsafe { capture::capture_object_attributes(object_attributes, mode) } {
        Ok(oa) => oa,
        Err(st) => return st,
    };
    let oa_attrs = oa.map_or(0, |a| a.attributes);
    let Some(body) = object::create(&object::TIMER_TYPE, size_of::<UserTimer2>()) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: `body` is fresh zeroed storage for `KTIMER2`.
    unsafe {
        timer2::KeInitializeTimer2(
            body.cast::<KTIMER2>(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            attributes,
        );
    }
    // SAFETY: `body` starts with 1 reference.
    let held = unsafe { ObRef::adopt(body) };
    let kernel_handle = !capture::is_user(mode) || (oa_attrs & OBJ_KERNEL_HANDLE) != 0;
    // SAFETY: `held` keeps `body` alive.
    let h = match unsafe {
        handle::open_with(
            held.body(),
            desired_access,
            Attributes {
                inherit: (oa_attrs & OBJ_INHERIT) != 0,
                protect_from_close: false,
            },
            kernel_handle,
        )
    } {
        Ok(h) => h,
        Err(st) => return st,
    };
    // SAFETY: per the contract.
    if let Err(st) = unsafe { capture::write(timer_handle, h as *mut c_void, mode) } {
        let _ = handle::close_for(h, capture::handle_mode(mode));
        return st;
    }
    STATUS_SUCCESS
}

/// `NtSetTimer2`: arm a `TIMER_TYPE` object with `due_time` and `period`.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtSetTimer2(
    timer_handle: *mut c_void,
    due_time: *const i64,
    period: *const i64,
    _parameters: *const c_void,
) -> NTSTATUS {
    const TIMER_MODIFY_STATE: u32 = 0x2;
    let mode = capture::mode();
    // SAFETY: per the contract.
    let due = match unsafe { capture::read(due_time, mode) } {
        Ok(v) => v,
        Err(st) => return st,
    };
    let per = if period.is_null() {
        0
    } else {
        // SAFETY: per the contract.
        match unsafe { capture::read(period, mode) } {
            Ok(v) => v,
            Err(st) => return st,
        }
    };
    let (held, _) = match handle::reference_for(
        timer_handle as u64,
        Some(&raw const object::TIMER_TYPE),
        TIMER_MODIFY_STATE,
        capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `held` keeps the `KTIMER2` alive.
    unsafe {
        timer2::KeSetTimer2(
            held.body().cast::<KTIMER2>(),
            due,
            per,
            core::ptr::null_mut(),
        );
    }
    STATUS_SUCCESS
}

/// `NtCancelTimer2`: cancel a `TIMER_TYPE` object.
///
/// # Safety
/// `parameters` is null or satisfies `PreviousMode`.
pub unsafe extern "C" fn NtCancelTimer2(
    timer_handle: *mut c_void,
    _parameters: *mut c_void,
) -> NTSTATUS {
    const TIMER_MODIFY_STATE: u32 = 0x2;
    let mode = capture::handle_mode(capture::mode());
    let (held, _) = match handle::reference_for(
        timer_handle as u64,
        Some(&raw const object::TIMER_TYPE),
        TIMER_MODIFY_STATE,
        mode,
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `held` keeps the `KTIMER2` alive.
    unsafe {
        timer2::KeCancelTimer2(held.body().cast::<KTIMER2>(), core::ptr::null_mut());
    }
    STATUS_SUCCESS
}

// ---- WorkerFactory (`WORKER_FACTORY_TYPE`) --------------------------------

/// Body of a `WORKER_FACTORY_TYPE` object.
pub struct WorkerFactory {
    iocp: ObRef,
    process: ObRef,
    start_routine: u64,
    start_param: u64,
    stack_reserve: u64,
    stack_commit: u64,
    timeout: AtomicI64,
    min_threads: AtomicU32,
    max_threads: AtomicU32,
    total_workers: AtomicU32,
    ready_workers: AtomicU32,
    pending_workers: AtomicU32,
    binding_count: AtomicU32,
    shutdown: AtomicBool,
    paused: AtomicBool,
}

/// `WORKER_FACTORY_TYPE`'s delete procedure.
///
/// # Safety
/// `body` is a `WorkerFactory` with zero remaining references.
pub unsafe extern "C" fn wf_deleted(body: *mut c_void) {
    // SAFETY: per the contract.
    unsafe {
        core::ptr::drop_in_place(body.cast::<WorkerFactory>());
    }
}

/// Ensure at least `target` worker threads have been spawned for `wf`.
fn ensure_workers(wf: &WorkerFactory, target: u32) {
    let limit = wf.max_threads.load(Ordering::Acquire).max(1);
    let desired = target.min(limit);
    while wf.total_workers.load(Ordering::Acquire) < desired {
        if wf.shutdown.load(Ordering::Acquire) {
            break;
        }
        let prev = wf.total_workers.fetch_add(1, Ordering::AcqRel);
        if prev >= desired {
            wf.total_workers.fetch_sub(1, Ordering::AcqRel);
            break;
        }
        // SAFETY: `wf.process` is a live user `EPROCESS`.
        let spawned = unsafe {
            crate::ps::user::create_thread(
                wf.process.body(),
                wf.start_routine,
                wf.start_param,
                wf.stack_reserve,
                wf.stack_commit,
                false,
                false,
            )
        };
        if spawned.is_err() {
            wf.total_workers.fetch_sub(1, Ordering::AcqRel);
            break;
        }
    }
}

/// `NtCreateWorkerFactory`: create a `WORKER_FACTORY_TYPE` object bound to an
/// I/O completion port and target user process.
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn NtCreateWorkerFactory(
    wf_handle: *mut *mut c_void,
    desired_access: u32,
    object_attributes: *const OBJECT_ATTRIBUTES,
    iocp_handle: *mut c_void,
    process_handle: *mut c_void,
    start_routine: *mut c_void,
    start_param: *mut c_void,
    max_thread_count: u32,
    stack_reserve: usize,
    stack_commit: usize,
) -> NTSTATUS {
    let mode = capture::mode();
    let hmode = capture::handle_mode(mode);
    // SAFETY: per the contract.
    let oa = match unsafe { capture::capture_object_attributes(object_attributes, mode) } {
        Ok(oa) => oa,
        Err(st) => return st,
    };
    let (iocp, _) = match handle::reference_for(
        iocp_handle as u64,
        Some(&raw const object::IO_COMPLETION_TYPE),
        IO_COMPLETION_MODIFY_STATE,
        hmode,
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    let (process, _) = match handle::reference_for(
        process_handle as u64,
        Some(&raw const object::PROCESS_TYPE),
        nk_ntabi::user::PROCESS_CREATE_THREAD,
        hmode,
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    let Some(body) = object::create(&object::WORKER_FACTORY_TYPE, size_of::<WorkerFactory>())
    else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    // SAFETY: `body` is fresh storage of `size_of::<WorkerFactory>()`.
    unsafe {
        body.cast::<WorkerFactory>().write(WorkerFactory {
            iocp,
            process,
            start_routine: start_routine.addr() as u64,
            start_param: start_param.addr() as u64,
            stack_reserve: stack_reserve as u64,
            stack_commit: stack_commit as u64,
            timeout: AtomicI64::new(-300_000_000), // 30s default idle timeout
            min_threads: AtomicU32::new(0),
            max_threads: AtomicU32::new(if max_thread_count == 0 {
                64
            } else {
                max_thread_count
            }),
            total_workers: AtomicU32::new(0),
            ready_workers: AtomicU32::new(0),
            pending_workers: AtomicU32::new(0),
            binding_count: AtomicU32::new(0),
            shutdown: AtomicBool::new(false),
            paused: AtomicBool::new(false),
        });
    }
    // SAFETY: `body` starts with 1 reference.
    let held = unsafe { ObRef::adopt(body) };
    let attrs = oa.map_or(0, |a| a.attributes);
    let kernel_handle = !capture::is_user(mode) || (attrs & OBJ_KERNEL_HANDLE) != 0;
    // SAFETY: `held` keeps `body` alive.
    let h = match unsafe {
        handle::open_with(
            held.body(),
            desired_access,
            Attributes {
                inherit: (attrs & OBJ_INHERIT) != 0,
                protect_from_close: false,
            },
            kernel_handle,
        )
    } {
        Ok(h) => h,
        Err(st) => return st,
    };
    // SAFETY: per the contract.
    if let Err(st) = unsafe { capture::write(wf_handle, h as *mut c_void, mode) } {
        let _ = handle::close_for(h, hmode);
        return st;
    }
    STATUS_SUCCESS
}

/// `WORKER_FACTORY_BASIC_INFORMATION` (120 bytes on x64 Windows 10).
#[repr(C)]
#[derive(Clone, Copy)]
struct WorkerFactoryBasicInformation {
    timeout: i64,
    retry_timeout: i64,
    idle_timeout: i64,
    paused: u8,
    timer_set: u8,
    queued_to_ex_worker: u8,
    may_create: u8,
    create_in_progress: u8,
    inserted_into_queue: u8,
    shutdown: u8,
    _pad0: u8,
    binding_count: u32,
    thread_minimum: u32,
    thread_maximum: u32,
    pending_worker_count: u32,
    waiting_worker_count: u32,
    total_worker_count: u32,
    release_count: u32,
    infinite_wait_goal: i64,
    start_routine: *mut c_void,
    start_parameter: *mut c_void,
    process_id: *mut c_void,
    stack_reserve: usize,
    stack_commit: usize,
    last_thread_creation_status: NTSTATUS,
    _pad1: u32,
}

/// `NtQueryInformationWorkerFactory`: supports `WorkerFactoryBasicInformation` (7).
///
/// # Safety
/// Output buffer and `return_length` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtQueryInformationWorkerFactory(
    wf_handle: *mut c_void,
    class: u32,
    information: *mut u8,
    length: u32,
    return_length: *mut u32,
) -> NTSTATUS {
    const WORKER_FACTORY_BASIC_INFORMATION: u32 = 7;
    let mode = capture::mode();
    let (held, _) = match handle::reference_for(
        wf_handle as u64,
        Some(&raw const object::WORKER_FACTORY_TYPE),
        0x0008,
        capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    if class != WORKER_FACTORY_BASIC_INFORMATION {
        return STATUS_INVALID_INFO_CLASS;
    }
    let needed = size_of::<WorkerFactoryBasicInformation>() as u32;
    if !return_length.is_null() {
        // SAFETY: per the contract.
        if let Err(st) = unsafe { capture::write(return_length, needed, mode) } {
            return st;
        }
    }
    if length < needed {
        return STATUS_INFO_LENGTH_MISMATCH;
    }
    // SAFETY: `held` is a live `WorkerFactory`.
    let wf = unsafe { &*held.body().cast::<WorkerFactory>() };
    // SAFETY: `wf.process` is a live `EPROCESS`.
    let pid = unsafe { crate::ps::process::PsGetProcessId(wf.process.body().cast()) };
    let info = WorkerFactoryBasicInformation {
        timeout: wf.timeout.load(Ordering::Acquire),
        retry_timeout: 0,
        idle_timeout: wf.timeout.load(Ordering::Acquire),
        paused: u8::from(wf.paused.load(Ordering::Acquire)),
        timer_set: 0,
        queued_to_ex_worker: 0,
        may_create: 1,
        create_in_progress: 0,
        inserted_into_queue: 0,
        shutdown: u8::from(wf.shutdown.load(Ordering::Acquire)),
        _pad0: 0,
        binding_count: wf.binding_count.load(Ordering::Acquire),
        thread_minimum: wf.min_threads.load(Ordering::Acquire),
        thread_maximum: wf.max_threads.load(Ordering::Acquire),
        pending_worker_count: wf.pending_workers.load(Ordering::Acquire),
        waiting_worker_count: wf.ready_workers.load(Ordering::Acquire),
        total_worker_count: wf.total_workers.load(Ordering::Acquire),
        release_count: 0,
        infinite_wait_goal: 0,
        start_routine: core::ptr::with_exposed_provenance_mut(wf.start_routine as usize),
        start_parameter: core::ptr::with_exposed_provenance_mut(wf.start_param as usize),
        process_id: pid,
        stack_reserve: wf.stack_reserve as usize,
        stack_commit: wf.stack_commit as usize,
        last_thread_creation_status: STATUS_SUCCESS,
        _pad1: 0,
    };
    // SAFETY: `WorkerFactoryBasicInformation` is plain `#[repr(C)]` data.
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&raw const info).cast::<u8>(),
            size_of::<WorkerFactoryBasicInformation>(),
        )
    };
    // SAFETY: per the contract.
    match unsafe { capture::copy_to_caller(information, bytes, mode) } {
        Ok(()) => STATUS_SUCCESS,
        Err(st) => st,
    }
}

/// `NtSetInformationWorkerFactory`: configure worker factory parameters.
///
/// # Safety
/// `information` must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtSetInformationWorkerFactory(
    wf_handle: *mut c_void,
    class: u32,
    information: *const c_void,
    length: u32,
) -> NTSTATUS {
    const WF_TIMEOUT: u32 = 2;
    const WF_THREAD_MINIMUM: u32 = 4;
    const WF_THREAD_MAXIMUM: u32 = 5;
    const WF_PAUSED: u32 = 6;
    const WF_BINDING_COUNT: u32 = 11;
    let mode = capture::mode();
    let (held, _) = match handle::reference_for(
        wf_handle as u64,
        Some(&raw const object::WORKER_FACTORY_TYPE),
        0x0002,
        capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `held` is a live `WorkerFactory`.
    let wf = unsafe { &*held.body().cast::<WorkerFactory>() };
    match class {
        WF_TIMEOUT if length >= 8 => {
            // SAFETY: per the contract.
            let v = match unsafe { capture::read(information.cast::<i64>(), mode) } {
                Ok(v) => v,
                Err(st) => return st,
            };
            wf.timeout.store(v, Ordering::Release);
            STATUS_SUCCESS
        }
        WF_THREAD_MINIMUM if length >= 4 => {
            // SAFETY: per the contract.
            let v = match unsafe { capture::read(information.cast::<u32>(), mode) } {
                Ok(v) => v,
                Err(st) => return st,
            };
            wf.min_threads.store(v, Ordering::Release);
            ensure_workers(wf, v);
            STATUS_SUCCESS
        }
        WF_THREAD_MAXIMUM if length >= 4 => {
            // SAFETY: per the contract.
            let v = match unsafe { capture::read(information.cast::<u32>(), mode) } {
                Ok(v) => v,
                Err(st) => return st,
            };
            wf.max_threads.store(v, Ordering::Release);
            STATUS_SUCCESS
        }
        WF_PAUSED if length >= 1 => {
            // SAFETY: per the contract.
            let v = match unsafe { capture::read(information.cast::<u8>(), mode) } {
                Ok(v) => v,
                Err(st) => return st,
            };
            wf.paused.store(v != 0, Ordering::Release);
            STATUS_SUCCESS
        }
        WF_BINDING_COUNT if length >= 4 => {
            // SAFETY: per the contract.
            let v = match unsafe { capture::read(information.cast::<u32>(), mode) } {
                Ok(v) => v,
                Err(st) => return st,
            };
            wf.binding_count.store(v, Ordering::Release);
            STATUS_SUCCESS
        }
        _ => STATUS_SUCCESS,
    }
}

/// `NtReleaseWorkerFactoryWorker`: ensure a worker thread is available for work.
pub extern "C" fn NtReleaseWorkerFactoryWorker(wf_handle: *mut c_void) -> NTSTATUS {
    let mode = capture::handle_mode(capture::mode());
    let (held, _) = match handle::reference_for(
        wf_handle as u64,
        Some(&raw const object::WORKER_FACTORY_TYPE),
        0x0001,
        mode,
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `held` is a live `WorkerFactory`.
    let wf = unsafe { &*held.body().cast::<WorkerFactory>() };
    if wf.ready_workers.load(Ordering::Acquire) == 0 {
        let cur = wf.total_workers.load(Ordering::Acquire);
        ensure_workers(wf, cur.saturating_add(1));
    }
    STATUS_SUCCESS
}

/// `NtWorkerFactoryWorkerReady`: called by a newly spawned worker thread before waiting.
pub extern "C" fn NtWorkerFactoryWorkerReady(wf_handle: *mut c_void) -> NTSTATUS {
    let mode = capture::handle_mode(capture::mode());
    let (held, _) = match handle::reference_for(
        wf_handle as u64,
        Some(&raw const object::WORKER_FACTORY_TYPE),
        0x0004,
        mode,
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `held` is a live `WorkerFactory`.
    let wf = unsafe { &*held.body().cast::<WorkerFactory>() };
    wf.ready_workers.fetch_add(1, Ordering::AcqRel);
    STATUS_SUCCESS
}

/// `NtWaitForWorkViaWorkerFactory`: block a worker thread until packets arrive
/// on the worker factory's I/O completion port (or shutdown/timeout).
///
/// # Safety
/// Pointer parameters must satisfy `PreviousMode`.
pub unsafe extern "C" fn NtWaitForWorkViaWorkerFactory(
    wf_handle: *mut c_void,
    mini_packets: *mut FileIoCompletionInformation,
    count: u32,
    packets_returned: *mut u32,
    _deferred_work: *const c_void,
) -> NTSTATUS {
    let mode = capture::mode();
    if count == 0 {
        return STATUS_INVALID_PARAMETER;
    }
    let (held, _) = match handle::reference_for(
        wf_handle as u64,
        Some(&raw const object::WORKER_FACTORY_TYPE),
        0x0004,
        capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `held` is a live `WorkerFactory`.
    let wf = unsafe { &*held.body().cast::<WorkerFactory>() };
    if wf.shutdown.load(Ordering::Acquire) {
        return STATUS_SHUTDOWN_IN_PROGRESS;
    }
    let capped = (count as usize).min(64);
    let mut entries = alloc::vec![
        FileIoCompletionInformation {
            key_context: core::ptr::null_mut(),
            apc_context: core::ptr::null_mut(),
            io_status_block: nk_ntabi::io::IO_STATUS_BLOCK {
                Status: 0,
                Information: 0,
            },
        };
        capped
    ];
    let timeout = wf.timeout.load(Ordering::Acquire);
    let timeout_opt = (timeout != 0).then_some(timeout);
    // SAFETY: `wf.iocp` is a live `IO_COMPLETION_TYPE` object.
    match unsafe { completion::remove_ex(wf.iocp.body(), &mut entries, timeout_opt, true, mode) } {
        Ok(n) => {
            let bytes_len = n * size_of::<FileIoCompletionInformation>();
            // SAFETY: `entries[..n]` is initialized.
            let src =
                unsafe { core::slice::from_raw_parts(entries.as_ptr().cast::<u8>(), bytes_len) };
            // SAFETY: per the contract.
            unsafe {
                if let Err(st) = capture::copy_to_caller(mini_packets.cast::<u8>(), src, mode) {
                    return st;
                }
                if let Err(st) = capture::write(packets_returned, n as u32, mode) {
                    return st;
                }
            }
            STATUS_SUCCESS
        }
        Err(st) => st,
    }
}

/// `NtShutdownWorkerFactory`: mark the worker factory shut down and wake any waiting workers.
///
/// # Safety
/// `pending_worker_count` is null or satisfies `PreviousMode`.
pub unsafe extern "C" fn NtShutdownWorkerFactory(
    wf_handle: *mut c_void,
    pending_worker_count: *mut u32,
) -> NTSTATUS {
    let mode = capture::mode();
    let (held, _) = match handle::reference_for(
        wf_handle as u64,
        Some(&raw const object::WORKER_FACTORY_TYPE),
        0x0010,
        capture::handle_mode(mode),
    ) {
        Ok(found) => found,
        Err(st) => return st,
    };
    // SAFETY: `held` is a live `WorkerFactory`.
    let wf = unsafe { &*held.body().cast::<WorkerFactory>() };
    wf.shutdown.store(true, Ordering::Release);
    if !pending_worker_count.is_null() {
        // SAFETY: per the contract.
        if let Err(st) = unsafe { capture::write(pending_worker_count, 0u32, mode) } {
            return st;
        }
    }
    STATUS_SUCCESS
}
