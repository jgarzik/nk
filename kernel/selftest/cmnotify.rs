//! Watching a registry key for changes, through `ZwNotifyChangeKey`.

use crate::cm::{self, notify};
use crate::ke::wait;
use crate::mm::pool;
use crate::ob::handle;
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::ffi::c_void;
use core::sync::atomic::{AtomicU32, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::ex::WORK_QUEUE_ITEM;
use nk_ntabi::io::{IO_STATUS_BLOCK, UNICODE_STRING};
use nk_ntabi::ke::KEVENT;
use nk_ntabi::ob::OBJECT_ATTRIBUTES;
use nk_ntabi::status::{
    NTSTATUS, STATUS_INVALID_PARAMETER, STATUS_NOTIFY_CLEANUP, STATUS_NOTIFY_ENUM_DIR,
    STATUS_PENDING, STATUS_SUCCESS,
};

pub static GROUP: Group = Group {
    names: &["cm.notify"],
    run,
    manual: false,
};

const WATCHED: &str = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\NkWatched";
const TAG: u32 = u32::from_le_bytes(*b"NkCn");
/// `REG_NOTIFY_CHANGE_NAME`, `REG_NOTIFY_CHANGE_LAST_SET`.
const NAME: u32 = 1;
const LAST_SET: u32 = 4;
/// `DelayedWorkQueue`.
const DELAYED: usize = 1;

/// How many times the watcher's work item has run.
static RUNS: AtomicU32 = AtomicU32::new(0);

/// The watcher's work routine: count, and set the event it is given.
///
/// # Safety
/// `event` points to an initialised event.
unsafe extern "C" fn told(event: *mut c_void) {
    RUNS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the test passes its event.
    unsafe { wait::KeSetEvent(event.cast(), 0, 0) };
}

/// Open or create the key `path`, relative to `root` unless that is
/// null.
fn key(path: &str, root: *mut c_void) -> Result<*mut c_void, &'static str> {
    let text: Vec<u16> = path.encode_utf16().collect();
    let name = UNICODE_STRING {
        Length: (text.len() * 2) as u16,
        MaximumLength: (text.len() * 2) as u16,
        Buffer: text.as_ptr().cast_mut(),
    };
    let attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: root,
        ObjectName: &raw const name,
        Attributes: 0x240,
        SecurityDescriptor: core::ptr::null_mut(),
        SecurityQualityOfService: core::ptr::null_mut(),
    };
    let mut made = core::ptr::null_mut();
    // SAFETY: locals that outlive the call.
    let status = unsafe {
        cm::ZwCreateKey(
            &raw mut made,
            0xF003F,
            &raw const attributes,
            0,
            core::ptr::null(),
            0,
            core::ptr::null_mut(),
        )
    };
    if status == STATUS_SUCCESS {
        Ok(made)
    } else {
        Err("a key could not be made")
    }
}

/// Set the value `Watched` of `key`.
fn set(key: *mut c_void, data: u32) -> bool {
    let text: Vec<u16> = "Watched".encode_utf16().collect();
    let name = UNICODE_STRING {
        Length: (text.len() * 2) as u16,
        MaximumLength: (text.len() * 2) as u16,
        Buffer: text.as_ptr().cast_mut(),
    };
    // SAFETY: locals that outlive the call.
    let status =
        unsafe { cm::ZwSetValueKey(key, &raw const name, 0, 4, (&raw const data).cast(), 4) };
    status == STATUS_SUCCESS
}

/// What one watcher is told through: a work item, the event its
/// routine sets, and a status block.
struct Watcher {
    item: *mut WORK_QUEUE_ITEM,
    event: *mut KEVENT,
    status: *mut IO_STATUS_BLOCK,
}

impl Watcher {
    fn new() -> Option<Self> {
        let item = pool::alloc_zeroed(size_of::<WORK_QUEUE_ITEM>(), TAG).cast::<WORK_QUEUE_ITEM>();
        let event = pool::alloc_zeroed(size_of::<KEVENT>(), TAG).cast::<KEVENT>();
        let status = pool::alloc_zeroed(size_of::<IO_STATUS_BLOCK>(), TAG).cast();
        let watcher = Self {
            item,
            event,
            status,
        };
        (!item.is_null() && !event.is_null() && !watcher.status.is_null()).then_some(watcher)
    }

    /// Watch `key` for `filter`, with its subtree or not: the status.
    fn watch(&self, key: *mut c_void, filter: u32, subtree: bool) -> NTSTATUS {
        // SAFETY: the watcher's own blocks, which live until it is
        // dropped, after it was told or its watch ended.
        unsafe {
            wait::KeInitializeEvent(self.event, 0, 0);
            self.item.write(WORK_QUEUE_ITEM {
                List: core::mem::zeroed(),
                WorkerRoutine: Some(told),
                Parameter: self.event.cast(),
            });
            self.status.write(IO_STATUS_BLOCK {
                Status: 0x7777,
                Information: 0x7777,
            });
            notify::ZwNotifyChangeKey(
                key,
                core::ptr::null_mut(),
                self.item.cast(),
                core::ptr::without_provenance_mut(DELAYED),
                self.status,
                filter,
                u8::from(subtree),
                core::ptr::null_mut(),
                0,
                1,
            )
        }
    }

    /// Wait to be told: the status the block was given, or none if
    /// five seconds pass.
    fn told(&self) -> Option<NTSTATUS> {
        let five_seconds = -50_000_000i64;
        // SAFETY: the watcher's event; the block is written before the
        // work item that sets the event is queued.
        unsafe {
            let waited =
                wait::KeWaitForSingleObject(self.event.cast(), 0, 0, 0, &raw const five_seconds);
            (waited == 0).then(|| (*self.status).Status)
        }
    }
}

impl Drop for Watcher {
    fn drop(&mut self) {
        for block in [
            self.item.cast::<u8>(),
            self.event.cast(),
            self.status.cast(),
        ] {
            if !block.is_null() {
                let _ = pool::free(block);
            }
        }
    }
}

fn watching(key: *mut c_void, sub: *mut c_void) -> Result<(), &'static str> {
    let watcher = Watcher::new().ok_or("no memory for a watcher")?;
    let before = notify::watches();
    RUNS.store(0, Ordering::Relaxed);

    if watcher.watch(key, 0, false) != STATUS_INVALID_PARAMETER
        || watcher.watch(key, 0x100, false) != STATUS_INVALID_PARAMETER
        || notify::watches() != before
    {
        return Err("a watch for no change, or an unknown one, was not refused");
    }

    // A watch on the key alone: a change below it does not meet it, a
    // change to it does, once.
    if watcher.watch(key, LAST_SET, false) != STATUS_PENDING {
        return Err("a watch was not made");
    }
    if !set(sub, 1) || notify::watches() != before + 1 {
        return Err("a change below a key met a watch that does not take in its subtree");
    }
    if !set(key, 2) || watcher.told() != Some(STATUS_NOTIFY_ENUM_DIR) {
        return Err("a watcher was not told of a change to its key");
    }
    if !set(key, 3) || notify::watches() != before || RUNS.load(Ordering::Relaxed) != 1 {
        return Err("a watcher was told twice");
    }

    // With its subtree, a change below meets it.
    if watcher.watch(key, LAST_SET, true) != STATUS_PENDING
        || !set(sub, 4)
        || watcher.told() != Some(STATUS_NOTIFY_ENUM_DIR)
    {
        return Err("a watcher of a subtree was not told of a change below its key");
    }

    // A subkey made is a change of name; a value set is not.
    if watcher.watch(key, NAME, false) != STATUS_PENDING
        || !set(key, 5)
        || notify::watches() != before + 1
    {
        return Err("a watcher of names was told of a value");
    }
    let made = key_under(key, "Made")?;
    if watcher.told() != Some(STATUS_NOTIFY_ENUM_DIR) {
        return Err("a watcher of names was not told of a new subkey");
    }
    // Deleting it is a change of name too.
    if watcher.watch(key, NAME, false) != STATUS_PENDING
        || cm::ZwDeleteKey(made) != STATUS_SUCCESS
        || watcher.told() != Some(STATUS_NOTIFY_ENUM_DIR)
    {
        return Err("a watcher of names was not told of a deleted subkey");
    }
    handle::close(made as u64);

    // Closing the handle a watch was made through ends it.
    let other = key_under(core::ptr::null_mut(), WATCHED)?;
    if watcher.watch(other, LAST_SET, false) != STATUS_PENDING {
        return Err("a watch was not made through a second handle");
    }
    handle::close(other as u64);
    if watcher.told() != Some(STATUS_NOTIFY_CLEANUP) || notify::watches() != before {
        return Err("closing a handle did not end its watch with STATUS_NOTIFY_CLEANUP");
    }
    if RUNS.load(Ordering::Relaxed) != 5 {
        return Err("the watcher's work item did not run once for each telling");
    }
    Ok(())
}

fn key_under(parent: *mut c_void, name: &str) -> Result<*mut c_void, &'static str> {
    key(name, parent)
}

fn notify_test() -> Result<(), &'static str> {
    let watched = key(WATCHED, core::ptr::null_mut())?;
    let sub = key_under(watched, "Below");
    let result = match sub {
        Ok(sub) => {
            let result = watching(watched, sub);
            cm::ZwDeleteKey(sub);
            handle::close(sub as u64);
            result
        }
        Err(why) => Err(why),
    };
    cm::ZwDeleteKey(watched);
    handle::close(watched as u64);
    result
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("cm.notify", notify_test);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
