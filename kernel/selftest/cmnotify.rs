//! Watching a registry key for changes, through `ZwNotifyChangeKey`,
//! and the routines that reach a key by `RelativeTo` and path, whose
//! writes a watcher is told of.

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
    NTSTATUS, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER, STATUS_NOTIFY_CLEANUP,
    STATUS_NOTIFY_ENUM_DIR, STATUS_OBJECT_NAME_NOT_FOUND, STATUS_PENDING, STATUS_SUCCESS,
};

pub static GROUP: Group = Group {
    names: &["cm.notify", "cm.rtl-keys", "cm.volatile-keys"],
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

/// `RtlCheckRegistryKey`, `RtlCreateRegistryKey`,
/// `RtlWriteRegistryValue` and `RtlDeleteRegistryValue`: the key by
/// each kind of `RelativeTo`, made when it is to be, and a watcher
/// told of what is written.
fn rtl_keys() -> Result<(), &'static str> {
    use nk_ntabi::cm::{
        RTL_REGISTRY_ABSOLUTE, RTL_REGISTRY_HANDLE, RTL_REGISTRY_OPTIONAL, RTL_REGISTRY_SERVICES,
    };
    const HELPER: &str = "Machine\\System\\CurrentControlSet\\Services\\NkRtlKeys";
    let z = |text: &str| -> Vec<u16> { text.encode_utf16().chain([0]).collect() };
    let (path, full) = (
        z("NkRtlKeys"),
        z("\\Registry\\Machine\\System\\CurrentControlSet\\Services\\NkRtlKeys"),
    );
    // The callers below pass terminated strings in locals that outlive
    // the call, or a handle where `relative_to` says so.
    let check = |relative_to: u32, path: *const u16| {
        // SAFETY: as said above.
        unsafe { cm::RtlCheckRegistryKey(relative_to, path) }
    };
    let create = |relative_to: u32, path: &[u16]| {
        // SAFETY: as said above.
        unsafe { cm::RtlCreateRegistryKey(relative_to, path.as_ptr()) }
    };
    let write = |relative_to: u32, path: *const u16, name: &str, kind: u32, data: u32| {
        let name = z(name);
        // SAFETY: as said above; the name and the value are locals.
        unsafe {
            cm::RtlWriteRegistryValue(
                relative_to,
                path,
                name.as_ptr(),
                kind,
                (&raw const data).cast(),
                4,
            )
        }
    };
    let delete = |relative_to: u32, path: *const u16, name: &str| {
        let name = z(name);
        // SAFETY: as said above; the name is a local.
        unsafe { cm::RtlDeleteRegistryValue(relative_to, path, name.as_ptr()) }
    };
    let value = |key: &str, name: &str| cm::read(key, name).ok();
    let dword = |data: u32| Some((4, data.to_le_bytes().to_vec()));
    let no_handle = core::ptr::without_provenance::<u16>(0x7FFC);

    if check(RTL_REGISTRY_SERVICES, path.as_ptr()) != STATUS_OBJECT_NAME_NOT_FOUND
        || check(RTL_REGISTRY_ABSOLUTE, full.as_ptr()) != STATUS_OBJECT_NAME_NOT_FOUND
        || check(7, path.as_ptr()) != STATUS_INVALID_PARAMETER
        || create(7, &path) != STATUS_INVALID_PARAMETER
    {
        return Err("a key that is not there, or a key of no known kind, was found");
    }
    let verdict = (|| {
        // Made under a key that exists, and not under one that does not.
        if create(RTL_REGISTRY_SERVICES, &z("NkRtlKeys\\Sub\\Deeper"))
            != STATUS_OBJECT_NAME_NOT_FOUND
            || create(RTL_REGISTRY_SERVICES | RTL_REGISTRY_OPTIONAL, &path) != STATUS_SUCCESS
            || create(RTL_REGISTRY_ABSOLUTE, &full) != STATUS_SUCCESS
            || check(RTL_REGISTRY_SERVICES, path.as_ptr()) != STATUS_SUCCESS
            || check(
                RTL_REGISTRY_ABSOLUTE,
                z("\\REGISTRY\\machine\\system\\currentcontrolset\\services\\nkrtlkeys").as_ptr(),
            ) != STATUS_SUCCESS
            || cm::exists("Machine\\System\\CurrentControlSet\\Services\\NkRtlKeys\\Sub")
        {
            return Err("a key was not made where its parent is, and only there");
        }
        // A value written is a value set: stored, without the type's
        // high byte, and whoever watches the key is told.
        let watched = key(
            &alloc::string::String::from_utf16_lossy(&full[..full.len() - 1]),
            core::ptr::null_mut(),
        )?;
        let watcher = Watcher::new().ok_or("no memory for a watcher")?;
        let told = (|| {
            if watcher.watch(watched, LAST_SET, false) != STATUS_PENDING {
                return Err("a watch was not made");
            }
            if write(
                RTL_REGISTRY_SERVICES,
                path.as_ptr(),
                "Count",
                0x0100_0004,
                7,
            ) != STATUS_SUCCESS
                || watcher.told() != Some(STATUS_NOTIFY_ENUM_DIR)
                || value(HELPER, "Count") != dword(7)
            {
                return Err("a value written was not stored, or the key's watcher not told");
            }
            // By handle: the caller's key, used as it is.
            if write(RTL_REGISTRY_HANDLE, watched.cast(), "ByHandle", 4, 8) != STATUS_SUCCESS
                || value(HELPER, "ByHandle") != dword(8)
                || write(RTL_REGISTRY_HANDLE, no_handle, "ByHandle", 4, 9) != STATUS_INVALID_HANDLE
                || delete(RTL_REGISTRY_HANDLE, no_handle, "ByHandle") != STATUS_INVALID_HANDLE
                || check(RTL_REGISTRY_HANDLE, no_handle) != STATUS_SUCCESS
                || create(RTL_REGISTRY_HANDLE, &[0x7FFC]) != STATUS_SUCCESS
            {
                return Err("a key given by handle was not written through it, or was looked at");
            }
            if watcher.watch(watched, LAST_SET, false) != STATUS_PENDING
                || delete(RTL_REGISTRY_SERVICES, path.as_ptr(), "Count") != STATUS_SUCCESS
                || watcher.told() != Some(STATUS_NOTIFY_ENUM_DIR)
                || value(HELPER, "Count").is_some()
                || delete(RTL_REGISTRY_SERVICES, path.as_ptr(), "Count")
                    != STATUS_OBJECT_NAME_NOT_FOUND
                || delete(RTL_REGISTRY_HANDLE, watched.cast(), "ByHandle") != STATUS_SUCCESS
            {
                return Err("a value was not deleted, or the key's watcher not told");
            }
            // Writing and deleting make the key, as Windows' do.
            let (made, emptied) = (z("NkRtlKeys\\Made"), z("NkRtlKeys\\Emptied"));
            if write(RTL_REGISTRY_SERVICES, made.as_ptr(), "", 4, 1) != STATUS_SUCCESS
                || value(
                    "Machine\\System\\CurrentControlSet\\Services\\NkRtlKeys\\Made",
                    "",
                ) != dword(1)
                || delete(RTL_REGISTRY_SERVICES, emptied.as_ptr(), "None")
                    != STATUS_OBJECT_NAME_NOT_FOUND
                || !cm::exists("Machine\\System\\CurrentControlSet\\Services\\NkRtlKeys\\Emptied")
            {
                return Err("writing or deleting a value did not make its key");
            }
            Ok(())
        })();
        handle::close(watched as u64);
        told
    })();
    let _ = cm::delete_tree(HELPER);
    verdict
}

/// The volatile keys a storage port driver makes for its adapter, as
/// storport makes them: `Hardware\DeviceMap\Scsi\Scsi Port 0` and
/// below, one level at a time with `REG_OPTION_VOLATILE`, each made
/// once and then opened, with values of several types.
fn volatile_keys() -> Result<(), &'static str> {
    const REG_OPTION_VOLATILE: u32 = 1;
    let make = |path: &str, root: *mut c_void| -> Result<(*mut c_void, u32), &'static str> {
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
        let (mut made, mut disposition) = (core::ptr::null_mut(), 0u32);
        // SAFETY: locals that outlive the call.
        let status = unsafe {
            cm::ZwCreateKey(
                &raw mut made,
                0xF003F,
                &raw const attributes,
                0,
                core::ptr::null(),
                REG_OPTION_VOLATILE,
                &raw mut disposition,
            )
        };
        if status == STATUS_SUCCESS {
            Ok((made, disposition))
        } else {
            Err("a volatile key could not be made")
        }
    };
    let none = core::ptr::null_mut();
    let (scsi, _) = make("\\Registry\\Machine\\Hardware\\DeviceMap\\Scsi", none)?;
    let verdict = (|| {
        let (port, first) = make("Scsi Port 0", scsi)?;
        let (again, second) = make("Scsi Port 0", scsi)?;
        handle::close(again as u64);
        let bus = make("Scsi Bus 0", port);
        let initiator = bus.and_then(|(bus, _)| {
            let made = make("Initiator Id 7", bus);
            handle::close(bus as u64);
            made
        });
        let stored = set(port, 11);
        handle::close(port as u64);
        let (initiator, _) = initiator?;
        handle::close(initiator as u64);
        // REG_CREATED_NEW_KEY, then REG_OPENED_EXISTING_KEY.
        if (first, second) != (1, 2) {
            return Err("a volatile key was not made once and opened after");
        }
        const PORT: &str = "Machine\\Hardware\\DeviceMap\\Scsi\\Scsi Port 0";
        if !stored
            || cm::read(PORT, "Watched").ok() != Some((4, 11u32.to_le_bytes().to_vec()))
            || !cm::exists(
                "Machine\\Hardware\\DeviceMap\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Initiator Id 7",
            )
        {
            return Err("a volatile key does not hold its values and subkeys");
        }
        Ok(())
    })();
    handle::close(scsi as u64);
    let _ = cm::delete_tree("Machine\\Hardware\\DeviceMap\\Scsi");
    verdict
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("cm.volatile-keys", volatile_keys);
    r.check("cm.notify", notify_test);
    r.check("cm.rtl-keys", rtl_keys);
}

/// This file's test groups, in the order they run.
pub static GROUPS: &[&Group] = &[&GROUP];
