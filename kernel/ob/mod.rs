//! The object namespace: the directories every Windows system has, and
//! in them the named objects and the symbolic links.
//!
//! The tree and its rules for paths are `nk_ob::tree`, tested on the
//! host; here are the lock around it, the objects and the references.
//! Names compare case-insensitively, whatever the caller asks: Windows
//! does the same unless it is configured otherwise.
//!
//! An entry does not keep its object alive, except a symbolic link's
//! and a directory's, which nothing else holds. Whoever names an
//! object takes the name away again ([`remove`]) before giving up the
//! reference it made the object with, so under the namespace's lock a
//! name leads to a live object.
//!
//! A directory is permanent or temporary, as on Windows. A temporary
//! one loses its name when its last handle closes; a permanent one
//! keeps it until it is made temporary ([`make_temporary`]). The boot
//! directories are permanent. What is in a directory holds a reference
//! to it, so a directory that lost its name lives on, reachable by
//! handle alone, until it is empty.

pub mod directory;
pub mod event;
pub mod handle;
pub mod object;
pub mod security;

use crate::ke::{Rank, SpinLock};
use alloc::vec::Vec;
use nk_ntabi::io::UNICODE_STRING;
use nk_ntabi::ob::{OBJECT_DIRECTORY_SIZE, OBJECT_SYMBOLIC_LINK};
use nk_ntabi::status::*;
use nk_ob::tree::{DirId, Error, Found, Options, Removed, Tree};
use object::ObRef;

/// An object as the namespace holds it.
#[derive(Clone, Copy, PartialEq)]
struct Entry(*mut u8);

// SAFETY: the pointer is an identity here, and is used only under the
// namespace's lock or with a reference taken there.
unsafe impl Send for Entry {}

struct Namespace {
    tree: Tree<Entry>,
    /// The root directory's object.
    root: Entry,
    /// Every other directory's object.
    directories: Vec<(DirId, Entry)>,
}

static NAMESPACE: SpinLock<Namespace> = SpinLock::new(
    Rank::Namespace,
    Namespace {
        tree: Tree::new(),
        root: Entry(core::ptr::null_mut()),
        directories: Vec::new(),
    },
);

/// How every path is read: any case, links followed.
const OPTIONS: Options = Options::new(true);
/// The same, stopping at a symbolic link the path ends on.
const THE_LINK: Options = Options {
    open_link: true,
    ..OPTIONS
};

/// The directories in the root, as on Windows.
const DIRECTORIES: [&str; 7] = [
    "Device",
    "Driver",
    "FileSystem",
    "GLOBAL??",
    "BaseNamedObjects",
    "KernelObjects",
    "Callback",
];

fn status(error: Error) -> NTSTATUS {
    match error {
        Error::PathSyntaxBad => STATUS_OBJECT_PATH_SYNTAX_BAD,
        Error::NameInvalid => STATUS_OBJECT_NAME_INVALID,
        Error::PathNotFound => STATUS_OBJECT_PATH_NOT_FOUND,
        Error::NameNotFound | Error::TooManyLinks => STATUS_OBJECT_NAME_NOT_FOUND,
        Error::Collision => STATUS_OBJECT_NAME_COLLISION,
        Error::TypeMismatch => STATUS_OBJECT_TYPE_MISMATCH,
        Error::NotEmpty => STATUS_DIRECTORY_NOT_EMPTY,
        Error::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}

/// The name an object called `path` has in its directory: what follows
/// the last backslash.
pub fn leaf(path: &[u16]) -> &[u16] {
    let start = path
        .iter()
        .rposition(|&c| c == u16::from(b'\\'))
        .map_or(0, |i| i + 1);
    &path[start..]
}

/// The object of directory `dir`.
fn directory(ns: &Namespace, dir: DirId) -> *mut u8 {
    if dir == DirId::ROOT {
        return ns.root.0;
    }
    ns.directories
        .iter()
        .find(|(id, _)| *id == dir)
        .map_or(core::ptr::null_mut(), |(_, object)| object.0)
}

/// The directory the object `object` is, if it is one of the tree's.
fn dir_of(ns: &Namespace, object: *mut u8) -> Option<DirId> {
    if object == ns.root.0 {
        return Some(DirId::ROOT);
    }
    ns.directories
        .iter()
        .find(|(_, directory)| directory.0 == object)
        .map(|(id, _)| *id)
}

/// Record that the object `body` is directory `dir`. The table holds
/// what it needs and no more, so that a directory made and removed
/// leaves the memory in use as it was. `false` without memory.
fn record(ns: &mut Namespace, dir: DirId, body: *mut u8) -> bool {
    if ns.directories.try_reserve_exact(1).is_err() {
        return false;
    }
    ns.directories.push((dir, Entry(body)));
    true
}

/// Make the root directory, the directories in it, and `\DosDevices`,
/// a link to `\??` (which is `\GLOBAL??`: there is one session).
pub fn init() -> Result<(), &'static str> {
    const NO_MEMORY: &str = "no memory for the object namespace";
    let root = object::create(&object::DIRECTORY_TYPE, OBJECT_DIRECTORY_SIZE).ok_or(NO_MEMORY)?;
    // SAFETY: the object just made.
    unsafe { object::set_permanent(root, true) };
    NAMESPACE.lock().root = Entry(root);
    for name in DIRECTORIES {
        let name = wide(name);
        let path: Vec<u16> = core::iter::once(u16::from(b'\\'))
            .chain(name.iter().copied())
            .collect();
        let body = object::create_named(&object::DIRECTORY_TYPE, OBJECT_DIRECTORY_SIZE, &name)
            .ok_or(NO_MEMORY)?;
        let mut ns = NAMESPACE.lock();
        let dir = ns
            .tree
            .create_directory(None, &path, OPTIONS)
            .map_err(|_| NO_MEMORY)?;
        if !record(&mut ns, dir, body) {
            return Err(NO_MEMORY);
        }
        // SAFETY: a named object made above; the root holds its name,
        // and the name the reference the object was made with.
        unsafe {
            object::set_permanent(body, true);
            object::entered(body, root);
        }
    }
    match insert_link(&wide("\\DosDevices"), &wide("\\??")) {
        STATUS_SUCCESS => Ok(()),
        _ => Err(NO_MEMORY),
    }
}

/// Give `body` the name `path`. Fails if the path is malformed, leads
/// through something that is not there, or is taken.
///
/// # Safety
/// `body` is an object from `object::create_named`, made with the last
/// component of `path` as its name. The caller holds a reference to it
/// and calls [`remove`] before giving that reference up.
pub unsafe fn insert(path: &[u16], body: *mut u8) -> NTSTATUS {
    let mut ns = NAMESPACE.lock();
    match ns.tree.insert_object(None, path, OPTIONS, Entry(body)) {
        Ok(dir) => {
            // SAFETY: per the contract, a named object.
            unsafe { object::entered(body, directory(&ns, dir)) };
            STATUS_SUCCESS
        }
        Err(error) => status(error),
    }
}

/// Take every name of `body` out of the namespace. Links that led to
/// them stay, and lead nowhere.
///
/// # Safety
/// `body` is an object the caller holds a reference to.
pub unsafe fn remove(body: *mut u8) {
    let directory = {
        let mut ns = NAMESPACE.lock();
        if ns.tree.remove_object(&Entry(body)) == 0 {
            return;
        }
        // SAFETY: only an object from `create_named` is given a name.
        unsafe { object::left(body) }
    };
    // SAFETY: the reference the object held on its directory, given
    // up with the lock released.
    unsafe { object::dereference(directory) };
}

/// A symbolic-link object called `name` that leads to `target`: the
/// body Windows gives one, then the target's characters.
fn new_link(name: &[u16], target: &[u16]) -> Option<*mut u8> {
    let bytes = u16::try_from(target.len() * 2).ok()?;
    let size = size_of::<OBJECT_SYMBOLIC_LINK>() + usize::from(bytes);
    let body = object::create_named(&object::SYMBOLIC_LINK_TYPE, size, name)?;
    // SAFETY: a fresh, zeroed object of that size, 16-byte aligned.
    unsafe {
        let link = body.cast::<OBJECT_SYMBOLIC_LINK>();
        let characters = link.add(1).cast::<u16>();
        characters.copy_from_nonoverlapping(target.as_ptr(), target.len());
        (&raw mut (*link).CreationTime).write(crate::ke::time::system_time() as i64);
        (&raw mut (*link).LinkTarget).write(UNICODE_STRING {
            Length: bytes,
            MaximumLength: bytes,
            Buffer: characters,
        });
    }
    Some(body)
}

/// Make the symbolic link `path`, which leads to `target`. The target
/// is not looked at until the link is followed.
pub fn insert_link(path: &[u16], target: &[u16]) -> NTSTATUS {
    let Some(link) = new_link(leaf(path), target) else {
        return STATUS_INSUFFICIENT_RESOURCES;
    };
    let inserted = {
        let mut ns = NAMESPACE.lock();
        let inserted = ns
            .tree
            .insert_link(None, path, OPTIONS, target, Entry(link));
        if let Ok(dir) = inserted {
            // SAFETY: a named object made above.
            unsafe { object::entered(link, directory(&ns, dir)) };
        }
        inserted
    };
    match inserted {
        Ok(_) => STATUS_SUCCESS,
        Err(error) => {
            // SAFETY: the link never got its name: this is its only
            // reference.
            unsafe { object::dereference(link) };
            status(error)
        }
    }
}

/// Remove the symbolic link called `path`. Anything else of that name
/// stays, and the caller is told it is no link.
pub fn remove_link(path: &[u16]) -> NTSTATUS {
    let (link, directory) = {
        let mut ns = NAMESPACE.lock();
        match ns.tree.lookup(None, path, THE_LINK) {
            Ok(outcome) if matches!(outcome.found, Found::SymbolicLink(..)) => {}
            Ok(_) => return STATUS_OBJECT_TYPE_MISMATCH,
            Err(error) => return status(error),
        }
        match ns.tree.remove(None, path, OPTIONS) {
            Ok(Removed::SymbolicLink(_, Entry(link))) => {
                // SAFETY: a link object, still held by the reference
                // its entry had.
                (link, unsafe { object::left(link) })
            }
            Ok(_) => return STATUS_OBJECT_TYPE_MISMATCH,
            Err(error) => return status(error),
        }
    };
    // SAFETY: the reference the entry held and the one the link held
    // on its directory, given up outside the lock.
    unsafe {
        object::dereference(link);
        object::dereference(directory);
    }
    STATUS_SUCCESS
}

/// What `path` leads to, following symbolic links: the object, with a
/// reference for the caller, and what
/// is left of the path if it goes on below the object, starting with
/// its backslash. The rest is the business of the object's type: the
/// lock is dropped before anything is done with it.
///
/// The path is absolute, or relative to the directory object `start`
/// (the `RootDirectory` of `OBJECT_ATTRIBUTES`).
pub fn lookup(start: Option<*mut u8>, path: &[u16]) -> Result<(ObRef, Vec<u16>), NTSTATUS> {
    let ns = NAMESPACE.lock();
    let start = match start {
        None => None,
        Some(object) => Some(dir_of(&ns, object).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?),
    };
    let outcome = ns.tree.lookup(start, path, OPTIONS).map_err(status)?;
    let body = match outcome.found {
        Found::Object(object) | Found::SymbolicLink(_, object) => object.0,
        Found::Directory(dir) => directory(&ns, dir),
    };
    // SAFETY: an object loses its names, under this lock, before it
    // gives up the reference it was made with; so one that still has a
    // name is alive. A directory's name holds a reference to it, and
    // the directory a look-up starts at is the caller's to hold.
    Ok((unsafe { ObRef::new(body) }, outcome.remainder))
}

/// Make a directory object: called `path` (absolute, or relative to
/// the directory object `start`), or without a name if `path` is
/// empty. `permanent` is `OBJ_PERMANENT`. If the name is taken the
/// creation fails, unless `open_if` (`OBJ_OPENIF`) and a directory
/// has it: that directory is then the result. Returns the directory
/// with a reference for the caller, and whether it existed already.
pub fn create_directory(
    start: Option<*mut u8>,
    path: &[u16],
    permanent: bool,
    open_if: bool,
) -> Result<(*mut u8, bool), NTSTATUS> {
    let body = if path.is_empty() {
        object::create(&object::DIRECTORY_TYPE, OBJECT_DIRECTORY_SIZE)
    } else {
        object::create_named(&object::DIRECTORY_TYPE, OBJECT_DIRECTORY_SIZE, leaf(path))
    }
    .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    let made = (|| {
        let mut ns = NAMESPACE.lock();
        if path.is_empty() {
            let dir = ns.tree.new_directory().map_err(status)?;
            if !record(&mut ns, dir, body) {
                let _ = ns.tree.release(dir);
                return Err(STATUS_INSUFFICIENT_RESOURCES);
            }
            // SAFETY: the object made above.
            unsafe { object::set_permanent(body, permanent) };
            return Ok((body, false));
        }
        let start = match start {
            None => None,
            Some(object) => Some(dir_of(&ns, object).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?),
        };
        match ns.tree.create_directory(start, path, OPTIONS) {
            Ok(dir) => {
                if !record(&mut ns, dir, body) {
                    ns.tree.detach(dir);
                    let _ = ns.tree.release(dir);
                    return Err(STATUS_INSUFFICIENT_RESOURCES);
                }
                let parent = ns
                    .tree
                    .parent(dir)
                    .map_or(core::ptr::null_mut(), |parent| directory(&ns, parent));
                // SAFETY: the object made above, named now: the name
                // holds a reference to it, and it one to the directory
                // it is in.
                unsafe {
                    object::set_permanent(body, permanent);
                    object::reference(body);
                    object::entered(body, parent);
                }
                Ok((body, false))
            }
            Err(Error::Collision) if open_if => {
                let outcome = ns.tree.lookup(start, path, OPTIONS).map_err(status)?;
                match outcome.found {
                    Found::Directory(dir) if outcome.remainder.is_empty() => {
                        let existing = directory(&ns, dir);
                        // SAFETY: a directory that has a name, or is
                        // the root, is alive under this lock.
                        unsafe { object::reference(existing) };
                        Ok((existing, true))
                    }
                    _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
                }
            }
            Err(error) => Err(status(error)),
        }
    })();
    match made {
        Ok((made, false)) => Ok((made, false)),
        other => {
            // SAFETY: the new object was not used: its only reference,
            // given up with the lock released.
            unsafe { object::dereference(body) };
            other
        }
    }
}

/// Make an event object (`event_type` 0 for notification, 1 for
/// synchronization, initial signal state `initial_state`): called
/// `path` (absolute, or relative to the directory object `start`), or
/// without a name if `path` is empty. `permanent` is `OBJ_PERMANENT`.
/// If the name is taken the creation fails, unless `open_if`
/// (`OBJ_OPENIF`) and an event has it: that event is then the result.
/// Returns the event with a reference for the caller, and whether it
/// existed already.
pub fn create_event(
    start: Option<*mut u8>,
    path: &[u16],
    permanent: bool,
    open_if: bool,
    event_type: u32,
    initial_state: u8,
) -> Result<(*mut u8, bool), NTSTATUS> {
    let body = if path.is_empty() {
        object::create(&object::EVENT_TYPE, size_of::<KEVENT>())
    } else {
        object::create_named(&object::EVENT_TYPE, size_of::<KEVENT>(), leaf(path))
    }
    .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
    // SAFETY: fresh storage of an event's size, initialised before
    // anything else can see it.
    unsafe { crate::ke::wait::KeInitializeEvent(body.cast(), event_type, initial_state) };
    if path.is_empty() {
        return Ok((body, false));
    }
    let made = (|| {
        let mut ns = NAMESPACE.lock();
        let start = match start {
            None => None,
            Some(object) => Some(dir_of(&ns, object).ok_or(STATUS_OBJECT_TYPE_MISMATCH)?),
        };
        match ns.tree.insert_object(start, path, OPTIONS, Entry(body)) {
            Ok(dir) => {
                let parent = directory(&ns, dir);
                // SAFETY: the object made above, named now: the name
                // holds a reference to it, and it one to the directory
                // it is in.
                unsafe {
                    object::set_permanent(body, permanent);
                    object::reference(body);
                    object::entered(body, parent);
                }
                Ok((body, false))
            }
            Err(Error::Collision) if open_if => {
                let outcome = ns.tree.lookup(start, path, OPTIONS).map_err(status)?;
                match outcome.found {
                    Found::Object(&Entry(existing)) if outcome.remainder.is_empty() => {
                        // SAFETY: an object in the namespace is live under
                        // this lock.
                        let is_event = unsafe {
                            core::ptr::eq(object::type_of(existing), &raw const object::EVENT_TYPE)
                        };
                        if is_event {
                            // SAFETY: as above.
                            unsafe { object::reference(existing) };
                            Ok((existing, true))
                        } else {
                            Err(STATUS_OBJECT_TYPE_MISMATCH)
                        }
                    }
                    _ => Err(STATUS_OBJECT_TYPE_MISMATCH),
                }
            }
            Err(error) => Err(status(error)),
        }
    })();
    match made {
        Ok((made, false)) => Ok((made, false)),
        other => {
            // SAFETY: the new object was not used: its only reference,
            // given up with the lock released.
            unsafe { object::dereference(body) };
            other
        }
    }
}

/// A temporary directory with no handle open loses its name: no path
/// leads to it any more, and the name's reference goes. What is in it
/// stays in it.
///
/// # Safety
/// `body` is a directory object the caller holds a reference to.
unsafe fn delete_name_check(body: *mut u8) {
    let parent = {
        let mut ns = NAMESPACE.lock();
        // SAFETY: per the contract.
        let keeps = unsafe {
            object::permanent(body)
                || object::handle_count(body).load(core::sync::atomic::Ordering::Acquire) != 0
        };
        if keeps {
            return;
        }
        let Some(dir) = dir_of(&ns, body) else {
            return;
        };
        if !ns.tree.detach(dir) {
            // It has no name: never had one, or lost it already.
            return;
        }
        // SAFETY: a directory that had a name was made with one.
        unsafe { object::left(body) }
    };
    // SAFETY: the reference the directory held on the one it was in,
    // and the name's on the directory, with the lock released; the
    // caller's own keeps `body` meanwhile.
    unsafe {
        object::dereference(parent);
        object::dereference(body);
    }
}

/// A temporary named non-directory object (such as an event) with no
/// handle open loses its name: no path leads to it any more, and the
/// name's reference goes.
///
/// # Safety
/// `body` is a named object made through the namespace (whose name
/// holds a reference to it), and the caller holds a reference to it.
unsafe fn delete_object_name_check(body: *mut u8) {
    let parent = {
        let mut ns = NAMESPACE.lock();
        // SAFETY: per the contract.
        let keeps = unsafe {
            object::permanent(body)
                || object::handle_count(body).load(core::sync::atomic::Ordering::Acquire) != 0
        };
        if keeps {
            return;
        }
        if ns.tree.remove_object(&Entry(body)) == 0 {
            // It has no name: never had one, or lost it already.
            return;
        }
        // SAFETY: an object that had a name was made with one.
        unsafe { object::left(body) }
    };
    // SAFETY: the reference the object held on the directory it was in,
    // and the name's on the object, with the lock released; the
    // caller's own keeps `body` meanwhile.
    unsafe {
        object::dereference(parent);
        object::dereference(body);
    }
}

/// What `ObMakeTemporaryObject` does to a directory or a named event:
/// it is no longer permanent, and loses its name now if no handle is
/// open to it, or else when the last one closes.
///
/// # Safety
/// `body` is a directory or event object the caller holds a reference
/// to.
pub unsafe fn make_temporary(body: *mut u8) {
    {
        let _ns = NAMESPACE.lock();
        // SAFETY: per the contract; the flag is the namespace's.
        unsafe { object::set_permanent(body, false) };
    }
    // SAFETY: per the contract.
    unsafe {
        if core::ptr::eq(object::type_of(body), &raw const object::DIRECTORY_TYPE) {
            delete_name_check(body);
        } else {
            delete_object_name_check(body);
        }
    }
}

/// The event type's close procedure: a handle to an event has been
/// closed. When it was the last, a temporary named event loses its
/// name.
///
/// # Safety
/// `object` is an event object the caller holds a reference to.
pub unsafe extern "C" fn event_handle_closed(
    _process: *mut core::ffi::c_void,
    object: *mut core::ffi::c_void,
    _process_handle_count: usize,
    system_handle_count: usize,
) {
    if system_handle_count == 1 {
        // SAFETY: per the contract.
        unsafe { delete_object_name_check(object.cast()) };
    }
}

/// The directory type's close procedure: a handle to a directory has
/// been closed. When it was the last, a temporary directory loses its
/// name.
///
/// # Safety
/// `object` is a directory object the caller holds a reference to.
pub unsafe extern "C" fn directory_handle_closed(
    _process: *mut core::ffi::c_void,
    object: *mut core::ffi::c_void,
    _process_handle_count: usize,
    system_handle_count: usize,
) {
    if system_handle_count == 1 {
        // SAFETY: per the contract.
        unsafe { delete_name_check(object.cast()) };
    }
}

/// The directory type's delete procedure: the last reference to a
/// directory has gone, so it has no name (which held one) and nothing
/// in it (each entry held one). The tree forgets it.
///
/// # Safety
/// `object` is a directory object nothing refers to any more.
pub unsafe extern "C" fn directory_deleted(object: *mut core::ffi::c_void) {
    let mut ns = NAMESPACE.lock();
    let Some(at) = ns
        .directories
        .iter()
        .position(|(_, directory)| directory.0 == object.cast())
    else {
        // It never became a directory of the tree.
        return;
    };
    let (dir, _) = ns.directories.swap_remove(at);
    ns.directories.shrink_to_fit();
    if ns.tree.release(dir).is_err() {
        crate::kd::bugcheck(format_args!(
            "a directory object was deleted while it had a name or entries"
        ));
    }
}

/// Number of entries in the namespace, the boot directories included
/// (for leak checks, which compare).
pub fn count() -> usize {
    NAMESPACE.lock().tree.counts().total()
}

// ---- tests --------------------------------------------------------------

use crate::mm::pool;
use nk_ntabi::ke::KEVENT;
use nk_ntabi::ob::{OB_INFOMASK_NAME, OBJECT_BODY, OBJECT_HEADER, OBJECT_HEADER_NAME_INFO};

/// An event object made to be called `path`.
fn named_event(path: &str) -> Result<*mut u8, &'static str> {
    object::create_named(&object::EVENT_TYPE, size_of::<KEVENT>(), leaf(&wide(path)))
        .ok_or("no memory")
}

/// What `path` leads to and the rest of the path, as text; the
/// look-up's reference is dropped at once, so the pointer is only an
/// identity.
fn find(path: &str) -> Result<(*mut u8, alloc::string::String), NTSTATUS> {
    let (body, rest) = lookup(None, &wide(path))?;
    Ok((body.body(), alloc::string::String::from_utf16_lossy(&rest)))
}

fn found(body: *mut u8, rest: &str) -> Result<(*mut u8, alloc::string::String), NTSTATUS> {
    Ok((body, rest.into()))
}

/// Paths: what is missing where, what is malformed, case, collisions
/// and the remainder below an object. Returns the look-ups made.
pub fn paths_test() -> Result<u32, &'static str> {
    const AT: &str = "\\BaseNamedObjects\\NkPaths";
    let before = (count(), pool::usage().blocks);
    let (first, second) = (named_event(AT)?, named_event(AT)?);
    // SAFETY: two live named objects this test holds references to
    // until the end, where it takes their names away first.
    let verdict = unsafe {
        (|| {
            let missing = [
                ("\\Device\\NkNone", STATUS_OBJECT_NAME_NOT_FOUND),
                ("\\BaseNamedObjects\\NkPaths", STATUS_OBJECT_NAME_NOT_FOUND),
                ("\\NkNoDirectory\\X", STATUS_OBJECT_PATH_NOT_FOUND),
                ("\\Device\\NkNone\\X", STATUS_OBJECT_PATH_NOT_FOUND),
                ("Device\\Null", STATUS_OBJECT_PATH_SYNTAX_BAD),
                ("", STATUS_OBJECT_PATH_SYNTAX_BAD),
                ("\\Device\\\\X", STATUS_OBJECT_NAME_INVALID),
                ("\\Device\\", STATUS_OBJECT_NAME_INVALID),
            ];
            for (path, expected) in missing {
                if find(path) != Err(expected) {
                    return Err("a path that leads nowhere did not fail with its own status");
                }
            }
            let (root, device) = (find("\\"), find("\\Device"));
            let is_directory = |found: &Result<(*mut u8, alloc::string::String), NTSTATUS>| {
                found.as_ref().is_ok_and(|(body, rest)| {
                    rest.is_empty()
                        && core::ptr::eq(object::type_of(*body), &raw const object::DIRECTORY_TYPE)
                })
            };
            if !is_directory(&root) || !is_directory(&device) || root == device {
                return Err("the root and \\Device are not two directory objects");
            }
            if find("\\DEVICE") != device || find("\\device") != device {
                return Err("a directory was not found whatever the case of its name");
            }

            if insert(&wide(AT), first) != STATUS_SUCCESS {
                return Err("an object could not be given a name");
            }
            let taken = [
                insert(&wide(AT), second),
                insert(&wide("\\BASENAMEDOBJECTS\\nkpaths"), second),
                insert_link(&wide(AT), &wide("\\Device")),
            ];
            if taken != [STATUS_OBJECT_NAME_COLLISION; 3] {
                return Err("a name that is taken was given out again");
            }
            let refused = [
                (
                    insert(&wide("\\NkNoDirectory\\X"), second),
                    STATUS_OBJECT_PATH_NOT_FOUND,
                ),
                (
                    insert(&wide("\\BaseNamedObjects\\NkPaths\\X"), second),
                    STATUS_OBJECT_TYPE_MISMATCH,
                ),
                (
                    insert(&wide("BaseNamedObjects\\X"), second),
                    STATUS_OBJECT_PATH_SYNTAX_BAD,
                ),
                (insert(&wide("\\"), second), STATUS_OBJECT_NAME_COLLISION),
            ];
            if refused.iter().any(|(status, expected)| status != expected) {
                return Err("a name that cannot be was not refused with its own status");
            }
            let leads = [
                (AT, ""),
                ("\\basenamedobjects\\NKPATHS", ""),
                ("\\BaseNamedObjects\\NkPaths\\", "\\"),
                ("\\BaseNamedObjects\\nkpaths\\Rest\\Of It", "\\Rest\\Of It"),
            ];
            for (path, rest) in leads {
                if find(path) != found(first, rest) {
                    return Err("a path did not lead to its object and the rest of the path");
                }
            }
            remove(first);
            if find(AT) != Err(STATUS_OBJECT_NAME_NOT_FOUND) {
                return Err("a name taken away still leads to its object");
            }
            Ok(missing.len() + leads.len() + 5)
        })()
    };
    // SAFETY: the creating references; neither object has a name now.
    unsafe {
        remove(first);
        object::dereference(first);
        object::dereference(second);
    }
    let looked = verdict?;
    if (count(), pool::usage().blocks) != before {
        return Err("names or memory were left behind");
    }
    Ok(looked as u32)
}

/// Symbolic links: followed in the middle of a path and at its end,
/// through the three names of the DOS-devices directory; rings and
/// links to nothing lead nowhere. Returns the look-ups made.
pub fn links_test() -> Result<u32, &'static str> {
    const TARGET: &str = "\\BaseNamedObjects\\NkTarget";
    let before = (count(), pool::usage().blocks);
    let target = named_event(TARGET)?;
    let link = |path: &str, to: &str| insert_link(&wide(path), &wide(to));
    let unlink = |path: &str| remove_link(&wide(path));
    // SAFETY: a live named object this test holds a reference to until
    // the end, where it takes the name away first.
    let verdict = unsafe {
        (|| {
            if insert(&wide(TARGET), target) != STATUS_SUCCESS {
                return Err("an object could not be given a name");
            }
            let made = [
                link("\\??\\NkLink", TARGET),
                link("\\DosDevices\\NkSecond", "\\??\\NkLink"),
                link("\\GLOBAL??\\NkDirectory", "\\BaseNamedObjects"),
                link("\\??\\NkRingA", "\\??\\NkRingB"),
                link("\\??\\NkRingB", "\\??\\NkRingA"),
                link("\\??\\NkNowhere", "\\Device\\NkNone"),
            ];
            if made != [STATUS_SUCCESS; 6] {
                return Err("a symbolic link could not be made");
            }
            if link("\\DosDevices\\nklink", "\\Device") != STATUS_OBJECT_NAME_COLLISION
                || link("\\GLOBAL??\\NKLINK", "\\Device") != STATUS_OBJECT_NAME_COLLISION
            {
                return Err("a link's name was given out again under another spelling");
            }
            let leads = [
                ("\\??\\NkLink", ""),
                ("\\DosDevices\\NKLINK", ""),
                ("\\GLOBAL??\\nklink", ""),
                ("\\??\\NkLink\\Below", "\\Below"),
                ("\\??\\NkSecond", ""),
                ("\\DosDevices\\NkSecond\\a\\b", "\\a\\b"),
                ("\\??\\NkDirectory\\NkTarget", ""),
                ("\\??\\NkDirectory\\nktarget\\", "\\"),
            ];
            for (path, rest) in leads {
                if find(path) != found(target, rest) {
                    return Err("a symbolic link did not lead to its target");
                }
            }
            let nowhere = [
                ("\\??\\NkRingA", STATUS_OBJECT_NAME_NOT_FOUND),
                ("\\??\\NkRingB\\x", STATUS_OBJECT_NAME_NOT_FOUND),
                ("\\??\\NkNowhere", STATUS_OBJECT_NAME_NOT_FOUND),
                ("\\??\\NkNowhere\\x", STATUS_OBJECT_PATH_NOT_FOUND),
                ("\\??\\NkNoLink", STATUS_OBJECT_NAME_NOT_FOUND),
            ];
            for (path, expected) in nowhere {
                if find(path) != Err(expected) {
                    return Err("a ring of links, or a link to nothing, led somewhere");
                }
            }
            // Only a link is removed as one.
            if unlink(TARGET) != STATUS_OBJECT_TYPE_MISMATCH
                || unlink("\\Device") != STATUS_OBJECT_TYPE_MISMATCH
                || unlink("\\??\\NkNoLink") != STATUS_OBJECT_NAME_NOT_FOUND
                || find(TARGET) != found(target, "")
            {
                return Err("something that is not a link was removed as one, or not refused");
            }
            // The link goes; what it led to stays.
            if unlink("\\DosDevices\\nklink") != STATUS_SUCCESS
                || unlink("\\??\\NkLink") != STATUS_OBJECT_NAME_NOT_FOUND
                || find("\\??\\NkLink") != Err(STATUS_OBJECT_NAME_NOT_FOUND)
                || find("\\??\\NkSecond") != Err(STATUS_OBJECT_NAME_NOT_FOUND)
                || find(TARGET) != found(target, "")
            {
                return Err("removing a link did not remove the link alone");
            }
            Ok(leads.len() + nowhere.len() + 5)
        })()
    };
    for path in [
        "\\??\\NkLink",
        "\\??\\NkSecond",
        "\\??\\NkDirectory",
        "\\??\\NkRingA",
        "\\??\\NkRingB",
        "\\??\\NkNowhere",
    ] {
        unlink(path);
    }
    // SAFETY: the creating reference, after the name is gone.
    unsafe {
        remove(target);
        object::dereference(target);
    }
    let looked = verdict?;
    if (count(), pool::usage().blocks) != before {
        return Err("names or memory were left behind");
    }
    Ok(looked as u32)
}

/// What a binary reading an object's header finds about its name.
///
/// # Safety
/// `body` is a live object.
unsafe fn read_name(body: *mut u8) -> Option<(*mut u8, alloc::string::String, i32)> {
    // SAFETY: per the contract; the arithmetic is Windows': the header
    // ends where the body begins, and name information ends where the
    // header begins.
    unsafe {
        let header = body.sub(OBJECT_BODY).cast::<OBJECT_HEADER>();
        if (*header).InfoMask & OB_INFOMASK_NAME == 0 {
            return None;
        }
        let info = header.cast::<OBJECT_HEADER_NAME_INFO>().sub(1);
        let name = (&raw const (*info).Name).read();
        let text = if name.Buffer.is_null() {
            alloc::string::String::new()
        } else {
            let characters = core::slice::from_raw_parts(name.Buffer, usize::from(name.Length) / 2);
            alloc::string::String::from_utf16_lossy(characters)
        };
        Some(((*info).Directory.cast(), text, (*info).ReferenceCount))
    }
}

/// A named object's header leads to its name and its directory, as on
/// Windows; an unnamed object's says it has neither; and both kinds
/// are freed whole.
pub fn name_info_test() -> Result<(), &'static str> {
    const AT: &str = "\\KernelObjects\\NkNamed";
    let before = (count(), pool::usage().blocks);
    let (root, directory) = (find("\\"), find("\\KernelObjects"));
    let (Ok((root, _)), Ok((directory, _))) = (root, directory) else {
        return Err("a boot directory is missing");
    };
    let named = named_event(AT)?;
    let Some(plain) = object::create(&object::EVENT_TYPE, size_of::<KEVENT>()) else {
        // SAFETY: the creating reference.
        unsafe { object::dereference(named) };
        return Err("no memory");
    };
    // SAFETY: live objects this test holds references to until the end.
    let verdict = unsafe {
        (|| {
            if pool::usage().blocks != before.1 + 2 {
                return Err("a named object is not one pool block");
            }
            if read_name(plain).is_some() {
                return Err("an object made without a name says it has name information");
            }
            if read_name(named) != Some((core::ptr::null_mut(), "NkNamed".into(), 1)) {
                return Err("a named object not yet in a directory does not say so");
            }
            if insert(&wide(AT), named) != STATUS_SUCCESS {
                return Err("an object could not be given a name");
            }
            if read_name(named) != Some((directory, "NkNamed".into(), 1)) {
                return Err("a named object's header does not lead to its directory and name");
            }
            if read_name(directory) != Some((root, "KernelObjects".into(), 1))
                || read_name(root).is_some()
            {
                return Err("a directory's header does not lead to the root");
            }
            if !core::ptr::eq(object::type_of(named), &raw const object::EVENT_TYPE) {
                return Err("a named object does not know its type");
            }
            remove(named);
            if read_name(named) != Some((core::ptr::null_mut(), "".into(), 1)) {
                return Err("an object that lost its name still says where it was");
            }
            Ok(())
        })()
    };
    // SAFETY: the creating references.
    unsafe {
        remove(named);
        object::dereference(named);
        object::dereference(plain);
    }
    verdict?;
    if (count(), pool::usage().blocks) != before {
        return Err("a named or an unnamed object was not freed whole");
    }
    Ok(())
}
