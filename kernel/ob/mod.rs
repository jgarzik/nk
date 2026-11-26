//! The object namespace: the directories every Windows system has, and
//! in them the named objects and the symbolic links.
//!
//! The tree and its rules for paths are `nk_ob::tree`, tested on the
//! host; here are the lock around it, the objects and the references.
//! Names compare case-insensitively, whatever the caller asks: Windows
//! does the same unless it is configured otherwise.
//!
//! An entry does not keep its object alive, except a symbolic link's,
//! which nothing else holds. Whoever names an object takes the name
//! away again ([`remove`]) before giving up the reference it made the
//! object with, so under the namespace's lock a name leads to a live
//! object. Directories are made at boot and never removed.

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

/// Make the root directory, the directories in it, and `\DosDevices`,
/// a link to `\??` (which is `\GLOBAL??`: there is one session).
pub fn init() -> Result<(), &'static str> {
    const NO_MEMORY: &str = "no memory for the object namespace";
    let root = object::create(&object::DIRECTORY_TYPE, OBJECT_DIRECTORY_SIZE).ok_or(NO_MEMORY)?;
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
        ns.directories.push((dir, Entry(body)));
        // SAFETY: a named object made above; the root holds its name.
        unsafe { object::entered(body, root) };
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
    let mut ns = NAMESPACE.lock();
    if ns.tree.remove_object(&Entry(body)) != 0 {
        // SAFETY: only an object from `create_named` is given a name.
        unsafe { object::left(body) };
    }
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
    let link = {
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
                unsafe { object::left(link) };
                link
            }
            Ok(_) => return STATUS_OBJECT_TYPE_MISMATCH,
            Err(error) => return status(error),
        }
    };
    // SAFETY: the reference the entry held, given up outside the lock.
    unsafe { object::dereference(link) };
    STATUS_SUCCESS
}

/// What `path` leads to, following symbolic links: the object, with a
/// reference for the caller to drop (`object::dereference`), and what
/// is left of the path if it goes on below the object, starting with
/// its backslash. The rest is the business of the object's type: the
/// lock is dropped before anything is done with it.
///
/// The path is absolute, or relative to the directory object `start`
/// (the `RootDirectory` of `OBJECT_ATTRIBUTES`).
pub fn lookup(start: Option<*mut u8>, path: &[u16]) -> Result<(*mut u8, Vec<u16>), NTSTATUS> {
    let ns = NAMESPACE.lock();
    let start = match start {
        None => None,
        Some(object) if object == ns.root.0 => Some(DirId::ROOT),
        Some(object) => Some(
            ns.directories
                .iter()
                .find(|(_, directory)| directory.0 == object)
                .map(|(id, _)| *id)
                .ok_or(STATUS_OBJECT_TYPE_MISMATCH)?,
        ),
    };
    let outcome = ns.tree.lookup(start, path, OPTIONS).map_err(status)?;
    let body = match outcome.found {
        Found::Object(object) | Found::SymbolicLink(_, object) => object.0,
        Found::Directory(dir) => directory(&ns, dir),
    };
    // SAFETY: an object loses its names, under this lock, before it
    // gives up the reference it was made with; so one that still has a
    // name is alive. Directories live for ever.
    unsafe { object::reference(body) };
    Ok((body, outcome.remainder))
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
    // SAFETY: the reference the look-up took.
    unsafe { object::dereference(body) };
    Ok((body, alloc::string::String::from_utf16_lossy(&rest)))
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
