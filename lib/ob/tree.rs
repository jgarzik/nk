//! The object namespace as a tree of directories, and the walk that
//! resolves a path in it.
//!
//! A directory holds named entries; an entry is another directory, a
//! symbolic link (a target path, with the kernel's object for the link)
//! or an object. Objects are the kernel's, and this module never looks
//! inside one. The kernel wraps the tree in a lock,
//! does the reference counting and owns everything a type decides:
//! [`Tree::lookup`] stops at the first object on the path and hands
//! back the rest of the path for that object's parse procedure.
//!
//! Background:
//! [Object Names](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-names),
//! [Object Directories](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/object-directories).
//!
//! # Paths
//!
//! A path is a run of components separated by `\`. Every `\` separates,
//! so no component can contain one. Without a starting directory a path
//! is absolute and begins with `\`; with one (the `RootDirectory` of
//! `OBJECT_ATTRIBUTES`) it is relative and does not. The rules, each
//! with the status its [`Error`] stands for:
//!
//! | Path | Result |
//! | --- | --- |
//! | absolute, empty or not starting with `\` | `PathSyntaxBad` |
//! | relative, starting with `\` | `PathSyntaxBad` |
//! | `\` | the root directory |
//! | relative, empty | the starting directory |
//! | an empty component: `\\A`, `\A\\B`, `\A\` below a directory | `NameInvalid` |
//! | a component before the last is missing | `PathNotFound` |
//! | the last component is missing | `NameNotFound` |
//! | an object with components after it | that object and the remainder |
//!
//! The remainder is everything after the object's own name, starting
//! with its separator: `\Device\NamedPipe\x\y` at the device `NamedPipe`
//! leaves `\x\y`, and `\Device\NamedPipe\` leaves `\`. Whether a
//! remainder is acceptable is the object type's business: the kernel
//! answers `STATUS_OBJECT_TYPE_MISMATCH` for a type with no parse
//! procedure.
//!
//! # Symbolic links
//!
//! A link met on the way is replaced, together with everything before
//! it, by its target, and the walk starts again from the root with the
//! same options. A look-up follows at most [`MAX_LINK_DEPTH`] links. A
//! target that is not an absolute path leads nowhere (`NameNotFound`).
//! A link as the last component is followed too, unless the caller asks
//! for the link itself ([`Options::open_link`]).
//!
//! # `\??`, `\GLOBAL??` and `\DosDevices`
//!
//! On Windows `\??` is not an entry of the root: it names the calling
//! process's DOS-devices directory, and the system-wide one is
//! `\GLOBAL??`. Here, an absolute path whose first component is `??`
//! continues in [`Options::dos_devices`] or, when that is `None`, in the
//! directory called `GLOBAL??` in the root. With neither, `??` is an
//! ordinary name. A relative path gets no such treatment. `\DosDevices`
//! is an ordinary symbolic link to `\??` that the kernel creates at
//! boot, as it creates `\GLOBAL??`.

use crate::MAX_LINK_DEPTH;
use alloc::vec::Vec;

const SEPARATOR: u16 = 0x5C;
/// `??`.
const DOS_DEVICES: [u16; 2] = [0x3F; 2];
/// `GLOBAL??`.
const GLOBAL_DOS_DEVICES: [u16; 8] = [0x47, 0x4C, 0x4F, 0x42, 0x41, 0x4C, 0x3F, 0x3F];

/// Why a path did not do what was asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// An absolute path that does not start with `\`, or a relative one
    /// that does (`STATUS_OBJECT_PATH_SYNTAX_BAD`).
    PathSyntaxBad,
    /// An empty component, or a path that names the root, `\??` or the
    /// starting directory where an entry is needed
    /// (`STATUS_OBJECT_NAME_INVALID`).
    NameInvalid,
    /// A component before the last names nothing, or the starting
    /// directory is not in the tree (`STATUS_OBJECT_PATH_NOT_FOUND`).
    PathNotFound,
    /// The last component names nothing, or a symbolic link's target is
    /// not an absolute path (`STATUS_OBJECT_NAME_NOT_FOUND`).
    NameNotFound,
    /// The name is taken (`STATUS_OBJECT_NAME_COLLISION`).
    Collision,
    /// The path goes on below an object, where an entry was to be added
    /// or removed (`STATUS_OBJECT_TYPE_MISMATCH`).
    TypeMismatch,
    /// More than [`MAX_LINK_DEPTH`] symbolic links: a ring, or a chain
    /// too long (`STATUS_OBJECT_NAME_NOT_FOUND`).
    TooManyLinks,
    /// The directory still has entries (`STATUS_DIRECTORY_NOT_EMPTY`).
    /// No driver sees this: a Windows directory lives as long as its
    /// entries do.
    NotEmpty,
    /// No memory; nothing was changed (`STATUS_INSUFFICIENT_RESOURCES`).
    NoMemory,
}

/// Names a directory of one tree. It stops naming anything when the
/// directory is removed, and is never given to another directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DirId {
    index: usize,
    serial: u64,
}

impl DirId {
    /// The root directory, `\`.
    pub const ROOT: DirId = DirId {
        index: usize::MAX,
        serial: 0,
    };
}

/// How to read a path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options {
    /// Compare names ignoring case (`OBJ_CASE_INSENSITIVE`). Without
    /// it a name matches only its exact spelling, and a directory can
    /// hold names that differ in case alone; a look-up ignoring case
    /// then finds the oldest of them.
    pub case_insensitive: bool,
    /// If the path ends on a symbolic link, stop at the link instead
    /// of following it: what `ZwOpenSymbolicLinkObject` needs, and
    /// `OBJ_OPENLINK`.
    pub open_link: bool,
    /// The directory `\??` names; `None` for `\GLOBAL??`.
    pub dos_devices: Option<DirId>,
}

impl Options {
    /// Follow links, `\??` is `\GLOBAL??`.
    pub const fn new(case_insensitive: bool) -> Self {
        Self {
            case_insensitive,
            open_link: false,
            dos_devices: None,
        }
    }
}

/// An entry, as a look-up or an enumeration shows it.
#[derive(Debug, PartialEq, Eq)]
pub enum Found<'a, T> {
    Directory(DirId),
    /// A symbolic link: its target, and the kernel's object for it.
    SymbolicLink(&'a [u16], &'a T),
    Object(&'a T),
}

/// Where a look-up ended.
#[derive(Debug, PartialEq, Eq)]
pub struct Outcome<'a, T> {
    pub found: Found<'a, T>,
    /// The part of the path after an object, starting with `\`; empty
    /// when the path ended on the entry.
    pub remainder: Vec<u16>,
}

/// An entry taken out of the tree.
#[derive(Debug, PartialEq, Eq)]
pub enum Removed<T> {
    Directory,
    /// A symbolic link: its target, and the kernel's object for it.
    SymbolicLink(Vec<u16>, T),
    Object(T),
}

/// How many entries a tree holds, by kind. The root is not an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counts {
    pub directories: usize,
    pub symbolic_links: usize,
    pub objects: usize,
}

impl Counts {
    /// Every entry.
    pub fn total(&self) -> usize {
        self.directories + self.symbolic_links + self.objects
    }

    /// Entries that are not directories.
    pub fn leaves(&self) -> usize {
        self.symbolic_links + self.objects
    }
}

#[derive(Debug)]
enum Node<T> {
    Directory(DirId),
    SymbolicLink(Vec<u16>, T),
    Object(T),
}

#[derive(Debug)]
struct Entry<T> {
    name: Vec<u16>,
    node: Node<T>,
}

#[derive(Debug)]
struct Directory<T> {
    serial: u64,
    entries: Vec<Entry<T>>,
}

/// Where one pass over a path ended.
enum Stop {
    /// On a directory that is not an entry of its parent here: the
    /// root, the starting directory, or what `\??` names.
    Directory(DirId),
    /// On entry `index` of `dir`; the path goes on at `rest`.
    Entry {
        dir: DirId,
        index: usize,
        rest: usize,
    },
    /// In `dir`, where the last component, `begin..end`, names nothing.
    Missing {
        dir: DirId,
        begin: usize,
        end: usize,
    },
}

enum Step {
    Stop(Stop),
    /// A symbolic link: walk this path instead.
    Link(Vec<u16>),
}

fn copy(text: &[u16]) -> Result<Vec<u16>, Error> {
    let mut out = Vec::new();
    out.try_reserve_exact(text.len())
        .map_err(|_| Error::NoMemory)?;
    out.extend_from_slice(text);
    Ok(out)
}

fn find<T>(entries: &[Entry<T>], name: &[u16], case_insensitive: bool) -> Option<usize> {
    entries.iter().position(|e| {
        if case_insensitive {
            nk_rtl::names_equal(&e.name, name)
        } else {
            e.name == name
        }
    })
}

fn shown<T>(node: &Node<T>) -> Found<'_, T> {
    match node {
        Node::Directory(dir) => Found::Directory(*dir),
        Node::SymbolicLink(target, object) => Found::SymbolicLink(target, object),
        Node::Object(object) => Found::Object(object),
    }
}

/// The object namespace: a root directory and what is below it. See the
/// module for the rules. An empty tree holds no memory, and a tree
/// reserves none ahead: what it holds depends on its entries alone, so
/// an entry added and removed leaves the memory in use as it was.
#[derive(Debug)]
pub struct Tree<T> {
    root: Vec<Entry<T>>,
    /// Every other directory; a [`DirId`] is an index here.
    directories: Vec<Option<Directory<T>>>,
    /// The serial number of the newest directory.
    serial: u64,
}

impl<T> Tree<T> {
    pub const fn new() -> Self {
        Self {
            root: Vec::new(),
            directories: Vec::new(),
            serial: 0,
        }
    }

    fn entries_of(&self, dir: DirId) -> Option<&Vec<Entry<T>>> {
        if dir == DirId::ROOT {
            return Some(&self.root);
        }
        let directory = self.directories.get(dir.index)?.as_ref()?;
        (directory.serial == dir.serial).then_some(&directory.entries)
    }

    fn entries_of_mut(&mut self, dir: DirId) -> Option<&mut Vec<Entry<T>>> {
        if dir == DirId::ROOT {
            return Some(&mut self.root);
        }
        let directory = self.directories.get_mut(dir.index)?.as_mut()?;
        (directory.serial == dir.serial).then_some(&mut directory.entries)
    }

    /// The directory `\??` names, if there is one.
    fn dos_devices(&self, options: Options) -> Option<DirId> {
        match options.dos_devices {
            Some(dir) => self.entries_of(dir).map(|_| dir),
            None => self.root.iter().find_map(|e| match e.node {
                Node::Directory(dir) if nk_rtl::names_equal(&e.name, &GLOBAL_DOS_DEVICES) => {
                    Some(dir)
                }
                _ => None,
            }),
        }
    }

    /// Walk `path` once, as far as its end, an object or a link to
    /// follow. `reparsed`: the path came from a symbolic link.
    fn walk_once(
        &self,
        start: Option<DirId>,
        path: &[u16],
        options: Options,
        follow_last: bool,
        reparsed: bool,
    ) -> Result<Step, Error> {
        let absolute = start.is_none();
        let leading = path.first() == Some(&SEPARATOR);
        let mut dir = match start {
            Some(dir) => {
                if self.entries_of(dir).is_none() {
                    return Err(Error::PathNotFound);
                }
                if leading {
                    return Err(Error::PathSyntaxBad);
                }
                dir
            }
            None if leading => DirId::ROOT,
            None if reparsed => return Err(Error::NameNotFound),
            None => return Err(Error::PathSyntaxBad),
        };
        if path.len() == usize::from(leading) {
            return Ok(Step::Stop(Stop::Directory(dir)));
        }
        let mut at = 0;
        loop {
            let begin = at + usize::from(path[at] == SEPARATOR);
            let end = path[begin..]
                .iter()
                .position(|&c| c == SEPARATOR)
                .map_or(path.len(), |n| begin + n);
            if begin == end {
                return Err(Error::NameInvalid);
            }
            let name = &path[begin..end];
            let last = end == path.len();
            let alias = if absolute && at == 0 && name == DOS_DEVICES {
                self.dos_devices(options)
            } else {
                None
            };
            if let Some(dos_devices) = alias {
                if last {
                    return Ok(Step::Stop(Stop::Directory(dos_devices)));
                }
                dir = dos_devices;
                at = end;
                continue;
            }
            let entries = self.entries_of(dir).ok_or(Error::PathNotFound)?;
            let Some(index) = find(entries, name, options.case_insensitive) else {
                return if last {
                    Ok(Step::Stop(Stop::Missing { dir, begin, end }))
                } else {
                    Err(Error::PathNotFound)
                };
            };
            match &entries[index].node {
                Node::Directory(below) if !last => {
                    dir = *below;
                    at = end;
                }
                Node::SymbolicLink(target, _) if !last || follow_last => {
                    let mut to = copy(target)?;
                    to.try_reserve_exact(path.len() - end)
                        .map_err(|_| Error::NoMemory)?;
                    to.extend_from_slice(&path[end..]);
                    return Ok(Step::Link(to));
                }
                _ => {
                    let rest = end;
                    return Ok(Step::Stop(Stop::Entry { dir, index, rest }));
                }
            }
        }
    }

    /// Walk `path`, following symbolic links. Returns where the walk
    /// stopped and the path it stopped in, if a link replaced the
    /// caller's.
    fn walk(
        &self,
        start: Option<DirId>,
        path: &[u16],
        options: Options,
        follow_last: bool,
    ) -> Result<(Option<Vec<u16>>, Stop), Error> {
        let mut start = start;
        let mut replaced: Option<Vec<u16>> = None;
        for _ in 0..=MAX_LINK_DEPTH {
            let reparsed = replaced.is_some();
            let current = replaced.as_deref().unwrap_or(path);
            match self.walk_once(start, current, options, follow_last, reparsed)? {
                Step::Stop(stop) => return Ok((replaced, stop)),
                Step::Link(to) => {
                    replaced = Some(to);
                    start = None;
                }
            }
        }
        Err(Error::TooManyLinks)
    }

    /// What `path` leads to, from the root or, given `start`, from that
    /// directory. Stops at the first object on the way and returns it
    /// with the rest of the path.
    pub fn lookup(
        &self,
        start: Option<DirId>,
        path: &[u16],
        options: Options,
    ) -> Result<Outcome<'_, T>, Error> {
        let (replaced, stop) = self.walk(start, path, options, !options.open_link)?;
        let path = replaced.as_deref().unwrap_or(path);
        match stop {
            Stop::Directory(dir) => Ok(Outcome {
                found: Found::Directory(dir),
                remainder: Vec::new(),
            }),
            Stop::Missing { .. } => Err(Error::NameNotFound),
            Stop::Entry { dir, index, rest } => {
                let entries = self.entries_of(dir).ok_or(Error::PathNotFound)?;
                Ok(Outcome {
                    found: shown(&entries[index].node),
                    remainder: copy(&path[rest..])?,
                })
            }
        }
    }

    /// Where a new entry called `path` goes: its directory, with room
    /// for it, and its name there. Links on the way are followed; a
    /// name that is taken, even by a link to nothing, is a collision
    /// (the caller implements `OBJ_OPENIF` by looking the name up).
    fn place(
        &mut self,
        start: Option<DirId>,
        path: &[u16],
        options: Options,
    ) -> Result<(DirId, Vec<u16>), Error> {
        let (replaced, stop) = self.walk(start, path, options, false)?;
        let path = replaced.as_deref().unwrap_or(path);
        match stop {
            Stop::Missing { dir, begin, end } => {
                let name = copy(&path[begin..end])?;
                let entries = self.entries_of_mut(dir).ok_or(Error::PathNotFound)?;
                entries.try_reserve_exact(1).map_err(|_| Error::NoMemory)?;
                Ok((dir, name))
            }
            Stop::Entry { rest, .. } if rest != path.len() => Err(Error::TypeMismatch),
            Stop::Entry { .. } | Stop::Directory(_) => Err(Error::Collision),
        }
    }

    /// Add `node` to `dir`, which [`Tree::place`] made room in.
    fn add(&mut self, dir: DirId, name: Vec<u16>, node: Node<T>) {
        if let Some(entries) = self.entries_of_mut(dir) {
            entries.push(Entry { name, node });
        }
    }

    /// Add an empty directory called `path`. Every directory on the way
    /// to it must exist.
    pub fn create_directory(
        &mut self,
        start: Option<DirId>,
        path: &[u16],
        options: Options,
    ) -> Result<DirId, Error> {
        let (parent, name) = self.place(start, path, options)?;
        let index = match self.directories.iter().position(Option::is_none) {
            Some(free) => free,
            None => {
                self.directories
                    .try_reserve_exact(1)
                    .map_err(|_| Error::NoMemory)?;
                self.directories.push(None);
                self.directories.len() - 1
            }
        };
        self.serial += 1;
        let serial = self.serial;
        self.directories[index] = Some(Directory {
            serial,
            entries: Vec::new(),
        });
        let dir = DirId { index, serial };
        self.add(parent, name, Node::Directory(dir));
        Ok(dir)
    }

    /// Add a symbolic link called `path` that leads to `target`, and
    /// say which directory it went into. The target is not looked at
    /// until the link is followed; `object` is the kernel's object for
    /// the link, handed back when the link is found or removed.
    pub fn insert_link(
        &mut self,
        start: Option<DirId>,
        path: &[u16],
        options: Options,
        target: &[u16],
        object: T,
    ) -> Result<DirId, Error> {
        let target = copy(target)?;
        let (parent, name) = self.place(start, path, options)?;
        self.add(parent, name, Node::SymbolicLink(target, object));
        Ok(parent)
    }

    /// Give `object` the name `path`, and say which directory the name
    /// went into.
    pub fn insert_object(
        &mut self,
        start: Option<DirId>,
        path: &[u16],
        options: Options,
        object: T,
    ) -> Result<DirId, Error> {
        let (parent, name) = self.place(start, path, options)?;
        self.add(parent, name, Node::Object(object));
        Ok(parent)
    }

    /// Forget directory `dir`, and give back the memory of the table's
    /// unused end.
    fn free_directory(&mut self, dir: DirId) {
        self.directories[dir.index] = None;
        while let Some(None) = self.directories.last() {
            self.directories.pop();
        }
        self.directories.shrink_to_fit();
    }

    /// Take the entry called `path` out of the tree. Links on the way
    /// are followed; a link at the end is the entry removed. A
    /// directory must be empty.
    pub fn remove(
        &mut self,
        start: Option<DirId>,
        path: &[u16],
        options: Options,
    ) -> Result<Removed<T>, Error> {
        let (replaced, stop) = self.walk(start, path, options, false)?;
        let length = replaced.as_deref().unwrap_or(path).len();
        let (dir, index) = match stop {
            Stop::Directory(_) => return Err(Error::NameInvalid),
            Stop::Missing { .. } => return Err(Error::NameNotFound),
            Stop::Entry { rest, .. } if rest != length => return Err(Error::TypeMismatch),
            Stop::Entry { dir, index, .. } => (dir, index),
        };
        let entries = self.entries_of(dir).ok_or(Error::PathNotFound)?;
        if let Node::Directory(below) = entries[index].node {
            if self.entries_of(below).is_some_and(|e| !e.is_empty()) {
                return Err(Error::NotEmpty);
            }
            self.free_directory(below);
        }
        let entries = self.entries_of_mut(dir).ok_or(Error::PathNotFound)?;
        let entry = entries.remove(index);
        entries.shrink_to_fit();
        Ok(match entry.node {
            Node::Directory(_) => Removed::Directory,
            Node::SymbolicLink(target, object) => Removed::SymbolicLink(target, object),
            Node::Object(object) => Removed::Object(object),
        })
    }

    /// Take every name of `object` out of the tree, and say how many
    /// there were. Links that led to those names stay, and lead nowhere.
    pub fn remove_object(&mut self, object: &T) -> usize
    where
        T: PartialEq,
    {
        let before = self.counts().objects;
        let below = self
            .directories
            .iter_mut()
            .flatten()
            .map(|d| &mut d.entries);
        for entries in core::iter::once(&mut self.root).chain(below) {
            entries.retain(|e| !matches!(&e.node, Node::Object(o) if o == object));
            entries.shrink_to_fit();
        }
        before - self.counts().objects
    }

    /// The entries in the tree. The directories the kernel creates at
    /// boot are entries like any other: leak accounting compares
    /// [`Counts::leaves`], or the total before and after.
    pub fn counts(&self) -> Counts {
        let mut counts = Counts {
            directories: 0,
            symbolic_links: 0,
            objects: 0,
        };
        let below = self.directories.iter().flatten().map(|d| &d.entries);
        for entry in core::iter::once(&self.root).chain(below).flatten() {
            match entry.node {
                Node::Directory(_) => counts.directories += 1,
                Node::SymbolicLink(..) => counts.symbolic_links += 1,
                Node::Object(_) => counts.objects += 1,
            }
        }
        counts
    }

    /// The entries of `dir`, oldest first, each with its name; `None`
    /// if `dir` is not in the tree.
    pub fn entries(&self, dir: DirId) -> Option<impl Iterator<Item = (&[u16], Found<'_, T>)>> {
        let entries = self.entries_of(dir)?;
        Some(entries.iter().map(|e| (e.name.as_slice(), shown(&e.node))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Shown = Result<(String, String), Error>;

    /// The object of every link the tests make, unless they say.
    const LINK: u32 = 1000;

    const ANY_CASE: Options = Options::new(true);
    const EXACT: Options = Options::new(false);
    const THE_LINK: Options = Options {
        open_link: true,
        ..ANY_CASE
    };

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    fn s(text: &[u16]) -> String {
        String::from_utf16(text).unwrap()
    }

    /// The path of directory `id`, found by enumerating from `dir`.
    fn search(tree: &Tree<u32>, dir: DirId, prefix: &str, id: DirId) -> Option<String> {
        for (name, found) in tree.entries(dir)? {
            if let Found::Directory(below) = found {
                let path = format!("{prefix}\\{}", s(name));
                if below == id {
                    return Some(path);
                }
                if let Some(deeper) = search(tree, below, &path, id) {
                    return Some(deeper);
                }
            }
        }
        None
    }

    fn dir_name(tree: &Tree<u32>, id: DirId) -> String {
        if id == DirId::ROOT {
            return "\\".into();
        }
        search(tree, DirId::ROOT, "", id).expect("a directory of the tree")
    }

    /// An outcome as text: `dir:<path>`, `link:<target>` or
    /// `obj:<number>`, and the remainder.
    fn show(tree: &Tree<u32>, outcome: Result<Outcome<'_, u32>, Error>) -> Shown {
        outcome.map(|o| {
            let found = match o.found {
                Found::Directory(dir) => format!("dir:{}", dir_name(tree, dir)),
                Found::SymbolicLink(target, _) => format!("link:{}", s(target)),
                Found::Object(object) => format!("obj:{object}"),
            };
            (found, s(&o.remainder))
        })
    }

    fn ok(found: &str, remainder: &str) -> Shown {
        Ok((found.into(), remainder.into()))
    }

    fn look(tree: &Tree<u32>, path: &str, options: Options) -> Shown {
        show(tree, tree.lookup(None, &w(path), options))
    }

    fn look_from(tree: &Tree<u32>, start: DirId, path: &str) -> Shown {
        show(tree, tree.lookup(Some(start), &w(path), ANY_CASE))
    }

    fn dir(tree: &mut Tree<u32>, path: &str) -> DirId {
        tree.create_directory(None, &w(path), EXACT).expect(path)
    }

    fn link(tree: &mut Tree<u32>, path: &str, target: &str) {
        tree.insert_link(None, &w(path), EXACT, &w(target), LINK)
            .expect(path);
    }

    fn object(tree: &mut Tree<u32>, path: &str, object: u32) {
        tree.insert_object(None, &w(path), EXACT, object)
            .expect(path);
    }

    /// The namespace roughly as the kernel sets it up at boot, with two
    /// devices and some links that lead nowhere.
    fn booted() -> Tree<u32> {
        let mut tree = Tree::new();
        dir(&mut tree, "\\Device");
        dir(&mut tree, "\\GLOBAL??");
        dir(&mut tree, "\\BaseNamedObjects");
        link(&mut tree, "\\DosDevices", "\\??");
        object(&mut tree, "\\Device\\Null", 1);
        object(&mut tree, "\\Device\\NamedPipe", 2);
        link(&mut tree, "\\GLOBAL??\\NUL", "\\Device\\Null");
        link(&mut tree, "\\GLOBAL??\\PIPE", "\\Device\\NamedPipe");
        link(&mut tree, "\\GLOBAL??\\Global", "\\GLOBAL??");
        object(&mut tree, "\\BaseNamedObjects\\Ev", 3);
        link(&mut tree, "\\Dangling", "\\Device\\Gone");
        link(&mut tree, "\\DanglingDeep", "\\Gone\\Deeper");
        link(&mut tree, "\\Relative", "Device\\Null");
        tree
    }

    fn check(tree: &Tree<u32>, options: Options, cases: &[(&str, Shown)]) {
        for (path, expected) in cases {
            assert_eq!(&look(tree, path, options), expected, "{path:?}");
        }
    }

    #[test]
    fn a_path_leads_to_a_directory_or_an_object() {
        let cases = [
            ("\\", ok("dir:\\", "")),
            ("\\Device", ok("dir:\\Device", "")),
            ("\\device", ok("dir:\\Device", "")),
            ("\\Device\\Null", ok("obj:1", "")),
            ("\\DEVICE\\null", ok("obj:1", "")),
            ("\\BaseNamedObjects\\Ev", ok("obj:3", "")),
        ];
        let any_case = Options::new(true);
        assert!(!any_case.open_link && any_case.dos_devices.is_none());
        check(&booted(), any_case, &cases);
    }

    #[test]
    fn a_path_below_an_object_stops_at_the_object_with_the_rest() {
        let cases = [
            // The remainder starts with the separator after the object.
            ("\\Device\\NamedPipe\\x", ok("obj:2", "\\x")),
            ("\\Device\\NamedPipe\\x\\y", ok("obj:2", "\\x\\y")),
            ("\\Device\\Null\\", ok("obj:1", "\\")),
            // It is the object's to judge, and is not looked at.
            ("\\Device\\NamedPipe\\\\x\\", ok("obj:2", "\\\\x\\")),
            ("\\device\\namedpipe\\MiXed", ok("obj:2", "\\MiXed")),
        ];
        check(&booted(), ANY_CASE, &cases);
    }

    #[test]
    fn a_malformed_path_is_refused() {
        let cases = [
            ("", Err(Error::PathSyntaxBad)),
            ("Device", Err(Error::PathSyntaxBad)),
            ("Device\\Null", Err(Error::PathSyntaxBad)),
            ("\\\\", Err(Error::NameInvalid)),
            ("\\\\Device", Err(Error::NameInvalid)),
            ("\\Device\\", Err(Error::NameInvalid)),
            ("\\Device\\\\Null", Err(Error::NameInvalid)),
            ("\\??\\", Err(Error::NameInvalid)),
        ];
        check(&booted(), ANY_CASE, &cases);
    }

    #[test]
    fn a_missing_last_name_differs_from_a_missing_middle_one() {
        let cases = [
            ("\\Gone", Err(Error::NameNotFound)),
            ("\\Device\\Gone", Err(Error::NameNotFound)),
            ("\\Gone\\Null", Err(Error::PathNotFound)),
            ("\\Device\\Gone\\x", Err(Error::PathNotFound)),
            // Something follows the missing name, if only a separator.
            ("\\Gone\\", Err(Error::PathNotFound)),
            ("\\Device\\Nul", Err(Error::NameNotFound)),
            ("\\Device\\Null2", Err(Error::NameNotFound)),
        ];
        check(&booted(), ANY_CASE, &cases);
    }

    #[test]
    fn a_symbolic_link_is_replaced_by_its_target() {
        let cases = [
            ("\\GLOBAL??\\NUL", ok("obj:1", "")),
            ("\\GLOBAL??\\PIPE\\srvsvc", ok("obj:2", "\\srvsvc")),
            ("\\global??\\pipe\\", ok("obj:2", "\\")),
            // A link to a directory, in the middle and at the end.
            ("\\GLOBAL??\\Global\\NUL", ok("obj:1", "")),
            ("\\GLOBAL??\\Global", ok("dir:\\GLOBAL??", "")),
            (
                "\\GLOBAL??\\Global\\Global\\Global",
                ok("dir:\\GLOBAL??", ""),
            ),
        ];
        check(&booted(), ANY_CASE, &cases);
    }

    #[test]
    fn a_link_to_nothing_fails_as_its_target_would() {
        let cases = [
            ("\\Dangling", Err(Error::NameNotFound)),
            ("\\Dangling\\x", Err(Error::PathNotFound)),
            ("\\DanglingDeep", Err(Error::PathNotFound)),
            // A target that is not an absolute path.
            ("\\Relative", Err(Error::NameNotFound)),
            ("\\Relative\\x", Err(Error::NameNotFound)),
        ];
        let mut tree = booted();
        link(&mut tree, "\\Empty", "");
        check(&tree, ANY_CASE, &cases);
        check(&tree, ANY_CASE, &[("\\Empty", Err(Error::NameNotFound))]);
        // A link made before its target works once the target exists.
        object(&mut tree, "\\Device\\Gone", 8);
        check(&tree, ANY_CASE, &[("\\Dangling\\x", ok("obj:8", "\\x"))]);
    }

    #[test]
    fn the_dos_devices_directory_has_three_names() {
        let cases = [
            ("\\??", ok("dir:\\GLOBAL??", "")),
            ("\\GLOBAL??", ok("dir:\\GLOBAL??", "")),
            ("\\DosDevices", ok("dir:\\GLOBAL??", "")),
            ("\\??\\NUL", ok("obj:1", "")),
            ("\\DosDevices\\NUL", ok("obj:1", "")),
            ("\\dosdevices\\nul", ok("obj:1", "")),
            ("\\??\\nul\\a", ok("obj:1", "\\a")),
            ("\\DosDevices\\PIPE\\srvsvc", ok("obj:2", "\\srvsvc")),
            ("\\??\\Global\\PIPE", ok("obj:2", "")),
            ("\\??\\Gone", Err(Error::NameNotFound)),
            ("\\??\\Gone\\x", Err(Error::PathNotFound)),
            // Only as the first name of an absolute path.
            ("\\Device\\??", Err(Error::NameNotFound)),
            ("\\Device\\??\\NUL", Err(Error::PathNotFound)),
        ];
        check(&booted(), ANY_CASE, &cases);
    }

    #[test]
    fn the_caller_says_which_directory_is_the_dos_devices_one() {
        let mut tree = booted();
        let local = dir(&mut tree, "\\Local");
        object(&mut tree, "\\Local\\NUL", 9);
        let options = Options {
            dos_devices: Some(local),
            ..ANY_CASE
        };
        let cases = [
            ("\\??", ok("dir:\\Local", "")),
            ("\\??\\NUL", ok("obj:9", "")),
            ("\\DosDevices\\NUL\\x", ok("obj:9", "\\x")),
            ("\\GLOBAL??\\NUL", ok("obj:1", "")),
            ("\\??\\PIPE", Err(Error::NameNotFound)),
        ];
        check(&tree, options, &cases);
        // New names go there too.
        assert!(tree.insert_object(None, &w("\\??\\X"), options, 10).is_ok());
        check(&tree, ANY_CASE, &[("\\Local\\X", ok("obj:10", ""))]);
        // Once the directory is gone, `??` is a name like any other.
        for name in ["\\Local\\NUL", "\\Local\\X", "\\Local"] {
            tree.remove(None, &w(name), EXACT).expect(name);
        }
        let cases = [
            ("\\??", Err(Error::NameNotFound)),
            ("\\??\\NUL", Err(Error::PathNotFound)),
        ];
        check(&tree, options, &cases);
    }

    #[test]
    fn without_a_dos_devices_directory_the_name_is_ordinary() {
        let mut tree = Tree::new();
        let cases = [
            ("\\??", Err(Error::NameNotFound)),
            ("\\??\\NUL", Err(Error::PathNotFound)),
        ];
        check(&tree, ANY_CASE, &cases);
        dir(&mut tree, "\\??");
        object(&mut tree, "\\??\\NUL", 4);
        let cases = [("\\??", ok("dir:\\??", "")), ("\\??\\NUL", ok("obj:4", ""))];
        check(&tree, ANY_CASE, &cases);
        // An object called `GLOBAL??` is not a directory to continue in.
        object(&mut tree, "\\GLOBAL??", 5);
        check(&tree, ANY_CASE, &cases);
        // A directory of that name takes over, however it is spelled.
        tree.remove(None, &w("\\GLOBAL??"), EXACT).unwrap();
        dir(&mut tree, "\\global??");
        let cases = [
            ("\\??", ok("dir:\\global??", "")),
            ("\\??\\NUL", Err(Error::NameNotFound)),
        ];
        check(&tree, ANY_CASE, &cases);
        check(&tree, EXACT, &cases);
    }

    #[test]
    fn a_final_link_is_returned_when_the_caller_asks_for_it() {
        let cases = [
            ("\\??\\NUL", ok("link:\\Device\\Null", "")),
            ("\\DosDevices", ok("link:\\??", "")),
            // Links before the end are still followed.
            ("\\DosDevices\\NUL", ok("link:\\Device\\Null", "")),
            ("\\??\\Global\\PIPE", ok("link:\\Device\\NamedPipe", "")),
            ("\\??\\NUL\\x", ok("obj:1", "\\x")),
            ("\\Dangling", ok("link:\\Device\\Gone", "")),
            ("\\Relative", ok("link:Device\\Null", "")),
            ("\\Dangling\\x", Err(Error::PathNotFound)),
            ("\\Device\\Null", ok("obj:1", "")),
            ("\\Device", ok("dir:\\Device", "")),
        ];
        check(&booted(), THE_LINK, &cases);
    }

    #[test]
    fn exact_spelling_is_needed_when_case_matters() {
        let cases = [
            ("\\Device\\Null", ok("obj:1", "")),
            ("\\Device\\null", Err(Error::NameNotFound)),
            ("\\device", Err(Error::NameNotFound)),
            ("\\device\\Null", Err(Error::PathNotFound)),
            ("\\Device\\NamedPipe\\X", ok("obj:2", "\\X")),
            ("\\Device\\namedpipe\\X", Err(Error::PathNotFound)),
            ("\\??\\NUL", ok("obj:1", "")),
            ("\\??\\nul", Err(Error::NameNotFound)),
            ("\\DosDevices\\NUL", ok("obj:1", "")),
            ("\\dosdevices\\NUL", Err(Error::PathNotFound)),
            ("\\global??\\NUL", Err(Error::PathNotFound)),
        ];
        check(&booted(), EXACT, &cases);
    }

    #[test]
    fn names_that_differ_in_case_coexist_when_case_matters() {
        let mut tree = booted();
        let at = w("\\Device\\NULL");
        assert_eq!(
            tree.insert_object(None, &at, ANY_CASE, 5),
            Err(Error::Collision)
        );
        assert!(tree.insert_object(None, &at, EXACT, 5).is_ok());
        check(&tree, EXACT, &[("\\Device\\NULL", ok("obj:5", ""))]);
        check(&tree, EXACT, &[("\\Device\\Null", ok("obj:1", ""))]);
        // Ignoring case, the older name is the one found.
        check(&tree, ANY_CASE, &[("\\Device\\NULL", ok("obj:1", ""))]);
        // Every letter folds, within Latin-1 and beyond it.
        object(&mut tree, "\\Device\\caf\u{e9}", 6);
        object(&mut tree, "\\Device\\\u{3b1}", 7);
        check(&tree, ANY_CASE, &[("\\Device\\CAF\u{c9}", ok("obj:6", ""))]);
        check(&tree, ANY_CASE, &[("\\Device\\\u{391}", ok("obj:7", ""))]);
        let greek = [("\\Device\\\u{391}", Err(Error::NameNotFound))];
        check(&tree, EXACT, &greek);
    }

    #[test]
    fn a_relative_path_starts_at_the_given_directory() {
        let mut tree = booted();
        let sub = dir(&mut tree, "\\Device\\Sub");
        object(&mut tree, "\\Device\\Sub\\Leaf", 11);
        let Ok(Outcome {
            found: Found::Directory(device),
            ..
        }) = tree.lookup(None, &w("\\Device"), ANY_CASE)
        else {
            panic!("\\Device is a directory");
        };
        let cases = [
            (device, "", ok("dir:\\Device", "")),
            (device, "Null", ok("obj:1", "")),
            (device, "null\\x", ok("obj:1", "\\x")),
            (device, "Null\\", ok("obj:1", "\\")),
            (device, "Sub", ok("dir:\\Device\\Sub", "")),
            (device, "Sub\\Leaf", ok("obj:11", "")),
            (sub, "Leaf\\a\\b", ok("obj:11", "\\a\\b")),
            (sub, "", ok("dir:\\Device\\Sub", "")),
            (device, "Gone", Err(Error::NameNotFound)),
            (device, "Gone\\x", Err(Error::PathNotFound)),
            (device, "\\Null", Err(Error::PathSyntaxBad)),
            (device, "\\", Err(Error::PathSyntaxBad)),
            (device, "Sub\\", Err(Error::NameInvalid)),
            (device, "Sub\\\\Leaf", Err(Error::NameInvalid)),
            (DirId::ROOT, "Device\\Null", ok("obj:1", "")),
            (DirId::ROOT, "", ok("dir:\\", "")),
            // A link's target is absolute wherever the walk began.
            (DirId::ROOT, "GLOBAL??\\NUL", ok("obj:1", "")),
            (sub, "Leaf", ok("obj:11", "")),
            // `??` means the DOS-devices directory in absolute paths only.
            (DirId::ROOT, "??", Err(Error::NameNotFound)),
            (DirId::ROOT, "??\\NUL", Err(Error::PathNotFound)),
        ];
        for (start, path, expected) in cases {
            assert_eq!(look_from(&tree, start, path), expected, "{path:?}");
        }
        // New entries and removals take a starting directory too.
        assert_eq!(tree.insert_object(Some(sub), &w("New"), EXACT, 12), Ok(sub));
        check(&tree, EXACT, &[("\\Device\\Sub\\New", ok("obj:12", ""))]);
        assert_eq!(
            tree.remove(Some(device), &w("Sub\\New"), EXACT),
            Ok(Removed::Object(12))
        );
        assert_eq!(
            tree.create_directory(Some(sub), &w(""), EXACT),
            Err(Error::Collision)
        );
        assert_eq!(
            tree.remove(Some(sub), &w(""), EXACT),
            Err(Error::NameInvalid)
        );
    }

    /// `\L0` -> `\L1` -> ... -> `\L<links>`, which is object 7.
    fn chain(links: usize) -> Tree<u32> {
        let mut tree = Tree::new();
        for i in 0..links {
            link(&mut tree, &format!("\\L{i}"), &format!("\\L{}", i + 1));
        }
        object(&mut tree, &format!("\\L{links}"), 7);
        tree
    }

    #[test]
    fn links_are_followed_up_to_the_limit_and_no_further() {
        for links in [0, 1, MAX_LINK_DEPTH - 1, MAX_LINK_DEPTH] {
            let cases = [("\\L0", ok("obj:7", "")), ("\\L0\\x", ok("obj:7", "\\x"))];
            check(&chain(links), ANY_CASE, &cases);
        }
        // One link more is one too many, though the object is there.
        let long = chain(MAX_LINK_DEPTH + 1);
        let cases = [
            ("\\L0", Err(Error::TooManyLinks)),
            ("\\L0\\x", Err(Error::TooManyLinks)),
            ("\\L1", ok("obj:7", "")),
        ];
        check(&long, ANY_CASE, &cases);
        // Asked for a final link itself, the look-up follows none.
        check(&long, THE_LINK, &[("\\L0", ok("link:\\L1", ""))]);
        check(&long, THE_LINK, &[("\\L0\\x", Err(Error::TooManyLinks))]);
    }

    #[test]
    fn a_ring_of_links_is_an_error() {
        let mut tree = Tree::new();
        link(&mut tree, "\\A", "\\B");
        link(&mut tree, "\\B", "\\A");
        link(&mut tree, "\\Self", "\\Self");
        link(&mut tree, "\\Grow", "\\Grow\\x");
        let cases = [
            ("\\A", Err(Error::TooManyLinks)),
            ("\\B\\x", Err(Error::TooManyLinks)),
            ("\\Self", Err(Error::TooManyLinks)),
            ("\\Grow", Err(Error::TooManyLinks)),
        ];
        check(&tree, ANY_CASE, &cases);
        // Nothing can be added below a ring.
        assert_eq!(
            tree.insert_object(None, &w("\\A\\x"), EXACT, 1),
            Err(Error::TooManyLinks)
        );
        // The links themselves can still be opened, and removed.
        check(&tree, THE_LINK, &[("\\Self", ok("link:\\Self", ""))]);
        assert_eq!(
            tree.remove(None, &w("\\Self"), EXACT),
            Ok(Removed::SymbolicLink(w("\\Self"), LINK))
        );
    }

    #[test]
    fn a_name_is_taken_once() {
        let mut tree = booted();
        let before = tree.counts();
        let cases = [
            // By an object, a directory, a link, even one to nothing.
            ("\\Device\\Null", Error::Collision),
            ("\\DEVICE\\NULL", Error::Collision),
            ("\\Device", Error::Collision),
            ("\\GLOBAL??\\NUL", Error::Collision),
            ("\\Dangling", Error::Collision),
            // The root, and the DOS-devices directory by each name.
            ("\\", Error::Collision),
            ("\\??", Error::Collision),
            ("\\DosDevices", Error::Collision),
            ("\\??\\nul", Error::Collision),
            ("\\DosDevices\\NUL", Error::Collision),
            ("\\GLOBAL??\\Global\\PIPE", Error::Collision),
            // Not names at all.
            ("", Error::PathSyntaxBad),
            ("Device\\New", Error::PathSyntaxBad),
            ("\\Device\\", Error::NameInvalid),
            ("\\Device\\\\New", Error::NameInvalid),
            // The directory must exist: none is made on the way.
            ("\\Gone\\New", Error::PathNotFound),
            ("\\Device\\Gone\\New", Error::PathNotFound),
            ("\\Dangling\\New", Error::PathNotFound),
            // An object is not a directory.
            ("\\Device\\Null\\New", Error::TypeMismatch),
            ("\\??\\NUL\\New\\Deeper", Error::TypeMismatch),
        ];
        for (path, error) in cases {
            let at = w(path);
            assert_eq!(
                tree.insert_object(None, &at, ANY_CASE, 99),
                Err(error),
                "{path:?}"
            );
            assert_eq!(
                tree.insert_link(None, &at, ANY_CASE, &w("\\X"), LINK),
                Err(error),
                "{path:?}"
            );
            assert_eq!(
                tree.create_directory(None, &at, ANY_CASE),
                Err(error),
                "{path:?}"
            );
        }
        // Nothing changed.
        assert_eq!(tree.counts(), before);
        check(&tree, ANY_CASE, &[("\\Device\\Null", ok("obj:1", ""))]);
    }

    #[test]
    fn a_new_name_goes_where_the_links_on_its_path_lead() {
        let mut tree = booted();
        object(&mut tree, "\\DosDevices\\COM1", 20);
        link(&mut tree, "\\??\\Global\\LPT1", "\\Device\\Null");
        let sub = dir(&mut tree, "\\DosDevices\\Sub");
        let names: Vec<String> = tree
            .entries(tree.dos_devices(ANY_CASE).unwrap())
            .unwrap()
            .map(|(name, _)| s(name))
            .collect();
        assert_eq!(names, ["NUL", "PIPE", "Global", "COM1", "LPT1", "Sub"]);
        assert_eq!(dir_name(&tree, sub), "\\GLOBAL??\\Sub");
        check(&tree, ANY_CASE, &[("\\GLOBAL??\\com1", ok("obj:20", ""))]);
    }

    #[test]
    fn entries_are_counted_by_kind() {
        let empty = Tree::<u32>::new();
        assert_eq!(empty.counts().total(), 0);
        let mut tree = booted();
        let counts = tree.counts();
        let expected = Counts {
            directories: 3,
            symbolic_links: 7,
            objects: 3,
        };
        assert_eq!(counts, expected);
        assert_eq!(counts.total(), 13);
        assert_eq!(counts.leaves(), 10);
        dir(&mut tree, "\\Device\\Sub");
        object(&mut tree, "\\Device\\Sub\\X", 1);
        let counts = tree.counts();
        assert_eq!((counts.total(), counts.leaves()), (15, 11));
        assert_eq!(counts.directories, 4);
    }

    fn list(tree: &Tree<u32>, dir: DirId) -> Vec<String> {
        let shown = |(name, found): (&[u16], Found<'_, u32>)| match found {
            Found::Directory(_) => format!("{}/", s(name)),
            Found::SymbolicLink(to, _) => format!("{}>{}", s(name), s(to)),
            Found::Object(object) => format!("{}={object}", s(name)),
        };
        tree.entries(dir).unwrap().map(shown).collect()
    }

    #[test]
    fn a_directory_lists_its_entries_oldest_first() {
        let mut tree = booted();
        let root = [
            "Device/",
            "GLOBAL??/",
            "BaseNamedObjects/",
            "DosDevices>\\??",
            "Dangling>\\Device\\Gone",
            "DanglingDeep>\\Gone\\Deeper",
            "Relative>Device\\Null",
        ];
        assert_eq!(list(&tree, DirId::ROOT), root);
        let device = tree.entries(DirId::ROOT).unwrap().next().unwrap().1;
        let Found::Directory(device) = device else {
            panic!("\\Device is a directory");
        };
        assert_eq!(list(&tree, device), ["Null=1", "NamedPipe=2"]);
        // Removing one keeps the order of the others.
        object(&mut tree, "\\Device\\Beep", 4);
        tree.remove(None, &w("\\Device\\Null"), EXACT).unwrap();
        assert_eq!(list(&tree, device), ["NamedPipe=2", "Beep=4"]);
        let unknown = DirId {
            index: 99,
            serial: 1,
        };
        assert!(tree.entries(unknown).is_none());
    }

    #[test]
    fn a_removed_entry_is_gone_and_its_name_is_free() {
        let mut tree = booted();
        let null = w("\\Device\\Null");
        assert_eq!(tree.remove(None, &null, EXACT), Ok(Removed::Object(1)));
        assert_eq!(tree.remove(None, &null, EXACT), Err(Error::NameNotFound));
        // The link to it stays, and leads nowhere until it is back.
        check(&tree, ANY_CASE, &[("\\??\\NUL", Err(Error::NameNotFound))]);
        object(&mut tree, "\\Device\\Null", 30);
        check(&tree, ANY_CASE, &[("\\??\\NUL", ok("obj:30", ""))]);
        // A link at the end of the path is what is removed, by any of
        // its directory's names and, when asked, in any case.
        let nul = w("\\dosdevices\\nul");
        assert_eq!(tree.remove(None, &nul, EXACT), Err(Error::PathNotFound));
        assert_eq!(
            tree.remove(None, &nul, ANY_CASE),
            Ok(Removed::SymbolicLink(null.clone(), LINK))
        );
        check(&tree, ANY_CASE, &[("\\Device\\Null", ok("obj:30", ""))]);
        check(&tree, ANY_CASE, &[("\\??\\PIPE", ok("obj:2", ""))]);
        assert_eq!(tree.counts().total(), 12);
    }

    #[test]
    fn what_cannot_be_removed() {
        let mut tree = booted();
        let before = tree.counts();
        let cases = [
            ("\\", Error::NameInvalid),
            ("\\??", Error::NameInvalid),
            ("\\Device", Error::NotEmpty),
            ("\\GLOBAL??", Error::NotEmpty),
            ("\\Gone", Error::NameNotFound),
            ("\\Gone\\x", Error::PathNotFound),
            ("\\Device\\Null\\x", Error::TypeMismatch),
            ("\\Device\\", Error::NameInvalid),
            ("Device", Error::PathSyntaxBad),
            ("\\Dangling\\x", Error::PathNotFound),
        ];
        for (path, error) in cases {
            assert_eq!(tree.remove(None, &w(path), EXACT), Err(error), "{path:?}");
        }
        assert_eq!(tree.counts(), before);
    }

    #[test]
    fn a_removed_directory_s_id_names_nothing_again() {
        let mut tree = Tree::<u32>::new();
        let a = dir(&mut tree, "\\A");
        let b = dir(&mut tree, "\\B");
        assert_ne!(a, b);
        assert_eq!(tree.remove(None, &w("\\A"), EXACT), Ok(Removed::Directory));
        assert!(tree.entries(a).is_none());
        assert_eq!(look_from(&tree, a, ""), Err(Error::PathNotFound));
        assert_eq!(look_from(&tree, a, "x"), Err(Error::PathNotFound));
        assert_eq!(
            tree.insert_object(Some(a), &w("x"), EXACT, 1),
            Err(Error::PathNotFound)
        );
        // A new directory takes the old one's place in the table, and
        // the old id still names nothing.
        let c = dir(&mut tree, "\\C");
        assert_eq!(c.index, a.index);
        assert_ne!(c, a);
        assert!(tree.entries(a).is_none());
        assert_eq!(look_from(&tree, a, ""), Err(Error::PathNotFound));
        assert_eq!(look_from(&tree, c, ""), ok("dir:\\C", ""));
        assert_eq!(look_from(&tree, b, ""), ok("dir:\\B", ""));
    }

    #[test]
    fn removing_an_object_removes_all_its_names_and_only_those() {
        let mut tree = booted();
        object(&mut tree, "\\Device\\Null2", 1);
        object(&mut tree, "\\BaseNamedObjects\\Null", 1);
        object(&mut tree, "\\RootNull", 1);
        assert_eq!(tree.remove_object(&1), 4);
        assert_eq!(tree.remove_object(&1), 0);
        assert_eq!(tree.remove_object(&42), 0);
        let cases = [
            ("\\Device\\Null", Err(Error::NameNotFound)),
            ("\\RootNull", Err(Error::NameNotFound)),
            ("\\??\\NUL", Err(Error::NameNotFound)),
            ("\\Device\\NamedPipe", ok("obj:2", "")),
            ("\\BaseNamedObjects\\Ev", ok("obj:3", "")),
        ];
        check(&tree, ANY_CASE, &cases);
        assert_eq!(tree.counts().objects, 2);
        assert_eq!(tree.counts().symbolic_links, 7);
    }

    #[test]
    fn a_link_keeps_the_object_it_was_given() {
        let mut tree = booted();
        let at = w("\\DosDevices\\COM1");
        let target = w("\\Device\\Null");
        // The new name goes where the links on its path lead, and the
        // tree says where that is.
        let global = tree.dos_devices(ANY_CASE).unwrap();
        assert_eq!(
            tree.insert_link(None, &at, ANY_CASE, &target, 77),
            Ok(global)
        );
        let device = tree.insert_object(None, &w("\\Device\\Beep"), EXACT, 4);
        assert_eq!(
            device.map(|dir| dir_name(&tree, dir)),
            Ok("\\Device".into())
        );
        // Asked for the link itself, a look-up shows its object.
        let found = tree.lookup(None, &at, THE_LINK).map(|o| match o.found {
            Found::SymbolicLink(to, object) => (s(to), *object),
            _ => panic!("a link"),
        });
        assert_eq!(found, Ok(("\\Device\\Null".into(), 77)));
        assert_eq!(
            tree.remove(None, &at, ANY_CASE),
            Ok(Removed::SymbolicLink(target, 77))
        );
    }

    #[test]
    fn an_entry_added_and_removed_leaves_the_memory_as_it_was() {
        let mut tree = booted();
        let before = (tree.root.capacity(), tree.directories.capacity());
        assert_eq!(before, (tree.root.len(), tree.directories.len()));
        for round in 0..3 {
            dir(&mut tree, "\\Extra");
            object(&mut tree, "\\Extra\\X", round);
            link(&mut tree, "\\ExtraLink", "\\Extra");
            assert!(tree.root.capacity() > before.0);
            for path in ["\\Extra\\X", "\\Extra", "\\ExtraLink"] {
                tree.remove(None, &w(path), EXACT).expect(path);
            }
            assert_eq!((tree.root.capacity(), tree.directories.capacity()), before);
        }
    }

    #[test]
    fn an_emptied_tree_holds_no_memory() {
        let mut tree = booted();
        dir(&mut tree, "\\Device\\Sub");
        assert!(tree.root.capacity() >= 7);
        assert!(tree.directories.capacity() >= 4);
        for object in 1..=3 {
            assert_eq!(tree.remove_object(&object), 1);
        }
        let first = [
            "\\Device\\Sub",
            "\\Device",
            "\\GLOBAL??\\NUL",
            "\\GLOBAL??\\PIPE",
            "\\GLOBAL??\\Global",
        ];
        for path in first {
            tree.remove(None, &w(path), EXACT).expect(path);
        }
        // The table keeps a hole below a directory still in use.
        assert_eq!(tree.directories.len(), 3);
        let rest = [
            "\\BaseNamedObjects",
            "\\GLOBAL??",
            "\\DosDevices",
            "\\Dangling",
            "\\DanglingDeep",
            "\\Relative",
        ];
        for path in rest {
            tree.remove(None, &w(path), EXACT).expect(path);
        }
        assert_eq!(tree.counts().total(), 0);
        assert_eq!(tree.root.capacity(), 0);
        assert_eq!(tree.directories.capacity(), 0);
    }

    // A second, naive namespace to hold the tree to: every entry under
    // its full upper-case path in one flat list, and a look-up that
    // tries each prefix of the path in it.

    enum Kind {
        Directory,
        Link(String),
        Object(u32),
    }

    type Model = Vec<(String, Kind)>;

    fn naive(model: &Model, path: &str, open_link: bool, links: usize) -> Shown {
        if !path.starts_with('\\') {
            return Err(if links == 0 {
                Error::PathSyntaxBad
            } else {
                Error::NameNotFound
            });
        }
        if path == "\\" {
            return ok("dir:\\", "");
        }
        let mut key = String::new();
        let mut end = 0;
        let count = path[1..].split('\\').count();
        for (i, name) in path[1..].split('\\').enumerate() {
            if name.is_empty() {
                return Err(Error::NameInvalid);
            }
            key = format!("{key}\\{}", name.to_uppercase());
            end += 1 + name.len();
            let last = i + 1 == count;
            let rest = &path[end..];
            match model.iter().find(|(k, _)| *k == key) {
                None if last => return Err(Error::NameNotFound),
                None => return Err(Error::PathNotFound),
                Some((_, Kind::Directory)) if last => return ok(&format!("dir:{key}"), ""),
                Some((_, Kind::Directory)) => {}
                Some((_, Kind::Link(to))) if last && open_link => {
                    return ok(&format!("link:{to}"), "");
                }
                Some((_, Kind::Link(_))) if links == MAX_LINK_DEPTH => {
                    return Err(Error::TooManyLinks);
                }
                Some((_, Kind::Link(to))) => {
                    return naive(model, &format!("{to}{rest}"), open_link, links + 1);
                }
                Some((_, Kind::Object(object))) => return ok(&format!("obj:{object}"), rest),
            }
        }
        unreachable!("a path has a last name")
    }

    struct Random(u64);

    impl Random {
        fn below(&mut self, n: usize) -> usize {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (self.0 >> 33) as usize % n
        }

        /// One of four names, in either case.
        fn name(&mut self) -> &'static str {
            ["A", "B", "C", "D", "a", "b", "c", "d"][self.below(8)]
        }

        /// A path of up to `most` names; now and then malformed.
        fn path(&mut self, most: usize) -> String {
            let mut path = String::new();
            if self.below(12) != 0 {
                path.push('\\');
            }
            for i in 0..self.below(most + 1) {
                if i != 0 || self.below(12) == 0 {
                    path.push('\\');
                }
                path.push_str(self.name());
            }
            if self.below(8) == 0 {
                path.push('\\');
            }
            path
        }
    }

    #[test]
    fn lookups_agree_with_a_naive_model_on_generated_trees() {
        let (mut found, mut failed) = (0, 0);
        for seed in 0..300 {
            let mut random = Random(seed);
            let mut tree = Tree::new();
            let mut model = Model::new();
            let mut directories = vec![String::new()];
            for number in 0..14 {
                let parent = directories[random.below(directories.len())].clone();
                let name = random.name();
                let key = format!("{parent}\\{}", name.to_uppercase());
                let path = w(&format!("{parent}\\{name}"));
                let kind = match random.below(3) {
                    0 => Kind::Directory,
                    1 => Kind::Link(random.path(3)),
                    _ => Kind::Object(number),
                };
                let result = match &kind {
                    Kind::Directory => tree.create_directory(None, &path, ANY_CASE).map(|_| ()),
                    Kind::Link(to) => tree
                        .insert_link(None, &path, ANY_CASE, &w(to), LINK)
                        .map(|_| ()),
                    Kind::Object(object) => tree
                        .insert_object(None, &path, ANY_CASE, *object)
                        .map(|_| ()),
                };
                if model.iter().any(|(k, _)| *k == key) {
                    assert_eq!(result, Err(Error::Collision), "seed {seed}: {key}");
                    continue;
                }
                assert_eq!(result, Ok(()), "seed {seed}: {key}");
                if matches!(kind, Kind::Directory) {
                    directories.push(key.clone());
                }
                model.push((key, kind));
            }
            assert_eq!(tree.counts().total(), model.len());
            for _ in 0..60 {
                let path = random.path(4);
                let open_link = random.below(4) == 0;
                let options = Options {
                    open_link,
                    ..ANY_CASE
                };
                let got = look(&tree, &path, options).map(|(what, rest)| match what {
                    dir if dir.starts_with("dir:") => {
                        (dir.to_uppercase().replacen("DIR", "dir", 1), rest)
                    }
                    other => (other, rest),
                });
                let expected = naive(&model, &path, open_link, 0);
                assert_eq!(got, expected, "seed {seed}: {path:?} {open_link}");
                match got {
                    Ok(_) => found += 1,
                    Err(_) => failed += 1,
                }
            }
        }
        // The generator reaches both kinds of answer in quantity.
        assert!(found > 2000 && failed > 2000, "{found} {failed}");
    }
}
