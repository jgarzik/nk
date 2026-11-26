//! The Unicode prefix table: the logic of
//! [`RtlInitializeUnicodePrefix`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinitializeunicodeprefix),
//! [`RtlInsertUnicodePrefix`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlinsertunicodeprefix),
//! [`RtlRemoveUnicodePrefix`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlremoveunicodeprefix)
//! and
//! [`RtlFindUnicodePrefix`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-rtlfindunicodeprefix).
//!
//! A file system keeps the path names it knows in such a table and asks
//! it which known name is the longest start, on a component boundary,
//! of a name being opened.
//!
//! # Whose memory
//!
//! The table and every entry are the driver's memory, with the fields
//! `ntifs.h` declares (`UNICODE_PREFIX_TABLE`,
//! `UNICODE_PREFIX_TABLE_ENTRY`); an entry points to the caller's name
//! and does not copy it. So nothing is kept here. The algorithm works
//! on a store of nodes it is handed ([`Nodes`]): the kernel's store
//! reads and writes the driver's fields through raw pointers, the
//! tests' is a vector. Nothing allocates and nothing can fail for want
//! of memory.
//!
//! # The structure, as the fields describe it
//!
//! - The entries are sorted into trees by how many components their
//!   names have ([`components`]; `NameLength`). The tree roots are a
//!   list through `NextPrefixTree`, longest names first, that starts
//!   and ends at the table, whose own `NameLength` is zero.
//! - A tree is a binary search tree through `Links`, ordered by
//!   [`compare`] without regard to case. Its root has the node type
//!   "root" and is its own parent; the others are "internal".
//! - Names that differ only in case share one place in the tree: one of
//!   them is in it and the rest ("case match") hang off it in a ring
//!   through `CaseMatch`. An entry alone is a ring of one.
//!
//! A search starts at the first tree whose names are no longer than
//! the name sought and goes on through shorter ones. A node found
//! without regard to case is moved to the root of its tree, so that
//! names used often are found soon.
//!
//! # INFERRED
//!
//! The documentation gives the outline (longest prefix; where the
//! comparison turns case-insensitive; a name already present is
//! refused), and the header the fields. These details are NK's reading,
//! to be checked against Windows:
//!
//! - a component boundary is a backslash in the name sought, right
//!   after the prefix; `\` alone starts every name that begins with a
//!   backslash; a name is its own prefix;
//! - a backslash sorts before every other character;
//! - `CaseInsensitiveIndex` counts characters; the units before it must
//!   be the same, those from it on the same in upper case;
//! - "already present" means the same units: a name that differs only
//!   in case is inserted. A search wholly without regard to case finds
//!   the one that is in the tree; one with a case-sensitive part tries
//!   the ring in order and, if none fits, goes on to shorter names;
//! - removing the name that is in the tree puts the next of its ring in
//!   its place;
//! - an empty name is refused (Windows does not expect one);
//! - which rotations rebalance a tree, and so the exact shape of the
//!   links, which no routine returns.

use crate::Text;
use crate::upcase::upcase_char;

const SEPARATOR: u16 = b'\\' as u16;

/// `NodeTypeCode` of a table (`RTL_NTC_UNICODE_PREFIX_TABLE`).
pub const NTC_TABLE: i16 = 0x0800;
/// Of the entry at the root of a tree (`RTL_NTC_UNICODE_ROOT`).
pub const NTC_ROOT: i16 = 0x0801;
/// Of any other entry in a tree (`RTL_NTC_UNICODE_INTERNAL`).
pub const NTC_INTERNAL: i16 = 0x0802;
/// Of an entry that hangs off one in a tree
/// (`RTL_NTC_UNICODE_CASE_MATCH`).
pub const NTC_CASE_MATCH: i16 = 0x0803;

/// The fields of a table and its entries. A `Node` names the table or
/// an entry: the table has the first three fields of an entry, where an
/// entry has them, and is treated as the entry that ends the list of
/// trees.
pub trait Nodes {
    type Node: Copy + PartialEq;
    type Name: Text;

    /// The table itself.
    fn table(&self) -> Self::Node;
    /// `NodeTypeCode`.
    fn kind(&self, node: Self::Node) -> i16;
    fn set_kind(&mut self, node: Self::Node, kind: i16);
    /// `NameLength`: the number of components.
    fn name_length(&self, node: Self::Node) -> i16;
    fn set_name_length(&mut self, node: Self::Node, length: i16);
    /// `NextPrefixTree`.
    fn next_tree(&self, node: Self::Node) -> Option<Self::Node>;
    fn set_next_tree(&mut self, node: Self::Node, next: Option<Self::Node>);
    /// `CaseMatch`.
    fn case_match(&self, entry: Self::Node) -> Self::Node;
    fn set_case_match(&mut self, entry: Self::Node, next: Self::Node);
    /// `Links.Parent`: a root's is itself.
    fn parent(&self, entry: Self::Node) -> Self::Node;
    fn set_parent(&mut self, entry: Self::Node, parent: Self::Node);
    /// `Links.LeftChild`.
    fn left(&self, entry: Self::Node) -> Option<Self::Node>;
    fn set_left(&mut self, entry: Self::Node, child: Option<Self::Node>);
    /// `Links.RightChild`.
    fn right(&self, entry: Self::Node) -> Option<Self::Node>;
    fn set_right(&mut self, entry: Self::Node, child: Option<Self::Node>);
    /// The name `Prefix` points to.
    fn name(&self, entry: Self::Node) -> Self::Name;
    /// Forget where an enumeration was (`LastNextEntry` of the table).
    fn forget_enumeration(&mut self);
}

/// How many components a name has: one, and one more for each
/// backslash before its last unit. `\a\b` has three, as has `\a\b\`.
pub fn components(name: &(impl Text + ?Sized)) -> i16 {
    let separators = (0..name.length().saturating_sub(1))
        .filter(|&at| name.unit(at) == SEPARATOR)
        .count();
    // A counted string is too short to have more.
    i16::try_from(separators + 1).unwrap_or(i16::MAX)
}

/// How a table's name stands to a name sought.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Comparison {
    Less,
    /// It starts the name sought and ends where a component does.
    Prefix,
    Equal,
    Greater,
}

/// Compare the name `prefix` with `name`. Units before
/// `case_insensitive_index` must be the same to be equal; later ones,
/// the same in upper case.
pub fn compare(
    prefix: &(impl Text + ?Sized),
    name: &(impl Text + ?Sized),
    case_insensitive_index: usize,
) -> Comparison {
    let (prefix_length, name_length) = (prefix.length(), name.length());
    // `\` alone starts every name that begins with one.
    if prefix_length == 1
        && prefix.unit(0) == SEPARATOR
        && name_length > 1
        && name.unit(0) == SEPARATOR
    {
        return Comparison::Prefix;
    }
    for at in 0..prefix_length.min(name_length) {
        let (mut x, mut y) = (prefix.unit(at), name.unit(at));
        if x != y && at >= case_insensitive_index {
            (x, y) = (upcase_char(x), upcase_char(y));
        }
        if x != y {
            // A backslash sorts before everything.
            return if x == SEPARATOR || (y != SEPARATOR && x < y) {
                Comparison::Less
            } else {
                Comparison::Greater
            };
        }
    }
    if prefix_length > name_length {
        Comparison::Greater
    } else if prefix_length == name_length {
        Comparison::Equal
    } else if name.unit(prefix_length) == SEPARATOR {
        Comparison::Prefix
    } else {
        Comparison::Less
    }
}

/// `RtlInitializeUnicodePrefix`: an empty table.
pub fn initialize<N: Nodes>(nodes: &mut N) {
    let table = nodes.table();
    nodes.set_kind(table, NTC_TABLE);
    nodes.set_name_length(table, 0);
    nodes.set_next_tree(table, Some(table));
    nodes.forget_enumeration();
}

/// The tree in the list whose `NextPrefixTree` is `root`.
fn tree_before<N: Nodes>(nodes: &N, root: N::Node) -> Option<N::Node> {
    let mut previous = nodes.table();
    loop {
        let next = nodes.next_tree(previous)?;
        if next == root {
            return Some(previous);
        }
        // Back at the table: `root` is not in the list.
        if next == nodes.table() {
            return None;
        }
        previous = next;
    }
}

/// Lift `node`, which is not a root, above its parent.
fn rotate<N: Nodes>(nodes: &mut N, node: N::Node) {
    let parent = nodes.parent(node);
    let grandparent = nodes.parent(parent);
    if nodes.left(parent) == Some(node) {
        let inner = nodes.right(node);
        nodes.set_left(parent, inner);
        if let Some(inner) = inner {
            nodes.set_parent(inner, parent);
        }
        nodes.set_right(node, Some(parent));
    } else {
        let inner = nodes.left(node);
        nodes.set_right(parent, inner);
        if let Some(inner) = inner {
            nodes.set_parent(inner, parent);
        }
        nodes.set_left(node, Some(parent));
    }
    nodes.set_parent(parent, node);
    if grandparent == parent {
        nodes.set_parent(node, node);
    } else {
        nodes.set_parent(node, grandparent);
        if nodes.left(grandparent) == Some(parent) {
            nodes.set_left(grandparent, Some(node));
        } else {
            nodes.set_right(grandparent, Some(node));
        }
    }
}

/// Rotate `node` to the top of the links it is in: a splay, which
/// halves the depth of the path it climbs.
fn splay<N: Nodes>(nodes: &mut N, node: N::Node) {
    loop {
        let parent = nodes.parent(node);
        if parent == node {
            return;
        }
        let grandparent = nodes.parent(parent);
        if grandparent != parent {
            let same_side =
                (nodes.left(grandparent) == Some(parent)) == (nodes.left(parent) == Some(node));
            // In line: the parent first. Bent: the node twice.
            rotate(nodes, if same_side { parent } else { node });
        }
        rotate(nodes, node);
    }
}

/// Make `node`, which is in a tree, that tree's root. None, with
/// nothing changed, if the tree is not in the table's list.
fn promote<N: Nodes>(nodes: &mut N, node: N::Node) -> Option<()> {
    let mut root = node;
    while nodes.parent(root) != root {
        root = nodes.parent(root);
    }
    if root == node {
        return Some(());
    }
    let before = tree_before(nodes, root)?;
    splay(nodes, node);
    let after = nodes.next_tree(root);
    nodes.set_kind(node, NTC_ROOT);
    nodes.set_next_tree(node, after);
    nodes.set_next_tree(before, Some(node));
    nodes.set_kind(root, NTC_INTERNAL);
    nodes.set_next_tree(root, None);
    Some(())
}

/// `RtlInsertUnicodePrefix`: add `entry`, whose name is already what
/// [`Nodes::name`] gives. False if the name is in the table, or empty,
/// or the table was never initialised.
pub fn insert<N: Nodes>(nodes: &mut N, entry: N::Node) -> bool {
    let name = nodes.name(entry);
    if name.length() == 0 {
        return false;
    }
    let length = components(&name);
    nodes.set_name_length(entry, length);
    nodes.set_parent(entry, entry);
    nodes.set_left(entry, None);
    nodes.set_right(entry, None);
    nodes.set_case_match(entry, entry);
    // The tree of names this long, or where it belongs in the list.
    let mut previous = nodes.table();
    let Some(mut tree) = nodes.next_tree(previous) else {
        return false;
    };
    while nodes.name_length(tree) > length {
        previous = tree;
        let Some(next) = nodes.next_tree(tree) else {
            return false;
        };
        tree = next;
    }
    if nodes.name_length(tree) != length {
        nodes.set_kind(entry, NTC_ROOT);
        nodes.set_next_tree(entry, Some(tree));
        nodes.set_next_tree(previous, Some(entry));
        return true;
    }
    nodes.set_next_tree(entry, None);
    let mut node = tree;
    loop {
        let leftwards = match compare(&nodes.name(node), &name, 0) {
            Comparison::Equal => {
                // The same but for case, at most: refused if one of the
                // ring is the same outright.
                let mut other = node;
                loop {
                    if compare(&nodes.name(other), &name, usize::MAX) == Comparison::Equal {
                        return false;
                    }
                    other = nodes.case_match(other);
                    if other == node {
                        break;
                    }
                }
                nodes.set_kind(entry, NTC_CASE_MATCH);
                let after = nodes.case_match(node);
                nodes.set_case_match(entry, after);
                nodes.set_case_match(node, entry);
                return true;
            }
            Comparison::Greater => true,
            Comparison::Less | Comparison::Prefix => false,
        };
        let below = if leftwards {
            nodes.left(node)
        } else {
            nodes.right(node)
        };
        match below {
            Some(child) => node = child,
            None => {
                nodes.set_kind(entry, NTC_INTERNAL);
                nodes.set_parent(entry, node);
                if leftwards {
                    nodes.set_left(node, Some(entry));
                } else {
                    nodes.set_right(node, Some(entry));
                }
                return true;
            }
        }
    }
}

/// `RtlFindUnicodePrefix`: the entry whose name is the longest prefix
/// of `full_name` that ends on a component boundary; the whole name
/// counts. Units before `case_insensitive_index` must be the same; from
/// there on, the same in upper case.
pub fn find<N: Nodes>(
    nodes: &mut N,
    full_name: &(impl Text + ?Sized),
    case_insensitive_index: usize,
) -> Option<N::Node> {
    if full_name.length() == 0 {
        return None;
    }
    let length = components(full_name);
    let mut tree = nodes.next_tree(nodes.table())?;
    while nodes.name_length(tree) > length {
        tree = nodes.next_tree(tree)?;
    }
    while nodes.name_length(tree) > 0 {
        // Before a node found takes the root's place in the list.
        let next = nodes.next_tree(tree);
        let mut at = Some(tree);
        while let Some(node) = at {
            at = match compare(&nodes.name(node), full_name, 0) {
                Comparison::Greater => nodes.left(node),
                Comparison::Less => nodes.right(node),
                Comparison::Prefix | Comparison::Equal => {
                    if case_insensitive_index == 0 {
                        promote(nodes, node);
                        return Some(node);
                    }
                    // Which of the names that differ in case, if any.
                    let mut other = node;
                    loop {
                        let exact = compare(&nodes.name(other), full_name, case_insensitive_index);
                        if matches!(exact, Comparison::Prefix | Comparison::Equal) {
                            return Some(other);
                        }
                        other = nodes.case_match(other);
                        if other == node {
                            break;
                        }
                    }
                    None
                }
            };
        }
        tree = next?;
    }
    None
}

/// `RtlRemoveUnicodePrefix`: take `entry`, which is in the table, out
/// of it.
pub fn remove<N: Nodes>(nodes: &mut N, entry: N::Node) {
    nodes.forget_enumeration();
    let kind = nodes.kind(entry);
    if !matches!(kind, NTC_ROOT | NTC_INTERNAL | NTC_CASE_MATCH) {
        // Not an entry of any table.
        return;
    }
    // The one before it in its ring, and the one after.
    let mut before = nodes.case_match(entry);
    while nodes.case_match(before) != entry {
        before = nodes.case_match(before);
    }
    let heir = nodes.case_match(entry);
    match kind {
        NTC_CASE_MATCH => nodes.set_case_match(before, heir),
        _ if heir != entry => {
            // The next of its ring takes its place in the tree.
            nodes.set_case_match(before, heir);
            let (left, right, parent) =
                (nodes.left(entry), nodes.right(entry), nodes.parent(entry));
            nodes.set_left(heir, left);
            nodes.set_right(heir, right);
            for child in [left, right].into_iter().flatten() {
                nodes.set_parent(child, heir);
            }
            if parent == entry {
                let Some(tree) = tree_before(nodes, entry) else {
                    return;
                };
                nodes.set_parent(heir, heir);
                nodes.set_next_tree(tree, Some(heir));
            } else {
                nodes.set_parent(heir, parent);
                if nodes.left(parent) == Some(entry) {
                    nodes.set_left(parent, Some(heir));
                } else {
                    nodes.set_right(parent, Some(heir));
                }
            }
            let next = nodes.next_tree(entry);
            nodes.set_kind(heir, kind);
            nodes.set_next_tree(heir, next);
        }
        _ => {
            // At the root, what is left is its two subtrees.
            if promote(nodes, entry).is_none() {
                return;
            }
            let Some(tree) = tree_before(nodes, entry) else {
                return;
            };
            let next = nodes.next_tree(entry);
            let root = match (nodes.left(entry), nodes.right(entry)) {
                (None, None) => {
                    nodes.set_next_tree(tree, next);
                    return;
                }
                (Some(only), None) | (None, Some(only)) => only,
                (Some(left), Some(right)) => {
                    // The largest of the left subtree, at its top, has
                    // no right child: the right subtree goes there.
                    nodes.set_parent(left, left);
                    let mut largest = left;
                    while let Some(larger) = nodes.right(largest) {
                        largest = larger;
                    }
                    splay(nodes, largest);
                    nodes.set_right(largest, Some(right));
                    nodes.set_parent(right, largest);
                    largest
                }
            };
            nodes.set_parent(root, root);
            nodes.set_kind(root, NTC_ROOT);
            nodes.set_next_tree(root, next);
            nodes.set_next_tree(tree, Some(root));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(s: &str) -> Vec<u16> {
        s.encode_utf16().collect()
    }

    impl Text for Vec<u16> {
        fn length(&self) -> usize {
            self.len()
        }
        fn unit(&self, at: usize) -> u16 {
            self[at]
        }
    }

    #[derive(Clone, Default)]
    struct Node {
        kind: i16,
        name_length: i16,
        next_tree: Option<usize>,
        case_match: usize,
        parent: usize,
        left: Option<usize>,
        right: Option<usize>,
        name: Vec<u16>,
    }

    /// A table in a vector: node 0 is the table, the rest entries. Every
    /// field starts as garbage, as a driver's memory does.
    struct Arena {
        nodes: Vec<Node>,
        enumeration: Option<usize>,
    }

    impl Arena {
        fn uninitialised() -> Self {
            Self {
                nodes: vec![Node::default()],
                enumeration: Some(77),
            }
        }

        fn new() -> Self {
            let mut arena = Self::uninitialised();
            initialize(&mut arena);
            arena
        }

        /// A new entry named `name`, not yet in the table.
        fn entry(&mut self, name: &str) -> usize {
            self.nodes.push(Node {
                kind: 0x7777,
                name_length: -3,
                next_tree: Some(usize::MAX),
                case_match: usize::MAX,
                parent: usize::MAX,
                left: Some(usize::MAX),
                right: Some(usize::MAX),
                name: w(name),
            });
            self.nodes.len() - 1
        }

        fn add(&mut self, name: &str) -> Option<usize> {
            let entry = self.entry(name);
            insert(self, entry).then_some(entry)
        }

        fn find(&mut self, name: &str, index: usize) -> Option<usize> {
            find(self, w(name).as_slice(), index)
        }

        /// The entries of the table, each tree's in order, having
        /// checked every rule of the structure.
        fn check(&self) -> Vec<usize> {
            let mut all = Vec::new();
            assert_eq!(self.nodes[0].kind, NTC_TABLE);
            assert_eq!(self.nodes[0].name_length, 0);
            let mut longer = i16::MAX;
            let mut tree = self.nodes[0].next_tree.unwrap();
            while tree != 0 {
                let root = &self.nodes[tree];
                assert_eq!(root.kind, NTC_ROOT);
                assert_eq!(root.parent, tree, "a root is its own parent");
                assert!(root.name_length > 0 && root.name_length < longer);
                longer = root.name_length;
                let from = all.len();
                self.walk(tree, root.name_length, &mut all);
                // In order, and no two alike but for case.
                for pair in all[from..].windows(2) {
                    let order = compare(&self.nodes[pair[0]].name, &self.nodes[pair[1]].name, 0);
                    assert!(
                        matches!(order, Comparison::Less | Comparison::Prefix),
                        "{:?} before {:?}",
                        self.nodes[pair[0]].name,
                        self.nodes[pair[1]].name
                    );
                }
                tree = root.next_tree.unwrap();
            }
            // Each ring: the same name but for case, marked as hanging.
            for at in 0..all.len() {
                let head = all[at];
                let mut other = self.nodes[head].case_match;
                while other != head {
                    let node = &self.nodes[other];
                    assert_eq!(node.kind, NTC_CASE_MATCH);
                    assert_eq!(node.name_length, self.nodes[head].name_length);
                    assert_eq!(
                        compare(&node.name, &self.nodes[head].name, 0),
                        Comparison::Equal
                    );
                    assert_ne!(node.name, self.nodes[head].name);
                    all.push(other);
                    other = node.case_match;
                }
            }
            all
        }

        fn walk(&self, at: usize, length: i16, all: &mut Vec<usize>) {
            let node = &self.nodes[at];
            assert_eq!(node.name_length, length);
            assert_eq!(components(&node.name), length);
            for child in [node.left, node.right].into_iter().flatten() {
                assert_eq!(self.nodes[child].parent, at);
                assert_eq!(self.nodes[child].kind, NTC_INTERNAL);
                assert_eq!(self.nodes[child].next_tree, None);
            }
            if let Some(left) = node.left {
                self.walk(left, length, all);
            }
            all.push(at);
            if let Some(right) = node.right {
                self.walk(right, length, all);
            }
        }

        /// The longest path from a root down.
        fn depth(&self, at: Option<usize>) -> usize {
            at.map_or(0, |at| {
                1 + self
                    .depth(self.nodes[at].left)
                    .max(self.depth(self.nodes[at].right))
            })
        }
    }

    impl Nodes for Arena {
        type Node = usize;
        type Name = Vec<u16>;

        fn table(&self) -> usize {
            0
        }
        fn kind(&self, node: usize) -> i16 {
            self.nodes[node].kind
        }
        fn set_kind(&mut self, node: usize, kind: i16) {
            self.nodes[node].kind = kind;
        }
        fn name_length(&self, node: usize) -> i16 {
            self.nodes[node].name_length
        }
        fn set_name_length(&mut self, node: usize, length: i16) {
            self.nodes[node].name_length = length;
        }
        fn next_tree(&self, node: usize) -> Option<usize> {
            self.nodes[node].next_tree
        }
        fn set_next_tree(&mut self, node: usize, next: Option<usize>) {
            self.nodes[node].next_tree = next;
        }
        fn case_match(&self, entry: usize) -> usize {
            self.nodes[entry].case_match
        }
        fn set_case_match(&mut self, entry: usize, next: usize) {
            self.nodes[entry].case_match = next;
        }
        fn parent(&self, entry: usize) -> usize {
            self.nodes[entry].parent
        }
        fn set_parent(&mut self, entry: usize, parent: usize) {
            self.nodes[entry].parent = parent;
        }
        fn left(&self, entry: usize) -> Option<usize> {
            self.nodes[entry].left
        }
        fn set_left(&mut self, entry: usize, child: Option<usize>) {
            self.nodes[entry].left = child;
        }
        fn right(&self, entry: usize) -> Option<usize> {
            self.nodes[entry].right
        }
        fn set_right(&mut self, entry: usize, child: Option<usize>) {
            self.nodes[entry].right = child;
        }
        fn name(&self, entry: usize) -> Vec<u16> {
            self.nodes[entry].name.clone()
        }
        fn forget_enumeration(&mut self) {
            self.enumeration = None;
        }
    }

    #[test]
    fn names_are_counted_in_components() {
        for (name, expected) in [
            ("\\", 1),
            ("a", 1),
            ("\\a", 2),
            ("a\\b", 2),
            ("\\a\\b", 3),
            ("\\a\\b\\", 3),
            ("\\\\", 2),
            ("", 1),
        ] {
            assert_eq!(components(w(name).as_slice()), expected, "{name}");
        }
        assert_eq!(components(vec![SEPARATOR; 40_000].as_slice()), i16::MAX);
    }

    #[test]
    fn names_compare_by_component() {
        use Comparison::*;
        for (prefix, name, index, expected) in [
            ("\\a", "\\a", 0, Equal),
            ("\\a", "\\a\\b", 0, Prefix),
            ("\\a", "\\ab", 0, Less),
            ("\\ab", "\\a", 0, Greater),
            ("\\a\\b", "\\a", 0, Greater),
            ("\\b", "\\a", 0, Greater),
            ("\\a", "\\b", 0, Less),
            // A backslash sorts before everything, on either side.
            ("\\a\\b", "\\a!b", 0, Less),
            ("\\a!b", "\\a\\b", 0, Greater),
            // `\` alone starts whatever begins with a backslash.
            ("\\", "\\", 0, Equal),
            ("\\", "\\zzz", 0, Prefix),
            ("\\", "zzz", 0, Less),
            ("z", "\\", 0, Greater),
            // Case: by the upper-case table from the index on.
            ("\\a", "\\A\\b", 0, Prefix),
            ("\\a", "\\A\\b", 1, Prefix),
            ("\\a", "\\A\\b", 2, Greater),
            ("\\A", "\\a\\b", 2, Less),
            ("\\a", "\\A\\b", usize::MAX, Greater),
            ("\\\u{E9}", "\\\u{C9}", 0, Equal),
            ("\\\u{E9}", "\\\u{C9}", 9, Greater),
            // Letters that differ are ordered in upper case.
            ("\\a", "\\B", 0, Less),
            ("\\b", "\\A", 0, Greater),
        ] {
            assert_eq!(
                compare(w(prefix).as_slice(), w(name).as_slice(), index),
                expected,
                "{prefix} against {name} from {index}"
            );
        }
    }

    /// The calls of the conformance driver `nkc-rtl`, and what its
    /// source predicts of Windows.
    #[test]
    fn the_conformance_drivers_table() {
        let mut t = Arena::uninitialised();
        initialize(&mut t);
        assert_eq!((t.nodes[0].kind, t.enumeration), (0x0800, None));
        assert_eq!(t.find("\\a", 0), None);
        let one = t.add("\\a").unwrap();
        let two = t.add("\\a\\b").unwrap();
        let three = t.add("\\a\\b\\c").unwrap();
        let four = t.add("\\x").unwrap();
        assert_eq!(t.add("\\a"), None, "a second time");
        t.check();
        for (full, index, expected) in [
            ("\\a\\b\\c\\d", 0, Some(three)),
            ("\\a\\b\\c", 0, Some(three)),
            ("\\a\\b", 0, Some(two)),
            ("\\a\\bc", 0, Some(one)),
            ("\\a", 0, Some(one)),
            ("\\ab", 0, None),
            ("\\y", 0, None),
            ("\\x\\a\\b", 0, Some(four)),
            ("a\\b", 0, None),
            ("\\a\\b\\", 0, Some(two)),
            // Letter case.
            ("\\A\\B\\X", 0, Some(two)),
            ("\\A\\B\\X", 100, None),
            ("\\a\\B\\X", 100, Some(one)),
            ("\\a\\B", 3, Some(two)),
            ("\\a\\B", 6, Some(one)),
            ("", 0, None),
        ] {
            assert_eq!(t.find(full, index), expected, "{full} from {index}");
            t.check();
        }
        remove(&mut t, two);
        assert_eq!(t.find("\\a\\b\\c\\d", 0), Some(three));
        assert_eq!(t.find("\\a\\b", 0), Some(one));
        remove(&mut t, three);
        assert_eq!(t.find("\\a\\b\\c\\d", 0), Some(one));
        // `\` alone.
        let root = t.add("\\").unwrap();
        assert_eq!(t.find("\\zzz", 0), Some(root));
        assert_eq!(t.find("\\x\\y", 0), Some(four));
        assert_eq!(t.find("\\a\\q", 0), Some(one));
        assert_eq!(t.find("zzz", 0), None);
        // Names that differ in case are different names.
        let capital = t.add("\\X").unwrap();
        assert_eq!(t.nodes[capital].kind, NTC_CASE_MATCH);
        assert_eq!(t.find("\\X", 100), Some(capital));
        assert_eq!(t.find("\\x", 100), Some(four));
        // Without regard to case: the one that is in the tree.
        assert_eq!(t.find("\\x", 0), Some(four));
        assert_eq!(t.find("\\X", 0), Some(four));
        t.check();
        remove(&mut t, four);
        t.check();
        assert_eq!(t.find("\\x\\y", 100), Some(root));
        assert_eq!(t.find("\\x\\y", 0), Some(capital));
        for entry in [one, capital, root] {
            remove(&mut t, entry);
            t.check();
        }
        assert_eq!(t.find("\\a", 0), None);
        assert_eq!(t.find("\\", 0), None);
        assert_eq!(t.nodes[0].next_tree, Some(0), "empty again");
    }

    #[test]
    fn a_name_already_there_or_empty_is_refused() {
        let mut t = Arena::new();
        let small = t.add("\\a").unwrap();
        assert_eq!(t.add(""), None);
        assert_eq!(t.add("\\a"), None);
        let big = t.add("\\A").unwrap();
        // The same as one that hangs off the tree.
        assert_eq!(t.add("\\A"), None);
        assert_eq!(t.check(), [small, big]);
        // A removed name can be inserted again.
        remove(&mut t, small);
        assert_eq!(t.check(), [big]);
        assert_eq!(t.nodes[big].kind, NTC_ROOT);
        let again = t.add("\\a").unwrap();
        assert_eq!(t.find("\\a\\x", 2), Some(again));
        assert_eq!(t.find("\\a\\x", 0), Some(big));
    }

    #[test]
    fn a_ring_is_tried_in_order_and_survives_removals() {
        let mut t = Arena::new();
        let other = t.add("\\m").unwrap();
        let names = ["\\ab", "\\AB", "\\Ab", "\\aB"];
        let ring: Vec<usize> = names.iter().map(|n| t.add(n).unwrap()).collect();
        t.check();
        for (name, &entry) in names.iter().zip(&ring) {
            assert_eq!(t.find(name, 9), Some(entry), "{name}");
            assert_eq!(t.find(name, 0), Some(ring[0]), "{name}");
        }
        assert_eq!(t.find("\\ab\\x", 2), Some(ring[0]), "the first that fits");
        assert_eq!(t.find("\\Ab\\x", 2), Some(ring[2]));
        // One from the middle of the ring.
        remove(&mut t, ring[2]);
        t.check();
        assert_eq!(t.find("\\Ab", 9), None);
        assert_eq!(t.find("\\Ab", 2), Some(ring[1]), "another that fits");
        // The one in the tree, which is not the root: the newest of the
        // ring takes its place.
        assert_eq!(t.find("\\m", 0), Some(other));
        assert_eq!(t.nodes[ring[0]].kind, NTC_INTERNAL);
        remove(&mut t, ring[0]);
        t.check();
        assert_eq!(t.nodes[ring[3]].kind, NTC_INTERNAL);
        assert_eq!(t.find("\\ab", 0), Some(ring[3]));
        // Found without regard to case, it is the root now; removed
        // from there, the last of the ring is.
        assert_eq!(t.nodes[ring[3]].kind, NTC_ROOT);
        remove(&mut t, ring[3]);
        assert_eq!(t.check(), [ring[1], other]);
        assert_eq!(t.nodes[ring[1]].kind, NTC_ROOT);
        assert_eq!(t.nodes[ring[1]].case_match, ring[1]);
        assert_eq!(t.find("\\m", 0), Some(other));
    }

    #[test]
    fn a_name_found_moves_to_the_root() {
        let mut t = Arena::new();
        // In order: a tree that is one long path.
        let names: Vec<String> = (0..64).map(|i| format!("\\{i:02}")).collect();
        let entries: Vec<usize> = names.iter().map(|n| t.add(n).unwrap()).collect();
        let root = |t: &Arena| t.nodes[0].next_tree;
        assert_eq!(t.depth(root(&t)), 64);
        assert_eq!(t.find("\\63\\x", 0), Some(entries[63]));
        assert_eq!(root(&t), Some(entries[63]));
        assert_eq!(t.nodes[entries[0]].kind, NTC_INTERNAL);
        assert!(t.depth(root(&t)) <= 34, "the path it climbed is halved");
        // A search with a case-sensitive part moves nothing.
        assert_eq!(t.find("\\07", 1), Some(entries[7]));
        assert_eq!(root(&t), Some(entries[63]));
        t.check();
        // Every name is still found, and the table stays sound, as
        // roots change.
        for (name, &entry) in names.iter().zip(&entries) {
            assert_eq!(t.find(name, 0), Some(entry));
            assert_eq!(root(&t), Some(entry));
            assert_eq!(t.check().len(), 64);
        }
        // Removed from every position of a tree.
        for &entry in entries.iter().step_by(3) {
            remove(&mut t, entry);
            t.check();
        }
        for (at, (name, &entry)) in names.iter().zip(&entries).enumerate() {
            assert_eq!(t.find(name, 0), (at % 3 != 0).then_some(entry));
        }
    }

    #[test]
    fn a_table_never_initialised_holds_nothing() {
        let mut t = Arena::uninitialised();
        assert_eq!(t.add("\\a"), None);
        assert_eq!(t.find("\\a", 0), None);
        // A list of trees that breaks off.
        let mut t = Arena::new();
        let long = t.add("\\a\\b").unwrap();
        t.nodes[long].next_tree = None;
        assert_eq!(t.add("\\a"), None);
        assert_eq!(t.find("\\a", 0), None);
        assert_eq!(t.find("\\a\\b\\c\\d", 0), Some(long));
        assert_eq!(t.find("\\x\\y\\z", 0), None);
        // An entry whose tree the table does not list is left alone.
        let mut t = Arena::new();
        let (a, b) = (t.add("\\a").unwrap(), t.add("\\b").unwrap());
        t.nodes[0].next_tree = Some(0);
        remove(&mut t, b);
        remove(&mut t, a);
        assert_eq!((t.nodes[a].right, t.nodes[b].parent), (Some(b), a));
        let capital = t.entry("\\A");
        t.nodes[0].next_tree = Some(a);
        assert!(insert(&mut t, capital));
        t.nodes[0].next_tree = Some(0);
        remove(&mut t, a);
        assert_eq!(t.nodes[capital].kind, NTC_CASE_MATCH);
        // What is no entry at all.
        let stray = t.entry("\\s");
        remove(&mut t, stray);
        assert_eq!(t.nodes[stray].kind, 0x7777);
    }

    /// The table as plain lists, searched the slow way: for each number
    /// of components, the names in groups that are alike but for case,
    /// each group in the order its ring is tried.
    #[derive(Default)]
    struct Model(Vec<Vec<(Vec<u16>, usize)>>);

    impl Model {
        fn insert(&mut self, name: &[u16], handle: usize) -> bool {
            if name.is_empty() || self.0.iter().flatten().any(|(n, _)| n == name) {
                return false;
            }
            let alike = self
                .0
                .iter_mut()
                .find(|group| compare(group[0].0.as_slice(), name, 0) == Comparison::Equal);
            match alike {
                // Right after the one in the tree.
                Some(group) => group.insert(1, (name.to_vec(), handle)),
                None => self.0.push(vec![(name.to_vec(), handle)]),
            }
            true
        }

        fn remove(&mut self, handle: usize) {
            for group in &mut self.0 {
                group.retain(|(_, h)| *h != handle);
            }
            self.0.retain(|group| !group.is_empty());
        }

        fn find(&self, full: &[u16], index: usize) -> Option<usize> {
            let starts = |name: &[u16], index| {
                matches!(
                    compare(name, full, index),
                    Comparison::Prefix | Comparison::Equal
                )
            };
            let mut groups: Vec<_> = self
                .0
                .iter()
                .filter(|group| starts(&group[0].0, 0))
                .collect();
            // Longest first; no two groups of one length start a name.
            groups.sort_by_key(|group| core::cmp::Reverse(components(group[0].0.as_slice())));
            for pair in groups.windows(2) {
                assert_ne!(
                    components(pair[0][0].0.as_slice()),
                    components(pair[1][0].0.as_slice())
                );
            }
            groups.into_iter().find_map(|group| {
                group
                    .iter()
                    .find(|(name, _)| index == 0 || starts(name, index))
                    .map(|(_, handle)| *handle)
            })
        }
    }

    #[test]
    fn random_sequences_agree_with_plain_lists() {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        let mut random = |below: usize| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) as usize % below
        };
        let (mut finds, mut hanging) = (0, 0);
        for _ in 0..300 {
            let (mut t, mut model) = (Arena::new(), Model::default());
            let mut live: Vec<usize> = Vec::new();
            for step in 0..80 {
                // `\` alone, or up to three components of one or two
                // letters, absolute or relative.
                let mut name = String::new();
                if random(12) == 0 {
                    name.push('\\');
                } else {
                    for part in 0..1 + random(3) {
                        if part > 0 || random(8) != 0 {
                            name.push('\\');
                        }
                        for _ in 0..1 + random(2) {
                            name.push(['a', 'A', 'b', 'B', 'c'][random(5)]);
                        }
                    }
                }
                match random(5) {
                    0 | 1 => {
                        let entry = t.entry(&name);
                        let inserted = insert(&mut t, entry);
                        assert_eq!(inserted, model.insert(&w(&name), entry), "{name}");
                        if inserted {
                            live.push(entry);
                            hanging += usize::from(t.nodes[entry].kind == NTC_CASE_MATCH);
                        }
                    }
                    2 if !live.is_empty() => {
                        let entry = live.swap_remove(random(live.len()));
                        remove(&mut t, entry);
                        model.remove(entry);
                    }
                    _ => {
                        let index = [0, 0, 1, 2, 3, 99][random(6)];
                        let (got, expected) = (t.find(&name, index), model.find(&w(&name), index));
                        assert_eq!(got, expected, "step {step}: {name} from {index}");
                        finds += usize::from(got.is_some());
                    }
                }
                let mut listed = t.check();
                listed.sort_unstable();
                live.sort_unstable();
                assert_eq!(listed, live);
            }
        }
        assert!(finds > 2000, "the sequences must find names: {finds}");
        assert!(
            hanging > 200,
            "and insert names alike but for case: {hanging}"
        );
    }
}
