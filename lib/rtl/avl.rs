//! The balancing of an AVL tree whose nodes carry parent links, as the
//! [AVL generic table](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinitializegenerictableavl)
//! keeps them.
//!
//! The nodes are the caller's memory (in the kernel, a driver's
//! allocations), so this module holds none of them: it sees a node as a
//! nonzero handle and reads and writes its links through [`Links`]. Zero
//! is no node. A tree hangs from a sentinel, `head`, whose right child
//! is the root; the head's own parent and left child are not touched.
//!
//! A node's balance is the height of its right subtree less that of its
//! left: -1, 0 or 1 between operations.

use core::cmp::Ordering;

/// The links of the nodes of one tree.
pub trait Links {
    fn parent(&self, node: usize) -> usize;
    fn left(&self, node: usize) -> usize;
    fn right(&self, node: usize) -> usize;
    fn balance(&self, node: usize) -> i8;
    fn set_parent(&mut self, node: usize, to: usize);
    fn set_left(&mut self, node: usize, to: usize);
    fn set_right(&mut self, node: usize, to: usize);
    fn set_balance(&mut self, node: usize, to: i8);
}

/// Where a search ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Search {
    /// The node that compares equal.
    Found(usize),
    /// Not there: a new node would be `parent`'s left child if `left`,
    /// else its right child (for an empty tree, the head's right).
    Absent { parent: usize, left: bool },
}

/// Find the node for which `order` answers `Equal`. `order(node)` is how
/// the key sought compares with `node`'s element.
pub fn find<L: Links + ?Sized>(
    tree: &L,
    head: usize,
    mut order: impl FnMut(usize) -> Ordering,
) -> Search {
    let (mut parent, mut left, mut at) = (head, false, tree.right(head));
    while at != 0 {
        match order(at) {
            Ordering::Equal => return Search::Found(at),
            Ordering::Less => (parent, left, at) = (at, true, tree.left(at)),
            Ordering::Greater => (parent, left, at) = (at, false, tree.right(at)),
        }
    }
    Search::Absent { parent, left }
}

/// The number of nodes from the root down to `node`, both counted.
pub fn depth<L: Links + ?Sized>(tree: &L, head: usize, mut node: usize) -> u32 {
    let mut depth = 0;
    while node != head {
        depth += 1;
        node = tree.parent(node);
    }
    depth
}

/// Link `node` where a search left off, and restore the balance.
pub fn insert<L: Links + ?Sized>(
    tree: &mut L,
    head: usize,
    parent: usize,
    left: bool,
    node: usize,
) {
    tree.set_parent(node, parent);
    tree.set_left(node, 0);
    tree.set_right(node, 0);
    tree.set_balance(node, 0);
    if left {
        tree.set_left(parent, node);
    } else {
        tree.set_right(parent, node);
    }
    // Up from the new leaf: each subtree on the path is one taller
    // until one absorbs the growth or is rotated back to its height.
    let (mut child, mut at) = (node, parent);
    while at != head {
        let grew_left = tree.left(at) == child;
        let balance = tree.balance(at) + if grew_left { -1 } else { 1 };
        match balance {
            0 => {
                tree.set_balance(at, 0);
                return;
            }
            -1 | 1 => {
                tree.set_balance(at, balance);
                (child, at) = (at, tree.parent(at));
            }
            _ => {
                // After an insertion a rotation always restores the
                // subtree's former height.
                restore(tree, at, balance);
                return;
            }
        }
    }
}

/// Unlink `node`, and restore the balance.
pub fn remove<L: Links + ?Sized>(tree: &mut L, head: usize, node: usize) {
    let parent = tree.parent(node);
    let (left, right) = (tree.left(node), tree.right(node));
    // Where a subtree became one shorter, and on which side.
    let (mut at, mut shrank_left);
    if left != 0 && right != 0 {
        // The successor takes the node's place, balance and children.
        let mut next = right;
        while tree.left(next) != 0 {
            next = tree.left(next);
        }
        if next == right {
            (at, shrank_left) = (next, false);
        } else {
            let above = tree.parent(next);
            let below = tree.right(next);
            tree.set_left(above, below);
            if below != 0 {
                tree.set_parent(below, above);
            }
            tree.set_right(next, right);
            tree.set_parent(right, next);
            (at, shrank_left) = (above, true);
        }
        tree.set_left(next, left);
        tree.set_parent(left, next);
        tree.set_balance(next, tree.balance(node));
        tree.set_parent(next, parent);
        replace(tree, parent, node, next);
    } else {
        let child = if left != 0 { left } else { right };
        shrank_left = tree.left(parent) == node;
        replace(tree, parent, node, child);
        if child != 0 {
            tree.set_parent(child, parent);
        }
        at = parent;
    }
    while at != head {
        let balance = tree.balance(at) + if shrank_left { 1 } else { -1 };
        let above = tree.parent(at);
        let side = tree.left(above) == at;
        match balance {
            -1 | 1 => {
                // Its other side is still as tall: its height stands.
                tree.set_balance(at, balance);
                return;
            }
            0 => tree.set_balance(at, 0),
            _ => {
                if !restore(tree, at, balance) {
                    return;
                }
            }
        }
        (at, shrank_left) = (above, side);
    }
}

/// Put `new` in `old`'s place among `parent`'s children.
fn replace<L: Links + ?Sized>(tree: &mut L, parent: usize, old: usize, new: usize) {
    if tree.left(parent) == old {
        tree.set_left(parent, new);
    } else {
        tree.set_right(parent, new);
    }
}

/// Rotate `node`'s left child up into its place.
fn rotate_right<L: Links + ?Sized>(tree: &mut L, node: usize) -> usize {
    let (up, parent) = (tree.left(node), tree.parent(node));
    let across = tree.right(up);
    tree.set_left(node, across);
    if across != 0 {
        tree.set_parent(across, node);
    }
    tree.set_right(up, node);
    tree.set_parent(node, up);
    tree.set_parent(up, parent);
    replace(tree, parent, node, up);
    up
}

/// Rotate `node`'s right child up into its place.
fn rotate_left<L: Links + ?Sized>(tree: &mut L, node: usize) -> usize {
    let (up, parent) = (tree.right(node), tree.parent(node));
    let across = tree.left(up);
    tree.set_right(node, across);
    if across != 0 {
        tree.set_parent(across, node);
    }
    tree.set_left(up, node);
    tree.set_parent(node, up);
    tree.set_parent(up, parent);
    replace(tree, parent, node, up);
    up
}

/// Rebalance the subtree at `node`, whose balance has become `balance`
/// (-2 or 2). Returns whether the subtree is now one shorter than it was
/// before the change that unbalanced it grew or shrank it.
fn restore<L: Links + ?Sized>(tree: &mut L, node: usize, balance: i8) -> bool {
    // The heavy side's child, and the direction it leans (+1 for the
    // same way as `node`).
    let sign = balance.signum();
    let heavy = if sign < 0 {
        tree.left(node)
    } else {
        tree.right(node)
    };
    let lean = tree.balance(heavy) * sign;
    if lean >= 0 {
        // One rotation.
        if sign < 0 {
            rotate_right(tree, node);
        } else {
            rotate_left(tree, node);
        }
        if lean == 0 {
            // Only after a removal: the subtree keeps its height.
            tree.set_balance(node, sign);
            tree.set_balance(heavy, -sign);
            false
        } else {
            tree.set_balance(node, 0);
            tree.set_balance(heavy, 0);
            true
        }
    } else {
        // Two: the heavy child's inner child comes up over both.
        let inner = if sign < 0 {
            tree.right(heavy)
        } else {
            tree.left(heavy)
        };
        let leaning = tree.balance(inner) * sign;
        if sign < 0 {
            rotate_left(tree, heavy);
            rotate_right(tree, node);
        } else {
            rotate_right(tree, heavy);
            rotate_left(tree, node);
        }
        tree.set_balance(node, if leaning > 0 { -sign } else { 0 });
        tree.set_balance(heavy, if leaning < 0 { sign } else { 0 });
        tree.set_balance(inner, 0);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Node 0 is "none", node 1 the head; node `k + 2` holds key `k`.
    #[derive(Clone, Copy, Default)]
    struct Node {
        parent: usize,
        left: usize,
        right: usize,
        balance: i8,
    }

    struct Arena(Vec<Node>);

    const HEAD: usize = 1;

    impl Links for Arena {
        fn parent(&self, n: usize) -> usize {
            self.0[n].parent
        }
        fn left(&self, n: usize) -> usize {
            self.0[n].left
        }
        fn right(&self, n: usize) -> usize {
            self.0[n].right
        }
        fn balance(&self, n: usize) -> i8 {
            self.0[n].balance
        }
        fn set_parent(&mut self, n: usize, to: usize) {
            self.0[n].parent = to;
        }
        fn set_left(&mut self, n: usize, to: usize) {
            self.0[n].left = to;
        }
        fn set_right(&mut self, n: usize, to: usize) {
            self.0[n].right = to;
        }
        fn set_balance(&mut self, n: usize, to: i8) {
            self.0[n].balance = to;
        }
    }

    impl Arena {
        fn new(keys: usize) -> Self {
            let mut arena = Arena(vec![Node::default(); keys + 2]);
            arena.0[HEAD].parent = HEAD;
            arena
        }

        fn search(&self, key: usize) -> Search {
            find(self, HEAD, |n| key.cmp(&(n - 2)))
        }

        fn add(&mut self, key: usize) -> bool {
            match self.search(key) {
                Search::Found(_) => false,
                Search::Absent { parent, left } => {
                    insert(self, HEAD, parent, left, key + 2);
                    true
                }
            }
        }

        fn delete(&mut self, key: usize) -> bool {
            match self.search(key) {
                Search::Found(n) => {
                    remove(self, HEAD, n);
                    true
                }
                Search::Absent { .. } => false,
            }
        }

        /// Every invariant, and the keys in order.
        fn check(&self) -> Vec<usize> {
            assert_eq!(self.0[HEAD].left, 0, "the head has no left child");
            assert_eq!(self.0[HEAD].parent, HEAD, "the head is its own parent");
            let mut keys = Vec::new();
            let root = self.0[HEAD].right;
            if root != 0 {
                assert_eq!(self.0[root].parent, HEAD);
                self.height(root, &mut keys);
            }
            keys
        }

        fn height(&self, n: usize, keys: &mut Vec<usize>) -> i32 {
            let Node {
                left,
                right,
                balance,
                ..
            } = self.0[n];
            let tall = |child: usize, keys: &mut Vec<usize>| {
                if child == 0 {
                    return 0;
                }
                assert_eq!(self.0[child].parent, n, "parent link of {child}");
                self.height(child, keys)
            };
            let l = tall(left, keys);
            keys.push(n - 2);
            let r = tall(right, keys);
            assert_eq!(i32::from(balance), r - l, "balance of node {n}");
            assert!((-1..=1).contains(&balance), "node {n} is out of balance");
            1 + l.max(r)
        }
    }

    #[test]
    fn ascending_insertions_stay_balanced() {
        let mut tree = Arena::new(1000);
        for k in 0..1000 {
            assert!(tree.add(k));
        }
        assert_eq!(tree.check(), (0..1000).collect::<Vec<_>>());
        // 1000 nodes fit in an AVL tree of height at most 14.
        assert!(depth(&tree, HEAD, 999 + 2) <= 14);
        assert!(!tree.add(500), "a key already present is found");
    }

    #[test]
    fn removal_of_every_shape() {
        // A leaf, a node with one child, one with two whose successor is
        // its right child, and one whose successor is deeper.
        for victim in 0..15 {
            let mut tree = Arena::new(15);
            for k in [7, 3, 11, 1, 5, 9, 13, 0, 2, 4, 6, 8, 10, 12, 14] {
                tree.add(k);
            }
            assert!(tree.delete(victim));
            let expect: Vec<_> = (0..15).filter(|&k| k != victim).collect();
            assert_eq!(tree.check(), expect, "after removing {victim}");
            assert!(!tree.delete(victim));
        }
    }

    #[test]
    fn random_operations_agree_with_a_set() {
        let mut tree = Arena::new(256);
        let mut model = BTreeSet::new();
        // A fixed linear congruential sequence: the same run every time.
        let mut seed: u64 = 0x4E4B_0001;
        for _ in 0..20_000 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            let key = (seed >> 33) as usize % 256;
            if seed >> 63 == 0 {
                assert_eq!(tree.add(key), model.insert(key));
            } else {
                assert_eq!(tree.delete(key), model.remove(&key));
            }
        }
        assert_eq!(tree.check(), model.into_iter().collect::<Vec<_>>());
    }

    #[test]
    fn emptied_tree_has_no_root() {
        let mut tree = Arena::new(3);
        for k in 0..3 {
            tree.add(k);
        }
        for k in [1, 0, 2] {
            tree.delete(k);
        }
        assert_eq!(tree.0[HEAD].right, 0);
        assert_eq!(
            tree.search(1),
            Search::Absent {
                parent: HEAD,
                left: false
            }
        );
    }
}
