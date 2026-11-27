//! Splay trees (`RTL_SPLAY_LINKS`): [`RtlSplay`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlsplay)
//! and [`RtlDelete`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtldelete).
//!
//! The links are the caller's, in nodes it allocates and orders itself
//! (a file system's tree of names): each has a parent, a left and a
//! right child; the root is its own parent and a missing child is null.
//! Splaying moves a node to the root by rotations that keep the order;
//! deleting takes a node out, a node with two children first trading
//! places with the one before it in order, and splays what was its
//! parent. Which shape the tree takes is no caller's concern: only
//! the order, and the node returned as the root.
//!
//! [`Links`] reads and writes the three links of a node; the kernel binds
//! it to the driver's memory, the tests to an array.

/// A tree's links.
pub trait Links {
    /// A node; [`Links::NULL`] is none.
    type Node: Copy + Eq;
    const NULL: Self::Node;
    fn parent(&self, n: Self::Node) -> Self::Node;
    fn left(&self, n: Self::Node) -> Self::Node;
    fn right(&self, n: Self::Node) -> Self::Node;
    fn set_parent(&mut self, n: Self::Node, to: Self::Node);
    fn set_left(&mut self, n: Self::Node, to: Self::Node);
    fn set_right(&mut self, n: Self::Node, to: Self::Node);
}

fn is_root<L: Links>(t: &L, n: L::Node) -> bool {
    t.parent(n) == n
}

/// Put `child` where `old` hung from `parent` (`old`'s parent), or make
/// it the root if `old` was.
fn replace_child<L: Links>(t: &mut L, old: L::Node, child: L::Node) {
    if is_root(t, old) {
        if child != L::NULL {
            t.set_parent(child, child);
        }
        return;
    }
    let parent = t.parent(old);
    if t.left(parent) == old {
        t.set_left(parent, child);
    } else {
        t.set_right(parent, child);
    }
    if child != L::NULL {
        t.set_parent(child, parent);
    }
}

/// Rotate `x` above its parent.
fn rotate<L: Links>(t: &mut L, x: L::Node) {
    let p = t.parent(x);
    let grand_root = is_root(t, p);
    let g = t.parent(p);
    if t.left(p) == x {
        let b = t.right(x);
        t.set_left(p, b);
        if b != L::NULL {
            t.set_parent(b, p);
        }
        t.set_right(x, p);
    } else {
        let b = t.left(x);
        t.set_right(p, b);
        if b != L::NULL {
            t.set_parent(b, p);
        }
        t.set_left(x, p);
    }
    t.set_parent(p, x);
    if grand_root {
        t.set_parent(x, x);
    } else {
        if t.left(g) == p {
            t.set_left(g, x);
        } else {
            t.set_right(g, x);
        }
        t.set_parent(x, g);
    }
}

/// `RtlSplay`: make `x` the root; returns it.
pub fn splay<L: Links>(t: &mut L, x: L::Node) -> L::Node {
    while !is_root(t, x) {
        let p = t.parent(x);
        if is_root(t, p) {
            rotate(t, x);
        } else {
            let g = t.parent(p);
            let zig_zig = (t.left(g) == p) == (t.left(p) == x);
            if zig_zig {
                rotate(t, p);
            } else {
                rotate(t, x);
            }
            rotate(t, x);
        }
    }
    x
}

/// The rightmost node under `n`.
fn rightmost<L: Links>(t: &L, mut n: L::Node) -> L::Node {
    while t.right(n) != L::NULL {
        n = t.right(n);
    }
    n
}

/// Trade the places of `a` and `b`, where `b` is under `a`'s left
/// subtree, so the tree is the same with the two nodes swapped.
fn swap<L: Links>(t: &mut L, a: L::Node, b: L::Node) {
    let a_root = is_root(t, a);
    let (a_parent, a_left, a_right) = (t.parent(a), t.left(a), t.right(a));
    let (b_parent, b_left, b_right) = (t.parent(b), t.left(b), t.right(b));
    // b takes a's place.
    if a_root {
        t.set_parent(b, b);
    } else {
        if t.left(a_parent) == a {
            t.set_left(a_parent, b);
        } else {
            t.set_right(a_parent, b);
        }
        t.set_parent(b, a_parent);
    }
    t.set_right(b, a_right);
    if a_right != L::NULL {
        t.set_parent(a_right, b);
    }
    if b_parent == a {
        // b was a's left child.
        t.set_left(b, a);
        t.set_parent(a, b);
    } else {
        t.set_left(b, a_left);
        t.set_parent(a_left, b);
        t.set_right(b_parent, a);
        t.set_parent(a, b_parent);
    }
    // a takes b's links below.
    t.set_left(a, b_left);
    if b_left != L::NULL {
        t.set_parent(b_left, a);
    }
    t.set_right(a, b_right);
    if b_right != L::NULL {
        t.set_parent(b_right, a);
    }
}

/// `RtlDelete`: take `x` out of its tree; returns the new root, or
/// [`Links::NULL`] if the tree is now empty.
pub fn delete<L: Links>(t: &mut L, x: L::Node) -> L::Node {
    if t.left(x) != L::NULL && t.right(x) != L::NULL {
        let before = rightmost(t, t.left(x));
        swap(t, x, before);
    }
    let child = if t.left(x) != L::NULL {
        t.left(x)
    } else {
        t.right(x)
    };
    if is_root(t, x) {
        replace_child(t, x, child);
        return child;
    }
    let parent = t.parent(x);
    replace_child(t, x, child);
    splay(t, parent)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nodes in an array; 0 is null, a node's key is its index.
    struct Arena {
        links: std::vec::Vec<[usize; 3]>,
    }

    impl Links for Arena {
        type Node = usize;
        const NULL: usize = 0;
        fn parent(&self, n: usize) -> usize {
            self.links[n][0]
        }
        fn left(&self, n: usize) -> usize {
            self.links[n][1]
        }
        fn right(&self, n: usize) -> usize {
            self.links[n][2]
        }
        fn set_parent(&mut self, n: usize, to: usize) {
            self.links[n][0] = to;
        }
        fn set_left(&mut self, n: usize, to: usize) {
            self.links[n][1] = to;
        }
        fn set_right(&mut self, n: usize, to: usize) {
            self.links[n][2] = to;
        }
    }

    impl Arena {
        fn new(n: usize) -> Self {
            Arena {
                links: std::vec![[0; 3]; n + 1],
            }
        }

        /// Insert `k` as a plain search-tree insert (as a file system
        /// does with the macros), then splay it.
        fn insert(&mut self, root: usize, k: usize) -> usize {
            self.links[k] = [k, 0, 0];
            if root == 0 {
                return k;
            }
            let mut n = root;
            loop {
                let next = if k < n { self.left(n) } else { self.right(n) };
                if next == 0 {
                    if k < n {
                        self.set_left(n, k);
                    } else {
                        self.set_right(n, k);
                    }
                    self.set_parent(k, n);
                    break;
                }
                n = next;
            }
            splay(self, k)
        }

        fn in_order(&self, n: usize, out: &mut std::vec::Vec<usize>) {
            if n == 0 {
                return;
            }
            self.in_order(self.left(n), out);
            out.push(n);
            self.in_order(self.right(n), out);
        }

        /// Every child's parent link points back, the root is its own
        /// parent, and the order holds.
        fn check(&self, root: usize) -> std::vec::Vec<usize> {
            if root != 0 {
                assert_eq!(self.parent(root), root);
            }
            let mut out = std::vec::Vec::new();
            self.in_order(root, &mut out);
            for &n in &out {
                for c in [self.left(n), self.right(n)] {
                    if c != 0 {
                        assert_eq!(self.parent(c), n);
                    }
                }
            }
            assert!(out.windows(2).all(|w| w[0] < w[1]));
            out
        }
    }

    const KEYS: [usize; 12] = [7, 3, 11, 1, 5, 9, 12, 2, 4, 6, 8, 10];

    fn tree() -> (Arena, usize) {
        let mut a = Arena::new(12);
        let mut root = 0;
        for k in KEYS {
            root = a.insert(root, k);
            assert_eq!(root, k);
        }
        (a, root)
    }

    #[test]
    fn splay_brings_a_node_to_the_root_and_keeps_the_order() {
        let (mut a, _) = tree();
        for k in [1, 12, 6, 7, 2, 10] {
            assert_eq!(splay(&mut a, k), k);
            assert_eq!(a.check(k), (1..=12).collect::<std::vec::Vec<_>>());
        }
    }

    #[test]
    fn delete_every_node_in_turn() {
        for order in [
            KEYS,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            [12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
        ] {
            let (mut a, mut root) = tree();
            let mut left: std::vec::Vec<usize> = (1..=12).collect();
            for k in order {
                root = delete(&mut a, k);
                left.retain(|&n| n != k);
                assert_eq!(a.check(root), left);
            }
            assert_eq!(root, 0);
        }
    }

    #[test]
    fn delete_a_node_with_two_children_whose_predecessor_is_its_child() {
        let mut a = Arena::new(3);
        a.links[2] = [2, 1, 3];
        a.links[1] = [2, 0, 0];
        a.links[3] = [2, 0, 0];
        let root = delete(&mut a, 2);
        assert_eq!(a.check(root), [1, 3]);
    }
}
