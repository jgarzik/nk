//! Splay trees in a driver's memory: `RtlSplay` and `RtlDelete`, over
//! the rules of `nk_rtl::splay`.

#![allow(non_snake_case)]

use core::ptr::null_mut;
use nk_ntabi::rtl::RTL_SPLAY_LINKS;
use nk_rtl::splay::{self, Links};

/// The links of the nodes of one driver's tree, read and written in
/// place.
struct Tree(());

impl Tree {
    /// # Safety
    /// Every node reached through the links of the node the caller
    /// passes is the driver's valid `RTL_SPLAY_LINKS`, which nothing else
    /// changes while the tree is in use.
    unsafe fn new() -> Self {
        Tree(())
    }
}

type Node = *mut RTL_SPLAY_LINKS;

impl Links for Tree {
    type Node = Node;
    const NULL: Node = null_mut();
    fn parent(&self, n: Node) -> Node {
        // SAFETY: `Tree::new`'s contract: `n` is a node of the tree.
        unsafe { (&raw const (*n).Parent).read_unaligned() }
    }
    fn left(&self, n: Node) -> Node {
        // SAFETY: as `parent`.
        unsafe { (&raw const (*n).LeftChild).read_unaligned() }
    }
    fn right(&self, n: Node) -> Node {
        // SAFETY: as `parent`.
        unsafe { (&raw const (*n).RightChild).read_unaligned() }
    }
    fn set_parent(&mut self, n: Node, to: Node) {
        // SAFETY: as `parent`.
        unsafe { (&raw mut (*n).Parent).write_unaligned(to) }
    }
    fn set_left(&mut self, n: Node, to: Node) {
        // SAFETY: as `parent`.
        unsafe { (&raw mut (*n).LeftChild).write_unaligned(to) }
    }
    fn set_right(&mut self, n: Node, to: Node) {
        // SAFETY: as `parent`.
        unsafe { (&raw mut (*n).RightChild).write_unaligned(to) }
    }
}

/// [`RtlSplay`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlsplay):
/// make `links` the root of its tree; returns it.
///
/// # Safety
/// `links` is a node of a well-formed tree the caller holds.
pub unsafe extern "C" fn RtlSplay(links: Node) -> Node {
    // SAFETY: per the contract.
    let mut tree = unsafe { Tree::new() };
    splay::splay(&mut tree, links)
}

/// [`RtlDelete`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtldelete):
/// take `links` out of its tree; returns the new root, null if the tree
/// is empty.
///
/// # Safety
/// As [`RtlSplay`].
pub unsafe extern "C" fn RtlDelete(links: Node) -> Node {
    // SAFETY: per the contract.
    let mut tree = unsafe { Tree::new() };
    splay::delete(&mut tree, links)
}
