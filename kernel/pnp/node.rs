//! Device nodes: what the Plug and Play manager knows of each device,
//! and how the devices hang together.
//!
//! A node is NK's own structure. Windows keeps a `DEVICE_NODE` that a
//! physical device object's `DeviceObjectExtension->DeviceNode` points
//! to, and Microsoft's drivers read the front of it (`partmgr.sys`
//! follows `Parent` to the parent's device). Each node has one, a pool
//! block of Windows' size (`nk_ntabi::pnp::DEVICE_NODE`) whose tree
//! links and device NK keeps as the tree changes, under the tree's
//! lock; the rest of it is zero. NK never reads it back: a node is
//! found by its device's address in the tree.
//!
//! The tree is one list under one lock, [`TREE`]. Nodes change only in
//! the hands of the thread that holds the engine's mutex
//! (`super::engine`); the lock is what lets every other thread read a
//! node while that goes on. It is held for a copy in or out, never
//! across a call.

use crate::ke::{Rank, SpinLock};
use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::mem::size_of;
use nk_ntabi::io::DEVICE_OBJECT;
use nk_ntabi::pnp::DEVICE_NODE;

/// How far a device has come.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Reported by its bus; nothing has been asked of it.
    New,
    /// Its identifiers are known and its key exists; its drivers have
    /// not been added.
    Identified,
    /// Its drivers have attached their devices.
    Stacked,
    /// Started.
    Started,
    /// Surprise-removed (`IRP_MN_SURPRISE_REMOVAL` delivered); awaiting
    /// closure of open file handles in its subtree before `IRP_MN_REMOVE_DEVICE`.
    SurpriseRemoved,
    /// Orderly removal requested while a descendant is deferred awaiting open
    /// handle closure; interfaces are disabled and `IRP_MN_REMOVE_DEVICE` runs
    /// once its children are removed.
    RemovePending,
    /// Not started, and not to be tried again: `problem` says why.
    Failed,
}

/// Windows' problem codes
/// ([`CM_PROB_*`](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/device-manager-error-messages)),
/// those NK gives.
pub const PROBLEM_NONE: u32 = 0;
pub const CM_PROB_OUT_OF_MEMORY: u32 = 3;
pub const CM_PROB_INVALID_DATA: u32 = 9;
pub const CM_PROB_FAILED_START: u32 = 10;
pub const CM_PROB_NORMAL_CONFLICT: u32 = 12;
pub const CM_PROB_FAILED_INSTALL: u32 = 28;
pub const CM_PROB_FAILED_ADD: u32 = 31;
pub const CM_PROB_DISABLED_SERVICE: u32 = 32;
pub const CM_PROB_FAILED_DRIVER_ENTRY: u32 = 37;
pub const CM_PROB_DRIVER_FAILED_LOAD: u32 = 39;
pub const CM_PROB_DUPLICATE_DEVICE: u32 = 42;
pub const CM_PROB_FAILED_POST_START: u32 = 43;
pub const CM_PROB_WAITING_ON_DEPENDENCY: u32 = 51;

/// What a bus driver answered `IRP_MN_QUERY_BUS_INFORMATION` with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BusInformation {
    pub bus_type: [u8; 16],
    pub legacy_bus_type: u32,
    pub bus_number: u32,
}

/// One device.
#[derive(Debug, Clone)]
pub struct Node {
    /// The address of the physical device object: the node's name
    /// among nodes. The tree holds a reference to the object.
    pub pdo: usize,
    /// The parent's device, or zero for the root.
    pub parent: usize,
    /// The children's devices, in the order they were first reported.
    pub children: Vec<usize>,
    /// How deep in the tree: the root is 0.
    pub level: u32,
    /// The instance path: the name of the device's key under `Enum`.
    pub instance: String,
    pub state: State,
    /// Why the device is not started, if it is not: a `CM_PROB_*`.
    pub problem: u32,
    /// The device was reported by the driver that serves it
    /// (`report_detected_device`): that driver's device is on the stack
    /// already, and nothing is added or started by the manager.
    pub reported: bool,
    /// `root::remove_reported_device` was called while removal of this
    /// reported device was deferred behind a child; delete its PDO once the
    /// deferred removal completes.
    pub delete_reported: bool,
    /// The log has said that the device waits for a device it depends
    /// on.
    pub held_back: bool,
    /// The device has been asked for its children.
    pub enumerated: bool,
    pub device_id: String,
    pub hardware_ids: Vec<String>,
    pub compatible_ids: Vec<String>,
    pub description: Option<String>,
    pub location: Option<String>,
    /// `DEVICE_CAPABILITIES`: the flags, `Address` and `UINumber`.
    pub capabilities: u32,
    pub address: u32,
    pub ui_number: u32,
    pub bus: Option<BusInformation>,
    /// The function driver's service, once one is found.
    pub service: Option<String>,
    /// The device class, as the registry spells a GUID.
    pub class: Option<String>,
    /// The drivers whose `AddDevice` was called for the device, bottom
    /// of the stack first.
    pub drivers: Vec<String>,
    /// What firmware configured (`IRP_MN_QUERY_RESOURCES`), as a
    /// `CM_RESOURCE_LIST`'s bytes; empty for none.
    pub boot: Vec<u8>,
    /// What the device could use (`IRP_MN_QUERY_RESOURCE_REQUIREMENTS`),
    /// as an `IO_RESOURCE_REQUIREMENTS_LIST`'s bytes; empty for none.
    pub requirements: Vec<u8>,
    /// What the device was given, raw and translated, as
    /// `CM_RESOURCE_LIST`s' bytes; empty for none.
    pub raw: Vec<u8>,
    pub translated: Vec<u8>,
    /// The interrupt vectors the hardware layer gave out for the
    /// device, to be given back.
    pub vectors: Vec<u32>,
    /// The prefix this device's children carry in their instance
    /// identifiers, once one of them needed it.
    pub child_prefix: Option<String>,
    /// The address of the node's `DEVICE_NODE`, which the tree owns.
    pub visible: usize,
}

impl Node {
    pub fn new(pdo: usize, parent: usize, level: u32) -> Self {
        Self {
            pdo,
            parent,
            children: Vec::new(),
            level,
            instance: String::new(),
            state: State::New,
            problem: PROBLEM_NONE,
            reported: false,
            delete_reported: false,
            held_back: false,
            enumerated: false,
            device_id: String::new(),
            hardware_ids: Vec::new(),
            compatible_ids: Vec::new(),
            description: None,
            location: None,
            capabilities: 0,
            address: u32::MAX,
            ui_number: u32::MAX,
            bus: None,
            service: None,
            class: None,
            drivers: Vec::new(),
            boot: Vec::new(),
            requirements: Vec::new(),
            raw: Vec::new(),
            translated: Vec::new(),
            vectors: Vec::new(),
            child_prefix: None,
            visible: 0,
        }
    }
}

/// Every node. Boxed, so that the address a device's `DeviceNode`
/// field holds stays the node's while the list grows.
#[expect(
    clippy::vec_box,
    reason = "a node's address is handed out and must not move when the list grows"
)]
static TREE: SpinLock<Vec<Box<Node>>> = SpinLock::new(Rank::DeviceTree, Vec::new());

/// Pool tag of the `DEVICE_NODE` blocks.
const TAG: u32 = u32::from_le_bytes(*b"PpDn");

/// Enter `node` in the tree, as a child of its parent if it has one,
/// and return the address its device's `DeviceNode` field is to hold:
/// its `DEVICE_NODE`, linked in as its parent's last child. `None` if
/// there is no memory or the device has a node already.
pub fn insert(mut node: Node) -> Option<usize> {
    let mut tree = TREE.lock();
    if tree.iter().any(|known| known.pdo == node.pdo) || tree.try_reserve_exact(1).is_err() {
        return None;
    }
    let (pdo, parent) = (node.pdo, node.parent);
    let above = tree.iter().position(|known| known.pdo == parent);
    if let Some(at) = above
        && tree[at].children.try_reserve_exact(1).is_err()
    {
        return None;
    }
    let visible = crate::mm::pool::alloc(size_of::<DEVICE_NODE>(), TAG).cast::<DEVICE_NODE>();
    if visible.is_null() {
        return None;
    }
    // SAFETY: a fresh block of the structure's size; the parent's block
    // is the tree's, changed only under its lock, which is held.
    unsafe {
        visible
            .cast::<u8>()
            .write_bytes(0, size_of::<DEVICE_NODE>());
        (*visible).PhysicalDeviceObject = pdo as *mut DEVICE_OBJECT;
        if let Some(at) = above {
            let up = tree[at].visible as *mut DEVICE_NODE;
            (*visible).Parent = up;
            match (*up).LastChild {
                last if last.is_null() => (*up).Child = visible,
                last => (*last).Sibling = visible,
            }
            (*up).LastChild = visible;
        }
    }
    if let Some(at) = above {
        tree[at].children.push(pdo);
    }
    node.visible = visible as usize;
    tree.push(Box::new(node));
    Some(visible as usize)
}

/// Take the node of the device `pdo` out of the tree, and out of its
/// parent's children, and free its `DEVICE_NODE`. Its own children are
/// the caller's to have taken out first, and the device's `DeviceNode`
/// field the caller's to have cleared.
pub fn remove(pdo: usize) -> Option<Node> {
    let mut tree = TREE.lock();
    let at = tree.iter().position(|node| node.pdo == pdo)?;
    let node = tree.swap_remove(at);
    let visible = node.visible as *mut DEVICE_NODE;
    if let Some(above) = tree.iter_mut().find(|known| known.pdo == node.parent) {
        above.children.retain(|child| *child != pdo);
        above.children.shrink_to_fit();
        // SAFETY: both blocks are the tree's, changed only under its
        // lock, which is held.
        unsafe {
            let up = above.visible as *mut DEVICE_NODE;
            let mut before: *mut DEVICE_NODE = core::ptr::null_mut();
            let mut at = (*up).Child;
            while !at.is_null() && at != visible {
                (before, at) = (at, (*at).Sibling);
            }
            if at == visible {
                let after = (*visible).Sibling;
                if before.is_null() {
                    (*up).Child = after;
                } else {
                    (*before).Sibling = after;
                }
                if (*up).LastChild == visible {
                    (*up).LastChild = before;
                }
            }
        }
    }
    tree.shrink_to_fit();
    drop(tree);
    // The block was the node's alone and is now unlinked; the device's
    // field was cleared by the caller.
    let _ = crate::mm::pool::free(visible.cast());
    Some(*node)
}

/// Run `f` on the node of the device `pdo`. `None` if it has none.
pub fn with<R>(pdo: usize, f: impl FnOnce(&mut Node) -> R) -> Option<R> {
    let mut tree = TREE.lock();
    tree.iter_mut()
        .find(|node| node.pdo == pdo)
        .map(|node| f(node))
}

/// A copy of the node of the device `pdo`.
pub fn get(pdo: usize) -> Option<Node> {
    with(pdo, |node| node.clone())
}

/// The device whose instance path is `instance`, letter case aside.
pub fn by_instance(instance: &str) -> Option<usize> {
    let tree = TREE.lock();
    tree.iter()
        .find(|node| node.instance.eq_ignore_ascii_case(instance))
        .map(|node| node.pdo)
}

/// The devices of every node, parents before their children.
pub fn all() -> Vec<usize> {
    let tree = TREE.lock();
    let mut order = Vec::new();
    let mut next: Vec<usize> = tree
        .iter()
        .filter(|node| node.parent == 0)
        .map(|node| node.pdo)
        .collect();
    while let Some(pdo) = next.pop() {
        order.push(pdo);
        if let Some(node) = tree.iter().find(|node| node.pdo == pdo) {
            next.extend(node.children.iter().rev());
        }
    }
    order
}

/// Whether `ancestor` is the device `pdo` or one above it in the tree.
pub fn is_at_or_above(ancestor: usize, pdo: usize) -> bool {
    let tree = TREE.lock();
    let mut at = pdo;
    while at != 0 {
        if at == ancestor {
            return true;
        }
        at = tree
            .iter()
            .find(|node| node.pdo == at)
            .map_or(0, |node| node.parent);
    }
    false
}
