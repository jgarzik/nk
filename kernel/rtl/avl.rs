//! The [AVL generic table](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinitializegenerictableavl).
//!
//! Everything is the driver's: the table header, the nodes its allocate
//! routine returns (each an `RTL_BALANCED_LINKS` with the element after
//! it) and the order its compare routine defines. The kernel only links
//! nodes, through raw reads and writes of the driver's memory; the
//! balancing is `nk_rtl::avl`. The caller serialises the calls on one
//! table and calls at the IRQL its own routines allow, as on Windows.

#![allow(non_snake_case)]

use core::cmp::Ordering;
use core::ffi::c_void;
use core::mem::size_of;
use core::ptr::{addr_of_mut, null_mut};
use nk_ntabi::rtl::*;
use nk_rtl::avl::{self, Links, Search};

/// Bytes of a node before the driver's element.
const HEADER: usize = size_of::<RTL_BALANCED_LINKS>();

/// A driver's table: nodes are addresses of `RTL_BALANCED_LINKS`.
struct Table(*mut RTL_AVL_TABLE);

impl Table {
    fn head(&self) -> usize {
        // SAFETY: the header is the driver's table; no reference is made.
        unsafe { addr_of_mut!((*self.0).BalancedRoot) as usize }
    }

    fn node(at: usize) -> *mut RTL_BALANCED_LINKS {
        at as *mut RTL_BALANCED_LINKS
    }

    /// How `buffer` compares with the element of node `at`.
    ///
    /// # Safety
    /// The table was initialised with a compare routine; `at` is a node.
    unsafe fn order(&self, buffer: *mut c_void, at: usize) -> Ordering {
        // SAFETY: per the contract.
        unsafe {
            let compare = (*self.0)
                .CompareRoutine
                .expect("an AVL table's compare routine");
            match compare(self.0, buffer, (at + HEADER) as *mut c_void) {
                GENERIC_LESS_THAN => Ordering::Less,
                GENERIC_GREATER_THAN => Ordering::Greater,
                _ => Ordering::Equal,
            }
        }
    }

    /// The node holding an element equal to `buffer`, or where one goes.
    ///
    /// # Safety
    /// As for [`Table::order`].
    unsafe fn search(&self, buffer: *mut c_void) -> Search {
        // SAFETY: per the contract; the search hands back only nodes.
        avl::find(self, self.head(), |at| unsafe { self.order(buffer, at) })
    }
}

// The balancing hands back only the head and nodes it was given: memory
// the driver gave this table and keeps while the table holds it.
impl Links for Table {
    fn parent(&self, at: usize) -> usize {
        // SAFETY: `at` is the head or a node of this table.
        unsafe { (*Self::node(at)).Parent as usize }
    }
    fn left(&self, at: usize) -> usize {
        // SAFETY: as in `parent`.
        unsafe { (*Self::node(at)).LeftChild as usize }
    }
    fn right(&self, at: usize) -> usize {
        // SAFETY: as in `parent`.
        unsafe { (*Self::node(at)).RightChild as usize }
    }
    fn balance(&self, at: usize) -> i8 {
        // SAFETY: as in `parent`.
        unsafe { (*Self::node(at)).Balance }
    }
    fn set_parent(&mut self, at: usize, to: usize) {
        // SAFETY: as in `parent`.
        unsafe { (*Self::node(at)).Parent = Self::node(to) }
    }
    fn set_left(&mut self, at: usize, to: usize) {
        // SAFETY: as in `parent`.
        unsafe { (*Self::node(at)).LeftChild = Self::node(to) }
    }
    fn set_right(&mut self, at: usize, to: usize) {
        // SAFETY: as in `parent`.
        unsafe { (*Self::node(at)).RightChild = Self::node(to) }
    }
    fn set_balance(&mut self, at: usize, to: i8) {
        // SAFETY: as in `parent`.
        unsafe { (*Self::node(at)).Balance = to }
    }
}

/// [`RtlInitializeGenericTableAvl`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinitializegenerictableavl):
/// an empty table with the driver's routines. Allocates nothing.
///
/// # Safety
/// `table` is writable for an `RTL_AVL_TABLE`.
pub unsafe extern "system" fn RtlInitializeGenericTableAvl(
    table: *mut RTL_AVL_TABLE,
    compare: Option<AvlCompare>,
    allocate: Option<AvlAllocate>,
    free: Option<AvlFree>,
    context: *mut c_void,
) {
    // SAFETY: per the contract; the header is written field by field.
    unsafe {
        let root = addr_of_mut!((*table).BalancedRoot);
        (*root).Parent = root;
        (*root).LeftChild = null_mut();
        (*root).RightChild = null_mut();
        (*root).Balance = 0;
        (*root).Reserved = [0; 3];
        (*table).OrderedPointer = null_mut();
        (*table).WhichOrderedElement = 0;
        (*table).NumberGenericTableElements = 0;
        (*table).DepthOfTree = 0;
        (*table).RestartKey = null_mut();
        (*table).DeleteCount = 0;
        (*table).CompareRoutine = compare;
        (*table).AllocateRoutine = allocate;
        (*table).FreeRoutine = free;
        (*table).TableContext = context;
    }
}

/// [`RtlInsertElementGenericTableAvl`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtlinsertelementgenerictableavl):
/// the element equal to `buffer` if the table has one, else a copy of
/// `buffer` in a node from the allocate routine. Null if that routine
/// fails. `new_element`, if given, says which.
///
/// # Safety
/// `table` was initialised; `buffer` holds `size` bytes.
pub unsafe extern "system" fn RtlInsertElementGenericTableAvl(
    table: *mut RTL_AVL_TABLE,
    buffer: *mut c_void,
    size: u32,
    new_element: *mut u8,
) -> *mut c_void {
    let mut tree = Table(table);
    // SAFETY: per the contract.
    unsafe {
        let say = |new: bool| {
            if !new_element.is_null() {
                new_element.write(u8::from(new));
            }
        };
        let (parent, left) = match tree.search(buffer) {
            Search::Found(at) => {
                say(false);
                return (at + HEADER) as *mut c_void;
            }
            Search::Absent { parent, left } => (parent, left),
        };
        let allocate = (*table)
            .AllocateRoutine
            .expect("an AVL table's allocate routine");
        let node = allocate(table, size + HEADER as u32);
        if node.is_null() {
            return null_mut();
        }
        let element = node.cast::<u8>().add(HEADER);
        core::ptr::copy_nonoverlapping(buffer.cast::<u8>(), element, size as usize);
        let head = tree.head();
        avl::insert(&mut tree, head, parent, left, node as usize);
        let depth = avl::depth(&tree, head, node as usize);
        (*table).NumberGenericTableElements += 1;
        (*table).DepthOfTree = (*table).DepthOfTree.max(depth);
        (*table).WhichOrderedElement = 0;
        (*table).OrderedPointer = null_mut();
        say(true);
        element.cast()
    }
}

/// [`RtlLookupElementGenericTableAvl`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtllookupelementgenerictableavl):
/// the element equal to `buffer`, or null.
///
/// # Safety
/// `table` was initialised.
pub unsafe extern "system" fn RtlLookupElementGenericTableAvl(
    table: *mut RTL_AVL_TABLE,
    buffer: *mut c_void,
) -> *mut c_void {
    // SAFETY: per the contract.
    match unsafe { Table(table).search(buffer) } {
        Search::Found(at) => (at + HEADER) as *mut c_void,
        Search::Absent { .. } => null_mut(),
    }
}

/// [`RtlDeleteElementGenericTableAvl`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-rtldeleteelementgenerictableavl):
/// unlink the element equal to `buffer` and give its node to the free
/// routine. FALSE if there is none.
///
/// # Safety
/// `table` was initialised.
pub unsafe extern "system" fn RtlDeleteElementGenericTableAvl(
    table: *mut RTL_AVL_TABLE,
    buffer: *mut c_void,
) -> u8 {
    let mut tree = Table(table);
    // SAFETY: per the contract.
    unsafe {
        let Search::Found(node) = tree.search(buffer) else {
            return 0;
        };
        let head = tree.head();
        avl::remove(&mut tree, head, node);
        (*table).NumberGenericTableElements -= 1;
        (*table).DeleteCount += 1;
        (*table).RestartKey = null_mut();
        (*table).WhichOrderedElement = 0;
        (*table).OrderedPointer = null_mut();
        let free = (*table).FreeRoutine.expect("an AVL table's free routine");
        free(table, node as *mut c_void);
        1
    }
}
