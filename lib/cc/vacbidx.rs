//! A file's VACB index: for each 256 KiB of its section, the view (VACB)
//! that maps it, if any.
//!
//! Windows keeps it in one of three forms by the section's size
//! (`CcCreateVacbArray`, `CcExtendVacbArray`), and so does NK:
//!
//! - up to 1 MiB, four entries inside the shared cache map
//!   (`InitialVacbs`);
//! - up to 32 MiB, one array of an entry per view;
//! - beyond, a tree whose leaves hold 128 entries (32 MiB of file) each,
//!   made when a view in their range is first mapped.
//!
//! Nothing here allocates while an entry is looked up or set: the
//! kernel holds a spin lock then. What a lookup may need (a leaf, a
//! larger index) is made beforehand, with the lock dropped, and handed
//! in.

use crate::VIEW_BYTES;
use alloc::vec::Vec;

/// Entries kept inside the shared cache map.
pub const INLINE_VIEWS: usize = 4;
/// Entries in one leaf of the tree, and views in the array's largest
/// size.
pub const LEAF_VIEWS: usize = 128;
/// The largest section the inline entries cover.
pub const INLINE_LIMIT: u64 = INLINE_VIEWS as u64 * VIEW_BYTES;
/// The largest section the array covers.
pub const ARRAY_LIMIT: u64 = LEAF_VIEWS as u64 * VIEW_BYTES;

/// No VACB maps the view.
const NONE: u32 = u32::MAX;

/// The form an index takes for a section of a given size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Inline,
    Array,
    Tree,
}

/// The class of a section of `size` bytes.
pub fn class(size: u64) -> Class {
    if size <= INLINE_LIMIT {
        Class::Inline
    } else if size <= ARRAY_LIMIT {
        Class::Array
    } else {
        Class::Tree
    }
}

/// The views of a section of `size` bytes.
pub fn views(size: u64) -> usize {
    size.div_ceil(VIEW_BYTES) as usize
}

/// The pool had no memory for an index or a leaf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoMemory;

/// A leaf of the tree, made with no lock held.
pub struct Leaf(Vec<u32>);

impl Leaf {
    /// A leaf with no view mapped.
    pub fn new() -> Result<Self, NoMemory> {
        filled(LEAF_VIEWS).map(Self)
    }
}

/// A vector of `n` empty entries, or `NoMemory`.
fn filled(n: usize) -> Result<Vec<u32>, NoMemory> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| NoMemory)?;
    v.resize(n, NONE);
    Ok(v)
}

enum Storage {
    Inline([u32; INLINE_VIEWS]),
    Array(Vec<u32>),
    /// One slot per leaf; a leaf made on demand.
    Tree(Vec<Option<Leaf>>),
}

/// The index of a section's views.
pub struct VacbIndex {
    views: usize,
    storage: Storage,
}

impl VacbIndex {
    /// An index for a section of `size` bytes, with no view mapped.
    pub fn new(size: u64) -> Result<Self, NoMemory> {
        let views = views(size);
        let storage = match class(size) {
            Class::Inline => Storage::Inline([NONE; INLINE_VIEWS]),
            Class::Array => Storage::Array(filled(views)?),
            Class::Tree => {
                let mut leaves = Vec::new();
                leaves
                    .try_reserve_exact(views.div_ceil(LEAF_VIEWS))
                    .map_err(|_| NoMemory)?;
                leaves.resize_with(views.div_ceil(LEAF_VIEWS), || None);
                Storage::Tree(leaves)
            }
        };
        Ok(Self { views, storage })
    }

    /// The views the index covers.
    pub fn views(&self) -> usize {
        self.views
    }

    pub fn class(&self) -> Class {
        match self.storage {
            Storage::Inline(_) => Class::Inline,
            Storage::Array(_) => Class::Array,
            Storage::Tree(_) => Class::Tree,
        }
    }

    /// The VACB mapping view `view`, if any.
    pub fn get(&self, view: usize) -> Option<u32> {
        let entry = match &self.storage {
            _ if view >= self.views => NONE,
            Storage::Inline(e) => e[view],
            Storage::Array(e) => e[view],
            Storage::Tree(leaves) => leaves[view / LEAF_VIEWS]
                .as_ref()
                .map_or(NONE, |l| l.0[view % LEAF_VIEWS]),
        };
        (entry != NONE).then_some(entry)
    }

    /// Whether setting view `view` needs a leaf made first.
    pub fn needs_leaf(&self, view: usize) -> bool {
        matches!(&self.storage, Storage::Tree(leaves)
            if view < self.views && leaves[view / LEAF_VIEWS].is_none())
    }

    /// Put `leaf` in place for view `view` if none is there. Returns it
    /// back if it was not needed, for the caller to drop once its lock
    /// is released.
    pub fn insert_leaf(&mut self, view: usize, leaf: Leaf) -> Option<Leaf> {
        match &mut self.storage {
            Storage::Tree(leaves) if view < self.views && leaves[view / LEAF_VIEWS].is_none() => {
                leaves[view / LEAF_VIEWS] = Some(leaf);
                None
            }
            _ => Some(leaf),
        }
    }

    /// Record that VACB `vacb` maps view `view` (`None`: that none does).
    /// The view is inside the index and, in a tree, has its leaf.
    pub fn set(&mut self, view: usize, vacb: Option<u32>) {
        let value = vacb.unwrap_or(NONE);
        assert!(view < self.views, "view {view} beyond the index");
        match &mut self.storage {
            Storage::Inline(e) => e[view] = value,
            Storage::Array(e) => e[view] = value,
            Storage::Tree(leaves) => match &mut leaves[view / LEAF_VIEWS] {
                Some(leaf) => leaf.0[view % LEAF_VIEWS] = value,
                None if vacb.is_none() => {}
                None => panic!("view {view} has no leaf"),
            },
        }
    }

    /// Every mapped view and its VACB, in view order.
    pub fn mapped(&self) -> impl Iterator<Item = (usize, u32)> + '_ {
        (0..self.views).filter_map(|v| self.get(v).map(|vacb| (v, vacb)))
    }

    /// Whether [`adopt`](Self::adopt) needs a leaf made in `self` first,
    /// to take the entries of an index of `old_views` views: when `self`
    /// is a tree and the old index was not, its entries all lie in the
    /// first leaf.
    pub fn needs_leaf_to_adopt(&self, old_views: usize) -> bool {
        old_views != 0 && old_views <= LEAF_VIEWS && self.needs_leaf(0)
    }

    /// Take every entry of `old`, an index of a smaller or equal
    /// section, into `self`, a fresh one: what extending a section does
    /// under the lock. `self` has what
    /// [`needs_leaf_to_adopt`](Self::needs_leaf_to_adopt) asked for.
    pub fn adopt(&mut self, old: &mut VacbIndex) {
        assert!(old.views <= self.views, "a smaller index adopts a larger");
        if let (Storage::Tree(new), Storage::Tree(old_leaves)) =
            (&mut self.storage, &mut old.storage)
        {
            for (slot, leaf) in new.iter_mut().zip(old_leaves.iter_mut()) {
                *slot = leaf.take();
            }
            return;
        }
        for view in 0..old.views {
            if let Some(vacb) = old.get(view) {
                self.set(view, Some(vacb));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_by_size() {
        assert_eq!(class(VIEW_BYTES), Class::Inline);
        assert_eq!(class(1 << 20), Class::Inline);
        assert_eq!(class((1 << 20) + 1), Class::Array);
        assert_eq!(class(32 << 20), Class::Array);
        assert_eq!(class((32 << 20) + 1), Class::Tree);
        assert_eq!(views(1), 1);
        assert_eq!(views(3 << 20), 12);
    }

    #[test]
    fn inline_and_array_entries() {
        for size in [1 << 20, 3 << 20] {
            let mut i = VacbIndex::new(size).unwrap();
            assert_eq!(i.get(0), None);
            i.set(3, Some(7));
            assert_eq!(i.get(3), Some(7));
            assert_eq!(i.get(views(size)), None, "beyond the section");
            assert!(!i.needs_leaf(3));
            i.set(3, None);
            assert_eq!(i.mapped().count(), 0);
        }
    }

    #[test]
    fn a_tree_makes_leaves_on_demand() {
        let mut i = VacbIndex::new(64 << 20).unwrap();
        assert_eq!(i.class(), Class::Tree);
        assert!(i.needs_leaf(200));
        assert_eq!(i.get(200), None);
        assert!(i.insert_leaf(200, Leaf::new().unwrap()).is_none());
        assert!(!i.needs_leaf(130), "one leaf covers 128 views");
        assert!(
            i.insert_leaf(130, Leaf::new().unwrap()).is_some(),
            "a second leaf is not taken"
        );
        i.set(200, Some(1));
        i.set(5, None); // clearing a view with no leaf changes nothing
        assert_eq!(i.get(200), Some(1));
        assert_eq!(i.mapped().collect::<Vec<_>>(), [(200, 1)]);
    }

    #[test]
    fn extension_keeps_the_entries() {
        // Inline to array.
        let mut old = VacbIndex::new(1 << 20).unwrap();
        old.set(2, Some(9));
        let mut new = VacbIndex::new(2 << 20).unwrap();
        assert!(!new.needs_leaf_to_adopt(old.views()));
        new.adopt(&mut old);
        assert_eq!(new.get(2), Some(9));
        // Array to tree: the first leaf is made first.
        let mut tree = VacbIndex::new(40 << 20).unwrap();
        assert!(tree.needs_leaf_to_adopt(new.views()));
        assert!(tree.insert_leaf(0, Leaf::new().unwrap()).is_none());
        tree.adopt(&mut new);
        assert_eq!(tree.get(2), Some(9));
        // Tree to tree: the leaves move.
        tree.insert_leaf(150, Leaf::new().unwrap());
        tree.set(150, Some(4));
        let mut bigger = VacbIndex::new(100 << 20).unwrap();
        assert!(!bigger.needs_leaf_to_adopt(tree.views()));
        bigger.adopt(&mut tree);
        assert_eq!((bigger.get(2), bigger.get(150)), (Some(9), Some(4)));
    }
}
