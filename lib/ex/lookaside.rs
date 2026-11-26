//! Lookaside lists (`GENERAL_LOOKASIDE`): what initialising one writes.
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-lookaside-lists>
//!
//! A lookaside list is a cache of freed blocks of one size on an SList
//! in the driver's memory. Allocating from it and freeing to it are
//! inline code from the WDK headers, compiled into the driver: they pop
//! and push `ListHead`, count in the structure, and call its `Allocate`
//! and `Free` routines on a miss. The kernel only initialises the
//! structure and deletes it.
//!
//! # Initialising
//!
//! [`paged`] and [`npaged`] give the fields that depend on the
//! arguments ([`Fields`]). The kernel also empties `ListHead`, zeroes
//! the counters (`TotalAllocates`, `AllocateMisses`, `TotalFrees`,
//! `FreeMisses` and the two `Last...` copies), and stores the driver's
//! `Allocate` and `Free` routines, or where the driver gave none, the
//! pool's own (`ExAllocatePoolWithTag`, `ExFreePool`).
//!
//! The size is stored as given, not rounded: the pool hands out nothing
//! smaller than an SList entry, and the driver's own `Allocate` routine
//! is entitled to see the number its driver asked for.
//!
//! # Deleting
//!
//! `ExDelete...LookasideList` flushes `ListHead` ([`crate::slist::flush`])
//! and passes every entry of the chain to the structure's `Free`
//! routine; the flushed header's depth says how many there are.
//!
//! # Depth
//!
//! Windows adjusts `Depth` over time from the miss counts, between
//! [`MINIMUM_DEPTH`] and `MaximumDepth`. NK leaves it at its first value.

/// `POOL_TYPE` values, from `wdm.h`.
pub const NON_PAGED_POOL: u32 = 0;
pub const PAGED_POOL: u32 = 1;

/// How many blocks a new list keeps: `Depth` as initialised.
pub const MINIMUM_DEPTH: u16 = 4;
/// `EX_MAXIMUM_LOOKASIDE_DEPTH_BASE`: `MaximumDepth`.
pub const MAXIMUM_DEPTH_BASE: u16 = 256;

/// The fields of `GENERAL_LOOKASIDE` that the arguments decide.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Fields {
    /// `Depth`: free blocks kept before `Free` is called instead.
    pub depth: u16,
    /// `MaximumDepth`.
    pub maximum_depth: u16,
    /// `Type`: the pool type passed to `Allocate`.
    pub pool_type: u32,
    /// `Tag`.
    pub tag: u32,
    /// `Size`: the block size passed to `Allocate`.
    pub size: u32,
}

const fn fields(pool_type: u32, size: usize, tag: u32) -> Fields {
    Fields {
        depth: MINIMUM_DEPTH,
        maximum_depth: MAXIMUM_DEPTH_BASE,
        pool_type,
        tag,
        // `Size` is a ULONG; the argument a SIZE_T.
        size: size as u32,
    }
}

/// `ExInitializePagedLookasideList`. `flags` are pool flag bits; the
/// routine's `Depth` argument is reserved and ignored.
pub const fn paged(flags: u32, size: usize, tag: u32) -> Fields {
    fields(PAGED_POOL | flags, size, tag)
}

/// `ExInitializeNPagedLookasideList`: as [`paged`], from non-paged pool.
pub const fn npaged(flags: u32, size: usize, tag: u32) -> Fields {
    fields(NON_PAGED_POOL | flags, size, tag)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: u32 = u32::from_le_bytes(*b"NkLa");
    /// Pool flag bits a driver may pass, from `wdm.h`.
    const POOL_RAISE_IF_ALLOCATION_FAILURE: u32 = 16;
    const POOL_NX_ALLOCATION: u32 = 512;

    #[test]
    fn a_paged_list_starts_shallow_and_takes_paged_pool() {
        assert_eq!(
            paged(0, 0x48, TAG),
            Fields {
                depth: 4,
                maximum_depth: 256,
                pool_type: 1,
                tag: TAG,
                size: 0x48,
            }
        );
        assert_eq!(
            paged(POOL_RAISE_IF_ALLOCATION_FAILURE, 8, TAG).pool_type,
            17
        );
    }

    #[test]
    fn a_non_paged_list_takes_non_paged_pool() {
        assert_eq!(
            npaged(0, 0x100, TAG),
            Fields {
                depth: 4,
                maximum_depth: 256,
                pool_type: 0,
                tag: TAG,
                size: 0x100,
            }
        );
        // The no-execute flag makes it NonPagedPoolNx.
        assert_eq!(npaged(POOL_NX_ALLOCATION, 16, 0).pool_type, 512);
    }

    #[test]
    fn the_size_is_kept_as_given() {
        for size in [0, 1, 7, 8, 9, 17, 4096, 0xFFFF_FFFF] {
            assert_eq!(paged(0, size, TAG).size as usize, size);
            assert_eq!(npaged(0, size, TAG).size as usize, size);
        }
        // Only its low 32 bits fit the field.
        assert_eq!(npaged(0, 0x1_0000_0020, TAG).size, 0x20);
    }
}
