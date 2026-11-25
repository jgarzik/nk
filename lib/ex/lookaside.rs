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
//! [`paged`], [`npaged`] and [`ex`] give the fields that depend on the
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

/// `POOL_TYPE` values and flag bits, from `wdm.h`.
pub const NON_PAGED_POOL: u32 = 0;
pub const PAGED_POOL: u32 = 1;
pub const POOL_CACHE_ALIGNED: u32 = 4;
pub const POOL_QUOTA_FAIL_INSTEAD_OF_RAISE: u32 = 8;
pub const POOL_RAISE_IF_ALLOCATION_FAILURE: u32 = 16;
pub const POOL_NX_ALLOCATION: u32 = 512;

/// `ExInitializeLookasideListEx` flags, from `wdm.h`.
pub const EX_LOOKASIDE_LIST_EX_FLAGS_RAISE_ON_FAIL: u32 = 1;
pub const EX_LOOKASIDE_LIST_EX_FLAGS_FAIL_NO_RAISE: u32 = 2;

/// How many blocks a new list keeps: `Depth` as initialised.
pub const MINIMUM_DEPTH: u16 = 4;
/// `EX_MAXIMUM_LOOKASIDE_DEPTH_BASE`: `MaximumDepth` unless the driver
/// asks for more.
pub const MAXIMUM_DEPTH_BASE: u16 = 256;
/// `EX_MAXIMUM_LOOKASIDE_DEPTH_LIMIT`: the most it may ask for.
pub const MAXIMUM_DEPTH_LIMIT: u16 = 1024;

pub const STATUS_INVALID_PARAMETER_4: u32 = 0xC000_00F2;
pub const STATUS_INVALID_PARAMETER_5: u32 = 0xC000_00F3;

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

const fn fields(pool_type: u32, size: usize, tag: u32, maximum_depth: u16) -> Fields {
    Fields {
        depth: MINIMUM_DEPTH,
        maximum_depth,
        pool_type,
        tag,
        // `Size` is a ULONG; the argument a SIZE_T.
        size: size as u32,
    }
}

/// `ExInitializePagedLookasideList`. `flags` are pool flag bits; the
/// routine's `Depth` argument is reserved and ignored.
pub const fn paged(flags: u32, size: usize, tag: u32) -> Fields {
    fields(PAGED_POOL | flags, size, tag, MAXIMUM_DEPTH_BASE)
}

/// `ExInitializeNPagedLookasideList`: as [`paged`], from non-paged pool.
pub const fn npaged(flags: u32, size: usize, tag: u32) -> Fields {
    fields(NON_PAGED_POOL | flags, size, tag, MAXIMUM_DEPTH_BASE)
}

/// Why `ExInitializeLookasideListEx` refuses.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Invalid {
    /// Not a pool type: [`STATUS_INVALID_PARAMETER_4`].
    PoolType,
    /// Unknown flag bits, or both flags at once:
    /// [`STATUS_INVALID_PARAMETER_5`].
    Flags,
}

impl Invalid {
    pub const fn status(self) -> u32 {
        match self {
            Invalid::PoolType => STATUS_INVALID_PARAMETER_4,
            Invalid::Flags => STATUS_INVALID_PARAMETER_5,
        }
    }
}

/// `ExInitializeLookasideListEx`. The pool type may be paged or
/// non-paged, with the cache-aligned and no-execute bits. A flag adds
/// its pool bit to the type `Allocate` is called with. A `depth` of zero
/// asks for the usual maximum; any other is brought within
/// [`MAXIMUM_DEPTH_BASE`] and [`MAXIMUM_DEPTH_LIMIT`].
pub const fn ex(
    pool_type: u32,
    flags: u32,
    size: usize,
    tag: u32,
    depth: u16,
) -> Result<Fields, Invalid> {
    if pool_type & !(PAGED_POOL | POOL_CACHE_ALIGNED | POOL_NX_ALLOCATION) != 0 {
        return Err(Invalid::PoolType);
    }
    let failure = match flags {
        0 => 0,
        EX_LOOKASIDE_LIST_EX_FLAGS_RAISE_ON_FAIL => POOL_RAISE_IF_ALLOCATION_FAILURE,
        EX_LOOKASIDE_LIST_EX_FLAGS_FAIL_NO_RAISE => POOL_QUOTA_FAIL_INSTEAD_OF_RAISE,
        _ => return Err(Invalid::Flags),
    };
    let maximum_depth = if depth < MAXIMUM_DEPTH_BASE {
        MAXIMUM_DEPTH_BASE
    } else if depth > MAXIMUM_DEPTH_LIMIT {
        MAXIMUM_DEPTH_LIMIT
    } else {
        depth
    };
    Ok(fields(pool_type | failure, size, tag, maximum_depth))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TAG: u32 = u32::from_le_bytes(*b"NkLa");

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
            assert_eq!(ex(0, 0, size, TAG, 0).unwrap().size as usize, size);
        }
        // Only its low 32 bits fit the field.
        assert_eq!(npaged(0, 0x1_0000_0020, TAG).size, 0x20);
    }

    #[test]
    fn the_ex_flags_become_pool_bits() {
        let of = |pool_type, flags| ex(pool_type, flags, 64, TAG, 0).map(|f| f.pool_type);
        assert_eq!(of(NON_PAGED_POOL, 0), Ok(0));
        assert_eq!(of(PAGED_POOL, 0), Ok(1));
        assert_eq!(of(POOL_NX_ALLOCATION, 0), Ok(512));
        assert_eq!(of(PAGED_POOL | POOL_CACHE_ALIGNED, 0), Ok(5));
        assert_eq!(
            of(PAGED_POOL, EX_LOOKASIDE_LIST_EX_FLAGS_RAISE_ON_FAIL),
            Ok(17)
        );
        assert_eq!(
            of(POOL_NX_ALLOCATION, EX_LOOKASIDE_LIST_EX_FLAGS_FAIL_NO_RAISE),
            Ok(520)
        );
        let whole = ex(PAGED_POOL, 0, 64, TAG, 0).unwrap();
        assert_eq!(whole, paged(0, 64, TAG));
    }

    #[test]
    fn bad_ex_arguments_are_refused_by_number() {
        for pool_type in [2, 8, 16, 32, 0x100, 0x400, u32::MAX] {
            assert_eq!(ex(pool_type, 0, 64, TAG, 0), Err(Invalid::PoolType));
        }
        for flags in [3, 4, 8, u32::MAX] {
            assert_eq!(ex(0, flags, 64, TAG, 0), Err(Invalid::Flags));
        }
        // The pool type is argument four and is looked at first.
        assert_eq!(ex(2, 3, 64, TAG, 0), Err(Invalid::PoolType));
        assert_eq!(Invalid::PoolType.status(), 0xC000_00F2);
        assert_eq!(Invalid::Flags.status(), 0xC000_00F3);
    }

    #[test]
    fn the_ex_depth_sets_the_maximum_within_bounds() {
        let of = |depth| {
            let fields = ex(0, 0, 64, TAG, depth).unwrap();
            assert_eq!(fields.depth, MINIMUM_DEPTH);
            fields.maximum_depth
        };
        assert_eq!(
            [0, 1, 255, 256, 257, 1023, 1024, 1025, u16::MAX].map(of),
            [256, 256, 256, 256, 257, 1023, 1024, 1024, 1024]
        );
    }
}
