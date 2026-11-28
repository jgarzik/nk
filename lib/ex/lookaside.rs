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

/// Why `ExInitializeLookasideListEx` refused its arguments: the
/// parameter that is wrong, counting from one.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct BadParameter(pub u8);

/// `EX_LOOKASIDE_LIST_EX_FLAG_RAISE_ON_FAIL` and `..._FAIL_NO_RAISE`.
pub const FLAG_RAISE_ON_FAIL: u32 = 1;
pub const FLAG_FAIL_NO_RAISE: u32 = 2;
/// The pool flags those stand for.
const POOL_RAISE_IF_ALLOCATION_FAILURE: u32 = 0x10;
const POOL_QUOTA_FAIL_INSTEAD_OF_RAISE: u32 = 0x8;

/// `ExInitializeLookasideListEx`, as the pinned kernel checks and fills
/// it: a `depth` of 0 means the default maximum, any other must be from
/// 256 to 1024 (parameter 8); at most one flag (parameter 5); a pool
/// type with no bits the pool does not know and not both paged and
/// session-cache-aligned at once (parameter 4). The flags join the pool
/// type as the pool's own; a size below 8 is made 8.
pub fn ex(
    pool_type: u32,
    flags: u32,
    size: usize,
    tag: u32,
    depth: u16,
) -> Result<Fields, BadParameter> {
    if depth != 0 && !(MAXIMUM_DEPTH_BASE..=4 * MAXIMUM_DEPTH_BASE).contains(&depth) {
        return Err(BadParameter(8));
    }
    if flags & !(FLAG_RAISE_ON_FAIL | FLAG_FAIL_NO_RAISE) != 0
        || !flags.is_power_of_two() && flags != 0
    {
        return Err(BadParameter(5));
    }
    if pool_type & 0xFFFF_FC18 != 0 || pool_type & 3 == 3 {
        return Err(BadParameter(4));
    }
    let flag_bits = match flags {
        FLAG_RAISE_ON_FAIL => POOL_RAISE_IF_ALLOCATION_FAILURE,
        FLAG_FAIL_NO_RAISE => POOL_QUOTA_FAIL_INSTEAD_OF_RAISE,
        _ => 0,
    };
    Ok(Fields {
        depth: MINIMUM_DEPTH,
        maximum_depth: if depth == 0 {
            MAXIMUM_DEPTH_BASE
        } else {
            depth
        },
        pool_type: pool_type | flag_bits,
        tag,
        size: size.max(8) as u32,
    })
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

    #[test]
    fn an_ex_list_is_checked_and_filled_as_windows_does() {
        assert_eq!(
            ex(PAGED_POOL, 0, 3, TAG, 0),
            Ok(Fields {
                depth: 4,
                maximum_depth: 256,
                pool_type: 1,
                tag: TAG,
                size: 8,
            })
        );
        assert_eq!(
            ex(0x200, FLAG_RAISE_ON_FAIL, 64, TAG, 1024)
                .unwrap()
                .pool_type,
            0x210
        );
        assert_eq!(
            ex(0, FLAG_FAIL_NO_RAISE, 64, TAG, 300).unwrap(),
            Fields {
                depth: 4,
                maximum_depth: 300,
                pool_type: 8,
                tag: TAG,
                size: 64,
            }
        );
        assert_eq!(ex(0, 0, 64, TAG, 255), Err(BadParameter(8)));
        assert_eq!(ex(0, 0, 64, TAG, 1025), Err(BadParameter(8)));
        assert_eq!(ex(0, 3, 64, TAG, 0), Err(BadParameter(5)));
        assert_eq!(ex(0, 4, 64, TAG, 0), Err(BadParameter(5)));
        assert_eq!(ex(3, 0, 64, TAG, 0), Err(BadParameter(4)));
        assert_eq!(ex(0x8, 0, 64, TAG, 0), Err(BadParameter(4)));
    }
}
