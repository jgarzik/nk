//! Tests of the executive's locks, lists and timers, called the way a
//! driver calls them: through the exports, on memory of the caller's.

use crate::ex::{lookaside, pushlock, resource, slist, timer, uuid};
use crate::mm::pool;
use crate::test::{Group, Report};
use core::fmt::Display;
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "ex.pushlock.words",
        "ex.pushlock.hand-over",
        "ex.pushlock.readers",
        "ex.pushlock.contention",
        "ex.slist.swap",
        "ex.slist.order",
        "ex.slist.contention",
        "ex.pool.variants",
        "ex.lookaside.fields",
        "ex.lookaside.cache",
        "ex.lookaside.routines",
        "ex.resource.recursion",
        "ex.resource.hand-over",
        "ex.resource.starve",
        "ex.resource.table",
        "ex.resource.contention",
        "ex.timer.callback",
        "ex.timer.periodic",
        "ex.timer.delete",
        "ex.timer.wait",
        "ex.pool.raise",
        "ex.uuid.fields",
        "ex.uuid.unique",
    ],
    run,
    manual: false,
};

fn counted<N: Display>(r: &mut Report, name: &str, what: &str, result: Result<N, &'static str>) {
    match result {
        Ok(n) => r.ok_with(name, format_args!("{what} {n}")),
        Err(why) => r.fail(name, format_args!("{why}")),
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("ex.pushlock.words", pushlock::words_test);
    counted(
        r,
        "ex.pushlock.hand-over",
        "pairings:",
        pushlock::hand_over_test(),
    );
    counted(
        r,
        "ex.pushlock.readers",
        "let in together:",
        pushlock::readers_test(),
    );
    counted(
        r,
        "ex.pushlock.contention",
        "writes:",
        pushlock::contention_test(),
    );
    r.check("ex.slist.swap", slist::swap_test);
    match slist::order_test() {
        Ok(header) => r.ok_with("ex.slist.order", format_args!("header ends {header:#010x}")),
        Err(why) => r.fail("ex.slist.order", format_args!("{why}")),
    }
    counted(
        r,
        "ex.slist.contention",
        "entries taken:",
        slist::contention_test(),
    );
    counted(
        r,
        "ex.pool.variants",
        "blocks:",
        crate::mm::pool::variants_test(),
    );
    r.check("ex.lookaside.fields", lookaside::fields_test);
    counted(
        r,
        "ex.lookaside.cache",
        "blocks kept:",
        lookaside::cache_test(),
    );
    counted(
        r,
        "ex.lookaside.routines",
        "calls of the list's own routines:",
        lookaside::routines_test(),
    );
    counted(
        r,
        "ex.resource.recursion",
        "acquisitions:",
        resource::recursion_test(),
    );
    r.check("ex.resource.hand-over", resource::hand_over_test);
    r.check("ex.resource.starve", resource::starve_test);
    counted(
        r,
        "ex.resource.table",
        "owner table entries:",
        resource::table_test(),
    );
    counted(
        r,
        "ex.resource.contention",
        "writes:",
        resource::contention_test(),
    );
    counted(r, "ex.timer.callback", "callbacks:", timer::callback_test());
    counted(r, "ex.timer.periodic", "callbacks:", timer::periodic_test());
    counted(
        r,
        "ex.timer.delete",
        "timers deleted:",
        timer::delete_test(),
    );
    r.check("ex.timer.wait", timer::wait_test);
    r.check("ex.pool.raise", pool_raise);
    r.check("ex.uuid.fields", uuid::fields_test);
    counted(r, "ex.uuid.unique", "UUIDs:", uuid::unique_test());
}

/// More than any pool holds.
const TOO_MUCH: usize = 1 << 46;
const TAG: u32 = u32::from_le_bytes(*b"NkPr");
/// `PagedPool`, and the two flag bits that say what failure looks like.
const PAGED: u32 = 1;
const QUOTA_FAIL_INSTEAD_OF_RAISE: u32 = 8;
const RAISE_IF_ALLOCATION_FAILURE: u32 = 16;

/// # Safety
/// None: a body for `except::raises`.
unsafe extern "C" fn with_quota(pool_type: usize) {
    pool::ExAllocatePoolWithQuotaTag(pool_type as u32, TOO_MUCH, TAG);
}

/// # Safety
/// None: a body for `except::raises`.
unsafe extern "C" fn with_tag(pool_type: usize) {
    pool::ExAllocatePoolWithTag(pool_type as u32, TOO_MUCH, TAG);
}

/// An allocation that cannot be made raises
/// `STATUS_INSUFFICIENT_RESOURCES` in its caller where Microsoft says
/// it does, and returns null where the caller asked for that.
fn pool_raise() -> Result<(), &'static str> {
    let no_memory = nk_ntabi::status::STATUS_INSUFFICIENT_RESOURCES as u32;
    super::except::raises(with_quota, PAGED as usize, no_memory)?;
    super::except::raises(
        with_tag,
        (PAGED | RAISE_IF_ALLOCATION_FAILURE) as usize,
        no_memory,
    )?;
    if !pool::ExAllocatePoolWithQuotaTag(PAGED | QUOTA_FAIL_INSTEAD_OF_RAISE, TOO_MUCH, TAG)
        .is_null()
        || !pool::ExAllocatePoolWithTag(PAGED, TOO_MUCH, TAG).is_null()
    {
        return Err("more memory than there is was allocated");
    }
    Ok(())
}
