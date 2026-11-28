//! The executive resource (`ERESOURCE`): a reader/writer lock that knows
//! its owners, so a thread may take it again while it holds it.
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-eresource-routines>
//!
//! [`Resource`] is the part of an `ERESOURCE` that decides who gets in,
//! under the names Windows gives the fields. The owners other than the
//! first sit in a table the kernel allocates (`ERESOURCE.OwnerTable`);
//! the functions take it as a slice and answer [`Acquire::TableFull`]
//! when it must grow. [`OwnerEntry`] has the layout of `OWNER_ENTRY`.
//!
//! Every function is one transition, made under the resource's spin
//! lock. Threads are told apart by an address that is never zero.
//!
//! | Export | Here |
//! | --- | --- |
//! | `ExInitializeResourceLite` | [`Resource::new`] |
//! | `ExReinitializeResourceLite` | [`Resource::reinitialize`] |
//! | `ExDeleteResourceLite` | nothing to decide: the kernel frees the table |
//! | `ExAcquireResourceExclusiveLite` | [`Resource::acquire_exclusive`] |
//! | `ExAcquireResourceSharedLite`, `ExAcquireSharedStarveExclusive`, `ExAcquireSharedWaitForExclusive` | [`Resource::acquire_shared`] |
//! | `ExReleaseResourceLite`, `ExReleaseResourceForThreadLite` | [`Resource::release`] |
//! | `ExConvertExclusiveToSharedLite` | [`Resource::convert_exclusive_to_shared`] |
//! | `ExIsResourceAcquiredExclusiveLite` | [`Resource::is_acquired_exclusive`] |
//! | `ExIsResourceAcquiredSharedLite` | [`Resource::is_acquired_shared`] |
//! | `ExGetExclusiveWaiterCount`, `ExGetSharedWaiterCount` | the two waiter counts |
//!
//! # Waiting and waking
//!
//! [`Acquire::Wait`] has counted the caller as a waiter: the kernel
//! queues it (exclusive waiters in order of arrival) and puts it to
//! sleep. Nobody sleeping here tries again. Ownership is handed over: a
//! release that frees the resource for waiters says which
//! ([`Release::WakeExclusive`], [`Release::WakeShared`]), and the
//! releaser, before it drops the spin lock, takes those waiters off the
//! queue and records each as an owner with [`Resource::grant_exclusive`]
//! or [`Resource::grant_shared`]. Then it readies them, and they return
//! owning the resource.
//!
//! # Who goes first
//!
//! The acquire rules are Microsoft's, from the pages of the three shared
//! routines: a thread waiting for exclusive access holds back new shared
//! owners; a thread that already owns the resource gets it again
//! regardless; `StarveExclusive` ignores the exclusive waiters;
//! `WaitForExclusive` yields to them even when the caller is an owner.
//!
//! The order of hand-over is not documented; NK follows what ReactOS
//! does. When an exclusive owner lets go, every shared waiter gets in,
//! and only if there is none the oldest exclusive waiter. When the last
//! shared owner lets go, the oldest exclusive waiter gets in. So the two
//! kinds take turns and neither starves.
//!
//! Windows also raises the priority of owners that keep others waiting.
//! NK does not.

/// `ERESOURCE.Flag`: an exclusive owner holds the resource
/// (`ResourceOwnedExclusive` in `wdm.h`).
pub const RESOURCE_OWNED_EXCLUSIVE: u16 = 0x80;

/// The bug check for releasing a resource the thread does not own.
pub const RESOURCE_NOT_OWNED: u32 = 0xE3;

/// One owner and how many times it has acquired: `OWNER_ENTRY`. A free
/// slot has no thread.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct OwnerEntry {
    /// `OwnerThread`.
    pub thread: usize,
    /// Three flag bits NK leaves clear, then `OwnerCount`.
    bits: u32,
}

const _: () = assert!(size_of::<OwnerEntry>() == 2 * size_of::<usize>());

/// `OwnerCount` starts at this bit of an entry's second word, above
/// three flag bits.
pub const OWNER_COUNT_SHIFT: u32 = 3;

impl OwnerEntry {
    const ONE: u32 = 1 << OWNER_COUNT_SHIFT;

    pub const FREE: Self = Self { thread: 0, bits: 0 };

    const fn first(thread: usize) -> Self {
        Self {
            thread,
            bits: Self::ONE,
        }
    }

    /// `OwnerCount`: how many releases this owner owes.
    pub const fn count(&self) -> u32 {
        self.bits >> OWNER_COUNT_SHIFT
    }
}

/// The state of one resource.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Resource {
    /// `Flag`. Only [`RESOURCE_OWNED_EXCLUSIVE`] is used.
    pub flag: u16,
    /// `OwnerEntry`: the exclusive owner, or one of the shared owners.
    pub owner: OwnerEntry,
    /// `ActiveEntries`: how many threads own the resource.
    pub active_entries: u32,
    /// `ContentionCount`: how many acquisitions had to wait.
    pub contention_count: u32,
    /// `NumberOfSharedWaiters`.
    pub shared_waiters: u32,
    /// `NumberOfExclusiveWaiters`.
    pub exclusive_waiters: u32,
}

/// Which shared acquisition: the three differ in how they treat threads
/// waiting for exclusive access.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Shared {
    /// `ExAcquireResourceSharedLite`: waits behind them, unless the
    /// caller already owns the resource.
    Plain,
    /// `ExAcquireSharedStarveExclusive`: goes ahead of them.
    StarveExclusive,
    /// `ExAcquireSharedWaitForExclusive`: waits behind them even as an
    /// owner. It then sleeps until another thread releases on its behalf
    /// and the exclusive waiters have had their turn.
    WaitForExclusive,
}

/// What an acquirer does next.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Acquire {
    /// The caller owns the resource: return TRUE.
    Acquired,
    /// The caller is counted as a waiter: queue it and sleep until a
    /// releaser grants it the resource, then return TRUE.
    Wait,
    /// Not available and the caller will not wait: return FALSE.
    WouldBlock,
    /// The owner table has no room for the caller. Nothing changed:
    /// give the resource a larger table (the old entries copied, the
    /// new ones [`OwnerEntry::FREE`]) and call again.
    TableFull,
}

/// What a releaser does next.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Release {
    /// Nothing more.
    Done,
    /// Grant the resource to the oldest exclusive waiter and ready it.
    WakeExclusive,
    /// Grant the resource to every shared waiter, this many, and ready
    /// them.
    WakeShared(u32),
}

/// The thread does not own the resource it releases or converts: bug
/// check [`RESOURCE_NOT_OWNED`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct NotOwned;

/// The entry of `thread` among the owners; with `thread` zero, a free
/// slot.
fn find<'a>(
    owner: &'a mut OwnerEntry,
    table: &'a mut [OwnerEntry],
    thread: usize,
) -> Option<&'a mut OwnerEntry> {
    core::iter::once(owner)
        .chain(table.iter_mut())
        .find(|entry| entry.thread == thread)
}

impl Resource {
    /// A resource nobody owns.
    pub const fn new() -> Self {
        Self {
            flag: 0,
            owner: OwnerEntry::FREE,
            active_entries: 0,
            contention_count: 0,
            shared_waiters: 0,
            exclusive_waiters: 0,
        }
    }

    /// Back to a resource nobody owns, keeping its table.
    pub fn reinitialize(&mut self, table: &mut [OwnerEntry]) {
        *self = Self::new();
        table.fill(OwnerEntry::FREE);
    }

    fn own_exclusive(&mut self, thread: usize) {
        self.flag |= RESOURCE_OWNED_EXCLUSIVE;
        self.owner = OwnerEntry::first(thread);
        self.active_entries = 1;
    }

    /// Record one more shared owner. The inline entry is used when free.
    /// Otherwise a table slot, leaving one free for every shared waiter
    /// so that granting them cannot fail. `false` if there is none.
    fn add_shared(&mut self, table: &mut [OwnerEntry], thread: usize) -> bool {
        let slot = if self.owner.thread == 0 {
            Some(&mut self.owner)
        } else {
            table
                .iter_mut()
                .filter(|entry| entry.thread == 0)
                .nth(self.shared_waiters as usize)
        };
        let Some(slot) = slot else {
            return false;
        };
        *slot = OwnerEntry::first(thread);
        self.active_entries += 1;
        true
    }

    /// Count the caller as a shared waiter, if the table will have a
    /// slot for it when its turn comes.
    fn wait_shared(&mut self, table: &[OwnerEntry], wait: bool) -> Acquire {
        if !wait {
            return Acquire::WouldBlock;
        }
        let free = table.iter().filter(|entry| entry.thread == 0).count();
        if free <= self.shared_waiters as usize {
            return Acquire::TableFull;
        }
        self.shared_waiters += 1;
        self.contention_count += 1;
        Acquire::Wait
    }

    /// Exclusive access for `thread`: granted when nobody owns the
    /// resource or the thread already owns it exclusively. A thread that
    /// owns it shared and asks for exclusive waits for itself for ever,
    /// as on Windows.
    pub fn acquire_exclusive(&mut self, thread: usize, wait: bool) -> Acquire {
        if self.active_entries == 0 {
            self.own_exclusive(thread);
        } else if self.is_acquired_exclusive(thread) {
            self.owner.bits += OwnerEntry::ONE;
        } else if wait {
            self.exclusive_waiters += 1;
            self.contention_count += 1;
            return Acquire::Wait;
        } else {
            return Acquire::WouldBlock;
        }
        Acquire::Acquired
    }

    /// Shared access for `thread`. An exclusive owner asking gets its
    /// exclusive access once more; the resource does not become shared.
    pub fn acquire_shared(
        &mut self,
        table: &mut [OwnerEntry],
        thread: usize,
        wait: bool,
        how: Shared,
    ) -> Acquire {
        if self.active_entries == 0 {
            self.owner = OwnerEntry::first(thread);
            self.active_entries = 1;
            return Acquire::Acquired;
        }
        if self.flag & RESOURCE_OWNED_EXCLUSIVE != 0 {
            if self.owner.thread != thread {
                return self.wait_shared(table, wait);
            }
            self.owner.bits += OwnerEntry::ONE;
            return Acquire::Acquired;
        }
        let mine = find(&mut self.owner, table, thread);
        let behind_exclusive = self.exclusive_waiters > 0
            && match how {
                Shared::Plain => mine.is_none(),
                Shared::StarveExclusive => false,
                Shared::WaitForExclusive => true,
            };
        if behind_exclusive {
            return self.wait_shared(table, wait);
        }
        match mine {
            Some(entry) => entry.bits += OwnerEntry::ONE,
            None => {
                if !self.add_shared(table, thread) {
                    return Acquire::TableFull;
                }
            }
        }
        Acquire::Acquired
    }

    /// The releaser of [`Release::WakeExclusive`] makes the waiter it
    /// took off the queue the owner.
    pub fn grant_exclusive(&mut self, thread: usize) {
        self.exclusive_waiters -= 1;
        self.own_exclusive(thread);
    }

    /// The releaser of [`Release::WakeShared`] makes each waiter it took
    /// off the queue an owner.
    pub fn grant_shared(&mut self, table: &mut [OwnerEntry], thread: usize) {
        self.shared_waiters -= 1;
        match find(&mut self.owner, table, thread) {
            Some(entry) => entry.bits += OwnerEntry::ONE,
            None => {
                let room = self.add_shared(table, thread);
                debug_assert!(room, "a shared waiter's slot was reserved");
            }
        }
    }

    /// Give up one acquisition by `thread` (the caller, or the thread
    /// named to `ExReleaseResourceForThreadLite`). The resource is let go
    /// with the last one.
    pub fn release(
        &mut self,
        table: &mut [OwnerEntry],
        thread: usize,
    ) -> Result<Release, NotOwned> {
        let exclusive = self.flag & RESOURCE_OWNED_EXCLUSIVE != 0;
        // An exclusive owner is the only entry there is.
        let entry = find(&mut self.owner, table, thread).ok_or(NotOwned)?;
        entry.bits -= OwnerEntry::ONE;
        if entry.count() > 0 {
            return Ok(Release::Done);
        }
        *entry = OwnerEntry::FREE;
        self.active_entries -= 1;
        self.flag &= !RESOURCE_OWNED_EXCLUSIVE;
        Ok(if self.active_entries > 0 {
            Release::Done
        } else if exclusive && self.shared_waiters > 0 {
            Release::WakeShared(self.shared_waiters)
        } else if self.exclusive_waiters > 0 {
            Release::WakeExclusive
        } else {
            Release::Done
        })
    }

    /// The exclusive owner becomes a shared owner, keeping its count,
    /// and the shared waiters join it.
    pub fn convert_exclusive_to_shared(&mut self, thread: usize) -> Result<Release, NotOwned> {
        if !self.is_acquired_exclusive(thread) {
            return Err(NotOwned);
        }
        self.flag &= !RESOURCE_OWNED_EXCLUSIVE;
        Ok(if self.shared_waiters > 0 {
            Release::WakeShared(self.shared_waiters)
        } else {
            Release::Done
        })
    }

    /// `ExSetResourceOwnerPointer`: what `from` owns passes, count and
    /// all, to `to`, an owner pointer (an address whose low two bits are
    /// set) that later releases name. If `to` already owns the resource
    /// shared, the counts are one entry.
    pub fn set_owner(
        &mut self,
        table: &mut [OwnerEntry],
        from: usize,
        to: usize,
    ) -> Result<(), NotOwned> {
        let count = find(&mut self.owner, table, from).ok_or(NotOwned)?.bits;
        if let Some(existing) = find(&mut self.owner, table, to) {
            existing.bits += count;
            *find(&mut self.owner, table, from).ok_or(NotOwned)? = OwnerEntry::FREE;
            self.active_entries -= 1;
        } else {
            find(&mut self.owner, table, from).ok_or(NotOwned)?.thread = to;
        }
        Ok(())
    }

    /// Whether `thread` owns the resource exclusively.
    pub const fn is_acquired_exclusive(&self, thread: usize) -> bool {
        self.flag & RESOURCE_OWNED_EXCLUSIVE != 0 && self.owner.thread == thread
    }

    /// How many times `thread` has acquired the resource, shared or
    /// exclusive; zero if it does not own it.
    pub fn is_acquired_shared(&self, table: &[OwnerEntry], thread: usize) -> u32 {
        core::iter::once(&self.owner)
            .chain(table)
            .find(|entry| entry.thread == thread)
            .map_or(0, OwnerEntry::count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::explore;

    const A: usize = 0x1000;
    const B: usize = 0x2000;
    const C: usize = 0x3000;
    const D: usize = 0x4000;

    fn table(slots: usize) -> Vec<OwnerEntry> {
        vec![OwnerEntry::FREE; slots]
    }

    #[test]
    fn ownership_passes_to_an_owner_pointer() {
        const P: usize = 0x5003;
        let mut t = table(4);
        let mut r = Resource::new();
        assert_eq!(r.acquire_exclusive(A, true), Acquire::Acquired);
        assert_eq!(r.acquire_exclusive(A, true), Acquire::Acquired);
        assert_eq!(r.set_owner(&mut t, A, P), Ok(()));
        assert!(r.is_acquired_exclusive(P));
        assert!(!r.is_acquired_exclusive(A));
        assert_eq!(r.release(&mut t, P), Ok(Release::Done));
        assert_eq!(r.release(&mut t, P), Ok(Release::Done));
        assert_eq!(r.active_entries, 0);
        assert_eq!(r.set_owner(&mut t, A, P), Err(NotOwned));
        // Shared, onto a pointer that owns it already: one entry.
        assert_eq!(
            r.acquire_shared(&mut t, A, true, Shared::Plain),
            Acquire::Acquired
        );
        assert_eq!(
            r.acquire_shared(&mut t, B, true, Shared::Plain),
            Acquire::Acquired
        );
        assert_eq!(r.set_owner(&mut t, A, P), Ok(()));
        assert_eq!(r.set_owner(&mut t, B, P), Ok(()));
        assert_eq!(r.is_acquired_shared(&t, P), 2);
        assert_eq!(r.active_entries, 1);
    }

    #[test]
    fn an_owner_entry_is_laid_out_as_windows_lays_it() {
        assert_eq!(size_of::<OwnerEntry>(), 16);
        assert_eq!(core::mem::offset_of!(OwnerEntry, bits), 8);
        let mut entry = OwnerEntry::first(A);
        entry.bits += OwnerEntry::ONE;
        // OwnerCount starts at bit 3.
        assert_eq!((entry.bits, entry.count()), (2 << 3, 2));
        assert_eq!(RESOURCE_OWNED_EXCLUSIVE, 0x80);
        assert_eq!(RESOURCE_NOT_OWNED, 0xE3);
    }

    #[test]
    fn exclusive_is_recursive_and_released_as_often() {
        let (mut r, mut t) = (Resource::new(), table(0));
        assert_eq!(r.acquire_exclusive(A, true), Acquire::Acquired);
        assert_eq!(r.acquire_exclusive(A, false), Acquire::Acquired);
        // Shared, asked by the exclusive owner, is exclusive once more.
        for how in [
            Shared::Plain,
            Shared::StarveExclusive,
            Shared::WaitForExclusive,
        ] {
            assert_eq!(r.acquire_shared(&mut t, A, false, how), Acquire::Acquired);
        }
        assert!(r.is_acquired_exclusive(A));
        assert!(!r.is_acquired_exclusive(B));
        assert_eq!(r.is_acquired_shared(&t, A), 5);
        assert_eq!(r.is_acquired_shared(&t, B), 0);
        assert_eq!((r.active_entries, r.flag), (1, RESOURCE_OWNED_EXCLUSIVE));
        for left in (0..5).rev() {
            assert_eq!(r.release(&mut t, A), Ok(Release::Done));
            assert_eq!(r.is_acquired_shared(&t, A), left);
            assert_eq!(r.is_acquired_exclusive(A), left > 0);
        }
        assert_eq!(r, Resource::new());
    }

    #[test]
    fn shared_is_recursive_per_owner() {
        let (mut r, mut t) = (Resource::new(), table(2));
        for thread in [A, B, A, C, A] {
            assert_eq!(
                r.acquire_shared(&mut t, thread, true, Shared::Plain),
                Acquire::Acquired
            );
        }
        assert_eq!((r.active_entries, r.flag), (3, 0));
        assert_eq!(
            [A, B, C, D].map(|thread| r.is_acquired_shared(&t, thread)),
            [3, 1, 1, 0]
        );
        assert!(!r.is_acquired_exclusive(A));
        // The first owner is in the resource itself, the others in the
        // table.
        assert_eq!((r.owner.thread, t[0].thread, t[1].thread), (A, B, C));
        assert_eq!(r.release(&mut t, B), Ok(Release::Done));
        assert_eq!(t[0], OwnerEntry::FREE);
        for _ in 0..3 {
            assert_eq!(r.release(&mut t, A), Ok(Release::Done));
        }
        // The inline entry is free again and is the first one reused.
        assert_eq!(
            r.acquire_shared(&mut t, D, true, Shared::Plain),
            Acquire::Acquired
        );
        assert_eq!(r.owner.thread, D);
        assert_eq!(r.release(&mut t, C), Ok(Release::Done));
        assert_eq!(r.release(&mut t, D), Ok(Release::Done));
        assert_eq!(r, Resource::new());
    }

    #[test]
    fn without_waiting_the_answer_is_no() {
        let (mut r, mut t) = (Resource::new(), table(2));
        r.acquire_exclusive(A, true);
        assert_eq!(r.acquire_exclusive(B, false), Acquire::WouldBlock);
        for how in [
            Shared::Plain,
            Shared::StarveExclusive,
            Shared::WaitForExclusive,
        ] {
            assert_eq!(r.acquire_shared(&mut t, B, false, how), Acquire::WouldBlock);
        }
        r.release(&mut t, A).unwrap();

        r.acquire_shared(&mut t, A, true, Shared::Plain);
        assert_eq!(r.acquire_exclusive(B, false), Acquire::WouldBlock);
        // Even the shared owner itself: exclusive needs it unowned.
        assert_eq!(r.acquire_exclusive(A, false), Acquire::WouldBlock);
        // Nothing was counted or changed by the refusals.
        assert_eq!(
            (r.exclusive_waiters, r.shared_waiters, r.contention_count),
            (0, 0, 0)
        );
        assert_eq!(r.is_acquired_shared(&t, A), 1);
    }

    /// A owns shared and B waits for exclusive access.
    fn shared_with_an_exclusive_waiter(slots: usize) -> (Resource, Vec<OwnerEntry>) {
        let (mut r, mut t) = (Resource::new(), table(slots));
        assert_eq!(
            r.acquire_shared(&mut t, A, true, Shared::Plain),
            Acquire::Acquired
        );
        assert_eq!(r.acquire_exclusive(B, true), Acquire::Wait);
        assert_eq!((r.exclusive_waiters, r.contention_count), (1, 1));
        (r, t)
    }

    #[test]
    fn an_exclusive_waiter_holds_back_new_shared_owners() {
        let (mut r, mut t) = shared_with_an_exclusive_waiter(2);
        assert_eq!(
            r.acquire_shared(&mut t, C, false, Shared::Plain),
            Acquire::WouldBlock
        );
        assert_eq!(
            r.acquire_shared(&mut t, C, true, Shared::Plain),
            Acquire::Wait
        );
        assert_eq!((r.shared_waiters, r.contention_count), (1, 2));
        // The owner itself is let in again.
        assert_eq!(
            r.acquire_shared(&mut t, A, false, Shared::Plain),
            Acquire::Acquired
        );
        assert_eq!(r.is_acquired_shared(&t, A), 2);
    }

    #[test]
    fn starve_exclusive_goes_ahead_of_the_waiter() {
        let (mut r, mut t) = shared_with_an_exclusive_waiter(2);
        let how = Shared::StarveExclusive;
        assert_eq!(r.acquire_shared(&mut t, C, false, how), Acquire::Acquired);
        assert_eq!(r.acquire_shared(&mut t, A, false, how), Acquire::Acquired);
        assert_eq!(r.active_entries, 2);
    }

    #[test]
    fn wait_for_exclusive_yields_even_as_an_owner() {
        let (mut r, mut t) = shared_with_an_exclusive_waiter(1);
        let how = Shared::WaitForExclusive;
        assert_eq!(r.acquire_shared(&mut t, C, false, how), Acquire::WouldBlock);
        assert_eq!(r.acquire_shared(&mut t, A, false, how), Acquire::WouldBlock);
        assert_eq!(r.acquire_shared(&mut t, A, true, how), Acquire::Wait);
        // A sleeps owning the resource. Another thread releases for it;
        // the exclusive waiter has its turn; then A is let back in.
        assert_eq!(r.release(&mut t, A), Ok(Release::WakeExclusive));
        r.grant_exclusive(B);
        assert!(r.is_acquired_exclusive(B));
        assert_eq!(r.release(&mut t, B), Ok(Release::WakeShared(1)));
        r.grant_shared(&mut t, A);
        assert_eq!(r.is_acquired_shared(&t, A), 1);
        assert_eq!(
            (r.shared_waiters, r.exclusive_waiters, r.active_entries),
            (0, 0, 1)
        );

        // With nobody waiting for exclusive it is the plain acquisition.
        assert_eq!(r.acquire_shared(&mut t, A, false, how), Acquire::Acquired);
        assert_eq!(r.acquire_shared(&mut t, C, false, how), Acquire::Acquired);
    }

    #[test]
    fn a_waiting_owner_granted_again_keeps_one_entry() {
        // A owns shared twice, waits behind B, and one of its two
        // acquisitions is released for it; C starves B meanwhile, so the
        // resource stays shared until C lets go.
        let (mut r, mut t) = shared_with_an_exclusive_waiter(2);
        r.acquire_shared(&mut t, A, true, Shared::Plain);
        assert_eq!(
            r.acquire_shared(&mut t, A, true, Shared::WaitForExclusive),
            Acquire::Wait
        );
        assert_eq!(r.release(&mut t, A), Ok(Release::Done));
        assert_eq!(r.release(&mut t, A), Ok(Release::WakeExclusive));
        r.grant_exclusive(B);
        assert_eq!(
            r.acquire_shared(&mut t, C, true, Shared::Plain),
            Acquire::Wait
        );
        // B turns shared: both waiters join it.
        assert_eq!(r.convert_exclusive_to_shared(B), Ok(Release::WakeShared(2)));
        r.grant_shared(&mut t, A);
        r.grant_shared(&mut t, C);
        assert_eq!(
            [A, B, C].map(|thread| r.is_acquired_shared(&t, thread)),
            [1, 1, 1]
        );
        // Granted an entry it still has, a waiter's count goes up.
        let (mut r, mut t) = shared_with_an_exclusive_waiter(1);
        assert_eq!(
            r.acquire_shared(&mut t, A, true, Shared::WaitForExclusive),
            Acquire::Wait
        );
        r.grant_shared(&mut t, A);
        assert_eq!((r.is_acquired_shared(&t, A), r.active_entries), (2, 1));
    }

    #[test]
    fn an_exclusive_release_lets_the_shared_waiters_in_first() {
        let (mut r, mut t) = (Resource::new(), table(2));
        r.acquire_exclusive(A, true);
        assert_eq!(r.acquire_exclusive(B, true), Acquire::Wait);
        assert_eq!(
            r.acquire_shared(&mut t, C, true, Shared::Plain),
            Acquire::Wait
        );
        assert_eq!(
            r.acquire_shared(&mut t, D, true, Shared::StarveExclusive),
            Acquire::Wait
        );
        assert_eq!(r.release(&mut t, A), Ok(Release::WakeShared(2)));
        r.grant_shared(&mut t, C);
        r.grant_shared(&mut t, D);
        assert_eq!((r.active_entries, r.flag, r.shared_waiters), (2, 0, 0));
        // Then the exclusive waiter, when the last of them lets go.
        assert_eq!(r.release(&mut t, C), Ok(Release::Done));
        assert_eq!(r.release(&mut t, D), Ok(Release::WakeExclusive));
        r.grant_exclusive(B);
        assert_eq!((r.active_entries, r.exclusive_waiters), (1, 0));
        assert!(r.is_acquired_exclusive(B));
        assert_eq!(r.release(&mut t, B), Ok(Release::Done));
        assert_eq!(r.contention_count, 3);

        // With no shared waiter, exclusive passes to exclusive.
        let mut r = Resource::new();
        r.acquire_exclusive(A, true);
        r.acquire_exclusive(B, true);
        assert_eq!(r.release(&mut t, A), Ok(Release::WakeExclusive));
    }

    #[test]
    fn conversion_keeps_the_count_and_admits_shared_waiters() {
        let (mut r, mut t) = (Resource::new(), table(1));
        r.acquire_exclusive(A, true);
        r.acquire_exclusive(A, true);
        assert_eq!(r.convert_exclusive_to_shared(A), Ok(Release::Done));
        assert!(!r.is_acquired_exclusive(A));
        assert_eq!(
            (r.is_acquired_shared(&t, A), r.flag, r.active_entries),
            (2, 0, 1)
        );
        assert_eq!(
            r.acquire_shared(&mut t, B, false, Shared::Plain),
            Acquire::Acquired
        );
        // Not exclusive any more, or never the owner: refused.
        assert_eq!(r.convert_exclusive_to_shared(A), Err(NotOwned));
        let mut r = Resource::new();
        r.acquire_exclusive(A, true);
        assert_eq!(r.convert_exclusive_to_shared(B), Err(NotOwned));
        assert_eq!(
            Resource::new().convert_exclusive_to_shared(A),
            Err(NotOwned)
        );
    }

    #[test]
    fn releasing_what_is_not_owned_is_refused() {
        let (mut r, mut t) = (Resource::new(), table(1));
        assert_eq!(r.release(&mut t, A), Err(NotOwned));
        r.acquire_exclusive(A, true);
        assert_eq!(r.release(&mut t, B), Err(NotOwned));
        r.release(&mut t, A).unwrap();
        assert_eq!(r.release(&mut t, A), Err(NotOwned));
        r.acquire_shared(&mut t, A, true, Shared::Plain);
        assert_eq!(r.release(&mut t, B), Err(NotOwned));
        assert_eq!(r.is_acquired_shared(&t, A), 1);
    }

    #[test]
    fn a_full_table_is_reported_and_nothing_changes() {
        let (mut r, mut t) = (Resource::new(), table(0));
        // The first shared owner needs no table.
        assert_eq!(
            r.acquire_shared(&mut t, A, true, Shared::Plain),
            Acquire::Acquired
        );
        let before = r.clone();
        assert_eq!(
            r.acquire_shared(&mut t, B, true, Shared::Plain),
            Acquire::TableFull
        );
        assert_eq!(r, before);
        let mut t = table(1);
        assert_eq!(
            r.acquire_shared(&mut t, B, true, Shared::Plain),
            Acquire::Acquired
        );
        assert_eq!(
            r.acquire_shared(&mut t, C, false, Shared::Plain),
            Acquire::TableFull
        );

        // A waiter needs a slot kept for it; without waiting it needs
        // none.
        let (mut r, mut t) = (Resource::new(), table(0));
        r.acquire_exclusive(A, true);
        assert_eq!(
            r.acquire_shared(&mut t, B, false, Shared::Plain),
            Acquire::WouldBlock
        );
        assert_eq!(
            r.acquire_shared(&mut t, B, true, Shared::Plain),
            Acquire::TableFull
        );
        assert_eq!((r.shared_waiters, r.contention_count), (0, 0));
        let mut t = table(1);
        assert_eq!(
            r.acquire_shared(&mut t, B, true, Shared::Plain),
            Acquire::Wait
        );
        assert_eq!(
            r.acquire_shared(&mut t, C, true, Shared::Plain),
            Acquire::TableFull
        );
    }

    #[test]
    fn a_waiters_slot_is_not_given_to_a_newcomer() {
        // A and C own shared (C fills one of two table slots); B waits
        // for exclusive; D waits for shared and so reserves the other.
        let (mut r, mut t) = shared_with_an_exclusive_waiter(2);
        let starve = Shared::StarveExclusive;
        assert_eq!(r.acquire_shared(&mut t, C, true, starve), Acquire::Acquired);
        assert_eq!(
            r.acquire_shared(&mut t, D, true, Shared::Plain),
            Acquire::Wait
        );
        assert_eq!(
            r.acquire_shared(&mut t, 0x5000, true, starve),
            Acquire::TableFull
        );
        // D's turn comes with every slot taken but its own.
        assert_eq!(r.release(&mut t, A), Ok(Release::Done));
        assert_eq!(
            r.acquire_shared(&mut t, 0x5000, true, starve),
            Acquire::Acquired
        );
        assert_eq!(r.release(&mut t, C), Ok(Release::Done));
        assert_eq!(r.release(&mut t, 0x5000), Ok(Release::WakeExclusive));
        r.grant_exclusive(B);
        assert_eq!(r.release(&mut t, B), Ok(Release::WakeShared(1)));
        r.grant_shared(&mut t, D);
        assert_eq!(r.is_acquired_shared(&t, D), 1);
    }

    #[test]
    fn reinitialising_forgets_everything() {
        let (mut r, mut t) = shared_with_an_exclusive_waiter(1);
        r.acquire_shared(&mut t, C, true, Shared::StarveExclusive);
        r.reinitialize(&mut t);
        assert_eq!(r, Resource::new());
        assert_eq!(t, table(1));
    }

    // The model: a few threads, each running a script against one
    // resource. Each operation is one step, as the spin lock makes it.

    #[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
    enum Op {
        Exclusive {
            wait: bool,
        },
        Shared {
            how: Shared,
            wait: bool,
        },
        /// Exclusive to shared, if the thread owns exclusively.
        Convert,
        /// Give up one acquisition, if the thread has any.
        Release,
    }

    #[derive(Clone, PartialEq, Eq, Hash, Debug)]
    struct Thread {
        script: &'static [Op],
        at: usize,
        asleep: bool,
        /// Acquisitions not yet released, and of which kind.
        owns: u32,
        exclusive: bool,
    }

    #[derive(Clone, PartialEq, Eq, Hash, Debug)]
    struct World {
        resource: Resource,
        table: Vec<OwnerEntry>,
        exclusive_queue: Vec<usize>,
        shared_queue: Vec<usize>,
        threads: Vec<Thread>,
        /// A deliberately broken releaser, to show the checker can fail:
        /// it grants the resource and forgets to ready the thread.
        forgets_to_ready: bool,
    }

    const fn id(i: usize) -> usize {
        (i + 1) << 12
    }

    impl World {
        fn new(scripts: &[&'static [Op]]) -> Self {
            World {
                resource: Resource::new(),
                table: Vec::new(),
                exclusive_queue: Vec::new(),
                shared_queue: Vec::new(),
                threads: scripts
                    .iter()
                    .map(|&script| Thread {
                        script,
                        at: 0,
                        asleep: false,
                        owns: 0,
                        exclusive: false,
                    })
                    .collect(),
                forgets_to_ready: false,
            }
        }

        fn finished(&self) -> bool {
            self.threads.iter().all(|t| t.at == t.script.len())
        }

        fn steps(&self) -> Vec<World> {
            (0..self.threads.len())
                .filter(|&i| {
                    let t = &self.threads[i];
                    t.at < t.script.len() && !t.asleep
                })
                .map(|i| {
                    let mut next = self.clone();
                    next.step(i);
                    next.check();
                    next
                })
                .collect()
        }

        fn owned(&mut self, i: usize, exclusive: bool) {
            let t = &mut self.threads[i];
            t.owns += 1;
            t.exclusive = exclusive;
            t.at += 1;
            if !self.forgets_to_ready {
                t.asleep = false;
            }
        }

        fn wake(&mut self, release: Release) {
            match release {
                Release::Done => {}
                Release::WakeExclusive => {
                    let i = self.exclusive_queue.remove(0);
                    self.resource.grant_exclusive(id(i));
                    self.owned(i, true);
                }
                Release::WakeShared(count) => {
                    assert_eq!(count as usize, self.shared_queue.len());
                    for i in core::mem::take(&mut self.shared_queue) {
                        self.resource.grant_shared(&mut self.table, id(i));
                        self.owned(i, false);
                    }
                }
            }
        }

        fn step(&mut self, i: usize) {
            let me = id(i);
            match self.threads[i].script[self.threads[i].at] {
                Op::Exclusive { wait } => match self.resource.acquire_exclusive(me, wait) {
                    Acquire::Acquired => self.owned(i, true),
                    Acquire::Wait => {
                        self.exclusive_queue.push(i);
                        self.threads[i].asleep = true;
                    }
                    Acquire::WouldBlock => self.threads[i].at += 1,
                    Acquire::TableFull => unreachable!(),
                },
                Op::Shared { how, wait } => loop {
                    let shared_by_others = self.resource.flag == 0
                        && self.resource.active_entries > 0
                        && self.threads[i].owns == 0;
                    match self.resource.acquire_shared(&mut self.table, me, wait, how) {
                        Acquire::Acquired => {
                            // The fairness rule: a newcomer does not join
                            // the shared owners past an exclusive waiter,
                            // unless it asked to starve them.
                            if shared_by_others && how != Shared::StarveExclusive {
                                assert!(self.exclusive_queue.is_empty(), "{self:?}");
                            }
                            let exclusive = self.threads[i].exclusive;
                            self.owned(i, exclusive);
                        }
                        Acquire::Wait => {
                            self.shared_queue.push(i);
                            self.threads[i].asleep = true;
                        }
                        Acquire::WouldBlock => self.threads[i].at += 1,
                        Acquire::TableFull => {
                            // The kernel's part: a larger table.
                            self.table.push(OwnerEntry::FREE);
                            continue;
                        }
                    }
                    break;
                },
                Op::Convert => {
                    if self.threads[i].exclusive {
                        let release = self.resource.convert_exclusive_to_shared(me).unwrap();
                        self.threads[i].exclusive = false;
                        self.wake(release);
                    }
                    self.threads[i].at += 1;
                }
                Op::Release => {
                    if self.threads[i].owns > 0 {
                        let release = self.resource.release(&mut self.table, me).unwrap();
                        let t = &mut self.threads[i];
                        t.owns -= 1;
                        t.exclusive &= t.owns > 0;
                        self.wake(release);
                    }
                    self.threads[i].at += 1;
                }
            }
        }

        /// What must hold between any two steps.
        fn check(&self) {
            let r = &self.resource;
            let owners = self.threads.iter().filter(|t| t.owns > 0).count();
            let writers = self.threads.iter().filter(|t| t.exclusive).count();
            // Mutual exclusion: an exclusive owner is the only owner.
            assert!(writers == 0 || owners == 1, "{self:?}");
            // The resource tells the truth about its owners.
            assert_eq!(r.flag == RESOURCE_OWNED_EXCLUSIVE, writers == 1, "{self:?}");
            assert_eq!(r.active_entries as usize, owners, "{self:?}");
            for (i, t) in self.threads.iter().enumerate() {
                assert_eq!(r.is_acquired_shared(&self.table, id(i)), t.owns, "{self:?}");
                assert_eq!(r.is_acquired_exclusive(id(i)), t.exclusive, "{self:?}");
            }
            // And about its waiters.
            assert_eq!(r.exclusive_waiters as usize, self.exclusive_queue.len());
            assert_eq!(r.shared_waiters as usize, self.shared_queue.len());
            let free = self.table.iter().filter(|e| e.thread == 0).count();
            assert!(free >= self.shared_queue.len(), "{self:?}");
            // Nobody waits for a resource nobody owns.
            if owners == 0 {
                assert_eq!((r.exclusive_waiters, r.shared_waiters), (0, 0), "{self:?}");
            }
            // Shared waiters wait only behind exclusive access, held or
            // wanted.
            if r.shared_waiters > 0 {
                assert!(writers == 1 || r.exclusive_waiters > 0, "{self:?}");
            }
        }
    }

    const PLAIN: Op = Op::Shared {
        how: Shared::Plain,
        wait: true,
    };
    const STARVE: Op = Op::Shared {
        how: Shared::StarveExclusive,
        wait: true,
    };
    const YIELD: Op = Op::Shared {
        how: Shared::WaitForExclusive,
        wait: true,
    };
    const EXCLUSIVE: Op = Op::Exclusive { wait: true };

    // No script takes exclusive while it owns shared, or yields to
    // exclusive waiters while it owns shared: those wait for ever by
    // design.
    const SCRIPTS: &[&[Op]] = &[
        &[EXCLUSIVE, Op::Release],
        &[PLAIN, Op::Release],
        &[STARVE, Op::Release],
        &[YIELD, Op::Release],
        &[EXCLUSIVE, EXCLUSIVE, Op::Release, Op::Release],
        &[PLAIN, PLAIN, Op::Release, Op::Release],
        &[EXCLUSIVE, PLAIN, Op::Release, Op::Release],
        &[EXCLUSIVE, Op::Convert, Op::Release],
        &[Op::Exclusive { wait: false }, Op::Release],
        &[
            Op::Shared {
                how: Shared::Plain,
                wait: false,
            },
            Op::Release,
        ],
        &[PLAIN, Op::Release, EXCLUSIVE, Op::Release],
        &[
            EXCLUSIVE,
            Op::Release,
            STARVE,
            PLAIN,
            Op::Release,
            Op::Release,
        ],
    ];

    #[test]
    fn every_interleaving_of_three_threads_excludes_and_wakes() {
        let mut states = 0;
        for a in SCRIPTS {
            for b in SCRIPTS {
                for c in SCRIPTS {
                    let world = World::new(&[a, b, c]);
                    let (seen, _) = explore(
                        world,
                        |w| {
                            let next = w.steps();
                            if next.is_empty() && w.finished() {
                                // All done: nobody owns it, nobody
                                // waits, every slot is free again.
                                let contention_count = w.resource.contention_count;
                                let unowned = Resource {
                                    contention_count,
                                    ..Resource::new()
                                };
                                assert_eq!(w.resource, unowned);
                                assert!(w.table.iter().all(|e| *e == OwnerEntry::FREE));
                            }
                            next
                        },
                        World::finished,
                    );
                    states += seen;
                }
            }
        }
        // The check is not vacuous: it walked a real state space.
        assert!(states > 50_000, "{states}");
    }

    #[test]
    #[should_panic(expected = "stuck with work left")]
    fn the_model_catches_a_lost_wake_up() {
        let scripts = [SCRIPTS[0], SCRIPTS[0]];
        let mut world = World::new(&scripts);
        world.forgets_to_ready = true;
        explore(world, World::steps, World::finished);
    }
}
