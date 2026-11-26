//! `ExUuidCreate`: time-based UUIDs.
//! <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-exuuidcreate>
//!
//! The layout and the choice of each UUID's time are `nk_ex::uuid`'s.
//! The kernel keeps what one boot's UUIDs share, under a lock
//! (`doc/LOCKING.md`): the time of the last one, the clock sequence and
//! the node.
//!
//! NK has no network card, so the node is not a card's address: it is
//! random, marked as such, and every call returns
//! `RPC_NT_UUID_LOCAL_ONLY`, the success status Windows gives without a
//! card.
//!
//! The clock sequence and node are made at the first call from what the
//! kernel has that differs between boots: the wall clock, the cycle
//! counter and the time since boot. That is little entropy, and none of
//! it secret; a locally unique UUID promises neither.

#![allow(non_snake_case)]

use crate::arch;
use crate::ke::{Rank, SpinLock, time};
use nk_ex::uuid::{self, RPC_NT_UUID_LOCAL_ONLY, Sequencer};
use nk_ntabi::ex::GUID;
use nk_ntabi::status::NTSTATUS;

/// What this boot's UUIDs share.
struct Identity {
    sequencer: Sequencer,
    node: [u8; 6],
}

static IDENTITY: SpinLock<Option<Identity>> = SpinLock::new(Rank::Uuid, None);

/// [`ExUuidCreate`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-exuuidcreate):
/// a new version-1 UUID, later in time than every one before it.
/// Always `RPC_NT_UUID_LOCAL_ONLY`: see the top of the file. Windows'
/// `STATUS_RETRY`, for a caller faster than its clock, is never
/// returned.
///
/// # Safety
/// `uuid` points to writable storage for a `GUID`.
pub unsafe extern "C" fn ExUuidCreate(uuid: *mut GUID) -> NTSTATUS {
    let now = uuid::timestamp(time::system_time());
    let (timestamp, sequence, node) = {
        let mut identity = IDENTITY.lock();
        let identity = identity.get_or_insert_with(|| {
            let (sequence, node) =
                uuid::identity([time::system_time(), arch::counter(), time::interrupt_time()]);
            Identity {
                sequencer: Sequencer::new(sequence),
                node,
            }
        });
        let (timestamp, sequence) = identity.sequencer.next(now);
        (timestamp, sequence, identity.node)
    };
    // SAFETY: per the contract; a `GUID` is these 16 bytes.
    unsafe {
        uuid.cast::<[u8; 16]>()
            .write_unaligned(uuid::version1(timestamp, sequence, node));
    }
    RPC_NT_UUID_LOCAL_ONLY as NTSTATUS
}

// ---- tests --------------------------------------------------------------

use super::stress;
use core::sync::atomic::{AtomicU64, Ordering};

/// A UUID, and the parts the tests compare.
fn create() -> (NTSTATUS, GUID) {
    let mut uuid = GUID {
        Data1: 0,
        Data2: 0,
        Data3: 0,
        Data4: [0; 8],
    };
    // SAFETY: storage for one `GUID`.
    let status = unsafe { ExUuidCreate(&raw mut uuid) };
    (status, uuid)
}

/// The 60-bit time of a version-1 UUID.
fn time_of(uuid: &GUID) -> u64 {
    u64::from(uuid.Data3 & 0x0FFF) << 48 | u64::from(uuid.Data2) << 32 | u64::from(uuid.Data1)
}

/// Two UUIDs made one after the other: version 1, the RFC's variant, a
/// node marked local with the status that says so, the same clock
/// sequence and node, and the second later than the first.
pub fn fields_test() -> Result<(), &'static str> {
    let (first_status, first) = create();
    let (second_status, second) = create();
    let local = RPC_NT_UUID_LOCAL_ONLY as NTSTATUS;
    if first_status != local || second_status != local {
        return Err("a UUID made without a network card did not say it is only locally unique");
    }
    for uuid in [&first, &second] {
        if uuid.Data3 >> 12 != 1 || uuid.Data4[0] >> 6 != 0b10 {
            return Err("a UUID is not version 1 of the RFC's variant");
        }
        if uuid.Data4[2] & 0x81 != 0x81 {
            return Err("a random node is not marked as no card's address");
        }
    }
    if first.Data4 != second.Data4 {
        return Err("two UUIDs of one boot differ in clock sequence or node");
    }
    if time_of(&second) <= time_of(&first) {
        return Err("the second of two UUIDs is not later than the first");
    }
    // Within a few seconds of the wall clock, as a UUID time.
    let now = uuid::timestamp(time::system_time());
    if time_of(&second).abs_diff(now) > 50_000_000 {
        return Err("a UUID's time is not the wall clock's");
    }
    Ok(())
}

const THREADS: usize = 4;
const EACH: usize = 400;
static TIMES: [AtomicU64; THREADS * EACH] = [const { AtomicU64::new(0) }; THREADS * EACH];

fn maker(index: usize) {
    for slot in &TIMES[index * EACH..(index + 1) * EACH] {
        slot.store(time_of(&create().1), Ordering::Release);
    }
}

/// Threads making UUIDs at once never get the same time twice. Returns
/// the UUIDs made.
pub fn unique_test() -> Result<u32, &'static str> {
    stress::run(THREADS, maker)?;
    let mut times = [0u64; THREADS * EACH];
    for (time, slot) in times.iter_mut().zip(&TIMES) {
        *time = slot.load(Ordering::Acquire);
    }
    times.sort_unstable();
    if times.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("two UUIDs were given the same time");
    }
    Ok(times.len() as u32)
}
