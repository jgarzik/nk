//! Microsoft's WDM cancel sample (`cancel.sys`), unmodified, built with
//! the WDK by the nk-fixtures repository.
//!
//! The driver queues each read on a cancel-safe queue; a system thread
//! of its own takes reads off one at a time and completes each with
//! four bytes, at once or after half a second (the sample decides by
//! the clock). `oracle.cancel` holds the plain requests to what Windows
//! answered. Here are the things a transcript cannot fix line by line:
//! reads cancelled while they wait, and loading and unloading again and
//! again.

use super::resources;
use crate::io::file::{self, IoResult};
use crate::io::service;
use crate::ldr;
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &["cancel.cancelled", "cancel.cycles"],
    run,
    manual: false,
};

const DEVICE: &str = "\\Device\\CANCELSAMP";
const DOS_NAME: &str = "\\DosDevices\\CancelSamp";
/// `STATUS_CANCELLED`
const CANCELLED: NTSTATUS = 0xC000_0120u32 as NTSTATUS;
/// What a completed read holds: the counter the driver's thread ran
/// down.
const DONE: [u8; 4] = [0xFF; 4];

/// Reads are started together and cancelled at once. The driver's
/// thread has one in hand by then, which it completes; the rest wait
/// on the queue unless the thread gets to them first. Each comes back
/// exactly once: done, with its four bytes, or cancelled, with none.
/// Returns how many were cancelled.
fn cancelled(opened: u64) -> Result<u32, &'static str> {
    const READS: usize = 8;
    // The sample decides by the clock whether its thread completes a
    // read at once or half a second later, the same way for reads that
    // arrive within one clock tick. A round in which it completes all
    // eight at once has nothing left to cancel; a tick later the answer
    // is as good as a coin's. Rounds go on until one has cancellations.
    const ROUNDS: usize = 40;
    let mut seen = 0;
    for _ in 0..ROUNDS {
        if seen != 0 {
            break;
        }
        crate::ke::time::stall(16_000);
        let mut buffers = [[0xEEu8; 4]; READS];
        let mut pending = alloc::vec::Vec::new();
        for buffer in &mut buffers {
            // SAFETY: each buffer outlives its request, which is waited
            // for below.
            pending.push(
                unsafe { file::read_start(opened, buffer) }
                    .map_err(|_| "a read could not be sent")?,
            );
        }
        for request in &pending {
            request.cancel();
        }
        let mut results = alloc::vec::Vec::new();
        for request in pending {
            results.push(request.wait().map_err(|_| "a read was never completed")?);
        }
        for (result, buffer) in results.iter().zip(&buffers) {
            match (result.status, result.information) {
                (STATUS_SUCCESS, 4) if *buffer == DONE => {}
                (CANCELLED, 0) if *buffer == [0xEE; 4] => seen += 1,
                _ => return Err("a read came back neither done nor cancelled"),
            }
        }
    }
    if seen == 0 {
        return Err("no read was cancelled while it waited on the queue");
    }
    Ok(seen)
}

/// Load, open by both names, have a short read refused, optionally do
/// a whole read, close and unload.
fn cycle(whole_read: bool) -> Result<(), &'static str> {
    service::start("cancel").map_err(|_| "load failed")?;
    let verdict = (|| {
        let by_device = super::open(DEVICE).map_err(|_| "open by device name failed")?;
        let by_link = super::open(DOS_NAME).map_err(|_| "open by link failed");
        let mut short = [0xEEu8; 2];
        let mut whole = [0xEEu8; 4];
        let checks = {
            let refused = matches!(
                file::read(by_device, &mut short),
                Ok(IoResult {
                    status: STATUS_BUFFER_TOO_SMALL,
                    information: 0
                })
            );
            let read = !whole_read
                || (matches!(
                    file::read(by_device, &mut whole),
                    Ok(IoResult {
                        status: STATUS_SUCCESS,
                        information: 4
                    })
                ) && whole == DONE);
            (refused, read)
        };
        let mut closed = true;
        for file in [Ok(by_device), by_link].into_iter().flatten() {
            closed &= file::close(file) == STATUS_SUCCESS;
        }
        by_link?;
        match (checks, closed) {
            ((false, _), _) => Err("a short read was not refused"),
            ((_, false), _) => Err("a read did not complete with the driver's four bytes"),
            (_, false) => Err("close failed"),
            _ => Ok(()),
        }
    })();
    service::stop("cancel")?;
    verdict
}

fn run(r: &mut Report, _: &BootInfo) {
    if ldr::boot_file("cancel.sys").is_none() {
        return r.skip_rest(format_args!("module cancel.sys not provided"));
    }
    let before = resources();
    let result = service::create("cancel", "cancel.sys")
        .and_then(|()| service::start("cancel"))
        .map_err(|_| "load failed")
        .and_then(|_| {
            let result = super::open(DEVICE)
                .map_err(|_| "open failed")
                .and_then(|opened| {
                    let result = cancelled(opened);
                    file::close(opened);
                    result
                });
            service::stop("cancel")?;
            result
        });
    match result {
        Ok(n) if resources() == before => r.ok_with(
            "cancel.cancelled",
            format_args!("reads cancelled while queued: {n}"),
        ),
        Ok(_) => r.fail(
            "cancel.cancelled",
            format_args!("leak: before {before:?}, after {:?}", resources()),
        ),
        Err(why) => r.fail("cancel.cancelled", format_args!("{why}")),
    }

    // A whole read takes up to half a second, so only some cycles do
    // one; `oracle.cancel` does more.
    const CYCLES: usize = 100;
    let failed = (0..CYCLES).find_map(|i| cycle(i % 20 == 0).err().map(|why| (i, why)));
    let after = resources();
    match failed {
        Some((i, why)) => r.fail("cancel.cycles", format_args!("cycle {i}: {why}")),
        None if after != before => r.fail(
            "cancel.cycles",
            format_args!("leak after {CYCLES} cycles: before {before:?}, after {after:?}"),
        ),
        None => r.ok_with(
            "cancel.cycles",
            format_args!("load/exercise/unload cycles, resources unchanged: {CYCLES}"),
        ),
    }
}
