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

use super::{module, resources};
use crate::io::driver;
use crate::io::file::{self, IoResult};
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::FILE_OBJECT;
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
fn cancelled(opened: *mut FILE_OBJECT) -> Result<u32, &'static str> {
    const READS: usize = 8;
    const ROUNDS: usize = 3;
    let mut seen = 0;
    for _ in 0..ROUNDS {
        let mut buffers = [[0xEEu8; 4]; READS];
        let mut pending = alloc::vec::Vec::new();
        for buffer in &mut buffers {
            // SAFETY: an open file; each buffer outlives its request,
            // which is waited for below.
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
    // The thread holds one read at a time, for half a second at most
    // times in two; the others were cancelled before it could reach
    // them all.
    if seen == 0 {
        return Err("no read was cancelled while it waited on the queue");
    }
    Ok(seen)
}

/// Load, open by both names, have a short read refused, optionally do
/// a whole read, close and unload.
fn cycle(image: &[u8], whole_read: bool) -> Result<(), &'static str> {
    let object = driver::load("cancel", image).map_err(|_| "load failed")?;
    let verdict = (|| {
        let by_device = file::open(DEVICE).map_err(|_| "open by device name failed")?;
        let by_link = file::open(DOS_NAME).map_err(|_| "open by link failed");
        let mut short = [0xEEu8; 2];
        let mut whole = [0xEEu8; 4];
        // SAFETY: `by_device` is open until the close below.
        let checks = unsafe {
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
            // SAFETY: each file came from `open` and is closed once.
            closed &= matches!(
                unsafe { file::close(file) },
                Ok(IoResult {
                    status: STATUS_SUCCESS,
                    ..
                })
            );
        }
        by_link?;
        match (checks, closed) {
            ((false, _), _) => Err("a short read was not refused"),
            ((_, false), _) => Err("a read did not complete with the driver's four bytes"),
            (_, false) => Err("close failed"),
            _ => Ok(()),
        }
    })();
    driver::unload(object)?;
    verdict
}

fn run(r: &mut Report, info: &BootInfo) {
    let Some(image) = module(info, "cancel.sys") else {
        return r.skip_rest(format_args!("module cancel.sys not provided"));
    };
    let before = resources();
    let result = driver::load("cancel", image)
        .map_err(|_| "load failed")
        .and_then(|object| {
            let result = file::open(DEVICE)
                .map_err(|_| "open failed")
                .and_then(|opened| {
                    let result = cancelled(opened);
                    // SAFETY: `opened` came from `open` and is closed once; no
                    // request of it is outstanding.
                    let _ = unsafe { file::close(opened) };
                    result
                });
            driver::unload(object)?;
            result
        });
    match result {
        Ok(n) if resources() == before => r.ok_with(
            "cancel.cancelled",
            format_args!("of 24 reads, cancelled: {n}"),
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
    let failed = (0..CYCLES).find_map(|i| cycle(image, i % 20 == 0).err().map(|why| (i, why)));
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
