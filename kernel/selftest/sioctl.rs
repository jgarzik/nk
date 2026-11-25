//! Microsoft's WDM IOCTL sample (`sioctl.sys`), unmodified, built with the
//! WDK by the nk-fixtures repository.
//!
//! Expected results follow the sample's published source: every control
//! request needs both buffers non-empty; the buffered and out-direct
//! requests return a fixed string (with its NUL) truncated to the output
//! length; the in-direct request reports the length of the direct buffer.
//!
//! `METHOD_NEITHER` is not sent: the driver probes the raw buffers as user
//! memory inside `__try`, which needs user address space and SEH.

use super::resources;
use crate::io::file::{self, IoError, IoResult};
use crate::io::service;
use crate::ldr;
use crate::mm::{PAGE_SIZE, pool};
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

const DEVICE: &str = "\\Device\\SIOCTL";
const DOS_NAME: &str = "\\DosDevices\\IoctlTest";
const DOS_ALIAS: &str = "\\??\\ioctltest";
/// What the driver answers, including the terminating NUL.
const REPLY: &[u8] = b"This String is from Device Driver !!!\0";
/// The sample's device type.
const SIOCTL_TYPE: u32 = 40000;
const IN_DIRECT: u32 = ctl_code(SIOCTL_TYPE, 0x900, METHOD_IN_DIRECT, 0);
const OUT_DIRECT: u32 = ctl_code(SIOCTL_TYPE, 0x901, METHOD_OUT_DIRECT, 0);
const BUFFERED: u32 = ctl_code(SIOCTL_TYPE, 0x902, METHOD_BUFFERED, 0);
const NEITHER: u32 = ctl_code(SIOCTL_TYPE, 0x903, METHOD_NEITHER, 0);
const UNKNOWN: u32 = ctl_code(SIOCTL_TYPE, 0x904, METHOD_BUFFERED, 0);
const FILL: u8 = 0xEE;
const TAG: u32 = u32::from_le_bytes(*b"NkTs");

type Check = Result<(), &'static str>;

fn ioctl(file: u64, code: u32, input: &[u8], output: &mut [u8]) -> Result<IoResult, &'static str> {
    file::device_control(file, code, input, output).map_err(|e| match e {
        IoError::Handle(_) => "the handle does not name an open file",
        IoError::NotCompleted { .. } => "the driver did not complete the request",
        IoError::StatusMismatch { .. } => "dispatch status differs from completion status",
        IoError::NoMemory => "out of memory",
        IoError::UnsupportedMethod => "buffer method not supported by the kernel",
    })
}

/// The reply, truncated to the output length, with the right byte count.
fn expect_reply(result: IoResult, output: &[u8]) -> Result<usize, &'static str> {
    let n = REPLY.len().min(output.len());
    if result
        != (IoResult {
            status: STATUS_SUCCESS,
            information: n,
        })
    {
        return Err("wrong status or byte count");
    }
    if output[..n] != REPLY[..n] {
        return Err("wrong payload");
    }
    Ok(n)
}

fn buffered(file: u64) -> Check {
    for len in [100, REPLY.len(), 10, 1] {
        let mut out = [FILL; 100];
        let r = ioctl(file, BUFFERED, b"hello from NK", &mut out[..len])?;
        let n = expect_reply(r, &out[..len])?;
        // The driver fills its whole system buffer, but the I/O manager
        // copies back only the bytes the driver reported.
        if out[n..].iter().any(|&b| b != FILL) {
            return Err("the kernel copied back more than the reported byte count");
        }
    }
    Ok(())
}

/// Direct output through an MDL. The buffer straddles a page boundary so
/// the MDL describes two pages and the driver's mapping must join them.
///
/// The sample copies the full output length into the direct buffer while
/// reporting only the string's length (`RtlCopyBytes(buffer, data,
/// outBufLength)` in its source). With direct I/O that lands in the
/// caller's own pages, so bytes after the reply are driver data, not the
/// caller's fill. What must hold is that nothing outside the buffer moves.
fn out_direct(file: u64) -> Check {
    let pages = pool::alloc(2 * PAGE_SIZE, TAG);
    if pages.is_null() {
        return Err("out of memory");
    }
    // SAFETY: `pages` is a fresh two-page allocation, freed below.
    let all = unsafe { core::slice::from_raw_parts_mut(pages, 2 * PAGE_SIZE) };
    all.fill(FILL);
    let start = PAGE_SIZE - 10;
    let result = ioctl(
        file,
        OUT_DIRECT,
        b"hello from NK",
        &mut all[start..start + 100],
    );
    let check = result.and_then(|r| {
        expect_reply(r, &all[start..start + 100])?;
        if all[..start]
            .iter()
            .chain(&all[start + 100..])
            .any(|&b| b != FILL)
        {
            return Err("memory outside the direct buffer was modified");
        }
        Ok(())
    });
    let _ = pool::free(pages);
    check
}

/// Direct input: the driver reads the MDL-described buffer and reports
/// its length.
fn in_direct(file: u64) -> Check {
    let mut data = *b"This String is from the requestor, sent with METHOD_IN_DIRECT\0\0\0";
    let before = data;
    let r = ioctl(file, IN_DIRECT, b"hello from NK", &mut data)?;
    if r != (IoResult {
        status: STATUS_SUCCESS,
        information: data.len(),
    }) {
        return Err("must succeed and report the direct buffer's length");
    }
    if data != before {
        return Err("an input-direct request modified the buffer");
    }
    Ok(())
}

fn bad_requests(file: u64) -> Check {
    let invalid = IoResult {
        status: STATUS_INVALID_PARAMETER,
        information: 0,
    };
    let mut out = [FILL; 16];
    for code in [BUFFERED, IN_DIRECT, OUT_DIRECT] {
        if ioctl(file, code, b"", &mut out)? != invalid
            || ioctl(file, code, b"x", &mut [])? != invalid
        {
            return Err("an empty input or output buffer must give STATUS_INVALID_PARAMETER");
        }
    }
    if ioctl(file, UNKNOWN, b"x", &mut out)?.status != STATUS_INVALID_DEVICE_REQUEST {
        return Err("an unknown control code must give STATUS_INVALID_DEVICE_REQUEST");
    }
    if out != [FILL; 16] {
        return Err("a failed request wrote to the output buffer");
    }
    // The driver registers no read routine: the kernel's default answers.
    match file::read(file, &mut out) {
        Ok(r) if r.status == STATUS_INVALID_DEVICE_REQUEST => Ok(()),
        _ => Err("a read must give STATUS_INVALID_DEVICE_REQUEST"),
    }
}

/// One full life of the driver: load, open, one request, close, unload.
fn cycle() -> Check {
    service::start("SIoctl").map_err(|_| "load failed")?;
    let file = super::open(DOS_NAME).map_err(|_| "open failed")?;
    let mut out = [FILL; 64];
    let verdict =
        ioctl(file, BUFFERED, b"cycle", &mut out).and_then(|r| expect_reply(r, &out).map(|_| ()));
    let closed = file::close(file);
    service::stop("SIoctl")?;
    verdict?;
    match closed {
        STATUS_SUCCESS => Ok(()),
        _ => Err("close failed"),
    }
}

pub static GROUP: Group = Group {
    names: &[
        "sioctl.load",
        "sioctl.open",
        "sioctl.buffered",
        "sioctl.out-direct",
        "sioctl.in-direct",
        "sioctl.bad-requests",
        "sioctl.neither",
        "sioctl.close",
        "sioctl.unload",
        "sioctl.no-leak",
        "sioctl.cycles",
    ],
    run,
    manual: false,
};

fn run(r: &mut Report, _: &BootInfo) {
    if ldr::boot_file("sioctl.sys").is_none() {
        return r.skip_rest(format_args!("module sioctl.sys not provided"));
    }
    let before = resources();
    if let Err(e) = service::create("SIoctl", "sioctl.sys").and_then(|()| service::start("SIoctl"))
    {
        return r.fail("sioctl.load", format_args!("{e:?}"));
    }
    r.ok("sioctl.load");

    // The device is reachable by its own name and through the symbolic
    // link the driver made, under either spelling of the DOS directory.
    let mut opened = alloc::vec::Vec::new();
    for name in [DEVICE, DOS_NAME, DOS_ALIAS] {
        match super::open(name) {
            Ok(file) => opened.push(file),
            Err(status) => kprintln!("sioctl: open {name} failed: {status:#x}"),
        }
    }
    if opened.len() == 3 {
        r.ok("sioctl.open");
        let file = opened[1];
        r.check("sioctl.buffered", || buffered(file));
        r.check("sioctl.out-direct", || out_direct(file));
        r.check("sioctl.in-direct", || in_direct(file));
        r.check("sioctl.bad-requests", || bad_requests(file));
        match file::device_control(file, NEITHER, b"x", &mut [0u8; 8]) {
            Err(IoError::UnsupportedMethod) => r.skip(
                "sioctl.neither",
                format_args!("METHOD_NEITHER needs user memory and SEH"),
            ),
            other => r.fail(
                "sioctl.neither",
                format_args!("expected the kernel to decline: {other:?}"),
            ),
        }
    } else {
        r.fail(
            "sioctl.open",
            format_args!("{} of 3 names opened", opened.len()),
        );
    }
    let mut closed = true;
    for file in opened.drain(..) {
        closed &= file::close(file) == STATUS_SUCCESS;
    }
    drop(opened);
    r.check("sioctl.close", || {
        if closed {
            Ok(())
        } else {
            Err("a close request failed")
        }
    });

    match service::stop("SIoctl") {
        Ok(()) if super::open(DOS_NAME).is_err() && super::open(DEVICE).is_err() => {
            r.ok("sioctl.unload")
        }
        Ok(()) => r.fail(
            "sioctl.unload",
            format_args!("device or symbolic link survived unload"),
        ),
        Err(why) => r.fail("sioctl.unload", format_args!("{why}")),
    }
    let after = resources();
    if after == before {
        r.ok("sioctl.no-leak");
    } else {
        r.fail(
            "sioctl.no-leak",
            format_args!("before {before:?}, after {after:?}"),
        );
    }

    const CYCLES: usize = 100;
    let failed = (0..CYCLES).find_map(|i| cycle().err().map(|why| (i, why)));
    let after = resources();
    match failed {
        Some((i, why)) => r.fail("sioctl.cycles", format_args!("cycle {i}: {why}")),
        None if after != before => r.fail(
            "sioctl.cycles",
            format_args!("leak after {CYCLES} cycles: before {before:?}, after {after:?}"),
        ),
        None => {
            kprintln!("sioctl: {CYCLES} load/exercise/unload cycles, resources unchanged");
            r.ok("sioctl.cycles");
        }
    }
}
