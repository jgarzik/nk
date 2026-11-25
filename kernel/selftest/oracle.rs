//! Replay the oracle scripts and hold NK to what Windows did.
//!
//! `oracle/<name>.script` lists requests to make of a driver. It was
//! replayed on real Windows, which produced `oracle/<name>.txt`. Here the
//! same script runs against the same driver binary on NK, and each line NK
//! produces must be the line Windows produced. `oracle/README.md` defines
//! the formats.

use super::module;
use crate::io::driver;
use crate::io::file::{self, IoResult};
use crate::test::{Group, Report};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use nk_bootinfo::BootInfo;
use nk_ntabi::io::{DRIVER_OBJECT, FILE_OBJECT};
use nk_oracle::{Checker, Dump, FILL, Mismatch, Outcome, Step};

/// What a script has open and loaded while it runs.
struct Replay<'a> {
    info: &'a BootInfo,
    files: Vec<(&'a str, *mut FILE_OBJECT)>,
    drivers: Vec<(&'a str, *mut DRIVER_OBJECT)>,
}

fn outcome(r: IoResult) -> Outcome {
    Outcome {
        status: r.status as u32,
        information: r.information,
    }
}

impl<'a> Replay<'a> {
    fn file(&self, handle: &str) -> Result<*mut FILE_OBJECT, String> {
        self.files
            .iter()
            .find(|(h, _)| *h == handle)
            .map(|(_, f)| *f)
            .ok_or_else(|| format!("handle {handle} is not open"))
    }

    fn load(&mut self, service: &'a str, file: &str) -> &'static str {
        let Some(image) = module(self.info, file) else {
            return "failed";
        };
        match driver::load(service, image) {
            Ok(object) => {
                self.drivers.push((service, object));
                "ok"
            }
            Err(e) => {
                kprintln!("oracle: load {service}: {e:?}");
                "failed"
            }
        }
    }

    fn unload(&mut self, service: &str) -> &'static str {
        let Some(i) = self.drivers.iter().position(|(s, _)| *s == service) else {
            return "failed";
        };
        match driver::unload(self.drivers.remove(i).1) {
            Ok(()) => "ok",
            Err(why) => {
                kprintln!("oracle: unload {service}: {why}");
                "failed"
            }
        }
    }

    /// Carry out one step; the text is what follows the step in its
    /// transcript line.
    fn step(&mut self, step: Step<'a>) -> Result<String, String> {
        Ok(match step {
            Step::Load { service, file } => self.load(service, file).into(),
            // Part of Windows there; here it is a boot module like any other.
            Step::Use { service } => self.load(service, &format!("{service}.sys")).into(),
            Step::Unload { service } => self.unload(service).into(),
            Step::Open { handle, path } => match file::open(path) {
                Ok(file) => {
                    self.files.push((handle, file));
                    format!("{:08x}", 0)
                }
                Err(status) => format!("{:08x}", status as u32),
            },
            Step::Close { handle } => {
                let file = self.file(handle)?;
                self.files.retain(|(h, _)| *h != handle);
                // SAFETY: the file came from `open` and was just removed
                // from the table, so it is closed exactly once.
                let r = unsafe { file::close(file) }.map_err(|e| format!("{e:?}"))?;
                format!("{:08x}", r.status as u32)
            }
            Step::Ioctl {
                handle,
                code,
                input,
                output_len,
            } => {
                let input: Vec<u8> = input.bytes().collect();
                let mut output = vec![FILL; output_len];
                // SAFETY: the file is open until its `close` step.
                let r =
                    unsafe { file::device_control(self.file(handle)?, code, &input, &mut output) }
                        .map_err(|e| format!("{e:?}"))?;
                format!("{} {}", outcome(r), Dump(&output))
            }
            Step::Read { handle, len } => {
                let mut buffer = vec![FILL; len];
                // SAFETY: as above.
                let r = unsafe { file::read(self.file(handle)?, &mut buffer) }
                    .map_err(|e| format!("{e:?}"))?;
                format!("{} {}", outcome(r), Dump(&buffer))
            }
            Step::Write { handle, data } => {
                let data: Vec<u8> = data.bytes().collect();
                // SAFETY: as above.
                let r = unsafe { file::write(self.file(handle)?, &data) }
                    .map_err(|e| format!("{e:?}"))?;
                format!("{}", outcome(r))
            }
        })
    }

    /// Close and unload whatever the script left behind, so a script that
    /// stopped early does not also leak.
    fn finish(&mut self) {
        for (_, file) in self.files.drain(..) {
            // SAFETY: still open, and removed from the table by `drain`.
            let _ = unsafe { file::close(file) };
        }
        for (_, object) in self.drivers.drain(..).rev() {
            let _ = driver::unload(object);
        }
    }
}

/// Replay `script`; `Err` names the first line that differs from what
/// Windows printed. Returns how many lines matched.
fn replay(info: &BootInfo, name: &str, script: &str, windows: &str) -> Result<usize, String> {
    let mut replay = Replay {
        info,
        files: Vec::new(),
        drivers: Vec::new(),
    };
    let mut checker = Checker::new(windows);
    let mut run = || -> Result<(), String> {
        for step in nk_oracle::steps(script) {
            let step = step.map_err(|why| format!("script: {why}"))?;
            if let Some(stop) = checker.stops_at(&format!("{step}")) {
                // Windows did not survive this step. NK must not
                // either: the boot's scenario expects the same stop,
                // and counts it only after this line.
                kprintln!(
                    "oracle: Windows stops at `{step}`: bugcheck {:#010x}, {:#010x}",
                    stop.code,
                    stop.parameter
                );
                kprintln!("NK-NEG-ARMED {name}");
                let _ = replay.step(step);
                return Err(format!("NK went on past `{step}`, where Windows stopped"));
            }
            let line = match replay.step(step) {
                Ok(result) => format!("{step}: {result}"),
                Err(why) => format!("{step}: NK could not: {why}"),
            };
            checker.line(&line).map_err(|m| match m {
                Mismatch::Differs { number, windows } => {
                    format!("line {number}: NK `{line}`, Windows `{windows}`")
                }
                _ => format!("NK `{line}`, but the Windows transcript has ended"),
            })?;
        }
        Ok(())
    };
    let verdict = run();
    replay.finish();
    verdict?;
    checker
        .finish()
        .map_err(|m| format!("the script ended before the Windows transcript: {m:?}"))
}

/// One script: skipped without its driver, else replayed and compared.
fn check(r: &mut Report, info: &BootInfo, name: &str, driver: &str, script: &str, windows: &str) {
    if module(info, driver).is_none() {
        return r.skip(name, format_args!("module {driver} not provided"));
    }
    match replay(info, name, script, windows) {
        Ok(lines) => r.ok_with(name, format_args!("{lines} lines as on Windows")),
        Err(why) => r.fail(name, format_args!("{why}")),
    }
}

pub static GROUP: Group = Group {
    names: &[
        "oracle.null",
        "oracle.sioctl",
        "oracle.nkc-irql",
        "oracle.nkc-time",
        "oracle.nkc-dpc",
        "oracle.nkc-timer",
    ],
    run,
    manual: false,
};

fn run(r: &mut Report, info: &BootInfo) {
    check(
        r,
        info,
        "oracle.null",
        "null.sys",
        include_str!("../../oracle/null.script"),
        include_str!("../../oracle/null.txt"),
    );
    check(
        r,
        info,
        "oracle.sioctl",
        "sioctl.sys",
        include_str!("../../oracle/sioctl.script"),
        include_str!("../../oracle/sioctl.txt"),
    );
    check(
        r,
        info,
        "oracle.nkc-irql",
        "nkc-irql.sys",
        include_str!("../../oracle/nkc-irql.script"),
        include_str!("../../oracle/nkc-irql.txt"),
    );
    check(
        r,
        info,
        "oracle.nkc-time",
        "nkc-time.sys",
        include_str!("../../oracle/nkc-time.script"),
        include_str!("../../oracle/nkc-time.txt"),
    );
    check(
        r,
        info,
        "oracle.nkc-dpc",
        "nkc-dpc.sys",
        include_str!("../../oracle/nkc-dpc.script"),
        include_str!("../../oracle/nkc-dpc.txt"),
    );
    check(
        r,
        info,
        "oracle.nkc-timer",
        "nkc-timer.sys",
        include_str!("../../oracle/nkc-timer.script"),
        include_str!("../../oracle/nkc-timer.txt"),
    );
}

/// Microsoft's event sample, as on Windows booted with no debugger: its
/// first act is a breakpoint, which stops the system. Run alone: it
/// ends the boot.
pub static EVENT: Group = Group {
    names: &["oracle.event"],
    run: event,
    manual: true,
};

fn event(r: &mut Report, info: &BootInfo) {
    check(
        r,
        info,
        "oracle.event",
        "event.sys",
        include_str!("../../oracle/event.script"),
        include_str!("../../oracle/event.txt"),
    );
}
