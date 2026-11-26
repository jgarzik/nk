//! Replay the oracle scripts and hold NK to what Windows did.
//!
//! `oracle/<name>.script` lists requests to make of a driver. It was
//! replayed on real Windows, which produced `oracle/<name>.txt`. Here the
//! same script runs against the same driver binary on NK, and each line NK
//! produces must be the line Windows produced. `oracle/README.md` defines
//! the formats.
//!
//! On Windows the requests are system services made by a user-mode
//! program. Here each is made as one ([`system_service`]): an exception
//! that nothing handles while it is served stops the system as it does
//! there. And each is made on behalf of user mode, with its buffers in
//! the user range ([`UserMemory`]) or, for `ioctlat`, wherever the
//! script says.

use super::{USER_INPUT, USER_OUTPUT, UserMemory};
use crate::io::file::{self, Buffer, IoResult, Kind, OpenRequest};
use crate::io::service::{self, ServiceError};
use crate::ke::seh::system_service;
use crate::ldr;
use crate::test::{Group, Report};
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use nk_bootinfo::BootInfo;
use nk_ntabi::io::{
    FILE_OPEN, IRP_MJ_DEVICE_CONTROL, IRP_MJ_FILE_SYSTEM_CONTROL, IRP_MJ_READ, IRP_MJ_WRITE,
    NAMED_PIPE_CREATE_PARAMETERS, USER_MODE,
};
use nk_oracle::{Checker, Dump, FILL, Input, Mismatch, Outcome, Output, Step};

/// What a script has open and loaded while it runs.
struct Replay<'a> {
    /// The handles the script has open, by the names it gave them.
    files: Vec<(&'a str, u64)>,
    /// The services the script started and has not stopped.
    drivers: Vec<&'a str>,
}

fn outcome(r: IoResult) -> Outcome {
    Outcome {
        status: r.status as u32,
        information: r.information,
    }
}

impl<'a> Replay<'a> {
    fn file(&self, handle: &str) -> Result<u64, String> {
        self.files
            .iter()
            .find(|(h, _)| *h == handle)
            .map(|(_, f)| *f)
            .ok_or_else(|| format!("handle {handle} is not open"))
    }

    fn load(&mut self, service: &'a str, file: &str) -> &'static str {
        // What `sc create` and `sc start` do on Windows.
        match service::create(service, file).and_then(|()| service::start(service)) {
            Ok(_) => {
                self.drivers.push(service);
                "ok"
            }
            Err(e) => {
                kprintln!("oracle: load {service}: {e:?}");
                "failed"
            }
        }
    }

    /// A service that is part of the system: started unless it is
    /// running, and then stopped when the script ends. Its key is made
    /// here if the registry has none, naming `<service>.sys`.
    fn use_service(&mut self, service: &'a str) -> &'static str {
        match service::start(service) {
            Ok(_) => {
                self.drivers.push(service);
                "ok"
            }
            Err(ServiceError::Running) => "ok",
            Err(ServiceError::NoKey) => self.load(service, &format!("{service}.sys")),
            Err(e) => {
                kprintln!("oracle: use {service}: {e:?}");
                "failed"
            }
        }
    }

    fn unload(&mut self, service: &str) -> &'static str {
        let Some(i) = self.drivers.iter().position(|s| *s == service) else {
            return "failed";
        };
        self.drivers.remove(i);
        match service::stop(service) {
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
            Step::Debugger => if crate::kd::debugger_attached() {
                "attached"
            } else {
                "absent"
            }
            .into(),
            Step::Load { service, file } => self.load(service, file).into(),
            Step::Use { service } => self.use_service(service).into(),
            Step::Unload { service } => self.unload(service).into(),
            Step::Install { .. } => {
                return Err("not yet supported on NK".into());
            }
            Step::Open { handle, path, args } => {
                let root = match args.root {
                    Some(root) => Some(self.file(root)?),
                    None => None,
                };
                let request = OpenRequest {
                    name: path,
                    root,
                    desired_access: args.access,
                    share_access: args.share,
                    create_options: args.options,
                    disposition: FILE_OPEN,
                    kind: Kind::File,
                    requestor_mode: USER_MODE,
                };
                let opened = system_service(|| file::open(&request));
                match opened {
                    Ok((file, _)) => {
                        self.files.push((handle, file));
                        format!("{:08x}", 0)
                    }
                    Err(status) => format!("{:08x}", status as u32),
                }
            }
            Step::Pipe { handle, path, args } => {
                let request = OpenRequest {
                    name: path,
                    root: None,
                    desired_access: args.access,
                    share_access: args.share,
                    create_options: args.options,
                    disposition: args.disposition,
                    kind: Kind::NamedPipe(NAMED_PIPE_CREATE_PARAMETERS {
                        NamedPipeType: args.kind,
                        ReadMode: args.read,
                        CompletionMode: args.completion,
                        MaximumInstances: args.instances,
                        InboundQuota: args.inquota,
                        OutboundQuota: args.outquota,
                        // Relative, in units of 100 ns.
                        DefaultTimeout: -10_000 * i64::from(args.timeout),
                        TimeoutSpecified: 1,
                    }),
                    requestor_mode: USER_MODE,
                };
                let opened = system_service(|| file::open(&request));
                let (status, information) = match opened {
                    Ok((file, information)) => {
                        self.files.push((handle, file));
                        (0, information)
                    }
                    Err(status) => (status as u32, 0),
                };
                format!(
                    "{}",
                    Outcome {
                        status,
                        information
                    }
                )
            }
            Step::Close { handle } => {
                let file = self.file(handle)?;
                self.files.retain(|(h, _)| *h != handle);
                format!("{:08x}", system_service(|| file::close(file)) as u32)
            }
            Step::Ioctl {
                handle,
                code,
                input,
                output_len,
            } => self.control(
                handle,
                IRP_MJ_DEVICE_CONTROL,
                code,
                Input::Bytes(input),
                Output::Len(output_len),
            )?,
            Step::IoctlAt {
                handle,
                code,
                input,
                output,
            } => self.control(handle, IRP_MJ_DEVICE_CONTROL, code, input, output)?,
            Step::Fsctl {
                handle,
                code,
                input,
                output_len,
            } => self.control(
                handle,
                IRP_MJ_FILE_SYSTEM_CONTROL,
                code,
                Input::Bytes(input),
                Output::Len(output_len),
            )?,
            Step::Read { handle, len } => {
                let file = self.file(handle)?;
                let buffer = UserMemory::new(USER_OUTPUT, &vec![FILL; len])?;
                let r = system_service(|| file::user_transfer(file, IRP_MJ_READ, buffer.buffer()))
                    .map_err(|e| format!("{e:?}"))?;
                format!("{} {}", outcome(r), Dump(&buffer.contents()))
            }
            Step::Write { handle, data } => {
                let file = self.file(handle)?;
                let data: Vec<u8> = data.bytes().collect();
                let buffer = UserMemory::new(USER_INPUT, &data)?;
                let r = system_service(|| file::user_transfer(file, IRP_MJ_WRITE, buffer.buffer()))
                    .map_err(|e| format!("{e:?}"))?;
                format!("{}", outcome(r))
            }
        })
    }

    /// A control request. A buffer the script gives as bytes or as a
    /// length is the replayer's own, in the user range; one it gives as
    /// an address is that address, whatever is or is not there. The
    /// text shows the replayer's output buffer, or `-` for one that is
    /// not its to show.
    fn control(
        &self,
        handle: &str,
        major: u8,
        code: u32,
        input: Input<'_>,
        output: Output<'_>,
    ) -> Result<String, String> {
        let file = self.file(handle)?;
        let at = |at: nk_oracle::At<'_>| Buffer {
            address: at.address as usize,
            len: at.len,
        };
        let (input, own_input) = match input {
            Input::Bytes(bytes) => {
                let bytes: Vec<u8> = bytes.bytes().collect();
                let memory = UserMemory::new(USER_INPUT, &bytes)?;
                (memory.buffer(), Some(memory))
            }
            Input::At(address) => (at(address), None),
        };
        let (output, own_output) = match output {
            Output::Len(len) => {
                let memory = UserMemory::new(USER_OUTPUT, &vec![FILL; len])?;
                (memory.buffer(), Some(memory))
            }
            Output::At(address) => (at(address), None),
        };
        let r = system_service(|| file::user_control(file, major, code, input, output))
            .map_err(|e| format!("{e:?}"))?;
        drop(own_input);
        Ok(match own_output {
            Some(memory) => format!("{} {}", outcome(r), Dump(&memory.contents())),
            None => format!("{} -", outcome(r)),
        })
    }

    /// Close and unload whatever the script left behind, so a script that
    /// stopped early does not also leak.
    fn finish(&mut self) {
        for (_, file) in self.files.drain(..) {
            file::close(file);
        }
        for service in self.drivers.drain(..).rev() {
            let _ = service::stop(service);
        }
    }
}

/// Replay `script`; `Err` names the first line that differs from what
/// Windows printed. Returns how many lines matched.
fn replay(name: &str, script: &str, windows: &str) -> Result<usize, String> {
    let mut replay = Replay {
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
fn check(r: &mut Report, name: &str, driver: &str, script: &str, windows: &str) {
    if ldr::boot_file(driver).is_none() {
        return r.skip(name, format_args!("module {driver} not provided"));
    }
    match replay(name, script, windows) {
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
        "oracle.nkc-thread",
        "oracle.nkc-wait",
        "oracle.nkc-mutex",
        "oracle.nkc-waitn",
        "oracle.nkc-work",
        "oracle.nkc-se",
        "oracle.nkc-reg",
        "oracle.cancel",
    ],
    run,
    manual: false,
};

fn run(r: &mut Report, _: &BootInfo) {
    check(
        r,
        "oracle.null",
        "null.sys",
        include_str!("../../oracle/null.script"),
        include_str!("../../oracle/null.txt"),
    );
    check(
        r,
        "oracle.sioctl",
        "sioctl.sys",
        include_str!("../../oracle/sioctl.script"),
        include_str!("../../oracle/sioctl.txt"),
    );
    check(
        r,
        "oracle.nkc-irql",
        "nkc-irql.sys",
        include_str!("../../oracle/nkc-irql.script"),
        include_str!("../../oracle/nkc-irql.txt"),
    );
    check(
        r,
        "oracle.nkc-time",
        "nkc-time.sys",
        include_str!("../../oracle/nkc-time.script"),
        include_str!("../../oracle/nkc-time.txt"),
    );
    check(
        r,
        "oracle.nkc-dpc",
        "nkc-dpc.sys",
        include_str!("../../oracle/nkc-dpc.script"),
        include_str!("../../oracle/nkc-dpc.txt"),
    );
    check(
        r,
        "oracle.nkc-timer",
        "nkc-timer.sys",
        include_str!("../../oracle/nkc-timer.script"),
        include_str!("../../oracle/nkc-timer.txt"),
    );
    check(
        r,
        "oracle.nkc-thread",
        "nkc-thread.sys",
        include_str!("../../oracle/nkc-thread.script"),
        include_str!("../../oracle/nkc-thread.txt"),
    );
    check(
        r,
        "oracle.nkc-wait",
        "nkc-wait.sys",
        include_str!("../../oracle/nkc-wait.script"),
        include_str!("../../oracle/nkc-wait.txt"),
    );
    check(
        r,
        "oracle.nkc-mutex",
        "nkc-mutex.sys",
        include_str!("../../oracle/nkc-mutex.script"),
        include_str!("../../oracle/nkc-mutex.txt"),
    );
    check(
        r,
        "oracle.nkc-waitn",
        "nkc-waitn.sys",
        include_str!("../../oracle/nkc-waitn.script"),
        include_str!("../../oracle/nkc-waitn.txt"),
    );
    check(
        r,
        "oracle.nkc-work",
        "nkc-work.sys",
        include_str!("../../oracle/nkc-work.script"),
        include_str!("../../oracle/nkc-work.txt"),
    );
    check(
        r,
        "oracle.nkc-se",
        "nkc-se.sys",
        include_str!("../../oracle/nkc-se.script"),
        include_str!("../../oracle/nkc-se.txt"),
    );
    check(
        r,
        "oracle.nkc-reg",
        "nkc-reg.sys",
        include_str!("../../oracle/nkc-reg.script"),
        include_str!("../../oracle/nkc-reg.txt"),
    );
    check(
        r,
        "oracle.cancel",
        "cancel.sys",
        include_str!("../../oracle/cancel.script"),
        include_str!("../../oracle/cancel.txt"),
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

fn event(r: &mut Report, _: &BootInfo) {
    check(
        r,
        "oracle.event",
        "event.sys",
        include_str!("../../oracle/event.script"),
        include_str!("../../oracle/event.txt"),
    );
}

/// Microsoft's event sample with a debugger attached that says go at
/// its breakpoint: the driver runs. Needs `debug=on`, so it has a boot
/// of its own.
pub static EVENT_DEBUG: Group = Group {
    names: &["oracle.event-debug"],
    run: event_debug,
    manual: true,
};

fn event_debug(r: &mut Report, _: &BootInfo) {
    check(
        r,
        "oracle.event-debug",
        "event.sys",
        include_str!("../../oracle/event-debug.script"),
        include_str!("../../oracle/event-debug.txt"),
    );
}
