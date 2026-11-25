//! The loader must refuse images it cannot run, and say why.

use super::{module, resources};
use crate::ldr::{self, LoadError};
use crate::test;
use nk_bootinfo::BootInfo;
use nk_pe::PeError;

/// Load `file`, expecting a refusal that `expected` recognises, and
/// expecting the failed load to give back everything it allocated.
fn expect_refusal(
    name: &str,
    module_name: &str,
    info: &BootInfo,
    expected: impl FnOnce(&LoadError) -> bool,
) {
    let Some(file) = module(info, module_name) else {
        return test::skip(name, format_args!("module {module_name} not provided"));
    };
    let before = resources();
    let result = ldr::load(file);
    let verdict = match &result {
        Err(e) if expected(e) => Ok(()),
        Err(e) => {
            kprintln!("ldr: {module_name}: {e:?}");
            Err("rejected for the wrong reason")
        }
        Ok(_) => Err("the image was loaded"),
    };
    // The error owns strings from the pool: release it before counting.
    drop(result);
    match verdict {
        Ok(()) if resources() != before => {
            test::fail(name, format_args!("rejected, but leaked memory"))
        }
        Ok(()) => test::ok(name),
        Err(why) => test::fail(name, format_args!("{why}")),
    }
}

pub fn run(info: &BootInfo) {
    // A real driver built for the other architecture.
    expect_refusal(
        "ldr.reject.wrong-machine",
        "wrongarch.sys",
        info,
        |e| match e {
            LoadError::Pe(PeError::WrongMachine(m)) => {
                kprintln!("ldr: refused image for machine {m:#06x}");
                true
            }
            _ => false,
        },
    );
    // A real driver that needs a module the kernel does not provide: the
    // KMDF sample imports the framework loader.
    expect_refusal(
        "ldr.reject.unresolved-import",
        "unresolved.sys",
        info,
        |e| match e {
            LoadError::Unresolved { module, symbol } => {
                kprintln!("ldr: refused image, unresolved import {module}!{symbol}");
                true
            }
            _ => false,
        },
    );
}
