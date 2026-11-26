//! Tests of reference-counted objects and kernel handles.

use crate::ob::{handle, object};
use crate::test::{Group, Report};
use nk_bootinfo::BootInfo;

pub static GROUP: Group = Group {
    names: &[
        "ob.types",
        "ob.references",
        "ob.references-smp",
        "ob.handles",
        "ob.thread",
        "ps.system",
        "ps.identity",
        "ps.attach",
        "ps.thread-information",
        "ps.quota",
        "ps.token",
        "ob.namespace.paths",
        "ps.silo",
        "ps.silo-monitor",
        "ps.silo-smp",
        "ob.namespace.links",
        "ob.namespace.name-info",
        "ob.handle-access",
        "ob.event-handle",
        "ob.security",
        "ob.security-store",
        "ob.security-store-smp",
    ],
    run,
    manual: false,
};

fn counted(r: &mut Report, name: &str, what: &str, result: Result<u32, &'static str>) {
    match result {
        Ok(n) => r.ok_with(name, format_args!("{what} {n}")),
        Err(why) => r.fail(name, format_args!("{why}")),
    }
}

fn run(r: &mut Report, _: &BootInfo) {
    r.check("ob.types", object::type_test);
    counted(
        r,
        "ob.references",
        "references taken and dropped:",
        handle::reference_test(),
    );
    counted(
        r,
        "ob.references-smp",
        "references taken on several processors:",
        handle::shared_reference_test(),
    );
    counted(r, "ob.handles", "look-ups:", handle::handle_test());
    counted(r, "ob.thread", "waits:", handle::thread_test());
    r.check("ps.system", crate::ps::process::self_test);
    counted(
        r,
        "ps.identity",
        "questions:",
        crate::ps::process::identity_test(),
    );
    r.check("ps.attach", crate::ps::process::attach_test);
    counted(
        r,
        "ps.thread-information",
        "calls:",
        crate::ps::thread_information_test(),
    );
    r.check("ps.quota", crate::ps::process::quota_test);
    counted(
        r,
        "ps.token",
        "references taken:",
        crate::ps::process::token_test(),
    );
    counted(r, "ps.silo", "calls:", crate::ps::silo::self_test());
    counted(
        r,
        "ps.silo-monitor",
        "calls:",
        crate::ps::silo::monitor_test(),
    );
    counted(
        r,
        "ps.silo-smp",
        "monitors on several processors:",
        crate::ps::silo::smp_test(),
    );
    counted(
        r,
        "ob.namespace.paths",
        "look-ups:",
        crate::ob::paths_test(),
    );
    counted(
        r,
        "ob.namespace.links",
        "look-ups:",
        crate::ob::links_test(),
    );
    r.check("ob.namespace.name-info", crate::ob::name_info_test);
    counted(r, "ob.handle-access", "look-ups:", handle::access_test());
    counted(
        r,
        "ob.event-handle",
        "waits by handle:",
        crate::ob::event::self_test(),
    );
    r.check("ob.security", crate::ob::security::self_test);
    counted(
        r,
        "ob.security-store",
        "descriptors logged:",
        crate::ob::security::store_test(),
    );
    counted(
        r,
        "ob.security-store-smp",
        "descriptors logged on several processors:",
        crate::ob::security::store_smp_test(),
    );
}
