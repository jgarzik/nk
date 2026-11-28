//! Microsoft's inbox USB 3.0 + HID keyboard stack (`usbxhci.sys`, `ucx01000.sys`,
//! `usbhub3.sys`, `usbd.sys`, `hidusb.sys`, `hidclass.sys`, `hidparse.sys`,
//! `kbdhid.sys`, `kbdclass.sys`) with real QEMU QMP hotplug:
//!
//! 1. Boot with an empty `qemu-xhci` controller; verify `USBXHCI` + `USBHUB3`
//!    start and no HID keyboard is present.
//! 2. Emit `NK-QMP-ADD-KBD`; verify full USB->HID->Keyboard stack enumeration.
//! 3. Open the keyboard class device, emit `NK-QMP-KEYS seq1` (`a`, `b`), and
//!    verify exact PS/2 Set 1 make/break `KEYBOARD_INPUT_DATA` records.
//! 4. Start an in-flight read on a helper thread, emit `NK-QMP-DEL-KBD`, verify
//!    surprise removal teardown of the USB and HID nodes, and check in-flight
//!    read completion.
//! 5. Reattach with `NK-QMP-ADD-KBD`, emit `NK-QMP-KEYS seq2` (`shift+c`, `d`),
//!    and verify the second distinct key sequence arrives cleanly.

use crate::io::file::{self, OpenRequest};
use crate::io::service;
use crate::ke::{thread, time};
use crate::ldr;
use crate::pnp::interface;
use crate::pnp::node::{self, State};
use crate::pnp::registry;
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use nk_bootinfo::BootInfo;
use nk_ntabi::status::STATUS_SUCCESS;

pub static GROUP: Group = Group {
    names: &["usb.boot", "usb.hotplug"],
    run,
    manual: true,
};

pub static GROUPS: &[&Group] = &[&GROUP];

/// `GUID_DEVINTERFACE_KEYBOARD` = `{884b96c3-56ef-11d1-bc8c-00a0c91405dd}`.
const GUID_DEVINTERFACE_KEYBOARD: [u8; 16] = [
    0xC3, 0x96, 0x4B, 0x88, 0xEF, 0x56, 0xD1, 0x11, 0xBC, 0x8C, 0x00, 0xA0, 0xC9, 0x14, 0x05, 0xDD,
];

/// `KEYBOARD_INPUT_DATA` (`ntddkbd.h`, 12 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeyboardInputData {
    unit_id: u16,
    make_code: u16,
    flags: u16,
    reserved: u16,
    extra_information: u32,
}

const _: () = assert!(size_of::<KeyboardInputData>() == 12);

const KEY_MAKE: u16 = 0;
const KEY_BREAK: u16 = 1;

const IMAGES: [&str; 9] = [
    "usbxhci.sys",
    "ucx01000.sys",
    "usbhub3.sys",
    "usbd.sys",
    "hidusb.sys",
    "hidclass.sys",
    "hidparse.sys",
    "kbdhid.sys",
    "kbdclass.sys",
];

fn all_nodes() -> Vec<node::Node> {
    node::all().into_iter().filter_map(node::get).collect()
}

fn find_started(prefix: &str) -> Option<node::Node> {
    let want = prefix.to_ascii_uppercase();
    all_nodes()
        .into_iter()
        .find(|n| n.state == State::Started && n.instance.to_ascii_uppercase().starts_with(&want))
}

fn find_any(prefix: &str) -> Option<node::Node> {
    let want = prefix.to_ascii_uppercase();
    all_nodes()
        .into_iter()
        .find(|n| n.instance.to_ascii_uppercase().starts_with(&want))
}

/// Wait up to `ms` milliseconds for `pred` to become true, yielding in between.
fn wait_until(ms: u64, mut pred: impl FnMut() -> bool) -> bool {
    let deadline = time::interrupt_time() + ms * 10_000;
    while time::interrupt_time() < deadline {
        if pred() {
            return true;
        }
        thread::yield_now();
        time::stall(10_000); // 10ms
    }
    pred()
}

/// Verify xHCI controller (`PCI\VEN_1B36&DEV_000D`) and Root Hub 3.0
/// (`USB\ROOT_HUB30`) started with no keyboard initially attached.
pub(super) fn verify_empty_xhci() -> Result<(), &'static str> {
    // Wait briefly for asynchronous USBXHCI -> USBHUB3 root hub enumeration.
    if !wait_until(10_000, || find_started("USB\\ROOT_HUB30\\").is_some()) {
        for n in all_nodes() {
            if n.instance.to_ascii_uppercase().contains("000D")
                || n.instance.to_ascii_uppercase().contains("USB")
            {
                kprintln!(
                    "usb: node {} state={:?} problem={} svc={:?}",
                    n.instance,
                    n.state,
                    n.problem,
                    n.service
                );
            }
        }
        return Err("USB\\ROOT_HUB30 did not start");
    }
    if !service::running("USBXHCI") || !service::running("USBHUB3") {
        return Err("USBXHCI or USBHUB3 service is not running");
    }
    let xhci = find_started("PCI\\VEN_1B36&DEV_000D")
        .ok_or("no started QEMU xHCI controller (1b36:000d)")?;
    let hub = find_started("USB\\ROOT_HUB30\\").ok_or("no started USB\\ROOT_HUB30")?;
    if hub.parent != xhci.pdo {
        return Err("USB\\ROOT_HUB30 is not a child of the xHCI controller");
    }
    if find_any("HID\\VID_0627").is_some() {
        return Err("unexpected USB keyboard present before QMP hotplug");
    }
    kprintln!(
        "usb: empty xHCI ready: {} -> {}",
        xhci.instance,
        hub.instance
    );
    Ok(())
}

/// Open the started USB keyboard via its published `GUID_DEVINTERFACE_KEYBOARD`
/// link (falling back to `\Device\KeyboardClass0`).
fn open_keyboard() -> Result<u64, &'static str> {
    let links = interface::enabled_of(&GUID_DEVINTERFACE_KEYBOARD);
    let path = links
        .iter()
        .find(|l| l.to_ascii_uppercase().contains("HID#VID_0627"))
        .or_else(|| links.first())
        .map(|s| s.as_str())
        .unwrap_or("\\Device\\KeyboardClass0");
    kprintln!("usb: opening keyboard {path}");
    let req = OpenRequest {
        desired_access: 0x8010_0000, // GENERIC_READ | SYNCHRONIZE
        share_access: 3,             // FILE_SHARE_READ | FILE_SHARE_WRITE
        ..OpenRequest::new(path)
    };
    file::open(&req).map(|(h, _)| h).map_err(|status| {
        kprintln!("usb: open {path} failed: {status:#010x}");
        "failed to open keyboard device"
    })
}

/// Read `want` `KEYBOARD_INPUT_DATA` events from `handle` (in chunks).
fn read_keys(handle: u64, want: usize) -> Result<Vec<(u16, u16)>, &'static str> {
    let mut out = Vec::new();
    let mut buf = [0u8; 12 * 16];
    let deadline = time::interrupt_time() + 15_000 * 10_000;
    while out.len() < want && time::interrupt_time() < deadline {
        let r = file::read(handle, &mut buf).map_err(|_| "keyboard read refused")?;
        if r.status != STATUS_SUCCESS {
            kprintln!("usb: keyboard read status={:#010x}", r.status as u32);
            return Err("keyboard read returned error status");
        }
        for chunk in buf[..r.information].as_chunks::<12>().0 {
            let make_code = u16::from_le_bytes([chunk[2], chunk[3]]);
            let flags = u16::from_le_bytes([chunk[4], chunk[5]]);
            out.push((make_code, flags));
        }
    }
    if out.len() < want {
        kprintln!(
            "usb: got {} key events, expected {want}: {out:?}",
            out.len()
        );
        return Err("timed out waiting for keyboard events");
    }
    Ok(out)
}

static PENDING_HANDLE: AtomicU64 = AtomicU64::new(0);
static PENDING_ENTERED: AtomicBool = AtomicBool::new(false);
static PENDING_DONE: AtomicBool = AtomicBool::new(false);
static PENDING_STATUS: AtomicI32 = AtomicI32::new(0);

fn pending_reader(_: usize) {
    let handle = PENDING_HANDLE.load(Ordering::Acquire);
    let mut buf = [0u8; 12 * 4];
    PENDING_ENTERED.store(true, Ordering::Release);
    let status = match file::read(handle, &mut buf) {
        Ok(r) => r.status,
        Err(e) => {
            kprintln!("usb: in-flight read IoError: {e:?}");
            -1
        }
    };
    PENDING_STATUS.store(status, Ordering::Release);
    PENDING_DONE.store(true, Ordering::Release);
}

/// Verify hotplug attach -> key seq1 -> hot-unplug with in-flight read ->
/// reattach -> distinct key seq2.
pub(super) fn hotplug_lifecycle() -> Result<(), &'static str> {
    // 1. Attach USB keyboard via host QMP.
    kprintln!("NK-QMP-ADD-KBD");
    if !wait_until(15_000, || {
        find_started("HID\\VID_0627").is_some()
            && !interface::enabled_of(&GUID_DEVINTERFACE_KEYBOARD).is_empty()
    }) {
        for n in all_nodes() {
            if n.instance.to_ascii_uppercase().contains("USB")
                || n.instance.to_ascii_uppercase().contains("HID")
            {
                kprintln!(
                    "usb: node {} state={:?} problem={} svc={:?}",
                    n.instance,
                    n.state,
                    n.problem,
                    n.service
                );
            }
        }
        return Err("hotplugged USB keyboard did not reach Started + interface enabled");
    }
    let usb_dev = find_started("USB\\VID_0627").ok_or("USB\\VID_0627 node not started")?;
    let hid_dev = find_started("HID\\VID_0627").ok_or("HID\\VID_0627 node not started")?;
    let hkey = registry::enum_key(&hid_dev.instance);
    if registry::string(&hkey, "Service").as_deref() != Some("kbdhid") {
        return Err("HID keyboard is not bound to kbdhid");
    }
    // SAFETY: live device node in the tree.
    let stack = unsafe {
        crate::pnp::engine::stack_drivers(hid_dev.pdo as *mut nk_ntabi::io::DEVICE_OBJECT)
    };
    kprintln!(
        "usb: attached {} -> {} stack={stack:?}",
        usb_dev.instance,
        hid_dev.instance
    );
    if !stack
        .iter()
        .any(|d| d.eq_ignore_ascii_case("\\Driver\\kbdhid"))
        || !stack
            .iter()
            .any(|d| d.eq_ignore_ascii_case("\\Driver\\kbdclass"))
    {
        return Err("HID keyboard stack does not contain kbdhid and kbdclass");
    }

    // 2. Open keyboard and verify seq1: 'a' (0x1E) and 'b' (0x30) make/break.
    let handle = open_keyboard()?;
    kprintln!("NK-QMP-KEYS seq1");
    let seq1 = read_keys(handle, 4);
    let seq1 = match seq1 {
        Ok(events) => events,
        Err(e) => {
            file::close(handle);
            return Err(e);
        }
    };
    kprintln!("usb: seq1 events={seq1:?}");
    let want1 = [
        (0x1Eu16, KEY_MAKE),
        (0x1E, KEY_BREAK),
        (0x30, KEY_MAKE),
        (0x30, KEY_BREAK),
    ];
    if seq1[..4] != want1 {
        file::close(handle);
        return Err("seq1 scancodes did not match expected a/b make+break");
    }

    // 3. Issue an in-flight read, then unplug the keyboard via QMP.
    PENDING_HANDLE.store(handle, Ordering::Release);
    PENDING_ENTERED.store(false, Ordering::Release);
    PENDING_DONE.store(false, Ordering::Release);
    PENDING_STATUS.store(0, Ordering::Release);
    thread::create(pending_reader, 0, thread::NORMAL_PRIORITY, thread::ANYWHERE)
        .map_err(|_| "failed to spawn keyboard reader thread")?;
    let _ = wait_until(2_000, || PENDING_ENTERED.load(Ordering::Acquire));
    time::stall(150_000); // 150ms so the read IRP is queued in kbdclass

    kprintln!("NK-QMP-DEL-KBD");
    // On Windows PnP, surprise removal disables the keyboard interface and
    // delivers IRP_MN_SURPRISE_REMOVAL while deferring IRP_MN_REMOVE_DEVICE
    // until all open handles are closed. Closing the handle while the read is
    // in flight sends IRP_MJ_CLEANUP, causing kbdclass to cancel the pending
    // read, drop the last file reference (IRP_MJ_CLOSE), and complete removal.
    if !wait_until(15_000, || {
        interface::enabled_of(&GUID_DEVINTERFACE_KEYBOARD).is_empty()
            && find_any("HID\\VID_0627").is_none_or(|n| n.state == State::SurpriseRemoved)
    }) {
        file::close(handle);
        return Err("USB keyboard did not enter SurpriseRemoved with interface disabled");
    }
    file::close(handle);
    if !wait_until(5_000, || PENDING_DONE.load(Ordering::Acquire)) {
        return Err("in-flight keyboard read did not complete after unplug + close");
    }
    let unplug_status = PENDING_STATUS.load(Ordering::Acquire);
    kprintln!(
        "usb: surprise-unplugged; in-flight read completed with status={:#010x}",
        unplug_status as u32
    );
    if unplug_status == STATUS_SUCCESS {
        return Err("in-flight keyboard read unexpectedly succeeded on unplug");
    }
    if !wait_until(15_000, || {
        find_any("HID\\VID_0627").is_none() && find_any("USB\\VID_0627").is_none()
    }) {
        kprintln!("usb: keyboard nodes still present after handle close");
        return Err("USB/HID keyboard nodes were not removed after closing handle");
    }

    // 4. Reattach on the same xHCI port and verify distinct seq2 (shift+c, d).
    kprintln!("NK-QMP-ADD-KBD");
    if !wait_until(15_000, || {
        find_started("HID\\VID_0627").is_some()
            && !interface::enabled_of(&GUID_DEVINTERFACE_KEYBOARD).is_empty()
    }) {
        return Err("reattached USB keyboard did not reach Started + interface enabled");
    }
    let handle2 = open_keyboard()?;
    kprintln!("NK-QMP-KEYS seq2");
    let seq2 = read_keys(handle2, 6);
    file::close(handle2);
    let seq2 = seq2?;
    kprintln!("usb: seq2 events={seq2:?}");
    // shift+c: Shift(0x2A) make, C(0x2E) make, then C break + Shift break (order
    // between C break and Shift break depends on QEMU send-key release order),
    // followed by D(0x20) make and D(0x20) break.
    let shift_c_ok = seq2[0] == (0x2A, KEY_MAKE)
        && seq2[1] == (0x2E, KEY_MAKE)
        && ((seq2[2] == (0x2E, KEY_BREAK) && seq2[3] == (0x2A, KEY_BREAK))
            || (seq2[2] == (0x2A, KEY_BREAK) && seq2[3] == (0x2E, KEY_BREAK)));
    let d_ok = seq2[4] == (0x20, KEY_MAKE) && seq2[5] == (0x20, KEY_BREAK);
    if !shift_c_ok || !d_ok {
        return Err("seq2 scancodes did not match expected shift+c, d make+break");
    }
    Ok(())
}

fn run(r: &mut Report, _: &BootInfo) {
    crate::test::keeps_what_it_started();
    if let Some(absent) = IMAGES.iter().find(|file| ldr::boot_file(file).is_none()) {
        r.skip_rest(format_args!("module {absent} not provided"));
        return;
    }
    r.check("usb.boot", verify_empty_xhci);
    r.check("usb.hotplug", hotplug_lifecycle);
}
