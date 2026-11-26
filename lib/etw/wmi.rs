//! WMI's record of the devices registered as data providers, the
//! registration requests it owes them, and the check of what a driver
//! answers such a request with.
//!
//! A device registers
//! ([`IoWMIRegistrationControl`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iowmiregistrationcontrol))
//! and is then asked, from a worker thread, which data blocks it has.
//! [`Registry`] is the bookkeeping: who is registered under which
//! provider id, which requests wait to be sent, and whether a worker is
//! sending. The kernel wraps it in a lock and does the sending.

use alloc::vec::Vec;

/// A device registered with WMI.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Provider {
    device: usize,
    id: u32,
    /// No more requests are to be sent to it (`WMIREG_ACTION_BLOCK_IRPS`).
    blocked: bool,
    /// A worker is sending it a request now.
    busy: bool,
    /// It is being deregistered, and has no provider id any more.
    leaving: bool,
    /// The data blocks its last good registration named.
    guids: Vec<[u8; 16]>,
}

/// A registration request to send.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Work {
    pub device: usize,
    /// The device asked for its registration to be read again
    /// (`WMIREG_ACTION_UPDATE_GUIDS`), which the request states.
    pub update: bool,
}

/// What registering a device did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Registered {
    /// It is registered already.
    Exists,
    /// It is registered now, and a request waits to be sent to it.
    /// `start` says a worker must be started to send it: none is at
    /// work.
    New { id: u32, start: bool },
}

/// What deregistering a device did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deregistered {
    /// It was not registered.
    Absent,
    /// A request is on its way to it: it has lost its provider id and
    /// its waiting requests, and is to be deregistered again when the
    /// request has come back.
    Busy,
    /// It is gone.
    Removed,
}

pub struct Registry {
    providers: Vec<Provider>,
    work: Vec<Work>,
    /// A worker is sending, or has been started to.
    working: bool,
    /// How many provider ids were ever given out.
    made: u32,
}

impl Registry {
    pub const fn new() -> Self {
        Self {
            providers: Vec::new(),
            work: Vec::new(),
            working: false,
            made: 0,
        }
    }

    fn find(&mut self, device: usize) -> Option<&mut Provider> {
        self.providers.iter_mut().find(|p| p.device == device)
    }

    /// Queue a request; whether a worker must be started for it.
    fn queue(&mut self, work: Work) -> bool {
        self.work.push(work);
        !core::mem::replace(&mut self.working, true)
    }

    /// Register `device`. Provider ids count up from 2, as Windows'
    /// do, and are never given out twice.
    pub fn register(&mut self, device: usize) -> Registered {
        if self.find(device).is_some() {
            return Registered::Exists;
        }
        self.made += 1;
        let id = self.made + 1;
        self.providers.push(Provider {
            device,
            id,
            blocked: false,
            busy: false,
            leaving: false,
            guids: Vec::new(),
        });
        let start = self.queue(Work {
            device,
            update: false,
        });
        Registered::New { id, start }
    }

    /// Have `device` asked for its registration again. `None` if it is
    /// not registered; else whether a worker must be started.
    pub fn update(&mut self, device: usize) -> Option<bool> {
        self.find(device).filter(|p| !p.leaving)?;
        Some(self.queue(Work {
            device,
            update: true,
        }))
    }

    /// Send `device` no more requests. `false` if it is not registered.
    pub fn block(&mut self, device: usize) -> bool {
        self.find(device)
            .filter(|p| !p.leaving)
            .map(|p| p.blocked = true)
            .is_some()
    }

    /// The provider id of `device`: zero if it is not registered, or is
    /// being deregistered.
    pub fn provider_id(&self, device: usize) -> u32 {
        self.providers
            .iter()
            .find(|p| p.device == device && !p.leaving)
            .map_or(0, |p| p.id)
    }

    /// The next request for the worker to send, its device marked as
    /// being sent to; requests for a blocked device are dropped. `None`
    /// when nothing waits: the worker is then done, and the next
    /// request starts another.
    pub fn next_work(&mut self) -> Option<Work> {
        while !self.work.is_empty() {
            let work = self.work.remove(0);
            if let Some(provider) = self.find(work.device)
                && !provider.blocked
            {
                provider.busy = true;
                return Some(work);
            }
        }
        self.work.shrink_to_fit();
        self.working = false;
        None
    }

    /// `device` answered a registration request with these data
    /// blocks: they are the ones it registers now.
    pub fn set_guids(&mut self, device: usize, guids: Vec<[u8; 16]>) {
        if let Some(provider) = self.find(device).filter(|p| !p.leaving) {
            provider.guids = guids;
        }
    }

    /// Whether a registered device's registration names the data block
    /// `guid`.
    pub fn registers(&self, guid: &[u8; 16]) -> bool {
        self.providers
            .iter()
            .any(|p| !p.leaving && p.guids.contains(guid))
    }

    /// The request to `device` has come back.
    pub fn work_done(&mut self, device: usize) {
        if let Some(provider) = self.find(device) {
            provider.busy = false;
        }
    }

    /// Deregister `device`: drop the requests waiting for it and, unless
    /// one is on its way to it now, forget it.
    pub fn deregister(&mut self, device: usize) -> Deregistered {
        let Some(provider) = self.find(device) else {
            return Deregistered::Absent;
        };
        provider.leaving = true;
        let busy = provider.busy;
        self.work.retain(|work| work.device != device);
        if busy {
            return Deregistered::Busy;
        }
        self.providers.retain(|p| p.device != device);
        // Empty lists hold no memory, so leak checks see none.
        self.providers.shrink_to_fit();
        self.work.shrink_to_fit();
        Deregistered::Removed
    }
}

/// `WMIREG_FLAG_INSTANCE_PDO`: a data block's instances are named after
/// a physical device object, which the entry points to.
pub const WMIREG_FLAG_INSTANCE_PDO: u32 = 0x20;
/// `WMIREG_FLAG_REMOVE_GUID`: the entry takes the data block away.
pub const WMIREG_FLAG_REMOVE_GUID: u32 = 0x0001_0000;

/// Sizes and offsets of `WMIREGINFOW` and of the `WMIREGGUIDW` entries
/// that follow it.
const HEADER: usize = 0x18;
const ENTRY: usize = 0x20;
const ENTRY_FLAGS: usize = 0x10;
const ENTRY_PDO: usize = 0x18;

fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    let field = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes(field.try_into().ok()?))
}

/// Whether a counted string lies inside `bytes` at `offset`; zero means
/// there is none, which is allowed.
fn string_fits(bytes: &[u8], offset: usize) -> bool {
    if offset == 0 {
        return true;
    }
    if offset % 2 != 0 {
        return false;
    }
    let Some(length) = bytes.get(offset..offset + 2) else {
        return false;
    };
    offset + 2 + usize::from(u16::from_le_bytes([length[0], length[1]])) <= bytes.len()
}

/// Check a driver's answer to a registration request, `reply` being the
/// bytes it reported as written, by Windows' rules: each `WMIREGINFOW`
/// of the chain states a size within the reply, its strings and its
/// GUID entries lie inside the reply. `None` for an answer that breaks
/// them.
///
/// For a good answer, the physical device objects its GUID entries
/// point to. A driver answering `IRP_MN_REGINFO_EX` (`extended`) has
/// referenced each for WMI, which owes the references back; answering
/// the older request it has not, and the list is empty.
pub fn registration_pdos(reply: &[u8], extended: bool) -> Option<Vec<u64>> {
    let mut pdos = Vec::new();
    for entry in guid_entries(reply)? {
        if extended && u32_at(entry, ENTRY_FLAGS)? & WMIREG_FLAG_INSTANCE_PDO != 0 {
            let pdo = entry.get(ENTRY_PDO..ENTRY_PDO + 8)?;
            pdos.push(u64::from_le_bytes(pdo.try_into().ok()?));
        }
    }
    Some(pdos)
}

/// The data blocks a driver's answer to a registration request
/// registers: the GUID of each entry that does not take its block
/// away. `None` for an answer that breaks Windows' rules
/// ([`registration_pdos`]).
pub fn registration_guids(reply: &[u8]) -> Option<Vec<[u8; 16]>> {
    let mut guids = Vec::new();
    for entry in guid_entries(reply)? {
        if u32_at(entry, ENTRY_FLAGS)? & WMIREG_FLAG_REMOVE_GUID == 0 {
            guids.push(entry.get(..16)?.try_into().ok()?);
        }
    }
    Some(guids)
}

/// The GUID entries of every `WMIREGINFOW` of a good answer, in order.
fn guid_entries(reply: &[u8]) -> Option<Vec<&[u8]>> {
    let mut entries = Vec::new();
    let mut at = 0usize;
    loop {
        let info = reply.get(at..)?;
        let size = u32_at(info, 0)? as usize;
        let next = u32_at(info, 4)? as usize;
        let registry_path = u32_at(info, 8)? as usize;
        let mof_resource = u32_at(info, 12)? as usize;
        let guids = u32_at(info, 16)? as usize;
        if size > info.len()
            || !string_fits(info, registry_path)
            || !string_fits(info, mof_resource)
            || guids.checked_mul(ENTRY)?.checked_add(HEADER)? > info.len()
        {
            return None;
        }
        for index in 0..guids {
            let entry = HEADER + index * ENTRY;
            entries.push(info.get(entry..entry + ENTRY)?);
        }
        if next == 0 {
            return Some(entries);
        }
        // A chain goes forward only, so it ends.
        at = at.checked_add(next)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: usize = 0x1000;
    const B: usize = 0x2000;

    #[test]
    fn a_device_registers_once_and_gets_an_id_of_its_own() {
        let mut wmi = Registry::new();
        assert_eq!(wmi.provider_id(A), 0);
        assert_eq!(wmi.register(A), Registered::New { id: 2, start: true });
        assert_eq!(wmi.register(A), Registered::Exists);
        // A worker has been started: the second request needs none.
        assert_eq!(
            wmi.register(B),
            Registered::New {
                id: 3,
                start: false
            }
        );
        assert_eq!((wmi.provider_id(A), wmi.provider_id(B)), (2, 3));
    }

    #[test]
    fn requests_are_sent_in_order_and_the_worker_ends_when_none_is_left() {
        let mut wmi = Registry::new();
        wmi.register(A);
        wmi.register(B);
        assert_eq!(wmi.update(A), Some(false));
        let sent: Vec<Work> = core::iter::from_fn(|| {
            let work = wmi.next_work()?;
            wmi.work_done(work.device);
            Some(work)
        })
        .collect();
        assert_eq!(
            sent,
            [
                Work {
                    device: A,
                    update: false
                },
                Work {
                    device: B,
                    update: false
                },
                Work {
                    device: A,
                    update: true
                },
            ]
        );
        // The worker is done: the next request starts one.
        assert_eq!(wmi.update(B), Some(true));
    }

    #[test]
    fn only_a_registered_device_can_be_updated_or_blocked() {
        let mut wmi = Registry::new();
        assert_eq!(wmi.update(A), None);
        assert!(!wmi.block(A));
        assert_eq!(wmi.deregister(A), Deregistered::Absent);
    }

    #[test]
    fn a_blocked_device_is_sent_nothing_more() {
        let mut wmi = Registry::new();
        wmi.register(A);
        wmi.register(B);
        assert!(wmi.block(A));
        assert_eq!(
            wmi.next_work(),
            Some(Work {
                device: B,
                update: false
            })
        );
        wmi.work_done(B);
        assert_eq!(wmi.update(A), Some(false));
        assert_eq!(wmi.next_work(), None);
        // It stays registered.
        assert_eq!(wmi.provider_id(A), 2);
    }

    #[test]
    fn deregistering_drops_what_waits_for_the_device() {
        let mut wmi = Registry::new();
        wmi.register(A);
        wmi.register(B);
        assert_eq!(wmi.deregister(A), Deregistered::Removed);
        assert_eq!(wmi.provider_id(A), 0);
        assert_eq!(wmi.next_work().map(|w| w.device), Some(B));
        wmi.work_done(B);
        assert_eq!(wmi.next_work(), None);
        // Registered again, it is a new provider.
        assert!(matches!(wmi.register(A), Registered::New { id: 4, .. }));
    }

    #[test]
    fn a_device_being_sent_to_is_deregistered_when_the_request_is_back() {
        let mut wmi = Registry::new();
        wmi.register(A);
        wmi.update(A);
        assert_eq!(wmi.next_work().map(|w| w.device), Some(A));
        assert_eq!(wmi.deregister(A), Deregistered::Busy);
        // Meanwhile it has no id, is still there, and gets nothing more.
        assert_eq!(wmi.provider_id(A), 0);
        assert_eq!(wmi.register(A), Registered::Exists);
        assert_eq!(wmi.update(A), None);
        assert!(!wmi.block(A));
        assert_eq!(wmi.deregister(A), Deregistered::Busy);
        wmi.work_done(A);
        assert_eq!(wmi.next_work(), None);
        assert_eq!(wmi.deregister(A), Deregistered::Removed);
        assert_eq!(wmi.deregister(A), Deregistered::Absent);
    }

    /// A `WMIREGINFOW` of `size` stated bytes with `guids` entries, in
    /// a buffer just large enough.
    fn info(size: u32, next: u32, guids: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER + guids as usize * ENTRY];
        bytes[0..4].copy_from_slice(&size.to_le_bytes());
        bytes[4..8].copy_from_slice(&next.to_le_bytes());
        bytes[16..20].copy_from_slice(&guids.to_le_bytes());
        bytes
    }

    fn with_pdo(mut bytes: Vec<u8>, at: usize, index: usize, pdo: u64) -> Vec<u8> {
        let entry = at + HEADER + index * ENTRY;
        bytes[entry + ENTRY_FLAGS..entry + ENTRY_FLAGS + 4]
            .copy_from_slice(&WMIREG_FLAG_INSTANCE_PDO.to_le_bytes());
        bytes[entry + ENTRY_PDO..entry + ENTRY_PDO + 8].copy_from_slice(&pdo.to_le_bytes());
        bytes
    }

    #[test]
    fn a_registration_with_no_guids_is_the_smallest_good_answer() {
        assert_eq!(registration_pdos(&info(0x18, 0, 0), true), Some(vec![]));
        // Shorter than the structure is no answer.
        assert_eq!(registration_pdos(&info(0x18, 0, 0)[..0x17], true), None);
        assert_eq!(registration_pdos(&[], true), None);
    }

    #[test]
    fn the_stated_size_and_the_entries_must_lie_in_the_reply() {
        assert_eq!(registration_pdos(&info(0x19, 0, 0), true), None);
        let two = info(0x58, 0, 2);
        assert_eq!(registration_pdos(&two, true), Some(vec![]));
        assert_eq!(registration_pdos(&two[..0x57], true), None);
        // A count far beyond the reply.
        let mut many = info(0x18, 0, 0);
        many[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(registration_pdos(&many, true), None);
    }

    #[test]
    fn strings_must_be_aligned_and_inside() {
        let mut bytes = info(0x20, 0, 0);
        bytes.extend_from_slice(&[4, 0, b'a', 0, b'b', 0, 0, 0]);
        let registry = |offset: u32, bytes: &[u8]| {
            let mut bytes = bytes.to_vec();
            bytes[8..12].copy_from_slice(&offset.to_le_bytes());
            registration_pdos(&bytes, true)
        };
        assert_eq!(registry(0x18, &bytes), Some(vec![]));
        assert_eq!(registry(0x19, &bytes), None);
        // Its characters run past the end.
        assert_eq!(registry(0x1C, &bytes), None);
        assert_eq!(registry(0x100, &bytes), None);
        // The MOF resource name is held to the same.
        let mut mof = bytes.clone();
        mof[12..16].copy_from_slice(&0x19u32.to_le_bytes());
        assert_eq!(registration_pdos(&mof, true), None);
    }

    #[test]
    fn a_registration_names_its_data_blocks() {
        let mut reply = info(0x78, 0, 3);
        for (index, flags) in [(0usize, 0u32), (1, WMIREG_FLAG_REMOVE_GUID), (2, 0x20)] {
            let entry = HEADER + index * ENTRY;
            reply[entry..entry + 16].copy_from_slice(&[index as u8 + 1; 16]);
            reply[entry + ENTRY_FLAGS..][..4].copy_from_slice(&flags.to_le_bytes());
        }
        assert_eq!(registration_guids(&reply), Some(vec![[1; 16], [3; 16]]));
        assert_eq!(registration_guids(&reply[..0x77]), None);
        assert_eq!(registration_guids(&info(0x18, 0, 0)), Some(vec![]));

        let mut registry = Registry::new();
        registry.register(A);
        assert!(!registry.registers(&[1; 16]));
        registry.set_guids(A, vec![[1; 16], [3; 16]]);
        registry.set_guids(B, vec![[9; 16]]);
        assert!(registry.registers(&[1; 16]) && registry.registers(&[3; 16]));
        assert!(!registry.registers(&[2; 16]) && !registry.registers(&[9; 16]));
        // A new answer replaces the old one's blocks.
        registry.set_guids(A, vec![[2; 16]]);
        assert!(registry.registers(&[2; 16]) && !registry.registers(&[1; 16]));
        // With the device, its blocks go.
        registry.next_work();
        registry.work_done(A);
        assert_eq!(registry.deregister(A), Deregistered::Removed);
        assert!(!registry.registers(&[2; 16]));
    }

    #[test]
    fn an_extended_answer_hands_over_its_device_references() {
        let reply = with_pdo(with_pdo(info(0x78, 0, 3), 0, 0, 0xAAAA), 0, 2, 0xBBBB);
        assert_eq!(registration_pdos(&reply, true), Some(vec![0xAAAA, 0xBBBB]));
        // The older request's answer names the devices without
        // references.
        assert_eq!(registration_pdos(&reply, false), Some(vec![]));
    }

    #[test]
    fn a_chain_of_registrations_is_followed_forward() {
        let mut reply = with_pdo(info(0x38, 0x38, 1), 0, 0, 0xAAAA);
        let second = with_pdo(info(0x38, 0, 1), 0, 0, 0xBBBB);
        reply.extend_from_slice(&second);
        assert_eq!(registration_pdos(&reply, true), Some(vec![0xAAAA, 0xBBBB]));
        // A link that leads outside the reply.
        let mut broken = reply.clone();
        broken[4..8].copy_from_slice(&0x100u32.to_le_bytes());
        assert_eq!(registration_pdos(&broken, true), None);
    }
}
