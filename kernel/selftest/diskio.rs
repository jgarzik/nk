//! The proof of disk I/O: [`disk_io`] takes the name of a disk device
//! and holds the disk behind it to the data disk's pattern
//! (`doc/TESTING.md`, "The data disk") through NK's own requestor,
//! reading, writing the write range, and flushing. It asks nothing of
//! the disk but its name, so it is the same proof for NK's test disk
//! (`testdisk.rs`), which the tests here run it on, and for the disk
//! Microsoft's storage stack makes (`storage.rs`).

use super::testdisk::{self, Fault, TestDisk};
use crate::io::file::{self, IoError, IoResult, OpenRequest};
use crate::ke::thread;
use crate::mm::PAGE_SIZE;
use crate::test::{Group, Report};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use nk_bootinfo::BootInfo;
use nk_disk::answer;
use nk_disk::pattern::{self, Mismatch, ORIGINAL, SECTOR, WRITE_END, WRITE_FIRST, WRITTEN};
use nk_ntabi::disk::*;
use nk_ntabi::io::*;
use nk_ntabi::status::*;

pub static GROUP: Group = Group {
    names: &[
        "disk.io.requestor",
        "disk.io.answers",
        "disk.io.proof",
        "disk.io.image",
        "disk.io.detects",
    ],
    run,
    manual: false,
};

pub static GROUPS: &[&Group] = &[&GROUP];

/// `FILE_SHARE_READ | FILE_SHARE_WRITE` (`wdm.h`): the disk is opened
/// by several threads at once.
const SHARE_READ_WRITE: u32 = 0x3;

/// What the proof did.
#[derive(Debug, Clone, Copy, Default)]
pub struct Counts {
    /// The disk's size in sectors.
    pub sectors: u64,
    pub reads: u32,
    pub writes: u32,
    /// Bytes transferred, both ways, and checked.
    pub bytes: u64,
    /// What the disk answered of itself: the bus its device names,
    /// and its adapter's limits and bus.
    pub bus_type: u32,
    pub adapter: Option<answer::Adapter>,
    /// The statuses of the transfers beyond the disk's end: a read at
    /// the end, a read across it, a write at it.
    pub beyond: [NTSTATUS; 3],
}

impl core::fmt::Display for Counts {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} sectors; {} reads, {} writes, {} bytes",
            self.sectors, self.reads, self.writes, self.bytes
        )
    }
}

/// Why a request did not come back as a completed request does.
fn why(error: IoError) -> &'static str {
    match error {
        IoError::Handle(_) => "the handle does not name the open disk",
        IoError::NotCompleted { .. } => "the disk's driver did not complete a request",
        IoError::StatusMismatch { .. } => {
            "the disk's driver returned another status than it completed a request with"
        }
        IoError::NoMemory => "no memory for a request",
        IoError::Refused(_) => "the I/O manager could not lock a buffer of the kernel's own",
    }
}

/// Say where a buffer differs from the pattern, and fail with `what`.
fn held(result: Result<(), Mismatch>, what: &'static str) -> Result<(), &'static str> {
    result.map_err(|mismatch| {
        kprintln!(
            "disk: {what}: sector {} holds {:#018x} at word {} of the disk",
            mismatch.sector,
            mismatch.found,
            mismatch.word
        );
        what
    })
}

/// What surrounds a buffer's bytes, to show a transfer that overran.
const GUARD: u8 = 0xA5;

/// A buffer for a transfer, starting a chosen number of bytes into a
/// page and spanning as many pages as its length takes from there,
/// with guard bytes before and after.
struct Buffer {
    storage: Vec<u8>,
    start: usize,
    len: usize,
}

impl Buffer {
    /// `len` bytes that start `in_page` bytes into a page.
    fn new(in_page: usize, len: usize) -> Self {
        let storage = alloc::vec![GUARD; len + 2 * PAGE_SIZE];
        let base = storage.as_ptr().addr() % PAGE_SIZE;
        // The first place after the storage's first byte that is that
        // far into a page.
        let start = match (in_page + PAGE_SIZE - base) % PAGE_SIZE {
            0 => PAGE_SIZE,
            start => start,
        };
        Self {
            storage,
            start,
            len,
        }
    }

    fn bytes(&mut self) -> &mut [u8] {
        &mut self.storage[self.start..self.start + self.len]
    }

    /// Fail with `what` if anything around the buffer was written.
    fn intact(&self, what: &'static str) -> Result<(), &'static str> {
        let (before, rest) = self.storage.split_at(self.start);
        let after = &rest[self.len..];
        if before.iter().chain(after).all(|&byte| byte == GUARD) {
            Ok(())
        } else {
            Err(what)
        }
    }
}

/// The disk, open.
struct Disk {
    handle: u64,
    counts: Counts,
}

impl Disk {
    /// Open the disk for reading and writing, synchronously, shared
    /// with whoever else has it open.
    fn open(name: &str) -> Result<Self, &'static str> {
        let request = OpenRequest {
            share_access: SHARE_READ_WRITE,
            ..OpenRequest::new(name)
        };
        let (handle, _) = file::open(&request).map_err(|status| {
            kprintln!("disk: opening {name}: {status:#x}");
            "the disk could not be opened"
        })?;
        Ok(Self {
            handle,
            counts: Counts::default(),
        })
    }

    /// Send a control code and return the answer: what the disk wrote
    /// of `room`. A code the disk fails is a failure.
    fn ask<'a>(
        &self,
        code: u32,
        input: &[u8],
        room: &'a mut [u8],
    ) -> Result<&'a [u8], &'static str> {
        let result = file::device_control(self.handle, code, input, room).map_err(why)?;
        if result.status != STATUS_SUCCESS {
            kprintln!("disk: control code {code:#x}: {:#x}", result.status);
            return Err("the disk failed a control code");
        }
        let room: &'a [u8] = room;
        room.get(..result.information)
            .ok_or("the disk answered a control code with more than there was room for")
    }

    /// The descriptor of a storage property.
    fn property<'a>(&self, property: u32, room: &'a mut [u8]) -> Result<&'a [u8], &'static str> {
        self.ask(
            IOCTL_STORAGE_QUERY_PROPERTY,
            &answer::property_query(property),
            room,
        )
    }

    /// Read into `buffer` at byte `offset`: whatever comes of it.
    fn try_read(&self, offset: u64, buffer: &mut [u8]) -> Result<IoResult, &'static str> {
        file::read_at(self.handle, offset as i64, buffer).map_err(why)
    }

    /// Write `buffer` at byte `offset`: whatever comes of it.
    fn try_write(&self, offset: u64, buffer: &[u8]) -> Result<IoResult, &'static str> {
        file::write_at(self.handle, offset as i64, buffer).map_err(why)
    }

    /// Whether a transfer of `len` bytes came back whole.
    fn whole(result: IoResult, len: usize, what: &'static str) -> Result<(), &'static str> {
        if result.status != STATUS_SUCCESS || result.information != len {
            kprintln!(
                "disk: {what}: status {:#x}, {} of {len} bytes",
                result.status,
                result.information
            );
            return Err(what);
        }
        Ok(())
    }

    /// Read the sectors from `first` that fill `buffer`. The read must
    /// succeed and say it read them all.
    fn read(&mut self, first: u64, buffer: &mut [u8]) -> Result<(), &'static str> {
        let result = self.try_read(first * SECTOR as u64, buffer)?;
        Self::whole(result, buffer.len(), "a read did not succeed in full")?;
        self.counts.reads += 1;
        self.counts.bytes += buffer.len() as u64;
        Ok(())
    }

    /// Write `buffer` to the sectors from `first`. The write must
    /// succeed and say it wrote them all.
    fn write(&mut self, first: u64, buffer: &[u8]) -> Result<(), &'static str> {
        let result = self.try_write(first * SECTOR as u64, buffer)?;
        Self::whole(result, buffer.len(), "a write did not succeed in full")?;
        self.counts.writes += 1;
        self.counts.bytes += buffer.len() as u64;
        Ok(())
    }

    /// Read `count` sectors from `first` into a buffer that starts
    /// `in_page` bytes into a page, and hold them to the pattern: each
    /// sector as the disk has it before the write range is written, or
    /// after (`written`). Nothing around the buffer may be touched.
    fn read_checked(
        &mut self,
        first: u64,
        count: u64,
        in_page: usize,
        written: bool,
        what: &'static str,
    ) -> Result<(), &'static str> {
        let mut buffer = Buffer::new(in_page, count as usize * SECTOR);
        self.read(first, buffer.bytes())?;
        held(pattern::check_disk(buffer.bytes(), first, written), what)?;
        buffer.intact("a read wrote outside the requestor's buffer")
    }

    /// Write the written pattern to `count` sectors from `first`, which
    /// are of the write range, from a buffer that starts `in_page`
    /// bytes into a page.
    fn write_pattern(
        &mut self,
        first: u64,
        count: u64,
        in_page: usize,
    ) -> Result<(), &'static str> {
        if first < WRITE_FIRST || first + count > WRITE_END {
            return Err("the proof was about to write outside the write range");
        }
        let mut buffer = Buffer::new(in_page, count as usize * SECTOR);
        pattern::fill(buffer.bytes(), first, WRITTEN);
        self.write(first, buffer.bytes())
    }
}

impl Drop for Disk {
    fn drop(&mut self) {
        file::close(self.handle);
    }
}

/// What the disk said of itself that the transfers go by.
#[derive(Clone, Copy)]
struct Facts {
    sectors: u64,
    /// How far into a page the proof's unaligned buffers start: not
    /// page-aligned, unless the adapter takes nothing else.
    in_page: usize,
    /// The most sectors of one transfer from such a buffer.
    largest: u64,
    bus_type: u32,
    adapter: answer::Adapter,
}

/// Ask the disk for its geometry, length, device number and properties
/// and hold them to each other and to what Microsoft documents: a
/// whole fixed disk of 512-byte sectors, its length the size its
/// geometry gives, its cylinders the whole ones of that size; a device
/// that is not removable, on a bus it names, with a product name; an
/// adapter whose limits leave room for a transfer.
fn properties(name: &str, disk: &Disk) -> Result<Facts, &'static str> {
    let mut room = [0u8; 1024];
    let geometry =
        answer::geometry_ex(disk.ask(IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &[], &mut room)?)?;
    let length = answer::length_info(disk.ask(IOCTL_DISK_GET_LENGTH_INFO, &[], &mut room)?)?;
    let sectors = geometry.check(length)?;
    let number =
        answer::device_number(disk.ask(IOCTL_STORAGE_GET_DEVICE_NUMBER, &[], &mut room)?)?;
    if number.device_type != FILE_DEVICE_DISK || number.partition_number != 0 {
        return Err("the device number is not a whole disk's");
    }
    let adapter = answer::adapter_descriptor(disk.property(STORAGE_ADAPTER_PROPERTY, &mut room)?)?;
    let alignment =
        answer::access_alignment(disk.property(STORAGE_ACCESS_ALIGNMENT_PROPERTY, &mut room)?)?;
    alignment.check(geometry.bytes_per_sector)?;
    let device = answer::device_descriptor(disk.property(STORAGE_DEVICE_PROPERTY, &mut room)?)?;
    if device.removable_media {
        return Err("the disk says its media can be removed");
    }
    if device.bus_type == 0 || device.bus_type >= BUS_TYPE_MAX {
        return Err("the disk names no bus it is on");
    }
    let product = device.product.unwrap_or_default();
    if product.is_empty() {
        return Err("the disk has no product name");
    }
    let in_page = 0xA58 & !(adapter.alignment_mask as usize) & (PAGE_SIZE - 1);
    let largest = adapter
        .largest_transfer(in_page, PAGE_SIZE)
        .ok_or("the adapter's limits leave no room for a transfer")?;
    // Room for the write range, and as much again beyond it that is
    // never written.
    if sectors < 2 * WRITE_END {
        return Err("the disk is too small for the proof");
    }
    kprintln!(
        "disk: {name}: {} {} on bus type {}, disk {}, {sectors} sectors, {largest} bytes a transfer",
        core::str::from_utf8(device.vendor.unwrap_or_default()).unwrap_or("?"),
        core::str::from_utf8(product).unwrap_or("?"),
        device.bus_type,
        number.device_number,
    );
    Ok(Facts {
        sectors,
        in_page,
        largest: ((largest / SECTOR) as u64).min(sectors - WRITE_END),
        bus_type: device.bus_type,
        adapter,
    })
}

/// The first sector, sectors in the middle and the last sector hold
/// the original pattern, read into page-aligned buffers.
fn originals(disk: &mut Disk, facts: &Facts) -> Result<(), &'static str> {
    for (first, count) in [(0, 1), (facts.sectors / 2, 8), (facts.sectors - 1, 1)] {
        disk.read_checked(
            first,
            count,
            0,
            false,
            "a sector does not hold the original pattern",
        )?;
    }
    Ok(())
}

/// Reads into a buffer that starts inside a page and spans several:
/// one sector, eight sectors, 128 KiB, and the largest transfer the
/// adapter allows, which ends at the disk's last sector.
fn unaligned(disk: &mut Disk, facts: &Facts) -> Result<(), &'static str> {
    const KIB_128: u64 = (128 << 10) / SECTOR as u64;
    for (first, count) in [
        (1, 1),
        (WRITE_END + 3, 8),
        (facts.sectors / 2 + 5, KIB_128),
        (facts.sectors - facts.largest, facts.largest),
    ] {
        disk.read_checked(
            first,
            count,
            facts.in_page,
            false,
            "a read into an unaligned buffer does not hold the original pattern",
        )?;
    }
    Ok(())
}

/// The write range, cut into unequal pieces.
const PIECES: [u64; 5] = [1, 7, 56, 64, 128];
const _: () = {
    let (mut at, mut sum) = (0, 0);
    while at < PIECES.len() {
        sum += PIECES[at];
        at += 1;
    }
    assert!(sum == WRITE_END - WRITE_FIRST);
};

/// Write the written pattern to the whole write range, piece by piece,
/// starting with the piece `turn` names.
fn write_range(disk: &mut Disk, facts: &Facts, turn: usize) -> Result<(), &'static str> {
    let starts = PIECES.iter().scan(WRITE_FIRST, |next, &count| {
        let first = *next;
        *next += count;
        Some((first, count))
    });
    let pieces: Vec<(u64, u64)> = starts.collect();
    for at in 0..pieces.len() {
        let (first, count) = pieces[(at + turn) % pieces.len()];
        disk.write_pattern(first, count, facts.in_page)?;
    }
    Ok(())
}

/// The write range holds the written pattern, read in one transfer,
/// and the sectors on both sides of each of its ends are as they
/// should be: written inside, original outside.
fn written(disk: &mut Disk, facts: &Facts) -> Result<(), &'static str> {
    disk.read_checked(
        WRITE_FIRST,
        WRITE_END - WRITE_FIRST,
        facts.in_page,
        true,
        "the write range does not read back as written",
    )?;
    for end in [WRITE_FIRST, WRITE_END] {
        disk.read_checked(
            end - 8,
            16,
            facts.in_page,
            true,
            "a sector at an end of the write range is not as it should be",
        )?;
    }
    Ok(())
}

/// The transfers a disk does not make. A transfer of no bytes succeeds
/// and moves nothing. A length or an offset that is not whole sectors
/// is `STATUS_INVALID_PARAMETER`. A transfer of whole sectors at or
/// across the disk's end is the drive's to refuse: it fails, with the
/// status the drive's refusal comes to, and moves nothing.
fn limits(disk: &Disk, facts: &Facts) -> Result<[NTSTATUS; 3], &'static str> {
    let nothing = IoResult {
        status: STATUS_SUCCESS,
        information: 0,
    };
    if disk.try_read(0, &mut [])? != nothing || disk.try_write(0, &[])? != nothing {
        return Err("a transfer of no bytes did not succeed with no bytes");
    }
    let invalid = IoResult {
        status: STATUS_INVALID_PARAMETER,
        information: 0,
    };
    let mut buffer = Buffer::new(facts.in_page, 2 * SECTOR);
    let sector = SECTOR as u64;
    if disk.try_read(0, &mut buffer.bytes()[..100])? != invalid
        || disk.try_read(100, &mut buffer.bytes()[..SECTOR])? != invalid
        || disk.try_write(WRITE_FIRST * sector, &buffer.bytes()[..100])? != invalid
        || disk.try_write(WRITE_FIRST * sector + 100, &buffer.bytes()[..SECTOR])? != invalid
    {
        return Err("a transfer that is not whole sectors was not refused as an invalid parameter");
    }
    let end = facts.sectors * sector;
    let beyond = [
        disk.try_read(end, &mut buffer.bytes()[..SECTOR])?,
        disk.try_read(end - sector, buffer.bytes())?,
        disk.try_write(end, &buffer.bytes()[..SECTOR])?,
    ];
    kprintln!(
        "disk: transfers at, across and (a write) at the end: {:#x} {:#x} {:#x}",
        beyond[0].status,
        beyond[1].status,
        beyond[2].status
    );
    if beyond
        .iter()
        .any(|result| !nt_error(result.status) || result.information != 0)
    {
        return Err("a transfer beyond the disk's end did not fail with no bytes");
    }
    buffer.intact("a refused transfer wrote outside the requestor's buffer")?;
    Ok(beyond.map(|result| result.status))
}

/// How the threads of the concurrent phase tell what came of them: the
/// reason one failed, which is a constant string.
struct Verdict {
    why: AtomicPtr<u8>,
    len: AtomicUsize,
}

impl Verdict {
    const fn new() -> Self {
        Self {
            why: AtomicPtr::new(core::ptr::null_mut()),
            len: AtomicUsize::new(0),
        }
    }

    fn fail(&self, why: &'static str) {
        self.len.store(why.len(), Ordering::Release);
        self.why.store(why.as_ptr().cast_mut(), Ordering::Release);
    }

    fn get(&self) -> Result<(), &'static str> {
        let why = self.why.load(Ordering::Acquire);
        if why.is_null() {
            return Ok(());
        }
        let len = self.len.load(Ordering::Acquire);
        // SAFETY: the pointer and the length are those of a constant
        // string, stored by `fail`, the length first.
        Err(unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(why, len)) })
    }
}

/// Threads reading in the concurrent phase, each its own stretch of
/// the disk, beside the one that writes.
const READERS: usize = 3;
/// Times each thread of the concurrent phase goes round.
const ROUNDS: u64 = 12;
/// Sectors a reader reads at a time, and how many such make up its
/// stretch of the disk.
const SPAN: u64 = 64;
const SPANS: u64 = 4;

/// What the threads of the concurrent phase share. It is their maker's,
/// which does not return while one of them runs.
struct Shared<'a> {
    name: &'a str,
    facts: Facts,
    /// Set when every thread exists: they start together.
    go: AtomicBool,
    verdicts: [Verdict; READERS + 1],
    reads: AtomicU32,
    writes: AtomicU32,
    bytes: AtomicU64,
}

impl Shared<'_> {
    fn add(&self, counts: &Counts) {
        self.reads.fetch_add(counts.reads, Ordering::AcqRel);
        self.writes.fetch_add(counts.writes, Ordering::AcqRel);
        self.bytes.fetch_add(counts.bytes, Ordering::AcqRel);
    }
}

/// One thread's part in the concurrent phase.
struct Job<'a> {
    shared: &'a Shared<'a>,
    /// Which reader it is; `READERS` is the writer.
    index: usize,
}

/// A reader: with its own handle, reads again and again within its own
/// stretch of the disk, none of which is ever written, and holds what
/// it reads to the original pattern.
fn reader(shared: &Shared<'_>, index: usize) -> Result<(), &'static str> {
    let facts = &shared.facts;
    let mut disk = Disk::open(shared.name)?;
    let stretch = match index {
        0 => 0,
        1 => facts.sectors / 2,
        _ => facts.sectors - SPANS * SPAN,
    };
    let mut outcome = Ok(());
    for round in 0..ROUNDS {
        let first = stretch + round * 37 % ((SPANS - 1) * SPAN);
        outcome = disk.read_checked(
            first,
            SPAN,
            facts.in_page,
            false,
            "a read beside other threads' transfers does not hold the original pattern",
        );
        if outcome.is_err() {
            break;
        }
    }
    shared.add(&disk.counts);
    outcome
}

/// The writer: with its own handle, writes the write range again and
/// again, in pieces, with the pattern it already holds.
fn writer(shared: &Shared<'_>) -> Result<(), &'static str> {
    let mut disk = Disk::open(shared.name)?;
    let mut outcome = Ok(());
    for round in 0..ROUNDS {
        outcome = write_range(&mut disk, &shared.facts, round as usize);
        if outcome.is_err() {
            break;
        }
    }
    shared.add(&disk.counts);
    outcome
}

/// A thread of the concurrent phase: `argument` is its [`Job`].
fn worker(argument: usize) {
    // SAFETY: the job and what it shares are the thread's maker's,
    // which waits for the thread to end before it lets go of them
    // (`concurrent`).
    let job = unsafe { &*core::ptr::with_exposed_provenance::<Job<'_>>(argument) };
    let shared = job.shared;
    while !shared.go.load(Ordering::Acquire) {
        thread::yield_now();
    }
    let outcome = if job.index < READERS {
        reader(shared, job.index)
    } else {
        writer(shared)
    };
    if let Err(why) = outcome {
        shared.verdicts[job.index].fail(why);
    }
}

/// Several threads at once, each with its own handle: three read
/// stretches of the disk that are never written, one writes the write
/// range over and over with the written pattern it holds already, and
/// this thread reads the write range meanwhile, which holds the
/// written pattern whichever write a read falls between. The threads
/// start together and are waited for, however long they take.
fn concurrent(name: &str, disk: &mut Disk, facts: &Facts) -> Result<(), &'static str> {
    let shared = Shared {
        name,
        facts: *facts,
        go: AtomicBool::new(false),
        verdicts: [const { Verdict::new() }; READERS + 1],
        reads: AtomicU32::new(0),
        writes: AtomicU32::new(0),
        bytes: AtomicU64::new(0),
    };
    let jobs: [Job<'_>; READERS + 1] = core::array::from_fn(|index| Job {
        shared: &shared,
        index,
    });
    let before = thread::count();
    let made = jobs.iter().try_for_each(|job| {
        let argument = core::ptr::from_ref(job).expose_provenance();
        thread::create(worker, argument, thread::NORMAL_PRIORITY, thread::ANYWHERE).map(drop)
    });
    shared.go.store(true, Ordering::Release);
    let mut outcome = made;
    for _ in 0..ROUNDS {
        if outcome.is_err() {
            break;
        }
        outcome = disk.read_checked(
            WRITE_FIRST,
            WRITE_END - WRITE_FIRST,
            facts.in_page,
            true,
            "the write range, read while it is rewritten, is not as written",
        );
    }
    // Not before every thread made has ended: they use `shared`.
    thread::settle(before);
    disk.counts.reads += shared.reads.load(Ordering::Acquire);
    disk.counts.writes += shared.writes.load(Ordering::Acquire);
    disk.counts.bytes += shared.bytes.load(Ordering::Acquire);
    outcome?;
    shared.verdicts.iter().try_for_each(Verdict::get)
}

/// The proof of disk I/O against the disk device called `name`: open
/// it; hold its geometry, length, device number and properties to each
/// other; read the original pattern at the start, in the middle and at
/// the end, into aligned buffers and into buffers that start inside a
/// page, up to the largest transfer the adapter allows; write the
/// written pattern to the write range in unequal pieces and read it
/// back, with the sectors beside it untouched; see the transfers a
/// disk does not make refused; do all of it at once from several
/// threads; flush; and read the write range and its surroundings once
/// more. Only the write range is written.
pub fn disk_io(name: &str) -> Result<Counts, &'static str> {
    let mut disk = Disk::open(name)?;
    let facts = properties(name, &disk)?;
    originals(&mut disk, &facts)?;
    unaligned(&mut disk, &facts)?;
    write_range(&mut disk, &facts, 0)?;
    written(&mut disk, &facts)?;
    let beyond = limits(&disk, &facts)?;
    concurrent(name, &mut disk, &facts)?;
    let flushed = file::flush(disk.handle).map_err(why)?;
    if flushed.status != STATUS_SUCCESS {
        kprintln!("disk: flush: {:#x}", flushed.status);
        return Err("the disk failed a flush");
    }
    written(&mut disk, &facts)?;
    originals(&mut disk, &facts)?;
    Ok(Counts {
        sectors: facts.sectors,
        bus_type: facts.bus_type,
        adapter: Some(facts.adapter),
        beyond,
        ..disk.counts
    })
}

/// The requestor's reads, writes and flushes as a direct-I/O device's
/// driver sees them: an MDL over the requestor's own buffer, its pages
/// locked, with the buffer's length and its place in its first page,
/// and no other buffer; the byte offset given, or the file's position;
/// no MDL for no bytes; a flush with nothing. User mode's buffer is
/// locked the same way, and one that is not there fails the request
/// before the driver sees it. Returns the facts checked.
fn requestor() -> Result<u32, &'static str> {
    let _disk = TestDisk::new()?;
    let disk = Disk::open(testdisk::NAME)?;
    let passive = crate::ke::irql::PASSIVE_LEVEL;
    let sector = SECTOR as u64;
    // A read of sixteen sectors into a buffer that starts 0x234 bytes
    // into a page: three pages.
    let mut buffer = Buffer::new(0x234, 16 * SECTOR);
    let whole = IoResult {
        status: STATUS_SUCCESS,
        information: 16 * SECTOR,
    };
    if disk.try_read(5 * sector, buffer.bytes())? != whole {
        return Err("a direct read did not succeed in full");
    }
    let expected = testdisk::Seen {
        major: IRP_MJ_READ,
        offset: 5 * sector as i64,
        length: 16 * SECTOR as u32,
        mdl: Some((16 * SECTOR as u32, 0x234)),
        locked: true,
        other_buffers: false,
        irql: passive,
    };
    if testdisk::seen() != expected {
        return Err("a direct read did not reach the driver as an MDL over the buffer");
    }
    held(
        pattern::check(buffer.bytes(), 5, ORIGINAL),
        "a direct read did not bring the disk's bytes",
    )?;
    buffer.intact("a direct read wrote outside the buffer")?;
    // The same buffer written to the write range.
    pattern::fill(buffer.bytes(), WRITE_FIRST, WRITTEN);
    if disk.try_write(WRITE_FIRST * sector, buffer.bytes())? != whole {
        return Err("a direct write did not succeed in full");
    }
    let expected = testdisk::Seen {
        major: IRP_MJ_WRITE,
        offset: (WRITE_FIRST * sector) as i64,
        ..expected
    };
    if testdisk::seen() != expected {
        return Err("a direct write did not reach the driver as an MDL over the buffer");
    }
    buffer.bytes().fill(0);
    if disk.try_read(WRITE_FIRST * sector, buffer.bytes())? != whole {
        return Err("a direct read did not succeed in full");
    }
    held(
        pattern::check(buffer.bytes(), WRITE_FIRST, WRITTEN),
        "a direct write did not reach the disk",
    )?;
    // No bytes: no MDL.
    let nothing = IoResult {
        status: STATUS_SUCCESS,
        information: 0,
    };
    if disk.try_write(3 * sector, &[])? != nothing {
        return Err("a write of no bytes did not succeed");
    }
    let expected = testdisk::Seen {
        major: IRP_MJ_WRITE,
        offset: 3 * sector as i64,
        length: 0,
        mdl: None,
        locked: false,
        other_buffers: false,
        irql: passive,
    };
    if testdisk::seen() != expected {
        return Err("a transfer of no bytes reached the driver with a buffer");
    }
    // Without an offset: where the file's position is, its start.
    let one = &mut buffer.bytes()[..SECTOR];
    let read = file::read(disk.handle, one).map_err(why)?;
    if read.status != STATUS_SUCCESS || read.information != SECTOR || testdisk::seen().offset != 0 {
        return Err("a read with no offset was not at the file's position");
    }
    held(
        pattern::check(one, 0, ORIGINAL),
        "a read with no offset did not bring the first sector",
    )?;
    // A flush: a request of its own, with nothing.
    let (transfers, flushes, _) = testdisk::requests();
    if file::flush(disk.handle).map_err(why)? != nothing
        || testdisk::requests() != (transfers, flushes + 1, testdisk::requests().2)
    {
        return Err("a flush did not reach the driver as one flush request");
    }
    // User mode: its buffer, a kilobyte 0x100 bytes into its pages.
    let user =
        super::open_as_user(testdisk::NAME).map_err(|_| "user mode could not open the disk")?;
    let outcome = (|| {
        let memory = super::UserMemory::new(super::USER_OUTPUT, &[0; 2 * PAGE_SIZE])?;
        let mut there = memory.buffer();
        there.address += 0x100;
        there.len = 2 * SECTOR;
        let read = file::user_transfer(user, IRP_MJ_READ, there).map_err(why)?;
        let seen = testdisk::seen();
        if read.status != STATUS_SUCCESS
            || read.information != 2 * SECTOR
            || seen.mdl != Some((2 * SECTOR as u32, 0x100))
            || !seen.locked
            || seen.other_buffers
        {
            return Err("user mode's direct read did not reach the driver as an MDL");
        }
        held(
            pattern::check(&memory.contents()[0x100..0x100 + 2 * SECTOR], 0, ORIGINAL),
            "user mode's direct read did not bring the disk's bytes",
        )?;
        // Pages that are not there.
        let absent = file::Buffer {
            address: super::USER_INPUT as usize,
            len: SECTOR,
        };
        let (transfers, ..) = testdisk::requests();
        let refused = file::user_transfer(user, IRP_MJ_READ, absent).map_err(why)?;
        if refused.status != STATUS_ACCESS_VIOLATION || testdisk::requests().0 != transfers {
            return Err("a direct read into memory that is not there reached the driver");
        }
        Ok(())
    })();
    file::close(user);
    outcome?;
    Ok(9)
}

/// The test disk answers as the model says a disk does, through the
/// requestor: a geometry answer has the parts there is room for; an
/// answer that does not fit, a query too short and a code it does not
/// know have their statuses; a transfer past the end is the drive's
/// "no such sector". A disk nothing has written is the original image.
/// Returns the answers checked.
fn answers() -> Result<u32, &'static str> {
    let made = TestDisk::new()?;
    let disk = Disk::open(testdisk::NAME)?;
    let control = |code: u32, input: &[u8], room: usize| {
        let mut output = [0u8; 256];
        file::device_control(disk.handle, code, input, &mut output[..room])
            .map(|result| (result.status, result.information))
            .map_err(why)
    };
    let query = answer::property_query(STORAGE_DEVICE_PROPERTY);
    let expected: [(u32, &[u8], usize, NTSTATUS, usize); 9] = [
        (
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            &[],
            31,
            STATUS_BUFFER_TOO_SMALL,
            0,
        ),
        (
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            &[],
            32,
            STATUS_SUCCESS,
            32,
        ),
        (
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            &[],
            60,
            STATUS_SUCCESS,
            56,
        ),
        (
            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX,
            &[],
            200,
            STATUS_SUCCESS,
            112,
        ),
        (
            IOCTL_DISK_GET_LENGTH_INFO,
            &[],
            7,
            STATUS_BUFFER_TOO_SMALL,
            0,
        ),
        (
            IOCTL_STORAGE_GET_DEVICE_NUMBER,
            &[],
            200,
            STATUS_SUCCESS,
            12,
        ),
        (IOCTL_STORAGE_QUERY_PROPERTY, &query, 8, STATUS_SUCCESS, 8),
        (
            IOCTL_STORAGE_QUERY_PROPERTY,
            &query[..11],
            200,
            STATUS_INFO_LENGTH_MISMATCH,
            0,
        ),
        // `IOCTL_DISK_GET_DRIVE_GEOMETRY`, which the test disk has not.
        (0x0007_0000, &[], 200, STATUS_INVALID_DEVICE_REQUEST, 0),
    ];
    for (code, input, room, status, information) in expected {
        if control(code, input, room)? != (status, information) {
            kprintln!("disk: control code {code:#x} with room for {room}: not {status:#x}");
            return Err("the test disk did not answer a control code as a disk does");
        }
    }
    let mut buffer = Buffer::new(0, SECTOR);
    let end = (testdisk::SIZE) as u64;
    let no_sector = IoResult {
        status: STATUS_NONEXISTENT_SECTOR,
        information: 0,
    };
    if disk.try_read(end, buffer.bytes())? != no_sector
        || disk.try_write(end, buffer.bytes())? != no_sector
    {
        return Err("the test disk did not refuse a transfer past its end as a drive does");
    }
    if held(
        made.image(false).map(drop),
        "the test disk is not the original image",
    )
    .is_err()
    {
        return Err("a test disk nothing has written is not the original image");
    }
    Ok(expected.len() as u32 + 3)
}

/// The proof notices a disk that goes wrong: one that loses a write,
/// one that writes a sector it was not asked to, one that reads a
/// sector from the wrong place, one that reports fewer bytes than it
/// moved. Returns the faults noticed.
fn detects() -> Result<u32, &'static str> {
    let middle = (testdisk::SIZE / SECTOR / 2) as u64;
    let faults = [
        (Fault::LostWrite, WRITE_FIRST + 70),
        // The write range's last sector, strayed into the one after.
        (Fault::StrayWrite, WRITE_END - 1),
        (Fault::WrongSector, middle + 3),
        (Fault::ShortCount, 0),
    ];
    for (fault, sector) in faults {
        let _disk = TestDisk::new()?;
        fault.at(sector);
        match disk_io(testdisk::NAME) {
            Err(why) => kprintln!("disk: {fault:?} at sector {sector}: noticed: {why}"),
            Ok(_) => {
                kprintln!("disk: {fault:?} at sector {sector}: not noticed");
                return Err("the proof passed a disk that went wrong");
            }
        }
    }
    Ok(faults.len() as u32)
}

fn run(report: &mut Report, _: &BootInfo) {
    let mut numbered = |name: &str, result: Result<u32, &'static str>| match result {
        Ok(n) => report.ok_with(name, format_args!("{n} checked")),
        Err(why) => report.fail(name, format_args!("{why}")),
    };
    numbered("disk.io.requestor", requestor());
    numbered("disk.io.answers", answers());
    // The proof, then the disk's bytes held to what the harness holds
    // a scenario's image to once the write range is written.
    match TestDisk::new() {
        Ok(disk) => {
            let (_, flushes, _) = testdisk::requests();
            let proof = disk_io(testdisk::NAME);
            match proof {
                Ok(counts) => report.ok_with("disk.io.proof", format_args!("{counts}")),
                Err(why) => report.fail("disk.io.proof", format_args!("{why}")),
            }
            let image = held(
                disk.image(true).map(drop),
                "the test disk's image is not what the proof leaves",
            );
            match image {
                _ if proof.is_err() => report.fail(
                    "disk.io.image",
                    format_args!("the proof did not get as far as leaving an image"),
                ),
                Ok(()) if testdisk::requests().1 == flushes => report.fail(
                    "disk.io.image",
                    format_args!("the proof's flush did not reach the disk"),
                ),
                Ok(()) => report.ok_with(
                    "disk.io.image",
                    format_args!("{} sectors compared", testdisk::SIZE / SECTOR),
                ),
                Err(why) => report.fail("disk.io.image", format_args!("{why}")),
            }
        }
        Err(why) => {
            report.fail("disk.io.proof", format_args!("{why}"));
            report.fail("disk.io.image", format_args!("{why}"));
        }
    }
    let mut numbered = |name: &str, result: Result<u32, &'static str>| match result {
        Ok(n) => report.ok_with(name, format_args!("{n} noticed")),
        Err(why) => report.fail(name, format_args!("{why}")),
    };
    numbered("disk.io.detects", detects());
}
