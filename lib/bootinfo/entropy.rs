//! Boot entropy as Windows' loader gathers it: what each source puts in
//! its record of `BOOT_ENTROPY_LDR_RESULT`, and the seeds made from all
//! of them. `nkload` reads the sources (hardware and firmware) and hands
//! what it read to these rules; `doc/BOOT.md` (Boot entropy) says what
//! Windows does and where NK differs.
//!
//! The records are what `cng.sys` reads (`SystemBootEntropyInformation`),
//! so each source is reported as winload 10.0.19041 reports it: its slot,
//! its result code and status, how many bytes it gave. The seeds are
//! random bytes no binary can tell from any others; NK makes them its own
//! way ([`finish`]).

use crate::sha512::{self, Sha512};
use nk_ntabi::status::*;
use nk_ntabi::sysinfo::*;

/// Which source each record holds, by slot: winload's order of
/// gathering. The last three slots stay empty.
pub const SLOTS: [u32; 7] = [
    BOOT_ENTROPY_SOURCE_SEEDFILE,
    BOOT_ENTROPY_SOURCE_EXTERNAL,
    BOOT_ENTROPY_SOURCE_TPM,
    BOOT_ENTROPY_SOURCE_TIME,
    BOOT_ENTROPY_SOURCE_ACPI_OEM0,
    BOOT_ENTROPY_SOURCE_RDRAND,
    BOOT_ENTROPY_SOURCE_UEFI,
];

/// What became of one source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Outcome {
    pub policy: u64,
    pub code: u32,
    pub status: NTSTATUS,
    pub data: [u8; BOOT_ENTROPY_SOURCE_DATA_SIZE],
    pub length: u32,
}

impl Outcome {
    /// The source is not there, for the reason `status` gives.
    pub const fn not_present(status: NTSTATUS) -> Self {
        Self::bare(BOOT_ENTROPY_SOURCE_NOT_PRESENT, status)
    }

    /// The source is there but failed.
    pub const fn error(status: NTSTATUS) -> Self {
        Self::bare(BOOT_ENTROPY_SOURCE_ERROR, status)
    }

    const fn bare(code: u32, status: NTSTATUS) -> Self {
        Self {
            policy: 0,
            code,
            status,
            data: [0; BOOT_ENTROPY_SOURCE_DATA_SIZE],
            length: 0,
        }
    }

    /// The source gave `data` (at most a record's worth is kept).
    pub fn success(status: NTSTATUS, data: &[u8]) -> Self {
        let mut outcome = Self::bare(BOOT_ENTROPY_SOURCE_SUCCESS, status);
        let length = data.len().min(BOOT_ENTROPY_SOURCE_DATA_SIZE);
        outcome.data[..length].copy_from_slice(&data[..length]);
        outcome.length = length as u32;
        outcome
    }
}

/// The length of the seed file (`RNG\Seed` in the SYSTEM hive):
/// a tag, four bytes winload does not read, then the entropy.
pub const SEED_FILE_SIZE: usize = 76;
const SEED_FILE_TAG: &[u8; 8] = b"SeedFile";
/// The most of `RNG\ExternalEntropy` winload reads.
pub const EXTERNAL_ENTROPY_SIZE: usize = 256;

/// The seed file, as the value `RNG\Seed` was read (or why it could
/// not be). Any size but [`SEED_FILE_SIZE`] is an error, a larger one
/// reported as the read's failure; a wrong tag is reported but the
/// entropy is used all the same.
pub fn seed_file(value: Result<&[u8], NTSTATUS>) -> Outcome {
    match value {
        Err(status) => Outcome::not_present(status),
        Ok(v) if v.len() > SEED_FILE_SIZE => Outcome::not_present(STATUS_UNSUCCESSFUL),
        Ok(v) if v.len() != SEED_FILE_SIZE => Outcome::error(STATUS_INFO_LENGTH_MISMATCH),
        Ok(v) => {
            let status = if &v[..8] == SEED_FILE_TAG {
                STATUS_SUCCESS
            } else {
                STATUS_DEVICE_POWER_FAILURE
            };
            Outcome::success(status, &v[12..])
        }
    }
}

/// Entropy someone left for the next boot (`RNG\ExternalEntropy`): its
/// hash. More than [`EXTERNAL_ENTROPY_SIZE`] bytes is the read's failure.
pub fn external(value: Result<&[u8], NTSTATUS>) -> Outcome {
    match value {
        Err(status) => Outcome::not_present(status),
        Ok(v) if v.len() > EXTERNAL_ENTROPY_SIZE => Outcome::not_present(STATUS_UNSUCCESSFUL),
        Ok(v) => Outcome::success(STATUS_SUCCESS, &sha512::digest(v)),
    }
}

/// The TPM's random bytes winload asks for.
pub const TPM_BYTES: usize = 40;

/// The time source's bytes: two cycle counts around the counter and its
/// frequency, the firmware clock as `TIME_FIELDS`, and the time since the
/// loader started in milliseconds. winload leaves the last four bytes
/// as whatever its stack held; NK leaves them zero.
pub fn time(
    cycles: [u64; 2],
    counter: u64,
    frequency: u64,
    fields: [u16; 8],
    relative: u32,
) -> Outcome {
    let mut data = [0u8; 56];
    data[0..8].copy_from_slice(&cycles[0].to_le_bytes());
    data[8..16].copy_from_slice(&counter.to_le_bytes());
    data[16..24].copy_from_slice(&frequency.to_le_bytes());
    data[24..32].copy_from_slice(&cycles[1].to_le_bytes());
    for (chunk, field) in data[32..48].as_chunks_mut::<2>().0.iter_mut().zip(fields) {
        chunk.copy_from_slice(&field.to_le_bytes());
    }
    data[48..52].copy_from_slice(&relative.to_le_bytes());
    Outcome::success(STATUS_SUCCESS, &data)
}

/// `EFI_UNSPECIFIED_TIMEZONE` and the widest zone UEFI allows, in
/// minutes.
const MAX_TIME_ZONE: i16 = 1440;

/// Firmware's clock (`EFI_TIME`'s fields) as winload's `BlGetTime` gives
/// it the time source: `TIME_FIELDS` (year, month, day, hour, minute,
/// second, milliseconds, weekday). With a time zone, the time is moved
/// to UTC (winload adds the zone's minutes) and the weekday is the
/// date's, Sunday 0; without one the fields stay as firmware gave them
/// and the weekday is 7.
pub fn time_fields(clock: [u16; 6], nanosecond: u32, time_zone: i16) -> [u16; 8] {
    let [year, month, day, hour, minute, second] = clock;
    let milliseconds = (nanosecond / 1_000_000) as u16;
    let local = [year, month, day, hour, minute, second, milliseconds, 7];
    if !(-MAX_TIME_ZONE..=MAX_TIME_ZONE).contains(&time_zone) {
        return local;
    }
    let Some(time) = crate::windows_time(
        year.into(),
        month.into(),
        day.into(),
        hour.into(),
        minute.into(),
        second.into(),
    ) else {
        return local;
    };
    let Some(seconds) = (time / 10_000_000).checked_add_signed(i64::from(time_zone) * 60) else {
        return local;
    };
    let days = seconds / 86_400;
    let in_day = seconds % 86_400;
    let (y, m, d) = civil(days);
    // 1601-01-01 was a Monday.
    let weekday = ((days + 1) % 7) as u16;
    [
        y,
        m,
        d,
        (in_day / 3600) as u16,
        (in_day / 60 % 60) as u16,
        (in_day % 60) as u16,
        milliseconds,
        weekday,
    ]
}

/// The date `days` days after 1601-01-01.
fn civil(mut days: u64) -> (u16, u16, u16) {
    let leap = |y: u64| y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mut year = 1601;
    loop {
        let length = if leap(year) { 366 } else { 365 };
        if days < length {
            break;
        }
        days -= length;
        year += 1;
    }
    let mut month = 0;
    for (m, length) in [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
        .into_iter()
        .enumerate()
    {
        let length = length + u64::from(m == 1 && leap(year));
        month = m;
        if days < length {
            break;
        }
        days -= length;
    }
    (year as u16, month as u16 + 1, days as u16 + 1)
}

/// The length of an ACPI table's header.
const ACPI_HEADER: usize = 36;

/// The ACPI table `OEM0`, a platform's entropy: the bytes after its
/// header.
pub fn acpi_oem0(table: Option<&[u8]>) -> Outcome {
    match table {
        None => Outcome::not_present(STATUS_NOT_FOUND),
        Some(t) => Outcome::success(STATUS_SUCCESS, t.get(ACPI_HEADER..).unwrap_or(&[])),
    }
}

/// How many bytes winload draws by `RDSEED`, and by `RDRAND` when there
/// is no `RDSEED`.
pub const RDSEED_BYTES: usize = 0x80;
pub const RDRAND_BYTES: usize = 0x6000;

/// The processor's generator: the hash of what it gave (`RDSEED`'s
/// bytes, else `RDRAND`'s), or not present without either instruction.
pub fn rdrand(drawn: Option<&[u8]>) -> Outcome {
    match drawn {
        None => Outcome::not_present(STATUS_SUCCESS),
        Some(bytes) => Outcome::success(STATUS_SUCCESS, &sha512::digest(bytes)),
    }
}

/// The bytes winload asks of firmware's `EFI_RNG_PROTOCOL`.
pub const UEFI_BYTES: usize = 32;

/// The status winload gives for a failed firmware call
/// (`EfiGetNtStatusCode`), for the codes NK's loader can meet. EFI codes
/// are `usize` with the top bit set; any other failure is unsuccessful.
pub fn efi_status(efi: usize) -> NTSTATUS {
    const ERROR: usize = 1 << (usize::BITS - 1);
    match efi & !ERROR {
        3 => STATUS_NOT_SUPPORTED,
        6 | 14 => STATUS_NOT_FOUND,
        7 => STATUS_IO_DEVICE_ERROR,
        _ => STATUS_UNSUCCESSFUL,
    }
}

/// Fill in the slot that holds source `id` with `outcome`, and the time
/// the source took, in cycles.
pub fn put(result: &mut BOOT_ENTROPY_LDR_RESULT, id: u32, outcome: &Outcome, time: u64) {
    let Some(slot) = SLOTS.iter().position(|&s| s == id) else {
        return;
    };
    result.maxEntropySources = BOOT_MAX_ENTROPY_SOURCES as u32;
    result.EntropySourceResult[slot] = BOOT_ENTROPY_SOURCE_LDR_RESULT {
        SourceId: id,
        Policy: outcome.policy,
        ResultCode: outcome.code,
        ResultStatus: outcome.status,
        Time: time,
        EntropyLength: outcome.length,
        EntropyData: outcome.data,
    };
}

/// Make the seeds from the records: the hash of every record's entropy
/// in slot order, as winload makes it, then bytes drawn from that hash
/// for `cng.sys`, for the kernel and for its debugger, in that order.
///
/// winload draws them from an AES counter-mode generator (SP 800-90A
/// CTR_DRBG) seeded with the hash's first 48 bytes. NK draws them as
/// SHA-512 of the whole hash and a block counter: no binary sees which.
pub fn finish(result: &mut BOOT_ENTROPY_LDR_RESULT) {
    let mut hash = Sha512::new();
    for record in &result.EntropySourceResult {
        let length = (record.EntropyLength as usize).min(BOOT_ENTROPY_SOURCE_DATA_SIZE);
        hash.update(&record.EntropyData[..length]);
    }
    let seed = hash.finish();
    let mut block = 0u32;
    let mut stream = [0u8; sha512::DIGEST];
    let mut used = sha512::DIGEST;
    let mut draw = |out: &mut [u8]| {
        for byte in out {
            if used == sha512::DIGEST {
                let mut h = Sha512::new();
                h.update(&seed);
                h.update(&block.to_le_bytes());
                stream = h.finish();
                block += 1;
                used = 0;
            }
            *byte = stream[used];
            used += 1;
        }
    };
    draw(&mut result.SeedBytesForCng);
    draw(&mut result.RngBytesForNtoskrnl);
    draw(&mut result.KdEntropy);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed(tag: &[u8; 8], fill: u8) -> [u8; SEED_FILE_SIZE] {
        let mut v = [fill; SEED_FILE_SIZE];
        v[..8].copy_from_slice(tag);
        v
    }

    #[test]
    fn seed_file_as_winload_reads_it() {
        let good = seed(b"SeedFile", 0xA5);
        let o = seed_file(Ok(&good));
        assert_eq!((o.code, o.status, o.length), (4, STATUS_SUCCESS, 64));
        assert_eq!(o.data, [0xA5; 64]);
        // A wrong tag is reported; the entropy is used anyway.
        let o = seed_file(Ok(&seed(b"Garbage!", 1)));
        assert_eq!(
            (o.code, o.status, o.length),
            (4, STATUS_DEVICE_POWER_FAILURE, 64)
        );
        assert_eq!(
            seed_file(Ok(&good[..75])),
            Outcome::error(STATUS_INFO_LENGTH_MISMATCH)
        );
        let long = [0u8; 77];
        assert_eq!(
            seed_file(Ok(&long)),
            Outcome::not_present(STATUS_UNSUCCESSFUL)
        );
        assert_eq!(
            seed_file(Err(STATUS_OBJECT_NAME_NOT_FOUND)),
            Outcome::not_present(STATUS_OBJECT_NAME_NOT_FOUND)
        );
    }

    #[test]
    fn external_entropy_is_hashed() {
        let o = external(Ok(b"abc"));
        assert_eq!((o.code, o.length), (4, 64));
        assert_eq!(o.data, sha512::digest(b"abc"));
        assert_eq!(
            external(Ok(&[0; 257])),
            Outcome::not_present(STATUS_UNSUCCESSFUL)
        );
        assert_eq!(external(Err(STATUS_NOT_FOUND)).code, 2);
    }

    #[test]
    fn firmware_clock_as_time_fields() {
        // No zone: as given, weekday 7.
        assert_eq!(
            time_fields([2026, 11, 27, 23, 30, 5], 250_000_000, 0x7FF),
            [2026, 11, 27, 23, 30, 5, 250, 7]
        );
        // A zone of 60 minutes: an hour later, into a Saturday.
        assert_eq!(
            time_fields([2026, 11, 27, 23, 30, 5], 0, 60),
            [2026, 11, 28, 0, 30, 5, 0, 6]
        );
        // Back across a year and a leap day.
        assert_eq!(
            time_fields([2025, 1, 1, 0, 10, 0], 0, -20),
            [2024, 12, 31, 23, 50, 0, 0, 2]
        );
        assert_eq!(
            time_fields([2024, 3, 1, 0, 0, 0], 0, -1),
            [2024, 2, 29, 23, 59, 0, 0, 4]
        );
        assert_eq!(time_fields([1601, 1, 1, 0, 0, 0], 0, 0)[7], 1);
    }

    #[test]
    fn time_and_firmware_sources() {
        let o = time([1, 4], 2, 3, [2026, 11, 27, 12, 0, 0, 0, 5], 9);
        assert_eq!((o.code, o.length), (4, 56));
        assert_eq!(o.data[0], 1);
        assert_eq!(o.data[24], 4);
        assert_eq!(&o.data[32..34], &2026u16.to_le_bytes());
        assert_eq!(o.data[48], 9);
        assert_eq!(acpi_oem0(None), Outcome::not_present(STATUS_NOT_FOUND));
        let mut table = [7u8; 200];
        table[..36].fill(0);
        let o = acpi_oem0(Some(&table));
        assert_eq!((o.code, o.length, o.data), (4, 64, [7; 64]));
        assert_eq!(acpi_oem0(Some(&table[..36])).length, 0);
        assert_eq!(rdrand(None), Outcome::not_present(STATUS_SUCCESS));
        assert_eq!(rdrand(Some(&[1; 128])).length, 64);
        assert_eq!(efi_status(usize::MAX / 2 + 1 + 14), STATUS_NOT_FOUND);
        assert_eq!(efi_status(usize::MAX / 2 + 1 + 7), STATUS_IO_DEVICE_ERROR);
    }

    #[test]
    fn records_take_winloads_slots_and_seeds_follow_them() {
        let mut result = BOOT_ENTROPY_LDR_RESULT::zeroed();
        put(
            &mut result,
            BOOT_ENTROPY_SOURCE_RDRAND,
            &rdrand(Some(&[1; 128])),
            77,
        );
        put(
            &mut result,
            BOOT_ENTROPY_SOURCE_UEFI,
            &Outcome::success(0, &[3; 32]),
            5,
        );
        assert_eq!(result.maxEntropySources, 10);
        let r = result.EntropySourceResult[5];
        assert_eq!((r.SourceId, r.ResultCode, r.Time), (4, 4, 77));
        assert_eq!(result.EntropySourceResult[6].SourceId, 7);
        assert_eq!(result.EntropySourceResult[7].SourceId, 0);
        finish(&mut result);
        assert_ne!(result.SeedBytesForCng, [0; 48]);
        assert_ne!(result.SeedBytesForCng[..], result.RngBytesForNtoskrnl[..48]);
        // The same records make the same seeds; any change, others.
        let mut again = result;
        finish(&mut again);
        assert_eq!(again, result);
        again.EntropySourceResult[6].EntropyData[0] ^= 1;
        finish(&mut again);
        assert_ne!(again.SeedBytesForCng, result.SeedBytesForCng);
        assert_ne!(again.KdEntropy, result.KdEntropy);
    }
}
