//! Boot entropy: read each source as winload reads it and hand the
//! kernel the `BOOT_ENTROPY_LDR_RESULT` (`nk_bootinfo::entropy` holds
//! the rules; `doc/BOOT.md`, Boot entropy, the sources NK has).

use crate::{arch, efi};
use nk_bootinfo::entropy::{self, Outcome};
use nk_cm::regf::{Lookup, Regf};
use nk_ntabi::status::*;
use nk_ntabi::sysinfo::*;

/// The value `RNG\<name>` of the SYSTEM hive, read into `out`, or the
/// status winload's look-up gives for its absence.
fn hive_value<'a>(
    hive: Option<&[u8]>,
    name: &str,
    out: &'a mut [u8],
) -> Result<&'a [u8], NTSTATUS> {
    // NK's built-in registry, without a hive file, has no RNG key.
    let hive = hive.ok_or(STATUS_OBJECT_NAME_NOT_FOUND)?;
    let regf = Regf::parse(hive).map_err(|_| STATUS_REGISTRY_CORRUPT)?;
    match regf.read_value(&["RNG"], name, out) {
        Ok(len) => Ok(&out[..len]),
        Err(Lookup::NoKey) => Err(STATUS_OBJECT_NAME_NOT_FOUND),
        Err(Lookup::NoValue) => Err(STATUS_NOT_FOUND),
        Err(Lookup::TooLong(_)) => Err(STATUS_UNSUCCESSFUL),
        Err(Lookup::Bad(_)) => Err(STATUS_REGISTRY_CORRUPT),
    }
}

/// The TPM, as winload finds it. NK's loader does not drive a TPM: with
/// none it reports what winload reports for none; with one it reports
/// the source as failed, where winload would have drawn from it.
fn tpm() -> Outcome {
    if efi::has_protocol(&efi::TCG2) || efi::has_protocol(&efi::TCG) {
        Outcome::error(STATUS_NOT_SUPPORTED)
    } else {
        Outcome::not_present(STATUS_NOT_FOUND)
    }
}

/// How many counts the counter advances in a second: measured against
/// firmware's stall, a millisecond long.
fn frequency() -> u64 {
    let start = arch::cycles();
    efi::stall(1000);
    arch::cycles().wrapping_sub(start) * 1000
}

/// Gather every source in winload's order and make the block, in pages
/// of its own; its physical address.
pub fn gather(
    hive: Option<&[u8]>,
    acpi_oem0: Option<&[u8]>,
    started: u64,
) -> Result<u64, &'static str> {
    let pages = size_of::<BOOT_ENTROPY_LDR_RESULT>().div_ceil(4096);
    let phys = efi::alloc_pages(pages).ok_or("out of memory for boot entropy")?;
    // SAFETY: fresh pages of the block's size, page aligned and zeroed,
    // which is the block with no sources; nothing else refers to them.
    // The block is made in place so that no copy of the seeds is left
    // behind in the loader's memory.
    let result = unsafe { &mut *(phys as *mut BOOT_ENTROPY_LDR_RESULT) };
    for id in entropy::SLOTS {
        let start = arch::cycles();
        let outcome = match id {
            BOOT_ENTROPY_SOURCE_SEEDFILE => {
                let mut value = [0u8; entropy::SEED_FILE_SIZE];
                entropy::seed_file(hive_value(hive, "Seed", &mut value))
            }
            BOOT_ENTROPY_SOURCE_EXTERNAL => {
                let mut value = [0u8; entropy::EXTERNAL_ENTROPY_SIZE];
                entropy::external(hive_value(hive, "ExternalEntropy", &mut value))
            }
            BOOT_ENTROPY_SOURCE_TPM => tpm(),
            BOOT_ENTROPY_SOURCE_TIME => {
                let first = arch::cycles();
                let counter = arch::cycles();
                let frequency_hz = frequency();
                let fields = efi::clock().map_or([0; 8], |(clock, ns, zone)| {
                    entropy::time_fields(clock, ns, zone)
                });
                let last = arch::cycles();
                let since = last.wrapping_sub(started) / (frequency_hz / 1000).max(1);
                entropy::time([first, last], counter, frequency_hz, fields, since as u32)
            }
            BOOT_ENTROPY_SOURCE_ACPI_OEM0 => entropy::acpi_oem0(acpi_oem0),
            BOOT_ENTROPY_SOURCE_RDRAND => {
                let mut seed = [0u8; entropy::RDSEED_BYTES];
                let mut rdrand = [0u8; entropy::RDRAND_BYTES];
                let outcome = entropy::rdrand(arch::draw_random(&mut seed, &mut rdrand)?);
                seed.fill(0);
                rdrand.fill(0);
                outcome
            }
            BOOT_ENTROPY_SOURCE_UEFI => {
                let mut bytes = [0u8; entropy::UEFI_BYTES];
                let outcome = match efi::rng(&mut bytes) {
                    efi::Rng::Absent(s) => Outcome::not_present(entropy::efi_status(s)),
                    efi::Rng::Failed(s) => Outcome::error(entropy::efi_status(s)),
                    efi::Rng::Filled => Outcome::success(STATUS_SUCCESS, &bytes),
                };
                bytes.fill(0);
                outcome
            }
            _ => continue,
        };
        crate::println!(
            "nkload: entropy source {id}: result {} status {:#x}, {} bytes",
            outcome.code,
            outcome.status as u32,
            outcome.length
        );
        entropy::put(result, id, &outcome, arch::cycles().wrapping_sub(start));
    }
    entropy::finish(result);
    Ok(phys)
}
