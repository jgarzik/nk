# Testing

Windows defines the expected behaviour. Until a Windows reference VM
exists, expectations come from Microsoft's documentation and from reading
the fixture binaries, and the ledger says so.

## Host unit tests

`make test`. Pure functions in `lib/` crates, tested on the build host.
Tests build their inputs in code (for example, synthetic PE images) so
they need no downloaded files. Tests that do use a fetched fixture report
that they were skipped when it is absent.

`lib/ntabi` also checks its structure layouts against tables built by
the WDK (`lib/ntabi/probe.rs`) and against the public symbols of the
pinned Windows kernel (`lib/ntabi/pdb.rs`), which `make test` downloads
with the other fixtures. Without them (offline) the test prints a SKIP note on stderr
and passes.

## Boot tests

`make check` (x86-64) and `make check-arm` (arm64) boot the real loader
and kernel under QEMU with UEFI firmware, the way a PC boots, and judge
the serial log. x86-64 uses KVM when available; arm64 is emulated.

### What the kernel reports

Tests are declared in groups (`kernel/test.rs`, `kernel/selftest/`). A
group names every verdict it will report; the runner holds it to that
list, and compares the kernel's resources (pool blocks and bytes, frames,
object names) before and after each group.

```
NK-TEST-PLAN <n>                 verdicts to expect, printed first
NK-TEST <name>:OK
NK-TEST <name>:FAIL <why>
NK-TEST <name>:SKIP <why>
NK-TEST-COMPLETE pass=<n> fail=<n> skip=<n>
```

A declared verdict that is never reported is a FAIL, as is one reported
twice, one that was not declared, and a group that does not give back
what it took (`NK-TEST leak:FAIL`).

The kernel command line is the file `\NK\cmdline.txt` on the boot volume:

| Word | Meaning |
| --- | --- |
| `test=<pattern>` | run only the groups with a matching test name (`*` matches any run of characters) |
| `cpus=<n>` | the machine has `n` processors; `hal.cpus` fails if the kernel finds another number. The harness sets it to what it asked QEMU for |

### What passing means

`tools/judge.py` decides, from the serial log alone, and
`tools/test_judge.py` tests it against canned logs of every kind of
failure. A boot passes only if:

- there is exactly one plan line and one totals line, the number of
  verdicts equals the plan, and the totals equal the lines;
- no test failed, and no line reports a panic or a bugcheck;
- no line is torn or malformed;
- the tests and their verdicts are the ones in the scenario's golden list
  (`tools/golden/<name>.txt`): a test that disappears, appears, or turns
  from OK into SKIP fails the boot until the list is changed on purpose
  (`tools/boot_test.py <scenario> --bless`);
- the kernel powered the machine off within the timeout.

Skips are printed, never counted as passes. A test that is skipped in
every scenario must be listed with its reason in
`tools/golden/blocked.txt`. When driver fixtures are not downloaded the
harness says so and accepts SKIP where the golden list says OK.

### Scenarios

`tools/scenarios.toml` lists the boots: architecture, kernel command line,
and what is expected. `make boot-gate` runs every scenario of the `gate`
tier in parallel:

| Scenario | Proves |
| --- | --- |
| `x86_64`, `aarch64` | the tests pass |
| `*-neg-panic`, `*-neg-fault` | a kernel panic or a stray memory access ends the boot in a bugcheck, and the harness sees it |
| `*-known-bad` | a failing test fails the run |
| `*-wrong-cpus` | a processor the kernel does not find fails a test |

All but the first are tests of the tests. An expected bugcheck counts
only if the test printed `NK-NEG-ARMED <name>` first, so a crash on the
way to the test is not taken for the one it meant to cause.

### The harness cleans up

`tools/boot_test.py` runs each scenario in `target/qemu/<scenario>/`:
EFI system partition image, firmware variable copy, serial log. QEMU runs
in its own session and is killed on every exit path (pass, fail, timeout,
Ctrl-C, SIGTERM); if the harness itself is killed outright, QEMU dies with
it. A scenario that passes deletes its directory. One that fails keeps
its logs and prints the path; the image and the variable copy are always
removed. The logs of the main scenario of each architecture stay as
`target/qemu/serial-<arch>.log` and `exports-<arch>.txt`.

A boot that reaches the timeout is a hang: before killing it the harness
saves every CPU's registers to `hang-registers.txt` in the scenario
directory, and on x86-64 sends an NMI so the kernel prints its own state.

Knobs: `BOOT_TEST_TIMEOUT` (seconds, default 120), `QEMU_SMP` (guest
CPUs where the scenario does not say; default 4), `QEMU_MEM`,
`NO_KVM=1`, `JOBS` (boots at once), `KEEP=1` (keep every scenario
directory). `make run` / `make run-arm` boot with the console attached.

## Driver fixtures

`fixtures/manifest.toml` lists every Windows binary the tests use, with
its URL and SHA-256; `make fixtures` downloads them to `target/fixtures/`.
None is committed. The boot tests put them on the EFI system partition:

| File on the ESP | What it is | Expected |
| --- | --- | --- |
| `null.sys` | Microsoft's inbox Null driver | loads; read gives end-of-file, write accepts all bytes; unloads without leaks |
| `sioctl.sys` | Microsoft's WDM IOCTL sample, WDK-built | loads; opens by device name and by its symbolic link; buffered, in-direct and out-direct control requests return the sample's data; bad requests fail with the sample's status codes; 100 load/exercise/unload cycles leak nothing |
| `wrongarch.sys` | the same sample built for the other architecture | refused: wrong machine |
| `unresolved.sys` | Microsoft's KMDF echo sample | refused: unresolved import, named in the log |

A fixture that is not present makes its tests print SKIP. There is no
Windows 10 arm64 `null.sys` fixture yet, so those tests skip on arm64.

`METHOD_NEITHER` control requests are not sent: the sample probes the raw
buffers as user memory inside `__try`, which needs user address space and
SEH. That test prints SKIP.

Expected results come from Microsoft's documentation, the sample's
published source and reading the driver binaries. They have not been compared with a run on Windows.

Each driver test compares pool usage, frames and namespace entries before
loading the driver and after unloading it, in addition to the check the
runner makes around every group.

## Continuous integration

`.github/workflows/ci.yml` runs `make ci` on every push and pull request:
formatting, lints, the unit tests, the main boot of each architecture and
the ledger check. Hosted runners have no KVM, so both architectures are
emulated there and the other gate scenarios are left to `make gate`,
which is run locally before every commit. A fixture that cannot be
downloaded fails the CI run (`NK_REQUIRE_FIXTURES=1`) instead of turning
its tests into skips.

## Release images

`make dist` builds one boot image per architecture with only NK's loader
and kernel on it, boots each to confirm it works, and writes them with
their checksums to `target/dist/`. With no drivers present the kernel
reports the driver tests as skipped.

## The gate

`make gate` runs every check a commit must pass and prints `GATE-OK`:
formatting, lints, the unit tests (library crates and the harness's own),
every gate-tier boot scenario, and the ledger check. Each commit passes
it alone, so history is bisectable.
