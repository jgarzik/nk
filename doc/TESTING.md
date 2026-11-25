# Testing

Windows defines the expected behaviour. Where a test's expectation was
recorded from real Windows it says so (the oracle, below); elsewhere
expectations come from Microsoft's documentation and from reading the
fixture binaries.

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

Logic that needs no hardware belongs in `lib/`, not in the kernel
binary, which the host cannot run: the rules of the self-test runner,
the processor census, the stack-gap check and the oracle's comparison
all live there for that reason. `make coverage` measures it: it runs
these tests under `cargo llvm-cov` and fails if any file in `lib/` has
under 95% of its lines executed. It needs the `cargo-llvm-cov` tool, so
it is run when a library changes and at the end of a phase rather than
in the gate.

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
- no line starts `NK-VERIFY`: a driver broke a rule that Windows does not
  enforce (raised the IRQL downward, say). NK lets the driver carry on,
  as Windows would, and fails the test run;
- no line is torn or malformed;
- the tests and their verdicts are the ones in the scenario's golden list
  (`tools/golden/<name>.txt`): a test that disappears, appears, or turns
  from OK into SKIP fails the boot until the list is changed on purpose
  (`tools/boot_test.py <scenario> --bless`);
- NK's second is a second. The kernel prints `NK-CLOCK-MARK` before and
  after a stall it believes lasts two seconds, and the harness times the
  two marks with the host's clock. Less than 1.9 s fails: a stall may run
  long on a busy host, never short, so a short one means NK's clock runs
  fast;
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
| `x86_64`, `aarch64` | the tests pass, on four processors |
| `*-smp1` | they pass on one |
| `*-neg-panic`, `*-neg-fault` | a kernel panic or a stray memory access ends the boot in a bugcheck, and the harness sees it |
| `*-neg-stack-overflow` | running off the kernel stack is reported as a stack overflow |
| `*-neg-lock-order`, `*-neg-lock-twice`, `*-neg-irql-lower` | breaking a locking or IRQL rule (`doc/LOCKING.md`) stops the system with the right bugcheck |
| `*-neg-cpu-stuck` | a processor that stops answering interprocessor interrupts stops the system |
| `*-neg-dpc-watchdog` | a DPC that never returns stops the system, with the limit shortened by `dpc-limit=<ticks>` |
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

The expected results of these hand-written tests come from Microsoft's
documentation, the sample's published source and reading the driver
binaries. The oracle tests below check the same two drivers against a run
on Windows.

## The Windows oracle

`oracle/<name>.script` lists requests to make of a driver: load it, open
its device, send control requests, read, write, close, unload. The script
is replayed in two places:

- on real Windows 10 (build 19045.2006), in a reference VM, by
  `oracle/runner.ps1`. The transcript it prints is committed as
  `oracle/<name>.txt`;
- on NK, by the kernel tests `oracle.<name>`, against the same driver
  binary. Each line NK produces must be the line Windows produced: same
  status, same byte count, same bytes in the output buffer, including the
  bytes nobody wrote.

`oracle/README.md` defines the script and the transcript. The transcripts
do not depend on the architecture, so arm64 NK is held to the lines
recorded on x86-64 Windows.

`make oracle` replays every script on Windows again and fails if a
committed transcript is not what Windows says. It is not part of the gate
or of CI: it needs KVM, and its first run downloads Microsoft's Windows
10 Enterprise evaluation ISO (5.5 GB, pinned by SHA-256) and installs it
unattended, about ten minutes. After that a replay takes half a minute
and is cached by the hash of its inputs. `tools/oracle.py` documents the
VM: a base image under `$NK_CACHE` (default `~/.cache/nk`) that is never
modified, and a throwaway overlay per replay.

The gate runs only the NK side, against the committed transcripts. A
transcript records the hashes of its script and driver;
`tools/test_oracle.py` fails if either changed without recording again.

Each driver test compares pool usage, frames and namespace entries before
loading the driver and after unloading it, in addition to the check the
runner makes around every group.

## Mutants

A test that still passes when the thing it tests is broken proves
nothing. `tools/mutants/` holds deliberate breaks of the kernel, each a
one-line change with the test that must catch it: a vector register the
trap exit forgets to restore, a byte count that differs from Windows by
one. `make mutants` applies each in turn, rebuilds, boots, requires that
test to fail, and puts the source back. It is not in the gate (one build
and boot per mutant); it is run when tests or the code they cover change,
and at the end of each roadmap phase. `make test` checks that every
mutant still applies to the source.

A change that adds a mechanism whose failure would be silent (state saved
and restored, an interrupt acknowledged, a wake-up delivered) adds the
mutant that removes it.

## Continuous integration

`.github/workflows/ci.yml` runs `make gate` on every push and pull
request: the same gate as locally. Hosted runners have no KVM, so both
architectures are emulated there and the boots run one at a time. A
fixture that cannot be downloaded fails the CI run
(`NK_REQUIRE_FIXTURES=1`) instead of turning its tests into skips.

Not in the gate, and so not in CI: `make mutants` and `make coverage`
(slow, or needing extra tools) and `make oracle` (needs the Windows
reference machine). They are run locally when tests change and at the
end of each phase.

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
