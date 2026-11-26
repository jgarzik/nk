# Testing

Windows defines the expected behaviour. Oracle tests hold NK to a
transcript recorded on real Windows; other expectations come from
Microsoft's documentation, sample source and the fixture binaries.

| Target | What | In the gate |
| --- | --- | --- |
| `make test` | host unit tests of `lib/` and of the tools | yes |
| `make check`, `check-arm` | one boot of the main scenario | (as part of `boot-gate`) |
| `make boot-gate` | every gate-tier boot scenario, in parallel | yes |
| `make ledger-check` | the committed ledger is what the boot printed | yes |
| `make unwind-check` | kernel code with no unwind entry is on the allow-list | yes |
| `make gate` | fmt, clippy (both arches), the four above; prints `GATE-OK` | |
| `make soak` | the whole list, repeated, on an overloaded host | no: long |
| `make mutants` | each deliberate break must fail its test | no: a build and boot each |
| `make coverage` | `lib/` line coverage, 95% per file | no: needs `cargo-llvm-cov` |
| `make oracle` | re-record the transcripts on Windows | no: needs KVM and the VM |

The ungated targets run when the code they cover changes and at the end
of a phase. CI (`.github/workflows/ci.yml`) runs `make gate` with both
architectures emulated and `NK_REQUIRE_FIXTURES=1`, which turns a
fixture that cannot be downloaded from a SKIP into a failure.

## Host unit tests

Pure functions in `lib/` crates. Tests build their inputs in code
(synthetic PE images, say); one that needs a fetched fixture prints SKIP
on stderr when it is absent.

`lib/ntabi` checks its layouts against tables built by the WDK
(`lib/ntabi/probe.rs`) and against the pinned kernel's public symbols
(`lib/ntabi/pdb.rs`).

Logic that needs no hardware belongs in `lib/`, because the host cannot
run the kernel binary: the self-test runner's rules, the processor
census, the stack-gap check and the oracle's comparison live there for
that reason.

## Boot tests

The real loader and kernel boot under QEMU with UEFI firmware and the
serial log is judged. x86-64 uses KVM when available; arm64 is emulated.

### What the kernel reports

Tests are declared in groups (`kernel/test.rs`, `kernel/selftest/`). A
group names every verdict it will report; the runner holds it to that
list and compares the kernel's resources (pool blocks and bytes, frames,
object names) before and after each group. Driver tests also compare
them across load and unload.

```
NK-TEST-PLAN <n>                 verdicts to expect, printed first
NK-TEST <name>:OK
NK-TEST <name>:FAIL <why>
NK-TEST <name>:SKIP <why>
NK-TEST-COMPLETE pass=<n> fail=<n> skip=<n>
```

A declared verdict never reported is a FAIL, as is one reported twice,
one not declared, and a group that does not give back what it took
(`NK-TEST leak:FAIL`).

The kernel command line is `\NK\cmdline.txt` on the boot volume:

| Word | Meaning |
| --- | --- |
| `test=<pattern>` | run only groups with a matching test name (`*` matches any run of characters) |
| `cpus=<n>` | `hal.cpus` fails unless the kernel finds `n` processors; the harness sets it to what it asked QEMU for |
| `dpc-limit=<ticks>` | how long one DPC may run, instead of Windows' 20 seconds |
| `debug=on` | behave as with a debugger attached that continues at every breakpoint |

### What passing means

`tools/judge.py` decides from the serial log alone; `tools/test_judge.py`
tests it against canned logs of every kind of failure. A boot passes
only if:

- there is one plan line and one totals line, the verdicts number what
  the plan said, and the totals equal the lines;
- no test failed, and no line reports a panic or a bugcheck;
- no line starts `NK-VERIFY`: a driver broke a rule Windows does not
  enforce (moved the IRQL the wrong way, say). NK lets the driver carry
  on, as Windows would, and fails the run;
- no line is torn or malformed;
- tests and verdicts are those of the scenario's golden list
  (`tools/golden/<name>.txt`): a test that disappears, appears, or turns
  from OK into SKIP fails until the list is changed on purpose
  (`tools/boot_test.py <scenario> --bless`);
- NK's second is a second: the kernel prints `NK-CLOCK-MARK` around a
  stall it believes lasts two seconds and the harness times the marks.
  Under 1.9 s fails: a stall may run long on a busy host, never short;
- the kernel powered the machine off within the timeout.

Skips are printed, never counted as passes. A test skipped in every
scenario must be listed with its reason in `tools/golden/blocked.txt`.
When driver fixtures are not downloaded the harness says so and accepts
SKIP where the golden list says OK.

### Scenarios

`tools/scenarios.toml` lists the boots and documents their fields. The
gate tier has, for each architecture:

- the main scenario (`x86_64`, `aarch64`): the tests pass on several
  processors; and `*-smp1`: on one;
- `*-neg-*`: boots that break a rule on purpose (a panic, a stack
  overflow, a lock taken out of order, a wait at `DISPATCH_LEVEL`, a
  driver breakpoint with no debugger, an exception nothing handles,
  ...) and must end in the named bugcheck;
- `*-oracle-event*`, `*-debugger-breakpoint`: Microsoft's event sample,
  whose first act is a breakpoint, stops NK with Windows' bugcheck at
  the same step, and with `debug=on` runs as on Windows with a debugger;
- `*-known-bad`, `*-wrong-cpus`: a failing test fails the run.

All but the first are tests of the tests. An expected bugcheck counts
only if the test printed `NK-NEG-ARMED <name>` first, so a crash on the
way is not taken for the one intended.

### Soak

`make soak` runs the soak tier `SOAK_REPEAT` times each: the whole list
with one to eight processors on both architectures,
x86-64 both virtualised and emulated. It starts twice as many guest
processors as the host has, on purpose: an overloaded host stalls guest
processors at arbitrary instants, which is what shakes out races. Run it
whenever scheduling, locking or interrupt entry changes.

### Firmware hangs

Rarely, under host load, the emulated UEFI firmware hangs before
starting `nkload` (seen on arm64). The harness recognises this by the
absence of the loader's first line, keeps the log and registers as
`firmware-hang.*`, and boots once more. A hang after the loader has
printed is never retried: that is NK's to explain.

### The harness

`tools/boot_test.py` runs each scenario in `target/qemu/<scenario>/`.
QEMU runs in its own session and is killed on every exit path. A passing
scenario deletes its directory; a failing one keeps its logs and prints
the path. The main scenario's logs stay as
`target/qemu/serial-<arch>.log` and `exports-<arch>.txt`. A boot that
reaches the timeout is a hang: the harness saves every CPU's registers
to `hang-registers.txt` and, on x86-64, sends an NMI so the kernel
prints its own state.

Knobs: `BOOT_TEST_TIMEOUT` (seconds), `QEMU_SMP`, `QEMU_MEM`,
`NO_KVM=1`, `JOBS` (boots at once), `KEEP=1` (keep every scenario
directory).

## Driver fixtures

`fixtures/manifest.toml` lists every Windows binary the tests use, with
URL and SHA-256; `make fixtures` downloads them to `target/fixtures/`.
None is committed. An absent fixture makes its tests SKIP.

| File on the ESP | What it is | Expected |
| --- | --- | --- |
| `null.sys` | Microsoft's inbox Null driver (x86-64 only: no arm64 source) | started at boot from its key in the hive; read gives end-of-file, write accepts all bytes; unloads without leaks |
| `sioctl.sys` | Microsoft's WDM IOCTL sample | opens by device name and symbolic link; buffered, direct and `METHOD_NEITHER` control requests return the sample's data; bad requests fail with its status codes, and buffers that are not there with an access violation its `__try` catches; repeated load/exercise/unload cycles leak nothing |
| `event.sys` | Microsoft's WDM event sample | with a debugger, its timer's DPC completes pended requests; without, its opening breakpoint stops the system |
| `cancel.sys` | Microsoft's WDM cancel sample | creates its device through Microsoft's device-security library (SDDL, registry, descriptor); its own thread serves a cancel-safe queue; reads are cancelled while queued; repeated cycles leak nothing |
| `nkc-*.sys` | NK's conformance drivers (nk-fixtures `nkc/`), one per kernel area | each returns the values it observed, the same list as on Windows |
| `\NK\SYSTEM` | a registry hive written by Windows' own registry from nk-fixtures' `hive/system.hive.txt` (one file for both architectures) | the kernel boots from it: its keys and values, of every size and name, are read back through `CurrentControlSet` (`cm.hive.*`); its boot-start services are started in group order, those without a boot file passed over (`io.service.boot-start`) |
| `nkc-lib.sys`, `nkc-libuser.sys` | an export driver and a driver that imports from it by name, by ordinal and a variable (nk-fixtures `nkc/nkc-lib*.c`) | the library is loaded with its importer, initialised once per load, kept while an importer is left and unloaded with the last; the importer logs the values it logs on Windows |
| `nkc-libbad.sys` | imports a name `nkc-lib.sys` does not export | refused with Windows' status, naming the import; its library is not left loaded |
| `wrongarch.sys` | `sioctl` built for the other architecture | refused: wrong machine |
| `unresolved.sys` | Microsoft's KMDF echo sample | refused: unresolved import, named in the log |

All but `null.sys` (from Microsoft's symbol server) are made in
[nk-fixtures](https://github.com/jgarzik/nk-fixtures), the drivers built
with the WDK and the hive saved by Windows' registry: a separate
repository so the test drivers cannot drift toward what NK supports.
They are identified by hash and never patched or rebuilt to suit NK.

## The Windows oracle

`oracle/<name>.script` lists requests to make of a driver. It is
replayed on Windows 10 (19045.2006) in a reference VM, whose transcript
is committed as `oracle/<name>.txt`, and on NK by the test
`oracle.<name>` against the same binary. Each NK line must be the
Windows line: status, byte count and every byte of the output buffer,
including those nobody wrote. Formats: `oracle/README.md`.

A conformance driver is the same idea inside out: it exercises kernel
routines itself and reports what it saw as a list of numbers. What
Windows returns is the specification, even where it surprises.

Transcripts do not depend on the architecture, so arm64 NK is held to
lines recorded on x86-64 Windows. The gate runs only the NK side; a
transcript records the hashes of its script and driver, and
`tools/test_oracle.py` fails if either changed without re-recording.

`make oracle` re-records and fails on any difference. Its first run
downloads Microsoft's Windows 10 Enterprise evaluation ISO (several GB,
pinned by SHA-256) and installs it unattended; later replays are cached
by the hash of their inputs. `tools/oracle.py` documents the VM: a base
image under `$NK_CACHE` (default `~/.cache/nk`) that is never modified,
and a throwaway overlay per replay.

## Mutants

A test that passes when the thing it tests is broken proves nothing.
`tools/mutants/` holds deliberate one-line breaks of the kernel, each
with the test that must catch it. `make mutants` applies each, rebuilds,
boots, requires that test to fail, and restores the source. `make test`
checks every mutant still applies.

A change that adds a mechanism whose failure would be silent (state
saved and restored, an interrupt acknowledged, a wake-up delivered) adds
the mutant that removes it.

## Unwind coverage

`tools/unwind_coverage.py` reads each built kernel image and its link
map (`nkkrnl.map`, written beside the image) and finds every code
symbol that no `.pdata` entry covers. Such a symbol must be one of:

- code of a library listed in `tools/unwind/<arch>.txt`: the
  prebuilt `core`, `alloc` and `compiler_builtins`. They are allowed
  whole: which of their functions a build links in changes with
  unrelated code and with the compiler's version;
- a Rust function compiled with NK: the compiler gives an entry to
  every function that uses the stack, so one without is a leaf;
- a symbol listed there by name with its reason: assembly, which
  nothing else checks.

A new assembly routine without unwind directives therefore fails the
gate until it gets them or is listed; so does a listed name that no
longer applies. The check prints the count and bytes of each kind.

## Release images

`make dist` builds one boot image per architecture holding only NK's
loader and kernel, boots each, and writes them with checksums to
`target/dist/`. With no drivers present the driver tests are SKIP.
