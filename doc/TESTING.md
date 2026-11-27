# Testing

Windows defines the expected behaviour. Oracle tests hold NK to a
transcript recorded on real Windows; other expectations come from
Microsoft's documentation, sample source and the fixture binaries.

## The gates

| Gate | Passes | Prints | Runs |
| --- | --- | --- | --- |
| `make gate-fast` | every commit | `GATE-FAST-OK` | format, clippy (host, x86-64), host unit tests, x86-64 unwind coverage; boots the main scenario `x86_64` and the x86-64 scenarios whose `paths` name a file the branch changed since it left `updates` |
| `make gate` (the batch gate) | the merged tip of `updates`; CI | `GATE-OK` | the same, clippy for arm64 (the proof that arm64 compiles), and every x86-64 scenario of the gate tier, except that a scenario that must end in a bugcheck or a failed test boots only when its `paths` name a file changed since the commit this gate last passed at |
| `make gate-full` | nightly; milestones | `GATE-FULL-OK` | every step on both architectures and every scenario of the gate tier |

Each runs its steps in order, the host tests while the machines boot,
and stops at the first that fails (`tools/gate.sh`). A file is changed
if it differs between the commit compared with and the working tree, or
is untracked. Where that commit is not known, every file counts as
changed: the fast gate without a branch `updates` (`GATE_BASE=<commit>`
names another base), the batch gate without `target/gate-passed`, which
`tools/gate.sh` writes when the batch or full gate passes on a clean
tree. CI (`.github/workflows/ci.yml`) starts with neither, so its
`make gate` boots every x86-64 scenario of the gate tier, emulated,
with `NK_REQUIRE_FIXTURES=1`, which turns a fixture that cannot be
downloaded from a SKIP into a failure.

arm64 is paused until x86-64 reaches a `cmd.exe` prompt: no gate but
the full one boots it, and the batch gate holds it to compiling without
a warning. Its scenarios stay in `tools/scenarios.toml`, each bootable
by name (`tools/boot_test.py aarch64-smp1`, `make check-arm`).

| Target | What | In the gates |
| --- | --- | --- |
| `make test` | host unit tests of `lib/` and of the tools | all |
| `make check`, `check-arm` | one boot of the main scenario | `check`: all (as part of the boots); `check-arm`: full |
| `make boot-fast`, `boot-gate`, `boot-full` | the boots of the fast, batch and full gate, in parallel | one each |
| `make ledger-check` | the committed ledger is what the last boots printed | no: the ledger is a report, regenerated with `make ledger` when a milestone is reached |
| `make unwind-check`, `unwind-check-arm` | kernel code with no unwind entry is on the allow-list | `unwind-check`: all; `unwind-check-arm`: full |
| `make soak` | the whole list, repeated, on an overloaded host | no: long |
| `make mutants` | each deliberate break must fail its test | no: a build and boot each |
| `make coverage` | `lib/` line coverage, 95% per file | no: needs `cargo-llvm-cov` |
| `make oracle` | re-record the transcripts on Windows | no: needs KVM and the VM |

`make help` lists the targets that test nothing themselves (`fixtures`,
`ledger`, `corpus`). The ungated targets run when the code they cover
changes and at the end of a phase.

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

A test reaches what the kernel does without memory by watching its own
thread's allocations from the kernel's heap (`kernel/rt.rs`): it counts
those a call makes, then repeats the call with each of them refused in
turn.

The kernel command line is `\NK\cmdline.txt` on the boot volume:

| Word | Meaning |
| --- | --- |
| `test=<pattern>` | run only groups with a matching test name (`*` matches any run of characters) |
| `cpus=<n>` | `hal.cpus` fails unless the kernel finds `n` processors; the harness sets it to what it asked QEMU for |
| `dpc-limit=<ticks>` | how long one DPC may run, instead of Windows' 20 seconds |
| `debug=on` | behave as with a debugger attached that continues at every breakpoint |
| `without=<file>[,<file>...]` | boot as if the driver files named had not been provided: their services are passed over, and a device that needs one is left without its driver (a filter is left out of the stack) |
| `trace=registry` | log every key a driver opens and every value it reads, with the status: what a driver looks for in the registry, for bringing one up |

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
  (`tools/golden/<name>/`, a file per first word of the tests' names):
  a test that disappears, appears, or turns
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

### Time in a test

A test does not limit by the clock what the kernel promises only
eventually. It waits for the threads it started to end for as long as
that takes (`ke::thread::settle`), and never returns while one of them
can still run: they use what the test is about to tear down. A thread
that never ends is a hang, and the harness's time limit for the whole
boot is the hang detector: it reports where every processor was. A
limit inside the test would only turn a slow host, an emulated machine
on a busy one, into a failure. A limit stays where the time is the
promise: a wait that must time out, a step one thread owes another at
once.

### Scenarios

`tools/scenarios.toml` lists the boots and documents their fields,
among them `paths`: the files and directories whose change selects a
scenario for the fast gate and, if it must end in a bugcheck or a
failed test, for the batch gate. Microsoft's storage stack
(`x86_64-storage`, `x86_64-storage-direct`) is selected by any change
to the kernel, the loader, `lib/` or the fixtures; a scenario that
breaks a rule on purpose by the code that enforces the rule. The gate
tier has, for each architecture:

- the main scenario (`x86_64`, `aarch64`): the tests pass on several
  processors; and `*-smp1`: on one;
- `*-neg-*`: boots that break a rule on purpose (a panic, a stack
  overflow, a lock taken out of order, a wait at `DISPATCH_LEVEL`, a
  driver breakpoint with no debugger, an exception nothing handles, a
  driver's `KeBugCheckEx`, ...) and must end in the named bugcheck;
  `*-neg-bugcheck-callback` also requires the line a bugcheck callback
  prints after it (the scenario's `then`);
- `*-oracle-event*`, `*-debugger-breakpoint`: Microsoft's event sample,
  whose first act is a breakpoint, stops NK with Windows' bugcheck at
  the same step, and with `debug=on` runs as on Windows with a debugger;
- `*-oracle-nkc-seh-fatal-*`: each request of the conformance driver
  `nkc-seh-fatal` stops NK with the bugcheck it stopped Windows with;
- `*-oracle-nkc-cross-dpc`: likewise the conformance driver `nkc-cross`,
  whose DPC routine raises over a thread inside a `__try`;
- `*-known-bad`, `*-wrong-cpus`: a failing test fails the run.

- `x86_64-disk-present`: a boot with a data disk attached passes, and
  the disk is afterwards as it was made.
- `x86_64-storage`: Microsoft's storage stack (`acpi.sys`, `pci.sys`,
  `pshed.dll`, `storport.sys`, `storahci.sys`, `classpnp.sys`,
  `disk.sys`) on the machine's AHCI controller and data disk, as far as
  NK runs it (`kernel/selftest/storage.rs`). The boot has the stack's
  registry (`registry = ["storage"]`), so its four drivers start at
  boot from their service keys as on Windows, bringing in the
  libraries they import from; `stor.load` requires every driver
  running and every image loaded; `stor.enumerate` requires the
  devices of the path from the root to the disk (the HAL's device, the
  ACPI device, the PCI root, the AHCI controller, the disk) to be where
  the reference Windows has them, with its identifiers, services,
  classes and stacks, each started, and the controller to have its
  firmware's ports and registers and one message-signalled interrupt;
  `stor.io` reads and writes the disk the stack makes, so the scenario
  expects the image written. The group is selected by name and
  leaves the stack running, so the leak comparison is waived for it
  (`test::keeps_what_it_started`).
- `x86_64-storage-direct`: the same stack from `storahci.sys` up, on
  a bus driver of the test's own in place of `pci.sys`
  (`kernel/selftest/stordirect.rs`, `ahcibus.rs`). The bus driver
  reports a device under the root and enumerates one child on it: the
  AHCI controller, found by its class code in PCI configuration
  space. The child answers what `pci.sys`'s device for that function
  answers, read out of the pinned `pci.sys`: its identifiers and text,
  its requirements and boot configuration from its address registers,
  interrupt pin and message capability, `GUID_BUS_INTERFACE_STANDARD`
  and the configuration requests, and at its start it programs the
  address registers, the command register and the message capability.
  Everything above the bus is as on the real path: the manager
  installs the controller from the driver database, calls
  `storahci`'s `AddDevice`, assigns and translates its resources and
  starts it; Storport enumerates the disk; `disk.sys` is installed and
  started on it. `stor.direct` requires the bus and the controller's
  identifiers; `stor.direct.failed-start` a start that fails to be
  undone: the bus's device refuses the start request Storport passes
  down, and the manager must leave the controller failed with
  `storahci`'s device gone from it and no resources or interrupt
  vector held, and take its device away when the controller leaves the
  bus; done twice, the second round must leave the kernel holding
  exactly what the first left (`selftest::resources`, read once the
  kernel has stopped changing: what was taken down frees what it held
  a moment later). The controller then comes back for the tests that
  follow, enumerated for the third time, its key from the first still
  there: the bus, like `pci.sys`, reads `MSISupported` from it when it
  is asked for the requirements, and offers a message;
  `stor.direct.controller` the controller started by
  `storahci` with its ports, the memory its sixth address register
  names and one interrupt: one message, as on the reference machine
  (the raw descriptor latched and message-signalled with the message
  token for a vector, the controller's message capability enabled for
  one message with the address and data the hardware layer has for
  the vector), with `storahci`'s the one service routine
  on its vector and called at least once (the count is in the
  verdict; Storport's DPCs are not counted anywhere, and are proved by
  the disk having been found, since every command's completion goes
  through one); `stor.direct.disk` the disk with the
  reference Windows' instance path, identifiers, service and class,
  started, `\Device\Harddisk0\DR0`, the link `PhysicalDrive0`, and
  the port and the unit in `HARDWARE\DEVICEMAP\Scsi` as the reference
  machine has them (driver, 64-bit DMA, initiator, identifier, device
  type and INQUIRY data); `stor.direct.io` the proof of
  disk I/O (below) on that device, with the disk's adapter answering
  as the reference machine's (SATA, 128 KiB and 33 pages a transfer,
  alignment mask 1), and the scenario holds the image to
  `disk_expect = "written"`. `x86_64-storage-direct-smp1` is the same
  on one processor.

  The proof leaves out the transfers at and across the disk's end
  here, as it does for `stor.io` (`diskio::Beyond::Skip`): with no
  partition manager on the stack they reach the controller, which
  fails them, and `classpnp.sys` retries each for some four seconds,
  logs Windows' event 153 and fails it with `STATUS_IO_DEVICE_ERROR`.
  That is Microsoft's code at work, not NK's, and was most of the
  boot's time. NK's test disk is asked them. The verdict states the
  proof's time.

  What it does not prove is the path below the controller:
  `acpi.sys` and `pci.sys` enumerating it, `acpi.sys`'s filter on its
  stack, and the interfaces of `pci.sys` the test's bus does not
  have. Storport asks for two of those, the D3cold support interface
  and the device reset interface; the test's bus completes the
  request unchanged, as `pci.sys` completes a request for an
  interface it has no entry for, and Storport goes on without them.
  The class filters the reference machine registers for disks
  (`partmgr`, `EhStorClass`) have no image among the boot files and
  are left out (`doc/DESIGN.md`, What is absent).

  The two paths never both have the controller. The direct path
  exists only in this group, which runs only when named
  (`test=stor.direct`), and its scenarios boot `without=pci.sys`, so
  that the machine's own bus driver is not there to enumerate the
  controller. The group looks at the device tree first all the same:
  if a device with the controller's PCI device identifier is already
  there, because `pci.sys` enumerated it, every test of the group is
  skipped saying so, and no second device is made for the function.

All but the first are tests of the tests. An expected bugcheck counts
only if the test printed `NK-NEG-ARMED <name>` first, so a crash on the
way is not taken for the one intended.

### The data disk

A scenario with `disk = "ahci"` boots a machine that has a disk on an
AHCI controller: the ICH9 controller q35 has, and the same controller
added as a PCIe device to arm64's `virt`. The disk is the raw file
`data.img` in the scenario's directory, made for each boot, 64 MiB
unless `disk_size` says otherwise, and written in place: after the
boot the harness reads what the kernel left there.

Its content is one a kernel test can compute (`tools/datadisk.py`).
Seen as 64-bit little-endian words, word `k` of the disk, the 8 bytes
at byte offset `8 * k`, holds `seed ^ k`; sector `n` (512 bytes) is
words `64 * n` to `64 * n + 63`.

| Name | Value | Meaning |
| --- | --- | --- |
| `ORIGINAL` | `0x4E4B_4F52_0000_0000` | the seed of every sector before the boot |
| `WRITTEN` | `0x4E4B_5752_0000_0000` | the seed a kernel test writes with |
| `WRITE_FIRST`, `WRITE_END` | 2048, 2304 | the write range: sectors `[2048, 2304)`, the only ones a kernel test may write |

A written sector holds `WRITTEN ^ k` with the same `k`, its place on
the disk, so a sector written to the wrong address is as wrong as one
not written. The scenario's `disk_expect` names what the harness
requires of the file after the boot:

- `unchanged`: every sector holds its original pattern;
- `written`: every sector of the write range holds its written
  pattern, and every other sector its original one.

A sector that differs is a problem of the boot like any other, named
with what it holds instead; the image is then kept beside the logs.
`tools/test_datadisk.py` holds the check to that without booting.

The kernel's side is one function, `disk_io` in
`kernel/selftest/diskio.rs`, which is given the name of a disk device
and nothing else. Through NK's own requestor (`kernel/io/file.rs`:
direct I/O at byte offsets, control codes, flush) it

- opens the disk and asks for its geometry, length, device number and
  its device, adapter and access-alignment properties, and holds them
  to each other: a whole fixed disk of 512-byte sectors, its length the
  size its geometry gives, its cylinders the whole cylinders of that
  size (`lib/disk/answer.rs` reads the answers; its host tests read the
  bytes Windows answered for the reference machine's disks);
- reads the original pattern from the first sector, the middle and the
  last sector, and into buffers that start inside a page and span
  several: one sector, eight, 128 KiB, and the largest transfer the
  adapter's properties allow, ending at the disk's last sector;
- writes the written pattern to the write range in unequal pieces,
  reads it back in one transfer, and reads across both of its ends:
  written inside, original outside;
- sees the transfers a disk does not make refused: no bytes succeeds
  and moves nothing; a length or an offset that is not whole sectors is
  `STATUS_INVALID_PARAMETER`; whole sectors at or across the disk's end
  fail with whatever the drive's refusal comes to (Microsoft's disk
  driver sends such a request down for the drive to judge) and move
  nothing. These last are asked of NK's test disk only;
- does it at once from several threads, each with its own handle:
  three read stretches that are never written, one rewrites the write
  range, and the write range is read meanwhile;
- flushes, and reads the write range and its surroundings once more.

It writes the write range and nothing else. The pattern is
`lib/disk/pattern.rs`, the mirror of `tools/datadisk.py`.

The proof runs on every boot of the main scenarios against a disk of
NK's own (`disk.io.*`, `kernel/selftest/testdisk.rs`): a driver in the
kernel whose device does direct I/O on 8 MiB of pool memory holding the
original pattern, answers as `nk_disk::model` says Microsoft's disk
driver does, and completes what it takes from a DPC. `disk.io.image`
then holds the test disk's bytes to what `disk_expect = "written"`
holds an image to, and `disk.io.detects` requires the proof to fail on
a test disk that loses a write, writes a sector it was not asked to,
reads a sector from the wrong place, or reports fewer bytes than it
moved.

Against Microsoft's disk the proof is `stor.direct.io` of the
`x86_64-storage-direct` scenario, whose image is held to
`disk_expect = "written"`, and `stor.io` of the `x86_64-storage`
scenario. That scenario says `disk_expect = "unchanged"` for as long as
`stor.io` is skipped; the boot in which the disk device first exists
writes the write range, and its scenario says `disk_expect = "written"`.

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

A tier prints its boots in the order they are listed, a line for each
that passed and everything a failed one said. When the boots fail,
each gate shows the failed ones and the tier's last line
(`tools/boot_test.py --failures <log>`), not the end of the output.

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
| `npfs.sys` | Microsoft's named pipe file system (x86-64 only) | started at boot from its key in the hive; a pipe is created, a client connects, both ends read and write, peek, disconnect and close, each request answered as on Windows |
| `msfs.sys` | Microsoft's mailslot file system (x86-64 only) | started at boot from its key in the hive; a mailslot is created, clients write messages, its creator peeks at and reads them, and names, sharing, sizes and closing behave as on Windows |
| `wpprecorder.sys` | Microsoft's WPP trace recorder, an export driver (x86-64 only) | loads as a library, its `DllInitialize` succeeds with every routine it looks up by name found, and it unloads without leaks |
| `wmilib.sys` | Microsoft's WMI library, an export driver (x86-64 only) | likewise loads as a library, initialises and unloads without leaks |
| `msrpc.sys` | Microsoft's kernel RPC run-time, an export driver (x86-64 only) | likewise loads as a library, initialises and unloads without leaks; its ALPC and completion-port imports are bound to traps it does not reach |
| `sioctl.sys` | Microsoft's WDM IOCTL sample | opens by device name and symbolic link; buffered, direct and `METHOD_NEITHER` control requests return the sample's data; bad requests fail with its status codes, and buffers that are not there with an access violation its `__try` catches; repeated load/exercise/unload cycles leak nothing |
| `event.sys` | Microsoft's WDM event sample | with a debugger, its timer's DPC completes pended requests; without, its opening breakpoint stops the system |
| `cancel.sys` | Microsoft's WDM cancel sample | creates its device through Microsoft's device-security library (SDDL, registry, descriptor); its own thread serves a cancel-safe queue; reads are cancelled while queued; repeated cycles leak nothing |
| the other `nkc-*.sys` | NK's conformance drivers (nk-fixtures `nkc/`), one per kernel area | each returns the values it observed, the same list as on Windows |
| `\NK\SYSTEM` | a registry hive written by Windows' own registry from nk-fixtures' `hive/system.hive.txt` (one file for both architectures) | the kernel boots from it: its keys and values, of every size and name, are read back through `CurrentControlSet` (`cm.hive.*`); its boot-start services are started in group order, those without a boot file passed over (`io.service.boot-start`) |
| `\NK\OVERLAY` | `fixtures/registry-overlay.txt`, NK's own text file of keys and values not yet in the hive | laid over the hive at boot: its keys are read back, and a value of its own in place of the hive's (`cm.overlay`) |
| `nkc-lib.sys`, `nkc-libuser.sys` | an export driver and a driver that imports from it by name, by ordinal and a variable (nk-fixtures `nkc/nkc-lib*.c`) | the library is loaded with its importer, initialised once per load, kept while an importer is left and unloaded with the last; the importer logs the values it logs on Windows |
| `nkc-libbad.sys` | imports a name `nkc-lib.sys` does not export | refused with Windows' status, naming the import; its library is not left loaded |
| `wrongarch.sys` | `sioctl` built for the other architecture | refused: wrong machine |
| `unresolved.sys` | Microsoft's KMDF echo sample | refused: unresolved import, named in the log |

All but Microsoft's own binaries (from its symbol server) are made in
[nk-fixtures](https://github.com/jgarzik/nk-fixtures), the drivers built
with the WDK and the hive saved by Windows' registry: a separate
repository so the test drivers cannot drift toward what NK supports.
They are identified by hash and never patched or rebuilt to suit NK.
The manifest pins what no boot loads as well: the layout tables the
WDK's compiler recorded and the kernel's symbol file, which the host
tests compare `lib/ntabi` with (`doc/ABI.md`).
`fixtures/registry-overlay.txt` is a fixture kept in this repository:
registry content, as text, that the next release of the hive takes
over (`doc/DESIGN.md`, The registry). `fixtures/registry-<name>.txt`
are more of the same, laid over the hive after it only in the boots
whose scenario names them (`registry`): `registry-storage.txt` holds
what Microsoft's storage stack and the enumeration of its devices read,
copied from the reference Windows installation.

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
lines recorded on x86-64 Windows. The gates run only the NK side; a
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
gates until it gets them or is listed; so does a listed name that no
longer applies. The check prints the count and bytes of each kind.

## Release images

`make dist` builds one boot image per architecture holding only NK's
loader and kernel, boots each, and writes them with checksums to
`target/dist/`. With no drivers present the driver tests are SKIP.
