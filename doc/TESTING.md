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
the WDK (`lib/ntabi/probe.rs`), which `make test` downloads with the other
fixtures. Without them (offline) the test prints a SKIP note on stderr
and passes.

## Boot tests

`make check` (x86-64) and `make check-arm` (arm64) boot the real loader
and kernel under QEMU with UEFI firmware, the way a PC boots, and judge
the serial log. x86-64 uses KVM when available; arm64 is emulated.

The kernel reports each self-test on the serial console:

```
NK-TEST <name>:OK
NK-TEST <name>:FAIL <why>
NK-TEST <name>:SKIP <why>
NK-TEST-COMPLETE pass=<n> fail=<n> skip=<n>
```

A boot passes only if the totals line shows `fail=0`, no line reports a
failure, panic or bugcheck, and the kernel powered the machine off within
the timeout. Skips are printed, never counted as passes.

`tools/boot_test.py` owns the run: it builds the EFI system partition
image, copies the firmware variable store, starts QEMU in its own process
group, and on every exit path kills QEMU and deletes the image and the
copy. What remains is `target/qemu/serial-<arch>.log`.

Knobs: `BOOT_TEST_TIMEOUT` (seconds, default 120), `QEMU_SMP`, `QEMU_MEM`,
`NO_KVM=1`. `make run` / `make run-arm` boot with the console attached.

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

Each driver test compares pool usage, free frames and namespace entries
before loading the driver and after unloading it.

## Continuous integration

`.github/workflows/ci.yml` runs `make gate` on every push and pull
request. Both architectures are emulated there, and a fixture that cannot
be downloaded fails the run (`NK_REQUIRE_FIXTURES=1`) instead of turning
its tests into skips.

## Release images

`make dist` builds one boot image per architecture with only NK's loader
and kernel on it, boots each to confirm it works, and writes them with
their checksums to `target/dist/`. With no drivers present the kernel
reports the driver tests as skipped.

## The gate

`make gate` runs every check a commit must pass and prints `GATE-OK`.
Each commit passes it alone, so history is bisectable.
